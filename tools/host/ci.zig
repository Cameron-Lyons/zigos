//! CI provisioning and GitHub summaries, using literal child process arguments.
const std = @import("std");
const common = @import("common.zig");

pub fn run(ctx: *common.Context, command: []const u8, args: []const []const u8) !void {
    if (std.mem.eql(u8, command, "ci-render-summary")) {
        try common.requireArgs(args, 1, 1);
        return renderSummary(ctx, args[0], ctx.env("GITHUB_STEP_SUMMARY") orelse return error.MissingGithubStepSummary);
    }
    try common.requireArgs(args, 0, 0);
    if (std.mem.eql(u8, command, "ci-verify-toolchain")) return verifyToolchain(ctx);
    if (std.mem.eql(u8, command, "ci-init-jj")) return initJujutsu(ctx);
    if (std.mem.eql(u8, command, "ci-enable-kvm")) return enableKvm(ctx);
    if (std.mem.eql(u8, command, "ci-setup-efi-tools")) return setupEfiTools(ctx);
    if (std.mem.eql(u8, command, "ci-install-linters")) return installLinters(ctx);
    return error.UnknownCommand;
}

fn pinnedVersion(contents: []const u8, tool: []const u8) ![]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const name = fields.next() orelse continue;
        if (!std.mem.eql(u8, name, tool)) continue;
        const version = fields.next() orelse return error.MissingToolVersion;
        if (fields.next() != null or found != null) return error.AmbiguousToolVersion;
        found = version;
    }
    return found orelse error.MissingToolVersion;
}

fn matchesVersion(output: []const u8, tool: []const u8, expected: []const u8) bool {
    const actual = std.mem.trim(u8, output, " \t\r\n");
    if (std.mem.eql(u8, tool, "zig")) return std.mem.eql(u8, actual, expected);
    if (!std.mem.startsWith(u8, actual, "jj ")) return false;
    const version = actual[3..];
    return std.mem.eql(u8, version, expected) or
        (std.mem.startsWith(u8, version, expected) and version.len > expected.len + 1 and version[expected.len] == '-');
}

fn verifyToolchain(ctx: *common.Context) !void {
    const pins = try ctx.read(".tool-versions");
    for ([_][]const u8{ "zig", "jujutsu" }, [_][]const u8{ "zig", "jj" }) |name, executable| {
        const expected = try pinnedVersion(pins, name);
        const output = try ctx.captureChecked(&.{ if (std.mem.eql(u8, executable, "zig")) ctx.envDefault("ZIG_BIN", "zig") else executable, if (std.mem.eql(u8, executable, "zig")) "version" else "--version" });
        if (!matchesVersion(output, executable, expected)) {
            try ctx.warn("Installed {s} version mismatch: expected {s}, got {s}\n", .{ name, expected, std.mem.trim(u8, output, " \t\r\n") });
            return error.ToolVersionMismatch;
        }
        try ctx.print("Using {s} {s}\n", .{ name, expected });
    }
}

fn initJujutsu(ctx: *common.Context) !void {
    const root = try ctx.capture(&.{ "jj", "root" });
    if (root.term.success()) return;
    if (ctx.exists(".jj")) return error.ExistingJujutsuRepositoryInvalid;
    const git_stat = std.Io.Dir.cwd().statFile(ctx.io, ".git", .{}) catch return error.MissingGitCheckout;
    if (git_stat.kind != .file and git_stat.kind != .directory) return error.MissingGitCheckout;
    try ctx.run(&.{ "jj", "git", "init", "--colocate" });
}

fn enableKvm(ctx: *common.Context) !void {
    if (!ctx.exists("/dev/kvm")) return ctx.print("KVM is unavailable; the QEMU harness will use software emulation.\n", .{});
    try ctx.run(&.{ "sudo", "chmod", "0666", "/dev/kvm" });
    try std.Io.Dir.cwd().access(ctx.io, "/dev/kvm", .{ .read = true, .write = true });
    try ctx.print("KVM acceleration is available.\n", .{});
}

const Firmware = struct { code: []const u8, vars: []const u8 };

fn secureBootFirmware(ctx: *common.Context, directory: []const u8) !Firmware {
    for ([_][]const u8{ "_4M", "" }) |suffix| {
        const code = try ctx.fmt("{s}/OVMF_CODE{s}.secboot.fd", .{ directory, suffix });
        const vars = try ctx.fmt("{s}/OVMF_VARS{s}.fd", .{ directory, suffix });
        const code_stat = std.Io.Dir.cwd().statFile(ctx.io, code, .{}) catch continue;
        const vars_stat = std.Io.Dir.cwd().statFile(ctx.io, vars, .{}) catch continue;
        if (code_stat.kind == .file and vars_stat.kind == .file) return .{ .code = code, .vars = vars };
    }
    return error.MissingSecureBootFirmwarePair;
}

fn append(ctx: *common.Context, path: []const u8, contents: []const u8) !void {
    try ctx.parent(path);
    const file = try std.Io.Dir.cwd().createFile(ctx.io, path, .{ .truncate = false });
    defer file.close(ctx.io);
    const stat = try file.stat(ctx.io);
    try file.writePositionalAll(ctx.io, contents, stat.size);
}

fn setupEfiTools(ctx: *common.Context) !void {
    const environment_path = ctx.env("GITHUB_ENV") orelse return error.MissingGithubEnvironmentFile;
    const firmware = try secureBootFirmware(ctx, "/usr/share/OVMF");
    try ctx.run(&.{ "python3", "-m", "venv", "build/efi-test-tools" });
    try ctx.run(&.{ "build/efi-test-tools/bin/pip", "install", "--disable-pip-version-check", "virt-firmware==26.9", "pefile==2024.8.26" });
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(ctx.io, "build/efi-test-tools/bin/virt-fw-vars", ctx.allocator);
    try append(ctx, environment_path, try ctx.fmt("EFI_VARS_TOOL={s}\nOVMF_SECURE_BOOT_CODE={s}\nOVMF_SECURE_BOOT_VARS={s}\n", .{ executable, firmware.code, firmware.vars }));
}

fn installLinters(ctx: *common.Context) !void {
    const directory = try ctx.tempDir("zigos-ci-linters");
    defer ctx.removeTree(directory) catch {};
    const zlint = try ctx.fmt("{s}/zlint", .{directory});
    const archive = try ctx.fmt("{s}/actionlint.tar.gz", .{directory});
    const actionlint = try ctx.fmt("{s}/actionlint", .{directory});
    try ctx.run(&.{ "curl", "-fsSL", "https://github.com/DonIsaac/zlint/releases/download/v0.7.9/zlint-linux-x86_64", "-o", zlint });
    try ctx.run(&.{ "install", zlint, "/usr/local/bin/zlint" });
    try ctx.run(&.{ "curl", "-fsSL", "https://github.com/rhysd/actionlint/releases/download/v1.7.11/actionlint_1.7.11_linux_amd64.tar.gz", "-o", archive });
    try ctx.run(&.{ "tar", "-xzf", archive, "-C", directory, "actionlint" });
    try ctx.run(&.{ "install", actionlint, "/usr/local/bin/actionlint" });
}

const fallback_summary = "## Command Summary\n\nThe command ended before it produced a validated summary.\n";

fn renderSummary(ctx: *common.Context, source: []const u8, destination: []const u8) !void {
    var contents = ctx.read(source) catch |err| switch (err) {
        error.FileNotFound => try ctx.allocator.dupe(u8, ""),
        else => return err,
    };
    if (contents.len == 0) {
        try ctx.write(source, fallback_summary);
        contents = try ctx.allocator.dupe(u8, fallback_summary);
    }
    try append(ctx, destination, contents);
}

test "CI toolchain pins reject missing and ambiguous versions" {
    const pins = "# tool versions\r\nzig\t0.17.0\r\njujutsu 0.43.0\n";
    try std.testing.expectEqualStrings("0.17.0", try pinnedVersion(pins, "zig"));
    try std.testing.expectEqualStrings("0.43.0", try pinnedVersion(pins, "jujutsu"));
    try std.testing.expectError(error.MissingToolVersion, pinnedVersion("zig\n", "zig"));
    try std.testing.expectError(error.MissingToolVersion, pinnedVersion(pins, "other"));
    try std.testing.expectError(error.AmbiguousToolVersion, pinnedVersion("zig 0.17.0\nzig 0.17.0\n", "zig"));
    try std.testing.expectError(error.AmbiguousToolVersion, pinnedVersion("zig 0.16.0 0.17.0\n", "zig"));
    try std.testing.expect(matchesVersion("0.17.0\n", "zig", "0.17.0"));
    try std.testing.expect(!matchesVersion("0.17.0-dev\n", "zig", "0.17.0"));
    try std.testing.expect(matchesVersion("jj 0.43.0\n", "jj", "0.43.0"));
    try std.testing.expect(matchesVersion("jj 0.43.0-release\n", "jj", "0.43.0"));
    try std.testing.expect(!matchesVersion("jj 0.43.01\n", "jj", "0.43.0"));
    try std.testing.expect(!matchesVersion("jj 0.43.0-\n", "jj", "0.43.0"));
}

test "CI firmware selection requires a matching pair and prefers 4M" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    const directory = try ctx.tempDir("zigos-ci-firmware-test");
    defer ctx.removeTree(directory) catch {};
    try ctx.write(try ctx.fmt("{s}/OVMF_CODE_4M.secboot.fd", .{directory}), "code");
    try ctx.write(try ctx.fmt("{s}/OVMF_VARS.fd", .{directory}), "vars");
    try std.testing.expectError(error.MissingSecureBootFirmwarePair, secureBootFirmware(&ctx, directory));
    const small_code = try ctx.fmt("{s}/OVMF_CODE.secboot.fd", .{directory});
    try ctx.write(small_code, "code");
    try std.testing.expectEqualStrings(small_code, (try secureBootFirmware(&ctx, directory)).code);
    const large_vars = try ctx.fmt("{s}/OVMF_VARS_4M.fd", .{directory});
    try ctx.mkdir(large_vars);
    try std.testing.expectEqualStrings(small_code, (try secureBootFirmware(&ctx, directory)).code);
    try ctx.removeTree(large_vars);
    try ctx.write(large_vars, "vars");
    try std.testing.expectEqualStrings(large_vars, (try secureBootFirmware(&ctx, directory)).vars);
}

test "CI summary preserves a validated report and appends fallback for missing or empty reports" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    const directory = try ctx.tempDir("zigos-ci-summary-test");
    defer ctx.removeTree(directory) catch {};
    const source = try ctx.fmt("{s}/nested/summary.md", .{directory});
    const destination = try ctx.fmt("{s}/github-summary.md", .{directory});
    try ctx.write(destination, "Existing summary\n");
    try renderSummary(&ctx, source, destination);
    try std.testing.expectEqualStrings(fallback_summary, try ctx.read(source));
    try std.testing.expectEqualStrings("Existing summary\n" ++ fallback_summary, try ctx.read(destination));
    try ctx.write(source, "Validated benchmark report\n");
    try renderSummary(&ctx, source, destination);
    try std.testing.expectEqualStrings("Validated benchmark report\n", try ctx.read(source));
    try std.testing.expectEqualStrings("Existing summary\n" ++ fallback_summary ++ "Validated benchmark report\n", try ctx.read(destination));
    try ctx.write(source, "");
    try renderSummary(&ctx, source, destination);
    try std.testing.expectEqualStrings(fallback_summary, try ctx.read(source));
}
