const std = @import("std");
const builtin = @import("builtin");
const common = @import("common.zig");

const Manager = enum { brew, apt, dnf, pacman };
const Privilege = enum { direct, sudo };
const Options = struct { check: bool = false, dry_run: bool = false, manager: ?Manager = null, repair_apt: bool = false, help: bool = false };
const Command = struct { argv: []const []const u8, fallback: bool = false };
const apt_options = [_][]const u8{ "-o", "Acquire::Retries=4", "-o", "Acquire::http::Timeout=30", "-o", "Acquire::https::Timeout=30", "-o", "Acquire::ForceIPv4=true" };
const apt_sources = [_][]const u8{ "/etc/apt/apt-mirrors.txt", "/etc/apt/sources.list", "/etc/apt/sources.list.d/ubuntu.sources" };
const ovmf_paths = [_][]const u8{
    "/usr/share/OVMF/OVMF_CODE.fd",              "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",         "/usr/share/edk2/ovmf/OVMF_CODE_4M.fd",
    "/usr/share/edk2/x64/OVMF_CODE.fd",          "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
    "/usr/share/qemu/edk2-x86_64-code.fd",       "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
    "/usr/local/share/qemu/edk2-x86_64-code.fd",
};

pub fn run(ctx: *common.Context, args: []const []const u8) !void {
    const options = try parseOptions(args);
    if (options.help) return ctx.print("Usage: zig build setup-deps -- [--check | --dry-run [--manager brew|apt|dnf|pacman]]\nRequires the preinstalled Zig that build.zig pins. --check verifies without installing.\n--dry-run prints command argv and native file repairs without changing the host.\n", .{});
    if (options.repair_apt) {
        if (builtin.os.tag != .linux or std.c.geteuid() != 0) return error.AptRepairRequiresRoot;
        return repairAptSources(ctx);
    }
    if (options.check) return verifyTools(ctx);

    const manager = options.manager orelse try detectManager(ctx);
    const privilege = planPrivilege(manager, std.c.geteuid() == 0, (try ctx.findExecutable("sudo")) != null or options.dry_run) catch |err| {
        try ctx.print("sudo is required when not running as root.\n", .{});
        return err;
    };
    const commands = try installPlan(ctx.allocator, manager, privilege);
    if (options.dry_run) {
        try ctx.print("Dependency installation plan ({s}); Zig is already installed.\n", .{@tagName(manager)});
        if (manager == .apt) try showAptRepair(ctx, privilege);
        for (commands) |command| try printCommand(ctx, command);
        try ctx.print("Then verify QEMU, xorriso, OVMF firmware, and the optional swtpm and Python tools.\n", .{});
        return;
    }

    try ctx.print("Installing dependencies with {s}...\n", .{@tagName(manager)});
    if (manager == .apt) {
        if (privilege == .direct) {
            try repairAptSources(ctx);
        } else {
            const executable = try std.process.executablePathAlloc(ctx.io, ctx.allocator);
            try ctx.run(&.{ "sudo", "--", executable, "setup-deps", "--repair-apt-sources" });
        }
    }
    var failed_fallback = false;
    for (commands) |command| {
        if (command.fallback and !failed_fallback) continue;
        ctx.run(command.argv) catch |err| {
            if (manager != .pacman or (!command.fallback and !std.mem.eql(u8, command.argv[command.argv.len - 1], "qemu-full"))) return err;
            if (std.mem.eql(u8, command.argv[command.argv.len - 1], "qemu")) return err;
            failed_fallback = true;
            continue;
        };
        failed_fallback = false;
    }
    try verifyTools(ctx);
    try ctx.print("Dependency setup complete.\n", .{});
}

fn parseOptions(args: []const []const u8) !Options {
    var options: Options = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--check")) options.check = true else if (std.mem.eql(u8, args[i], "--dry-run")) options.dry_run = true else if (std.mem.eql(u8, args[i], "--help")) options.help = true else if (std.mem.eql(u8, args[i], "--repair-apt-sources")) options.repair_apt = true else if (std.mem.eql(u8, args[i], "--manager")) {
            i += 1;
            if (i == args.len) return error.InvalidArguments;
            options.manager = std.meta.stringToEnum(Manager, args[i]) orelse return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    if (options.check and options.dry_run) return error.InvalidArguments;
    if (options.manager != null and !options.dry_run) return error.InvalidArguments;
    if (options.repair_apt and args.len != 1) return error.InvalidArguments;
    return options;
}

fn chooseManager(os: std.Target.Os.Tag, brew: bool, apt: bool, dnf: bool, pacman: bool) !Manager {
    return switch (os) {
        .macos => if (brew) .brew else error.HomebrewRequired,
        .linux => if (apt) .apt else if (dnf) .dnf else if (pacman) .pacman else error.UnsupportedPackageManager,
        else => error.UnsupportedOperatingSystem,
    };
}

fn detectManager(ctx: *common.Context) !Manager {
    return chooseManager(builtin.os.tag, (try ctx.findExecutable("brew")) != null, (try ctx.findExecutable("apt-get")) != null, (try ctx.findExecutable("dnf")) != null, (try ctx.findExecutable("pacman")) != null) catch |err| {
        switch (err) {
            error.HomebrewRequired => try ctx.print("Homebrew is required on macOS. Install from https://brew.sh\n", .{}),
            error.UnsupportedPackageManager => try ctx.print("Unsupported Linux package manager. Supported: apt, dnf, pacman.\n", .{}),
            else => try ctx.print("Unsupported OS: {s}\n", .{@tagName(builtin.os.tag)}),
        }
        return err;
    };
}

fn planPrivilege(manager: Manager, root: bool, sudo_available: bool) !Privilege {
    if (manager == .brew or root) return .direct;
    if (sudo_available) return .sudo;
    return error.SudoRequired;
}

fn plannedCommand(allocator: std.mem.Allocator, privilege: Privilege, base: []const []const u8, options: []const []const u8, packages: []const []const u8, fallback: bool) !Command {
    var argv = std.ArrayList([]const u8).empty;
    if (privilege == .sudo) try argv.append(allocator, "sudo");
    try argv.appendSlice(allocator, base);
    try argv.appendSlice(allocator, options);
    try argv.appendSlice(allocator, packages);
    return .{ .argv = try argv.toOwnedSlice(allocator), .fallback = fallback };
}

fn installPlan(allocator: std.mem.Allocator, manager: Manager, privilege: Privilege) ![]const Command {
    var commands = std.ArrayList(Command).empty;
    switch (manager) {
        .brew => try commands.append(allocator, try plannedCommand(allocator, .direct, &.{ "brew", "install" }, &.{}, &.{ "python", "qemu", "xorriso", "swtpm" }, false)),
        .apt => {
            try commands.append(allocator, try plannedCommand(allocator, privilege, &.{"apt-get"}, &apt_options, &.{"update"}, false));
            try commands.append(allocator, try plannedCommand(allocator, privilege, &.{"apt-get"}, &apt_options, &.{ "install", "-y", "python3", "python3-venv", "qemu-system-x86", "ovmf", "xorriso", "swtpm", "swtpm-tools" }, false));
        },
        .dnf => try commands.append(allocator, try plannedCommand(allocator, privilege, &.{ "dnf", "install", "-y" }, &.{}, &.{ "python3", "qemu-system-x86", "edk2-ovmf", "xorriso", "swtpm", "swtpm-tools" }, false)),
        .pacman => {
            try commands.append(allocator, try plannedCommand(allocator, privilege, &.{ "pacman", "-Sy", "--noconfirm" }, &.{}, &.{ "python", "edk2-ovmf", "xorriso", "swtpm" }, false));
            for ([_][]const u8{ "qemu-full", "qemu-desktop", "qemu" }, 0..) |package, i| try commands.append(allocator, try plannedCommand(allocator, privilege, &.{ "pacman", "-S", "--noconfirm" }, &.{}, &.{package}, i != 0));
        },
    }
    return commands.toOwnedSlice(allocator);
}

fn printCommand(ctx: *common.Context, step: Command) !void {
    try ctx.print("{s}{s}\n", .{ if (step.fallback) "If previous QEMU package fails: " else "Run: ", try std.json.Stringify.valueAlloc(ctx.allocator, step.argv, .{}) });
}

fn showAptRepair(ctx: *common.Context, privilege: Privilege) !void {
    if (privilege == .sudo) try printCommand(ctx, .{ .argv = &.{ "sudo", "--", try std.process.executablePathAlloc(ctx.io, ctx.allocator), "setup-deps", "--repair-apt-sources" } });
    try ctx.print("Native file repair, when files exist:\n  {s}: remove lines containing azure.archive.ubuntu.com\n", .{apt_sources[0]});
    for (apt_sources[1..]) |path| try ctx.print("  {s}: replace http://azure.archive.ubuntu.com/ubuntu with https://archive.ubuntu.com/ubuntu\n", .{path});
}

fn rewriteApt(allocator: std.mem.Allocator, original: []const u8, mirror_list: bool) ![]const u8 {
    if (!mirror_list) return std.mem.replaceOwned(u8, allocator, original, "http://azure.archive.ubuntu.com/ubuntu", "https://archive.ubuntu.com/ubuntu");
    var output = std.ArrayList(u8).empty;
    var offset: usize = 0;
    while (offset < original.len) {
        const end = if (std.mem.indexOfScalarPos(u8, original, offset, '\n')) |i| i + 1 else original.len;
        const line = original[offset..end];
        if (std.mem.indexOf(u8, line, "azure.archive.ubuntu.com") == null) try output.appendSlice(allocator, line);
        offset = end;
    }
    return output.toOwnedSlice(allocator);
}

fn repairAptFile(ctx: *common.Context, path: []const u8, mirror_list: bool) !bool {
    const original = ctx.read(path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    const replacement = try rewriteApt(ctx.allocator, original, mirror_list);
    if (std.mem.eql(u8, original, replacement)) return false;
    const stat = try std.Io.Dir.cwd().statFile(ctx.io, path, .{});
    if (stat.kind != .file) return error.NotRegularFile;
    var atomic = try std.Io.Dir.cwd().createFileAtomic(ctx.io, path, .{ .replace = true, .permissions = stat.permissions });
    defer atomic.deinit(ctx.io);
    try atomic.file.writeStreamingAll(ctx.io, replacement);
    try atomic.file.setPermissions(ctx.io, stat.permissions);
    try atomic.file.sync(ctx.io);
    try atomic.replace(ctx.io);
    return true;
}

fn repairAptSources(ctx: *common.Context) !void {
    for (apt_sources, 0..) |path, i| if (try repairAptFile(ctx, path, i == 0)) try ctx.print("Repaired apt source: {s}\n", .{path});
}

fn regularFile(ctx: *common.Context, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(ctx.io, path, .{}) catch return false;
    return stat.kind == .file;
}

fn firstRegularFile(ctx: *common.Context, override: ?[]const u8, candidates: []const []const u8) ?[]const u8 {
    if (override) |path| if (path.len != 0 and regularFile(ctx, path)) return path;
    for (candidates) |path| if (regularFile(ctx, path)) return path;
    return null;
}

const OptionalTool = struct { name: []const u8, purpose: []const u8 };
const optional_tools = [_]OptionalTool{
    .{ .name = "swtpm", .purpose = "TPM QEMU tests" },
    .{ .name = "swtpm_setup", .purpose = "TPM QEMU tests" },
    .{ .name = "python3", .purpose = "the isolated virt-fw-vars tool used by unified-efi-qemu-test" },
};

fn verifyTools(ctx: *common.Context) !void {
    try ctx.print("Verifying toolchain...\n", .{});
    var missing = false;
    for ([_][]const u8{ "qemu-system-x86_64", "xorriso" }) |name| if ((try ctx.findExecutable(name)) == null) {
        try ctx.print("Missing command: {s}\n", .{name});
        missing = true;
    };
    if (firstRegularFile(ctx, ctx.env("OVMF_CODE"), &ovmf_paths)) |path| try ctx.print("Using OVMF firmware: {s}\n", .{path}) else {
        try ctx.print("Missing OVMF firmware. Install OVMF/edk2-ovmf or set OVMF_CODE for uefi-qemu-test.\n", .{});
        missing = true;
    }
    for (optional_tools) |tool| if ((try ctx.findExecutable(tool.name)) == null) {
        try ctx.print("Optional command {s} is missing; it is needed only for {s}.\n", .{ tool.name, tool.purpose });
    };
    if (missing) {
        try ctx.print("Dependency verification completed with missing tools.\n", .{});
        return error.MissingDependencies;
    }
    try ctx.print("Using Zig: {s}\nDependency verification passed.\n", .{builtin.zig_version_string});
}

test "dependency options restrict manager overrides to harmless plans" {
    try std.testing.expect((try parseOptions(&.{"--check"})).check);
    try std.testing.expectEqual(Manager.apt, (try parseOptions(&.{ "--dry-run", "--manager", "apt" })).manager.?);
    try std.testing.expectError(error.InvalidArguments, parseOptions(&.{ "--manager", "apt" }));
    try std.testing.expectError(error.InvalidArguments, parseOptions(&.{ "--check", "--dry-run" }));
    try std.testing.expectError(error.InvalidArguments, parseOptions(&.{ "--dry-run", "--manager", "unknown" }));
    try std.testing.expectError(error.InvalidArguments, parseOptions(&.{ "--repair-apt-sources", "--check" }));
}

test "package manager discovery and privilege planning preserve platform precedence" {
    try std.testing.expectEqual(Manager.brew, try chooseManager(.macos, true, true, true, true));
    try std.testing.expectEqual(Manager.apt, try chooseManager(.linux, false, true, true, true));
    try std.testing.expectEqual(Manager.dnf, try chooseManager(.linux, false, false, true, true));
    try std.testing.expectEqual(Manager.pacman, try chooseManager(.linux, false, false, false, true));
    try std.testing.expectError(error.HomebrewRequired, chooseManager(.macos, false, true, true, true));
    try std.testing.expectError(error.UnsupportedPackageManager, chooseManager(.linux, false, false, false, false));
    try std.testing.expectError(error.UnsupportedOperatingSystem, chooseManager(.windows, true, true, true, true));
    try std.testing.expectEqual(Privilege.direct, try planPrivilege(.brew, false, false));
    try std.testing.expectEqual(Privilege.direct, try planPrivilege(.apt, true, false));
    try std.testing.expectEqual(Privilege.sudo, try planPrivilege(.dnf, false, true));
    try std.testing.expectError(error.SudoRequired, planPrivilege(.pacman, false, false));
}

test "installer argv preserve packages apt retry flags and pacman fallbacks without installing Zig" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const apt = try installPlan(arena.allocator(), .apt, .sudo);
    try std.testing.expectEqualStrings("sudo", apt[0].argv[0]);
    try std.testing.expectEqualStrings("apt-get", apt[0].argv[1]);
    try std.testing.expectEqualSlices([]const u8, &apt_options, apt[0].argv[2..10]);
    try std.testing.expectEqualStrings("update", apt[0].argv[10]);
    try std.testing.expectEqualSlices([]const u8, &.{ "install", "-y", "python3", "python3-venv", "qemu-system-x86", "ovmf", "xorriso", "swtpm", "swtpm-tools" }, apt[1].argv[10..]);
    const pacman = try installPlan(arena.allocator(), .pacman, .direct);
    try std.testing.expectEqual(@as(usize, 4), pacman.len);
    try std.testing.expect(!pacman[1].fallback and pacman[2].fallback and pacman[3].fallback);
    try std.testing.expectEqualStrings("qemu-full", pacman[1].argv[3]);
    try std.testing.expectEqualStrings("qemu-desktop", pacman[2].argv[3]);
    try std.testing.expectEqualStrings("qemu", pacman[3].argv[3]);
    for ([_]Manager{ .brew, .apt, .dnf, .pacman }) |manager| {
        for (try installPlan(arena.allocator(), manager, .sudo)) |step| {
            for (step.argv) |word| {
                try std.testing.expect(!std.mem.eql(u8, word, "zig"));
                try std.testing.expect(!std.mem.eql(u8, word, "bash"));
                try std.testing.expect(!std.mem.eql(u8, word, "sh"));
            }
            if (manager == .brew) try std.testing.expectEqualStrings("brew", step.argv[0]);
        }
    }
}

test "apt repair removes Azure mirror lines and replaces every source occurrence without altering line endings" {
    const allocator = std.testing.allocator;
    const mirrors = try rewriteApt(allocator, "https://archive.ubuntu.com/ubuntu\r\nhttp://azure.archive.ubuntu.com/ubuntu\r\n# azure.archive.ubuntu.com\nhttps://security.ubuntu.com/ubuntu", true);
    defer allocator.free(mirrors);
    try std.testing.expectEqualStrings("https://archive.ubuntu.com/ubuntu\r\nhttps://security.ubuntu.com/ubuntu", mirrors);
    const sources = try rewriteApt(allocator, "URIs: http://azure.archive.ubuntu.com/ubuntu\r\n# http://azure.archive.ubuntu.com/ubuntu\nSuites: noble\n", false);
    defer allocator.free(sources);
    try std.testing.expectEqualStrings("URIs: https://archive.ubuntu.com/ubuntu\r\n# https://archive.ubuntu.com/ubuntu\nSuites: noble\n", sources);
}

test "native apt repair only replaces changed fixture files and retains permissions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    const temporary = try ctx.tempDir("zigos-apt-repair-test");
    defer ctx.removeTree(temporary) catch {};
    const path = try ctx.fmt("{s}/ubuntu.sources", .{temporary});
    try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = path, .data = "URIs: http://azure.archive.ubuntu.com/ubuntu\n", .flags = .{ .permissions = .fromMode(0o640) } });
    try std.testing.expect(try repairAptFile(&ctx, path, false));
    try std.testing.expectEqualStrings("URIs: https://archive.ubuntu.com/ubuntu\n", try ctx.read(path));
    try std.testing.expectEqual(@as(u32, 0o640), (try std.Io.Dir.cwd().statFile(ctx.io, path, .{})).permissions.toMode() & 0o777);
    const before = try std.Io.Dir.cwd().statFile(ctx.io, path, .{});
    try std.testing.expect(!try repairAptFile(&ctx, path, false));
    try std.testing.expectEqual(before.inode, (try std.Io.Dir.cwd().statFile(ctx.io, path, .{})).inode);
    try std.testing.expect(!try repairAptFile(&ctx, try ctx.fmt("{s}/missing", .{temporary}), false));
}

test "OVMF discovery honors existing overrides and rejects directories" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    const temporary = try ctx.tempDir("zigos-dependency-discovery-test");
    defer ctx.removeTree(temporary) catch {};
    const firmware = try ctx.fmt("{s}/firmware.fd", .{temporary});
    const override = try ctx.fmt("{s}/override.fd", .{temporary});
    try ctx.write(firmware, "firmware");
    try ctx.write(override, "override");
    try std.testing.expectEqualStrings(override, firstRegularFile(&ctx, override, &.{firmware}).?);
    try std.testing.expectEqualStrings(firmware, firstRegularFile(&ctx, temporary, &.{firmware}).?);
    try std.testing.expect(firstRegularFile(&ctx, "missing", &.{temporary}) == null);
}
