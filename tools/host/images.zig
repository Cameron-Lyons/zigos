const std = @import("std");
const common = @import("common.zig");

pub fn run(ctx: *common.Context, command: []const u8, args: []const []const u8) !void {
    if (std.mem.eql(u8, command, "clean-build")) return clean(ctx, args);
    if (std.mem.eql(u8, command, "build-native-store")) return store(ctx, args);
    if (std.mem.eql(u8, command, "build-efi-iso")) return efiIso(ctx, args);
    if (std.mem.eql(u8, command, "build-grub-iso")) return grubIso(ctx, args);
    if (std.mem.eql(u8, command, "test-production-boot-log-checker")) {
        try productionLogFixtures();
        return ctx.print("Production boot log checker self-test: PASS\n", .{});
    }
    try common.requireArgs(args, 1, 1);
    const stat = try std.Io.Dir.cwd().statFile(ctx.io, args[0], .{});
    if (stat.kind != .file or stat.size == 0) return error.ExpectedNonemptyRegularFile;
    const bytes = try ctx.read(args[0]);
    if (std.mem.eql(u8, command, "check-efi-image")) {
        try validateEfi(bytes);
        return ctx.print("EFI PE/COFF image header validated: {s}\n", .{args[0]});
    }
    if (std.mem.eql(u8, command, "check-multiboot2-image")) {
        try validateElf(bytes);
        return ctx.print("ELF64 long-mode kernel image validated: {s}\n", .{args[0]});
    }
    if (std.mem.eql(u8, command, "check-production-boot-log")) {
        try validateProductionBootLog(bytes);
        return ctx.print("Production boot log ordering OK: {s}\n", .{args[0]});
    }
    return error.UnknownCommand;
}

fn clean(ctx: *common.Context, args: []const []const u8) !void {
    var dry_run = false;
    for (args) |value| {
        if (std.mem.eql(u8, value, "--dry-run") or std.mem.eql(u8, value, "-n")) {
            dry_run = true;
        } else if (std.mem.eql(u8, value, "--help") or std.mem.eql(u8, value, "-h")) {
            return ctx.print("Usage: zig build clean [-Dclean-dry-run=true]\nRemoves build/, zig-out/, .zig-cache/, zig-cache/.\n", .{});
        } else return error.InvalidArguments;
    }
    for ([_][]const u8{ "build", "zig-out", ".zig-cache", "zig-cache" }) |path| {
        // lstat sees dangling links too; deleteTree removes links without
        // traversing them. Only these fixed repository-relative paths are used.
        _ = std.Io.Dir.cwd().statFile(ctx.io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => {
                try ctx.print("Already clean: {s}\n", .{path});
                continue;
            },
            else => return err,
        };
        if (dry_run) {
            try ctx.print("Would remove: {s}\n", .{path});
        } else {
            try ctx.removeTree(path);
            try ctx.print("Removed: {s}\n", .{path});
        }
    }
}

fn store(ctx: *common.Context, args: []const []const u8) !void {
    try common.requireArgs(args, 0, 3);
    const path = common.arg(args, 0, "build/native-store.img");
    const size = try std.fmt.parseInt(u64, common.arg(args, 1, "8"), 10);
    const bytes = try std.math.mul(u64, size, 1024 * 1024);
    const mode = common.arg(args, 2, "preserve");
    if (!std.mem.eql(u8, mode, "preserve") and !std.mem.eql(u8, mode, "reset")) return error.InvalidArguments;
    try ctx.parent(path);
    if (std.mem.eql(u8, mode, "reset")) try ctx.removeFile(path);
    const file = try std.Io.Dir.cwd().createFile(ctx.io, path, .{ .truncate = false, .read = true });
    defer file.close(ctx.io);
    const stat = try file.stat(ctx.io);
    if (stat.kind != .file) return error.NotRegularFile;
    if (stat.size < bytes or std.mem.eql(u8, mode, "reset")) try file.setLength(ctx.io, bytes);
}

pub fn validateEfi(bytes: []const u8) !void {
    if (bytes.len < 64 or !std.mem.eql(u8, bytes[0..2], "MZ")) return error.InvalidMzHeader;
    const pe_offset = std.mem.readInt(u32, bytes[60..64], .little);
    if (pe_offset > bytes.len or bytes.len - pe_offset < 4 or !std.mem.eql(u8, bytes[pe_offset..][0..4], "PE\x00\x00")) return error.InvalidPeHeader;
}

pub fn validateElf(bytes: []const u8) !void {
    if (bytes.len < 64 or !std.mem.eql(u8, bytes[0..4], "\x7fELF") or bytes[4] != 2) return error.ExpectedElf64;
    if (bytes[5] != 1 or bytes[6] != 1 or std.mem.readInt(u16, bytes[18..20], .little) != 62) return error.ExpectedX86_64;
    if (std.mem.readInt(u32, bytes[20..24], .little) != 1 or std.mem.readInt(u16, bytes[52..54], .little) != 64) return error.InvalidElfHeader;
}

pub fn validateProductionBootLog(bytes: []const u8) !void {
    if (bytes.len == 0) return error.EmptyProductionLog;
    const checkpoint = "ZIGOS:STORAGE:CHECKPOINT:FINAL";
    const checkpoint_start = checkpoint ++ " enabled=true dirty=false generation=";
    const checkpoint_end = " error=none";
    const task = "ZIGOS:TASK:SESSION_READY";
    const ready = "ZIGOS:NATIVE:READY";
    var counts = [_]usize{ 0, 0, 0 };
    var positions = [_]usize{ 0, 0, 0 };
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var number: usize = 0;
    while (lines.next()) |line| {
        number += 1;
        for ([_][]const u8{ checkpoint, task, ready }, 0..) |prefix, index| {
            if (!std.mem.startsWith(u8, line, prefix)) continue;
            counts[index] += 1;
            positions[index] = number;
            if (index == 0) {
                if (!std.mem.startsWith(u8, line, checkpoint_start) or !std.mem.endsWith(u8, line, checkpoint_end) or line.len <= checkpoint_start.len + checkpoint_end.len) return error.InvalidProductionCheckpoint;
                const generation = line[checkpoint_start.len .. line.len - checkpoint_end.len];
                if (generation[0] < '1' or generation[0] > '9') return error.InvalidProductionCheckpoint;
                for (generation) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidProductionCheckpoint;
            } else if (!std.mem.eql(u8, line, prefix)) return error.InvalidProductionReadyMarker;
        }
    }
    for (counts) |count| if (count != 1) return error.ProductionMarkerCount;
    if (!(positions[0] < positions[1] and positions[1] < positions[2])) return error.ProductionMarkerOrder;
}

pub fn sourceDateEpoch(raw: []const u8) !u64 {
    if (raw.len == 0 or raw.len > 10) return error.InvalidSourceDateEpoch;
    for (raw) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidSourceDateEpoch;
    const value = try std.fmt.parseInt(u64, raw, 10);
    if (value > 4354819199) return error.InvalidSourceDateEpoch;
    return @max(value, 315532800);
}

fn checkedReport(ctx: *common.Context, args: []const []const u8) ![]const u8 {
    const result = try ctx.capture(args);
    if (!result.term.success()) {
        std.debug.print("{s}{s}", .{ result.stdout, result.stderr });
        return error.BootMediaInspectionFailed;
    }
    return ctx.fmt("{s}{s}", .{ result.stdout, result.stderr });
}

/// deleteTree accepts '.', unlike rm. Refuse the checkout, filesystem root,
/// and checkout ancestors before clearing a caller-supplied staging directory.
pub fn validateStagingDirectory(allocator: std.mem.Allocator, cwd: []const u8, path: []const u8) ![]const u8 {
    if (path.len == 0) return error.UnsafeStagingDirectory;
    const absolute = try std.fs.path.resolve(allocator, &.{ cwd, path });
    if (std.mem.eql(u8, absolute, "/") or std.mem.eql(u8, absolute, cwd) or
        (std.mem.startsWith(u8, cwd, absolute) and cwd.len > absolute.len and cwd[absolute.len] == '/')) return error.UnsafeStagingDirectory;
    return absolute;
}

fn prepareStaging(ctx: *common.Context, path: []const u8, input_paths: []const []const u8) !void {
    const cwd = try std.process.currentPathAlloc(ctx.io, ctx.allocator);
    const absolute = try validateStagingDirectory(ctx.allocator, cwd, path);
    const existing = std.Io.Dir.cwd().realPathFileAlloc(ctx.io, path, ctx.allocator) catch |err| switch (err) {
        error.FileNotFound => absolute,
        else => return err,
    };
    _ = try validateStagingDirectory(ctx.allocator, cwd, existing);
    for (input_paths) |input| {
        if (input.len == 0) continue;
        const resolved = try std.Io.Dir.cwd().realPathFileAlloc(ctx.io, input, ctx.allocator);
        if (std.mem.eql(u8, resolved, existing) or (std.mem.startsWith(u8, resolved, existing) and resolved.len > existing.len and resolved[existing.len] == '/')) return error.StagingContainsInput;
    }
    try ctx.removeTree(path);
}

pub fn validateElTorito(report: []const u8) !void {
    var lines = std.mem.splitScalar(u8, report, '\n');
    var bootable: usize = 0;
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        var tokens: [8][]const u8 = undefined;
        var count: usize = 0;
        while (fields.next()) |token| {
            if (count == tokens.len) break;
            tokens[count] = token;
            count += 1;
        }
        if (count != 8 or !std.mem.eql(u8, tokens[0], "El") or !std.mem.eql(u8, tokens[1], "Torito") or !std.mem.eql(u8, tokens[2], "boot") or !std.mem.eql(u8, tokens[3], "img") or !std.mem.eql(u8, tokens[4], ":") or !std.mem.eql(u8, tokens[7], "y")) continue;
        if (!std.mem.eql(u8, tokens[6], "UEFI")) return error.NonUefiBootImage;
        bootable += 1;
    }
    if (bootable == 0) return error.MissingUefiBootImage;
}

fn efiIso(ctx: *common.Context, args: []const []const u8) !void {
    try common.requireArgs(args, 3, 4);
    // Rock Ridge stores staging permissions. Match the original media builder
    // regardless of the caller's umask, including child mtools/xorriso creation.
    const previous_umask = std.c.umask(0o022);
    defer _ = std.c.umask(previous_umask);
    const epoch = try sourceDateEpoch(common.arg(args, 3, ctx.envDefault("SOURCE_DATE_EPOCH", "315532800")));
    try ctx.environ.put("SOURCE_DATE_EPOCH", try ctx.fmt("{d}", .{epoch}));
    try ctx.environ.put("TZ", "UTC");
    try validateEfi(try ctx.read(args[0]));
    for ([_][]const u8{ "xorriso", "mformat", "mcopy", "mmd" }) |name| if (try ctx.findExecutable(name) == null) return error.MissingMediaTool;
    try prepareStaging(ctx, args[2], &.{args[0]});
    const staged = try ctx.fmt("{s}/EFI/BOOT/BOOTX64.EFI", .{args[2]});
    try ctx.copy(args[0], staged);
    const efi_file = try std.Io.Dir.cwd().openFile(ctx.io, staged, .{});
    defer efi_file.close(ctx.io);
    try efi_file.setPermissions(ctx.io, .fromMode(0o644));
    try ctx.parent(args[1]);
    const esp = try ctx.fmt("{s}/esp.img", .{args[2]});
    try store(ctx, &.{ esp, "40", "reset" });
    try ctx.run(&.{ "mformat", "-i", esp, "-N", "0", "-v", "ZIGOS", "::" });
    try ctx.run(&.{ "mmd", "-i", esp, "::/EFI", "::/EFI/BOOT" });
    try ctx.run(&.{ "mcopy", "-i", esp, staged, "::/EFI/BOOT/BOOTX64.EFI" });
    try ctx.run(&.{ "xorriso", "-as", "mkisofs", "-R", "-J", "-uid", "0", "-gid", "0", "-e", "esp.img", "-no-emul-boot", "--set_all_file_dates", try ctx.fmt("={d}", .{epoch}), "-o", args[1], args[2] });
    try validateElTorito(try checkedReport(ctx, &.{ "xorriso", "-indev", args[1], "-report_el_torito", "plain" }));
    try ctx.print("Validated x86-64 UEFI native boot media: {s}\n", .{args[1]});
}

fn grubIso(ctx: *common.Context, args: []const []const u8) !void {
    try common.requireArgs(args, 3, 5);
    const config = common.arg(args, 3, "src/boot/grub-x86_64-kernel.cfg");
    const stub = common.arg(args, 4, "");
    if (!ctx.exists(config) or !ctx.exists(stub)) return error.MissingGrubInput;
    var rescue: ?[]const u8 = ctx.env("GRUB_MKRESCUE");
    if (rescue == null or rescue.?.len == 0) {
        rescue = try ctx.findExecutable("x86_64-elf-grub-mkrescue");
        if (rescue == null) rescue = try ctx.findExecutable("grub-mkrescue");
    }
    const executable = rescue orelse return error.MissingGrubMkrescue;
    var module_dir: ?[]const u8 = ctx.env("GRUB_MODULE_DIR");
    if (module_dir == null or module_dir.?.len == 0) {
        const path = (try ctx.findExecutable(executable)) orelse return error.MissingGrubMkrescue;
        const bin = std.mem.indexOf(u8, path, "/bin/") orelse path.len;
        const candidate = try ctx.fmt("{s}/lib/x86_64-elf/grub/x86_64-efi", .{path[0..bin]});
        for ([_][]const u8{ candidate, "/usr/lib/grub/x86_64-efi", "/usr/lib64/grub/x86_64-efi", "/usr/share/grub/x86_64-efi" }) |directory| {
            if (ctx.exists(try ctx.fmt("{s}/modinfo.sh", .{directory}))) {
                module_dir = directory;
                break;
            }
        }
    }
    const modules = module_dir orelse return error.MissingGrubEfiModules;
    if (!ctx.exists(try ctx.fmt("{s}/modinfo.sh", .{modules}))) return error.MissingGrubEfiModules;
    for ([_][]const u8{ "xorriso", "mformat" }) |name| if (try ctx.findExecutable(name) == null) return error.MissingMediaTool;
    try prepareStaging(ctx, args[2], &.{ args[0], config, stub });
    try ctx.copy(args[0], try ctx.fmt("{s}/boot/kernel.elf", .{args[2]}));
    try ctx.copy(config, try ctx.fmt("{s}/boot/grub/grub.cfg", .{args[2]}));
    try ctx.copy(stub, try ctx.fmt("{s}/EFI/BOOT/BOOTX64.EFI", .{args[2]}));
    try ctx.parent(args[1]);
    try ctx.run(&.{ executable, "--directory", modules, "-o", args[1], args[2] });
    try validateElTorito(try checkedReport(ctx, &.{ "xorriso", "-indev", args[1], "-report_el_torito", "plain" }));
    const report = try checkedReport(ctx, &.{ "xorriso", "-report_about", "SORRY", "-indev", args[1], "-find", "/boot/grub/x86_64-efi", "-type", "d", "-exec", "echo", "--" });
    if (std.mem.indexOf(u8, report, "'/boot/grub/x86_64-efi'") == null) return error.MissingGrubEfiModules;
    try ctx.print("Validated x86-64 UEFI boot media: {s}\n", .{args[1]});
}

const valid_log = "BOOT:ROLE:production\nZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none\nZIGOS:TASK:SESSION_READY\nZIGOS:NATIVE:READY\n";

fn productionLogFixtures() !void {
    try validateProductionBootLog(valid_log);
    const invalid = [_][]const u8{
        "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=0 error=none\nZIGOS:TASK:SESSION_READY\nZIGOS:NATIVE:READY\n",
        "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=DiskFault\nZIGOS:TASK:SESSION_READY\nZIGOS:NATIVE:READY\n",
        "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none forged\nZIGOS:TASK:SESSION_READY\nZIGOS:NATIVE:READY\n",
        "ZIGOS:TASK:SESSION_READY\nZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none\nZIGOS:NATIVE:READY\n",
        "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none\nZIGOS:TASK:SESSION_READY forged\nZIGOS:NATIVE:READY\n",
        "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none\nZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=4 error=none\nZIGOS:TASK:SESSION_READY\nZIGOS:NATIVE:READY\n",
        "# ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none\n# ZIGOS:TASK:SESSION_READY\n# ZIGOS:NATIVE:READY\n",
        "",
    };
    for (invalid) |bytes| {
        if (validateProductionBootLog(bytes)) |_| return error.InvalidFixtureAccepted else |_| {}
    }
}

test "production log preserves exact checkpoint, duplicate and ordering fixtures" {
    try productionLogFixtures();
}

test "EFI offsets cannot read beyond truncated or malformed input" {
    var bytes: [80]u8 = @splat(0);
    @memcpy(bytes[0..2], "MZ");
    std.mem.writeInt(u32, bytes[60..64], 64, .little);
    @memcpy(bytes[64..68], "PE\x00\x00");
    try validateEfi(&bytes);
    try std.testing.expectError(error.InvalidPeHeader, validateEfi(bytes[0..66]));
    std.mem.writeInt(u32, bytes[60..64], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidPeHeader, validateEfi(&bytes));
}

test "media epochs preserve FAT bounds and reject invalid decimal seconds" {
    try std.testing.expectEqual(@as(u64, 315532800), try sourceDateEpoch("0"));
    try std.testing.expectEqual(@as(u64, 4354819199), try sourceDateEpoch("4354819199"));
    for ([_][]const u8{ "", "-1", "1x", "4354819200", "00000000000" }) |value| try std.testing.expectError(error.InvalidSourceDateEpoch, sourceDateEpoch(value));
}

test "boot media rejects mixed BIOS/UEFI and missing boot images" {
    try validateElTorito("El Torito boot img : 1 UEFI y none 0 1 100\n");
    try std.testing.expectError(error.NonUefiBootImage, validateElTorito("El Torito boot img : 1 UEFI y\nEl Torito boot img : 2 BIOS y\n"));
    try std.testing.expectError(error.MissingUefiBootImage, validateElTorito("El Torito boot img : 1 UEFI n\n"));
}

test "native store preserves data, grows without shrinking and resets to zero" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    const temporary = try ctx.tempDir("zigos-store-test");
    defer ctx.removeTree(temporary) catch {};
    const path = try ctx.fmt("{s}/store.img", .{temporary});
    try ctx.write(path, "persisted");
    try store(&ctx, &.{ path, "1", "preserve" });
    const file = try std.Io.Dir.cwd().openFile(ctx.io, path, .{});
    defer file.close(ctx.io);
    var bytes: [9]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 9), try file.readPositionalAll(ctx.io, &bytes, 0));
    try std.testing.expectEqualStrings("persisted", &bytes);
    try store(&ctx, &.{ path, "0", "preserve" });
    try std.testing.expectEqual(@as(u64, 1024 * 1024), (try file.stat(ctx.io)).size);
    try store(&ctx, &.{ path, "1", "reset" });
    const reset = try std.Io.Dir.cwd().openFile(ctx.io, path, .{});
    defer reset.close(ctx.io);
    _ = try reset.readPositionalAll(ctx.io, &bytes, 0);
    try std.testing.expectEqualSlices(u8, &@as([9]u8, @splat(0)), &bytes);
}

test "media cleanup rejects checkout and ancestor paths before deletion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ "", ".", "..", "/", "/repo", "staging/..", "/repo/../" }) |path| {
        try std.testing.expectError(error.UnsafeStagingDirectory, validateStagingDirectory(arena.allocator(), "/repo", path));
    }
    try std.testing.expectEqualStrings("/repo/build/staging", try validateStagingDirectory(arena.allocator(), "/repo", "build/staging"));
    try std.testing.expectEqualStrings("/repo-sibling", try validateStagingDirectory(arena.allocator(), "/repo", "/repo-sibling"));
}
