const std = @import("std");
const common = @import("../common.zig");
const catalog = @import("release_catalog");

pub const Context = common.Context;
pub const metadata_limit = 16 * 1024 * 1024;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn required(ctx: *Context, name: []const u8) ![]const u8 {
    const value = ctx.env(name) orelse return error.MissingReleaseEnvironment;
    if (value.len == 0) return error.MissingReleaseEnvironment;
    return value;
}

pub fn absolute(value: []const u8) !void {
    if (!std.fs.path.isAbsolute(value)) return error.ReleasePathMustBeAbsolute;
}

pub fn requireHash(value: []const u8) !void {
    if (value.len != 64) return error.InvalidReleaseHash;
    for (value) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidReleaseHash;
}

pub fn positive(value: []const u8) !u64 {
    if (value.len == 0 or value[0] == '0') return error.InvalidReleaseInteger;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidReleaseInteger;
    return std.fmt.parseInt(u64, value, 10) catch return error.InvalidReleaseInteger;
}

pub fn canonical(ctx: *Context, path: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().realPathFileAlloc(ctx.io, path, ctx.allocator);
}

pub fn contained(root: []const u8, path: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (root.len == path.len) return true;
    return root.len != 0 and (std.fs.path.isSep(root[root.len - 1]) or std.fs.path.isSep(path[root.len]));
}

pub fn rootPath(ctx: *Context) ![]const u8 {
    return canonical(ctx, ".");
}

pub fn regular(ctx: *Context, path: []const u8, executable: bool) !void {
    const stat = try std.Io.Dir.cwd().statFile(ctx.io, path, .{ .follow_symlinks = false });
    if (stat.kind != .file) return error.ReleaseFileMustBeRegular;
    if (executable and stat.permissions.toMode() & 0o111 == 0) return error.ReleaseVerifierMustBeExecutable;
}

pub fn containedFile(ctx: *Context, root: []const u8, relative: []const u8) !std.Io.File {
    if (!catalog.isSafeRelativePath(relative)) return error.UnsafeReleasePath;
    var dir = try std.Io.Dir.cwd().openDir(ctx.io, root, .{ .follow_symlinks = false });
    defer dir.close(ctx.io);
    const path = try ctx.fmt("{s}/{s}", .{ root, relative });
    try regular(ctx, path, false);
    const resolved = try canonical(ctx, path);
    if (!contained(root, resolved) or std.mem.eql(u8, root, resolved)) return error.ReleasePathEscapesRoot;
    return dir.openFile(ctx.io, relative, .{ .follow_symlinks = false, .resolve_beneath = true });
}

pub fn readContained(ctx: *Context, root: []const u8, relative: []const u8) ![]u8 {
    var file = try containedFile(ctx, root, relative);
    defer file.close(ctx.io);
    var reader = file.reader(ctx.io, &.{});
    return reader.interface.allocRemaining(ctx.allocator, .limited(metadata_limit)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => return err,
    };
}

pub const Record = struct { path: []const u8, sha256: []const u8, sizeBytes: u64 };

pub fn measure(ctx: *Context, root: []const u8, relative: []const u8) !Record {
    var file = try containedFile(ctx, root, relative);
    defer file.close(ctx.io);
    const stat = try file.stat(ctx.io);
    if (stat.kind != .file) return error.ReleaseFileMustBeRegular;
    var hash = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const amount = try file.readPositionalAll(ctx.io, &buffer, offset);
        if (amount == 0) break;
        hash.update(buffer[0..amount]);
        offset += amount;
    }
    return .{ .path = relative, .sha256 = try ctx.allocator.dupe(u8, &std.fmt.bytesToHex(hash.finalResult(), .lower)), .sizeBytes = stat.size };
}

pub fn records(ctx: *Context, root: []const u8, paths: []const []const u8) ![]Record {
    const result = try ctx.allocator.alloc(Record, paths.len);
    for (paths, result) |path, *record| record.* = try measure(ctx, root, path);
    return result;
}

pub fn outputPath(ctx: *Context, relative: []const u8, create: bool) ![]const u8 {
    if (!std.mem.startsWith(u8, relative, "build/") or !catalog.isSafeRelativePath(relative)) return error.UnsafeReleaseOutputPath;
    const root = try rootPath(ctx);
    if (create) try ctx.mkdir("build");
    const build = try canonical(ctx, "build");
    if (!std.mem.eql(u8, build, try ctx.fmt("{s}/build", .{root}))) return error.ReleaseBuildDirectoryEscapesWorkspace;
    if (create) try ctx.mkdir(relative);
    const output = try canonical(ctx, relative);
    if (!contained(build, output) or std.mem.eql(u8, build, output)) return error.ReleaseOutputEscapesBuildDirectory;
    var dir = try std.Io.Dir.cwd().openDir(ctx.io, relative, .{ .follow_symlinks = false });
    dir.close(ctx.io);
    return output;
}

pub fn remove(ctx: *Context, path: []const u8) !void {
    std.Io.Dir.cwd().deleteFile(ctx.io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

pub fn rename(ctx: *Context, source: []const u8, destination: []const u8) !void {
    try std.Io.Dir.renameAbsolute(source, destination, ctx.io);
}

pub fn privateTemp(ctx: *Context, parent: []const u8, prefix: []const u8) ![]const u8 {
    for (0..16) |_| {
        var random: [16]u8 = undefined;
        try std.Io.randomSecure(ctx.io, &random);
        const path = try ctx.fmt("{s}/{s}{s}", .{ parent, prefix, std.fmt.bytesToHex(random, .lower) });
        std.Io.Dir.cwd().createDir(ctx.io, path, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return err,
        };
        return path;
    }
    return error.TemporaryDirectoryCollision;
}

pub fn cleanup(ctx: *Context, path: []const u8) void {
    std.Io.Dir.cwd().deleteTree(ctx.io, path) catch {};
}

pub fn chmod(ctx: *Context, path: []const u8, mode: std.posix.mode_t) !void {
    var file = try std.Io.Dir.cwd().openFile(ctx.io, path, .{ .follow_symlinks = false });
    defer file.close(ctx.io);
    try file.setPermissions(ctx.io, .fromMode(mode));
}

pub fn pinVerifier(ctx: *Context, path: []const u8, pin: []const u8, work: []const u8, roots: []const []const u8) ![]const u8 {
    try absolute(path);
    try requireHash(pin);
    try regular(ctx, path, true);
    const resolved = try canonical(ctx, path);
    for (roots) |root| if (contained(root, resolved)) return error.ReleaseVerifierMustBeIndependent;
    const target = try ctx.fmt("{s}/pinned-release-verifier", .{work});
    try ctx.copy(path, target);
    try chmod(ctx, target, 0o500);
    const digest = try ctx.sha256File(target);
    if (!std.mem.eql(u8, &digest, pin)) return error.ReleaseVerifierPinMismatch;
    return target;
}

pub fn json(ctx: *Context, value: anytype) ![]const u8 {
    return std.json.Stringify.valueAlloc(ctx.allocator, value, .{});
}

pub fn writeJson(ctx: *Context, path: []const u8, value: anytype) !void {
    try ctx.write(path, try ctx.fmt("{s}\n", .{try json(ctx, value)}));
}

pub fn parse(ctx: *Context, bytes: []const u8) !std.json.Value {
    const result = try std.json.parseFromSlice(std.json.Value, ctx.allocator, bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    return result.value;
}

pub fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidReleaseJson;
    return value.object.get(name) orelse error.MissingReleaseJsonField;
}

pub fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    const result = try field(value, name);
    if (result != .string or result.string.len == 0) return error.InvalidReleaseJsonString;
    return result.string;
}

pub fn integer(value: std.json.Value, name: []const u8) !u64 {
    const result = try field(value, name);
    if (result != .integer or result.integer < 0) return error.InvalidReleaseJsonInteger;
    return @intCast(result.integer);
}

pub fn same(a: []const u8, b: []const u8) !void {
    if (!std.mem.eql(u8, a, b)) return error.ReleaseEvidenceMismatch;
}

pub fn decode64(ctx: *Context, encoded: []const u8) ![]u8 {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const result = try ctx.allocator.alloc(u8, size);
    try std.base64.standard.Decoder.decode(result, encoded);
    return result;
}

pub fn encode64(ctx: *Context, bytes: []const u8) ![]const u8 {
    const result = try ctx.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
    return std.base64.standard.Encoder.encode(result, bytes);
}

pub fn utc(ctx: *Context) ![]const u8 {
    const now = std.Io.Clock.real.now(ctx.io).toSeconds();
    if (now < 0) return error.InvalidReleaseClock;
    const seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(now) };
    const day = seconds.getEpochDay().calculateYearDay();
    const month = day.calculateMonthDay();
    const time = seconds.getDaySeconds();
    return ctx.fmt("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{ day.year, month.month.numeric(), month.day_index + 1, time.getHoursIntoDay(), time.getMinutesIntoHour(), time.getSecondsIntoMinute() });
}

pub fn checkedCapture(ctx: *Context, argv: []const []const u8) ![]const u8 {
    const result = try ctx.capture(argv);
    if (!result.term.success()) return error.ReleaseCommandFailed;
    return std.mem.trim(u8, result.stdout, "\r\n");
}

test "release paths reject sibling-prefix escapes and unsafe output components" {
    try std.testing.expect(!contained("/release/trusted", "/release/trusted-evil/verifier"));
    try std.testing.expect(contained("/release/trusted", "/release/trusted/verifier"));
    try std.testing.expect(!catalog.isSafeRelativePath("build/../other"));
    try std.testing.expect(!catalog.isSafeRelativePath("build//other"));
    try std.testing.expectError(error.InvalidReleaseHash, requireHash("ABCDEF"));
    try std.testing.expectError(error.InvalidReleaseInteger, positive("01"));
}

test "release artifacts reject direct symlinks and parent-directory escapes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    try tmp.dir.createDir(ctx.io, "artifacts", .default_dir);
    try tmp.dir.writeFile(ctx.io, .{ .sub_path = "outside", .data = "outside" });
    var artifacts = try tmp.dir.openDir(ctx.io, "artifacts", .{});
    defer artifacts.close(ctx.io);
    try artifacts.symLink(ctx.io, "../outside", "direct", .{});
    try artifacts.symLink(ctx.io, "..", "parent", .{ .is_directory = true });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const tmp_path = path_buffer[0..try tmp.dir.realPath(ctx.io, &path_buffer)];
    const root = try ctx.fmt("{s}/artifacts", .{tmp_path});
    try std.testing.expectError(error.ReleaseFileMustBeRegular, containedFile(&ctx, root, "direct"));
    try std.testing.expectError(error.ReleasePathEscapesRoot, containedFile(&ctx, root, "parent/outside"));
}

test "pinned verifiers reject candidate-sourced executables and digest substitution" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    try tmp.dir.createDir(ctx.io, "work", .default_dir);
    try tmp.dir.writeFile(ctx.io, .{ .sub_path = "verifier", .data = "test executable", .flags = .{ .permissions = .fromMode(0o700) } });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const tmp_path = path_buffer[0..try tmp.dir.realPath(ctx.io, &path_buffer)];
    const verifier = try ctx.fmt("{s}/verifier", .{tmp_path});
    const work = try ctx.fmt("{s}/work", .{tmp_path});
    const wrong_pin = "0000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expectError(error.ReleaseVerifierMustBeIndependent, pinVerifier(&ctx, verifier, wrong_pin, work, &.{tmp_path}));
    try std.testing.expectError(error.ReleaseVerifierPinMismatch, pinVerifier(&ctx, verifier, wrong_pin, work, &.{}));
}
