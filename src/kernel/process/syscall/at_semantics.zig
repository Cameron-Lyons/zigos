const std = @import("std");
const path_semantics = @import("path_semantics.zig");

pub fn resolveAtPath(root: []const u8, cwd: []const u8, dir_path: ?[]const u8, path: []const u8, visible_buf: []u8, out: []u8) path_semantics.Error![]const u8 {
    if (dir_path) |base_path| {
        return path_semantics.resolvePathFromDir(root, base_path, path, out);
    }
    return path_semantics.resolvePath(cwd, root, path, visible_buf, out);
}

test "resolveAtPath uses cwd for AT_FDCWD semantics" {
    var visible_buf: [128]u8 = undefined;
    var actual_buf: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "/srv/jail/var/tmp/cache.dat",
        try resolveAtPath("/srv/jail", "/var/log", null, "../tmp/cache.dat", &visible_buf, &actual_buf),
    );
}

test "resolveAtPath uses directory fd base for relative paths" {
    var visible_buf: [128]u8 = undefined;
    var actual_buf: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "/srv/jail/etc/init.d/rc",
        try resolveAtPath("/srv/jail", "/var/log", "/srv/jail/etc/init.d", "./rc", &visible_buf, &actual_buf),
    );
}

test "resolveAtPath ignores directory fd for absolute paths" {
    var visible_buf: [128]u8 = undefined;
    var actual_buf: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "/srv/jail/usr/bin/sh",
        try resolveAtPath("/srv/jail", "/var/log", "/srv/jail/etc/init.d", "/usr/bin/sh", &visible_buf, &actual_buf),
    );
}
