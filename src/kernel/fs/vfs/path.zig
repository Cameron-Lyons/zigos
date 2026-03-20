const std = @import("std");

pub const PathParts = struct {
    parent: []const u8,
    name: []const u8,
};

pub fn hasRemainingComponents(path: []const u8, index: usize) bool {
    var i = index;
    while (i < path.len and path[i] == '/') : (i += 1) {}
    return i < path.len;
}

pub fn mountPathMatches(path: []const u8, mount_path: []const u8) bool {
    if (mount_path.len == 1 and mount_path[0] == '/') {
        return true;
    }

    if (path.len < mount_path.len) return false;
    if (!std.mem.eql(u8, path[0..mount_path.len], mount_path)) return false;
    return path.len == mount_path.len or path[mount_path.len] == '/';
}

pub fn splitPath(path: []const u8) PathParts {
    var last_slash: usize = 0;
    for (path, 0..) |c, i| {
        if (c == '/') {
            last_slash = i;
        }
    }
    return .{
        .parent = if (last_slash == 0) "/" else path[0..last_slash],
        .name = path[last_slash + 1 ..],
    };
}
