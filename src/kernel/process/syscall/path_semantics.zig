const std = @import("std");

pub const Error = error{
    InvalidBase,
    ArgumentTooLong,
};

pub fn normalizePathFromBase(base: []const u8, floor_len: usize, path: []const u8, out: []u8) Error![]const u8 {
    if (base.len == 0 or base[0] != '/') return error.InvalidBase;
    if (base.len >= out.len or floor_len == 0 or floor_len > base.len) return error.ArgumentTooLong;

    @memcpy(out[0..base.len], base);
    var out_len = base.len;

    while (out_len > floor_len and out[out_len - 1] == '/') {
        out_len -= 1;
    }

    if (path.len == 0) {
        return out[0..out_len];
    }

    var i: usize = 0;
    while (i < path.len) {
        while (i < path.len and path[i] == '/') : (i += 1) {}
        if (i >= path.len) break;

        const start = i;
        while (i < path.len and path[i] != '/') : (i += 1) {}
        const component = path[start..i];

        if (component.len == 1 and component[0] == '.') {
            continue;
        }

        if (component.len == 2 and component[0] == '.' and component[1] == '.') {
            var new_len = out_len;
            while (new_len > floor_len and out[new_len - 1] != '/') : (new_len -= 1) {}
            if (new_len > floor_len) {
                new_len -= 1;
            }
            out_len = new_len;
            continue;
        }

        const needs_slash = out_len > 1;
        const required = out_len + @as(usize, if (needs_slash) 1 else 0) + component.len;
        if (required >= out.len) return error.ArgumentTooLong;
        if (needs_slash) {
            out[out_len] = '/';
            out_len += 1;
        }
        @memcpy(out[out_len .. out_len + component.len], component);
        out_len += component.len;
    }

    if (out_len == 0) {
        out[0] = '/';
        out_len = 1;
    }
    return out[0..out_len];
}

pub fn resolveVisiblePath(cwd: []const u8, path: []const u8, out: []u8) Error![]const u8 {
    const base = if (path.len > 0 and path[0] == '/') "/" else cwd;
    return normalizePathFromBase(base, 1, path, out);
}

pub fn resolveActualPath(root: []const u8, visible_path: []const u8, out: []u8) Error![]const u8 {
    return normalizePathFromBase(root, root.len, visible_path, out);
}

pub fn resolvePath(cwd: []const u8, root: []const u8, path: []const u8, visible_buf: []u8, out: []u8) Error![]const u8 {
    const visible_path = try resolveVisiblePath(cwd, path, visible_buf);
    return resolveActualPath(root, visible_path, out);
}

pub fn resolvePathFromDir(root: []const u8, base_path: []const u8, path: []const u8, out: []u8) Error![]const u8 {
    if (path.len > 0 and path[0] == '/') {
        return resolveActualPath(root, path, out);
    }
    return normalizePathFromBase(base_path, root.len, path, out);
}

test "resolveVisiblePath normalizes cwd relative traversal" {
    var buffer: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "/var/tmp/file.txt",
        try resolveVisiblePath("/var/log", "../tmp/./file.txt", &buffer),
    );
    try std.testing.expectEqualStrings(
        "/etc/passwd",
        try resolveVisiblePath("/usr/bin", "../../etc/passwd", &buffer),
    );
}

test "resolveActualPath keeps traversal inside root" {
    var buffer: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "/srv/jail/etc/config",
        try resolveActualPath("/srv/jail", "/../../etc/config", &buffer),
    );
    try std.testing.expectEqualStrings(
        "/srv/jail/var/log",
        try resolveActualPath("/srv/jail", "/var/log", &buffer),
    );
}

test "resolvePathFromDir honors root floor for relative paths" {
    var buffer: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "/srv/jail/var/tmp/out.log",
        try resolvePathFromDir("/srv/jail", "/srv/jail/var/log", "../tmp/out.log", &buffer),
    );
    try std.testing.expectEqualStrings(
        "/srv/jail/etc/hosts",
        try resolvePathFromDir("/srv/jail", "/srv/jail/var/log", "/etc/hosts", &buffer),
    );
}

test "resolvePath combines cwd and root views" {
    var visible_buf: [128]u8 = undefined;
    var actual_buf: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "/srv/jail/usr/share/doc.txt",
        try resolvePath("/usr/bin", "/srv/jail", "../share/doc.txt", &visible_buf, &actual_buf),
    );
}

test "normalizePathFromBase rejects oversized output" {
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(
        error.ArgumentTooLong,
        normalizePathFromBase("/root", 1, "very-long-component", &buffer),
    );
}
