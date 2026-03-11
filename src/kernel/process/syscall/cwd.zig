const abi = @import("abi.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

var current_working_dir: [256]u8 = [_]u8{0} ** 256;
var cwd_len: usize = 1;
var cwd_initialized: bool = false;

fn normalizePath(path: []const u8, out: []u8) ?[]const u8 {
    if (out.len < 2) return null;

    out[0] = '/';
    var out_len: usize = 1;
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
            if (out_len > 1) {
                out_len -= 1;
                while (out_len > 1 and out[out_len - 1] != '/') : (out_len -= 1) {}
            }
            continue;
        }

        const needs_slash = out_len > 1;
        const required = out_len + @as(usize, if (needs_slash) 1 else 0) + component.len;
        if (required >= out.len) return null;
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

pub fn resolvePath(path: []const u8, out: []u8) ?[]const u8 {
    ensureCwdInit();

    if (path.len == 0) {
        if (out.len < 2) return null;
        out[0] = '/';
        return out[0..1];
    }

    if (path[0] == '/') {
        return normalizePath(path, out);
    }

    var combined: [512]u8 = undefined;
    const cwd = getCwd();
    var combined_len: usize = 0;
    @memcpy(combined[0..cwd.len], cwd);
    combined_len = cwd.len;

    if (combined_len == 0) {
        combined[0] = '/';
        combined_len = 1;
    }

    if (combined_len > 1 and combined[combined_len - 1] != '/') {
        combined[combined_len] = '/';
        combined_len += 1;
    }

    if (combined_len + path.len >= combined.len) return null;
    @memcpy(combined[combined_len .. combined_len + path.len], path);
    combined_len += path.len;

    return normalizePath(combined[0..combined_len], out);
}

fn ensureCwdInit() void {
    if (!cwd_initialized) {
        current_working_dir[0] = '/';
        cwd_len = 1;
        cwd_initialized = true;
    }
}

pub fn getCwd() []const u8 {
    ensureCwdInit();
    return current_working_dir[0..cwd_len];
}

pub fn setCwd(path: []const u8) bool {
    ensureCwdInit();
    var resolved_buf: [256]u8 = undefined;
    const resolved = resolvePath(path, &resolved_buf) orelse return false;
    const node = vfs.lookupPath(resolved) catch return false;
    if (node.file_type != .Directory) return false;
    @memcpy(current_working_dir[0..resolved.len], resolved);
    cwd_len = resolved.len;
    return true;
}

pub fn sys_getcwd(buf: [*]u8, size: usize) i32 {
    ensureCwdInit();
    if (!protection.verifyUserPointer(@intFromPtr(buf), size)) return abi.EINVAL;
    if (size < cwd_len + 1) return abi.EINVAL;

    var kernel_buf: [257]u8 = undefined;
    @memcpy(kernel_buf[0..cwd_len], current_working_dir[0..cwd_len]);
    kernel_buf[cwd_len] = 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buf[0 .. cwd_len + 1]) catch return abi.EINVAL;
    return @intCast(cwd_len);
}

pub fn sys_chdir(pathname: [*]const u8) i32 {
    ensureCwdInit();
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return abi.EINVAL;

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    if (!setCwd(path_slice)) {
        return abi.ENOENT;
    }
    return 0;
}
