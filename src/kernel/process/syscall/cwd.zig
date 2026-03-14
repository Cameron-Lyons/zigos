const abi = @import("abi.zig");
const process_mod = @import("../process.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

fn currentProcess() ?*process_mod.Process {
    return process_mod.getEffectiveCurrent();
}

fn visibleCwd(proc: *const process_mod.Process) []const u8 {
    return proc.cwd_path[0..proc.cwd_len];
}

fn actualRoot(proc: *const process_mod.Process) []const u8 {
    if (proc.chroot_len == 0) return "/";
    return proc.chroot_path[0..proc.chroot_len];
}

fn normalizePathFromBase(base: []const u8, floor_len: usize, path: []const u8, out: []u8) ?[]const u8 {
    if (base.len == 0 or base[0] != '/') return null;
    if (base.len >= out.len or floor_len == 0 or floor_len > base.len) return null;

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

pub fn resolveVisiblePath(path: []const u8, out: []u8) ?[]const u8 {
    const base = if (currentProcess()) |proc|
        if (path.len > 0 and path[0] == '/') "/" else visibleCwd(proc)
    else
        "/";
    return normalizePathFromBase(base, 1, path, out);
}

fn resolveVisibleIntoActual(proc: ?*process_mod.Process, visible_path: []const u8, out: []u8) ?[]const u8 {
    const root = if (proc) |p| actualRoot(p) else "/";
    return normalizePathFromBase(root, root.len, visible_path, out);
}

pub fn resolvePath(path: []const u8, out: []u8) ?[]const u8 {
    var visible_buf: [512]u8 = undefined;
    const visible_path = resolveVisiblePath(path, &visible_buf) orelse return null;
    return resolveVisibleIntoActual(currentProcess(), visible_path, out);
}

pub fn resolvePathFromDir(base_path: []const u8, path: []const u8, out: []u8) ?[]const u8 {
    if (path.len > 0 and path[0] == '/') {
        return resolvePath(path, out);
    }

    const floor_len = if (currentProcess()) |proc| actualRoot(proc).len else 1;
    return normalizePathFromBase(base_path, floor_len, path, out);
}

pub fn getCwd() []const u8 {
    if (currentProcess()) |proc| {
        return visibleCwd(proc);
    }
    return "/";
}

pub fn setCwd(path: []const u8) bool {
    const proc = currentProcess() orelse return false;

    var resolved_visible_buf: [512]u8 = undefined;
    const resolved_visible = resolveVisiblePath(path, &resolved_visible_buf) orelse return false;
    if (resolved_visible.len >= process_mod.PATH_BUFFER_LEN) return false;

    var resolved_actual_buf: [512]u8 = undefined;
    const resolved_actual = resolveVisibleIntoActual(proc, resolved_visible, &resolved_actual_buf) orelse return false;
    const node = vfs.lookupPath(resolved_actual) catch return false;
    if (node.file_type != .Directory) return false;

    @memset(&proc.cwd_path, 0);
    @memcpy(proc.cwd_path[0..resolved_visible.len], resolved_visible);
    proc.cwd_len = resolved_visible.len;
    return true;
}

pub fn setChroot(actual_path: []const u8) bool {
    const proc = currentProcess() orelse return false;
    if (actual_path.len == 0 or actual_path.len >= process_mod.PATH_BUFFER_LEN) return false;

    @memset(&proc.chroot_path, 0);
    if (!(actual_path.len == 1 and actual_path[0] == '/')) {
        @memcpy(proc.chroot_path[0..actual_path.len], actual_path);
        proc.chroot_len = actual_path.len;
    } else {
        proc.chroot_len = 0;
    }

    proc.cwd_path = [_]u8{0} ** process_mod.PATH_BUFFER_LEN;
    proc.cwd_path[0] = '/';
    proc.cwd_len = 1;
    return true;
}

pub fn sys_getcwd(buf: [*]u8, size: usize) i32 {
    const cwd = getCwd();

    if (!protection.verifyUserPointer(@intFromPtr(buf), size)) return abi.EINVAL;
    if (size < cwd.len + 1) return abi.EINVAL;

    var kernel_buf: [process_mod.PATH_BUFFER_LEN + 1]u8 = undefined;
    @memcpy(kernel_buf[0..cwd.len], cwd);
    kernel_buf[cwd.len] = 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buf[0 .. cwd.len + 1]) catch return abi.EINVAL;
    return @intCast(cwd.len);
}

pub fn sys_chdir(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), process_mod.PATH_BUFFER_LEN)) return abi.EINVAL;

    var kernel_buffer: [process_mod.PATH_BUFFER_LEN]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    if (!setCwd(path_slice)) {
        return abi.ENOENT;
    }
    return 0;
}
