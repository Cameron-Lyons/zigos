const abi = @import("abi.zig");
const common = @import("common.zig");
const path_semantics = @import("path_semantics.zig");
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

pub fn getActualRoot() []const u8 {
    if (currentProcess()) |proc| {
        return actualRoot(proc);
    }
    return "/";
}

pub fn resolveVisiblePath(path: []const u8, out: []u8) ?[]const u8 {
    const cwd = if (currentProcess()) |proc| visibleCwd(proc) else "/";
    return path_semantics.resolveVisiblePath(cwd, path, out) catch null;
}

fn resolveVisibleIntoActual(proc: ?*process_mod.Process, visible_path: []const u8, out: []u8) ?[]const u8 {
    const root = if (proc) |p| actualRoot(p) else "/";
    return path_semantics.resolveActualPath(root, visible_path, out) catch null;
}

pub fn resolvePath(path: []const u8, out: []u8) ?[]const u8 {
    const proc = currentProcess();
    const cwd = if (proc) |p| visibleCwd(p) else "/";
    const root = if (proc) |p| actualRoot(p) else "/";
    var visible_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    return path_semantics.resolvePath(cwd, root, path, &visible_buf, out) catch null;
}

pub fn resolvePathFromDir(base_path: []const u8, path: []const u8, out: []u8) ?[]const u8 {
    const root = if (currentProcess()) |proc| actualRoot(proc) else "/";
    return path_semantics.resolvePathFromDir(root, base_path, path, out) catch null;
}

pub fn getCwd() []const u8 {
    if (currentProcess()) |proc| {
        return visibleCwd(proc);
    }
    return "/";
}

pub fn setCwd(path: []const u8) bool {
    const proc = currentProcess() orelse return false;

    var resolved_visible_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved_visible = resolveVisiblePath(path, &resolved_visible_buf) orelse return false;
    if (resolved_visible.len >= process_mod.PATH_BUFFER_LEN) return false;

    var resolved_actual_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved_actual = resolveVisibleIntoActual(proc, resolved_visible, &resolved_actual_buf) orelse return false;
    const node = vfs.lookupPathRetained(resolved_actual) catch return false;
    defer vfs.releaseLookupVNode(node);
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
