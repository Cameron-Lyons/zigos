const abi = @import("abi.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

var current_working_dir: [256]u8 = [_]u8{0} ** 256;
var cwd_len: usize = 1;
var cwd_initialized: bool = false;

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
    const node = vfs.lookupPath(path) catch return false;
    if (node.file_type != .Directory) return false;
    @memcpy(current_working_dir[0..path.len], path);
    cwd_len = path.len;
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

    const node = vfs.lookupPath(path_slice) catch return abi.ENOENT;
    if (node.file_type != .Directory) return abi.ENOTDIR;

    @memcpy(current_working_dir[0..path_slice.len], path_slice);
    cwd_len = path_slice.len;
    return 0;
}
