const std = @import("std");
const abi = @import("abi.zig");
const common = @import("common.zig");
const errno = @import("errno.zig");
const syscall_event = @import("event.zig");
const credentials = @import("../credentials.zig");
const process_mod = @import("../process.zig");
const cwd_mod = @import("cwd.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

fn resolvePath(path: []const u8, buffer: *[common.RESOLVED_PATH_BUFFER_SIZE]u8) ?[]const u8 {
    return cwd_mod.resolvePath(path, buffer);
}

pub fn sys_mkdir(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolvePath(path_slice, &resolved_buf) orelse return abi.ENAMETOOLONG;

    vfs.mkdir(resolved, common.fileModeFromBits(mode)) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(resolved, abi.IN_CREATE, abi.IN_CREATE);
    return 0;
}

pub fn sys_rmdir(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolvePath(path_slice, &resolved_buf) orelse return abi.ENAMETOOLONG;

    vfs.rmdir(resolved) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(resolved, abi.IN_DELETE_SELF, abi.IN_DELETE);
    return 0;
}

pub fn sys_unlink(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolvePath(path_slice, &resolved_buf) orelse return abi.ENAMETOOLONG;

    vfs.unlink(resolved) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(resolved, abi.IN_DELETE_SELF, abi.IN_DELETE);
    return 0;
}

pub fn sys_rename(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), common.USER_PATH_BUFFER_SIZE) or
        !protection.verifyUserPointer(@intFromPtr(newpath), common.USER_PATH_BUFFER_SIZE))
    {
        return abi.EINVAL;
    }

    var old_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var new_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return abi.EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return abi.EINVAL;
    var resolved_old_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_new_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved_old = resolvePath(old_slice, &resolved_old_buf) orelse return abi.ENAMETOOLONG;
    const resolved_new = resolvePath(new_slice, &resolved_new_buf) orelse return abi.ENAMETOOLONG;

    vfs.rename(resolved_old, resolved_new) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyRename(resolved_old, resolved_new);
    return 0;
}

pub fn sys_open(pathname: [*]const u8, flags: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolvePath(path_slice, &resolved_buf) orelse return abi.ENAMETOOLONG;

    if (process_mod.current_process) |proc| {
        if (vfs.lookupPathRetained(resolved)) |vnode| {
            defer vfs.releaseLookupVNode(vnode);
            const access_mode = flags & 0x3;
            var access: u3 = 0;
            if (access_mode == 0 or access_mode == 2) access |= 4;
            if (access_mode == 1 or access_mode == 2) access |= 2;
            if (!credentials.checkPermission(&proc.creds, vnode.mode, vnode.uid, vnode.gid, access)) {
                return abi.EACCES;
            }
        } else |_| {}
    }

    const vfs_fd = vfs.open(resolved, flags) catch |err| return errno.vfsErrno(err);
    return @intCast(@as(i32, @intCast(vfs_fd)) + abi.FD_OFFSET);
}

pub fn sys_pipe(pipefd: ?*[2]i32) i32 {
    if (pipefd == null) return abi.EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(pipefd), @sizeOf([2]i32))) {
        return abi.EINVAL;
    }

    const result = vfs.createPipe() catch |err| return errno.vfsErrno(err);
    const fds = [2]i32{
        @as(i32, @intCast(result.read_fd)) + abi.FD_OFFSET,
        @as(i32, @intCast(result.write_fd)) + abi.FD_OFFSET,
    };

    protection.copyToUser(@intFromPtr(pipefd), std.mem.asBytes(&fds)) catch {
        vfs.close(result.read_fd) catch {};
        vfs.close(result.write_fd) catch {};
        return abi.EINVAL;
    };
    return 0;
}

pub fn sys_dup2(old_fd: i32, new_fd: i32) i32 {
    if (old_fd < abi.FD_OFFSET or new_fd < abi.FD_OFFSET) return abi.EBADF;
    const old_vfs_fd: u32 = @intCast(old_fd - abi.FD_OFFSET);
    const new_vfs_fd: u32 = @intCast(new_fd - abi.FD_OFFSET);

    const result = vfs.dup2(old_vfs_fd, new_vfs_fd) catch |err| return errno.vfsErrno(err);
    return @as(i32, @intCast(result)) + abi.FD_OFFSET;
}
