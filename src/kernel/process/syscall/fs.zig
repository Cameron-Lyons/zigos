const std = @import("std");
const abi = @import("abi.zig");
const errno = @import("errno.zig");
const credentials = @import("../credentials.zig");
const process_mod = @import("../process.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

pub fn sys_mkdir(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    const mode_struct = vfs.FileMode{
        .owner_read = (mode & 0o400) != 0,
        .owner_write = (mode & 0o200) != 0,
        .owner_exec = (mode & 0o100) != 0,
        .group_read = (mode & 0o040) != 0,
        .group_write = (mode & 0o020) != 0,
        .group_exec = (mode & 0o010) != 0,
        .other_read = (mode & 0o004) != 0,
        .other_write = (mode & 0o002) != 0,
        .other_exec = (mode & 0o001) != 0,
    };

    vfs.mkdir(path_slice, mode_struct) catch |err| return errno.vfsErrno(err);
    return 0;
}

pub fn sys_rmdir(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    vfs.rmdir(path_slice) catch |err| return errno.vfsErrno(err);
    return 0;
}

pub fn sys_unlink(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    vfs.unlink(path_slice) catch |err| return errno.vfsErrno(err);
    return 0;
}

pub fn sys_rename(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), 256) or
        !protection.verifyUserPointer(@intFromPtr(newpath), 256))
    {
        return abi.EINVAL;
    }

    var old_buffer: [256]u8 = undefined;
    var new_buffer: [256]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return abi.EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return abi.EINVAL;

    vfs.rename(old_slice, new_slice) catch |err| return errno.vfsErrno(err);
    return 0;
}

pub fn sys_open(pathname: [*]const u8, flags: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    if (process_mod.current_process) |proc| {
        if (vfs.lookupPath(path_slice)) |vnode| {
            const access_mode = flags & 0x3;
            var access: u3 = 0;
            if (access_mode == 0 or access_mode == 2) access |= 4;
            if (access_mode == 1 or access_mode == 2) access |= 2;
            if (!credentials.checkPermission(&proc.creds, vnode.mode, vnode.uid, vnode.gid, access)) {
                return abi.EACCES;
            }
        } else |_| {}
    }

    const vfs_fd = vfs.open(path_slice, flags) catch |err| return errno.vfsErrno(err);
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
