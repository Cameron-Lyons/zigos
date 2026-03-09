const std = @import("std");
const abi = @import("abi.zig");
const errno = @import("errno.zig");
const syscall_event = @import("event.zig");
const syscall_net = @import("net.zig");
const syscall_time = @import("time.zig");
const process_mod = @import("../process.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const FD_CLOEXEC: u32 = 1;

const Flock = extern struct {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
};

const FileLock = struct {
    fd: u32,
    l_type: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
    in_use: bool,
};

var file_locks: [256]FileLock = [_]FileLock{.{
    .fd = 0,
    .l_type = abi.F_UNLCK,
    .l_start = 0,
    .l_len = 0,
    .l_pid = 0,
    .in_use = false,
}} ** 256;

pub fn isSpecialFd(fd: i32) bool {
    return syscall_event.isEpollFd(fd) or
        syscall_time.isTimerFd(fd) or
        fd >= syscall_net.unix_socket_fd_base;
}

pub fn sys_close(unix_sockets: *syscall_net.UnixSocketTable, socket_table: *syscall_net.SocketTable, fd: i32) i32 {
    if (fd >= 0 and fd < socket_table.len) {
        if (socket_table[@intCast(fd)]) |sock| {
            sock.close();
            socket_table[@intCast(fd)] = null;
            return 0;
        }
    }

    if (fd >= syscall_net.unix_socket_fd_base and fd < syscall_net.unix_socket_fd_base + syscall_net.unix_socket_count) {
        const idx: usize = @intCast(fd - syscall_net.unix_socket_fd_base);
        var usock = &unix_sockets[idx];
        if (!usock.in_use) return abi.EBADF;
        if (usock.peer) |peer| {
            peer.peer = null;
            peer.connected = false;
        }
        usock.in_use = false;
        usock.peer = null;
        usock.path_len = 0;
        usock.listening = false;
        usock.connected = false;
        return 0;
    }

    if (syscall_event.closePseudoFd(fd)) |result| {
        return result;
    }

    if (syscall_time.isTimerFd(fd)) {
        return syscall_time.closeTimerFd(fd);
    }

    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);
    vfs.close(vfs_fd) catch |err| return errno.vfsErrno(err);
    return 0;
}

pub fn sys_lseek(fd: i32, offset: i64, whence: u32) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);
    const result = vfs.lseek(vfs_fd, offset, whence) catch |err| return errno.vfsErrno(err);
    if (result > 0x7FFFFFFF) return abi.EOVERFLOW;
    return @intCast(result);
}

pub fn sys_ioctl(fd: i32, request: u32, arg: usize) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    const result = vfs.ioctl(vfs_fd, request, arg) catch |err| return errno.vfsErrno(err);
    return result;
}

pub fn sys_dup(fd: i32) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    var new_fd: u32 = 0;
    while (new_fd < 256) : (new_fd += 1) {
        const result = vfs.dup2(vfs_fd, new_fd) catch continue;
        return @as(i32, @intCast(result)) + abi.FD_OFFSET;
    }
    return abi.EMFILE;
}

pub fn sys_fcntl(fd: i32, cmd: i32, arg: usize) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    const ucmd: u32 = @bitCast(cmd);
    switch (ucmd) {
        F_DUPFD => {
            const min_fd = if (arg >= abi.FD_OFFSET) @as(u32, @intCast(arg - abi.FD_OFFSET)) else 0;
            var new_fd = min_fd;
            while (new_fd < 256) : (new_fd += 1) {
                const result = vfs.dup2(vfs_fd, new_fd) catch continue;
                return @as(i32, @intCast(result)) + abi.FD_OFFSET;
            }
            return abi.EMFILE;
        },
        F_GETFD => {
            const fd_flags = vfs.getFdFlags(vfs_fd) catch return abi.EBADF;
            return @intCast(fd_flags);
        },
        F_SETFD => {
            vfs.setFdFlags(vfs_fd, @intCast(arg & FD_CLOEXEC)) catch return abi.EBADF;
            return 0;
        },
        F_GETFL => {
            const flags = vfs.getFileFlags(vfs_fd) catch return abi.EBADF;
            return @intCast(flags);
        },
        F_SETFL => {
            vfs.setFileFlags(vfs_fd, @intCast(arg)) catch return abi.EBADF;
            return 0;
        },
        abi.F_GETLK => {
            if (!protection.verifyUserPointer(arg, @sizeOf(Flock))) return abi.EINVAL;
            var flock: Flock = undefined;
            protection.copyFromUser(std.mem.asBytes(&flock), arg) catch return abi.EINVAL;

            for (file_locks) |lock| {
                if (lock.in_use and lock.fd == vfs_fd) {
                    if (locksOverlap(flock.l_start, flock.l_len, lock.l_start, lock.l_len)) {
                        if (lock.l_type == abi.F_WRLCK or flock.l_type == abi.F_WRLCK) {
                            flock.l_type = lock.l_type;
                            flock.l_start = lock.l_start;
                            flock.l_len = lock.l_len;
                            flock.l_pid = lock.l_pid;
                            protection.copyToUser(arg, std.mem.asBytes(&flock)) catch return abi.EINVAL;
                            return 0;
                        }
                    }
                }
            }
            flock.l_type = abi.F_UNLCK;
            protection.copyToUser(arg, std.mem.asBytes(&flock)) catch return abi.EINVAL;
            return 0;
        },
        abi.F_SETLK, abi.F_SETLKW => {
            if (!protection.verifyUserPointer(arg, @sizeOf(Flock))) return abi.EINVAL;
            var flock: Flock = undefined;
            protection.copyFromUser(std.mem.asBytes(&flock), arg) catch return abi.EINVAL;

            const pid: i32 = if (process_mod.current_process) |proc| @intCast(proc.pid) else 0;

            if (flock.l_type == abi.F_UNLCK) {
                for (&file_locks) |*lock| {
                    if (lock.in_use and lock.fd == vfs_fd and lock.l_pid == pid) {
                        if (locksOverlap(flock.l_start, flock.l_len, lock.l_start, lock.l_len)) {
                            lock.in_use = false;
                        }
                    }
                }
                return 0;
            }

            for (file_locks) |lock| {
                if (lock.in_use and lock.fd == vfs_fd and lock.l_pid != pid) {
                    if (locksOverlap(flock.l_start, flock.l_len, lock.l_start, lock.l_len)) {
                        if (lock.l_type == abi.F_WRLCK or flock.l_type == abi.F_WRLCK) {
                            return abi.EAGAIN;
                        }
                    }
                }
            }

            for (&file_locks) |*lock| {
                if (!lock.in_use) {
                    lock.* = FileLock{
                        .fd = vfs_fd,
                        .l_type = flock.l_type,
                        .l_start = flock.l_start,
                        .l_len = flock.l_len,
                        .l_pid = pid,
                        .in_use = true,
                    };
                    return 0;
                }
            }
            return abi.ENOLCK;
        },
        else => return abi.EINVAL,
    }
}

pub fn sys_fsync(fd: i32) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    return 0;
}

pub fn sys_pipe2(pipefd: ?*[2]i32, flags: u32) i32 {
    if (pipefd == null) return abi.EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(pipefd), @sizeOf([2]i32))) return abi.EINVAL;

    const result = vfs.createPipe() catch |err| return errno.vfsErrno(err);
    const fds = [2]i32{
        @as(i32, @intCast(result.read_fd)) + abi.FD_OFFSET,
        @as(i32, @intCast(result.write_fd)) + abi.FD_OFFSET,
    };

    if ((flags & abi.O_CLOEXEC) != 0) {
        vfs.setFdFlags(result.read_fd, FD_CLOEXEC) catch {};
        vfs.setFdFlags(result.write_fd, FD_CLOEXEC) catch {};
    }

    if ((flags & vfs.O_NONBLOCK) != 0) {
        vfs.setFileFlags(result.read_fd, vfs.O_NONBLOCK) catch {};
        vfs.setFileFlags(result.write_fd, vfs.O_NONBLOCK) catch {};
    }

    protection.copyToUser(@intFromPtr(pipefd), std.mem.asBytes(&fds)) catch {
        vfs.close(result.read_fd) catch {};
        vfs.close(result.write_fd) catch {};
        return abi.EINVAL;
    };
    return 0;
}

pub fn sys_dup3(old_fd: i32, new_fd: i32, flags: u32) i32 {
    if (old_fd < abi.FD_OFFSET or new_fd < abi.FD_OFFSET) return abi.EBADF;
    if (old_fd == new_fd) return abi.EINVAL;

    const old_vfs_fd: u32 = @intCast(old_fd - abi.FD_OFFSET);
    const new_vfs_fd: u32 = @intCast(new_fd - abi.FD_OFFSET);

    const result = vfs.dup2(old_vfs_fd, new_vfs_fd) catch |err| return errno.vfsErrno(err);

    if ((flags & abi.O_CLOEXEC) != 0) {
        vfs.setFdFlags(new_vfs_fd, FD_CLOEXEC) catch {};
    }

    return @as(i32, @intCast(result)) + abi.FD_OFFSET;
}

pub fn sys_copy_file_range(fd_in: i32, off_in_ptr: usize, fd_out: i32, off_out_ptr: usize, len: usize) i32 {
    if (fd_in < abi.FD_OFFSET or fd_out < abi.FD_OFFSET) return abi.EBADF;
    if (isSpecialFd(fd_in) or isSpecialFd(fd_out)) return abi.EBADF;

    const vfs_fd_in: u32 = @intCast(fd_in - abi.FD_OFFSET);
    const vfs_fd_out: u32 = @intCast(fd_out - abi.FD_OFFSET);

    var off_in: i64 = -1;
    var off_out: i64 = -1;

    if (off_in_ptr != 0) {
        if (!protection.verifyUserPointer(off_in_ptr, @sizeOf(i64))) return abi.EFAULT;
        protection.copyFromUser(std.mem.asBytes(&off_in), off_in_ptr) catch return abi.EFAULT;
    }

    if (off_out_ptr != 0) {
        if (!protection.verifyUserPointer(off_out_ptr, @sizeOf(i64))) return abi.EFAULT;
        protection.copyFromUser(std.mem.asBytes(&off_out), off_out_ptr) catch return abi.EFAULT;
    }

    var buffer: [512]u8 = undefined;
    var total_copied: usize = 0;
    var remaining = len;

    while (remaining > 0) {
        const chunk = @min(remaining, buffer.len);

        const bytes_read = if (off_in >= 0) blk: {
            const result = vfs.pread(vfs_fd_in, buffer[0..chunk], @intCast(off_in)) catch |err| return errno.vfsErrno(err);
            off_in += @intCast(result);
            break :blk result;
        } else blk: {
            break :blk vfs.read(vfs_fd_in, buffer[0..chunk]) catch |err| return errno.vfsErrno(err);
        };

        if (bytes_read == 0) break;

        const bytes_written = if (off_out >= 0) blk: {
            const result = vfs.pwrite(vfs_fd_out, buffer[0..bytes_read], @intCast(off_out)) catch |err| return errno.vfsErrno(err);
            off_out += @intCast(result);
            break :blk result;
        } else blk: {
            break :blk vfs.write(vfs_fd_out, buffer[0..bytes_read]) catch |err| return errno.vfsErrno(err);
        };

        total_copied += bytes_written;
        remaining -= bytes_written;

        if (bytes_written < bytes_read) break;
    }

    if (off_in_ptr != 0) {
        protection.copyToUser(off_in_ptr, std.mem.asBytes(&off_in)) catch return abi.EFAULT;
    }
    if (off_out_ptr != 0) {
        protection.copyToUser(off_out_ptr, std.mem.asBytes(&off_out)) catch return abi.EFAULT;
    }

    return @intCast(total_copied);
}

pub fn sys_fadvise64(fd: i32, offset: i64, len: usize, advice: u32) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    _ = offset;
    _ = len;
    _ = advice;
    return 0;
}

pub fn sys_readahead(fd: i32, offset: i64, count: usize) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    _ = offset;
    _ = count;
    return 0;
}

pub fn sys_sync_file_range(fd: i32, offset: i64, nbytes: i64, flags: u32) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    _ = offset;
    _ = nbytes;
    _ = flags;
    return 0;
}

pub fn sys_syncfs(fd: i32) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    return 0;
}

fn locksOverlap(start1: i64, len1: i64, start2: i64, len2: i64) bool {
    const end1 = if (len1 == 0) std.math.maxInt(i64) else start1 + len1;
    const end2 = if (len2 == 0) std.math.maxInt(i64) else start2 + len2;
    return start1 < end2 and start2 < end1;
}
