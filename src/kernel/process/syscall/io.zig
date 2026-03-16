const std = @import("std");
const abi = @import("abi.zig");
const common = @import("common.zig");
const descriptor = @import("descriptor.zig");
const errno = @import("errno.zig");
const fd_ops = @import("fd.zig");
const support = @import("support.zig");
const tty = @import("../../fs/tty.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

const LinuxDirent = extern struct {
    d_ino: u32,
    d_off: u32,
    d_reclen: u16,
    d_type: u8,
};

const IoVec = extern struct {
    iov_base: usize,
    iov_len: usize,
};

const MAX_IOV_COUNT: usize = 16;
const StatFs = support.StatFs;

pub fn sys_write(fd: i32, buf: [*]const u8, count: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return abi.EINVAL;
    }

    const effective_fd = support.resolveIoFd(fd);

    if (effective_fd == abi.STDOUT or effective_fd == abi.STDERR) {
        var kernel_buffer: [support.TERMINAL_IO_BUFFER_SIZE]u8 = undefined;
        var written: usize = 0;

        while (written < count) {
            const chunk_size = @min(count - written, kernel_buffer.len);
            protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch {
                return abi.EINVAL;
            };

            tty.write(kernel_buffer[0..chunk_size]);
            written += chunk_size;
        }

        return @intCast(count);
    }

    if (count == 0) return 0;

    var kernel_buffer: [support.FILE_IO_BUFFER_SIZE]u8 = undefined;
    var written: usize = 0;

    while (written < count) {
        const chunk_size = @min(count - written, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch {
            return abi.EINVAL;
        };

        if (descriptor.write(effective_fd, kernel_buffer[0..chunk_size])) |result| {
            if (result < 0) return result;

            const bytes_written: usize = @intCast(result);
            written += bytes_written;
            if (bytes_written < chunk_size) break;
            continue;
        }

        if (effective_fd < abi.FD_OFFSET) return abi.EBADF;
        const vfs_fd: u32 = @intCast(effective_fd - abi.FD_OFFSET);

        const bytes_written = vfs.write(vfs_fd, kernel_buffer[0..chunk_size]) catch |err| return errno.vfsErrno(err);
        written += bytes_written;
        if (bytes_written < chunk_size) break;
    }

    return @intCast(written);
}

pub fn sys_read(fd: i32, buf: [*]u8, count: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return abi.EINVAL;
    }

    const effective_fd = support.resolveIoFd(fd);

    if (effective_fd == abi.STDIN) {
        var kernel_buffer: [support.TERMINAL_IO_BUFFER_SIZE]u8 = undefined;
        const read_size = tty.read(kernel_buffer[0..@min(count, kernel_buffer.len)]);

        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..read_size]) catch {
            return abi.EINVAL;
        };

        return @intCast(read_size);
    }

    if (count == 0) return 0;

    var kernel_buffer: [support.FILE_IO_BUFFER_SIZE]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < count) {
        const chunk_size = @min(count - total_read, kernel_buffer.len);

        if (descriptor.read(effective_fd, kernel_buffer[0..chunk_size])) |result| {
            if (result < 0) return result;
            if (result == 0) break;

            const bytes_read: usize = @intCast(result);
            protection.copyToUser(@intFromPtr(buf) + total_read, kernel_buffer[0..bytes_read]) catch {
                return abi.EINVAL;
            };

            total_read += bytes_read;
            if (bytes_read < chunk_size) break;
            continue;
        }

        if (effective_fd < abi.FD_OFFSET) return abi.EBADF;
        const vfs_fd: u32 = @intCast(effective_fd - abi.FD_OFFSET);

        const bytes_read = vfs.read(vfs_fd, kernel_buffer[0..chunk_size]) catch |err| return errno.vfsErrno(err);
        if (bytes_read == 0) break;

        protection.copyToUser(@intFromPtr(buf) + total_read, kernel_buffer[0..bytes_read]) catch {
            return abi.EINVAL;
        };

        total_read += bytes_read;
        if (bytes_read < chunk_size) break;
    }

    return @intCast(total_read);
}

pub fn sys_stat(pathname: [*]const u8, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) {
        return abi.EINVAL;
    }

    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = support.resolveUserPathFromPointer(pathname, &kernel_buffer, &resolved_buf) catch |err| {
        return support.errnoFromResolvedUserPathError(err, abi.EINVAL);
    };

    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(resolved, &stat_buf) catch |err| return errno.vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_fstat(fd: i32, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) {
        return abi.EINVAL;
    }

    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    var stat_buf: vfs.FileStat = undefined;
    vfs.fstat(vfs_fd, &stat_buf) catch |err| return errno.vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_ioctl(fd: i32, request: u32, arg: usize) i32 {
    const effective_fd = support.resolveIoFd(fd);
    if (effective_fd == abi.STDIN or effective_fd == abi.STDOUT or effective_fd == abi.STDERR) {
        return tty.ioctl(request, arg);
    }
    return fd_ops.sys_ioctl(effective_fd, request, arg);
}

pub fn sys_getdents(fd: i32, buf_addr: usize, buf_size: usize) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    if (!protection.verifyUserPointer(buf_addr, buf_size)) return abi.EINVAL;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    var dirent: vfs.DirEntry = undefined;
    var offset: usize = 0;
    while (offset + @sizeOf(LinuxDirent) + 1 < buf_size) {
        const has_entry = vfs.readdirNext(vfs_fd, &dirent) catch |err| return errno.vfsErrno(err);
        if (!has_entry) break;

        const name_len = dirent.name_len;
        const reclen: u16 = @intCast(@sizeOf(LinuxDirent) + name_len + 1);
        if (offset + reclen > buf_size) break;

        var kernel_entry: LinuxDirent = .{
            .d_ino = @intCast(dirent.inode & 0xFFFFFFFF),
            .d_off = @intCast(offset + reclen),
            .d_reclen = reclen,
            .d_type = @intFromEnum(dirent.file_type),
        };

        protection.copyToUser(buf_addr + offset, std.mem.asBytes(&kernel_entry)) catch return abi.EINVAL;
        protection.copyToUser(buf_addr + offset + @sizeOf(LinuxDirent), dirent.name[0..name_len]) catch return abi.EINVAL;
        const null_byte = [_]u8{0};
        protection.copyToUser(buf_addr + offset + @sizeOf(LinuxDirent) + name_len, &null_byte) catch return abi.EINVAL;

        offset += reclen;
    }

    return @intCast(offset);
}

pub fn sys_pread(fd: i32, buf: [*]u8, count: usize, offset: u64) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) return abi.EINVAL;
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    if (fd_ops.isSpecialFd(fd)) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    var kernel_buffer: [support.FILE_IO_BUFFER_SIZE]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < count) {
        const chunk_size = @min(count - total_read, kernel_buffer.len);
        const bytes_read = vfs.pread(vfs_fd, kernel_buffer[0..chunk_size], offset + total_read) catch |err| return errno.vfsErrno(err);
        if (bytes_read == 0) break;

        protection.copyToUser(@intFromPtr(buf) + total_read, kernel_buffer[0..bytes_read]) catch return abi.EINVAL;
        total_read += bytes_read;
        if (bytes_read < chunk_size) break;
    }

    return @intCast(total_read);
}

pub fn sys_pwrite(fd: i32, buf: [*]const u8, count: usize, offset: u64) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) return abi.EINVAL;
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    if (fd_ops.isSpecialFd(fd)) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    var kernel_buffer: [support.FILE_IO_BUFFER_SIZE]u8 = undefined;
    var written: usize = 0;

    while (written < count) {
        const chunk_size = @min(count - written, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch return abi.EINVAL;
        const bytes_written = vfs.pwrite(vfs_fd, kernel_buffer[0..chunk_size], offset + written) catch |err| return errno.vfsErrno(err);
        written += bytes_written;
        if (bytes_written < chunk_size) break;
    }

    return @intCast(written);
}

pub fn sys_readv(fd: i32, iov_addr: usize, iovcnt: i32) i32 {
    if (iovcnt <= 0 or iovcnt > @as(i32, @intCast(MAX_IOV_COUNT))) return abi.EINVAL;
    const cnt: u32 = @intCast(iovcnt);
    const iov_size = cnt * @sizeOf(IoVec);
    if (!protection.verifyUserPointer(iov_addr, iov_size)) return abi.EINVAL;

    var iov: [MAX_IOV_COUNT]IoVec = undefined;
    protection.copyFromUser(std.mem.asBytes(&iov)[0..iov_size], iov_addr) catch return abi.EINVAL;

    var total: usize = 0;
    var i: u32 = 0;
    while (i < cnt) : (i += 1) {
        if (iov[i].iov_len == 0) continue;
        if (!protection.verifyUserPointer(iov[i].iov_base, iov[i].iov_len)) return abi.EINVAL;

        const result = sys_read(fd, @ptrFromInt(iov[i].iov_base), iov[i].iov_len);
        if (result < 0) {
            if (total > 0) return @intCast(total);
            return result;
        }
        total += @intCast(result);
        if (@as(usize, @intCast(result)) < iov[i].iov_len) break;
    }

    return @intCast(total);
}

pub fn sys_writev(fd: i32, iov_addr: usize, iovcnt: i32) i32 {
    if (iovcnt <= 0 or iovcnt > @as(i32, @intCast(MAX_IOV_COUNT))) return abi.EINVAL;
    const cnt: u32 = @intCast(iovcnt);
    const iov_size = cnt * @sizeOf(IoVec);
    if (!protection.verifyUserPointer(iov_addr, iov_size)) return abi.EINVAL;

    var iov: [MAX_IOV_COUNT]IoVec = undefined;
    protection.copyFromUser(std.mem.asBytes(&iov)[0..iov_size], iov_addr) catch return abi.EINVAL;

    var total: usize = 0;
    var i: u32 = 0;
    while (i < cnt) : (i += 1) {
        if (iov[i].iov_len == 0) continue;
        if (!protection.verifyUserPointer(iov[i].iov_base, iov[i].iov_len)) return abi.EINVAL;

        const result = sys_write(fd, @ptrFromInt(iov[i].iov_base), iov[i].iov_len);
        if (result < 0) {
            if (total > 0) return @intCast(total);
            return result;
        }
        total += @intCast(result);
        if (@as(usize, @intCast(result)) < iov[i].iov_len) break;
    }

    return @intCast(total);
}

pub fn sys_isatty(fd: i32) i32 {
    const effective_fd = support.resolveIoFd(fd);
    if (effective_fd == abi.STDIN or effective_fd == abi.STDOUT or effective_fd == abi.STDERR) {
        return 1;
    }
    if (descriptor.lookup(effective_fd) != null) return 0;
    if (effective_fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(effective_fd - abi.FD_OFFSET);
    const vnode = vfs.getVNodeFromFd(vfs_fd) catch return abi.EBADF;
    defer vfs.releaseVNode(vnode);
    return if (tty.isTtyVNode(vnode)) 1 else 0;
}

pub fn sys_statfs(pathname: [*]const u8, buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(StatFs))) return abi.EINVAL;

    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = support.copyUserPathFromPointer(pathname, &kernel_buffer) catch return abi.EINVAL;

    _ = vfs.lookupPath(path_slice) catch |err| return errno.vfsErrno(err);

    const buf = support.syntheticStatFs();

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_fstatfs(fd: i32, buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(StatFs))) return abi.EINVAL;
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    _ = vfs.getFileFlags(vfs_fd) catch return abi.EBADF;

    const buf = support.syntheticStatFs();

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return abi.EINVAL;
    return 0;
}
