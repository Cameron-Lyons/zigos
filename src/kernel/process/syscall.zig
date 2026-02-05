const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const idt = @import("../interrupts/idt.zig");
const process = @import("process.zig");
const vga = @import("../drivers/vga.zig");
const keyboard = @import("../drivers/keyboard.zig");
const protection = @import("../memory/protection.zig");
const posix = @import("../utils/posix.zig");
const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");
const vfs = @import("../fs/vfs.zig");
const credentials = @import("credentials.zig");
const signal = @import("signal.zig");
const socket = @import("../net/socket.zig");
const ipc = @import("ipc.zig");

pub const SYS_EXIT = 1;
pub const SYS_WRITE = 2;
pub const SYS_READ = 3;
pub const SYS_OPEN = 4;
pub const SYS_CLOSE = 5;
pub const SYS_GETPID = 6;
pub const SYS_YIELD = 7;
pub const SYS_FORK = 8;
pub const SYS_EXECVE = 9;
pub const SYS_WAIT4 = 10;
pub const SYS_BRK = 11;
pub const SYS_MMAP = 12;
pub const SYS_MKDIR = 13;
pub const SYS_RMDIR = 14;
pub const SYS_UNLINK = 15;
pub const SYS_RENAME = 16;
pub const SYS_LSEEK = 17;
pub const SYS_STAT = 18;
pub const SYS_FSTAT = 19;
pub const SYS_GETUID = 20;
pub const SYS_GETGID = 21;
pub const SYS_SETUID = 22;
pub const SYS_SETGID = 23;
pub const SYS_CHOWN = 24;
pub const SYS_PIPE = 25;
pub const SYS_DUP2 = 26;
pub const SYS_SOCKET = 27;
pub const SYS_BIND = 28;
pub const SYS_CONNECT = 29;
pub const SYS_LISTEN = 30;
pub const SYS_ACCEPT = 31;
pub const SYS_SEND = 32;
pub const SYS_RECV = 33;
pub const SYS_SHUTDOWN = 34;
pub const SYS_KILL = 35;
pub const SYS_SIGACTION = 36;
pub const SYS_GETCWD = 37;
pub const SYS_CHDIR = 38;
pub const SYS_MSGGET = 39;
pub const SYS_MSGSND = 40;
pub const SYS_MSGRCV = 41;
pub const SYS_MUNMAP = 42;
pub const SYS_IOCTL = 43;
pub const SYS_GETPPID = 44;
pub const SYS_GETPGID = 45;
pub const SYS_SETPGID = 46;
pub const SYS_SETSID = 47;
pub const SYS_NANOSLEEP = 48;
pub const SYS_CLOCK_GETTIME = 49;
pub const SYS_ACCESS = 50;
pub const SYS_CHMOD = 51;
pub const SYS_FCHMOD = 52;
pub const SYS_FTRUNCATE = 53;
pub const SYS_GETDENTS = 54;
pub const SYS_SYMLINK = 55;
pub const SYS_LINK = 56;
pub const SYS_READLINK = 57;
pub const SYS_SIGPROCMASK = 58;
pub const SYS_SIGPENDING = 59;
pub const SYS_SIGSUSPEND = 60;
pub const SYS_DUP = 61;
pub const SYS_FCNTL = 62;
pub const SYS_SELECT = 63;
pub const SYS_UMASK = 64;
pub const SYS_UNAME = 65;
pub const SYS_TRUNCATE = 66;
pub const SYS_PREAD = 67;
pub const SYS_PWRITE = 68;
pub const SYS_SENDTO = 69;
pub const SYS_RECVFROM = 70;
pub const SYS_GETSOCKNAME = 71;
pub const SYS_GETPEERNAME = 72;
pub const SYS_FCHOWN = 73;
pub const SYS_FSYNC = 74;
pub const SYS_FDATASYNC = 75;
pub const SYS_POLL = 76;
pub const SYS_LSTAT = 77;
pub const SYS_GETSOCKOPT = 78;
pub const SYS_SETSOCKOPT = 79;
pub const SYS_READV = 80;
pub const SYS_WRITEV = 81;
pub const SYS_GETEUID = 82;
pub const SYS_GETEGID = 83;
pub const SYS_ISATTY = 84;
pub const SYS_STATFS = 85;
pub const SYS_FSTATFS = 86;

pub const STDIN = 0;
pub const STDOUT = 1;
pub const STDERR = 2;
const FD_OFFSET = 3;

pub const EPERM = -1;
pub const ENOENT = -2;
pub const ESRCH = -3;
pub const EINTR = -4;
pub const EBADF = -9;
pub const EAGAIN = -11;
pub const ENOMEM = -12;
pub const EACCES = -13;
pub const EFAULT = -14;
pub const ENOTDIR = -20;
pub const EINVAL = -22;
pub const EEXIST = -17;
pub const EISDIR = -21;
pub const ENFILE = -23;
pub const EMFILE = -24;
pub const ENOSPC = -28;
pub const EROFS = -30;
pub const EPIPE = -32;
pub const ENAMETOOLONG = -36;
pub const ENOSYS = -38;
pub const EOVERFLOW = -75;
pub const ENODEV = -19;
pub const EOPNOTSUPP = -95;
pub const EAFNOSUPPORT = -97;
pub const EADDRINUSE = -98;
pub const EADDRNOTAVAIL = -99;
pub const ENETDOWN = -100;
pub const ENETUNREACH = -101;
pub const ECONNABORTED = -103;
pub const ECONNRESET = -104;
pub const ENOBUFS = -105;
pub const EISCONN = -106;
pub const ENOTCONN = -107;
pub const ETIMEDOUT = -110;
pub const ECONNREFUSED = -111;
pub const EHOSTUNREACH = -113;
pub const ENXIO = -6;
pub const ENOEXEC = -8;
pub const EXDEV = -18;
pub const ENOTTY = -25;
pub const ETXTBSY = -26;
pub const ELOOP = -40;
pub const EMSGSIZE = -90;

fn vfsErrno(err: vfs.VFSError) i32 {
    return switch (err) {
        vfs.VFSError.NotFound => ENOENT,
        vfs.VFSError.PermissionDenied => EACCES,
        vfs.VFSError.IsDirectory => EISDIR,
        vfs.VFSError.NotDirectory => ENOTDIR,
        vfs.VFSError.AlreadyExists => EEXIST,
        vfs.VFSError.NoSpace => ENOSPC,
        vfs.VFSError.ReadOnly => EROFS,
        vfs.VFSError.OutOfMemory => ENOMEM,
        vfs.VFSError.InvalidPath => EINVAL,
        vfs.VFSError.InvalidOperation => EINVAL,
        vfs.VFSError.DeviceError => EINVAL,
        vfs.VFSError.BrokenPipe => EPIPE,
        vfs.VFSError.TooManyOpenFiles => EMFILE,
    };
}

fn socketErrno(err: anyerror) i32 {
    if (err == socket.SocketError.InvalidSocket) return EBADF;
    if (err == socket.SocketError.InvalidAddress) return EINVAL;
    if (err == socket.SocketError.AlreadyConnected) return EISCONN;
    if (err == socket.SocketError.NotConnected) return ENOTCONN;
    if (err == socket.SocketError.ConnectionRefused) return ECONNREFUSED;
    if (err == socket.SocketError.ConnectionReset) return ECONNRESET;
    if (err == socket.SocketError.NoBufferSpace) return ENOBUFS;
    if (err == socket.SocketError.Timeout) return ETIMEDOUT;
    if (err == socket.SocketError.AddressInUse) return EADDRINUSE;
    if (err == socket.SocketError.NotListening) return EINVAL;
    if (err == error.OutOfMemory) return ENOMEM;
    return EINVAL;
}

export fn syscall_handler(regs: *idt.InterruptRegisters) callconv(.c) void {
    const syscall_num = regs.eax;

    const arg1 = regs.ebx;
    const arg2 = regs.ecx;
    const arg3 = regs.edx;
    const arg4 = regs.esi;
    const arg5 = regs.edi;

    const result = switch (syscall_num) {
        SYS_EXIT => sys_exit(@intCast(arg1)),
        SYS_WRITE => sys_write(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_READ => sys_read(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3),
        SYS_OPEN => sys_open(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_CLOSE => sys_close(@intCast(arg1)),
        SYS_GETPID => sys_getpid(),
        SYS_YIELD => sys_yield(),
        SYS_FORK => sys_fork(),
        SYS_EXECVE => sys_execve(@as([*]const u8, @ptrFromInt(arg1)), arg2, arg3),
        SYS_WAIT4 => sys_wait4(@intCast(arg1), @as(?*i32, @ptrFromInt(arg2)), @intCast(arg3), @as(?*anyopaque, @ptrFromInt(arg4))),
        SYS_BRK => sys_brk(arg1),
        SYS_MMAP => sys_mmap(arg1, arg2, @intCast(arg3), @intCast(arg4), @intCast(arg5), @intCast(@as(i32, @intCast(regs.ebp)))),
        SYS_MKDIR => sys_mkdir(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_RMDIR => sys_rmdir(@as([*]const u8, @ptrFromInt(arg1))),
        SYS_UNLINK => sys_unlink(@as([*]const u8, @ptrFromInt(arg1))),
        SYS_RENAME => sys_rename(@as([*]const u8, @ptrFromInt(arg1)), @as([*]const u8, @ptrFromInt(arg2))),
        SYS_LSEEK => sys_lseek(@intCast(arg1), @as(i64, @bitCast(@as(u64, arg2) | (@as(u64, arg3) << 32))), @intCast(arg4)),
        SYS_STAT => sys_stat(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_GETUID => sys_getuid(),
        SYS_GETGID => sys_getgid(),
        SYS_SETUID => sys_setuid(@intCast(arg1)),
        SYS_SETGID => sys_setgid(@intCast(arg1)),
        SYS_CHOWN => sys_chown(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2), @intCast(arg3)),
        SYS_FSTAT => sys_fstat(@intCast(arg1), arg2),
        SYS_PIPE => sys_pipe(@as(?*[2]i32, @ptrFromInt(arg1))),
        SYS_DUP2 => sys_dup2(@intCast(arg1), @intCast(arg2)),
        SYS_SOCKET => sys_socket(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_BIND => sys_bind(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_CONNECT => sys_connect(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_LISTEN => sys_listen(@intCast(arg1), @intCast(arg2)),
        SYS_ACCEPT => sys_accept(@intCast(arg1)),
        SYS_SEND => sys_send(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_RECV => sys_recv(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3),
        SYS_SHUTDOWN => sys_shutdown(@intCast(arg1)),
        SYS_KILL => sys_kill(@intCast(arg1), @intCast(arg2)),
        SYS_SIGACTION => sys_sigaction(@intCast(arg1), arg2, arg3),
        SYS_GETCWD => sys_getcwd(@as([*]u8, @ptrFromInt(arg1)), arg2),
        SYS_CHDIR => sys_chdir(@as([*]const u8, @ptrFromInt(arg1))),
        SYS_MSGGET => sys_msgget(@intCast(arg1)),
        SYS_MSGSND => sys_msgsnd(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_MSGRCV => sys_msgrcv(@as([*]u8, @ptrFromInt(arg1)), arg2, @intCast(arg3)),
        SYS_MUNMAP => sys_munmap(arg1, arg2),
        SYS_IOCTL => sys_ioctl(@intCast(arg1), @intCast(arg2), arg3),
        SYS_GETPPID => sys_getppid_syscall(),
        SYS_GETPGID => sys_getpgid(@intCast(arg1)),
        SYS_SETPGID => sys_setpgid(@intCast(arg1), @intCast(arg2)),
        SYS_SETSID => sys_setsid(),
        SYS_NANOSLEEP => sys_nanosleep(arg1, arg2),
        SYS_CLOCK_GETTIME => sys_clock_gettime(@intCast(arg1), arg2),
        SYS_ACCESS => sys_access(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_CHMOD => sys_chmod_syscall(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_FCHMOD => sys_fchmod(@intCast(arg1), arg2),
        SYS_FTRUNCATE => sys_ftruncate(@intCast(arg1), arg2),
        SYS_GETDENTS => sys_getdents(@intCast(arg1), arg2, arg3),
        SYS_SYMLINK => sys_symlink(@as([*]const u8, @ptrFromInt(arg1)), @as([*]const u8, @ptrFromInt(arg2))),
        SYS_LINK => sys_link(@as([*]const u8, @ptrFromInt(arg1)), @as([*]const u8, @ptrFromInt(arg2))),
        SYS_READLINK => sys_readlink(@as([*]const u8, @ptrFromInt(arg1)), @as([*]u8, @ptrFromInt(arg2)), arg3),
        SYS_SIGPROCMASK => sys_sigprocmask(@intCast(arg1), arg2, arg3),
        SYS_SIGPENDING => sys_sigpending(arg1),
        SYS_SIGSUSPEND => sys_sigsuspend(arg1),
        SYS_DUP => sys_dup(@intCast(arg1)),
        SYS_FCNTL => sys_fcntl(@intCast(arg1), @intCast(arg2), arg3),
        SYS_SELECT => sys_select(@intCast(arg1), arg2, arg3, arg4),
        SYS_UMASK => sys_umask(@intCast(arg1)),
        SYS_UNAME => sys_uname(arg1),
        SYS_TRUNCATE => sys_truncate(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_PREAD => sys_pread(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3, @as(u64, arg4) | (@as(u64, arg5) << 32)),
        SYS_PWRITE => sys_pwrite(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3, @as(u64, arg4) | (@as(u64, arg5) << 32)),
        SYS_SENDTO => sys_sendto(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3, arg4, @intCast(arg5)),
        SYS_RECVFROM => sys_recvfrom(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3, arg4, arg5),
        SYS_GETSOCKNAME => sys_getsockname(@intCast(arg1), arg2, arg3),
        SYS_GETPEERNAME => sys_getpeername(@intCast(arg1), arg2, arg3),
        SYS_FCHOWN => sys_fchown(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_FSYNC => sys_fsync(@intCast(arg1)),
        SYS_FDATASYNC => sys_fsync(@intCast(arg1)),
        SYS_POLL => sys_poll(arg1, @intCast(arg2), @intCast(@as(i32, @bitCast(arg3)))),
        SYS_LSTAT => sys_lstat(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_GETSOCKOPT => sys_getsockopt(@intCast(arg1), @intCast(arg2), @intCast(arg3), arg4, arg5),
        SYS_SETSOCKOPT => sys_setsockopt(@intCast(arg1), @intCast(arg2), @intCast(arg3), arg4, arg5),
        SYS_READV => sys_readv(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_WRITEV => sys_writev(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_GETEUID => sys_geteuid(),
        SYS_GETEGID => sys_getegid(),
        SYS_ISATTY => sys_isatty(@intCast(arg1)),
        SYS_STATFS => sys_statfs(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_FSTATFS => sys_fstatfs(@intCast(arg1), arg2),
        else => ENOSYS,
    };

    regs.eax = @intCast(@as(i32, result));

    signal.handlePendingSignals();
}

fn sys_exit(status: i32) i32 {
    if (process.current_process) |proc| {
        proc.state = .Terminated;
        proc.exit_code = status;

        if (proc.parent_pid != 0) {
            if (process.getProcessByPid(proc.parent_pid)) |parent| {
                signal.sendSignal(parent, signal.SIGCHLD);
            }
        }

        _ = process.schedule();

        x86.hlt();
    }

    return 0;
}

fn sys_write(fd: i32, buf: [*]const u8, count: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return EINVAL;
    }

    if (fd == STDOUT or fd == STDERR) {
        // SAFETY: filled by the subsequent copyFromUser call
        var kernel_buffer: [256]u8 = undefined;
        var written: usize = 0;

        while (written < count) {
            const chunk_size = @min(count - written, kernel_buffer.len);
            protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch {
                return EINVAL;
            };

            var i: usize = 0;
            while (i < chunk_size) : (i += 1) {
                vga.print(&[_]u8{kernel_buffer[i]});
            }

            written += chunk_size;
        }

        return @intCast(count);
    }

    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    // SAFETY: filled by the subsequent copyFromUser call
    var kernel_buffer: [512]u8 = undefined;
    var written: usize = 0;

    while (written < count) {
        const chunk_size = @min(count - written, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch {
            return EINVAL;
        };

        const bytes_written = vfs.write(vfs_fd, kernel_buffer[0..chunk_size]) catch |err| return vfsErrno(err);
        written += bytes_written;
        if (bytes_written < chunk_size) break;
    }

    return @intCast(written);
}

fn sys_read(fd: i32, buf: [*]u8, count: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return EINVAL;
    }

    if (fd == STDIN) {
        // SAFETY: filled by the subsequent keyboard.getchar calls
        var kernel_buffer: [256]u8 = undefined;
        const read_size = @min(count, kernel_buffer.len);
        var i: usize = 0;

        while (i < read_size) : (i += 1) {
            while (!keyboard.has_char()) {
                x86.hlt();
            }

            if (keyboard.getchar()) |ch| {
                kernel_buffer[i] = ch;

                if (ch == '\n') {
                    i += 1;
                    break;
                }
            }
        }

        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..i]) catch {
            return EINVAL;
        };

        return @intCast(i);
    }

    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    // SAFETY: filled by the subsequent vfs.read call
    var kernel_buffer: [512]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < count) {
        const chunk_size = @min(count - total_read, kernel_buffer.len);
        const bytes_read = vfs.read(vfs_fd, kernel_buffer[0..chunk_size]) catch |err| return vfsErrno(err);
        if (bytes_read == 0) break;

        protection.copyToUser(@intFromPtr(buf) + total_read, kernel_buffer[0..bytes_read]) catch {
            return EINVAL;
        };

        total_read += bytes_read;
        if (bytes_read < chunk_size) break;
    }

    return @intCast(total_read);
}

fn sys_getpid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.pid);
    }
    return 0;
}

fn sys_yield() i32 {
    process.yield();
    return 0;
}

fn sys_mkdir(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

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

    vfs.mkdir(path_slice, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_rmdir(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.rmdir(path_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_unlink(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.unlink(path_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_rename(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), 256) or
        !protection.verifyUserPointer(@intFromPtr(newpath), 256))
    {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var old_buffer: [256]u8 = undefined;
    // SAFETY: filled by the subsequent copyStringFromUser call
    var new_buffer: [256]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return EINVAL;

    vfs.rename(old_slice, new_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_open(pathname: [*]const u8, flags: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    if (process.current_process) |proc| {
        if (vfs.lookupPath(path_slice)) |vnode| {
            const access_mode = flags & 0x3;
            var access: u3 = 0;
            if (access_mode == 0 or access_mode == 2) access |= 4;
            if (access_mode == 1 or access_mode == 2) access |= 2;
            if (!credentials.checkPermission(&proc.creds, vnode.mode, vnode.uid, vnode.gid, access)) {
                return EACCES;
            }
        } else |_| {}
    }

    const vfs_fd = vfs.open(path_slice, flags) catch |err| return vfsErrno(err);
    return @intCast(@as(i32, @intCast(vfs_fd)) + FD_OFFSET);
}

fn sys_close(fd: i32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    vfs.close(vfs_fd) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_lseek(fd: i32, offset: i64, whence: u32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    const result = vfs.lseek(vfs_fd, offset, whence) catch |err| return vfsErrno(err);
    if (result > 0x7FFFFFFF) return EOVERFLOW;
    return @intCast(result);
}

fn sys_stat(pathname: [*]const u8, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    // SAFETY: filled by the subsequent vfs.stat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(path_slice, &stat_buf) catch |err| return vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return EINVAL;
    return 0;
}

pub fn init() void {
    idt.register_interrupt_handler(0x80, syscall_handler);

    idt.set_gate_flags(0x80, 0x8E | 0x60);
}

pub fn syscall0(num: u32) i32 {
    // SAFETY: populated by the subsequent inline assembly (int $0x80)
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
        : "memory"
    );
    return result;
}

pub fn syscall1(num: u32, arg1: usize) i32 {
    // SAFETY: populated by the subsequent inline assembly (int $0x80)
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
        : "memory"
    );
    return result;
}

pub fn syscall3(num: u32, arg1: usize, arg2: usize, arg3: usize) i32 {
    // SAFETY: populated by the subsequent inline assembly (int $0x80)
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
        : "memory"
    );
    return result;
}

fn sys_getuid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.creds.uid);
    }
    return 0;
}

fn sys_getgid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.creds.gid);
    }
    return 0;
}

fn sys_setuid(uid: u16) i32 {
    if (process.current_process) |proc| {
        if (proc.creds.euid == 0 or proc.creds.uid == uid) {
            proc.creds.uid = uid;
            proc.creds.euid = uid;
            return 0;
        }
        return EPERM;
    }
    return ENOSYS;
}

fn sys_setgid(gid: u16) i32 {
    if (process.current_process) |proc| {
        if (proc.creds.euid == 0 or proc.creds.gid == gid) {
            proc.creds.gid = gid;
            proc.creds.egid = gid;
            return 0;
        }
        return EPERM;
    }
    return ENOSYS;
}

fn sys_chown(pathname: [*]const u8, uid: u16, gid: u16) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    if (process.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return EPERM;
        }
    }

    vfs.chown(path_slice, uid, gid) catch |err| return vfsErrno(err);
    return 0;
}

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

const SockAddrIn = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

const SockAddrIn6 = extern struct {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};

var socket_table: [64]?*socket.Socket = [_]?*socket.Socket{null} ** 64;

fn sys_socket(domain: u32, sock_type: u32, protocol: u32) i32 {
    _ = protocol;
    const addr_family: socket.AddressFamily = switch (domain) {
        AF_INET => .AF_INET,
        AF_INET6 => .AF_INET6,
        else => return EAFNOSUPPORT,
    };

    const s_type: socket.SocketType = switch (sock_type) {
        SOCK_STREAM => .STREAM,
        SOCK_DGRAM => .DGRAM,
        else => return EINVAL,
    };

    const s_proto: socket.Protocol = switch (sock_type) {
        SOCK_STREAM => .TCP,
        SOCK_DGRAM => .UDP,
        else => return EINVAL,
    };

    const sock = socket.createSocket(s_type, s_proto) catch return ENOMEM;
    sock.address_family = addr_family;

    for (&socket_table, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = sock;
            return @intCast(i);
        }
    }

    sock.close();
    return EMFILE;
}

fn sys_bind(sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (sock.address_family == .AF_INET6) {
        if (addr_len < @sizeOf(SockAddrIn6)) return EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return EINVAL;

        var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
        protection.copyFromUser(&addr_buf, addr_ptr) catch return EINVAL;
        const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

        sock.local_ipv6 = @import("../net/ipv6.zig").IPv6Address{ .octets = addr.addr };
        sock.local_port = @byteSwap(addr.port);
        return 0;
    }

    if (addr_len < @sizeOf(SockAddrIn)) return EINVAL;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return EINVAL;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return EINVAL;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    const ipv4_addr = @import("../net/ipv4.zig").IPv4Address{
        .octets = .{
            @intCast((addr.addr >> 0) & 0xFF),
            @intCast((addr.addr >> 8) & 0xFF),
            @intCast((addr.addr >> 16) & 0xFF),
            @intCast((addr.addr >> 24) & 0xFF),
        },
    };

    sock.bind(ipv4_addr, @byteSwap(addr.port)) catch |err| return socketErrno(err);
    return 0;
}

fn sys_connect(sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (sock.address_family == .AF_INET6) {
        if (addr_len < @sizeOf(SockAddrIn6)) return EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return EINVAL;

        var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
        protection.copyFromUser(&addr_buf, addr_ptr) catch return EINVAL;
        const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

        sock.remote_ipv6 = @import("../net/ipv6.zig").IPv6Address{ .octets = addr.addr };
        sock.remote_port = @byteSwap(addr.port);
        sock.state = .CONNECTED;
        return 0;
    }

    if (addr_len < @sizeOf(SockAddrIn)) return EINVAL;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return EINVAL;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return EINVAL;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    const ipv4_addr = @import("../net/ipv4.zig").IPv4Address{
        .octets = .{
            @intCast((addr.addr >> 0) & 0xFF),
            @intCast((addr.addr >> 8) & 0xFF),
            @intCast((addr.addr >> 16) & 0xFF),
            @intCast((addr.addr >> 24) & 0xFF),
        },
    };

    sock.connect(ipv4_addr, @byteSwap(addr.port)) catch |err| return socketErrno(err);
    return 0;
}

fn sys_listen(sockfd: i32, backlog: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    sock.listen(backlog) catch |err| return socketErrno(err);
    return 0;
}

fn sys_accept(sockfd: i32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    const client = sock.accept() catch |err| return socketErrno(err);

    for (&socket_table, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = client;
            return @intCast(i);
        }
    }

    client.close();
    return EMFILE;
}

fn sys_send(sockfd: i32, buf: [*]const u8, len: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser call
    var kernel_buffer: [4096]u8 = undefined;
    const to_send = @min(len, kernel_buffer.len);
    protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return EINVAL;

    const sent = sock.send(kernel_buffer[0..to_send]) catch |err| return socketErrno(err);
    return @intCast(sent);
}

fn sys_recv(sockfd: i32, buf: [*]u8, len: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    // SAFETY: filled by the subsequent sock.recv call
    var kernel_buffer: [4096]u8 = undefined;
    const to_recv = @min(len, kernel_buffer.len);

    const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return socketErrno(err);
    if (received == 0) return 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return EINVAL;
    return @intCast(received);
}

fn sys_shutdown(sockfd: i32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    sock.close();
    socket_table[@intCast(sockfd)] = null;
    return 0;
}

fn sys_kill(pid: i32, signum: i32) i32 {
    signal.kill(pid, signum) catch |err| {
        return switch (err) {
            error.InvalidSignal => EINVAL,
            error.NoSuchProcess => ESRCH,
        };
    };
    return 0;
}

fn sys_sigaction(signum: i32, act_addr: usize, oldact_addr: usize) i32 {
    var act: ?*const signal.SigAction = null;
    var oldact: ?*signal.SigAction = null;

    // SAFETY: filled by the subsequent copyFromUser call
    var act_buf: [@sizeOf(signal.SigAction)]u8 = undefined;
    // SAFETY: filled by the subsequent sigaction call
    var oldact_buf: signal.SigAction = undefined;

    if (act_addr != 0) {
        if (!protection.verifyUserPointer(act_addr, @sizeOf(signal.SigAction))) return EINVAL;
        protection.copyFromUser(&act_buf, act_addr) catch return EINVAL;
        act = @ptrCast(@alignCast(&act_buf));
    }

    if (oldact_addr != 0) {
        if (!protection.verifyUserPointer(oldact_addr, @sizeOf(signal.SigAction))) return EINVAL;
        oldact = &oldact_buf;
    }

    signal.sigaction(signum, act, oldact) catch return EINVAL;

    if (oldact_addr != 0) {
        protection.copyToUser(oldact_addr, std.mem.asBytes(&oldact_buf)) catch return EINVAL;
    }

    return 0;
}

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

fn sys_getcwd(buf: [*]u8, size: usize) i32 {
    ensureCwdInit();
    if (!protection.verifyUserPointer(@intFromPtr(buf), size)) return EINVAL;
    if (size < cwd_len + 1) return EINVAL;

    // SAFETY: cwd_len bytes + null terminator written before copy
    var kernel_buf: [257]u8 = undefined;
    @memcpy(kernel_buf[0..cwd_len], current_working_dir[0..cwd_len]);
    kernel_buf[cwd_len] = 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buf[0 .. cwd_len + 1]) catch return EINVAL;
    return @intCast(cwd_len);
}

fn sys_chdir(pathname: [*]const u8) i32 {
    ensureCwdInit();
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    const node = vfs.lookupPath(path_slice) catch return ENOENT;
    if (node.file_type != .Directory) return ENOTDIR;

    @memcpy(current_working_dir[0..path_slice.len], path_slice);
    cwd_len = path_slice.len;

    return 0;
}

fn sys_fstat(fd: i32, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) {
        return EINVAL;
    }

    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    // SAFETY: filled by the subsequent vfs.fstat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.fstat(vfs_fd, &stat_buf) catch |err| return vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return EINVAL;
    return 0;
}

fn sys_pipe(pipefd: ?*[2]i32) i32 {
    if (pipefd == null) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(pipefd), @sizeOf([2]i32))) {
        return EINVAL;
    }

    const result = vfs.createPipe() catch |err| return vfsErrno(err);
    const fds = [2]i32{
        @as(i32, @intCast(result.read_fd)) + FD_OFFSET,
        @as(i32, @intCast(result.write_fd)) + FD_OFFSET,
    };

    protection.copyToUser(@intFromPtr(pipefd), std.mem.asBytes(&fds)) catch return EINVAL;
    return 0;
}

fn sys_dup2(old_fd: i32, new_fd: i32) i32 {
    if (old_fd < FD_OFFSET or new_fd < FD_OFFSET) return EBADF;
    const old_vfs_fd: u32 = @intCast(old_fd - FD_OFFSET);
    const new_vfs_fd: u32 = @intCast(new_fd - FD_OFFSET);

    const result = vfs.dup2(old_vfs_fd, new_vfs_fd) catch |err| return vfsErrno(err);
    return @as(i32, @intCast(result)) + FD_OFFSET;
}

fn sys_fork() i32 {
    const result = posix.fork() catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.NoProcessSlots => EAGAIN,
            error.OutOfMemory => ENOMEM,
        };
    };
    return result;
}

fn sys_execve(path: [*]const u8, argv: usize, envp: usize) i32 {
    // SAFETY: filled by the subsequent copyStringFromUser call
    var path_buf: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buf, @intFromPtr(path)) catch {
        return EINVAL;
    };

    // SAFETY: entries written before read; argv_count tracks valid entries
    var argv_array: [32][]const u8 = undefined;
    var argv_count: usize = 0;
    // SAFETY: entries filled by subsequent copyStringFromUser calls
    var argv_buffers: [32][256]u8 = undefined;

    if (argv != 0) {
        while (argv_count < 32) {
            const ptr_addr = argv + argv_count * @sizeOf(usize);
            if (!protection.verifyUserPointer(ptr_addr, @sizeOf(usize))) {
                break;
            }

            const str_ptr = @as(*const usize, @ptrFromInt(ptr_addr)).*;
            if (str_ptr == 0) break;

            const arg_slice = protection.copyStringFromUser(&argv_buffers[argv_count], str_ptr) catch {
                break;
            };
            argv_array[argv_count] = arg_slice;
            argv_count += 1;
        }
    }

    // SAFETY: entries written before read; envp_count tracks valid entries
    var envp_array: [32][]const u8 = undefined;
    var envp_count: usize = 0;
    // SAFETY: entries filled by subsequent copyStringFromUser calls
    var envp_buffers: [32][256]u8 = undefined;

    if (envp != 0) {
        while (envp_count < 32) {
            const ptr_addr = envp + envp_count * @sizeOf(usize);
            if (!protection.verifyUserPointer(ptr_addr, @sizeOf(usize))) {
                break;
            }

            const str_ptr = @as(*const usize, @ptrFromInt(ptr_addr)).*;
            if (str_ptr == 0) break;

            const env_slice = protection.copyStringFromUser(&envp_buffers[envp_count], str_ptr) catch {
                break;
            };
            envp_array[envp_count] = env_slice;
            envp_count += 1;
        }
    }

    const argv_slice = argv_array[0..argv_count];
    const envp_slice = envp_array[0..envp_count];

    posix.execve(path_slice, argv_slice, envp_slice) catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.OutOfMemory => ENOMEM,
            error.FileReadError => ENOENT,
            else => EINVAL,
        };
    };

    return 0;
}

fn sys_wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) i32 {
    const result = posix.wait4(pid, status, options, rusage) catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.InvalidPointer => EINVAL,
        };
    };
    return result;
}

var current_brk: usize = protection.USER_HEAP_START;

fn sys_brk(addr: usize) i32 {
    if (addr == 0) {
        return @intCast(current_brk);
    }

    if (addr < protection.USER_HEAP_START or addr >= protection.USER_SPACE_END) {
        return @intCast(current_brk);
    }

    const new_brk = (addr + 0xFFF) & ~@as(usize, 0xFFF);

    if (new_brk > current_brk) {
        var page_addr = current_brk;
        while (page_addr < new_brk) : (page_addr += 0x1000) {
            const phys_page = memory.allocatePhysicalPage() orelse {
                return @intCast(current_brk);
            };
            paging.mapPage(@intCast(page_addr), phys_page, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
        }
    } else if (new_brk < current_brk) {
        var page_addr = new_brk;
        while (page_addr < current_brk) : (page_addr += 0x1000) {
            paging.unmap_page(@intCast(page_addr));
        }
    }

    current_brk = new_brk;
    return @intCast(current_brk);
}

const MAP_SHARED = 0x01;
const MAP_PRIVATE = 0x02;
const MAP_ANONYMOUS = 0x20;
const MAP_FIXED = 0x10;

fn sys_mmap(addr: usize, length: usize, prot: i32, flags: i32, fd: i32, offset: i32) i32 {
    if (length == 0) {
        return EINVAL;
    }

    if ((flags & MAP_ANONYMOUS) == 0) {
        if (fd < 0) {
            return EINVAL;
        }

        _ = offset;
        return ENOSYS;
    }

    if ((flags & MAP_PRIVATE) != 0 and (flags & MAP_SHARED) != 0) {
        return EINVAL;
    }
    if ((flags & MAP_PRIVATE) == 0 and (flags & MAP_SHARED) == 0) {
        return EINVAL;
    }

    // SAFETY: assigned in every branch of the if/else below
    var result_addr: usize = undefined;
    if (addr != 0) {
        const aligned_addr = addr & ~@as(usize, 0xFFF);

        if ((flags & MAP_FIXED) != 0) {
            if (aligned_addr < protection.USER_HEAP_START or aligned_addr >= protection.USER_SPACE_END) {
                return EINVAL;
            }

            result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch {
                return ENOMEM;
            };
        } else {
            result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch {
                return ENOMEM;
            };
        }
    } else {
        result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch {
            return ENOMEM;
        };
    }

    return @intCast(result_addr);
}

fn sys_msgget(max_messages: u32) i32 {
    const pid = if (process.current_process) |proc| proc.pid else return ENOSYS;
    const clamped = if (max_messages == 0) @as(u32, 16) else @min(max_messages, 256);

    if (ipc.getMessageQueue(pid) != null) return 0;

    _ = ipc.createMessageQueue(pid, clamped) catch return ENOMEM;
    return 0;
}

fn sys_msgsnd(receiver_pid: u32, buf: [*]const u8, len: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;
    const sender_pid = if (process.current_process) |proc| proc.pid else return ENOSYS;

    const msg_len = @min(len, 256);
    // SAFETY: filled by the subsequent copyFromUser call
    var kernel_buffer: [256]u8 = undefined;
    protection.copyFromUser(kernel_buffer[0..msg_len], @intFromPtr(buf)) catch return EINVAL;

    ipc.sendMessage(sender_pid, receiver_pid, .Data, kernel_buffer[0..msg_len]) catch |err| {
        return switch (err) {
            error.OutOfMemory => ENOMEM,
            error.ReceiverNotFound => ESRCH,
            error.QueueFull => EAGAIN,
        };
    };
    return 0;
}

fn sys_msgrcv(buf: [*]u8, size: usize, flags: i32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), size)) return EINVAL;
    const pid = if (process.current_process) |proc| proc.pid else return ENOSYS;

    const queue = ipc.getMessageQueue(pid) orelse return ENOENT;

    const msg = if (flags != 0) queue.tryReceive() else queue.receive();
    if (msg == null) return 0;

    const m = msg.?;
    const copy_len = @min(m.data_len, @as(u32, @intCast(size)));
    protection.copyToUser(@intFromPtr(buf), m.data[0..copy_len]) catch return EINVAL;
    return @intCast(copy_len);
}

fn sys_munmap(addr: usize, length: usize) i32 {
    if (addr == 0 or length == 0) return EINVAL;
    if (addr & 0xFFF != 0) return EINVAL;
    if (addr < protection.USER_HEAP_START or addr >= protection.USER_SPACE_END) return EINVAL;

    protection.freeUserMemory(addr, length);
    return 0;
}

fn sys_ioctl(fd: i32, request: u32, arg: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    const result = vfs.ioctl(vfs_fd, request, arg) catch |err| return vfsErrno(err);
    return result;
}

fn sys_getppid_syscall() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.parent_pid);
    }
    return 0;
}

fn sys_getpgid(pid: i32) i32 {
    if (pid == 0) {
        if (process.current_process) |proc| {
            return @intCast(proc.process_group);
        }
        return ESRCH;
    }

    if (pid > 0) {
        if (process.getProcessByPid(@intCast(pid))) |proc| {
            return @intCast(proc.process_group);
        }
    }
    return ESRCH;
}

fn sys_setpgid(pid: i32, pgid: i32) i32 {
    const target = blk: {
        if (pid == 0) {
            break :blk process.current_process orelse return ESRCH;
        }
        if (pid > 0) {
            break :blk process.getProcessByPid(@as(u32, @intCast(pid))) orelse return ESRCH;
        }
        return EINVAL;
    };

    if (pgid == 0) {
        target.process_group = target.pid;
    } else if (pgid > 0) {
        target.process_group = @intCast(pgid);
    } else {
        return EINVAL;
    }

    return 0;
}

fn sys_setsid() i32 {
    const proc = process.current_process orelse return EPERM;
    proc.process_group = proc.pid;
    return @intCast(proc.pid);
}

const TimeSpec = extern struct {
    tv_sec: i32,
    tv_nsec: i32,
};

fn sys_nanosleep(req_addr: usize, rem_addr: usize) i32 {
    if (!protection.verifyUserPointer(req_addr, @sizeOf(TimeSpec))) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser call
    var req: TimeSpec = undefined;
    protection.copyFromUser(std.mem.asBytes(&req), req_addr) catch return EINVAL;

    if (req.tv_sec < 0 or req.tv_nsec < 0 or req.tv_nsec >= 1_000_000_000) return EINVAL;

    const total_ms: u64 = @as(u64, @intCast(req.tv_sec)) * 1000 + @as(u64, @intCast(req.tv_nsec)) / 1_000_000;
    const ticks_to_wait = total_ms / 10;

    const start = process.getSystemTime();
    while (process.getSystemTime() - start < ticks_to_wait) {
        process.yield();
    }

    if (rem_addr != 0 and protection.verifyUserPointer(rem_addr, @sizeOf(TimeSpec))) {
        var zero = TimeSpec{ .tv_sec = 0, .tv_nsec = 0 };
        protection.copyToUser(rem_addr, std.mem.asBytes(&zero)) catch {};
    }

    return 0;
}

const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

fn sys_clock_gettime(clock_id: i32, tp_addr: usize) i32 {
    if (!protection.verifyUserPointer(tp_addr, @sizeOf(TimeSpec))) return EINVAL;

    switch (clock_id) {
        CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID => {},
        else => return EINVAL,
    }

    const ticks = process.getSystemTime();
    const total_ms = ticks * 10;

    const tp = TimeSpec{
        .tv_sec = @intCast(total_ms / 1000),
        .tv_nsec = @intCast((total_ms % 1000) * 1_000_000),
    };

    protection.copyToUser(tp_addr, std.mem.asBytes(&tp)) catch return EINVAL;
    return 0;
}

fn sys_access(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    const vnode = vfs.lookupPath(path_slice) catch return ENOENT;

    if (mode == 0) return 0;

    if (process.current_process) |proc| {
        var access_bits: u3 = 0;
        if (mode & 4 != 0) access_bits |= 4;
        if (mode & 2 != 0) access_bits |= 2;
        if (mode & 1 != 0) access_bits |= 1;
        if (!credentials.checkPermission(&proc.creds, vnode.mode, vnode.uid, vnode.gid, access_bits)) {
            return EACCES;
        }
    }

    return 0;
}

fn sys_chmod_syscall(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

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

    vfs.chmod(path_slice, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_fchmod(fd: i32, mode: u32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

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

    vfs.fchmod(vfs_fd, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_ftruncate(fd: i32, length: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    vfs.ftruncate(vfs_fd, length) catch |err| return vfsErrno(err);
    return 0;
}

const LinuxDirent = extern struct {
    d_ino: u32,
    d_off: u32,
    d_reclen: u16,
    d_type: u8,
};

fn sys_getdents(fd: i32, buf_addr: usize, buf_size: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    if (!protection.verifyUserPointer(buf_addr, buf_size)) return EINVAL;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    // SAFETY: filled by the subsequent vfs.readdir calls
    var dirent: vfs.DirEntry = undefined;
    var offset: usize = 0;
    var index: u64 = 0;

    while (offset + @sizeOf(LinuxDirent) + 1 < buf_size) {
        const has_entry = vfs.readdir(vfs_fd, &dirent, index) catch |err| return vfsErrno(err);
        if (!has_entry) break;

        const name_len = dirent.name_len;
        const reclen: u16 = @intCast(@sizeOf(LinuxDirent) + name_len + 1);
        if (offset + reclen > buf_size) break;

        var kernel_entry: LinuxDirent = .{
            .d_ino = @intCast(dirent.inode & 0xFFFFFFFF),
            .d_off = @intCast(index + 1),
            .d_reclen = reclen,
            .d_type = @intFromEnum(dirent.file_type),
        };

        protection.copyToUser(buf_addr + offset, std.mem.asBytes(&kernel_entry)) catch return EINVAL;
        protection.copyToUser(buf_addr + offset + @sizeOf(LinuxDirent), dirent.name[0..name_len]) catch return EINVAL;
        const null_byte = [_]u8{0};
        protection.copyToUser(buf_addr + offset + @sizeOf(LinuxDirent) + name_len, &null_byte) catch return EINVAL;

        offset += reclen;
        index += 1;
    }

    return @intCast(offset);
}

fn sys_symlink(target: [*]const u8, linkpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(target), 256)) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(linkpath), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser calls
    var target_buf: [256]u8 = undefined;
    var link_buf: [256]u8 = undefined;

    const target_slice = protection.copyStringFromUser(&target_buf, @intFromPtr(target)) catch return EINVAL;
    const link_slice = protection.copyStringFromUser(&link_buf, @intFromPtr(linkpath)) catch return EINVAL;

    vfs.symlink(target_slice, link_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_link(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), 256)) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(newpath), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser calls
    var old_buf: [256]u8 = undefined;
    var new_buf: [256]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buf, @intFromPtr(oldpath)) catch return EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buf, @intFromPtr(newpath)) catch return EINVAL;

    vfs.link(old_slice, new_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_readlink(pathname: [*]const u8, buf: [*]u8, buf_size: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(buf), buf_size)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser call
    var path_buf: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buf, @intFromPtr(pathname)) catch return EINVAL;

    // SAFETY: filled by the subsequent vfs.readlink call
    var kernel_buf: [256]u8 = undefined;
    const read_size = @min(buf_size, kernel_buf.len);
    const link_len = vfs.readlink(path_slice, kernel_buf[0..read_size]) catch |err| return vfsErrno(err);

    protection.copyToUser(@intFromPtr(buf), kernel_buf[0..link_len]) catch return EINVAL;
    return @intCast(link_len);
}

fn sys_sigprocmask(how: i32, set_addr: usize, oldset_addr: usize) i32 {
    var set_ptr: ?*const signal.SigSet = null;
    var oldset_ptr: ?*signal.SigSet = null;

    // SAFETY: filled by the subsequent copyFromUser call
    var set_buf: signal.SigSet = undefined;
    // SAFETY: filled by the subsequent sigprocmask call
    var oldset_buf: signal.SigSet = undefined;

    if (set_addr != 0) {
        if (!protection.verifyUserPointer(set_addr, @sizeOf(signal.SigSet))) return EINVAL;
        protection.copyFromUser(std.mem.asBytes(&set_buf), set_addr) catch return EINVAL;
        set_ptr = &set_buf;
    }

    if (oldset_addr != 0) {
        if (!protection.verifyUserPointer(oldset_addr, @sizeOf(signal.SigSet))) return EINVAL;
        oldset_ptr = &oldset_buf;
    }

    signal.sigprocmask(how, set_ptr, oldset_ptr) catch return EINVAL;

    if (oldset_addr != 0) {
        protection.copyToUser(oldset_addr, std.mem.asBytes(&oldset_buf)) catch return EINVAL;
    }

    return 0;
}

fn sys_sigpending(set_addr: usize) i32 {
    if (!protection.verifyUserPointer(set_addr, @sizeOf(signal.SigSet))) return EINVAL;

    // SAFETY: filled by the subsequent sigpending call
    var set: signal.SigSet = undefined;
    signal.sigpending(&set);

    protection.copyToUser(set_addr, std.mem.asBytes(&set)) catch return EINVAL;
    return 0;
}

fn sys_sigsuspend(mask_addr: usize) i32 {
    if (!protection.verifyUserPointer(mask_addr, @sizeOf(signal.SigSet))) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser call
    var mask: signal.SigSet = undefined;
    protection.copyFromUser(std.mem.asBytes(&mask), mask_addr) catch return EINVAL;

    signal.sigsuspend(&mask) catch |err| {
        return switch (err) {
            error.Interrupted => EINTR,
        };
    };
    return EINTR;
}

fn sys_dup(fd: i32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    var new_fd: u32 = 0;
    while (new_fd < 256) : (new_fd += 1) {
        const result = vfs.dup2(vfs_fd, new_fd) catch continue;
        return @as(i32, @intCast(result)) + FD_OFFSET;
    }
    return EMFILE;
}

const F_DUPFD = 0;
const F_GETFD = 1;
const F_SETFD = 2;
const F_GETFL = 3;
const F_SETFL = 4;
const FD_CLOEXEC: u32 = 1;

fn sys_fcntl(fd: i32, cmd: i32, arg: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    switch (cmd) {
        F_DUPFD => {
            const min_fd = if (arg >= FD_OFFSET) @as(u32, @intCast(arg - FD_OFFSET)) else 0;
            var new_fd = min_fd;
            while (new_fd < 256) : (new_fd += 1) {
                const result = vfs.dup2(vfs_fd, new_fd) catch continue;
                return @as(i32, @intCast(result)) + FD_OFFSET;
            }
            return EMFILE;
        },
        F_GETFD => {
            const fd_flags = vfs.getFdFlags(vfs_fd) catch return EBADF;
            return @intCast(fd_flags);
        },
        F_SETFD => {
            vfs.setFdFlags(vfs_fd, @intCast(arg & FD_CLOEXEC)) catch return EBADF;
            return 0;
        },
        F_GETFL => {
            const flags = vfs.getFileFlags(vfs_fd) catch return EBADF;
            return @intCast(flags);
        },
        F_SETFL => {
            vfs.setFileFlags(vfs_fd, @intCast(arg)) catch return EBADF;
            return 0;
        },
        else => return EINVAL,
    }
}

const FdSet = extern struct {
    fds_bits: [8]u32,
};

fn sys_select(nfds: i32, readfds_addr: usize, writefds_addr: usize, exceptfds_addr: usize) i32 {
    if (nfds < 0 or nfds > 256) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser calls
    var readfds: FdSet = std.mem.zeroes(FdSet);
    // SAFETY: filled by the subsequent copyFromUser calls
    var writefds: FdSet = std.mem.zeroes(FdSet);
    var result_readfds: FdSet = std.mem.zeroes(FdSet);
    var result_writefds: FdSet = std.mem.zeroes(FdSet);

    if (readfds_addr != 0) {
        if (!protection.verifyUserPointer(readfds_addr, @sizeOf(FdSet))) return EINVAL;
        protection.copyFromUser(std.mem.asBytes(&readfds), readfds_addr) catch return EINVAL;
    }

    if (writefds_addr != 0) {
        if (!protection.verifyUserPointer(writefds_addr, @sizeOf(FdSet))) return EINVAL;
        protection.copyFromUser(std.mem.asBytes(&writefds), writefds_addr) catch return EINVAL;
    }

    _ = exceptfds_addr;

    var count: i32 = 0;
    var i: u32 = 0;
    while (i < @as(u32, @intCast(nfds))) : (i += 1) {
        const word_idx = i / 32;
        const bit_idx: u5 = @intCast(i % 32);
        const mask = @as(u32, 1) << bit_idx;

        if (readfds.fds_bits[word_idx] & mask != 0) {
            if (i < FD_OFFSET) {
                if (i == STDIN) {
                    result_readfds.fds_bits[word_idx] |= mask;
                    count += 1;
                }
            } else {
                const vfs_fd: u32 = i - FD_OFFSET;
                if (vfs.getFileFlags(vfs_fd)) |_| {
                    result_readfds.fds_bits[word_idx] |= mask;
                    count += 1;
                } else |_| {}
            }
        }

        if (writefds.fds_bits[word_idx] & mask != 0) {
            if (i < FD_OFFSET) {
                if (i == STDOUT or i == STDERR) {
                    result_writefds.fds_bits[word_idx] |= mask;
                    count += 1;
                }
            } else {
                const vfs_fd: u32 = i - FD_OFFSET;
                if (vfs.getFileFlags(vfs_fd)) |_| {
                    result_writefds.fds_bits[word_idx] |= mask;
                    count += 1;
                } else |_| {}
            }
        }
    }

    if (readfds_addr != 0) {
        protection.copyToUser(readfds_addr, std.mem.asBytes(&result_readfds)) catch return EINVAL;
    }
    if (writefds_addr != 0) {
        protection.copyToUser(writefds_addr, std.mem.asBytes(&result_writefds)) catch return EINVAL;
    }

    return count;
}

fn sys_umask(mask: u16) i32 {
    const proc = process.current_process orelse return ENOSYS;
    const old = proc.umask;
    proc.umask = mask & 0o777;
    return @intCast(old);
}

const UtsName = extern struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
};

var system_hostname: [65]u8 = blk: {
    var name = [_]u8{0} ** 65;
    name[0] = 'z';
    name[1] = 'i';
    name[2] = 'g';
    name[3] = 'o';
    name[4] = 's';
    break :blk name;
};
var hostname_len: usize = 5;

pub fn getHostname() []const u8 {
    return system_hostname[0..hostname_len];
}

pub fn setHostname(name: []const u8) void {
    const len = @min(name.len, 64);
    @memset(&system_hostname, 0);
    @memcpy(system_hostname[0..len], name[0..len]);
    hostname_len = len;
}

fn fillField(dest: *[65]u8, src: []const u8) void {
    @memset(dest, 0);
    const len = @min(src.len, 64);
    @memcpy(dest[0..len], src[0..len]);
}

fn sys_uname(buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(UtsName))) return EINVAL;

    var buf: UtsName = undefined;
    fillField(&buf.sysname, "ZigOS");
    fillField(&buf.nodename, system_hostname[0..hostname_len]);
    fillField(&buf.release, "0.1.0");
    fillField(&buf.version, "ZigOS 0.1.0 (Zig 0.16.0-dev)");
    fillField(&buf.machine, "i386");

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return EINVAL;
    return 0;
}

fn sys_truncate(pathname: [*]const u8, length: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.truncate(path_slice, length) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_pread(fd: i32, buf: [*]u8, count: usize, offset: u64) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) return EINVAL;
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    var kernel_buffer: [512]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < count) {
        const chunk_size = @min(count - total_read, kernel_buffer.len);
        const bytes_read = vfs.pread(vfs_fd, kernel_buffer[0..chunk_size], offset + total_read) catch |err| return vfsErrno(err);
        if (bytes_read == 0) break;

        protection.copyToUser(@intFromPtr(buf) + total_read, kernel_buffer[0..bytes_read]) catch return EINVAL;
        total_read += bytes_read;
        if (bytes_read < chunk_size) break;
    }

    return @intCast(total_read);
}

fn sys_pwrite(fd: i32, buf: [*]const u8, count: usize, offset: u64) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) return EINVAL;
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    var kernel_buffer: [512]u8 = undefined;
    var written: usize = 0;

    while (written < count) {
        const chunk_size = @min(count - written, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch return EINVAL;
        const bytes_written = vfs.pwrite(vfs_fd, kernel_buffer[0..chunk_size], offset + written) catch |err| return vfsErrno(err);
        written += bytes_written;
        if (bytes_written < chunk_size) break;
    }

    return @intCast(written);
}

fn parseSockAddr(addr_ptr: usize, addr_len: u32) ?struct { addr: @import("../net/ipv4.zig").IPv4Address, port: u16 } {
    if (addr_len < @sizeOf(SockAddrIn)) return null;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return null;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return null;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    return .{
        .addr = @import("../net/ipv4.zig").IPv4Address{
            .octets = .{
                @intCast((addr.addr >> 0) & 0xFF),
                @intCast((addr.addr >> 8) & 0xFF),
                @intCast((addr.addr >> 16) & 0xFF),
                @intCast((addr.addr >> 24) & 0xFF),
            },
        },
        .port = @byteSwap(addr.port),
    };
}

fn writeSockAddr(addr_ptr: usize, len_ptr: usize, ipv4_addr: @import("../net/ipv4.zig").IPv4Address, port: u16) i32 {
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return EINVAL;

    const addr = SockAddrIn{
        .family = @intCast(AF_INET),
        .port = @byteSwap(port),
        .addr = @as(u32, ipv4_addr.octets[0]) |
            (@as(u32, ipv4_addr.octets[1]) << 8) |
            (@as(u32, ipv4_addr.octets[2]) << 16) |
            (@as(u32, ipv4_addr.octets[3]) << 24),
        .zero = [_]u8{0} ** 8,
    };

    protection.copyToUser(addr_ptr, std.mem.asBytes(&addr)) catch return EINVAL;
    if (len_ptr != 0 and protection.verifyUserPointer(len_ptr, @sizeOf(u32))) {
        var len: u32 = @sizeOf(SockAddrIn);
        protection.copyToUser(len_ptr, std.mem.asBytes(&len)) catch {};
    }
    return 0;
}

fn writeSockAddr6(addr_ptr: usize, len_ptr: usize, ipv6_addr: @import("../net/ipv6.zig").IPv6Address, port: u16) i32 {
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return EINVAL;

    const addr = SockAddrIn6{
        .family = @intCast(AF_INET6),
        .port = @byteSwap(port),
        .flowinfo = 0,
        .addr = ipv6_addr.octets,
        .scope_id = 0,
    };

    protection.copyToUser(addr_ptr, std.mem.asBytes(&addr)) catch return EINVAL;
    if (len_ptr != 0 and protection.verifyUserPointer(len_ptr, @sizeOf(u32))) {
        var len: u32 = @sizeOf(SockAddrIn6);
        protection.copyToUser(len_ptr, std.mem.asBytes(&len)) catch {};
    }
    return 0;
}

fn sys_sendto(sockfd: i32, buf: [*]const u8, len: usize, dest_addr: usize, addr_len: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    var kernel_buffer: [4096]u8 = undefined;
    const to_send = @min(len, kernel_buffer.len);
    protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return EINVAL;

    if (dest_addr == 0) {
        if (sock.address_family == .AF_INET6) {
            if (sock.remote_ipv6) |dst| {
                @import("../net/ipv6.zig").sendPacket(dst, @import("../net/ipv6.zig").NEXT_HEADER_UDP, kernel_buffer[0..to_send]);
                return @intCast(to_send);
            }
            return ENOTCONN;
        }
        const sent = sock.send(kernel_buffer[0..to_send]) catch |err| return socketErrno(err);
        return @intCast(sent);
    }

    if (sock.address_family == .AF_INET6) {
        if (addr_len < @sizeOf(SockAddrIn6)) return EINVAL;
        if (!protection.verifyUserPointer(dest_addr, @sizeOf(SockAddrIn6))) return EINVAL;

        var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
        protection.copyFromUser(&addr_buf, dest_addr) catch return EINVAL;
        const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

        const dst = @import("../net/ipv6.zig").IPv6Address{ .octets = addr.addr };
        @import("../net/ipv6.zig").sendPacket(dst, @import("../net/ipv6.zig").NEXT_HEADER_UDP, kernel_buffer[0..to_send]);
        return @intCast(to_send);
    }

    const parsed = parseSockAddr(dest_addr, addr_len) orelse return EINVAL;
    sock.sendTo(kernel_buffer[0..to_send], parsed.addr, parsed.port) catch |err| return socketErrno(err);
    return @intCast(to_send);
}

fn sys_recvfrom(sockfd: i32, buf: [*]u8, len: usize, src_addr: usize, addr_len_ptr: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    var kernel_buffer: [4096]u8 = undefined;
    const to_recv = @min(len, kernel_buffer.len);

    if (src_addr == 0) {
        const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return socketErrno(err);
        if (received == 0) return 0;
        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return EINVAL;
        return @intCast(received);
    }

    if (sock.address_family == .AF_INET6) {
        const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return socketErrno(err);
        if (received == 0) return 0;
        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return EINVAL;
        if (sock.remote_ipv6) |from_ipv6| {
            _ = writeSockAddr6(src_addr, addr_len_ptr, from_ipv6, sock.remote_port);
        }
        return @intCast(received);
    }

    var from_addr = @import("../net/ipv4.zig").IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
    var from_port: u16 = 0;
    const received = sock.recvFrom(kernel_buffer[0..to_recv], &from_addr, &from_port) catch |err| return socketErrno(err);
    if (received == 0) return 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return EINVAL;
    _ = writeSockAddr(src_addr, addr_len_ptr, from_addr, from_port);
    return @intCast(received);
}

fn sys_getsockname(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    if (sock.address_family == .AF_INET6) {
        const local = sock.local_ipv6 orelse @import("../net/ipv6.zig").UNSPECIFIED;
        return writeSockAddr6(addr_ptr, addr_len_ptr, local, sock.local_port);
    }
    return writeSockAddr(addr_ptr, addr_len_ptr, sock.local_addr, sock.local_port);
}

fn sys_getpeername(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    if (sock.state != .CONNECTED) return ENOTCONN;
    if (sock.address_family == .AF_INET6) {
        const remote = sock.remote_ipv6 orelse @import("../net/ipv6.zig").UNSPECIFIED;
        return writeSockAddr6(addr_ptr, addr_len_ptr, remote, sock.remote_port);
    }
    return writeSockAddr(addr_ptr, addr_len_ptr, sock.remote_addr, sock.remote_port);
}

fn sys_fchown(fd: i32, uid: u16, gid: u16) i32 {
    if (fd < FD_OFFSET) return EBADF;

    if (process.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return EPERM;
        }
    }

    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    vfs.fchown(vfs_fd, uid, gid) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_fsync(fd: i32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    return 0;
}

const PollFd = extern struct {
    fd: i32,
    events: i16,
    revents: i16,
};

const POLLIN: i16 = 0x001;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;
const POLLNVAL: i16 = 0x020;

fn sys_poll(fds_addr: usize, nfds: u32, timeout: i32) i32 {
    _ = timeout;
    if (nfds == 0) return 0;
    if (nfds > 256) return EINVAL;

    const copy_size = nfds * @sizeOf(PollFd);
    if (!protection.verifyUserPointer(fds_addr, copy_size)) return EINVAL;

    var kernel_fds: [256]PollFd = undefined;
    protection.copyFromUser(std.mem.asBytes(&kernel_fds)[0..copy_size], fds_addr) catch return EINVAL;

    var count: i32 = 0;
    var i: u32 = 0;
    while (i < nfds) : (i += 1) {
        kernel_fds[i].revents = 0;
        const fd = kernel_fds[i].fd;

        if (fd < 0) continue;

        if (fd < FD_OFFSET) {
            if (fd == STDIN and (kernel_fds[i].events & POLLIN) != 0) {
                kernel_fds[i].revents |= POLLIN;
                count += 1;
            }
            if ((fd == STDOUT or fd == STDERR) and (kernel_fds[i].events & POLLOUT) != 0) {
                kernel_fds[i].revents |= POLLOUT;
                count += 1;
            }
            continue;
        }

        const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
        if (vfs.getFileFlags(vfs_fd)) |flags| {
            const access_mode = flags & 0x3;
            if ((kernel_fds[i].events & POLLIN) != 0 and (access_mode == 0 or access_mode == 2)) {
                kernel_fds[i].revents |= POLLIN;
            }
            if ((kernel_fds[i].events & POLLOUT) != 0 and (access_mode == 1 or access_mode == 2)) {
                kernel_fds[i].revents |= POLLOUT;
            }
            if (kernel_fds[i].revents != 0) count += 1;
        } else |_| {
            kernel_fds[i].revents = POLLNVAL;
            count += 1;
        }
    }

    protection.copyToUser(fds_addr, std.mem.asBytes(&kernel_fds)[0..copy_size]) catch return EINVAL;
    return count;
}

fn sys_lstat(pathname: [*]const u8, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) return EINVAL;

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(path_slice, &stat_buf) catch |err| return vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return EINVAL;
    return 0;
}

const SOL_SOCKET: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_KEEPALIVE: i32 = 9;

fn sys_getsockopt(sockfd: i32, level: i32, optname: i32, optval_addr: usize, optlen_addr: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (level != SOL_SOCKET) return EINVAL;
    if (!protection.verifyUserPointer(optval_addr, @sizeOf(i32))) return EINVAL;

    var val: i32 = 0;
    switch (optname) {
        SO_TYPE => val = switch (sock.socket_type) {
            .STREAM => SOCK_STREAM,
            .DGRAM => SOCK_DGRAM,
            else => 0,
        },
        SO_ERROR => val = 0,
        SO_REUSEADDR, SO_KEEPALIVE => val = 0,
        else => return EINVAL,
    }

    protection.copyToUser(optval_addr, std.mem.asBytes(&val)) catch return EINVAL;
    if (optlen_addr != 0 and protection.verifyUserPointer(optlen_addr, @sizeOf(u32))) {
        var len: u32 = @sizeOf(i32);
        protection.copyToUser(optlen_addr, std.mem.asBytes(&len)) catch {};
    }
    return 0;
}

fn sys_setsockopt(sockfd: i32, level: i32, optname: i32, optval_addr: usize, optlen: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    _ = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (level != SOL_SOCKET) return EINVAL;
    if (optlen < @sizeOf(i32)) return EINVAL;
    if (!protection.verifyUserPointer(optval_addr, @sizeOf(i32))) return EINVAL;

    switch (optname) {
        SO_REUSEADDR, SO_KEEPALIVE => return 0,
        else => return EINVAL,
    }
}

const IoVec = extern struct {
    iov_base: usize,
    iov_len: usize,
};

fn sys_readv(fd: i32, iov_addr: usize, iovcnt: i32) i32 {
    if (iovcnt <= 0 or iovcnt > 16) return EINVAL;
    const cnt: u32 = @intCast(iovcnt);
    const iov_size = cnt * @sizeOf(IoVec);
    if (!protection.verifyUserPointer(iov_addr, iov_size)) return EINVAL;

    var iov: [16]IoVec = undefined;
    protection.copyFromUser(std.mem.asBytes(&iov)[0..iov_size], iov_addr) catch return EINVAL;

    var total: usize = 0;
    var i: u32 = 0;
    while (i < cnt) : (i += 1) {
        if (iov[i].iov_len == 0) continue;
        if (!protection.verifyUserPointer(iov[i].iov_base, iov[i].iov_len)) return EINVAL;

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

fn sys_writev(fd: i32, iov_addr: usize, iovcnt: i32) i32 {
    if (iovcnt <= 0 or iovcnt > 16) return EINVAL;
    const cnt: u32 = @intCast(iovcnt);
    const iov_size = cnt * @sizeOf(IoVec);
    if (!protection.verifyUserPointer(iov_addr, iov_size)) return EINVAL;

    var iov: [16]IoVec = undefined;
    protection.copyFromUser(std.mem.asBytes(&iov)[0..iov_size], iov_addr) catch return EINVAL;

    var total: usize = 0;
    var i: u32 = 0;
    while (i < cnt) : (i += 1) {
        if (iov[i].iov_len == 0) continue;
        if (!protection.verifyUserPointer(iov[i].iov_base, iov[i].iov_len)) return EINVAL;

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

fn sys_geteuid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.creds.euid);
    }
    return 0;
}

fn sys_getegid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.creds.egid);
    }
    return 0;
}

fn sys_isatty(fd: i32) i32 {
    if (fd == STDIN or fd == STDOUT or fd == STDERR) {
        return 1;
    }
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    if (vfs.getFileFlags(vfs_fd)) |_| {
        return 0;
    } else |_| {
        return EBADF;
    }
}

const StatFs = extern struct {
    f_type: u32,
    f_bsize: u32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]u32,
    f_namelen: u32,
    f_frsize: u32,
    f_flags: u32,
    f_spare: [4]u32,
};

fn sys_statfs(pathname: [*]const u8, buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(StatFs))) return EINVAL;

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    _ = vfs.lookupPath(path_slice) catch |err| return vfsErrno(err);

    const buf = StatFs{
        .f_type = 0x858458f6,
        .f_bsize = 4096,
        .f_blocks = 1024 * 1024,
        .f_bfree = 512 * 1024,
        .f_bavail = 512 * 1024,
        .f_files = 65536,
        .f_ffree = 32768,
        .f_fsid = .{ 0, 0 },
        .f_namelen = 255,
        .f_frsize = 4096,
        .f_flags = 0,
        .f_spare = .{ 0, 0, 0, 0 },
    };

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return EINVAL;
    return 0;
}

fn sys_fstatfs(fd: i32, buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(StatFs))) return EINVAL;
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    _ = vfs.getFileFlags(vfs_fd) catch return EBADF;

    const buf = StatFs{
        .f_type = 0x858458f6,
        .f_bsize = 4096,
        .f_blocks = 1024 * 1024,
        .f_bfree = 512 * 1024,
        .f_bavail = 512 * 1024,
        .f_files = 65536,
        .f_ffree = 32768,
        .f_fsid = .{ 0, 0 },
        .f_namelen = 255,
        .f_frsize = 4096,
        .f_flags = 0,
        .f_spare = .{ 0, 0, 0, 0 },
    };

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return EINVAL;
    return 0;
}
