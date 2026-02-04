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

pub const STDIN = 0;
pub const STDOUT = 1;
pub const STDERR = 2;
const FD_OFFSET = 3;

pub const EBADF = -1;
pub const EINVAL = -2;
pub const ENOSYS = -3;
pub const ENOMEM = -12;
pub const ENOENT = -2;
pub const EACCES = -13;

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
        else => ENOSYS,
    };

    regs.eax = @intCast(@as(i32, result));

    signal.handlePendingSignals();
}

fn sys_exit(status: i32) i32 {
    if (process.current_process) |proc| {
        proc.state = .Terminated;
        proc.exit_code = status;

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

        const bytes_written = vfs.write(vfs_fd, kernel_buffer[0..chunk_size]) catch return -1;
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
        const bytes_read = vfs.read(vfs_fd, kernel_buffer[0..chunk_size]) catch return -1;
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

    vfs.mkdir(path_slice, mode_struct) catch return -1;
    return 0;
}

fn sys_rmdir(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.rmdir(path_slice) catch return -1;
    return 0;
}

fn sys_unlink(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.unlink(path_slice) catch return -1;
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

    vfs.rename(old_slice, new_slice) catch return -1;
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

    const vfs_fd = vfs.open(path_slice, flags) catch return -1;
    return @intCast(@as(i32, @intCast(vfs_fd)) + FD_OFFSET);
}

fn sys_close(fd: i32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    vfs.close(vfs_fd) catch return -1;
    return 0;
}

fn sys_lseek(fd: i32, offset: i64, whence: u32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    const result = vfs.lseek(vfs_fd, offset, whence) catch return -1;
    return @intCast(@as(i32, @intCast(result & 0x7FFFFFFF)));
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
    vfs.stat(path_slice, &stat_buf) catch return -1;

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
        return -1;
    }
    return -1;
}

fn sys_setgid(gid: u16) i32 {
    if (process.current_process) |proc| {
        if (proc.creds.euid == 0 or proc.creds.gid == gid) {
            proc.creds.gid = gid;
            proc.creds.egid = gid;
            return 0;
        }
        return -1;
    }
    return -1;
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
            return -1;
        }
    }

    vfs.chown(path_slice, uid, gid) catch return -1;
    return 0;
}

const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

const SockAddrIn = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

var socket_table: [64]?*socket.Socket = [_]?*socket.Socket{null} ** 64;

fn sys_socket(domain: u32, sock_type: u32, protocol: u32) i32 {
    _ = protocol;
    if (domain != AF_INET) return EINVAL;

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

    for (&socket_table, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = sock;
            return @intCast(i);
        }
    }

    sock.close();
    return ENOMEM;
}

fn sys_bind(sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (addr_len < @sizeOf(SockAddrIn)) return EINVAL;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser call
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

    sock.bind(ipv4_addr, @byteSwap(addr.port)) catch return -1;
    return 0;
}

fn sys_connect(sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (addr_len < @sizeOf(SockAddrIn)) return EINVAL;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser call
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

    sock.connect(ipv4_addr, @byteSwap(addr.port)) catch return -1;
    return 0;
}

fn sys_listen(sockfd: i32, backlog: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    sock.listen(backlog) catch return -1;
    return 0;
}

fn sys_accept(sockfd: i32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    const client = sock.accept() catch return -1;

    for (&socket_table, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = client;
            return @intCast(i);
        }
    }

    client.close();
    return ENOMEM;
}

fn sys_send(sockfd: i32, buf: [*]const u8, len: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser call
    var kernel_buffer: [4096]u8 = undefined;
    const to_send = @min(len, kernel_buffer.len);
    protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return EINVAL;

    const sent = sock.send(kernel_buffer[0..to_send]) catch return -1;
    return @intCast(sent);
}

fn sys_recv(sockfd: i32, buf: [*]u8, len: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    // SAFETY: filled by the subsequent sock.recv call
    var kernel_buffer: [4096]u8 = undefined;
    const to_recv = @min(len, kernel_buffer.len);

    const received = sock.recv(kernel_buffer[0..to_recv]) catch return -1;
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
    signal.kill(pid, signum) catch return -1;
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
    if (node.file_type != .Directory) return -20;

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
    vfs.fstat(vfs_fd, &stat_buf) catch return -1;

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return EINVAL;
    return 0;
}

fn sys_pipe(pipefd: ?*[2]i32) i32 {
    if (pipefd == null) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(pipefd), @sizeOf([2]i32))) {
        return EINVAL;
    }

    const result = vfs.createPipe() catch return -1;
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

    const result = vfs.dup2(old_vfs_fd, new_vfs_fd) catch return -1;
    return @as(i32, @intCast(result)) + FD_OFFSET;
}

fn sys_fork() i32 {
    const result = posix.fork() catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.NoProcessSlots => -11,
            error.OutOfMemory => -12,
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
            error.OutOfMemory => -12,
            error.FileReadError => -2,
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
        return -38;
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

            result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch |err| {
                return switch (err) {
                    error.OutOfMemory => -12,
                    error.OutOfVirtualMemory => -12,
                };
            };
        } else {
            result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch |err| {
                return switch (err) {
                    error.OutOfMemory => -12,
                    error.OutOfVirtualMemory => -12,
                };
            };
        }
    } else {
        result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch |err| {
            return switch (err) {
                error.OutOfMemory => -12,
                error.OutOfVirtualMemory => -12,
            };
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

    ipc.sendMessage(sender_pid, receiver_pid, .Data, kernel_buffer[0..msg_len]) catch return -1;
    return 0;
}

fn sys_msgrcv(buf: [*]u8, size: usize, flags: i32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), size)) return EINVAL;
    const pid = if (process.current_process) |proc| proc.pid else return ENOSYS;

    const queue = ipc.getMessageQueue(pid) orelse return -1;

    const msg = if (flags != 0) queue.tryReceive() else queue.receive();
    if (msg == null) return 0;

    const m = msg.?;
    const copy_len = @min(m.data_len, @as(u32, @intCast(size)));
    protection.copyToUser(@intFromPtr(buf), m.data[0..copy_len]) catch return EINVAL;
    return @intCast(copy_len);
}
