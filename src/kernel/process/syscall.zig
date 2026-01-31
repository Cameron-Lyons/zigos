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

pub const STDIN = 0;
pub const STDOUT = 1;
pub const STDERR = 2;
const FD_OFFSET = 3;

pub const EBADF = -1;
pub const EINVAL = -2;
pub const ENOSYS = -3;
pub const ENOMEM = -12;
pub const ENOENT = -2;

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
        else => ENOSYS,
    };

    regs.eax = @intCast(@as(i32, result));
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
