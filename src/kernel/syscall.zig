const std = @import("std");
const x86 = @import("../arch/x86.zig");
const idt = @import("idt.zig");
const process = @import("process.zig");
const vga = @import("vga.zig");
const keyboard = @import("keyboard.zig");
const protection = @import("protection.zig");
const posix = @import("posix.zig");
const memory = @import("memory.zig");
const paging = @import("paging.zig");
const vfs = @import("vfs.zig");

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

pub const STDIN = 0;
pub const STDOUT = 1;
pub const STDERR = 2;

pub const EBADF = -1;
pub const EINVAL = -2;
pub const ENOSYS = -3;

export fn syscall_handler(regs: *idt.InterruptRegisters) callconv(.C) void {
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
    if (fd != STDOUT and fd != STDERR) {
        return EBADF;
    }

    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return EINVAL;
    }

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

fn sys_read(fd: i32, buf: [*]u8, count: usize) i32 {
    if (fd != STDIN) {
        return EBADF;
    }

    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return EINVAL;
    }

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
    
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;
    
    vfs.rmdir(path_slice) catch return -1;
    return 0;
}

fn sys_unlink(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }
    
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;
    
    vfs.unlink(path_slice) catch return -1;
    return 0;
}

fn sys_rename(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), 256) or
        !protection.verifyUserPointer(@intFromPtr(newpath), 256)) {
        return EINVAL;
    }
    
    var old_buffer: [256]u8 = undefined;
    var new_buffer: [256]u8 = undefined;
    
    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return EINVAL;
    
    vfs.rename(old_slice, new_slice) catch return -1;
    return 0;
}

pub fn init() void {
    idt.register_interrupt_handler(0x80, syscall_handler);

    idt.set_gate_flags(0x80, 0x8E | 0x60); // Present, DPL=3, 32-bit trap gate
}

pub fn syscall0(num: u32) i32 {
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
            error.NoProcessSlots => -11, // EAGAIN
            error.OutOfMemory => -12, // ENOMEM
        };
    };
    return result;
}

fn sys_execve(path: [*]const u8, argv: usize, envp: usize) i32 {
    var path_buf: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buf, @intFromPtr(path)) catch {
        return EINVAL;
    };

    // Parse argv
    var argv_array: [32][]const u8 = undefined;
    var argv_count: usize = 0;
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
    
    // Parse envp
    var envp_array: [32][]const u8 = undefined;
    var envp_count: usize = 0;
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
            error.OutOfMemory => -12, // ENOMEM
            error.FileReadError => -2, // ENOENT
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
        return @intCast(current_brk); // Invalid address, return current
    }

    const new_brk = (addr + 0xFFF) & ~@as(usize, 0xFFF);

    if (new_brk > current_brk) {
        var page_addr = current_brk;
        while (page_addr < new_brk) : (page_addr += 0x1000) {
            const phys_page = memory.allocatePhysicalPage() orelse {
                return @intCast(current_brk); // Out of memory
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

    // Handle file mappings
    if ((flags & MAP_ANONYMOUS) == 0) {
        // File-backed mapping requested
        if (fd < 0) {
            return EINVAL;
        }
        // For now, file mappings are not supported, return error
        _ = offset;
        return -38; // ENOSYS - function not implemented
    }

    // Check flags for MAP_PRIVATE vs MAP_SHARED
    if ((flags & MAP_PRIVATE) != 0 and (flags & MAP_SHARED) != 0) {
        return EINVAL; // Can't have both
    }
    if ((flags & MAP_PRIVATE) == 0 and (flags & MAP_SHARED) == 0) {
        return EINVAL; // Must have one
    }

    // Try to use suggested address if provided
    var result_addr: usize = undefined;
    if (addr != 0) {
        // Align the address to page boundary
        const aligned_addr = addr & ~@as(usize, 0xFFF);
        
        if ((flags & MAP_FIXED) != 0) {
            // MAP_FIXED requires exact address
            if (aligned_addr < protection.USER_HEAP_START or aligned_addr >= protection.USER_SPACE_END) {
                return EINVAL;
            }
            // For MAP_FIXED, we'd need to unmap existing mappings first
            // For now, just try to allocate at any address
            result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch |err| {
                return switch (err) {
                    error.OutOfMemory => -12, // ENOMEM
                    error.OutOfVirtualMemory => -12, // ENOMEM
                };
            };
        } else {
            // Try the suggested address, fall back to any address if it fails
            result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch |err| {
                return switch (err) {
                    error.OutOfMemory => -12, // ENOMEM
                    error.OutOfVirtualMemory => -12, // ENOMEM
                };
            };
        }
    } else {
        result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch |err| {
            return switch (err) {
                error.OutOfMemory => -12, // ENOMEM
                error.OutOfVirtualMemory => -12, // ENOMEM
            };
        };
    }

    return @intCast(result_addr);
}
