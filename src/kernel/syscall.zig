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

    // Verify user buffer
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return EINVAL;
    }

    // Copy data from user space safely
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

    // Verify user buffer
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

    // Copy to user space
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
    _ = argv; // TODO: Parse argv
    _ = envp; // TODO: Parse envp
    
    // Convert path to slice
    var path_buf: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buf, @intFromPtr(path)) catch {
        return EINVAL;
    };
    
    // Empty argv and envp for now
    const empty_argv = [_][]const u8{};
    const empty_envp = [_][]const u8{};
    
    posix.execve(path_slice, &empty_argv, &empty_envp) catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.OutOfMemory => -12, // ENOMEM
            error.FileReadError => -2, // ENOENT
            else => EINVAL,
        };
    };
    
    // If execve succeeds, we should never reach here
    return 0;
}

fn sys_wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) i32 {
    const result = posix.wait4(pid, status, options, rusage) catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.InvalidPointer => EINVAL
        };
    };
    return result;
}

var current_brk: usize = protection.USER_HEAP_START;

fn sys_brk(addr: usize) i32 {
    if (addr == 0) {
        // Return current break
        return @intCast(current_brk);
    }
    
    if (addr < protection.USER_HEAP_START or addr >= protection.USER_SPACE_END) {
        return @intCast(current_brk); // Invalid address, return current
    }
    
    // Align to page boundary
    const new_brk = (addr + 0xFFF) & ~@as(usize, 0xFFF);
    
    if (new_brk > current_brk) {
        // Allocate new pages
        var page_addr = current_brk;
        while (page_addr < new_brk) : (page_addr += 0x1000) {
            const phys_page = memory.allocatePhysicalPage() orelse {
                return @intCast(current_brk); // Out of memory
            };
            paging.mapPage(@intCast(page_addr), phys_page, 
                          paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
        }
    } else if (new_brk < current_brk) {
        // Free pages
        var page_addr = new_brk;
        while (page_addr < current_brk) : (page_addr += 0x1000) {
            paging.unmap_page(@intCast(page_addr));
        }
    }
    
    current_brk = new_brk;
    return @intCast(current_brk);
}

fn sys_mmap(addr: usize, length: usize, prot: i32, flags: i32, fd: i32, offset: i32) i32 {
    _ = flags; // TODO: Handle MAP_PRIVATE, MAP_SHARED, etc.
    _ = fd; // TODO: Handle file mappings
    _ = offset;
    
    if (length == 0) {
        return EINVAL;
    }
    
    // For now, only support anonymous mappings
    if (addr != 0) {
        // TODO: Try to use suggested address
    }
    
    const result = protection.allocateUserMemory(length, @intCast(prot)) catch |err| {
        return switch (err) {
            error.OutOfMemory => -12, // ENOMEM
            error.OutOfVirtualMemory => -12, // ENOMEM
        };
    };
    
    return @intCast(result);
}

