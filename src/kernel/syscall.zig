const std = @import("std");
const x86 = @import("../arch/x86.zig");
const idt = @import("idt.zig");
const process = @import("process.zig");
const vga = @import("vga.zig");
const keyboard = @import("keyboard.zig");

// System call numbers
pub const SYS_EXIT = 1;
pub const SYS_WRITE = 2;
pub const SYS_READ = 3;
pub const SYS_OPEN = 4;
pub const SYS_CLOSE = 5;
pub const SYS_GETPID = 6;
pub const SYS_YIELD = 7;

// File descriptors
pub const STDIN = 0;
pub const STDOUT = 1;
pub const STDERR = 2;

// Error codes
pub const EBADF = -1;
pub const EINVAL = -2;
pub const ENOSYS = -3;

// System call handler entry point
export fn syscall_handler(regs: *idt.InterruptRegisters) callconv(.C) void {
    // System call number in EAX
    const syscall_num = regs.eax;
    
    // Arguments in EBX, ECX, EDX, ESI, EDI
    const arg1 = regs.ebx;
    const arg2 = regs.ecx;
    const arg3 = regs.edx;
    
    // Handle system call
    const result = switch (syscall_num) {
        SYS_EXIT => sys_exit(@intCast(arg1)),
        SYS_WRITE => sys_write(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_READ => sys_read(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3),
        SYS_GETPID => sys_getpid(),
        SYS_YIELD => sys_yield(),
        else => ENOSYS,
    };
    
    // Return value in EAX
    regs.eax = @intCast(@as(i32, result));
}

// System call implementations
fn sys_exit(status: i32) i32 {
    // Get current process
    if (process.current_process) |proc| {
        proc.state = .Terminated;
        proc.exit_code = status;
        
        // Schedule next process
        _ = process.schedule();
        
        // Should not return
        x86.hlt();
    }
    
    return 0;
}

fn sys_write(fd: i32, buf: [*]const u8, count: usize) i32 {
    // Only support stdout/stderr for now
    if (fd != STDOUT and fd != STDERR) {
        return EBADF;
    }
    
    // Write to VGA console
    var i: usize = 0;
    while (i < count) : (i += 1) {
        vga.print(&[_]u8{buf[i]});
    }
    
    return @intCast(count);
}

fn sys_read(fd: i32, buf: [*]u8, count: usize) i32 {
    // Only support stdin for now
    if (fd != STDIN) {
        return EBADF;
    }
    
    // Read from keyboard buffer
    var i: usize = 0;
    while (i < count) : (i += 1) {
        // Block until character available
        while (!keyboard.has_char()) {
            x86.hlt();
        }
        
        if (keyboard.getchar()) |ch| {
            buf[i] = ch;
            
            // Stop at newline
            if (ch == '\n') {
                i += 1;
                break;
            }
        }
    }
    
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

// Initialize system call interface
pub fn init() void {
    // Register interrupt handler for int 0x80
    idt.register_interrupt_handler(0x80, syscall_handler);
    
    // Set IDT entry as a trap gate (doesn't disable interrupts)
    // and allow userspace to call it (DPL = 3)
    idt.set_gate_flags(0x80, 0x8E | 0x60); // Present, DPL=3, 32-bit trap gate
}

// C wrapper for userspace (will be used when we have userspace)
pub fn syscall0(num: u32) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result)
        : [num] "{eax}" (num)
        : "memory"
    );
    return result;
}

pub fn syscall1(num: u32, arg1: usize) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result)
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1)
        : "memory"
    );
    return result;
}

pub fn syscall3(num: u32, arg1: usize, arg2: usize, arg3: usize) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result)
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3)
        : "memory"
    );
    return result;
}