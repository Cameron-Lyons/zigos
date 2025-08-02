const std = @import("std");
const process = @import("process.zig");
const vga = @import("vga.zig");
const syscall = @import("syscall.zig");
const panic_handler = @import("panic.zig");

// User space test program
fn user_hello_world() void {
    // This will run in user space and must use system calls
    // to interact with the kernel
    
    // System call to print a message
    asm volatile (
        \\mov $1, %%eax    # syscall number for write
        \\mov $1, %%ebx    # file descriptor (stdout)
        \\lea %[msg], %%ecx # message pointer
        \\mov $24, %%edx   # message length
        \\int $0x80        # trigger system call
        :
        : [msg] "m" ("Hello from userspace!\n")
        : "eax", "ebx", "ecx", "edx"
    );
    
    // System call to exit
    asm volatile (
        \\mov $0, %%eax    # syscall number for exit
        \\mov $0, %%ebx    # exit code
        \\int $0x80        # trigger system call
        :
        :
        : "eax", "ebx"
    );
}

// Create a user process
pub fn createUserTestProcess() void {
    vga.print("Creating user space test process...\n");
    
    const user_proc = process.create_user_process("user_hello", user_hello_world);
    
    vga.print("User process created with PID: ");
    printNumber(user_proc.pid);
    vga.print("\n");
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }
    
    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var n = num;
    
    while (n > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast((n % 10) + '0'));
        n /= 10;
    }
    
    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}