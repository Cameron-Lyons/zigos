const std = @import("std");
const syscall = @import("syscall.zig");

// Test process that uses syscalls
pub fn test_syscall_process() void {
    const message = "Hello from syscall!\n";
    
    // Test write syscall
    _ = syscall.syscall3(syscall.SYS_WRITE, syscall.STDOUT, @intFromPtr(message.ptr), message.len);
    
    // Test getpid syscall
    const pid = syscall.syscall0(syscall.SYS_GETPID);
    
    // Write PID message
    const pid_msg = "Process ID: ";
    _ = syscall.syscall3(syscall.SYS_WRITE, syscall.STDOUT, @intFromPtr(pid_msg.ptr), pid_msg.len);
    
    // Simple number to string conversion for PID
    var buf: [16]u8 = undefined;
    var i: usize = 0;
    var n = @as(u32, @intCast(pid));
    
    if (n == 0) {
        buf[0] = '0';
        i = 1;
    } else {
        var j: usize = 0;
        while (n > 0) : (j += 1) {
            buf[j] = '0' + @as(u8, @intCast(n % 10));
            n /= 10;
        }
        // Reverse the digits
        i = j;
        var k: usize = 0;
        while (k < j / 2) : (k += 1) {
            const tmp = buf[k];
            buf[k] = buf[j - k - 1];
            buf[j - k - 1] = tmp;
        }
    }
    
    buf[i] = '\n';
    i += 1;
    
    _ = syscall.syscall3(syscall.SYS_WRITE, syscall.STDOUT, @intFromPtr(&buf), i);
    
    // Test yield syscall
    var count: u32 = 0;
    while (count < 3) : (count += 1) {
        const yield_msg = "Yielding...\n";
        _ = syscall.syscall3(syscall.SYS_WRITE, syscall.STDOUT, @intFromPtr(yield_msg.ptr), yield_msg.len);
        _ = syscall.syscall0(syscall.SYS_YIELD);
    }
    
    // Test exit syscall
    const exit_msg = "Exiting with code 42\n";
    _ = syscall.syscall3(syscall.SYS_WRITE, syscall.STDOUT, @intFromPtr(exit_msg.ptr), exit_msg.len);
    _ = syscall.syscall1(syscall.SYS_EXIT, 42);
    
    // Should never reach here
    while (true) {}
}