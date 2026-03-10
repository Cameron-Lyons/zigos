const std = @import("std");
const syscall = @import("syscall");

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    _ = syscall.write(syscall.STDERR, "panic: ");
    _ = syscall.write(syscall.STDERR, msg);
    _ = syscall.write(syscall.STDERR, "\n");
    syscall.exit(1);
}
