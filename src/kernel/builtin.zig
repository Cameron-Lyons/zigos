const panic_handler = @import("panic.zig");

pub fn panic(msg: []const u8, error_return_trace: ?*@import("std").builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    panic_handler.panic("{s}", .{msg});
}