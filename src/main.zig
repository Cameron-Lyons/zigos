const std = @import("std");

pub const kernel = @import("kernel/main.zig");
pub const isr = @import("kernel/isr.zig");
pub const panic = @import("kernel/builtin.zig").panic;

comptime {
    _ = kernel;
    _ = isr;
}