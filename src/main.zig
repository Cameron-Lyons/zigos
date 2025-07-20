const std = @import("std");

pub const kernel = @import("kernel/main.zig");
pub const isr = @import("kernel/isr.zig");

comptime {
    _ = kernel;
    _ = isr;
}