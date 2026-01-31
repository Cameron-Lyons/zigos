pub const kernel = @import("kernel/main.zig");
pub const isr = @import("kernel/interrupts/isr.zig");
pub const panic = @import("kernel/utils/builtin.zig").panic;

comptime {
    _ = kernel;
    _ = isr;
}