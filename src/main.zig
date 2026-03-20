pub const kernel = @import("kernel/boot/entry.zig");
pub const isr = @import("kernel/interrupts/isr.zig");
pub const panic = @import("kernel/utils/builtin.zig").panic;

export fn kernel_main() void {
    kernel.kernelMain();
}

comptime {
    _ = kernel;
    _ = isr;
}
