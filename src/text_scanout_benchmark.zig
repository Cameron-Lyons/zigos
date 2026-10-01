pub const scanout = @import("kernel/platform/text_scanout.zig");
pub const framebuffer = @import("kernel/platform/framebuffer.zig");

comptime {
    if (@import("builtin").is_test) _ = @import("kernel/platform/text_scanout_test.zig");
}
