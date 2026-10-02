pub const layout = @import("native/core/text_layout.zig");

comptime {
    if (@import("builtin").is_test) @import("std").testing.refAllDecls(layout);
}
