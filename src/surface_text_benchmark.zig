pub const abi = @import("native/core/abi.zig");

comptime {
    if (@import("builtin").is_test) @import("std").testing.refAllDecls(abi);
}
