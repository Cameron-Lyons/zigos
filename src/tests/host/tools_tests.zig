const std = @import("std");

const inspect_native_store = @import("../../tools/inspect_native_store.zig");

test "tools host tests import source-aware tools" {
    std.testing.refAllDecls(inspect_native_store);
}
