pub const quota = @import("native/storage/volume/quota.zig");
pub const Store = @import("native/storage/object_store.zig").Store;
pub const workspace = @import("native/storage/workspace.zig");

comptime {
    if (@import("builtin").is_test) @import("std").testing.refAllDecls(quota);
}
