pub const objects = @import("native/storage/object_store.zig");
pub const signing = @import("native/core/signing.zig");
pub const MAX_TRANSFER_CHUNK = @import("native/sync/object_transfer.zig").MAX_CHUNK;

comptime {
    if (@import("builtin").is_test) _ = objects;
}
