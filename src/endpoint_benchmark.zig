const endpoint = @import("native/kernel_api/endpoint.zig");

pub const ids = @import("native/core/ids.zig");
pub const Table = endpoint.Table;
pub const MAX_ENDPOINTS = endpoint.MAX_ENDPOINTS;
pub const MAX_MESSAGE_BYTES = endpoint.MAX_MESSAGE_BYTES;
pub const no_index = @import("native/core/indexed_arena.zig").no_index;

comptime {
    if (@import("builtin").is_test) _ = endpoint;
}
