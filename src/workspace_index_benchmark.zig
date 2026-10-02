pub const workspace_index = @import("native/storage/workspace/index.zig");
pub const id_index = @import("native/core/id_index.zig");

comptime {
    if (@import("builtin").is_test) _ = workspace_index;
}
