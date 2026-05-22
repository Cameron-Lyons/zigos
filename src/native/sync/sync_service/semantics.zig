const std = @import("std");
const state_support = @import("../sync_state_support.zig");
const workspace = @import("../../storage/workspace.zig");

pub fn classifyEntry(entry: workspace.Entry) state_support.SyncSemantic {
    return switch (entry.object_type) {
        .document => .mergeable_crdt,
        .media_asset => .chunked_snapshot,
        .secret => .secure_transfer,
        .event_stream => .transactional_contract,
        else => if (std.mem.startsWith(u8, entry.pathSlice(), "documents/") or
            std.mem.startsWith(u8, entry.pathSlice(), "settings/"))
            .mergeable_crdt
        else
            .chunked_snapshot,
    };
}
