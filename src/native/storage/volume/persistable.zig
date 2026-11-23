const workspace = @import("../workspace.zig");
const volume_errors = @import("errors.zig");

// The fixed object and workspace tables are the storage capacity limits. These
// checks only reject in-memory slots whose counts could not be serialized.

pub fn workspaceCount(workspaces: *const workspace.Directory) usize {
    var count: usize = 0;
    for (&workspaces.workspaces.slots) |*slot| {
        if (persistableWorkspaceSlot(slot)) count += 1;
    }
    return count;
}

pub fn snapshotCount(workspaces: *const workspace.Directory) usize {
    var count: usize = 0;
    for (&workspaces.snapshots.slots) |*slot| {
        if (persistableSnapshotSlot(slot)) count += 1;
    }
    return count;
}

pub fn persistableWorkspaceSlot(slot: anytype) bool {
    if (!slot.in_use) return false;
    return slot.workspace.label_len <= slot.workspace.label.len and
        slot.workspace.counts.entry_count <= workspace.MAX_WORKSPACE_ENTRIES and
        slot.workspace.counts.entry_mutation_count <= workspace.MAX_WORKSPACE_ENTRY_MUTATIONS and
        slot.workspace.counts.share_grant_count <= workspace.MAX_SHARE_GRANTS and
        slot.workspace.counts.deleted_count <= workspace.MAX_RECOVERABLE_DELETES;
}

pub fn persistableSnapshotSlot(slot: anytype) bool {
    if (!slot.in_use) return false;
    return slot.snapshot.label_len <= slot.snapshot.label.len and
        slot.snapshot.entry_count <= workspace.MAX_WORKSPACE_ENTRIES;
}

/// Refuses to persist a directory with a live slot that cannot be encoded,
/// rather than silently dropping it from the checkpoint.
pub fn ensurePersistableSlots(workspaces: *const workspace.Directory) volume_errors.Error!void {
    for (&workspaces.workspaces.slots) |*slot| {
        if (slot.in_use and !persistableWorkspaceSlot(slot)) return error.NoSpaceLeft;
    }
    for (&workspaces.snapshots.slots) |*slot| {
        if (slot.in_use and !persistableSnapshotSlot(slot)) return error.NoSpaceLeft;
    }
}

test "persistable slots exclude every malformed workspace and snapshot metadata combination" {
    const std = @import("std");
    const directory = try std.testing.allocator.create(workspace.Directory);
    defer std.testing.allocator.destroy(directory);
    directory.* = workspace.Directory.init();

    // Directly populate the last physical slots: persistability accounting must
    // inspect the whole arena, independently of its live counters and indexes.
    const workspace_slot = &directory.workspaces.slots[workspace.MAX_WORKSPACES - 1];
    for (0..64) |invalid| {
        workspace_slot.in_use = invalid & 1 == 0;
        workspace_slot.workspace.label_len = if (invalid & 2 == 0) workspace.MAX_WORKSPACE_LABEL_BYTES else workspace.MAX_WORKSPACE_LABEL_BYTES + 1;
        workspace_slot.workspace.counts = .{
            .entry_count = if (invalid & 4 == 0) workspace.MAX_WORKSPACE_ENTRIES else workspace.MAX_WORKSPACE_ENTRIES + 1,
            .entry_mutation_count = if (invalid & 8 == 0) workspace.MAX_WORKSPACE_ENTRY_MUTATIONS else workspace.MAX_WORKSPACE_ENTRY_MUTATIONS + 1,
            .share_grant_count = if (invalid & 16 == 0) workspace.MAX_SHARE_GRANTS else workspace.MAX_SHARE_GRANTS + 1,
            .deleted_count = if (invalid & 32 == 0) workspace.MAX_RECOVERABLE_DELETES else workspace.MAX_RECOVERABLE_DELETES + 1,
        };
        const expected_count: usize = if (invalid == 0) 1 else 0;
        try std.testing.expectEqual(expected_count, workspaceCount(directory));
        if (workspace_slot.in_use and invalid != 0) {
            try std.testing.expectError(error.NoSpaceLeft, ensurePersistableSlots(directory));
        } else {
            try ensurePersistableSlots(directory);
        }
    }
    workspace_slot.in_use = false;

    const snapshot_slot = &directory.snapshots.slots[workspace.MAX_SNAPSHOTS - 1];
    for (0..8) |invalid| {
        snapshot_slot.in_use = invalid & 1 == 0;
        snapshot_slot.snapshot.label_len = if (invalid & 2 == 0) workspace.MAX_WORKSPACE_LABEL_BYTES else workspace.MAX_WORKSPACE_LABEL_BYTES + 1;
        snapshot_slot.snapshot.entry_count = if (invalid & 4 == 0) workspace.MAX_WORKSPACE_ENTRIES else workspace.MAX_WORKSPACE_ENTRIES + 1;
        const expected_count: usize = if (invalid == 0) 1 else 0;
        try std.testing.expectEqual(expected_count, snapshotCount(directory));
        if (snapshot_slot.in_use and invalid != 0) {
            try std.testing.expectError(error.NoSpaceLeft, ensurePersistableSlots(directory));
        } else {
            try ensurePersistableSlots(directory);
        }
    }
    try std.testing.expectEqual(@as(u64, 0), directory.dirty_revision);
    try std.testing.expectEqual(@as(usize, 0), directory.workspaceCount());
    try std.testing.expectEqual(@as(usize, 0), directory.snapshotCount());
}
