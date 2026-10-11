const object_store = @import("../object_store.zig");
const volume_capacity = @import("capacity.zig");
const volume_layout = @import("layout.zig");
const workspace = @import("../workspace.zig");

pub const ProductCapacityEnvelope = volume_capacity.ProductCapacityEnvelope;
pub const ProductCapacityUsage = volume_capacity.ProductCapacityUsage;
pub const QuotaLimit = volume_capacity.QuotaLimit;
pub const QuotaRejection = volume_capacity.QuotaRejection;

pub const first_supported_capacity_envelope = ProductCapacityEnvelope{
    .volume_image_bytes = volume_layout.image_bytes,
    .required_device_sectors = volume_layout.required_device_sectors,
    .max_volume_log_bytes = volume_layout.data_region_bytes,
    .max_object_payload_bytes = object_store.MAX_PAYLOAD_BYTES,
    .max_object_records = object_store.MAX_OBJECTS,
    .max_version_records = object_store.MAX_VERSIONS,
    .max_blob_records = object_store.MAX_BLOBS,
    .max_blob_chunks_per_payload = object_store.MAX_BLOB_CHUNKS,
    .max_chunk_records = object_store.MAX_CHUNKS,
    .max_chunk_bytes = object_store.MAX_CHUNK_BYTES,
    .max_workspaces = workspace.MAX_WORKSPACES,
    .max_workspace_entries_per_workspace = workspace.MAX_WORKSPACE_ENTRIES,
    .max_snapshots = workspace.MAX_SNAPSHOTS,
    .max_replay_log_records = volume_layout.max_replay_log_records,
    .max_log_segments = volume_layout.max_log_segments,
};

pub fn productCapacityUsage(store: *const object_store.Store, workspaces: *const workspace.Directory) ProductCapacityUsage {
    var usage = ProductCapacityUsage{
        .object_records = store.objectCount(),
        .version_records = store.versionCount(),
        .blob_records = store.blobCount(),
        .chunk_records = store.chunkCount(),
        .object_payload_bytes = store.maxBlobPayloadBytes(),
    };

    for (&workspaces.workspaces.slots) |*slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        usage.workspaces += 1;
        usage.max_workspace_entries = @max(usage.max_workspace_entries, slot.workspace.counts.entry_count);
    }
    for (&workspaces.snapshots.slots) |*slot| {
        if (!persistableSnapshotSlot(slot)) continue;
        usage.snapshots += 1;
        usage.max_workspace_entries = @max(usage.max_workspace_entries, slot.snapshot.entry_count);
    }
    return usage;
}

pub fn quotaRejectionForCurrentState(
    store: *const object_store.Store,
    workspaces: *const workspace.Directory,
    envelope: ProductCapacityEnvelope,
) ?QuotaRejection {
    return quotaRejectionForUsage(productCapacityUsage(store, workspaces), envelope);
}

pub fn quotaRejectionForUsage(usage: ProductCapacityUsage, envelope: ProductCapacityEnvelope) ?QuotaRejection {
    if (usage.object_payload_bytes > envelope.max_object_payload_bytes) {
        return quotaRejection(.object_payload_bytes, usage.object_payload_bytes, envelope.max_object_payload_bytes);
    }
    if (usage.object_records > envelope.max_object_records) {
        return quotaRejection(.object_records, usage.object_records, envelope.max_object_records);
    }
    if (usage.version_records > envelope.max_version_records) {
        return quotaRejection(.version_records, usage.version_records, envelope.max_version_records);
    }
    if (usage.blob_records > envelope.max_blob_records) {
        return quotaRejection(.blob_records, usage.blob_records, envelope.max_blob_records);
    }
    if (usage.chunk_records > envelope.max_chunk_records) {
        return quotaRejection(.chunk_records, usage.chunk_records, envelope.max_chunk_records);
    }
    if (usage.workspaces > envelope.max_workspaces) {
        return quotaRejection(.workspaces, usage.workspaces, envelope.max_workspaces);
    }
    if (usage.max_workspace_entries > envelope.max_workspace_entries_per_workspace) {
        return quotaRejection(.workspace_entries, usage.max_workspace_entries, envelope.max_workspace_entries_per_workspace);
    }
    if (usage.snapshots > envelope.max_snapshots) {
        return quotaRejection(.snapshots, usage.snapshots, envelope.max_snapshots);
    }
    return null;
}

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

fn quotaRejection(limit: QuotaLimit, requested: usize, allowed: usize) QuotaRejection {
    return .{
        .limit = limit,
        .used = requested,
        .requested = requested,
        .allowed = allowed,
    };
}

test "storage quota excludes every malformed workspace and snapshot metadata combination" {
    const std = @import("std");
    const store = try std.testing.allocator.create(object_store.Store);
    defer std.testing.allocator.destroy(store);
    store.* = object_store.Store.init();
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
        const usage = productCapacityUsage(store, directory);
        const expected_count: usize = if (invalid == 0) 1 else 0;
        try std.testing.expectEqual(expected_count, usage.workspaces);
        try std.testing.expectEqual(expected_count * workspace.MAX_WORKSPACE_ENTRIES, usage.max_workspace_entries);
        try std.testing.expectEqual(@as(usize, 0), usage.snapshots);
        try std.testing.expectEqual(expected_count, workspaceCount(directory));
    }
    workspace_slot.in_use = false;

    const snapshot_slot = &directory.snapshots.slots[workspace.MAX_SNAPSHOTS - 1];
    for (0..8) |invalid| {
        snapshot_slot.in_use = invalid & 1 == 0;
        snapshot_slot.snapshot.label_len = if (invalid & 2 == 0) workspace.MAX_WORKSPACE_LABEL_BYTES else workspace.MAX_WORKSPACE_LABEL_BYTES + 1;
        snapshot_slot.snapshot.entry_count = if (invalid & 4 == 0) workspace.MAX_WORKSPACE_ENTRIES else workspace.MAX_WORKSPACE_ENTRIES + 1;
        const usage = productCapacityUsage(store, directory);
        const expected_count: usize = if (invalid == 0) 1 else 0;
        try std.testing.expectEqual(expected_count, usage.snapshots);
        try std.testing.expectEqual(expected_count * workspace.MAX_WORKSPACE_ENTRIES, usage.max_workspace_entries);
        try std.testing.expectEqual(@as(usize, 0), usage.workspaces);
        try std.testing.expectEqual(expected_count, snapshotCount(directory));
    }
    try std.testing.expectEqual(@as(u64, 0), directory.dirty_revision);
    try std.testing.expectEqual(@as(usize, 0), directory.workspaceCount());
    try std.testing.expectEqual(@as(usize, 0), directory.snapshotCount());
}

test "storage quota aggregates mixed physical slots and preserves rejection priority" {
    const std = @import("std");
    const store = try std.testing.allocator.create(object_store.Store);
    defer std.testing.allocator.destroy(store);
    store.* = object_store.Store.init();
    store.max_blob_payload_bytes = 1_234;
    const directory = try std.testing.allocator.create(workspace.Directory);
    defer std.testing.allocator.destroy(directory);
    directory.* = workspace.Directory.init();
    for (&directory.workspaces.slots, 0..) |*slot, index| {
        slot.in_use = true;
        slot.workspace.counts.entry_count = @intCast(index + 1);
    }
    directory.workspaces.slots[3].workspace.counts.deleted_count = workspace.MAX_RECOVERABLE_DELETES + 1;
    // A malformed slot's high entry count must not affect the accepted maximum.
    directory.workspaces.slots[3].workspace.counts.entry_count = workspace.MAX_WORKSPACE_ENTRIES;
    for (&directory.snapshots.slots, 0..) |*slot, index| {
        slot.in_use = true;
        slot.snapshot.entry_count = @intCast(index + 1);
    }
    directory.snapshots.slots[0].snapshot.label_len = workspace.MAX_WORKSPACE_LABEL_BYTES + 1;
    directory.snapshots.slots[1].snapshot.entry_count = workspace.MAX_WORKSPACE_ENTRIES + 1;
    directory.snapshots.slots[workspace.MAX_SNAPSHOTS - 1].snapshot.entry_count = workspace.MAX_WORKSPACE_ENTRIES;

    const usage = productCapacityUsage(store, directory);
    try std.testing.expectEqual(ProductCapacityUsage{
        .object_payload_bytes = 1_234,
        .workspaces = workspace.MAX_WORKSPACES - 1,
        .snapshots = workspace.MAX_SNAPSHOTS - 2,
        .max_workspace_entries = workspace.MAX_WORKSPACE_ENTRIES,
    }, usage);
    var envelope = first_supported_capacity_envelope;
    envelope.max_workspaces = usage.workspaces - 1;
    envelope.max_workspace_entries_per_workspace = usage.max_workspace_entries - 1;
    envelope.max_snapshots = usage.snapshots - 1;
    try std.testing.expectEqual(QuotaLimit.workspaces, quotaRejectionForCurrentState(store, directory, envelope).?.limit);
    envelope.max_workspaces = usage.workspaces;
    try std.testing.expectEqual(QuotaLimit.workspace_entries, quotaRejectionForCurrentState(store, directory, envelope).?.limit);
    envelope.max_workspace_entries_per_workspace = usage.max_workspace_entries;
    const rejection = quotaRejectionForCurrentState(store, directory, envelope).?;
    try std.testing.expectEqual(QuotaLimit.snapshots, rejection.limit);
    try std.testing.expectEqual(usage.snapshots, rejection.used);
    try std.testing.expectEqual(usage.snapshots, rejection.requested);
    try std.testing.expectEqual(envelope.max_snapshots, rejection.allowed);
    envelope.max_snapshots = usage.snapshots;
    try std.testing.expect(quotaRejectionForCurrentState(store, directory, envelope) == null);
    try std.testing.expectEqual(@as(u64, 0), directory.dirty_revision);
}
