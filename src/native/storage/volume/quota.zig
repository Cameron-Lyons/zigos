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
    .max_volume_log_bytes = volume_layout.data_capacity_bytes,
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
        .workspaces = workspaceCount(workspaces),
        .snapshots = snapshotCount(workspaces),
    };

    for (workspaces.workspaces.slots) |slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        usage.max_workspace_entries = @max(usage.max_workspace_entries, slot.workspace.path_index.entry_count);
    }
    for (workspaces.snapshots.slots) |slot| {
        if (!persistableSnapshotSlot(slot)) continue;
        usage.max_workspace_entries = @max(usage.max_workspace_entries, slot.snapshot.entry_count);
    }
    var blob_slot_index: usize = 0;
    while (blob_slot_index < store.blobSlotCapacity()) : (blob_slot_index += 1) {
        const slot = store.blobSlotAtConst(blob_slot_index);
        if (!slot.in_use) continue;
        usage.object_payload_bytes = @max(usage.object_payload_bytes, slot.blob.payload_len);
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
    for (workspaces.workspaces.slots) |slot| {
        if (persistableWorkspaceSlot(slot)) count += 1;
    }
    return count;
}

pub fn snapshotCount(workspaces: *const workspace.Directory) usize {
    var count: usize = 0;
    for (workspaces.snapshots.slots) |slot| {
        if (persistableSnapshotSlot(slot)) count += 1;
    }
    return count;
}

pub fn persistableWorkspaceSlot(slot: anytype) bool {
    if (!slot.in_use) return false;
    return slot.workspace.label_len <= slot.workspace.label.len and
        slot.workspace.path_index.entry_count <= workspace.MAX_WORKSPACE_ENTRIES and
        slot.workspace.mutation_log.entry_mutation_count <= workspace.MAX_WORKSPACE_ENTRY_MUTATIONS and
        slot.workspace.share_table.share_grant_count <= workspace.MAX_SHARE_GRANTS and
        slot.workspace.recoverable_deletes.deleted_count <= workspace.MAX_RECOVERABLE_DELETES;
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
