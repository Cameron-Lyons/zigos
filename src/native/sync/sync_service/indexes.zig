const std = @import("std");
const indexed_arena = @import("../../core/indexed_arena.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const principal = @import("../../core/principal.zig");
const state_support = @import("../sync_state_support.zig");
const contracts = @import("contracts.zig");
const workspace = @import("../../storage/workspace.zig");

pub const replica_index_capacity: usize = state_support.MAX_REPLICA_ENTRIES * 2;
pub const ReplicaIndex = indexed_arena.UniqueIndex(replica_index_capacity);
pub const workspace_policy_index_capacity: usize = state_support.MAX_WORKSPACE_POLICIES * 2;
pub const WorkspacePolicyIndex = indexed_arena.UniqueIndex(workspace_policy_index_capacity);
pub const overlay_index_capacity: usize = state_support.MAX_OVERLAYS * 2;
pub const OverlayIndex = indexed_arena.UniqueIndex(overlay_index_capacity);
pub const database_contract_index_capacity: usize = state_support.MAX_DATABASE_CONTRACTS * 2;
pub const DatabaseContractIndex = indexed_arena.UniqueIndex(database_contract_index_capacity);
pub const database_contract_equivalent_index_capacity: usize = state_support.MAX_DATABASE_CONTRACTS * 2;
pub const DatabaseContractEquivalentIndex = indexed_arena.UniqueIndex(database_contract_equivalent_index_capacity);
pub const database_contract_bundle_index_capacity: usize = state_support.MAX_DATABASE_CONTRACTS * 2;
pub const DatabaseContractBundleIndex = indexed_arena.MultimapIndex(
    state_support.MAX_DATABASE_CONTRACTS,
    state_support.MAX_DATABASE_CONTRACTS,
    database_contract_bundle_index_capacity,
);
pub const conflict_index_capacity: usize = state_support.MAX_CONFLICTS * 2;
pub const ConflictIndex = indexed_arena.UniqueIndex(conflict_index_capacity);
pub const inbound_transport_duplicate_index_capacity: usize = state_support.MAX_TRANSPORT_FRAMES * 2;
pub const InboundTransportDuplicateIndex = indexed_arena.UniqueIndex(inbound_transport_duplicate_index_capacity);
pub const inbound_transport_high_water_index_capacity: usize = state_support.MAX_TRANSPORT_FRAMES * 2;
pub const InboundTransportHighWaterIndex = indexed_arena.UniqueIndex(inbound_transport_high_water_index_capacity);
pub const outbound_transport_frame_index_capacity: usize = state_support.MAX_TRANSPORT_FRAMES * 2;
pub const OutboundTransportFrameIndex = indexed_arena.UniqueIndex(outbound_transport_frame_index_capacity);

pub const WorkspacePolicyLookup = struct {
    workspace_id: u64,
};

pub const OverlayLookup = struct {
    workspace_id: u64,
};

pub const ReplicaLookup = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
    path: []const u8,
    path_hash: u64,
};

pub const ConflictLookup = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
    path: []const u8,
    path_hash: u64,
};

pub const InboundTransportDuplicateLookup = struct {
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    source_frame_id: u64,
};

pub const InboundTransportScopeLookup = struct {
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
};

const ReplicaIndexKey = struct {
    workspace_id: u64 = 0,
    device_id: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    path_hash: u64 = 0,
};

pub const DatabaseContractEquivalentLookup = struct {
    workspace_id: u64,
    bundle_id: []const u8,
    label: []const u8,
    signature: manifest.Signature,
};

pub fn workspacePolicySlotMatches(context: WorkspacePolicyLookup, slot: *const state_support.WorkspacePolicySlot) bool {
    return slot.policy.workspace_id == context.workspace_id;
}

pub fn overlaySlotMatches(context: OverlayLookup, slot: *const state_support.OverlaySlot) bool {
    return slot.overlay.workspace_id == context.workspace_id;
}

pub fn replicaSlotMatches(context: ReplicaLookup, slot: *const state_support.ReplicaSlot) bool {
    return slot.entry.workspace_id == context.workspace_id and
        slot.entry.device_id.eql(context.device_id) and
        slot.entry.pathHash() == context.path_hash and
        std.mem.eql(u8, slot.entry.pathSlice(), context.path);
}

pub fn conflictSlotMatches(context: ConflictLookup, slot: *const state_support.ConflictSlot) bool {
    return slot.conflict.workspace_id == context.workspace_id and
        slot.conflict.device_id.eql(context.device_id) and
        conflictPathHash(&slot.conflict) == context.path_hash and
        std.mem.eql(u8, slot.conflict.pathSlice(), context.path);
}

pub fn inboundTransportDuplicateSlotMatches(context: InboundTransportDuplicateLookup, slot: *const state_support.DurableTransportFrameSlot) bool {
    return slot.frame.workspace_id == context.workspace_id and
        slot.frame.source_frame_id == context.source_frame_id and
        slot.frame.source_device.eql(context.source_device) and
        slot.frame.target_device.eql(context.target_device);
}

pub fn inboundTransportScopeSlotMatches(context: InboundTransportScopeLookup, slot: *const state_support.DurableTransportFrameSlot) bool {
    return slot.frame.workspace_id == context.workspace_id and
        slot.frame.source_device.eql(context.source_device) and
        slot.frame.target_device.eql(context.target_device);
}

pub fn equivalentDatabaseContractSlotMatches(context: DatabaseContractEquivalentLookup, slot: *const state_support.DatabaseContractSlot) bool {
    return slot.contract.workspace_id == context.workspace_id and
        std.mem.eql(u8, slot.contract.bundleIdSlice(), context.bundle_id) and
        std.mem.eql(u8, slot.contract.labelSlice(), context.label) and
        contracts.signatureEql(slot.contract.signature, context.signature);
}

fn replicaIndexKey(workspace_id: u64, device_id: principal.PrincipalId, path_hash: u64) ReplicaIndexKey {
    return .{
        .workspace_id = workspace_id,
        .device_id = device_id,
        .path_hash = path_hash,
    };
}

pub fn replicaIndexLookupKey(workspace_id: u64, device_id: principal.PrincipalId, path_hash: u64) u64 {
    return indexed_arena.nonZeroKey(replicaIndexHash(replicaIndexKey(workspace_id, device_id, path_hash)));
}

pub fn conflictIndexLookupKey(workspace_id: u64, device_id: principal.PrincipalId, path_hash: u64) u64 {
    return indexed_arena.nonZeroKey(replicaIndexHash(replicaIndexKey(workspace_id, device_id, path_hash)));
}

pub fn inboundTransportDuplicateIndexLookupKey(
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    source_frame_id: u64,
) u64 {
    var hash = inboundTransportScopeHash(workspace_id, source_device, target_device);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, source_frame_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn inboundTransportHighWaterIndexLookupKey(
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
) u64 {
    return indexed_arena.nonZeroKey(inboundTransportScopeHash(workspace_id, source_device, target_device));
}

pub fn outboundTransportFrameIndexLookupKey(frame_id: u64) u64 {
    return indexed_arena.nonZeroKey(frame_id);
}

fn inboundTransportScopeHash(
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(source_device.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, source_device.serial);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(target_device.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, target_device.serial);
    return hash;
}

pub fn workspacePolicyIndexLookupKey(workspace_id: u64) u64 {
    return workspaceScopedIndexKey(workspace_id);
}

pub fn overlayIndexLookupKey(workspace_id: u64) u64 {
    return workspaceScopedIndexKey(workspace_id);
}

pub fn databaseContractIndexLookupKey(contract_id: u64) u64 {
    return indexed_arena.nonZeroKey(contract_id);
}

pub fn databaseContractEquivalentIndexLookupKey(
    workspace_id: u64,
    bundle_id: []const u8,
    label: []const u8,
    signature: manifest.Signature,
) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendBytesWithLength(hash, bundle_id);
    hash = appendBytesWithLength(hash, label);
    hash = appendBytesWithLength(hash, signature.format);
    hash = appendBytesWithLength(hash, signature.signer);
    hash = appendBytesWithLength(hash, signature.publicKeySlice());
    hash = appendBytesWithLength(hash, signature.valueSlice());
    return indexed_arena.nonZeroKey(hash);
}

pub fn databaseContractBundleIndexLookupKey(workspace_id: u64, bundle_id: []const u8) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendBytesWithLength(hash, bundle_id);
    return indexed_arena.nonZeroKey(hash);
}

fn replicaIndexHash(key: ReplicaIndexKey) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.workspace_id);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(key.device_id.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.device_id.serial);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.path_hash);
    return hash;
}

fn workspaceScopedIndexKey(workspace_id: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    return indexed_arena.nonZeroKey(hash);
}

fn appendBytesWithLength(hash: u64, bytes: []const u8) u64 {
    const with_len = native_util.fnv1a64AppendU64LittleEndian(hash, @intCast(bytes.len));
    return native_util.fnv1a64WithSeed(with_len, bytes);
}

fn conflictPathHash(conflict: *const state_support.ConflictRecord) u64 {
    return workspace.pathHash(conflict.pathSlice());
}

test "sync service lookup indexes use nonzero workspace keys" {
    try std.testing.expect(workspacePolicyIndexLookupKey(0) != 0);
    try std.testing.expect(overlayIndexLookupKey(42) != 0);
    try std.testing.expectEqual(workspacePolicyIndexLookupKey(42), overlayIndexLookupKey(42));
    try std.testing.expect(conflictIndexLookupKey(7, .{ .kind = .device, .serial = 2 }, 99) != 0);
    try std.testing.expect(inboundTransportDuplicateIndexLookupKey(
        7,
        .{ .kind = .device, .serial = 2 },
        .{ .kind = .device, .serial = 3 },
        99,
    ) != 0);
    try std.testing.expect(inboundTransportHighWaterIndexLookupKey(
        7,
        .{ .kind = .device, .serial = 2 },
        .{ .kind = .device, .serial = 3 },
    ) != 0);
    try std.testing.expect(outboundTransportFrameIndexLookupKey(0) != 0);
    try std.testing.expect(databaseContractIndexLookupKey(0) != 0);
    const signature = manifest.Signature{ .signer = "test-signer" };
    try std.testing.expect(databaseContractEquivalentIndexLookupKey(7, "app.notes", "main", signature) != 0);
    try std.testing.expect(databaseContractEquivalentIndexLookupKey(7, "app.notes", "main", signature) != databaseContractEquivalentIndexLookupKey(7, "app.notes", "other", signature));
    try std.testing.expect(databaseContractBundleIndexLookupKey(7, "app.notes") != 0);
    try std.testing.expect(databaseContractBundleIndexLookupKey(7, "app.notes") != databaseContractBundleIndexLookupKey(8, "app.notes"));
}
