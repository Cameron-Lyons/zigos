const std = @import("std");
const indexed_arena = @import("../../core/indexed_arena.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const principal = @import("../../core/principal.zig");
const state_support = @import("../sync_state_support.zig");
const contracts = @import("contracts.zig");

pub const replica_index_capacity: usize = state_support.MAX_REPLICA_ENTRIES * 2;
pub const ReplicaIndex = indexed_arena.UniqueIndex(replica_index_capacity);
pub const workspace_policy_index_capacity: usize = state_support.MAX_WORKSPACE_POLICIES * 2;
pub const WorkspacePolicyIndex = indexed_arena.UniqueIndex(workspace_policy_index_capacity);
pub const overlay_index_capacity: usize = state_support.MAX_OVERLAYS * 2;
pub const OverlayIndex = indexed_arena.UniqueIndex(overlay_index_capacity);
pub const database_contract_index_capacity: usize = state_support.MAX_DATABASE_CONTRACTS * 2;
pub const DatabaseContractIndex = indexed_arena.UniqueIndex(database_contract_index_capacity);

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

pub fn workspacePolicyIndexLookupKey(workspace_id: u64) u64 {
    return workspaceScopedIndexKey(workspace_id);
}

pub fn overlayIndexLookupKey(workspace_id: u64) u64 {
    return workspaceScopedIndexKey(workspace_id);
}

pub fn databaseContractIndexLookupKey(contract_id: u64) u64 {
    return indexed_arena.nonZeroKey(contract_id);
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

test "sync service lookup indexes use nonzero workspace keys" {
    try std.testing.expect(workspacePolicyIndexLookupKey(0) != 0);
    try std.testing.expect(overlayIndexLookupKey(42) != 0);
    try std.testing.expectEqual(workspacePolicyIndexLookupKey(42), overlayIndexLookupKey(42));
    try std.testing.expect(databaseContractIndexLookupKey(0) != 0);
}
