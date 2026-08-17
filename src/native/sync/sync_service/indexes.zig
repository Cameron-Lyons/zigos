const std = @import("std");
const indexed_arena = @import("../../core/indexed_arena.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const principal = @import("../../core/principal.zig");
const state_support = @import("../sync_state_support.zig");
const contracts = @import("contracts.zig");

pub const replica_index_capacity: usize = state_support.MAX_REPLICA_ENTRIES * 2;
pub const workspace_policy_index_capacity: usize = state_support.MAX_WORKSPACE_POLICIES * 2;
pub const overlay_index_capacity: usize = state_support.MAX_OVERLAYS * 2;
pub const database_contract_index_capacity: usize = state_support.MAX_DATABASE_CONTRACTS * 2;
pub const conflict_index_capacity: usize = state_support.MAX_CONFLICTS * 2;
pub const transport_frame_index_capacity: usize = state_support.MAX_TRANSPORT_FRAMES * 2;
pub const WorkspacePolicyIndex = indexed_arena.UniqueIndex(workspace_policy_index_capacity);
pub const OverlayIndex = indexed_arena.UniqueIndex(overlay_index_capacity);
pub const DatabaseContractIdIndex = indexed_arena.UniqueIndex(database_contract_index_capacity);
pub const DatabaseContractBundleIndex = indexed_arena.MultimapIndex(state_support.MAX_DATABASE_CONTRACTS, state_support.MAX_DATABASE_CONTRACTS, database_contract_index_capacity);
pub const DatabaseContractEquivalentIndex = indexed_arena.UniqueIndex(database_contract_index_capacity);
pub const ConflictPathIndex = indexed_arena.UniqueIndex(conflict_index_capacity);
pub const ConflictObjectIndex = indexed_arena.UniqueIndex(conflict_index_capacity);
pub const ConflictScopeIndex = indexed_arena.MultimapIndex(state_support.MAX_CONFLICTS, state_support.MAX_CONFLICTS, conflict_index_capacity);
pub const ReplicaIndex = indexed_arena.UniqueIndex(replica_index_capacity);
pub const ReplicaScopeIndex = CompactMultimapIndex(state_support.MAX_REPLICA_ENTRIES, state_support.MAX_REPLICA_ENTRIES);
pub const TransportFramePathIndex = CompactMultimapIndex(state_support.MAX_TRANSPORT_FRAMES, state_support.MAX_TRANSPORT_FRAMES);
pub const TransportFrameTargetIndex = CompactMultimapIndex(state_support.MAX_TRANSPORT_FRAMES, state_support.MAX_TRANSPORT_FRAMES);
pub const InboundSourceHighWaterIndex = CompactMultimapIndex(state_support.MAX_TRANSPORT_FRAMES, state_support.MAX_TRANSPORT_FRAMES);

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

pub const ReplicaScopeLookup = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
};

pub const DatabaseContractLookup = struct {
    id: u64,
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

pub fn replicaScopeSlotMatches(context: ReplicaScopeLookup, slot: *const state_support.ReplicaSlot) bool {
    return slot.entry.workspace_id == context.workspace_id and
        slot.entry.device_id.eql(context.device_id);
}

pub fn databaseContractSlotMatches(context: DatabaseContractLookup, slot: *const state_support.DatabaseContractSlot) bool {
    return slot.contract.id == context.id;
}

pub fn equivalentDatabaseContractSlotMatches(context: DatabaseContractEquivalentLookup, slot: *const state_support.DatabaseContractSlot) bool {
    return slot.contract.workspace_id == context.workspace_id and
        std.mem.eql(u8, slot.contract.bundleIdSlice(), context.bundle_id) and
        std.mem.eql(u8, slot.contract.labelSlice(), context.label) and
        contracts.signatureEql(slot.contract.signature, context.signature);
}

pub fn replicaIndexLookupKey(workspace_id: u64, device_id: principal.PrincipalId, path_hash: u64) u64 {
    return state_support.replicaArenaKey(workspace_id, device_id, path_hash);
}

pub fn replicaScopeLookupKey(workspace_id: u64, device_id: principal.PrincipalId) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0x5250_4C43_5343_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendPrincipal(hash, device_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn workspacePolicyLookupKey(workspace_id: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0xA11C_4F4B_5350_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn overlayLookupKey(workspace_id: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0xA11C_4F4B_4F56_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn databaseContractIdLookupKey(contract_id: u64) u64 {
    return state_support.databaseContractArenaKey(contract_id);
}

pub fn databaseContractBundleLookupKey(workspace_id: u64, bundle_id: []const u8) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0xDBCA_0001_4255_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendHashBytes(hash, bundle_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn databaseContractEquivalentLookupKey(
    workspace_id: u64,
    bundle_id: []const u8,
    label: []const u8,
    signature: manifest.Signature,
) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0xDBCA_0001_4551_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendHashBytes(hash, bundle_id);
    hash = appendHashBytes(hash, label);
    hash = appendSignature(hash, signature);
    return indexed_arena.nonZeroKey(hash);
}

pub fn conflictPathLookupKey(workspace_id: u64, device_id: principal.PrincipalId, path: []const u8) u64 {
    return state_support.conflictArenaKey(workspace_id, device_id, path);
}

pub fn conflictObjectLookupKey(workspace_id: u64, device_id: principal.PrincipalId, object_id: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0xCF11_C700_4F42_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendPrincipal(hash, device_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, object_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn conflictScopeLookupKey(workspace_id: u64, device_id: principal.PrincipalId) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0xCF11_C700_5343_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendPrincipal(hash, device_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn transportFramePathLookupKey(workspace_id: u64, target_device: principal.PrincipalId, path: []const u8) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0x5452_4652_5041_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendPrincipal(hash, target_device);
    hash = appendHashBytes(hash, path);
    return indexed_arena.nonZeroKey(hash);
}

pub fn transportFrameTargetLookupKey(workspace_id: u64, target_device: principal.PrincipalId) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0x5452_4652_5447_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendPrincipal(hash, target_device);
    return indexed_arena.nonZeroKey(hash);
}

pub fn inboundSourceHighWaterLookupKey(
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0x5452_4652_4857_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = appendPrincipal(hash, source_device);
    hash = appendPrincipal(hash, target_device);
    return indexed_arena.nonZeroKey(hash);
}

fn appendSignature(hash: u64, signature: manifest.Signature) u64 {
    var next = appendHashBytes(hash, signature.format);
    next = appendHashBytes(next, signature.signer);
    next = appendHashBytes(next, signature.publicKeySlice());
    next = appendHashBytes(next, signature.valueSlice());
    return next;
}

fn appendHashBytes(hash: u64, bytes: []const u8) u64 {
    var next = native_util.fnv1a64AppendU64LittleEndian(hash, bytes.len);
    for (bytes) |byte| next = native_util.fnv1a64AppendByte(next, byte);
    return next;
}

fn appendPrincipal(hash: u64, value: principal.PrincipalId) u64 {
    var next = native_util.fnv1a64AppendByte(hash, @intFromEnum(value.kind));
    next = native_util.fnv1a64AppendU64LittleEndian(next, value.serial);
    return next;
}

fn CompactMultimapIndex(comptime link_capacity: usize, comptime bucket_capacity: usize) type {
    if (link_capacity == 0) @compileError("compact multimap index requires at least one linked slot");
    if (bucket_capacity == 0) @compileError("compact multimap index requires at least one bucket");
    if (link_capacity >= std.math.maxInt(u8)) @compileError("compact multimap index stores links as u8");
    if (bucket_capacity >= std.math.maxInt(u8)) @compileError("compact multimap index stores bucket indexes as u8");

    return struct {
        const Self = @This();
        const empty_link = std.math.maxInt(u8);

        const Bucket = struct {
            key: u64 = 0,
            head: u8 = empty_link,
            tail: u8 = empty_link,
            count: u8 = 0,
        };

        buckets: [bucket_capacity]Bucket = [_]Bucket{Bucket{}} ** bucket_capacity,
        next_by_slot: [link_capacity]u8 = [_]u8{empty_link} ** link_capacity,
        previous_by_slot: [link_capacity]u8 = [_]u8{empty_link} ** link_capacity,
        bucket_by_slot: [link_capacity]u8 = [_]u8{empty_link} ** link_capacity,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.* = Self.init();
        }

        pub fn count(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return 0;
            return entry.count;
        }

        pub fn head(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return indexed_arena.no_index;
            return decode(entry.head);
        }

        pub fn tail(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return indexed_arena.no_index;
            return decode(entry.tail);
        }

        pub fn next(self: *const Self, slot_index: usize) usize {
            if (slot_index >= link_capacity) return indexed_arena.no_index;
            return decode(self.next_by_slot[slot_index]);
        }

        pub fn previous(self: *const Self, slot_index: usize) usize {
            if (slot_index >= link_capacity) return indexed_arena.no_index;
            return decode(self.previous_by_slot[slot_index]);
        }

        pub fn append(self: *Self, key: u64, slot_index: usize) bool {
            if (key == 0 or slot_index >= link_capacity) return false;
            if (self.bucket_by_slot[slot_index] != empty_link) return false;
            const bucket_index = self.findOrCreateBucketIndex(key) orelse return false;
            const entry = &self.buckets[bucket_index];
            const encoded = encode(slot_index);
            self.next_by_slot[slot_index] = empty_link;
            self.previous_by_slot[slot_index] = entry.tail;
            self.bucket_by_slot[slot_index] = encode(bucket_index);
            if (entry.tail == empty_link) {
                entry.head = encoded;
            } else {
                self.next_by_slot[decode(entry.tail)] = encoded;
            }
            entry.tail = encoded;
            entry.count += 1;
            return true;
        }

        pub fn remove(self: *Self, key: u64, slot_index: usize) bool {
            if (key == 0 or slot_index >= link_capacity) return false;
            const bucket_index = self.bucketIndex(key) orelse return false;
            if (self.bucket_by_slot[slot_index] != encode(bucket_index)) return false;

            const entry = &self.buckets[bucket_index];
            const previous_link = self.previous_by_slot[slot_index];
            const next_link = self.next_by_slot[slot_index];
            if (previous_link == empty_link) {
                entry.head = next_link;
            } else {
                self.next_by_slot[decode(previous_link)] = next_link;
            }
            if (next_link == empty_link) {
                entry.tail = previous_link;
            } else {
                self.previous_by_slot[decode(next_link)] = previous_link;
            }
            self.next_by_slot[slot_index] = empty_link;
            self.previous_by_slot[slot_index] = empty_link;
            self.bucket_by_slot[slot_index] = empty_link;
            entry.count -= 1;
            if (entry.count == 0) entry.* = .{};
            return true;
        }

        fn bucketConst(self: *const Self, key: u64) ?*const Bucket {
            const index = self.bucketIndex(key) orelse return null;
            return &self.buckets[index];
        }

        fn bucketIndex(self: *const Self, key: u64) ?usize {
            if (key == 0) return null;
            for (self.buckets, 0..) |bucket_slot, bucket_index| {
                if (bucket_slot.key == key) return bucket_index;
            }
            return null;
        }

        fn findOrCreateBucketIndex(self: *Self, key: u64) ?usize {
            if (self.bucketIndex(key)) |index| return index;
            for (&self.buckets, 0..) |*slot, index| {
                if (slot.key != 0) continue;
                slot.* = .{ .key = key };
                return index;
            }
            return null;
        }

        fn encode(slot_index: usize) u8 {
            return @intCast(slot_index);
        }

        fn decode(link: u8) usize {
            return if (link == empty_link) indexed_arena.no_index else @as(usize, link);
        }
    };
}

test "compact multimap traverses backward and unlinks arbitrary slots" {
    const Index = CompactMultimapIndex(5, 3);
    var index = Index.init();

    try std.testing.expect(index.append(7, 0));
    try std.testing.expect(index.append(7, 2));
    try std.testing.expect(index.append(7, 4));
    try std.testing.expect(index.append(8, 1));
    try std.testing.expect(!index.append(8, 2));
    try std.testing.expectEqual(@as(usize, 0), index.head(7));
    try std.testing.expectEqual(@as(usize, 4), index.tail(7));
    try std.testing.expectEqual(@as(usize, 2), index.previous(4));
    try std.testing.expectEqual(@as(usize, 0), index.previous(2));
    try std.testing.expectEqual(indexed_arena.no_index, index.previous(0));

    try std.testing.expect(!index.remove(8, 2));
    try std.testing.expect(index.remove(7, 2));
    try std.testing.expectEqual(@as(usize, 4), index.next(0));
    try std.testing.expectEqual(@as(usize, 0), index.previous(4));
    try std.testing.expectEqual(indexed_arena.no_index, index.next(2));
    try std.testing.expectEqual(indexed_arena.no_index, index.previous(2));
    try std.testing.expect(index.append(9, 2));
    try std.testing.expectEqual(@as(usize, 2), index.head(9));
    try std.testing.expectEqual(@as(usize, 2), index.tail(9));
}
