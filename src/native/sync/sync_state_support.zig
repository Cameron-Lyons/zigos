const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const device_graph = @import("device_graph.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_util = @import("../core/util.zig");
const network_policy = @import("network_policy.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const workspace = @import("../storage/workspace.zig");

pub const MAX_WORKSPACE_POLICIES: usize = 8;
pub const MAX_SELECTIVE_PREFIXES: usize = 4;
pub const MAX_PREFIX_BYTES: usize = 48;
pub const MAX_REPLICA_ENTRIES: usize = 32;
pub const MAX_CONFLICTS: usize = 16;
pub const MAX_DATABASE_CONTRACTS: usize = 8;
pub const MAX_OVERLAYS: usize = 4;
pub const MAX_PRIVATE_SERVICES: usize = 4;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_TRANSPORT_FRAMES: usize = 64;
pub const TRANSPORT_REPLAY_WINDOW: u64 = 32;
pub const COMPACT_RECORD_METADATA = true;
pub const SyncPathLength = workspace.WorkspacePathLength;
pub const WORKSPACE_POLICY_SIZE_CEILING_BYTES: usize = 328;
pub const OVERLAY_RECORD_SIZE_CEILING_BYTES: usize = 280;
pub const REPLICA_ENTRY_SIZE_CEILING_BYTES: usize = 144;
pub const CONFLICT_RECORD_SIZE_CEILING_BYTES: usize = 152;
pub const CONFLICT_REVIEW_RECORD_SIZE_CEILING_BYTES: usize = 152;
pub const DATABASE_CONTRACT_SIZE_CEILING_BYTES: usize = 240;
pub const TRANSPORT_FRAME_SIZE_CEILING_BYTES: usize = 176;
pub const PERSISTENT_STATE_SIZE_CEILING_BYTES: usize = 55_640;
pub const RESIDENT_STATE_SIZE_CEILING_BYTES: usize = 57_768;
pub const state_workspace_label = "system-sync";
pub const state_signer = signing.SignerIdentity{
    .label = "zigos-sync-state",
    .seed = signing.seedFromByte(0xA7),
};

comptime {
    if (MAX_SELECTIVE_PREFIXES > std.math.maxInt(u8) or
        MAX_PRIVATE_SERVICES > std.math.maxInt(u8) or
        MAX_PREFIX_BYTES > std.math.maxInt(u8) or
        MAX_LABEL_BYTES > std.math.maxInt(u8) or
        workspace.MAX_ENTRY_PATH_BYTES > std.math.maxInt(SyncPathLength))
    {
        @compileError("sync record metadata no longer fits compact counters");
    }
}

pub const TransportMode = enum(u8) {
    device_to_device,
    relay_assisted,
};

pub const SyncSemantic = enum(u8) {
    mergeable_crdt,
    chunked_snapshot,
    secure_transfer,
    transactional_contract,
};

pub const WorkspacePolicyRequest = struct {
    workspace_id: u64,
    owner: principal.PrincipalId,
    offline_first: bool = true,
    personal_e2ee: bool = true,
    require_shared_access: bool = false,
    selective_prefixes: []const []const u8 = &.{},
    device_to_device_policy_id: ?u64 = null,
    relay_policy_id: ?u64 = null,
    overlay_policy_id: ?u64 = null,
    relay_domain: []const u8 = "",
};

pub const WorkspacePolicy = struct {
    workspace_id: u64,
    owner: principal.PrincipalId,
    offline_first: bool,
    personal_e2ee: bool,
    require_shared_access: bool,
    selective_prefix_count: u8,
    selective_prefixes: [MAX_SELECTIVE_PREFIXES][MAX_PREFIX_BYTES]u8,
    selective_prefix_lens: [MAX_SELECTIVE_PREFIXES]u8,
    device_to_device_policy_id: ?u64,
    relay_policy_id: ?u64,
    overlay_policy_id: ?u64,
    relay_domain_len: u8,
    relay_domain: [MAX_LABEL_BYTES]u8,

    pub fn relayDomainSlice(self: *const WorkspacePolicy) []const u8 {
        return self.relay_domain[0..@as(usize, self.relay_domain_len)];
    }

    pub fn matchesPath(self: *const WorkspacePolicy, path: []const u8) bool {
        if (self.selective_prefix_count == 0) return true;
        var index: usize = 0;
        while (index < @as(usize, self.selective_prefix_count)) : (index += 1) {
            const prefix = self.selective_prefixes[index][0..@as(usize, self.selective_prefix_lens[index])];
            if (std.mem.startsWith(u8, path, prefix)) return true;
        }
        return false;
    }

    comptime {
        if (@sizeOf(@This()) > WORKSPACE_POLICY_SIZE_CEILING_BYTES) {
            @compileError("workspace sync policy exceeds its compact size ceiling");
        }
    }
};

pub const OverlayRecord = struct {
    id: u64,
    workspace_id: u64,
    home_device: principal.PrincipalId,
    service_identity_len: u8,
    service_identity: [MAX_LABEL_BYTES]u8,
    remote_access_enabled: bool,
    private_service_count: u8,
    private_services: [MAX_PRIVATE_SERVICES][MAX_LABEL_BYTES]u8,
    private_service_lens: [MAX_PRIVATE_SERVICES]u8,

    pub fn serviceIdentitySlice(self: *const OverlayRecord) []const u8 {
        return self.service_identity[0..@as(usize, self.service_identity_len)];
    }

    pub fn hasPrivateServices(self: *const OverlayRecord) bool {
        return self.private_service_count != 0;
    }

    pub fn hasPrivateService(self: *const OverlayRecord, label: []const u8) bool {
        var index: usize = 0;
        while (index < @as(usize, self.private_service_count)) : (index += 1) {
            if (std.mem.eql(u8, self.private_services[index][0..@as(usize, self.private_service_lens[index])], label)) {
                return true;
            }
        }
        return false;
    }

    comptime {
        if (@sizeOf(@This()) > OVERLAY_RECORD_SIZE_CEILING_BYTES) {
            @compileError("sync overlay record exceeds its compact size ceiling");
        }
    }
};

pub const ReplicaEntry = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
    workspace_generation: u32,
    path_len: SyncPathLength,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8,
    object_id: u64,
    version_id: u64,

    pub fn pathSlice(self: *const ReplicaEntry) []const u8 {
        return self.path[0..@as(usize, self.path_len)];
    }

    pub fn pathHash(self: *const ReplicaEntry) u64 {
        return workspace.pathHash(self.pathSlice());
    }

    comptime {
        if (@sizeOf(@This()) > REPLICA_ENTRY_SIZE_CEILING_BYTES) {
            @compileError("sync replica entry exceeds its compact size ceiling");
        }
    }
};

pub const ConflictRecord = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
    object_id: u64,
    path_len: SyncPathLength,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8,
    local_version_id: u64,
    remote_version_id: u64,
    semantic: SyncSemantic,

    pub fn pathSlice(self: *const ConflictRecord) []const u8 {
        return self.path[0..@as(usize, self.path_len)];
    }

    comptime {
        if (@sizeOf(@This()) > CONFLICT_RECORD_SIZE_CEILING_BYTES) {
            @compileError("sync conflict record exceeds its compact size ceiling");
        }
    }
};

pub const ConflictReviewDecision = enum(u8) {
    keep_local,
    accept_remote,
    keep_both,
};

pub const ConflictReviewRecord = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
    object_id: u64,
    path_len: SyncPathLength,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8,
    local_version_id: u64,
    remote_version_id: u64,
    semantic: SyncSemantic,
    decision: ConflictReviewDecision,
    resolved: bool,

    pub fn pathSlice(self: *const ConflictReviewRecord) []const u8 {
        return self.path[0..@as(usize, self.path_len)];
    }

    comptime {
        if (@sizeOf(@This()) > CONFLICT_REVIEW_RECORD_SIZE_CEILING_BYTES) {
            @compileError("sync conflict review record exceeds its compact size ceiling");
        }
    }
};

pub const DatabaseContract = struct {
    id: u64,
    workspace_id: u64,
    bundle_id_len: u8,
    bundle_id: [MAX_LABEL_BYTES]u8,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    signature: manifest.Signature = .{},

    pub fn bundleIdSlice(self: *const DatabaseContract) []const u8 {
        return self.bundle_id[0..@as(usize, self.bundle_id_len)];
    }

    pub fn labelSlice(self: *const DatabaseContract) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }

    comptime {
        if (@sizeOf(@This()) > DATABASE_CONTRACT_SIZE_CEILING_BYTES) {
            @compileError("sync database contract exceeds its compact size ceiling");
        }
    }
};

pub const ReplicationSummary = struct {
    selected_entry_count: usize = 0,
    skipped_entry_count: usize = 0,
    share_denied_entry_count: usize = 0,
    merged_count: usize = 0,
    snapshot_count: usize = 0,
    secret_transfer_count: usize = 0,
    transactional_count: usize = 0,
    conflict_count: usize = 0,
    used_device_to_device: bool = false,
    used_relay: bool = false,
    overlay_ready: bool = false,
    remote_access_ready: bool = false,
    private_service_published: bool = false,
    personal_e2ee: bool = false,
    offline_first: bool = false,
    transport_frame_count: usize = 0,
    encrypted_transport_count: usize = 0,
};

pub const TransportQueueKind = enum(u8) {
    outbound,
    inbound,
};

pub const TransportFrame = struct {
    id: u64 = 0,
    source_frame_id: u64 = 0,
    workspace_id: u64 = 0,
    object_id: u64 = 0,
    version_id: u64 = 0,
    source_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    target_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    transport: TransportMode = .device_to_device,
    semantic: SyncSemantic = .mergeable_crdt,
    encrypted: bool = false,
    workspace_generation: u32 = 0,
    path_len: SyncPathLength = 0,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8 = [_]u8{0} ** workspace.MAX_ENTRY_PATH_BYTES,

    pub fn pathSlice(self: *const TransportFrame) []const u8 {
        return self.path[0..@as(usize, self.path_len)];
    }

    comptime {
        if (@sizeOf(@This()) > TRANSPORT_FRAME_SIZE_CEILING_BYTES) {
            @compileError("sync transport frame exceeds its compact size ceiling");
        }
    }
};

pub const TransportFrameRequest = struct {
    source_frame_id: u64 = 0,
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    transport: TransportMode,
    semantic: SyncSemantic,
    encrypted: bool,
    workspace_generation: u32 = 0,
    path: []const u8,
};

pub const DurableTransportFrameSlot = struct {
    in_use: bool = false,
    duplicate_count: u16 = 0,
    next_frame_id_after_publish: u64 = 1,
    frame: TransportFrame = .{},
};

pub fn advanceTransportFrameId(frame_id: u64) u64 {
    std.debug.assert(frame_id != 0);
    return if (frame_id == std.math.maxInt(u64)) 0 else frame_id + 1;
}

pub const Error = error{
    BundleIdTooLong,
    ConflictNotFound,
    ConflictTableFull,
    CorruptState,
    DatabaseContractNotFound,
    DatabaseContractTableFull,
    DeviceNotTrusted,
    DocumentBufferTooSmall,
    DocumentOperationTooLarge,
    DuplicateDocumentOperation,
    InvalidContractSignature,
    InvalidStateSignatureEncoding,
    LabelTooLong,
    NetworkTargetTooLong,
    OverlayNotFound,
    OverlaySessionNotFound,
    OverlayTableFull,
    PrivateServiceNotPublished,
    ReplicaTableFull,
    RelayDeliveryMissing,
    RemoteAccessDisabled,
    StateSigningFailed,
    StateTooLarge,
    SyncSemanticMismatch,
    PathTooLong,
    SecretPayloadNotEncrypted,
    TooManyPrivateServices,
    TooManySelectivePrefixes,
    ServiceIdentityTooLong,
    TransportDenied,
    TransportDuplicateFrame,
    TransportFrameIdExhausted,
    TransportQueueFull,
    TransportReplayRejected,
    TooManyDocumentOperations,
    DocumentOperationLogFull,
    UnsupportedStateVersion,
    WorkspacePolicyNotFound,
    WorkspacePolicyTableFull,
} || network_policy.Error || device_graph.Error || workspace.Error || object_store.Error;

pub const WorkspacePolicySlot = struct {
    in_use: bool = false,
    policy: WorkspacePolicy = zeroWorkspacePolicy(),
};

pub const ReplicaSlot = struct {
    in_use: bool = false,
    entry: ReplicaEntry = zeroReplicaEntry(),
};

pub const ConflictSlot = struct {
    in_use: bool = false,
    conflict: ConflictRecord = zeroConflict(),
};

pub const DatabaseContractSlot = struct {
    in_use: bool = false,
    contract: DatabaseContract = zeroDatabaseContract(),
};

pub const OverlaySlot = struct {
    in_use: bool = false,
    overlay: OverlayRecord = zeroOverlay(),
};

const WORKSPACE_POLICY_ARENA_INDEX_CAPACITY = MAX_WORKSPACE_POLICIES * 2;
const REPLICA_ARENA_INDEX_CAPACITY = MAX_REPLICA_ENTRIES * 2;
const CONFLICT_ARENA_INDEX_CAPACITY = MAX_CONFLICTS * 2;
const DATABASE_CONTRACT_ARENA_INDEX_CAPACITY = MAX_DATABASE_CONTRACTS * 2;
const OVERLAY_ARENA_INDEX_CAPACITY = MAX_OVERLAYS * 2;
const TRANSPORT_FRAME_ARENA_INDEX_CAPACITY = MAX_TRANSPORT_FRAMES * 2;

pub fn workspacePolicyArenaKey(workspace_id: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0x5354_4154_4557_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn overlayArenaKey(workspace_id: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0x5354_4154_454F_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn replicaArenaKey(workspace_id: u64, device_id: principal.PrincipalId, path_hash: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(device_id.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, device_id.serial);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, path_hash);
    return indexed_arena.nonZeroKey(hash);
}

pub fn conflictArenaKey(workspace_id: u64, device_id: principal.PrincipalId, path: []const u8) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0xCF11_C700_5041_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(device_id.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, device_id.serial);
    hash = appendHashBytes(hash, path);
    return indexed_arena.nonZeroKey(hash);
}

pub fn databaseContractArenaKey(contract_id: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0xDBCA_0001_4944_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, contract_id);
    return indexed_arena.nonZeroKey(hash);
}

pub fn transportFrameArenaKey(frame_id: u64) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, 0x5452_414E_4652_0001);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, frame_id);
    return indexed_arena.nonZeroKey(hash);
}

fn appendHashBytes(hash: u64, bytes: []const u8) u64 {
    var next = native_util.fnv1a64AppendU64LittleEndian(hash, bytes.len);
    for (bytes) |byte| next = native_util.fnv1a64AppendByte(next, byte);
    return next;
}

fn workspacePolicySlotKey(slot: *const WorkspacePolicySlot) u64 {
    return workspacePolicyArenaKey(slot.policy.workspace_id);
}

fn replicaSlotKey(slot: *const ReplicaSlot) u64 {
    return replicaArenaKey(slot.entry.workspace_id, slot.entry.device_id, slot.entry.pathHash());
}

fn conflictSlotKey(slot: *const ConflictSlot) u64 {
    return conflictArenaKey(slot.conflict.workspace_id, slot.conflict.device_id, slot.conflict.pathSlice());
}

fn databaseContractSlotKey(slot: *const DatabaseContractSlot) u64 {
    return databaseContractArenaKey(slot.contract.id);
}

fn transportFrameSlotKey(slot: *const DurableTransportFrameSlot) u64 {
    return transportFrameArenaKey(slot.frame.id);
}

fn overlaySlotKey(slot: *const OverlaySlot) u64 {
    return overlayArenaKey(slot.overlay.workspace_id);
}

pub const WorkspacePolicyArena = indexed_arena.IndexedArenaWithKey(u64, WorkspacePolicySlot, MAX_WORKSPACE_POLICIES, WORKSPACE_POLICY_ARENA_INDEX_CAPACITY, workspacePolicySlotKey);
pub const ReplicaArena = indexed_arena.IndexedArenaWithKey(u64, ReplicaSlot, MAX_REPLICA_ENTRIES, REPLICA_ARENA_INDEX_CAPACITY, replicaSlotKey);
pub const ConflictArena = indexed_arena.IndexedArenaWithKey(u64, ConflictSlot, MAX_CONFLICTS, CONFLICT_ARENA_INDEX_CAPACITY, conflictSlotKey);
pub const DatabaseContractArena = indexed_arena.IndexedArenaWithKey(u64, DatabaseContractSlot, MAX_DATABASE_CONTRACTS, DATABASE_CONTRACT_ARENA_INDEX_CAPACITY, databaseContractSlotKey);
pub const OverlayArena = indexed_arena.IndexedArenaWithKey(u64, OverlaySlot, MAX_OVERLAYS, OVERLAY_ARENA_INDEX_CAPACITY, overlaySlotKey);
pub const TransportFrameArena = indexed_arena.IndexedArenaWithKey(u64, DurableTransportFrameSlot, MAX_TRANSPORT_FRAMES, TRANSPORT_FRAME_ARENA_INDEX_CAPACITY, transportFrameSlotKey);

pub const PersistentState = struct {
    next_overlay_id: u64 = 1,
    next_contract_id: u64 = 1,
    graph: device_graph.Graph = device_graph.Graph.init(),
    network_policies: network_policy.Directory = network_policy.Directory.init(),
    workspace_policies: WorkspacePolicyArena = WorkspacePolicyArena.init(),
    replica_entries: ReplicaArena = ReplicaArena.init(),
    conflicts: ConflictArena = ConflictArena.init(),
    database_contracts: DatabaseContractArena = DatabaseContractArena.init(),
    overlays: OverlayArena = OverlayArena.init(),
    next_transport_frame_id: u64 = 1,
    outbound_transport_frames: TransportFrameArena = TransportFrameArena.init(),
    inbound_transport_frames: TransportFrameArena = TransportFrameArena.init(),

    pub fn reset(self: *PersistentState) void {
        self.next_overlay_id = 1;
        self.next_contract_id = 1;
        self.next_transport_frame_id = 1;
        self.graph.reset();
        self.network_policies.reset();
        self.workspace_policies.reset();
        self.replica_entries.reset();
        self.conflicts.reset();
        self.database_contracts.reset();
        self.overlays.reset();
        self.outbound_transport_frames.reset();
        self.inbound_transport_frames.reset();
    }

    comptime {
        if (@sizeOf(@This()) > PERSISTENT_STATE_SIZE_CEILING_BYTES) {
            @compileError("sync persistent state exceeds its compact size ceiling");
        }
    }
};

pub const ResidentState = struct {
    persisted_state: PersistentState = .{},
    has_persisted_state: bool = false,
    transport_cursor_loaded: bool = false,
    user_root_signers: [device_graph.MAX_USER_ROOTS][MAX_LABEL_BYTES]u8 =
        [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** device_graph.MAX_USER_ROOTS,
    device_signature_signers: [device_graph.MAX_DEVICES][4][MAX_LABEL_BYTES]u8 =
        [_][4][MAX_LABEL_BYTES]u8{[_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** 4} ** device_graph.MAX_DEVICES,
    database_contract_signers: [MAX_DATABASE_CONTRACTS][MAX_LABEL_BYTES]u8 =
        [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_DATABASE_CONTRACTS,
    next_state_tick: u64 = 1,

    pub fn initializeAllocated(self: *ResidentState) void {
        @memset(std.mem.asBytes(self), 0);
        self.resetPersistent();
    }

    pub fn resetForServiceInit(self: *ResidentState) void {
        self.persisted_state.reset();
        self.transport_cursor_loaded = false;
        self.resetSignatureStorage();
    }

    pub fn resetPersistent(self: *ResidentState) void {
        self.persisted_state.reset();
        self.has_persisted_state = false;
        self.transport_cursor_loaded = false;
        self.resetSignatureStorage();
        self.next_state_tick = 1;
    }

    pub fn markDirty(self: *ResidentState) void {
        self.has_persisted_state = true;
    }

    pub fn userRootCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.graph.user_roots.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn deviceCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.graph.devices.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn networkPolicyCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.network_policies.policies.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn workspacePolicyCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.workspace_policies.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn replicaCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.replica_entries.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn conflictCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.conflicts.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn databaseContractCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.database_contracts.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn overlayCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.overlays.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn outboundTransportFrameCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.outbound_transport_frames.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn inboundTransportFrameCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.inbound_transport_frames.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn nextPersistedPolicyId(self: *const ResidentState) u64 {
        var next_id: u64 = 1;
        for (self.persisted_state.network_policies.policies.slots) |slot| {
            if (!slot.in_use) continue;
            next_id = @max(next_id, slot.policy.id + 1);
        }
        return next_id;
    }

    pub fn nextPersistTick(self: *ResidentState) u64 {
        defer self.next_state_tick += 1;
        return self.next_state_tick;
    }

    pub fn resetSignatureStorage(self: *ResidentState) void {
        @memset(std.mem.asBytes(&self.user_root_signers), 0);
        @memset(std.mem.asBytes(&self.device_signature_signers), 0);
        @memset(std.mem.asBytes(&self.database_contract_signers), 0);
    }

    comptime {
        if (@sizeOf(@This()) > RESIDENT_STATE_SIZE_CEILING_BYTES) {
            @compileError("sync resident state exceeds its compact size ceiling");
        }
    }
};

pub fn readOptionalU64(value: u64) ?u64 {
    return if (value == 0) null else value;
}

pub fn databaseContractMessage(
    buffer: []u8,
    workspace_id: u64,
    bundle_id: []const u8,
    label: []const u8,
) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buffer, "db-contract:{d}:{s}:{s}", .{ workspace_id, bundle_id, label }) catch error.NoSpaceLeft;
}

pub fn zeroDeviceGraphRecord() device_graph.DeviceRecord {
    return .{
        .principal_id = .{ .kind = .device, .serial = 0 },
        .owner = .{ .kind = .user, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** device_graph.MAX_LABEL_BYTES,
        .overlay_id = 0,
        .status = .trusted,
        .trust_generation = 1,
        .key_rotation_generation = 1,
        .device_signature = .{},
        .enrollment_signature = .{},
        .rotation_signature = .{},
        .revocation_signature = .{},
        .last_rotated_at_ticks = 0,
        .revoked_at_ticks = 0,
        .device_key_origin = .software,
        .platform_key_bound = false,
        .platform_key_label_len = 0,
        .platform_key_label = [_]u8{0} ** device_graph.MAX_LABEL_BYTES,
        .platform_key_digest = crypto_hash.zero_digest,
        .platform_root_generation = 0,
        .platform_root_provenance = measured_boot.RootProvenance.synthetic_host,
        .platform_root_digest = crypto_hash.zero_digest,
    };
}

test "allocated sync resident state starts in canonical empty state" {
    var resident_state: ResidentState = undefined;
    resident_state.initializeAllocated();

    try std.testing.expect(!resident_state.has_persisted_state);
    try std.testing.expect(!resident_state.transport_cursor_loaded);
    try std.testing.expectEqual(@as(u64, 1), resident_state.next_state_tick);
    try std.testing.expectEqual(@as(usize, 0), resident_state.userRootCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.deviceCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.networkPolicyCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.workspacePolicyCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.replicaCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.conflictCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.databaseContractCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.overlayCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.outboundTransportFrameCount());
    try std.testing.expectEqual(@as(usize, 0), resident_state.inboundTransportFrameCount());
}

pub fn zeroWorkspacePolicy() WorkspacePolicy {
    return .{
        .workspace_id = 0,
        .owner = .{ .kind = .user, .serial = 0 },
        .offline_first = true,
        .personal_e2ee = true,
        .require_shared_access = false,
        .selective_prefix_count = 0,
        .selective_prefixes = [_][MAX_PREFIX_BYTES]u8{[_]u8{0} ** MAX_PREFIX_BYTES} ** MAX_SELECTIVE_PREFIXES,
        .selective_prefix_lens = [_]u8{0} ** MAX_SELECTIVE_PREFIXES,
        .device_to_device_policy_id = null,
        .relay_policy_id = null,
        .overlay_policy_id = null,
        .relay_domain_len = 0,
        .relay_domain = [_]u8{0} ** MAX_LABEL_BYTES,
    };
}

pub fn zeroOverlay() OverlayRecord {
    return .{
        .id = 0,
        .workspace_id = 0,
        .home_device = .{ .kind = .device, .serial = 0 },
        .service_identity_len = 0,
        .service_identity = [_]u8{0} ** MAX_LABEL_BYTES,
        .remote_access_enabled = false,
        .private_service_count = 0,
        .private_services = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_PRIVATE_SERVICES,
        .private_service_lens = [_]u8{0} ** MAX_PRIVATE_SERVICES,
    };
}

pub fn zeroReplicaEntry() ReplicaEntry {
    return .{
        .workspace_id = 0,
        .device_id = .{ .kind = .device, .serial = 0 },
        .workspace_generation = 0,
        .path_len = 0,
        .path = [_]u8{0} ** workspace.MAX_ENTRY_PATH_BYTES,
        .object_id = 0,
        .version_id = 0,
    };
}

pub fn zeroConflict() ConflictRecord {
    return .{
        .workspace_id = 0,
        .device_id = .{ .kind = .device, .serial = 0 },
        .object_id = 0,
        .path_len = 0,
        .path = [_]u8{0} ** workspace.MAX_ENTRY_PATH_BYTES,
        .local_version_id = 0,
        .remote_version_id = 0,
        .semantic = .mergeable_crdt,
    };
}

pub fn zeroDatabaseContract() DatabaseContract {
    return .{
        .id = 0,
        .workspace_id = 0,
        .bundle_id_len = 0,
        .bundle_id = [_]u8{0} ** MAX_LABEL_BYTES,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .signature = .{},
    };
}

pub fn copyTransportPath(destination: *[workspace.MAX_ENTRY_PATH_BYTES]u8, path: []const u8) Error!SyncPathLength {
    if (path.len > destination.len) return error.PathTooLong;
    @memset(destination[0..], 0);
    @memcpy(destination[0..path.len], path);
    return @intCast(path.len);
}

test "compact sync record metadata preserves exact path and label capacities" {
    const full_label = [_]u8{'l'} ** MAX_LABEL_BYTES;
    const full_path = [_]u8{'p'} ** workspace.MAX_ENTRY_PATH_BYTES;

    var policy = zeroWorkspacePolicy();
    policy.relay_domain_len = @intCast(try native_util.copyTextExact(&policy.relay_domain, &full_label));
    for (&policy.selective_prefixes, &policy.selective_prefix_lens) |*prefix, *prefix_len| {
        prefix_len.* = @intCast(try native_util.copyTextExact(prefix, full_path[0..MAX_PREFIX_BYTES]));
        policy.selective_prefix_count += 1;
    }
    try std.testing.expectEqual(@as(u8, MAX_SELECTIVE_PREFIXES), policy.selective_prefix_count);
    try std.testing.expectEqual(@as(usize, MAX_LABEL_BYTES), policy.relayDomainSlice().len);
    try std.testing.expect(policy.matchesPath(&full_path));

    var overlay = zeroOverlay();
    overlay.service_identity_len = @intCast(try native_util.copyTextExact(&overlay.service_identity, &full_label));
    for (&overlay.private_services, &overlay.private_service_lens) |*service, *service_len| {
        service_len.* = @intCast(try native_util.copyTextExact(service, &full_label));
        overlay.private_service_count += 1;
    }
    try std.testing.expectEqual(@as(u8, MAX_PRIVATE_SERVICES), overlay.private_service_count);
    try std.testing.expectEqual(@as(usize, MAX_LABEL_BYTES), overlay.serviceIdentitySlice().len);
    try std.testing.expect(overlay.hasPrivateService(&full_label));

    var replica = zeroReplicaEntry();
    replica.path_len = try copyTransportPath(&replica.path, &full_path);
    var conflict = zeroConflict();
    conflict.path_len = try copyTransportPath(&conflict.path, &full_path);
    var frame = TransportFrame{};
    frame.path_len = try copyTransportPath(&frame.path, &full_path);
    try std.testing.expectEqual(@as(usize, workspace.MAX_ENTRY_PATH_BYTES), replica.pathSlice().len);
    try std.testing.expectEqual(@as(usize, workspace.MAX_ENTRY_PATH_BYTES), conflict.pathSlice().len);
    try std.testing.expectEqual(@as(usize, workspace.MAX_ENTRY_PATH_BYTES), frame.pathSlice().len);
}
