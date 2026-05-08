const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const device_graph = @import("device_graph.zig");
const manifest = @import("../policy/manifest.zig");
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
pub const state_workspace_label = "system-sync";
pub const state_index_path = "state/index";
pub const state_chunk_prefix = "state/chunks/";
pub const state_magic = "ZGSYNC1";
pub const state_index_magic = "ZGSYNCI";
pub const state_version: u16 = 3;
pub const max_state_chunks: usize = workspace.MAX_WORKSPACE_ENTRIES - 1;
pub const max_state_chunk_bytes: usize = 64 * 1024;
pub const max_state_bytes: usize = max_state_chunks * max_state_chunk_bytes;
pub const state_signer = signing.SignerIdentity{
    .label = "zigos-sync-state",
    .seed = [_]u8{0xA7} ** 32,
};

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
    selective_prefix_count: usize,
    selective_prefixes: [MAX_SELECTIVE_PREFIXES][MAX_PREFIX_BYTES]u8,
    selective_prefix_lens: [MAX_SELECTIVE_PREFIXES]usize,
    device_to_device_policy_id: ?u64,
    relay_policy_id: ?u64,
    overlay_policy_id: ?u64,
    relay_domain_len: usize,
    relay_domain: [MAX_LABEL_BYTES]u8,

    pub fn relayDomainSlice(self: *const WorkspacePolicy) []const u8 {
        return self.relay_domain[0..self.relay_domain_len];
    }

    pub fn matchesPath(self: *const WorkspacePolicy, path: []const u8) bool {
        if (self.selective_prefix_count == 0) return true;
        var index: usize = 0;
        while (index < self.selective_prefix_count) : (index += 1) {
            const prefix = self.selective_prefixes[index][0..self.selective_prefix_lens[index]];
            if (std.mem.startsWith(u8, path, prefix)) return true;
        }
        return false;
    }
};

pub const OverlayRecord = struct {
    id: u64,
    workspace_id: u64,
    home_device: principal.PrincipalId,
    service_identity_len: usize,
    service_identity: [MAX_LABEL_BYTES]u8,
    remote_access_enabled: bool,
    private_service_count: usize,
    private_services: [MAX_PRIVATE_SERVICES][MAX_LABEL_BYTES]u8,
    private_service_lens: [MAX_PRIVATE_SERVICES]usize,

    pub fn serviceIdentitySlice(self: *const OverlayRecord) []const u8 {
        return self.service_identity[0..self.service_identity_len];
    }

    pub fn hasPrivateServices(self: *const OverlayRecord) bool {
        return self.private_service_count != 0;
    }

    pub fn hasPrivateService(self: *const OverlayRecord, label: []const u8) bool {
        var index: usize = 0;
        while (index < self.private_service_count) : (index += 1) {
            if (std.mem.eql(u8, self.private_services[index][0..self.private_service_lens[index]], label)) {
                return true;
            }
        }
        return false;
    }
};

pub const ReplicaEntry = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
    workspace_generation: u32,
    path_len: usize,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8,
    object_id: u64,
    version_id: u64,

    pub fn pathSlice(self: *const ReplicaEntry) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn pathHash(self: *const ReplicaEntry) u64 {
        return workspace.pathHash(self.pathSlice());
    }
};

pub const ConflictRecord = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
    object_id: u64,
    path_len: usize,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8,
    local_version_id: u64,
    remote_version_id: u64,
    semantic: SyncSemantic,

    pub fn pathSlice(self: *const ConflictRecord) []const u8 {
        return self.path[0..self.path_len];
    }
};

pub const DatabaseContract = struct {
    id: u64,
    workspace_id: u64,
    bundle_id_len: usize,
    bundle_id: [MAX_LABEL_BYTES]u8,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    signature: manifest.Signature = .{},

    pub fn bundleIdSlice(self: *const DatabaseContract) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn labelSlice(self: *const DatabaseContract) []const u8 {
        return self.label[0..self.label_len];
    }
};

pub const ReplicationSummary = struct {
    selected_entry_count: usize = 0,
    skipped_entry_count: usize = 0,
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

pub const Error = error{
    BundleIdTooLong,
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
    RemoteAccessDisabled,
    StateSigningFailed,
    StateTooLarge,
    PathTooLong,
    TooManyPrivateServices,
    TooManySelectivePrefixes,
    ServiceIdentityTooLong,
    TransportDenied,
    TransportQueueFull,
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

pub const PersistentState = struct {
    next_overlay_id: u64 = 1,
    next_contract_id: u64 = 1,
    graph: device_graph.Graph = device_graph.Graph.init(),
    network_policies: network_policy.Directory = network_policy.Directory.init(),
    workspace_policies: [MAX_WORKSPACE_POLICIES]WorkspacePolicySlot = [_]WorkspacePolicySlot{WorkspacePolicySlot{}} ** MAX_WORKSPACE_POLICIES,
    replica_entries: [MAX_REPLICA_ENTRIES]ReplicaSlot = [_]ReplicaSlot{ReplicaSlot{}} ** MAX_REPLICA_ENTRIES,
    conflicts: [MAX_CONFLICTS]ConflictSlot = [_]ConflictSlot{ConflictSlot{}} ** MAX_CONFLICTS,
    database_contracts: [MAX_DATABASE_CONTRACTS]DatabaseContractSlot = [_]DatabaseContractSlot{DatabaseContractSlot{}} ** MAX_DATABASE_CONTRACTS,
    overlays: [MAX_OVERLAYS]OverlaySlot = [_]OverlaySlot{OverlaySlot{}} ** MAX_OVERLAYS,

    pub fn reset(self: *PersistentState) void {
        self.next_overlay_id = 1;
        self.next_contract_id = 1;
        self.graph.reset();
        self.network_policies.reset();
        for (&self.workspace_policies) |*slot| {
            slot.* = .{};
        }
        for (&self.replica_entries) |*slot| {
            slot.* = .{};
        }
        for (&self.conflicts) |*slot| {
            slot.* = .{};
        }
        for (&self.database_contracts) |*slot| {
            slot.* = .{};
        }
        for (&self.overlays) |*slot| {
            slot.* = .{};
        }
    }
};

pub const ResidentState = struct {
    persisted_state: PersistentState = .{},
    has_persisted_state: bool = false,
    user_root_signers: [device_graph.MAX_USER_ROOTS][MAX_LABEL_BYTES]u8 =
        [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** device_graph.MAX_USER_ROOTS,
    device_signature_signers: [device_graph.MAX_DEVICES][4][MAX_LABEL_BYTES]u8 =
        [_][4][MAX_LABEL_BYTES]u8{[_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** 4} ** device_graph.MAX_DEVICES,
    database_contract_signers: [MAX_DATABASE_CONTRACTS][MAX_LABEL_BYTES]u8 =
        [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_DATABASE_CONTRACTS,
    next_state_tick: u64 = 1,

    pub fn resetForServiceInit(self: *ResidentState) void {
        self.persisted_state.reset();
        self.resetSignatureStorage();
    }

    pub fn resetPersistent(self: *ResidentState) void {
        self.persisted_state.reset();
        self.has_persisted_state = false;
        self.resetSignatureStorage();
        self.next_state_tick = 1;
    }

    pub fn markDirty(self: *ResidentState) void {
        self.has_persisted_state = true;
    }

    pub fn userRootCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.graph.user_roots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn deviceCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.graph.devices) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn networkPolicyCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.network_policies.policies) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn workspacePolicyCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.workspace_policies) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn replicaCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.replica_entries) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn conflictCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.conflicts) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn databaseContractCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.database_contracts) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn overlayCount(self: *const ResidentState) usize {
        var count: usize = 0;
        for (self.persisted_state.overlays) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn nextPersistedPolicyId(self: *const ResidentState) u64 {
        var next_id: u64 = 1;
        for (self.persisted_state.network_policies.policies) |slot| {
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
};

pub fn readOptionalU64(value: u64) ?u64 {
    return if (value == 0) null else value;
}

pub fn chunkPath(buffer: []u8, chunk_index: usize) Error![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{d}", .{ state_chunk_prefix, chunk_index }) catch error.StateTooLarge;
}

pub fn indexObjectId() u64 {
    return 0x5A_49_47_4F_53_53_59_01;
}

pub fn chunkObjectId(chunk_index: usize) u64 {
    return 0x5A_49_47_4F_53_53_59_10 + @as(u64, @intCast(chunk_index));
}

pub fn stateDigest(bytes: []const u8) [32]u8 {
    var hasher = crypto_hash.init();
    hasher.update(bytes);
    return crypto_hash.finalize(&hasher);
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
    };
}

pub fn zeroWorkspacePolicy() WorkspacePolicy {
    return .{
        .workspace_id = 0,
        .owner = .{ .kind = .user, .serial = 0 },
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefix_count = 0,
        .selective_prefixes = [_][MAX_PREFIX_BYTES]u8{[_]u8{0} ** MAX_PREFIX_BYTES} ** MAX_SELECTIVE_PREFIXES,
        .selective_prefix_lens = [_]usize{0} ** MAX_SELECTIVE_PREFIXES,
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
        .private_service_lens = [_]usize{0} ** MAX_PRIVATE_SERVICES,
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
