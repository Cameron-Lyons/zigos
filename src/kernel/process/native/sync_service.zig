const std = @import("std");
const crypto_hash = @import("crypto_hash.zig");
const device_graph = @import("device_graph.zig");
const manifest = @import("manifest.zig");
const native_util = @import("util.zig");
const network_policy = @import("network_policy.zig");
const object_store = @import("object_store.zig");
const principal = @import("principal.zig");
const signing = @import("signing.zig");
const storage_service = @import("storage_service.zig");
const workspace = @import("workspace.zig");
const copyText = native_util.copyText;

pub const MAX_WORKSPACE_POLICIES: usize = 8;
pub const MAX_SELECTIVE_PREFIXES: usize = 4;
pub const MAX_PREFIX_BYTES: usize = 48;
pub const MAX_REPLICA_ENTRIES: usize = 32;
pub const MAX_CONFLICTS: usize = 16;
pub const MAX_DATABASE_CONTRACTS: usize = 8;
pub const MAX_OVERLAYS: usize = 4;
pub const MAX_PRIVATE_SERVICES: usize = 4;
pub const MAX_LABEL_BYTES: usize = 48;
const state_workspace_label = "system-sync";
const state_index_path = "state/index";
const state_chunk_prefix = "state/chunks/";
const state_magic = "ZGSYNC1";
const state_index_magic = "ZGSYNCI";
const state_version: u16 = 2;
const max_state_chunks: usize = workspace.MAX_WORKSPACE_ENTRIES - 1;
const max_state_bytes: usize = max_state_chunks * object_store.MAX_PAYLOAD_BYTES;
const state_signer = signing.SignerIdentity{
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
};

pub const ReplicaEntry = struct {
    workspace_id: u64,
    device_id: principal.PrincipalId,
    path_len: usize,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8,
    object_id: u64,
    version_id: u64,

    pub fn pathSlice(self: *const ReplicaEntry) []const u8 {
        return self.path[0..self.path_len];
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
};

pub const Error = error{
    ConflictTableFull,
    CorruptState,
    DatabaseContractNotFound,
    DatabaseContractTableFull,
    DeviceNotTrusted,
    InvalidContractSignature,
    InvalidStateSignatureEncoding,
    OverlayNotFound,
    OverlayTableFull,
    ReplicaTableFull,
    StateSigningFailed,
    StateTooLarge,
    TooManyPrivateServices,
    TooManySelectivePrefixes,
    TransportDenied,
    UnsupportedStateVersion,
    WorkspacePolicyNotFound,
    WorkspacePolicyTableFull,
} || network_policy.Error || device_graph.Error || workspace.Error || object_store.Error;

const WorkspacePolicySlot = struct {
    in_use: bool = false,
    policy: WorkspacePolicy = zeroWorkspacePolicy(),
};

const ReplicaSlot = struct {
    in_use: bool = false,
    entry: ReplicaEntry = zeroReplicaEntry(),
};

const ConflictSlot = struct {
    in_use: bool = false,
    conflict: ConflictRecord = zeroConflict(),
};

const DatabaseContractSlot = struct {
    in_use: bool = false,
    contract: DatabaseContract = zeroDatabaseContract(),
};

const OverlaySlot = struct {
    in_use: bool = false,
    overlay: OverlayRecord = zeroOverlay(),
};

const PersistentState = struct {
    next_overlay_id: u64 = 1,
    next_contract_id: u64 = 1,
    graph: device_graph.Graph = device_graph.Graph.init(),
    network_policies: network_policy.Directory = network_policy.Directory.init(),
    workspace_policies: [MAX_WORKSPACE_POLICIES]WorkspacePolicySlot = [_]WorkspacePolicySlot{WorkspacePolicySlot{}} ** MAX_WORKSPACE_POLICIES,
    replica_entries: [MAX_REPLICA_ENTRIES]ReplicaSlot = [_]ReplicaSlot{ReplicaSlot{}} ** MAX_REPLICA_ENTRIES,
    conflicts: [MAX_CONFLICTS]ConflictSlot = [_]ConflictSlot{ConflictSlot{}} ** MAX_CONFLICTS,
    database_contracts: [MAX_DATABASE_CONTRACTS]DatabaseContractSlot = [_]DatabaseContractSlot{DatabaseContractSlot{}} ** MAX_DATABASE_CONTRACTS,
    overlays: [MAX_OVERLAYS]OverlaySlot = [_]OverlaySlot{OverlaySlot{}} ** MAX_OVERLAYS,

    fn reset(self: *PersistentState) void {
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

var persisted_state = PersistentState{};
var has_persisted_state = false;
var user_root_signers: [device_graph.MAX_USER_ROOTS][MAX_LABEL_BYTES]u8 =
    [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** device_graph.MAX_USER_ROOTS;
var device_signature_signers: [device_graph.MAX_DEVICES][4][MAX_LABEL_BYTES]u8 =
    [_][4][MAX_LABEL_BYTES]u8{[_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** 4} ** device_graph.MAX_DEVICES;
var database_contract_signers: [MAX_DATABASE_CONTRACTS][MAX_LABEL_BYTES]u8 =
    [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_DATABASE_CONTRACTS;
var next_state_tick: u64 = 1;

pub const Service = struct {
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    loaded_existing_state: bool = false,
    storage: ?*storage_service.Service = null,
    state_workspace_id: u64 = 0,
    state: *PersistentState,

    pub fn init(service_id: u64, task_id: u64, owner: principal.PrincipalId) Service {
        const loaded_existing_state = has_persisted_state;
        if (!has_persisted_state) {
            persisted_state.reset();
            resetSignatureStorage();
        }
        return .{
            .service_id = service_id,
            .task_id = task_id,
            .owner = owner,
            .loaded_existing_state = loaded_existing_state,
            .storage = null,
            .state_workspace_id = 0,
            .state = &persisted_state,
        };
    }

    pub fn initWithStorage(
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        storage: *storage_service.Service,
    ) Error!Service {
        const workspace_id = try ensureStateWorkspace(storage, owner);
        const loaded_existing_state = if (has_persisted_state)
            true
        else
            try loadStateFromStorage(storage, workspace_id);

        if (!loaded_existing_state) {
            persisted_state.reset();
            resetSignatureStorage();
        }

        return .{
            .service_id = service_id,
            .task_id = task_id,
            .owner = owner,
            .loaded_existing_state = loaded_existing_state,
            .storage = storage,
            .state_workspace_id = workspace_id,
            .state = &persisted_state,
        };
    }

    pub fn resetPersistentState() void {
        persisted_state.reset();
        has_persisted_state = false;
        resetSignatureStorage();
        next_state_tick = 1;
    }

    pub fn ensureUserRoot(
        self: *Service,
        user_principal: principal.PrincipalId,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) Error!*device_graph.UserRootRecord {
        const root = try self.state.graph.ensureUserRoot(user_principal, label, identity);
        markResidentStateDirty();
        return root;
    }

    pub fn enrollTrustedDevice(
        self: *Service,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        label: []const u8,
        authorizer: signing.SignerIdentity,
        device_identity: signing.SignerIdentity,
        tick: u64,
    ) Error!*device_graph.DeviceRecord {
        const record = try self.state.graph.enrollDevice(user_principal, device_principal, label, authorizer, device_identity, tick);
        markResidentStateDirty();
        return record;
    }

    pub fn rotateDeviceKey(
        self: *Service,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        next_device_identity: signing.SignerIdentity,
        tick: u64,
    ) Error!*device_graph.DeviceRecord {
        const record = try self.state.graph.rotateDeviceKey(user_principal, device_principal, authorizer, next_device_identity, tick);
        markResidentStateDirty();
        return record;
    }

    pub fn revokeTrustedDevice(
        self: *Service,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        tick: u64,
    ) Error!void {
        try self.state.graph.revokeDevice(user_principal, device_principal, authorizer, tick);
        markResidentStateDirty();
    }

    pub fn findDeviceRecord(self: *const Service, device_id: principal.PrincipalId) ?*const device_graph.DeviceRecord {
        return self.state.graph.findDeviceConst(device_id);
    }

    pub fn createNetworkPolicy(self: *Service, request: network_policy.CreateRequest) Error!*network_policy.PolicyRecord {
        const record = try self.state.network_policies.create(request);
        markResidentStateDirty();
        return record;
    }

    pub fn evaluateNetworkPolicy(
        self: *Service,
        policy_id: u64,
        destination: network_policy.Destination,
    ) Error!network_policy.Decision {
        return self.state.network_policies.authorize(policy_id, destination);
    }

    pub fn configureWorkspacePolicy(
        self: *Service,
        request: WorkspacePolicyRequest,
    ) Error!*WorkspacePolicy {
        if (request.selective_prefixes.len > MAX_SELECTIVE_PREFIXES) return error.TooManySelectivePrefixes;

        const slot = self.lookupWorkspacePolicySlot(request.workspace_id) orelse self.allocateWorkspacePolicy() orelse return error.WorkspacePolicyTableFull;
        slot.in_use = true;
        slot.policy = zeroWorkspacePolicy();
        slot.policy.workspace_id = request.workspace_id;
        slot.policy.owner = request.owner;
        slot.policy.offline_first = request.offline_first;
        slot.policy.personal_e2ee = request.personal_e2ee;
        slot.policy.device_to_device_policy_id = request.device_to_device_policy_id;
        slot.policy.relay_policy_id = request.relay_policy_id;
        slot.policy.overlay_policy_id = request.overlay_policy_id;
        slot.policy.relay_domain_len = copyText(&slot.policy.relay_domain, request.relay_domain);

        for (request.selective_prefixes, 0..) |prefix, index| {
            slot.policy.selective_prefix_lens[index] = copyText(&slot.policy.selective_prefixes[index], prefix);
            slot.policy.selective_prefix_count += 1;
        }

        try self.checkpoint();
        return &slot.policy;
    }

    pub fn findWorkspacePolicy(self: *Service, workspace_id: u64) ?*WorkspacePolicy {
        const slot = self.lookupWorkspacePolicySlot(workspace_id) orelse return null;
        return &slot.policy;
    }

    pub fn configureOverlay(
        self: *Service,
        workspace_id: u64,
        home_device: principal.PrincipalId,
        service_identity: []const u8,
        remote_access_enabled: bool,
    ) Error!*OverlayRecord {
        const slot = self.lookupOverlaySlot(workspace_id) orelse self.allocateOverlay() orelse return error.OverlayTableFull;
        slot.in_use = true;
        if (slot.overlay.id == 0) {
            slot.overlay = zeroOverlay();
            slot.overlay.id = self.nextOverlayId();
            slot.overlay.workspace_id = workspace_id;
        }
        slot.overlay.home_device = home_device;
        slot.overlay.service_identity_len = copyText(&slot.overlay.service_identity, service_identity);
        slot.overlay.remote_access_enabled = remote_access_enabled;
        try self.checkpoint();
        return &slot.overlay;
    }

    pub fn publishPrivateService(
        self: *Service,
        workspace_id: u64,
        label: []const u8,
    ) Error!*OverlayRecord {
        const overlay = self.findOverlay(workspace_id) orelse return error.OverlayNotFound;
        var index: usize = 0;
        while (index < overlay.private_service_count) : (index += 1) {
            if (std.mem.eql(u8, overlay.private_services[index][0..overlay.private_service_lens[index]], label)) {
                return overlay;
            }
        }
        if (overlay.private_service_count >= MAX_PRIVATE_SERVICES) return error.TooManyPrivateServices;
        const slot_index = overlay.private_service_count;
        overlay.private_service_lens[slot_index] = copyText(&overlay.private_services[slot_index], label);
        overlay.private_service_count += 1;
        try self.checkpoint();
        return overlay;
    }

    pub fn findOverlay(self: *Service, workspace_id: u64) ?*OverlayRecord {
        const slot = self.lookupOverlaySlot(workspace_id) orelse return null;
        return &slot.overlay;
    }

    pub fn setReplicaVersion(
        self: *Service,
        workspace_id: u64,
        device_id: principal.PrincipalId,
        path: []const u8,
        object_id: u64,
        version_id: u64,
    ) Error!void {
        const slot = self.lookupReplicaSlot(workspace_id, device_id, path) orelse self.allocateReplicaSlot() orelse return error.ReplicaTableFull;
        slot.in_use = true;
        slot.entry.workspace_id = workspace_id;
        slot.entry.device_id = device_id;
        slot.entry.path_len = copyText(&slot.entry.path, path);
        slot.entry.object_id = object_id;
        slot.entry.version_id = version_id;
        markResidentStateDirty();
    }

    pub fn replicaVersion(
        self: *const Service,
        workspace_id: u64,
        device_id: principal.PrincipalId,
        path: []const u8,
    ) ?u64 {
        for (&self.state.replica_entries) |*slot| {
            if (!slot.in_use) continue;
            if (slot.entry.workspace_id != workspace_id) continue;
            if (!slot.entry.device_id.eql(device_id)) continue;
            if (!std.mem.eql(u8, slot.entry.pathSlice(), path)) continue;
            return slot.entry.version_id;
        }
        return null;
    }

    pub fn registerDatabaseContract(
        self: *Service,
        workspace_id: u64,
        bundle_id: []const u8,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) Error!*DatabaseContract {
        var message_buffer: [160]u8 = undefined;
        const message = databaseContractMessage(&message_buffer, workspace_id, bundle_id, label) catch return error.InvalidContractSignature;
        const signature = signing.sign(identity, message) catch return error.InvalidContractSignature;
        if (!signing.verify(signature, message)) return error.InvalidContractSignature;

        if (self.findEquivalentDatabaseContract(workspace_id, bundle_id, label, signature)) |existing| {
            return existing;
        }

        const slot = self.allocateDatabaseContract() orelse return error.DatabaseContractTableFull;
        slot.in_use = true;
        slot.contract = zeroDatabaseContract();
        slot.contract.id = self.nextDatabaseContractId();
        slot.contract.workspace_id = workspace_id;
        slot.contract.bundle_id_len = copyText(&slot.contract.bundle_id, bundle_id);
        slot.contract.label_len = copyText(&slot.contract.label, label);
        slot.contract.signature = signature;

        try self.checkpoint();
        return &slot.contract;
    }

    pub fn replicateWorkspace(
        self: *Service,
        store: *const storage_service.Service,
        workspace_id: u64,
        from_device: principal.PrincipalId,
        to_device: principal.PrincipalId,
        transport: TransportMode,
    ) Error!ReplicationSummary {
        try self.ensureTrustedDevices(from_device, to_device);
        const policy = self.findWorkspacePolicy(workspace_id) orelse return error.WorkspacePolicyNotFound;
        var summary = ReplicationSummary{
            .personal_e2ee = policy.personal_e2ee,
            .offline_first = policy.offline_first,
        };

        try self.authorizeTransport(policy, transport, &summary);
        try self.evaluateOverlay(policy, workspace_id, &summary);

        const entries = try store.entries(workspace_id);
        for (entries) |entry| {
            if (!policy.matchesPath(entry.pathSlice())) {
                summary.skipped_entry_count += 1;
                continue;
            }
            summary.selected_entry_count += 1;

            const semantic = classifyEntry(entry);
            const remote_version_id = self.replicaVersion(workspace_id, to_device, entry.pathSlice()) orelse 0;
            if (remote_version_id != 0 and remote_version_id != entry.version_id) {
                try self.recordConflict(
                    workspace_id,
                    to_device,
                    entry.object_id,
                    entry.pathSlice(),
                    entry.version_id,
                    remote_version_id,
                    semantic,
                );
            }

            switch (semantic) {
                .mergeable_crdt => summary.merged_count += 1,
                .chunked_snapshot => summary.snapshot_count += 1,
                else => {},
            }
            try self.setReplicaVersion(workspace_id, to_device, entry.pathSlice(), entry.object_id, entry.version_id);
        }
        summary.conflict_count = self.countConflictsFor(workspace_id, to_device);
        if (summary.selected_entry_count != 0 or summary.conflict_count != 0) {
            try self.checkpoint();
        }
        return summary;
    }

    pub fn transferSecretObject(
        self: *Service,
        store: *object_store.Store,
        workspace_id: u64,
        object_id: u64,
        from_device: principal.PrincipalId,
        to_device: principal.PrincipalId,
        transport: TransportMode,
    ) Error!bool {
        try self.ensureTrustedDevices(from_device, to_device);
        const policy = self.findWorkspacePolicy(workspace_id) orelse return error.WorkspacePolicyNotFound;
        if (!policy.personal_e2ee) return error.TransportDenied;
        try self.authorizeTransport(policy, transport, null);

        const object_record = store.object(object_id) orelse return error.ObjectNotFound;
        if (object_record.object_type != .secret) return error.TypeMismatch;
        return true;
    }

    pub fn replicateDatabaseContract(
        self: *Service,
        contract_id: u64,
        workspace_id: u64,
        from_device: principal.PrincipalId,
        to_device: principal.PrincipalId,
        transport: TransportMode,
    ) Error!bool {
        try self.ensureTrustedDevices(from_device, to_device);
        const policy = self.findWorkspacePolicy(workspace_id) orelse return error.WorkspacePolicyNotFound;
        try self.authorizeTransport(policy, transport, null);

        const record = self.findDatabaseContract(contract_id) orelse return error.DatabaseContractNotFound;
        var message_buffer: [160]u8 = undefined;
        const message = databaseContractMessage(
            &message_buffer,
            record.workspace_id,
            record.bundleIdSlice(),
            record.labelSlice(),
        ) catch return error.InvalidContractSignature;
        if (!signing.verify(record.signature, message)) return error.InvalidContractSignature;
        return true;
    }

    pub fn repairWorkspaceMetadata(
        self: *Service,
        store: *const storage_service.Service,
        workspace_id: u64,
        device_id: principal.PrincipalId,
    ) Error!bool {
        if (!self.isTrustedDevice(device_id)) return error.DeviceNotTrusted;
        const policy = self.findWorkspacePolicy(workspace_id) orelse return error.WorkspacePolicyNotFound;
        var repaired = try self.clearConflictsFor(workspace_id, device_id);
        const entries = try store.entries(workspace_id);
        for (entries) |entry| {
            if (!policy.matchesPath(entry.pathSlice())) continue;
            try self.setReplicaVersion(workspace_id, device_id, entry.pathSlice(), entry.object_id, entry.version_id);
            repaired = true;
        }
        if (repaired) try self.checkpoint();
        return repaired;
    }

    pub fn trustedDeviceCount(self: *const Service) usize {
        return self.state.graph.trustedDeviceCount();
    }

    pub fn findConflict(
        self: *Service,
        workspace_id: u64,
        device_id: principal.PrincipalId,
        path: []const u8,
    ) ?*ConflictRecord {
        for (&self.state.conflicts) |*slot| {
            if (!slot.in_use) continue;
            if (slot.conflict.workspace_id != workspace_id) continue;
            if (!slot.conflict.device_id.eql(device_id)) continue;
            if (!std.mem.eql(u8, slot.conflict.pathSlice(), path)) continue;
            return &slot.conflict;
        }
        return null;
    }

    pub fn isTrustedDevice(self: *const Service, device_id: principal.PrincipalId) bool {
        return self.state.graph.isTrusted(device_id);
    }

    fn checkpoint(self: *const Service) Error!void {
        if (self.storage) |storage| {
            try persistStateToStorage(storage, self.state_workspace_id);
        }
        has_persisted_state = true;
    }

    fn authorizeTransport(
        self: *Service,
        policy: *const WorkspacePolicy,
        transport: TransportMode,
        summary: ?*ReplicationSummary,
    ) Error!void {
        switch (transport) {
            .device_to_device => {
                const policy_id = policy.device_to_device_policy_id orelse return error.TransportDenied;
                const decision = try self.evaluateNetworkPolicy(policy_id, .local_network);
                if (!decision.allowed) return error.TransportDenied;
                if (summary) |value| value.used_device_to_device = true;
            },
            .relay_assisted => {
                const policy_id = policy.relay_policy_id orelse return error.TransportDenied;
                const decision = try self.evaluateNetworkPolicy(policy_id, .{ .domain = policy.relayDomainSlice() });
                if (!decision.allowed) return error.TransportDenied;
                if (summary) |value| value.used_relay = true;
            },
        }
    }

    fn evaluateOverlay(
        self: *Service,
        policy: *const WorkspacePolicy,
        workspace_id: u64,
        summary: *ReplicationSummary,
    ) Error!void {
        const overlay_policy_id = policy.overlay_policy_id orelse return;
        const overlay = self.findOverlay(workspace_id) orelse return;
        const decision = try self.evaluateNetworkPolicy(overlay_policy_id, .{ .service_identity = overlay.serviceIdentitySlice() });
        if (!decision.allowed) return;
        summary.overlay_ready = true;
        summary.remote_access_ready = overlay.remote_access_enabled;
        summary.private_service_published = overlay.hasPrivateServices();
    }

    fn ensureTrustedDevices(self: *Service, from_device: principal.PrincipalId, to_device: principal.PrincipalId) Error!void {
        if (!self.state.graph.isTrusted(from_device) or !self.state.graph.isTrusted(to_device)) {
            return error.DeviceNotTrusted;
        }
    }

    fn recordConflict(
        self: *Service,
        workspace_id: u64,
        device_id: principal.PrincipalId,
        object_id: u64,
        path: []const u8,
        local_version_id: u64,
        remote_version_id: u64,
        semantic: SyncSemantic,
    ) Error!void {
        const slot = self.allocateConflict() orelse return error.ConflictTableFull;
        slot.in_use = true;
        slot.conflict = zeroConflict();
        slot.conflict.workspace_id = workspace_id;
        slot.conflict.device_id = device_id;
        slot.conflict.object_id = object_id;
        slot.conflict.path_len = copyText(&slot.conflict.path, path);
        slot.conflict.local_version_id = local_version_id;
        slot.conflict.remote_version_id = remote_version_id;
        slot.conflict.semantic = semantic;
        markResidentStateDirty();
    }

    fn countConflictsFor(self: *const Service, workspace_id: u64, device_id: principal.PrincipalId) usize {
        var count: usize = 0;
        for (self.state.conflicts) |slot| {
            if (!slot.in_use) continue;
            if (slot.conflict.workspace_id != workspace_id) continue;
            if (!slot.conflict.device_id.eql(device_id)) continue;
            count += 1;
        }
        return count;
    }

    fn clearConflictsFor(self: *Service, workspace_id: u64, device_id: principal.PrincipalId) Error!bool {
        var cleared = false;
        for (&self.state.conflicts) |*slot| {
            if (!slot.in_use) continue;
            if (slot.conflict.workspace_id != workspace_id) continue;
            if (!slot.conflict.device_id.eql(device_id)) continue;
            slot.* = .{};
            cleared = true;
        }
        if (cleared) markResidentStateDirty();
        return cleared;
    }

    fn findDatabaseContract(self: *Service, contract_id: u64) ?*DatabaseContract {
        for (&self.state.database_contracts) |*slot| {
            if (slot.in_use and slot.contract.id == contract_id) return &slot.contract;
        }
        return null;
    }

    fn findEquivalentDatabaseContract(
        self: *Service,
        workspace_id: u64,
        bundle_id: []const u8,
        label: []const u8,
        signature: manifest.Signature,
    ) ?*DatabaseContract {
        for (&self.state.database_contracts) |*slot| {
            if (!slot.in_use) continue;
            if (slot.contract.workspace_id != workspace_id) continue;
            if (!std.mem.eql(u8, slot.contract.bundleIdSlice(), bundle_id)) continue;
            if (!std.mem.eql(u8, slot.contract.labelSlice(), label)) continue;
            if (!signatureEql(slot.contract.signature, signature)) continue;
            return &slot.contract;
        }
        return null;
    }

    fn lookupWorkspacePolicySlot(self: *Service, workspace_id: u64) ?*WorkspacePolicySlot {
        for (&self.state.workspace_policies) |*slot| {
            if (slot.in_use and slot.policy.workspace_id == workspace_id) return slot;
        }
        return null;
    }

    fn allocateWorkspacePolicy(self: *Service) ?*WorkspacePolicySlot {
        for (&self.state.workspace_policies) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }

    fn lookupOverlaySlot(self: *Service, workspace_id: u64) ?*OverlaySlot {
        for (&self.state.overlays) |*slot| {
            if (slot.in_use and slot.overlay.workspace_id == workspace_id) return slot;
        }
        return null;
    }

    fn allocateOverlay(self: *Service) ?*OverlaySlot {
        for (&self.state.overlays) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }

    fn nextOverlayId(self: *Service) u64 {
        defer self.state.next_overlay_id += 1;
        return self.state.next_overlay_id;
    }

    fn lookupReplicaSlot(
        self: *Service,
        workspace_id: u64,
        device_id: principal.PrincipalId,
        path: []const u8,
    ) ?*ReplicaSlot {
        for (&self.state.replica_entries) |*slot| {
            if (!slot.in_use) continue;
            if (slot.entry.workspace_id != workspace_id) continue;
            if (!slot.entry.device_id.eql(device_id)) continue;
            if (!std.mem.eql(u8, slot.entry.pathSlice(), path)) continue;
            return slot;
        }
        return null;
    }

    fn allocateReplicaSlot(self: *Service) ?*ReplicaSlot {
        for (&self.state.replica_entries) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }

    fn allocateConflict(self: *Service) ?*ConflictSlot {
        for (&self.state.conflicts) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }

    fn allocateDatabaseContract(self: *Service) ?*DatabaseContractSlot {
        for (&self.state.database_contracts) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }

    fn nextDatabaseContractId(self: *Service) u64 {
        defer self.state.next_contract_id += 1;
        return self.state.next_contract_id;
    }
};

const CursorWriter = struct {
    buffer: []u8,
    offset: usize = 0,

    fn writeByte(self: *CursorWriter, value: u8) Error!void {
        if (self.offset >= self.buffer.len) return error.StateTooLarge;
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    fn writeBytes(self: *CursorWriter, bytes: []const u8) Error!void {
        if (self.offset + bytes.len > self.buffer.len) return error.StateTooLarge;
        @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn writeU16(self: *CursorWriter, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU32(self: *CursorWriter, value: u32) Error!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU64(self: *CursorWriter, value: u64) Error!void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }
};

const CursorReader = struct {
    buffer: []const u8,
    offset: usize = 0,

    fn readByte(self: *CursorReader) Error!u8 {
        if (self.offset >= self.buffer.len) return error.CorruptState;
        const value = self.buffer[self.offset];
        self.offset += 1;
        return value;
    }

    fn readBytes(self: *CursorReader, dest: []u8) Error!void {
        if (self.offset + dest.len > self.buffer.len) return error.CorruptState;
        @memcpy(dest, self.buffer[self.offset .. self.offset + dest.len]);
        self.offset += dest.len;
    }

    fn readU16(self: *CursorReader) Error!u16 {
        var bytes: [2]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u16, &bytes, .little);
    }

    fn readU32(self: *CursorReader) Error!u32 {
        var bytes: [4]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u32, &bytes, .little);
    }

    fn readU64(self: *CursorReader) Error!u64 {
        var bytes: [8]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }
};

const StateIndex = struct {
    total_len: usize,
    chunk_count: usize,
    digest: [32]u8,
};

fn ensureStateWorkspace(storage: *storage_service.Service, owner: principal.PrincipalId) Error!u64 {
    const existing = storage.findWorkspace(owner, state_workspace_label) orelse try storage.createWorkspace(.{
        .owner = owner,
        .label = state_workspace_label,
    });
    return existing.id;
}

fn loadStateFromStorage(storage: *storage_service.Service, workspace_id: u64) Error!bool {
    const index_entry = storage.resolve(workspace_id, state_index_path) catch |err| switch (err) {
        error.EntryNotFound => return false,
        else => return err,
    };
    const index_version = storage.store.version(index_entry.version_id) orelse return error.CorruptState;
    const index = try decodeStateIndex(index_version.payloadSlice());
    if (index.chunk_count == 0 or index.chunk_count > max_state_chunks) return error.CorruptState;
    if (index.total_len == 0 or index.total_len > max_state_bytes) return error.CorruptState;

    var assembled: [max_state_bytes]u8 = undefined;
    var offset: usize = 0;
    var chunk_index: usize = 0;
    while (chunk_index < index.chunk_count) : (chunk_index += 1) {
        var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
        const path = try chunkPath(path_buffer[0..], chunk_index);
        const chunk_entry = storage.resolve(workspace_id, path) catch |err| switch (err) {
            error.EntryNotFound => return error.CorruptState,
            else => return err,
        };
        const chunk_version = storage.store.version(chunk_entry.version_id) orelse return error.CorruptState;
        const payload = chunk_version.payloadSlice();
        if (offset + payload.len > index.total_len) return error.CorruptState;
        @memcpy(assembled[offset .. offset + payload.len], payload);
        offset += payload.len;
    }
    if (offset != index.total_len) return error.CorruptState;
    if (!std.mem.eql(u8, &index.digest, &stateDigest(assembled[0..offset]))) return error.CorruptState;

    try deserializeState(assembled[0..offset]);
    has_persisted_state = true;
    return true;
}

fn persistStateToStorage(storage: *storage_service.Service, workspace_id: u64) Error!void {
    var encoded: [max_state_bytes]u8 = undefined;
    const encoded_len = try serializeState(encoded[0..]);
    const chunk_count = @divFloor(encoded_len + object_store.MAX_PAYLOAD_BYTES - 1, object_store.MAX_PAYLOAD_BYTES);
    if (chunk_count == 0 or chunk_count > max_state_chunks) return error.StateTooLarge;

    const tick = nextPersistTick();
    try storage.beginTransaction(workspace_id);

    var chunk_index: usize = 0;
    while (chunk_index < chunk_count) : (chunk_index += 1) {
        const start = chunk_index * object_store.MAX_PAYLOAD_BYTES;
        const end = @min(start + object_store.MAX_PAYLOAD_BYTES, encoded_len);
        const payload = encoded[start..end];
        var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
        const path = try chunkPath(path_buffer[0..], chunk_index);
        const existing_entry = storage.resolve(workspace_id, path) catch |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };
        const result = try storage.putVersion(.{
            .preferred_object_id = chunkObjectId(chunk_index),
            .object_type = .blob,
            .payload = payload,
            .metadata = object_store.signMetadata(
                state_signer,
                path,
                "application/zigos-sync-chunk",
                .blob,
                payload,
                tick,
            ) catch return error.StateSigningFailed,
            .parent_version_id = if (existing_entry) |entry| entry.version_id else null,
        });
        try storage.stagePut(workspace_id, path, result.object_id, result.version_id, .blob);
    }

    chunk_index = chunk_count;
    while (chunk_index < max_state_chunks) : (chunk_index += 1) {
        var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
        const path = try chunkPath(path_buffer[0..], chunk_index);
        storage.stageDelete(workspace_id, path) catch |err| switch (err) {
            error.EntryNotFound => {},
            else => return err,
        };
    }

    var index_payload: [object_store.MAX_PAYLOAD_BYTES]u8 = undefined;
    const index_bytes = try encodeStateIndex(
        index_payload[0..],
        encoded_len,
        chunk_count,
        stateDigest(encoded[0..encoded_len]),
    );
    const existing_index = storage.resolve(workspace_id, state_index_path) catch |err| switch (err) {
        error.EntryNotFound => null,
        else => return err,
    };
    const index_result = try storage.putVersion(.{
        .preferred_object_id = indexObjectId(),
        .object_type = .document,
        .payload = index_bytes,
        .metadata = object_store.signMetadata(
            state_signer,
            state_index_path,
            "application/zigos-sync-index",
            .document,
            index_bytes,
            tick,
        ) catch return error.StateSigningFailed,
        .parent_version_id = if (existing_index) |entry| entry.version_id else null,
    });
    try storage.stagePut(workspace_id, state_index_path, index_result.object_id, index_result.version_id, .document);
    _ = try storage.commit(workspace_id, tick);
}

fn serializeState(buffer: []u8) Error!usize {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(state_magic);
    try writer.writeU16(state_version);
    try writer.writeU64(persisted_state.next_overlay_id);
    try writer.writeU64(persisted_state.next_contract_id);
    try writer.writeU16(@intCast(userRootCount()));
    try writer.writeU16(@intCast(deviceCount()));
    try writer.writeU16(@intCast(networkPolicyCount()));
    try writer.writeU16(@intCast(workspacePolicyCount()));
    try writer.writeU16(@intCast(replicaCount()));
    try writer.writeU16(@intCast(conflictCount()));
    try writer.writeU16(@intCast(databaseContractCount()));
    try writer.writeU16(@intCast(overlayCount()));

    for (persisted_state.graph.user_roots) |slot| {
        if (!slot.in_use) continue;
        try writePrincipal(&writer, slot.root.principal_id);
        try writeText(&writer, slot.root.labelSlice());
        try writeSignature(&writer, slot.root.root_signature);
    }
    for (persisted_state.graph.devices) |slot| {
        if (!slot.in_use) continue;
        try writePrincipal(&writer, slot.device.principal_id);
        try writePrincipal(&writer, slot.device.owner);
        try writeText(&writer, slot.device.labelSlice());
        try writer.writeU64(slot.device.overlay_id);
        try writer.writeByte(@intFromEnum(slot.device.status));
        try writer.writeU32(slot.device.trust_generation);
        try writer.writeU32(slot.device.key_rotation_generation);
        try writeSignature(&writer, slot.device.device_signature);
        try writeSignature(&writer, slot.device.enrollment_signature);
        try writeSignature(&writer, slot.device.rotation_signature);
        try writeSignature(&writer, slot.device.revocation_signature);
        try writer.writeU64(slot.device.last_rotated_at_ticks);
        try writer.writeU64(slot.device.revoked_at_ticks);
    }
    for (persisted_state.network_policies.policies) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.policy.id);
        try writePrincipal(&writer, slot.policy.owner);
        try writer.writeU64(slot.policy.workspace_id orelse 0);
        try writeText(&writer, slot.policy.labelSlice());
        try writer.writeByte(@intFromEnum(slot.policy.mode));
        try writeText(&writer, slot.policy.targetSlice());
        try writer.writeByte(@intFromBool(slot.policy.explicit_internet_grant));
        try writer.writeByte(@intFromBool(slot.policy.require_remote_attestation));
        try writer.writeByte(@intFromBool(slot.policy.pinned_root_digest_present));
        if (slot.policy.pinned_root_digest_present) {
            try writer.writeBytes(&slot.policy.pinned_root_digest);
        }
    }
    for (persisted_state.workspace_policies) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.policy.workspace_id);
        try writePrincipal(&writer, slot.policy.owner);
        try writer.writeByte(@intFromBool(slot.policy.offline_first));
        try writer.writeByte(@intFromBool(slot.policy.personal_e2ee));
        try writer.writeU64(slot.policy.device_to_device_policy_id orelse 0);
        try writer.writeU64(slot.policy.relay_policy_id orelse 0);
        try writer.writeU64(slot.policy.overlay_policy_id orelse 0);
        try writeText(&writer, slot.policy.relayDomainSlice());
        try writer.writeU16(@intCast(slot.policy.selective_prefix_count));
        var prefix_index: usize = 0;
        while (prefix_index < slot.policy.selective_prefix_count) : (prefix_index += 1) {
            const prefix = slot.policy.selective_prefixes[prefix_index][0..slot.policy.selective_prefix_lens[prefix_index]];
            try writeText(&writer, prefix);
        }
    }
    for (persisted_state.replica_entries) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.entry.workspace_id);
        try writePrincipal(&writer, slot.entry.device_id);
        try writeText(&writer, slot.entry.pathSlice());
        try writer.writeU64(slot.entry.object_id);
        try writer.writeU64(slot.entry.version_id);
    }
    for (persisted_state.conflicts) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.conflict.workspace_id);
        try writePrincipal(&writer, slot.conflict.device_id);
        try writer.writeU64(slot.conflict.object_id);
        try writeText(&writer, slot.conflict.pathSlice());
        try writer.writeU64(slot.conflict.local_version_id);
        try writer.writeU64(slot.conflict.remote_version_id);
        try writer.writeByte(@intFromEnum(slot.conflict.semantic));
    }
    for (persisted_state.database_contracts) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.contract.id);
        try writer.writeU64(slot.contract.workspace_id);
        try writeText(&writer, slot.contract.bundleIdSlice());
        try writeText(&writer, slot.contract.labelSlice());
        try writeSignature(&writer, slot.contract.signature);
    }
    for (persisted_state.overlays) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.overlay.id);
        try writer.writeU64(slot.overlay.workspace_id);
        try writePrincipal(&writer, slot.overlay.home_device);
        try writeText(&writer, slot.overlay.serviceIdentitySlice());
        try writer.writeByte(@intFromBool(slot.overlay.remote_access_enabled));
        try writer.writeU16(@intCast(slot.overlay.private_service_count));
        var service_index: usize = 0;
        while (service_index < slot.overlay.private_service_count) : (service_index += 1) {
            const label = slot.overlay.private_services[service_index][0..slot.overlay.private_service_lens[service_index]];
            try writeText(&writer, label);
        }
    }

    return writer.offset;
}

fn deserializeState(payload: []const u8) Error!void {
    persisted_state.reset();
    resetSignatureStorage();

    var reader = CursorReader{ .buffer = payload };
    var magic_buffer: [state_magic.len]u8 = undefined;
    try reader.readBytes(&magic_buffer);
    if (!std.mem.eql(u8, &magic_buffer, state_magic)) return error.CorruptState;
    if ((try reader.readU16()) != state_version) return error.UnsupportedStateVersion;

    persisted_state.next_overlay_id = try reader.readU64();
    persisted_state.next_contract_id = try reader.readU64();
    const root_count = try reader.readU16();
    const device_count_value = try reader.readU16();
    const network_policy_count = try reader.readU16();
    const workspace_policy_count = try reader.readU16();
    const replica_count_value = try reader.readU16();
    const conflict_count_value = try reader.readU16();
    const contract_count = try reader.readU16();
    const overlay_count_value = try reader.readU16();

    if (root_count > device_graph.MAX_USER_ROOTS or
        device_count_value > device_graph.MAX_DEVICES or
        network_policy_count > network_policy.MAX_POLICIES or
        workspace_policy_count > MAX_WORKSPACE_POLICIES or
        replica_count_value > MAX_REPLICA_ENTRIES or
        conflict_count_value > MAX_CONFLICTS or
        contract_count > MAX_DATABASE_CONTRACTS or
        overlay_count_value > MAX_OVERLAYS)
    {
        return error.CorruptState;
    }

    var index: usize = 0;
    while (index < root_count) : (index += 1) {
        persisted_state.graph.user_roots[index].in_use = true;
        persisted_state.graph.user_roots[index].root = .{
            .principal_id = try readPrincipal(&reader),
            .label_len = 0,
            .label = [_]u8{0} ** device_graph.MAX_LABEL_BYTES,
            .root_signature = .{},
        };
        try readTextInto(&reader, &persisted_state.graph.user_roots[index].root.label, &persisted_state.graph.user_roots[index].root.label_len);
        persisted_state.graph.user_roots[index].root.root_signature = try readSignature(&reader, &user_root_signers[index]);
    }

    index = 0;
    while (index < device_count_value) : (index += 1) {
        persisted_state.graph.devices[index].in_use = true;
        persisted_state.graph.devices[index].device = zeroDeviceGraphRecord();
        persisted_state.graph.devices[index].device.principal_id = try readPrincipal(&reader);
        persisted_state.graph.devices[index].device.owner = try readPrincipal(&reader);
        try readTextInto(&reader, &persisted_state.graph.devices[index].device.label, &persisted_state.graph.devices[index].device.label_len);
        persisted_state.graph.devices[index].device.overlay_id = try reader.readU64();
        persisted_state.graph.devices[index].device.status = try parseDeviceStatus(try reader.readByte());
        persisted_state.graph.devices[index].device.trust_generation = try reader.readU32();
        persisted_state.graph.devices[index].device.key_rotation_generation = try reader.readU32();
        persisted_state.graph.devices[index].device.device_signature = try readSignature(&reader, &device_signature_signers[index][0]);
        persisted_state.graph.devices[index].device.enrollment_signature = try readSignature(&reader, &device_signature_signers[index][1]);
        persisted_state.graph.devices[index].device.rotation_signature = try readSignature(&reader, &device_signature_signers[index][2]);
        persisted_state.graph.devices[index].device.revocation_signature = try readSignature(&reader, &device_signature_signers[index][3]);
        persisted_state.graph.devices[index].device.last_rotated_at_ticks = try reader.readU64();
        persisted_state.graph.devices[index].device.revoked_at_ticks = try reader.readU64();
    }

    index = 0;
    while (index < network_policy_count) : (index += 1) {
        persisted_state.network_policies.policies[index].in_use = true;
        persisted_state.network_policies.policies[index].policy = .{
            .id = try reader.readU64(),
            .owner = try readPrincipal(&reader),
            .workspace_id = null,
            .label_len = 0,
            .label = [_]u8{0} ** network_policy.MAX_LABEL_BYTES,
            .mode = .none,
            .target_len = 0,
            .target = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
            .explicit_internet_grant = false,
            .require_remote_attestation = false,
            .pinned_root_digest_present = false,
            .pinned_root_digest = [_]u8{0} ** 32,
        };
        const workspace_id = try reader.readU64();
        persisted_state.network_policies.policies[index].policy.workspace_id = if (workspace_id == 0) null else workspace_id;
        try readTextInto(&reader, &persisted_state.network_policies.policies[index].policy.label, &persisted_state.network_policies.policies[index].policy.label_len);
        persisted_state.network_policies.policies[index].policy.mode = try parsePolicyMode(try reader.readByte());
        try readTextInto(&reader, &persisted_state.network_policies.policies[index].policy.target, &persisted_state.network_policies.policies[index].policy.target_len);
        persisted_state.network_policies.policies[index].policy.explicit_internet_grant = (try reader.readByte()) != 0;
        persisted_state.network_policies.policies[index].policy.require_remote_attestation = (try reader.readByte()) != 0;
        persisted_state.network_policies.policies[index].policy.pinned_root_digest_present = (try reader.readByte()) != 0;
        if (persisted_state.network_policies.policies[index].policy.pinned_root_digest_present) {
            try reader.readBytes(&persisted_state.network_policies.policies[index].policy.pinned_root_digest);
        }
    }
    persisted_state.network_policies.next_policy_id = nextPersistedPolicyId();

    index = 0;
    while (index < workspace_policy_count) : (index += 1) {
        persisted_state.workspace_policies[index].in_use = true;
        persisted_state.workspace_policies[index].policy = zeroWorkspacePolicy();
        persisted_state.workspace_policies[index].policy.workspace_id = try reader.readU64();
        persisted_state.workspace_policies[index].policy.owner = try readPrincipal(&reader);
        persisted_state.workspace_policies[index].policy.offline_first = (try reader.readByte()) != 0;
        persisted_state.workspace_policies[index].policy.personal_e2ee = (try reader.readByte()) != 0;
        persisted_state.workspace_policies[index].policy.device_to_device_policy_id = readOptionalU64(try reader.readU64());
        persisted_state.workspace_policies[index].policy.relay_policy_id = readOptionalU64(try reader.readU64());
        persisted_state.workspace_policies[index].policy.overlay_policy_id = readOptionalU64(try reader.readU64());
        try readTextInto(&reader, &persisted_state.workspace_policies[index].policy.relay_domain, &persisted_state.workspace_policies[index].policy.relay_domain_len);
        const prefix_count = try reader.readU16();
        if (prefix_count > MAX_SELECTIVE_PREFIXES) return error.CorruptState;
        persisted_state.workspace_policies[index].policy.selective_prefix_count = prefix_count;
        var prefix_index: usize = 0;
        while (prefix_index < prefix_count) : (prefix_index += 1) {
            try readTextInto(
                &reader,
                &persisted_state.workspace_policies[index].policy.selective_prefixes[prefix_index],
                &persisted_state.workspace_policies[index].policy.selective_prefix_lens[prefix_index],
            );
        }
    }

    index = 0;
    while (index < replica_count_value) : (index += 1) {
        persisted_state.replica_entries[index].in_use = true;
        persisted_state.replica_entries[index].entry = zeroReplicaEntry();
        persisted_state.replica_entries[index].entry.workspace_id = try reader.readU64();
        persisted_state.replica_entries[index].entry.device_id = try readPrincipal(&reader);
        try readTextInto(&reader, &persisted_state.replica_entries[index].entry.path, &persisted_state.replica_entries[index].entry.path_len);
        persisted_state.replica_entries[index].entry.object_id = try reader.readU64();
        persisted_state.replica_entries[index].entry.version_id = try reader.readU64();
    }

    index = 0;
    while (index < conflict_count_value) : (index += 1) {
        persisted_state.conflicts[index].in_use = true;
        persisted_state.conflicts[index].conflict = zeroConflict();
        persisted_state.conflicts[index].conflict.workspace_id = try reader.readU64();
        persisted_state.conflicts[index].conflict.device_id = try readPrincipal(&reader);
        persisted_state.conflicts[index].conflict.object_id = try reader.readU64();
        try readTextInto(&reader, &persisted_state.conflicts[index].conflict.path, &persisted_state.conflicts[index].conflict.path_len);
        persisted_state.conflicts[index].conflict.local_version_id = try reader.readU64();
        persisted_state.conflicts[index].conflict.remote_version_id = try reader.readU64();
        persisted_state.conflicts[index].conflict.semantic = try parseSyncSemantic(try reader.readByte());
    }

    index = 0;
    while (index < contract_count) : (index += 1) {
        persisted_state.database_contracts[index].in_use = true;
        persisted_state.database_contracts[index].contract = zeroDatabaseContract();
        persisted_state.database_contracts[index].contract.id = try reader.readU64();
        persisted_state.database_contracts[index].contract.workspace_id = try reader.readU64();
        try readTextInto(&reader, &persisted_state.database_contracts[index].contract.bundle_id, &persisted_state.database_contracts[index].contract.bundle_id_len);
        try readTextInto(&reader, &persisted_state.database_contracts[index].contract.label, &persisted_state.database_contracts[index].contract.label_len);
        persisted_state.database_contracts[index].contract.signature = try readSignature(&reader, &database_contract_signers[index]);
    }

    index = 0;
    while (index < overlay_count_value) : (index += 1) {
        persisted_state.overlays[index].in_use = true;
        persisted_state.overlays[index].overlay = zeroOverlay();
        persisted_state.overlays[index].overlay.id = try reader.readU64();
        persisted_state.overlays[index].overlay.workspace_id = try reader.readU64();
        persisted_state.overlays[index].overlay.home_device = try readPrincipal(&reader);
        try readTextInto(&reader, &persisted_state.overlays[index].overlay.service_identity, &persisted_state.overlays[index].overlay.service_identity_len);
        persisted_state.overlays[index].overlay.remote_access_enabled = (try reader.readByte()) != 0;
        const private_service_count = try reader.readU16();
        if (private_service_count > MAX_PRIVATE_SERVICES) return error.CorruptState;
        persisted_state.overlays[index].overlay.private_service_count = private_service_count;
        var service_index: usize = 0;
        while (service_index < private_service_count) : (service_index += 1) {
            try readTextInto(
                &reader,
                &persisted_state.overlays[index].overlay.private_services[service_index],
                &persisted_state.overlays[index].overlay.private_service_lens[service_index],
            );
        }
    }
}

fn encodeStateIndex(
    buffer: []u8,
    total_len: usize,
    chunk_count: usize,
    digest: [32]u8,
) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(state_index_magic);
    try writer.writeU16(state_version);
    try writer.writeU16(@intCast(total_len));
    try writer.writeByte(@intCast(chunk_count));
    try writer.writeBytes(&digest);
    return buffer[0..writer.offset];
}

fn decodeStateIndex(payload: []const u8) Error!StateIndex {
    var reader = CursorReader{ .buffer = payload };
    var magic_buffer: [state_index_magic.len]u8 = undefined;
    try reader.readBytes(&magic_buffer);
    if (!std.mem.eql(u8, &magic_buffer, state_index_magic)) return error.CorruptState;
    if ((try reader.readU16()) != state_version) return error.UnsupportedStateVersion;
    const total_len = try reader.readU16();
    const chunk_count = try reader.readByte();
    var digest: [32]u8 = undefined;
    try reader.readBytes(&digest);
    return .{
        .total_len = total_len,
        .chunk_count = chunk_count,
        .digest = digest,
    };
}

fn writePrincipal(writer: *CursorWriter, id: principal.PrincipalId) Error!void {
    try writer.writeByte(@intFromEnum(id.kind));
    try writer.writeU64(id.serial);
}

fn readPrincipal(reader: *CursorReader) Error!principal.PrincipalId {
    return .{
        .kind = try parsePrincipalKind(try reader.readByte()),
        .serial = try reader.readU64(),
    };
}

fn writeText(writer: *CursorWriter, text: []const u8) Error!void {
    if (text.len > std.math.maxInt(u16)) return error.StateTooLarge;
    try writer.writeU16(@intCast(text.len));
    try writer.writeBytes(text);
}

fn readTextInto(reader: *CursorReader, buffer: []u8, out_len: *usize) Error!void {
    const text_len = try reader.readU16();
    if (text_len > buffer.len) return error.CorruptState;
    @memset(buffer, 0);
    try reader.readBytes(buffer[0..text_len]);
    out_len.* = text_len;
}

fn writeSignature(writer: *CursorWriter, signature: manifest.Signature) Error!void {
    if (!signature.isPresent()) {
        try writer.writeByte(0);
        return;
    }
    if (signature.signer.len > MAX_LABEL_BYTES) return error.StateTooLarge;
    try writer.writeByte(1);
    try writeText(writer, signature.signer);
    try writer.writeU16(@intCast(signature.public_key_len));
    try writer.writeBytes(signature.public_key[0..signature.public_key_len]);
    try writer.writeU16(@intCast(signature.value_len));
    try writer.writeBytes(signature.value[0..signature.value_len]);
}

fn readSignature(reader: *CursorReader, signer_storage: *[MAX_LABEL_BYTES]u8) Error!manifest.Signature {
    if ((try reader.readByte()) == 0) return .{};

    var signature = manifest.Signature{
        .format = "ed25519",
        .signer = signer_storage[0..0],
    };
    var signer_len: usize = 0;
    try readTextInto(reader, signer_storage, &signer_len);
    signature.signer = signer_storage[0..signer_len];
    signature.public_key_len = try reader.readU16();
    if (signature.public_key_len > signature.public_key.len) return error.InvalidStateSignatureEncoding;
    try reader.readBytes(signature.public_key[0..signature.public_key_len]);
    signature.value_len = try reader.readU16();
    if (signature.value_len > signature.value.len) return error.InvalidStateSignatureEncoding;
    try reader.readBytes(signature.value[0..signature.value_len]);
    return signature;
}

fn parsePrincipalKind(raw: u8) Error!principal.PrincipalKind {
    return switch (raw) {
        0 => .user,
        1 => .device,
        2 => .app,
        3 => .service,
        4 => .policy_authority,
        else => error.CorruptState,
    };
}

fn parseDeviceStatus(raw: u8) Error!device_graph.DeviceStatus {
    return switch (raw) {
        0 => .trusted,
        1 => .revoked,
        else => error.CorruptState,
    };
}

fn parsePolicyMode(raw: u8) Error!network_policy.PolicyMode {
    return switch (raw) {
        0 => .none,
        1 => .local_network,
        2 => .local_subnet_discovery,
        3 => .named_service_identity,
        4 => .named_domain,
        5 => .inbound_collaborative_session,
        6 => .unrestricted_internet,
        else => error.CorruptState,
    };
}

fn parseSyncSemantic(raw: u8) Error!SyncSemantic {
    return switch (raw) {
        0 => .mergeable_crdt,
        1 => .chunked_snapshot,
        2 => .secure_transfer,
        3 => .transactional_contract,
        else => error.CorruptState,
    };
}

fn readOptionalU64(value: u64) ?u64 {
    return if (value == 0) null else value;
}

fn userRootCount() usize {
    var count: usize = 0;
    for (persisted_state.graph.user_roots) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn deviceCount() usize {
    var count: usize = 0;
    for (persisted_state.graph.devices) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn networkPolicyCount() usize {
    var count: usize = 0;
    for (persisted_state.network_policies.policies) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn workspacePolicyCount() usize {
    var count: usize = 0;
    for (persisted_state.workspace_policies) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn replicaCount() usize {
    var count: usize = 0;
    for (persisted_state.replica_entries) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn conflictCount() usize {
    var count: usize = 0;
    for (persisted_state.conflicts) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn databaseContractCount() usize {
    var count: usize = 0;
    for (persisted_state.database_contracts) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn overlayCount() usize {
    var count: usize = 0;
    for (persisted_state.overlays) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn nextPersistedPolicyId() u64 {
    var next_id: u64 = 1;
    for (persisted_state.network_policies.policies) |slot| {
        if (!slot.in_use) continue;
        next_id = @max(next_id, slot.policy.id + 1);
    }
    return next_id;
}

fn chunkPath(buffer: []u8, chunk_index: usize) Error![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{d}", .{ state_chunk_prefix, chunk_index }) catch error.StateTooLarge;
}

fn indexObjectId() u64 {
    return 0x5A_49_47_4F_53_53_59_01;
}

fn chunkObjectId(chunk_index: usize) u64 {
    return 0x5A_49_47_4F_53_53_59_10 + @as(u64, @intCast(chunk_index));
}

fn stateDigest(bytes: []const u8) [32]u8 {
    var hasher = crypto_hash.init();
    hasher.update(bytes);
    return crypto_hash.finalize(&hasher);
}

fn nextPersistTick() u64 {
    defer next_state_tick += 1;
    return next_state_tick;
}

fn markResidentStateDirty() void {
    has_persisted_state = true;
}

fn resetSignatureStorage() void {
    @memset(std.mem.asBytes(&user_root_signers), 0);
    @memset(std.mem.asBytes(&device_signature_signers), 0);
    @memset(std.mem.asBytes(&database_contract_signers), 0);
}

fn zeroDeviceGraphRecord() device_graph.DeviceRecord {
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

fn zeroWorkspacePolicy() WorkspacePolicy {
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

fn zeroOverlay() OverlayRecord {
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

fn zeroReplicaEntry() ReplicaEntry {
    return .{
        .workspace_id = 0,
        .device_id = .{ .kind = .device, .serial = 0 },
        .path_len = 0,
        .path = [_]u8{0} ** workspace.MAX_ENTRY_PATH_BYTES,
        .object_id = 0,
        .version_id = 0,
    };
}

fn zeroConflict() ConflictRecord {
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

fn zeroDatabaseContract() DatabaseContract {
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


fn signatureEql(a: manifest.Signature, b: manifest.Signature) bool {
    return std.mem.eql(u8, a.format, b.format) and
        std.mem.eql(u8, a.signer, b.signer) and
        a.public_key_len == b.public_key_len and
        std.mem.eql(u8, a.publicKeySlice(), b.publicKeySlice()) and
        a.value_len == b.value_len and
        std.mem.eql(u8, a.valueSlice(), b.valueSlice());
}

fn classifyEntry(entry: workspace.Entry) SyncSemantic {
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

fn databaseContractMessage(
    buffer: []u8,
    workspace_id: u64,
    bundle_id: []const u8,
    label: []const u8,
) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buffer, "db-contract:{d}:{s}:{s}", .{ workspace_id, bundle_id, label }) catch error.NoSpaceLeft;
}

test "sync service covers device graph policy replication semantics and restart recovery" {
    storage_service.Service.resetPersistentState();
    Service.resetPersistentState();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 11 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 12 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 13 };
    const storage_signer = signing.SignerIdentity{
        .label = "storage-signer",
        .seed = [_]u8{0x51} ** 32,
    };
    const user_signer = signing.SignerIdentity{
        .label = "user-root",
        .seed = [_]u8{0x52} ** 32,
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "laptop",
        .seed = [_]u8{0x53} ** 32,
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "tablet",
        .seed = [_]u8{0x54} ** 32,
    };
    const tablet_rotated_signer = signing.SignerIdentity{
        .label = "tablet-v2",
        .seed = [_]u8{0x55} ** 32,
    };
    const phone_signer = signing.SignerIdentity{
        .label = "phone",
        .seed = [_]u8{0x56} ** 32,
    };
    const contract_signer = signing.SignerIdentity{
        .label = "db-sync",
        .seed = [_]u8{0x57} ** 32,
    };

    var storage = storage_service.Service.init(40, 4, storage_owner);
    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = 800,
        .object_type = .document,
        .payload = "# Notes\n- v1\n",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/markdown", .document, "# Notes\n- v1\n", 10),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = 800,
        .object_type = .document,
        .payload = "# Notes\n- v2\n",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/markdown", .document, "# Notes\n- v2\n", 11),
        .parent_version_id = notes_v1.version_id,
    });
    const inbox = try storage.putVersion(.{
        .preferred_object_id = 801,
        .object_type = .collection,
        .payload = "inbox",
        .metadata = try object_store.signMetadata(storage_signer, "inbox", "application/zigos-collection", .collection, "inbox", 12),
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = 802,
        .object_type = .media_asset,
        .payload = "jpeg:cover",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "jpeg:cover", 13),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = 803,
        .object_type = .secret,
        .payload = "enc:secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:secret", 14),
    });

    const notes = try storage.createWorkspace(.{
        .owner = user,
        .label = "notes",
    });
    try storage.beginTransaction(notes.id);
    try storage.stagePut(notes.id, "documents/notes.md", notes_v1.object_id, notes_v1.version_id, .document);
    try storage.stagePut(notes.id, "collections/inbox", inbox.object_id, inbox.version_id, .collection);
    try storage.stagePut(notes.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    _ = try storage.commit(notes.id, 15);

    var service = try Service.initWithStorage(80, 8, sync_owner, &storage);
    _ = try service.ensureUserRoot(user, "cameron", user_signer);
    _ = try service.enrollTrustedDevice(user, laptop, "laptop", user_signer, laptop_signer, 20);
    _ = try service.enrollTrustedDevice(user, tablet, "tablet", user_signer, tablet_signer, 21);
    _ = try service.enrollTrustedDevice(user, phone, "phone", user_signer, phone_signer, 22);
    _ = try service.rotateDeviceKey(user, tablet, user_signer, tablet_rotated_signer, 23);
    try service.revokeTrustedDevice(user, phone, user_signer, 24);

    const none_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "none",
        .mode = .none,
    });
    const local_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "local",
        .mode = .local_network,
    });
    const discovery_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const overlay_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    });
    const relay_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    const inbound_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "collab-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    });
    const internet_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    });

    try std.testing.expect(!(try service.evaluateNetworkPolicy(none_policy.id, .public_internet)).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(local_policy.id, .local_network)).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(discovery_policy.id, .{ .discovery_class = "printer" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(overlay_policy.id, .{ .service_identity = "overlay.notes.sync" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(relay_policy.id, .{ .domain = "relay.zigos.dev" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(inbound_policy.id, .{ .inbound_session_type = "document-review/v1" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(internet_policy.id, .public_internet)).allowed);

    _ = try service.configureWorkspacePolicy(.{
        .workspace_id = notes.id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/" },
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    });
    _ = try service.configureOverlay(notes.id, laptop, "overlay.notes.sync", true);
    _ = try service.publishPrivateService(notes.id, "notes.remote");

    try service.setReplicaVersion(notes.id, tablet, "documents/notes.md", notes_v1.object_id, notes_v2.version_id);
    const summary = try service.replicateWorkspace(&storage, notes.id, laptop, tablet, .device_to_device);
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_device_to_device);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expect(summary.remote_access_ready);
    try std.testing.expect(summary.private_service_published);
    try std.testing.expectEqual(@as(usize, 2), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.skipped_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.snapshot_count);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expect(service.findConflict(notes.id, tablet, "documents/notes.md") != null);

    try std.testing.expect(try service.transferSecretObject(storage.store, notes.id, secret.object_id, laptop, tablet, .device_to_device));
    const contract = try service.registerDatabaseContract(notes.id, "app.db.notes", "notes-db", contract_signer);
    try std.testing.expect(try service.replicateDatabaseContract(contract.id, notes.id, laptop, tablet, .relay_assisted));
    try std.testing.expectError(error.DeviceNotTrusted, service.replicateWorkspace(&storage, notes.id, laptop, phone, .device_to_device));

    Service.resetPersistentState();
    var restarted = try Service.initWithStorage(80, 9, sync_owner, &storage);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 2), restarted.trustedDeviceCount());
    try std.testing.expect(restarted.findWorkspacePolicy(notes.id) != null);
    try std.testing.expect(restarted.findOverlay(notes.id) != null);
    try std.testing.expect(restarted.findConflict(notes.id, tablet, "documents/notes.md") != null);
    const restarted_local_policy = try restarted.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "local",
        .mode = .local_network,
    });
    try std.testing.expectEqual(local_policy.id, restarted_local_policy.id);
    const restarted_overlay = try restarted.publishPrivateService(notes.id, "notes.remote");
    try std.testing.expectEqual(@as(usize, 1), restarted_overlay.private_service_count);
    const restarted_contract = try restarted.registerDatabaseContract(notes.id, "app.db.notes", "notes-db", contract_signer);
    try std.testing.expectEqual(contract.id, restarted_contract.id);

    Service.resetPersistentState();
    storage_service.Service.resetPersistentState();
}
