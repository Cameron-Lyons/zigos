const std = @import("std");
const device_graph = @import("device_graph.zig");
const manifest = @import("manifest.zig");
const network_policy = @import("network_policy.zig");
const object_store = @import("object_store.zig");
const principal = @import("principal.zig");
const signing = @import("signing.zig");
const storage_service = @import("storage_service.zig");
const workspace = @import("workspace.zig");

pub const MAX_WORKSPACE_POLICIES: usize = 8;
pub const MAX_SELECTIVE_PREFIXES: usize = 4;
pub const MAX_PREFIX_BYTES: usize = 48;
pub const MAX_REPLICA_ENTRIES: usize = 32;
pub const MAX_CONFLICTS: usize = 16;
pub const MAX_DATABASE_CONTRACTS: usize = 8;
pub const MAX_OVERLAYS: usize = 4;
pub const MAX_PRIVATE_SERVICES: usize = 4;
pub const MAX_LABEL_BYTES: usize = 48;

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
    DatabaseContractNotFound,
    DatabaseContractTableFull,
    DeviceNotTrusted,
    InvalidContractSignature,
    OverlayNotFound,
    OverlayTableFull,
    ReplicaTableFull,
    TooManyPrivateServices,
    TooManySelectivePrefixes,
    TransportDenied,
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

pub const Service = struct {
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    loaded_existing_state: bool = false,
    state: *PersistentState,

    pub fn init(service_id: u64, task_id: u64, owner: principal.PrincipalId) Service {
        const loaded_existing_state = has_persisted_state;
        if (!has_persisted_state) {
            persisted_state.reset();
        }
        return .{
            .service_id = service_id,
            .task_id = task_id,
            .owner = owner,
            .loaded_existing_state = loaded_existing_state,
            .state = &persisted_state,
        };
    }

    pub fn resetPersistentState() void {
        persisted_state.reset();
        has_persisted_state = false;
    }

    pub fn ensureUserRoot(
        self: *Service,
        user_principal: principal.PrincipalId,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) Error!*device_graph.UserRootRecord {
        const root = try self.state.graph.ensureUserRoot(user_principal, label, identity);
        self.checkpoint();
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
        self.checkpoint();
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
        self.checkpoint();
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
        self.checkpoint();
    }

    pub fn createNetworkPolicy(self: *Service, request: network_policy.CreateRequest) Error!*network_policy.PolicyRecord {
        const record = try self.state.network_policies.create(request);
        self.checkpoint();
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

        self.checkpoint();
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
        self.checkpoint();
        return &slot.overlay;
    }

    pub fn publishPrivateService(
        self: *Service,
        workspace_id: u64,
        label: []const u8,
    ) Error!*OverlayRecord {
        const overlay = self.findOverlay(workspace_id) orelse return error.OverlayNotFound;
        if (overlay.private_service_count >= MAX_PRIVATE_SERVICES) return error.TooManyPrivateServices;
        const index = overlay.private_service_count;
        overlay.private_service_lens[index] = copyText(&overlay.private_services[index], label);
        overlay.private_service_count += 1;
        self.checkpoint();
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
        self.checkpoint();
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
        const slot = self.allocateDatabaseContract() orelse return error.DatabaseContractTableFull;
        slot.in_use = true;
        slot.contract = zeroDatabaseContract();
        slot.contract.id = self.nextDatabaseContractId();
        slot.contract.workspace_id = workspace_id;
        slot.contract.bundle_id_len = copyText(&slot.contract.bundle_id, bundle_id);
        slot.contract.label_len = copyText(&slot.contract.label, label);

        var message_buffer: [160]u8 = undefined;
        const message = databaseContractMessage(&message_buffer, workspace_id, bundle_id, label) catch return error.InvalidContractSignature;
        slot.contract.signature = signing.sign(identity, message) catch return error.InvalidContractSignature;
        if (!signing.verify(slot.contract.signature, message)) return error.InvalidContractSignature;

        self.checkpoint();
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
        var repaired = self.clearConflictsFor(workspace_id, device_id);
        const entries = try store.entries(workspace_id);
        for (entries) |entry| {
            if (!policy.matchesPath(entry.pathSlice())) continue;
            try self.setReplicaVersion(workspace_id, device_id, entry.pathSlice(), entry.object_id, entry.version_id);
            repaired = true;
        }
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

    fn checkpoint(self: *const Service) void {
        _ = self;
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
        self.checkpoint();
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

    fn clearConflictsFor(self: *Service, workspace_id: u64, device_id: principal.PrincipalId) bool {
        var cleared = false;
        for (&self.state.conflicts) |*slot| {
            if (!slot.in_use) continue;
            if (slot.conflict.workspace_id != workspace_id) continue;
            if (!slot.conflict.device_id.eql(device_id)) continue;
            slot.* = .{};
            cleared = true;
        }
        if (cleared) self.checkpoint();
        return cleared;
    }

    fn findDatabaseContract(self: *Service, contract_id: u64) ?*DatabaseContract {
        for (&self.state.database_contracts) |*slot| {
            if (slot.in_use and slot.contract.id == contract_id) return &slot.contract;
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

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
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

    var service = Service.init(80, 8, sync_owner);
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
    const internet_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    });

    try std.testing.expect(!(try service.evaluateNetworkPolicy(none_policy.id, .public_internet)).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(local_policy.id, .local_network)).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(overlay_policy.id, .{ .service_identity = "overlay.notes.sync" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(relay_policy.id, .{ .domain = "relay.zigos.dev" })).allowed);
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

    var restarted = Service.init(80, 9, sync_owner);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 2), restarted.trustedDeviceCount());
    try std.testing.expect(restarted.findWorkspacePolicy(notes.id) != null);
    try std.testing.expect(restarted.findOverlay(notes.id) != null);
    try std.testing.expect(restarted.findConflict(notes.id, tablet, "documents/notes.md") != null);

    Service.resetPersistentState();
    storage_service.Service.resetPersistentState();
}
