const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const device_graph = @import("device_graph.zig");
const fixed_table = @import("../core/fixed_table.zig");
const id_index = @import("../core/id_index.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const network_policy = @import("network_policy.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sync_adapters = @import("sync_adapters.zig");
const state_store = @import("sync_state_store.zig");
const state_support = @import("sync_state_support.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");

pub const MAX_WORKSPACE_POLICIES = state_support.MAX_WORKSPACE_POLICIES;
pub const MAX_SELECTIVE_PREFIXES = state_support.MAX_SELECTIVE_PREFIXES;
pub const MAX_PREFIX_BYTES = state_support.MAX_PREFIX_BYTES;
pub const MAX_REPLICA_ENTRIES = state_support.MAX_REPLICA_ENTRIES;
pub const MAX_CONFLICTS = state_support.MAX_CONFLICTS;
pub const MAX_DATABASE_CONTRACTS = state_support.MAX_DATABASE_CONTRACTS;
pub const MAX_OVERLAYS = state_support.MAX_OVERLAYS;
pub const MAX_PRIVATE_SERVICES = state_support.MAX_PRIVATE_SERVICES;
pub const MAX_LABEL_BYTES = state_support.MAX_LABEL_BYTES;
pub const MAX_OVERLAY_SESSIONS: usize = 8;
const REPLICA_INDEX_CAPACITY: usize = MAX_REPLICA_ENTRIES * 2;
pub const ServiceConfig = struct {
    max_overlay_sessions: usize = MAX_OVERLAY_SESSIONS,

    pub fn validate(comptime config: ServiceConfig) void {
        if (config.max_overlay_sessions == 0) @compileError("sync service requires at least one overlay session slot");
    }
};
pub const TransportMode = state_support.TransportMode;
pub const SyncSemantic = state_support.SyncSemantic;
pub const WorkspacePolicyRequest = state_support.WorkspacePolicyRequest;
pub const WorkspacePolicy = state_support.WorkspacePolicy;
pub const OverlayRecord = state_support.OverlayRecord;
pub const OverlaySessionUse = enum(u8) {
    sync_replication,
    remote_access,
    private_service,
};
pub const OverlaySessionState = enum(u8) {
    establishing,
    established,
    closed,
};
pub const OverlaySession = struct {
    session_id: u64 = 0,
    overlay_id: u64,
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    usage: OverlaySessionUse,
    transport: TransportMode,
    state: OverlaySessionState = .establishing,
    encrypted: bool,
    relay_encrypted: bool,
    remote_access: bool,
    open_tick: u64 = 0,
    last_activity_tick: u64 = 0,
    keepalive_count: u16 = 0,
    service_identity_len: usize = 0,
    service_identity: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    relay_domain_len: usize = 0,
    relay_domain: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    private_service_len: usize = 0,
    private_service: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,

    pub fn serviceIdentitySlice(self: *const OverlaySession) []const u8 {
        return self.service_identity[0..self.service_identity_len];
    }

    pub fn relayDomainSlice(self: *const OverlaySession) []const u8 {
        return self.relay_domain[0..self.relay_domain_len];
    }

    pub fn privateServiceSlice(self: *const OverlaySession) []const u8 {
        return self.private_service[0..self.private_service_len];
    }

    pub fn isActive(self: *const OverlaySession) bool {
        return self.state == .established;
    }
};
pub const ReplicaEntry = state_support.ReplicaEntry;
pub const ConflictRecord = state_support.ConflictRecord;
pub const DatabaseContract = state_support.DatabaseContract;
pub const ReplicationSummary = state_support.ReplicationSummary;
pub const MergeableDocumentAdapter = sync_adapters.MergeableDocumentAdapter;
pub const ChunkMediaAdapter = sync_adapters.ChunkMediaAdapter;
pub const SecretTransferAdapter = sync_adapters.SecretTransferAdapter;
pub const DatabaseSyncAdapter = sync_adapters.DatabaseSyncAdapter;
pub const TransportFrame = sync_adapters.TransportFrame;
pub const TransportQueue = sync_adapters.TransportQueue;
pub const Error = state_support.Error;

const WorkspacePolicySlot = state_support.WorkspacePolicySlot;
const ReplicaSlot = state_support.ReplicaSlot;
const ConflictSlot = state_support.ConflictSlot;
const DatabaseContractSlot = state_support.DatabaseContractSlot;
const OverlaySlot = state_support.OverlaySlot;
const PersistentState = state_support.PersistentState;
pub const ResidentState = state_support.ResidentState;
const zeroConflict = state_support.zeroConflict;
const zeroDatabaseContract = state_support.zeroDatabaseContract;
const zeroOverlay = state_support.zeroOverlay;
const zeroReplicaEntry = state_support.zeroReplicaEntry;
const zeroWorkspacePolicy = state_support.zeroWorkspacePolicy;

const OverlaySessionSlot = struct {
    in_use: bool = false,
    session: OverlaySession = .{
        .overlay_id = 0,
        .workspace_id = 0,
        .source_device = .{ .kind = .device, .serial = 0 },
        .target_device = .{ .kind = .device, .serial = 0 },
        .usage = .sync_replication,
        .transport = .device_to_device,
        .state = .closed,
        .encrypted = true,
        .relay_encrypted = false,
        .remote_access = false,
    },
};

const WorkspacePolicyLookup = struct {
    workspace_id: u64,
};

const OverlayLookup = struct {
    workspace_id: u64,
};

const ReplicaLookup = struct {
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

const ReplicaIndexSlot = struct {
    state: id_index.State = .empty,
    key: ReplicaIndexKey = .{},
    slot_index: usize = 0,
};

const DatabaseContractLookup = struct {
    id: u64,
};

const DatabaseContractEquivalentLookup = struct {
    workspace_id: u64,
    bundle_id: []const u8,
    label: []const u8,
    signature: manifest.Signature,
};

fn workspacePolicySlotMatches(context: WorkspacePolicyLookup, slot: *const WorkspacePolicySlot) bool {
    return slot.policy.workspace_id == context.workspace_id;
}

fn overlaySlotMatches(context: OverlayLookup, slot: *const OverlaySlot) bool {
    return slot.overlay.workspace_id == context.workspace_id;
}

fn replicaSlotMatches(context: ReplicaLookup, slot: *const ReplicaSlot) bool {
    return slot.entry.workspace_id == context.workspace_id and
        slot.entry.device_id.eql(context.device_id) and
        slot.entry.pathHash() == context.path_hash and
        std.mem.eql(u8, slot.entry.pathSlice(), context.path);
}

fn databaseContractSlotMatches(context: DatabaseContractLookup, slot: *const DatabaseContractSlot) bool {
    return slot.contract.id == context.id;
}

fn equivalentDatabaseContractSlotMatches(context: DatabaseContractEquivalentLookup, slot: *const DatabaseContractSlot) bool {
    return slot.contract.workspace_id == context.workspace_id and
        std.mem.eql(u8, slot.contract.bundleIdSlice(), context.bundle_id) and
        std.mem.eql(u8, slot.contract.labelSlice(), context.label) and
        signatureEql(slot.contract.signature, context.signature);
}

fn emptyReplicaIndex() [REPLICA_INDEX_CAPACITY]ReplicaIndexSlot {
    return [_]ReplicaIndexSlot{ReplicaIndexSlot{}} ** REPLICA_INDEX_CAPACITY;
}

fn replicaIndexKey(workspace_id: u64, device_id: principal.PrincipalId, path_hash: u64) ReplicaIndexKey {
    return .{
        .workspace_id = workspace_id,
        .device_id = device_id,
        .path_hash = path_hash,
    };
}

fn replicaIndexLookup(table: *const [REPLICA_INDEX_CAPACITY]ReplicaIndexSlot, key: ReplicaIndexKey) ?usize {
    var index = replicaIndexStart(key);
    var attempts: usize = 0;
    while (attempts < REPLICA_INDEX_CAPACITY) : (attempts += 1) {
        const slot = table[index];
        switch (slot.state) {
            .empty => return null,
            .filled => if (replicaIndexKeyEql(slot.key, key)) return slot.slot_index,
            .tombstone => {},
        }
        index = (index + 1) % REPLICA_INDEX_CAPACITY;
    }
    return null;
}

fn replicaIndexInsert(table: *[REPLICA_INDEX_CAPACITY]ReplicaIndexSlot, key: ReplicaIndexKey, slot_index: usize) void {
    var index = replicaIndexStart(key);
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < REPLICA_INDEX_CAPACITY) : (attempts += 1) {
        switch (table[index].state) {
            .empty => {
                const insert_index = first_tombstone orelse index;
                table[insert_index] = .{
                    .state = .filled,
                    .key = key,
                    .slot_index = slot_index,
                };
                return;
            },
            .filled => {
                if (replicaIndexKeyEql(table[index].key, key)) {
                    table[index].slot_index = slot_index;
                    return;
                }
            },
            .tombstone => {
                if (first_tombstone == null) first_tombstone = index;
            },
        }
        index = (index + 1) % REPLICA_INDEX_CAPACITY;
    }

    native_util.impossibleByInvariant("replica index capacity covers replica slots");
}

fn replicaIndexStart(key: ReplicaIndexKey) usize {
    return @as(usize, @intCast(replicaIndexHash(key) % REPLICA_INDEX_CAPACITY));
}

fn replicaIndexHash(key: ReplicaIndexKey) u64 {
    var hash: u64 = 0xCBF2_9CE4_8422_2325;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.workspace_id);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(key.device_id.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.device_id.serial);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.path_hash);
    return hash;
}

fn replicaIndexKeyEql(left: ReplicaIndexKey, right: ReplicaIndexKey) bool {
    return left.workspace_id == right.workspace_id and
        left.device_id.eql(right.device_id) and
        left.path_hash == right.path_hash;
}

pub const Service = ServiceWith(.{});

pub fn ServiceWith(comptime config: ServiceConfig) type {
    config.validate();
    return struct {
        const Self = @This();
        const MAX_SERVICE_OVERLAY_SESSIONS = config.max_overlay_sessions;

        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        loaded_existing_state: bool = false,
        storage: ?*storage_service.Service = null,
        state_workspace_id: u64 = 0,
        resident_store: ?*ResidentState = null,
        owned_resident_state: ResidentState = .{},
        replica_index_slots: [REPLICA_INDEX_CAPACITY]ReplicaIndexSlot = emptyReplicaIndex(),
        next_overlay_session_id: u64 = 1,
        overlay_sessions: [MAX_SERVICE_OVERLAY_SESSIONS]OverlaySessionSlot = [_]OverlaySessionSlot{OverlaySessionSlot{}} ** MAX_SERVICE_OVERLAY_SESSIONS,
        mergeable_document_adapter: MergeableDocumentAdapter = sync_adapters.default_mergeable_document_adapter,
        chunk_media_adapter: ChunkMediaAdapter = sync_adapters.default_chunk_media_adapter,
        secret_transfer_adapter: SecretTransferAdapter = sync_adapters.default_secret_transfer_adapter,
        database_sync_adapter: DatabaseSyncAdapter = sync_adapters.default_database_sync_adapter,
        transport_queue: TransportQueue = TransportQueue.init(),

        pub fn init(service_id: u64, task_id: u64, owner: principal.PrincipalId) Self {
            var service = Self{
                .service_id = service_id,
                .task_id = task_id,
                .owner = owner,
                .storage = null,
                .state_workspace_id = 0,
                .next_overlay_session_id = 1,
                .overlay_sessions = [_]OverlaySessionSlot{OverlaySessionSlot{}} ** MAX_SERVICE_OVERLAY_SESSIONS,
                .mergeable_document_adapter = sync_adapters.default_mergeable_document_adapter,
                .chunk_media_adapter = sync_adapters.default_chunk_media_adapter,
                .secret_transfer_adapter = sync_adapters.default_secret_transfer_adapter,
                .database_sync_adapter = sync_adapters.default_database_sync_adapter,
                .transport_queue = TransportQueue.init(),
            };
            service.owned_resident_state.resetForServiceInit();
            return service;
        }

        pub fn initWithResidentState(
            service_id: u64,
            task_id: u64,
            owner: principal.PrincipalId,
            resident_state: *ResidentState,
        ) Self {
            const loaded_existing_state = resident_state.has_persisted_state;
            if (!resident_state.has_persisted_state) {
                resident_state.resetForServiceInit();
            }
            var service = Self{
                .service_id = service_id,
                .task_id = task_id,
                .owner = owner,
                .loaded_existing_state = loaded_existing_state,
                .storage = null,
                .state_workspace_id = 0,
                .resident_store = resident_state,
                .next_overlay_session_id = 1,
                .overlay_sessions = [_]OverlaySessionSlot{OverlaySessionSlot{}} ** MAX_SERVICE_OVERLAY_SESSIONS,
                .mergeable_document_adapter = sync_adapters.default_mergeable_document_adapter,
                .chunk_media_adapter = sync_adapters.default_chunk_media_adapter,
                .secret_transfer_adapter = sync_adapters.default_secret_transfer_adapter,
                .database_sync_adapter = sync_adapters.default_database_sync_adapter,
                .transport_queue = TransportQueue.init(),
            };
            service.rebuildReplicaIndex();
            return service;
        }

        pub fn initWithStorage(
            service_id: u64,
            task_id: u64,
            owner: principal.PrincipalId,
            storage: *storage_service.Service,
            resident_state: *ResidentState,
        ) Error!Self {
            const workspace_id = try state_store.ensureWorkspace(storage, owner);
            const loaded_existing_state = if (resident_state.has_persisted_state)
                true
            else
                try state_store.load(storage, workspace_id, resident_state);

            if (!loaded_existing_state) {
                resident_state.resetForServiceInit();
            }

            var service = Self{
                .service_id = service_id,
                .task_id = task_id,
                .owner = owner,
                .loaded_existing_state = loaded_existing_state,
                .storage = storage,
                .state_workspace_id = workspace_id,
                .resident_store = resident_state,
                .next_overlay_session_id = 1,
                .overlay_sessions = [_]OverlaySessionSlot{OverlaySessionSlot{}} ** MAX_SERVICE_OVERLAY_SESSIONS,
                .mergeable_document_adapter = sync_adapters.default_mergeable_document_adapter,
                .chunk_media_adapter = sync_adapters.default_chunk_media_adapter,
                .secret_transfer_adapter = sync_adapters.default_secret_transfer_adapter,
                .database_sync_adapter = sync_adapters.default_database_sync_adapter,
                .transport_queue = TransportQueue.init(),
            };
            service.rebuildReplicaIndex();
            return service;
        }

        pub fn bindSyncAdapters(
            self: *Self,
            mergeable_document_adapter: MergeableDocumentAdapter,
            chunk_media_adapter: ChunkMediaAdapter,
            secret_transfer_adapter: SecretTransferAdapter,
            database_sync_adapter: DatabaseSyncAdapter,
        ) void {
            self.mergeable_document_adapter = mergeable_document_adapter;
            self.chunk_media_adapter = chunk_media_adapter;
            self.secret_transfer_adapter = secret_transfer_adapter;
            self.database_sync_adapter = database_sync_adapter;
        }

        pub fn transportFrameCount(self: *const Self) usize {
            return self.transport_queue.count();
        }

        pub fn transportFrameCountFor(self: *const Self, workspace_id: u64, device_id: principal.PrincipalId) usize {
            return self.transport_queue.countFor(workspace_id, device_id);
        }

        pub fn latestTransportFrameForPath(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?TransportFrame {
            return self.transport_queue.latestForPath(workspace_id, device_id, path);
        }

        pub fn ensureUserRoot(
            self: *Self,
            user_principal: principal.PrincipalId,
            label: []const u8,
            identity: signing.SignerIdentity,
        ) Error!*device_graph.UserRootRecord {
            const root = try self.state().graph.ensureUserRoot(user_principal, label, identity);
            self.resident().markDirty();
            return root;
        }

        pub fn enrollTrustedDevice(
            self: *Self,
            user_principal: principal.PrincipalId,
            device_principal: principal.PrincipalId,
            label: []const u8,
            authorizer: signing.SignerIdentity,
            device_identity: signing.SignerIdentity,
            tick: u64,
        ) Error!*device_graph.DeviceRecord {
            const record = try self.state().graph.enrollDevice(user_principal, device_principal, label, authorizer, device_identity, tick);
            self.resident().markDirty();
            return record;
        }

        pub fn rotateDeviceKey(
            self: *Self,
            user_principal: principal.PrincipalId,
            device_principal: principal.PrincipalId,
            authorizer: signing.SignerIdentity,
            next_device_identity: signing.SignerIdentity,
            tick: u64,
        ) Error!*device_graph.DeviceRecord {
            const record = try self.state().graph.rotateDeviceKey(user_principal, device_principal, authorizer, next_device_identity, tick);
            self.resident().markDirty();
            return record;
        }

        pub fn revokeTrustedDevice(
            self: *Self,
            user_principal: principal.PrincipalId,
            device_principal: principal.PrincipalId,
            authorizer: signing.SignerIdentity,
            tick: u64,
        ) Error!void {
            try self.state().graph.revokeDevice(user_principal, device_principal, authorizer, tick);
            self.resident().markDirty();
        }

        pub fn findDeviceRecord(self: *const Self, device_id: principal.PrincipalId) ?*const device_graph.DeviceRecord {
            return self.stateConst().graph.findDeviceConst(device_id);
        }

        pub fn createNetworkPolicy(self: *Self, request: network_policy.CreateRequest) Error!*network_policy.PolicyRecord {
            const record = try self.state().network_policies.create(request);
            self.resident().markDirty();
            return record;
        }

        pub fn evaluateNetworkPolicy(
            self: *Self,
            policy_id: u64,
            destination: network_policy.Destination,
        ) Error!network_policy.Decision {
            return self.state().network_policies.authorize(policy_id, destination);
        }

        pub fn authorizeNetworkConnection(
            self: *Self,
            capability_table: *const capability.CapabilityTable,
            request: network_policy.EgressConnectionRequest,
        ) Error!network_policy.EgressDecision {
            var broker = network_policy.EgressBroker.init(&self.state().network_policies, capability_table);
            return broker.connect(request);
        }

        pub fn egressBroker(
            self: *Self,
            capability_table: *const capability.CapabilityTable,
        ) network_policy.EgressBroker {
            return network_policy.EgressBroker.init(&self.state().network_policies, capability_table);
        }

        pub fn configureWorkspacePolicy(
            self: *Self,
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
            slot.policy.relay_domain_len = native_util.copyTextExact(&slot.policy.relay_domain, request.relay_domain) catch return error.NetworkTargetTooLong;

            for (request.selective_prefixes, 0..) |prefix, index| {
                slot.policy.selective_prefix_lens[index] = native_util.copyTextExact(&slot.policy.selective_prefixes[index], prefix) catch return error.PathTooLong;
                slot.policy.selective_prefix_count += 1;
            }

            try self.checkpoint();
            return &slot.policy;
        }

        pub fn findWorkspacePolicy(self: *Self, workspace_id: anytype) ?*WorkspacePolicy {
            const slot = self.lookupWorkspacePolicySlot(object_store.ids.raw(workspace_id)) orelse return null;
            return &slot.policy;
        }

        pub fn configureOverlay(
            self: *Self,
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
            slot.overlay.service_identity_len = native_util.copyTextExact(&slot.overlay.service_identity, service_identity) catch return error.ServiceIdentityTooLong;
            slot.overlay.remote_access_enabled = remote_access_enabled;
            try self.checkpoint();
            return &slot.overlay;
        }

        pub fn publishPrivateService(
            self: *Self,
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
            overlay.private_service_lens[slot_index] = native_util.copyTextExact(&overlay.private_services[slot_index], label) catch return error.ServiceIdentityTooLong;
            overlay.private_service_count += 1;
            try self.checkpoint();
            return overlay;
        }

        pub fn findOverlay(self: *Self, workspace_id: anytype) ?*OverlayRecord {
            const slot = self.lookupOverlaySlot(object_store.ids.raw(workspace_id)) orelse return null;
            return &slot.overlay;
        }

        pub fn findOverlaySession(self: *Self, session_id: u64) ?*OverlaySession {
            for (&self.overlay_sessions) |*slot| {
                if (slot.in_use and slot.session.session_id == session_id) return &slot.session;
            }
            return null;
        }

        pub fn activeOverlaySessionCount(self: *const Self) usize {
            var count: usize = 0;
            for (self.overlay_sessions) |slot| {
                if (slot.in_use and slot.session.state == .established) count += 1;
            }
            return count;
        }

        pub fn openOverlaySession(
            self: *Self,
            workspace_id: u64,
            from_device: principal.PrincipalId,
            to_device: principal.PrincipalId,
            usage: OverlaySessionUse,
            transport: TransportMode,
            private_service_label: ?[]const u8,
            tick: u64,
        ) Error!OverlaySession {
            try self.ensureTrustedDevices(from_device, to_device);
            const policy = self.findWorkspacePolicy(workspace_id) orelse return error.WorkspacePolicyNotFound;
            const overlay = self.findOverlay(workspace_id) orelse return error.OverlayNotFound;
            const overlay_policy_id = policy.overlay_policy_id orelse return error.TransportDenied;
            const overlay_decision = try self.evaluateNetworkPolicy(overlay_policy_id, .{
                .service_identity = overlay.serviceIdentitySlice(),
            });
            if (!overlay_decision.allowed) return error.TransportDenied;

            try self.authorizeTransport(policy, transport, null);
            if (transport == .relay_assisted and !overlay.remote_access_enabled) {
                return error.RemoteAccessDisabled;
            }

            var session = OverlaySession{
                .session_id = self.nextOverlaySessionId(),
                .overlay_id = overlay.id,
                .workspace_id = workspace_id,
                .source_device = from_device,
                .target_device = to_device,
                .usage = usage,
                .transport = transport,
                .state = .establishing,
                .encrypted = true,
                .relay_encrypted = transport == .relay_assisted,
                .remote_access = false,
                .open_tick = tick,
                .last_activity_tick = tick,
            };
            session.service_identity_len = native_util.copyTextExact(&session.service_identity, overlay.serviceIdentitySlice()) catch return error.ServiceIdentityTooLong;

            switch (usage) {
                .sync_replication => {},
                .remote_access => {
                    if (!overlay.remote_access_enabled) return error.RemoteAccessDisabled;
                    session.remote_access = true;
                },
                .private_service => {
                    const label = private_service_label orelse return error.PrivateServiceNotPublished;
                    if (!overlay.hasPrivateService(label)) return error.PrivateServiceNotPublished;
                    session.private_service_len = native_util.copyTextExact(&session.private_service, label) catch return error.ServiceIdentityTooLong;
                    session.remote_access = overlay.remote_access_enabled and transport == .relay_assisted;
                },
            }

            if (transport == .relay_assisted) {
                session.relay_domain_len = native_util.copyTextExact(&session.relay_domain, policy.relayDomainSlice()) catch return error.NetworkTargetTooLong;
                session.remote_access = true;
            }

            const slot = self.allocateOverlaySessionSlot() orelse return error.OverlayTableFull;
            slot.in_use = true;
            slot.session = session;
            slot.session.state = .established;
            session.state = .established;
            return session;
        }

        pub fn probeOverlaySession(self: *Self, session_id: u64, tick: u64) Error!bool {
            const session = self.findOverlaySession(session_id) orelse return error.OverlaySessionNotFound;
            if (session.state != .established) return false;
            session.keepalive_count += 1;
            session.last_activity_tick = tick;
            return true;
        }

        pub fn closeOverlaySession(self: *Self, session_id: u64, tick: u64) Error!bool {
            const session = self.findOverlaySession(session_id) orelse return error.OverlaySessionNotFound;
            if (session.state == .closed) return false;
            session.state = .closed;
            session.last_activity_tick = tick;
            return true;
        }

        pub fn setReplicaVersion(
            self: *Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
            object_id: anytype,
            version_id: anytype,
        ) Error!void {
            if (path.len > workspace.MAX_ENTRY_PATH_BYTES) return error.PathTooLong;
            try self.setReplicaVersionForPathHash(workspace_id, device_id, path, workspace.pathHash(path), object_id, version_id);
        }

        pub fn replicaVersion(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?u64 {
            const slot = self.lookupReplicaSlotConst(workspace_id, device_id, path, workspace.pathHash(path)) orelse return null;
            return slot.entry.version_id;
        }

        pub fn registerDatabaseContract(
            self: *Self,
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
            slot.contract.bundle_id_len = native_util.copyTextExact(&slot.contract.bundle_id, bundle_id) catch return error.BundleIdTooLong;
            slot.contract.label_len = native_util.copyTextExact(&slot.contract.label, label) catch return error.LabelTooLong;
            slot.contract.signature = signature;

            try self.checkpoint();
            return &slot.contract;
        }

        pub fn replicateWorkspace(
            self: *Self,
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
                const entry_path = entry.pathSlice();
                const entry_path_hash = entry.pathHash();
                const remote_version_id = self.replicaVersionForPathHash(workspace_id, to_device, entry_path, entry_path_hash) orelse 0;

                switch (semantic) {
                    .mergeable_crdt => {
                        const result = try self.mergeable_document_adapter.merge(.{
                            .store = store,
                            .entry = entry,
                            .remote_version_id = remote_version_id,
                        });
                        if (result.merged) summary.merged_count += 1;
                        if (result.conflict) {
                            try self.recordConflict(
                                workspace_id,
                                to_device,
                                entry.object_id.raw(),
                                entry_path,
                                entry.version_id.raw(),
                                remote_version_id,
                                semantic,
                            );
                        }
                    },
                    .chunked_snapshot => {
                        const result = try self.chunk_media_adapter.replicate(.{
                            .store = store,
                            .entry = entry,
                        });
                        if (result.snapshot_replicated) summary.snapshot_count += result.replicated_chunks;
                    },
                    .secure_transfer => {
                        const result = try self.secret_transfer_adapter.transfer(.{
                            .store = store,
                            .workspace_id = workspace_id,
                            .object_id = entry.object_id.raw(),
                            .from_device = from_device,
                            .to_device = to_device,
                            .personal_e2ee = policy.personal_e2ee,
                        });
                        if (result.transferred) summary.secret_transfer_count += 1;
                    },
                    .transactional_contract => summary.transactional_count += 1,
                }
                const frame = try self.transport_queue.enqueue(.{
                    .workspace_id = workspace_id,
                    .object_id = entry.object_id.raw(),
                    .version_id = entry.version_id.raw(),
                    .source_device = from_device,
                    .target_device = to_device,
                    .transport = transport,
                    .semantic = semantic,
                    .encrypted = policy.personal_e2ee,
                    .path = entry_path,
                });
                summary.transport_frame_count += 1;
                if (frame.encrypted) summary.encrypted_transport_count += 1;
                try self.setReplicaVersionForPathHash(workspace_id, to_device, entry_path, entry_path_hash, entry.object_id, entry.version_id);
            }
            summary.conflict_count = self.countConflictsFor(workspace_id, to_device);
            if (summary.selected_entry_count != 0 or summary.conflict_count != 0) {
                try self.checkpoint();
            }
            return summary;
        }

        pub fn transferSecretObject(
            self: *Self,
            storage: *const storage_service.Service,
            workspace_id: u64,
            object_id: anytype,
            from_device: principal.PrincipalId,
            to_device: principal.PrincipalId,
            transport: TransportMode,
        ) Error!bool {
            try self.ensureTrustedDevices(from_device, to_device);
            const policy = self.findWorkspacePolicy(workspace_id) orelse return error.WorkspacePolicyNotFound;
            if (!policy.personal_e2ee) return error.TransportDenied;
            try self.authorizeTransport(policy, transport, null);

            const result = try self.secret_transfer_adapter.transfer(.{
                .store = storage,
                .workspace_id = workspace_id,
                .object_id = object_store.ids.raw(object_id),
                .from_device = from_device,
                .to_device = to_device,
                .personal_e2ee = policy.personal_e2ee,
            });
            return result.transferred;
        }

        pub fn replicateDatabaseContract(
            self: *Self,
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
            const result = try self.database_sync_adapter.replicate(.{
                .contract = record,
                .workspace_id = workspace_id,
                .from_device = from_device,
                .to_device = to_device,
            });
            return result.replicated;
        }

        pub fn repairWorkspaceMetadata(
            self: *Self,
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

        pub fn trustedDeviceCount(self: *const Self) usize {
            return self.stateConst().graph.trustedDeviceCount();
        }

        pub fn findConflict(
            self: *Self,
            workspace_id: anytype,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?*ConflictRecord {
            const raw_workspace_id = object_store.ids.raw(workspace_id);
            for (&self.state().conflicts) |*slot| {
                if (!slot.in_use) continue;
                if (slot.conflict.workspace_id != raw_workspace_id) continue;
                if (!slot.conflict.device_id.eql(device_id)) continue;
                if (!std.mem.eql(u8, slot.conflict.pathSlice(), path)) continue;
                return &slot.conflict;
            }
            return null;
        }

        pub fn isTrustedDevice(self: *const Self, device_id: principal.PrincipalId) bool {
            return self.stateConst().graph.isTrusted(device_id);
        }

        fn checkpoint(self: *Self) Error!void {
            if (self.storage) |storage| {
                try state_store.persist(storage, self.state_workspace_id, self.residentConst());
            }
            self.resident().markDirty();
        }

        fn authorizeTransport(
            self: *Self,
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
            self: *Self,
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

        fn ensureTrustedDevices(self: *Self, from_device: principal.PrincipalId, to_device: principal.PrincipalId) Error!void {
            if (!self.state().graph.isTrusted(from_device) or !self.state().graph.isTrusted(to_device)) {
                return error.DeviceNotTrusted;
            }
        }

        fn allocateOverlaySessionSlot(self: *Self) ?*OverlaySessionSlot {
            for (&self.overlay_sessions) |*slot| {
                if (!slot.in_use) return slot;
            }
            for (&self.overlay_sessions) |*slot| {
                if (slot.session.state == .closed) return slot;
            }
            return null;
        }

        fn nextOverlaySessionId(self: *Self) u64 {
            defer self.next_overlay_session_id += 1;
            return self.next_overlay_session_id;
        }

        fn recordConflict(
            self: *Self,
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
            slot.conflict.path_len = native_util.copyTextExact(&slot.conflict.path, path) catch return error.PathTooLong;
            slot.conflict.local_version_id = local_version_id;
            slot.conflict.remote_version_id = remote_version_id;
            slot.conflict.semantic = semantic;
            self.resident().markDirty();
        }

        fn countConflictsFor(self: *const Self, workspace_id: u64, device_id: principal.PrincipalId) usize {
            var count: usize = 0;
            for (self.stateConst().conflicts) |slot| {
                if (!slot.in_use) continue;
                if (slot.conflict.workspace_id != workspace_id) continue;
                if (!slot.conflict.device_id.eql(device_id)) continue;
                count += 1;
            }
            return count;
        }

        fn clearConflictsFor(self: *Self, workspace_id: u64, device_id: principal.PrincipalId) Error!bool {
            var cleared = false;
            for (&self.state().conflicts) |*slot| {
                if (!slot.in_use) continue;
                if (slot.conflict.workspace_id != workspace_id) continue;
                if (!slot.conflict.device_id.eql(device_id)) continue;
                slot.* = .{};
                cleared = true;
            }
            if (cleared) self.resident().markDirty();
            return cleared;
        }

        fn findDatabaseContract(self: *Self, contract_id: u64) ?*DatabaseContract {
            const slot = fixed_table.findSlot(DatabaseContractSlot, MAX_DATABASE_CONTRACTS, &self.state().database_contracts, DatabaseContractLookup{
                .id = contract_id,
            }, databaseContractSlotMatches) orelse return null;
            return &slot.contract;
        }

        fn findEquivalentDatabaseContract(
            self: *Self,
            workspace_id: u64,
            bundle_id: []const u8,
            label: []const u8,
            signature: manifest.Signature,
        ) ?*DatabaseContract {
            const slot = fixed_table.findSlot(DatabaseContractSlot, MAX_DATABASE_CONTRACTS, &self.state().database_contracts, DatabaseContractEquivalentLookup{
                .workspace_id = workspace_id,
                .bundle_id = bundle_id,
                .label = label,
                .signature = signature,
            }, equivalentDatabaseContractSlotMatches) orelse return null;
            return &slot.contract;
        }

        fn lookupWorkspacePolicySlot(self: *Self, workspace_id: u64) ?*WorkspacePolicySlot {
            return fixed_table.findSlot(WorkspacePolicySlot, MAX_WORKSPACE_POLICIES, &self.state().workspace_policies, WorkspacePolicyLookup{
                .workspace_id = workspace_id,
            }, workspacePolicySlotMatches);
        }

        fn allocateWorkspacePolicy(self: *Self) ?*WorkspacePolicySlot {
            return fixed_table.firstFreeSlot(WorkspacePolicySlot, MAX_WORKSPACE_POLICIES, &self.state().workspace_policies);
        }

        fn lookupOverlaySlot(self: *Self, workspace_id: u64) ?*OverlaySlot {
            return fixed_table.findSlot(OverlaySlot, MAX_OVERLAYS, &self.state().overlays, OverlayLookup{
                .workspace_id = workspace_id,
            }, overlaySlotMatches);
        }

        fn allocateOverlay(self: *Self) ?*OverlaySlot {
            return fixed_table.firstFreeSlot(OverlaySlot, MAX_OVERLAYS, &self.state().overlays);
        }

        fn nextOverlayId(self: *Self) u64 {
            defer self.state().next_overlay_id += 1;
            return self.stateConst().next_overlay_id;
        }

        fn lookupReplicaSlotIndex(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
            path_hash: u64,
        ) ?usize {
            const slot_index = replicaIndexLookup(&self.replica_index_slots, replicaIndexKey(workspace_id, device_id, path_hash)) orelse return null;
            if (slot_index >= MAX_REPLICA_ENTRIES) native_util.impossibleByInvariant("replica index points outside slots");
            const slot = &self.stateConst().replica_entries[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("replica index points at a free slot");
            if (!replicaSlotMatches(.{
                .workspace_id = workspace_id,
                .device_id = device_id,
                .path = path,
                .path_hash = path_hash,
            }, slot)) {
                native_util.impossibleByInvariant("replica index points at the wrong slot");
            }
            return slot_index;
        }

        fn lookupReplicaSlotConst(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
            path_hash: u64,
        ) ?*const ReplicaSlot {
            const slot_index = self.lookupReplicaSlotIndex(workspace_id, device_id, path, path_hash) orelse return null;
            return &self.stateConst().replica_entries[slot_index];
        }

        fn replicaVersionForPathHash(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
            path_hash: u64,
        ) ?u64 {
            const slot = self.lookupReplicaSlotConst(workspace_id, device_id, path, path_hash) orelse return null;
            return slot.entry.version_id;
        }

        fn setReplicaVersionForPathHash(
            self: *Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
            path_hash: u64,
            object_id: anytype,
            version_id: anytype,
        ) Error!void {
            if (path.len > workspace.MAX_ENTRY_PATH_BYTES) return error.PathTooLong;
            const slot_index = if (self.lookupReplicaSlotIndex(workspace_id, device_id, path, path_hash)) |existing_index|
                existing_index
            else
                fixed_table.firstFreeSlotIndex(ReplicaSlot, MAX_REPLICA_ENTRIES, &self.stateConst().replica_entries) orelse return error.ReplicaTableFull;
            const slot = &self.state().replica_entries[slot_index];
            slot.in_use = true;
            slot.entry.workspace_id = workspace_id;
            slot.entry.device_id = device_id;
            slot.entry.path_len = native_util.copyTextExact(&slot.entry.path, path) catch return error.PathTooLong;
            slot.entry.object_id = object_store.ids.raw(object_id);
            slot.entry.version_id = object_store.ids.raw(version_id);
            replicaIndexInsert(&self.replica_index_slots, replicaIndexKey(workspace_id, device_id, path_hash), slot_index);
            self.resident().markDirty();
        }

        fn rebuildReplicaIndex(self: *Self) void {
            self.replica_index_slots = emptyReplicaIndex();
            for (self.stateConst().replica_entries, 0..) |slot, slot_index| {
                if (!slot.in_use) continue;
                replicaIndexInsert(
                    &self.replica_index_slots,
                    replicaIndexKey(slot.entry.workspace_id, slot.entry.device_id, slot.entry.pathHash()),
                    slot_index,
                );
            }
        }

        fn allocateConflict(self: *Self) ?*ConflictSlot {
            return fixed_table.firstFreeSlot(ConflictSlot, MAX_CONFLICTS, &self.state().conflicts);
        }

        fn allocateDatabaseContract(self: *Self) ?*DatabaseContractSlot {
            return fixed_table.firstFreeSlot(DatabaseContractSlot, MAX_DATABASE_CONTRACTS, &self.state().database_contracts);
        }

        fn nextDatabaseContractId(self: *Self) u64 {
            defer self.state().next_contract_id += 1;
            return self.stateConst().next_contract_id;
        }

        fn resident(self: *Self) *ResidentState {
            return self.resident_store orelse &self.owned_resident_state;
        }

        fn residentConst(self: *const Self) *ResidentState {
            return self.resident_store orelse @constCast(&self.owned_resident_state);
        }

        fn state(self: *Self) *PersistentState {
            return &self.resident().persisted_state;
        }

        fn stateConst(self: *const Self) *const PersistentState {
            return &self.residentConst().persisted_state;
        }
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
