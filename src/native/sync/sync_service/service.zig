const std = @import("std");
const capability = @import("../../kernel_api/capability.zig");
const device_graph = @import("../device_graph.zig");
const fixed_table = @import("../../core/fixed_table.zig");
const indexed_arena = @import("../../core/indexed_arena.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const network_policy = @import("../network_policy.zig");
const object_store = @import("../../storage/object_store.zig");
const principal = @import("../../core/principal.zig");
const service_authority = @import("../../services/service_authority.zig");
const signing = @import("../../core/signing.zig");
const sync_adapters = @import("../sync_adapters.zig");
const state_store = @import("../sync_state_store.zig");
const state_support = @import("../sync_state_support.zig");
const sync_transport = @import("../sync_transport.zig");
const storage_service = @import("../../storage/storage_service.zig");
const workspace = @import("../../storage/workspace.zig");
const sync_contracts = @import("contracts.zig");
const sync_indexes = @import("indexes.zig");
const latest_mutations = @import("latest_mutations.zig");
const overlay_model = @import("overlay.zig");
const overlay_sessions = @import("overlay_sessions.zig");
const replication_ops = @import("replication.zig");
const replication_model = @import("replication_model.zig");
const sync_semantics = @import("semantics.zig");

pub const MAX_WORKSPACE_POLICIES = state_support.MAX_WORKSPACE_POLICIES;
pub const MAX_SELECTIVE_PREFIXES = state_support.MAX_SELECTIVE_PREFIXES;
pub const MAX_PREFIX_BYTES = state_support.MAX_PREFIX_BYTES;
pub const MAX_REPLICA_ENTRIES = state_support.MAX_REPLICA_ENTRIES;
pub const MAX_CONFLICTS = state_support.MAX_CONFLICTS;
pub const MAX_DATABASE_CONTRACTS = state_support.MAX_DATABASE_CONTRACTS;
pub const MAX_OVERLAYS = state_support.MAX_OVERLAYS;
pub const MAX_PRIVATE_SERVICES = state_support.MAX_PRIVATE_SERVICES;
pub const MAX_LABEL_BYTES = state_support.MAX_LABEL_BYTES;
pub const MAX_TRANSPORT_FRAMES = state_support.MAX_TRANSPORT_FRAMES;
pub const MAX_OVERLAY_SESSIONS = overlay_model.MAX_OVERLAY_SESSIONS;
pub const ServiceConfig = overlay_model.ServiceConfig;
pub const TransportMode = state_support.TransportMode;
pub const SyncSemantic = state_support.SyncSemantic;
pub const WorkspacePolicyRequest = state_support.WorkspacePolicyRequest;
pub const WorkspacePolicy = state_support.WorkspacePolicy;
pub const OverlayRecord = state_support.OverlayRecord;
pub const OverlaySessionUse = overlay_model.OverlaySessionUse;
pub const OverlaySessionState = overlay_model.OverlaySessionState;
pub const OverlaySession = overlay_model.OverlaySession;
pub const OverlayRelayFrameRequest = overlay_model.OverlayRelayFrameRequest;
pub const OverlayRelayFrameResult = overlay_model.OverlayRelayFrameResult;
pub const ReplicaEntry = state_support.ReplicaEntry;
pub const ConflictRecord = state_support.ConflictRecord;
pub const ConflictReviewDecision = state_support.ConflictReviewDecision;
pub const ConflictReviewRecord = state_support.ConflictReviewRecord;
pub const DatabaseContract = state_support.DatabaseContract;
pub const ReplicationSummary = state_support.ReplicationSummary;
pub const PeerReplicationRequest = replication_model.PeerReplicationRequest;
pub const PeerReplicationResult = replication_model.PeerReplicationResult;
pub const MergeableDocumentAdapter = sync_adapters.MergeableDocumentAdapter;
pub const ChunkMediaAdapter = sync_adapters.ChunkMediaAdapter;
pub const SecretTransferAdapter = sync_adapters.SecretTransferAdapter;
pub const DatabaseSyncAdapter = sync_adapters.DatabaseSyncAdapter;
pub const TransportFrame = sync_adapters.TransportFrame;
pub const TransportFrameRequest = sync_adapters.QueueFrameRequest;
pub const TransportQueue = sync_adapters.TransportQueue;
pub const Error = state_support.Error;
pub const AuthorityContext = service_authority.Context;
pub const AuthorityError = service_authority.Error;
pub const PeerReplicationError = AuthorityError || Error || sync_transport.Error;

const WorkspacePolicySlot = state_support.WorkspacePolicySlot;
const ReplicaSlot = state_support.ReplicaSlot;
const ConflictSlot = state_support.ConflictSlot;
const DatabaseContractSlot = state_support.DatabaseContractSlot;
const OverlaySlot = state_support.OverlaySlot;
const DurableTransportFrameSlot = state_support.DurableTransportFrameSlot;
const PersistentState = state_support.PersistentState;
const TransportQueueKind = state_support.TransportQueueKind;
pub const ResidentState = state_support.ResidentState;
const zeroConflict = state_support.zeroConflict;
const zeroDatabaseContract = state_support.zeroDatabaseContract;
const zeroOverlay = state_support.zeroOverlay;
const zeroWorkspacePolicy = state_support.zeroWorkspacePolicy;

const OverlaySessionSlot = overlay_model.OverlaySessionSlot;
const WorkspacePolicyLookup = sync_indexes.WorkspacePolicyLookup;
const OverlayLookup = sync_indexes.OverlayLookup;
const DatabaseContractLookup = sync_indexes.DatabaseContractLookup;
const DatabaseContractEquivalentLookup = sync_indexes.DatabaseContractEquivalentLookup;
const ReplicaIndex = sync_indexes.ReplicaIndex;
pub const Service = ServiceWith(.{});

const sync_port = @import("port.zig");
pub const SyncPort = sync_port.SyncPortWith(Service);

pub fn mintEndpointConnectAuthority(
    capability_table: *capability.CapabilityTable,
    sync: *const Service,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = sync.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = sync.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = sync.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = issued_at_ticks,
            .expires_at_ticks = expires_at_ticks,
        },
        .audit = .{},
    });
}

pub fn authorityContext(
    sync: *const Service,
    authority_capability: capability.Capability,
    now_ticks: u64,
) AuthorityContext {
    return .{
        .task_id = sync.task_id,
        .principal = sync.owner,
        .capability_id = authority_capability.id,
        .now_ticks = now_ticks,
    };
}

pub fn ServiceWith(comptime config: ServiceConfig) type {
    config.validate();
    return struct {
        const Self = @This();
        const MAX_SERVICE_OVERLAY_SESSIONS = config.max_overlay_sessions;
        const OVERLAY_SESSION_INDEX_CAPACITY: usize = MAX_SERVICE_OVERLAY_SESSIONS * 2;
        const OverlaySessionArena = indexed_arena.IndexedArenaWithKey(u64, OverlaySessionSlot, MAX_SERVICE_OVERLAY_SESSIONS, OVERLAY_SESSION_INDEX_CAPACITY, overlay_model.sessionSlotId);
        const ClosedOverlaySessionIndex = indexed_arena.MultimapIndex(MAX_SERVICE_OVERLAY_SESSIONS, MAX_SERVICE_OVERLAY_SESSIONS, OVERLAY_SESSION_INDEX_CAPACITY);

        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        loaded_existing_state: bool = false,
        storage: ?*storage_service.Service = null,
        state_workspace_id: u64 = 0,
        resident_store: ?*ResidentState = null,
        owned_resident_state: ResidentState = .{},
        replica_index: ReplicaIndex = ReplicaIndex.init(),
        next_overlay_session_id: u64 = 1,
        overlay_sessions: OverlaySessionArena = OverlaySessionArena.init(),
        closed_overlay_sessions: ClosedOverlaySessionIndex = ClosedOverlaySessionIndex.init(),
        active_overlay_session_count: usize = 0,
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
                .overlay_sessions = OverlaySessionArena.init(),
                .closed_overlay_sessions = ClosedOverlaySessionIndex.init(),
                .active_overlay_session_count = 0,
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
                .overlay_sessions = OverlaySessionArena.init(),
                .closed_overlay_sessions = ClosedOverlaySessionIndex.init(),
                .active_overlay_session_count = 0,
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
                .overlay_sessions = OverlaySessionArena.init(),
                .closed_overlay_sessions = ClosedOverlaySessionIndex.init(),
                .active_overlay_session_count = 0,
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
            return self.transportFrameSlotCount(.outbound) + self.transportFrameSlotCount(.inbound);
        }

        pub fn latestTransportFrameId(self: *const Self) u64 {
            const next_id = self.stateConst().next_transport_frame_id;
            return if (next_id == 1) 0 else next_id - 1;
        }

        pub fn overlaySessionCapacity(self: *const Self) usize {
            _ = self;
            return MAX_SERVICE_OVERLAY_SESSIONS;
        }

        pub fn transportFrameCountFor(self: *const Self, workspace_id: u64, device_id: principal.PrincipalId) usize {
            return self.transportFrameSlotCountFor(.outbound, workspace_id, device_id) +
                self.transportFrameSlotCountFor(.inbound, workspace_id, device_id);
        }

        pub fn copyTransportFramesForSince(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            min_frame_id: u64,
            out: []TransportFrame,
        ) usize {
            return self.copyTransportFrameSlotsForSince(.outbound, workspace_id, device_id, min_frame_id, out);
        }

        pub fn latestTransportFrameForPath(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?TransportFrame {
            const outbound = self.latestTransportFrameSlotForPath(.outbound, workspace_id, device_id, path);
            const inbound = self.latestTransportFrameSlotForPath(.inbound, workspace_id, device_id, path);
            if (outbound == null) return inbound;
            if (inbound == null) return outbound;
            return if (outbound.?.id >= inbound.?.id) outbound else inbound;
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

        pub fn enrollPlatformBackedDevice(
            self: *Self,
            user_principal: principal.PrincipalId,
            device_principal: principal.PrincipalId,
            label: []const u8,
            authorizer: signing.SignerIdentity,
            device_identity: signing.SignerIdentity,
            platform_key: device_graph.PlatformKeyBindingRequest,
            tick: u64,
        ) Error!*device_graph.DeviceRecord {
            const record = try self.state().graph.enrollPlatformBackedDevice(user_principal, device_principal, label, authorizer, device_identity, platform_key, tick);
            try self.checkpoint();
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

        pub fn rotatePlatformBackedDeviceKey(
            self: *Self,
            user_principal: principal.PrincipalId,
            device_principal: principal.PrincipalId,
            authorizer: signing.SignerIdentity,
            next_device_identity: signing.SignerIdentity,
            platform_key: device_graph.PlatformKeyBindingRequest,
            tick: u64,
        ) Error!*device_graph.DeviceRecord {
            const record = try self.state().graph.rotatePlatformBackedDeviceKey(user_principal, device_principal, authorizer, next_device_identity, platform_key, tick);
            try self.checkpoint();
            return record;
        }

        pub fn revokeTrustedDevice(
            self: *Self,
            user_principal: principal.PrincipalId,
            device_principal: principal.PrincipalId,
            authorizer: signing.SignerIdentity,
            tick: u64,
        ) Error!void {
            const was_platform_backed = if (self.state().graph.findDevice(device_principal)) |record|
                record.usesPlatformBackedKey()
            else
                false;
            try self.state().graph.revokeDevice(user_principal, device_principal, authorizer, tick);
            if (was_platform_backed) {
                try self.checkpoint();
            } else {
                self.resident().markDirty();
            }
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
            slot.policy.require_shared_access = request.require_shared_access;
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
            const slot = self.overlay_sessions.get(session_id) orelse return null;
            return &slot.session;
        }

        pub fn activeOverlaySessionCount(self: *const Self) usize {
            return self.active_overlay_session_count;
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

            const slot = self.allocateOverlaySessionSlot(session.session_id) orelse return error.OverlayTableFull;
            slot.session = session;
            slot.session.state = .established;
            self.overlay_sessions.clearDirty();
            self.active_overlay_session_count += 1;
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
            const slot_index = self.overlay_sessions.slotIndexOf(session_id) orelse return error.OverlaySessionNotFound;
            if (slot_index >= MAX_SERVICE_OVERLAY_SESSIONS) native_util.impossibleByInvariant("overlay session primary index points outside slots");
            const session = &self.overlay_sessions.slots[slot_index].session;
            if (session.state == .closed) return false;
            if (session.state == .established and self.active_overlay_session_count != 0) {
                self.active_overlay_session_count -= 1;
            }
            session.state = .closed;
            session.last_activity_tick = tick;
            self.overlay_sessions.markDirty(session_id);
            self.overlay_sessions.clearDirty();
            if (!self.closed_overlay_sessions.append(overlay_model.closed_session_key, slot_index)) {
                native_util.impossibleByInvariant("closed overlay session index capacity covers overlay session slots");
            }
            return true;
        }

        pub fn sendOverlayRelayFrame(
            self: *Self,
            network_capabilities: *const capability.CapabilityTable,
            relay: *sync_transport.Relay,
            request: OverlayRelayFrameRequest,
        ) (Error || sync_transport.Error)!OverlayRelayFrameResult {
            return overlay_sessions.sendOverlayRelayFrame(self, network_capabilities, relay, request);
        }

        pub fn sendOverlayRelayFrameViaService(
            self: *Self,
            network_capabilities: *const capability.CapabilityTable,
            relay_service: *sync_transport.BootedOverlayRelayService,
            request: OverlayRelayFrameRequest,
        ) (Error || sync_transport.Error)!OverlayRelayFrameResult {
            return overlay_sessions.sendOverlayRelayFrameViaService(self, network_capabilities, relay_service, request);
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
            try self.setReplicaVersionForPathHash(workspace_id, device_id, path, workspace.pathHash(path), object_id, version_id, 0);
            try self.checkpoint();
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
            const message = state_support.databaseContractMessage(&message_buffer, workspace_id, bundle_id, label) catch return error.InvalidContractSignature;
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

        pub fn importDatabaseContract(self: *Self, source: *const DatabaseContract) Error!*DatabaseContract {
            try sync_contracts.validateDatabaseContractSignature(source);
            if (self.findEquivalentDatabaseContract(
                source.workspace_id,
                source.bundleIdSlice(),
                source.labelSlice(),
                source.signature,
            )) |existing| {
                return existing;
            }

            const slot = self.allocateDatabaseContract() orelse return error.DatabaseContractTableFull;
            slot.in_use = true;
            slot.contract = source.*;
            slot.contract.id = self.nextDatabaseContractId();

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
            try self.authorizeWorkspaceAnyShare(store, policy, to_device, transport);
            try self.evaluateOverlay(policy, workspace_id, &summary);

            const last_replicated_generation = self.replicaWorkspaceGeneration(workspace_id, to_device);
            const changes = try store.entryChangesSince(workspace_id, last_replicated_generation);
            const latest_mutation_index = latest_mutations.build(changes);
            try self.preflightTransactionalEntries(workspace_id, to_device, changes, latest_mutation_index, policy);
            for (changes, 0..) |mutation, mutation_index| {
                const entry = mutation.entry;
                if (!latest_mutation_index.isLatest(changes, mutation_index)) continue;
                if (!policy.matchesPath(entry.pathSlice())) {
                    summary.skipped_entry_count += 1;
                    continue;
                }
                if (!self.workspaceEntryShareAllowed(store, policy, to_device, transport, entry)) {
                    summary.skipped_entry_count += 1;
                    summary.share_denied_entry_count += 1;
                    continue;
                }

                const semantic = sync_semantics.classifyEntry(entry);
                const entry_path = entry.pathSlice();
                const entry_path_hash = entry.pathHash();
                const remote_version_id = self.replicaVersionForPathHash(workspace_id, to_device, entry_path, entry_path_hash) orelse 0;
                if (remote_version_id == entry.version_id.raw()) continue;
                summary.selected_entry_count += 1;

                try replication_ops.applyOutboundSemantic(
                    self,
                    store,
                    workspace_id,
                    from_device,
                    to_device,
                    policy,
                    entry,
                    semantic,
                    remote_version_id,
                    &summary,
                );
                const frame = try self.enqueueTransportFrame(.outbound, .{
                    .workspace_id = workspace_id,
                    .object_id = entry.object_id.raw(),
                    .version_id = entry.version_id.raw(),
                    .source_device = from_device,
                    .target_device = to_device,
                    .transport = transport,
                    .semantic = semantic,
                    .encrypted = policy.personal_e2ee,
                    .workspace_generation = mutation.generation,
                    .path = entry_path,
                });
                summary.transport_frame_count += 1;
                if (frame.encrypted) summary.encrypted_transport_count += 1;
                try self.setReplicaVersionForPathHash(workspace_id, to_device, entry_path, entry_path_hash, entry.object_id, entry.version_id, mutation.generation);
            }
            summary.conflict_count = self.countConflictsFor(workspace_id, to_device);
            if (summary.selected_entry_count != 0 or summary.conflict_count != 0) {
                try self.checkpoint();
            }
            return summary;
        }

        pub fn acceptTransportFrame(
            self: *Self,
            store: *const storage_service.Service,
            request: TransportFrameRequest,
        ) Error!TransportFrame {
            try self.ensureTrustedDevices(request.source_device, request.target_device);
            const policy = self.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
            try self.authorizeTransport(policy, request.transport, null);
            try self.authorizeWorkspaceFrameShare(store, policy, request);
            if (policy.personal_e2ee and !request.encrypted) return error.TransportDenied;
            if (self.findDuplicateInboundFrame(request)) |duplicate| {
                try self.recordDuplicateInboundFrame(duplicate.frame.id);
                return duplicate.frame;
            }
            if (self.replayWindowRejects(request)) return error.TransportReplayRejected;

            const entry = store.resolve(request.workspace_id, request.path) catch |err| switch (err) {
                error.EntryNotFound => return error.VersionNotFound,
                else => return err,
            };
            if (entry.object_id.raw() != request.object_id or entry.version_id.raw() != request.version_id) {
                return error.VersionNotFound;
            }
            const expected_semantic = sync_semantics.classifyEntry(entry);
            if (request.semantic != expected_semantic) return error.SyncSemanticMismatch;

            try replication_ops.applyInboundSemantic(self, store, entry, request, policy, expected_semantic);

            const accepted = try self.enqueueTransportFrame(.inbound, request);
            try self.setReplicaVersionForPathHash(
                request.workspace_id,
                request.target_device,
                accepted.pathSlice(),
                workspace.pathHash(accepted.pathSlice()),
                request.object_id,
                request.version_id,
                request.workspace_generation,
            );
            try self.checkpoint();
            return accepted;
        }

        pub fn ackOutboundTransportFrame(self: *Self, frame_id: u64) Error!bool {
            for (&self.state().outbound_transport_frames) |*slot| {
                if (!slot.in_use or slot.frame.id != frame_id) continue;
                if (slot.acked) return false;
                slot.acked = true;
                try self.checkpoint();
                return true;
            }
            return false;
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
            const slot = self.findConflictSlot(object_store.ids.raw(workspace_id), device_id, path) orelse return null;
            return &slot.conflict;
        }

        pub fn reviewConflict(
            self: *Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) Error!ConflictReviewRecord {
            const slot = self.findConflictSlot(workspace_id, device_id, path) orelse return error.ConflictNotFound;
            return conflictReviewRecord(&slot.conflict, .keep_local, false);
        }

        pub fn resolveConflict(
            self: *Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
            decision: ConflictReviewDecision,
        ) Error!ConflictReviewRecord {
            const slot = self.findConflictSlot(workspace_id, device_id, path) orelse return error.ConflictNotFound;
            const conflict = slot.conflict;
            const selected_version_id = switch (decision) {
                .keep_local, .keep_both => conflict.local_version_id,
                .accept_remote => blk: {
                    if (conflict.remote_version_id == 0) return error.VersionNotFound;
                    break :blk conflict.remote_version_id;
                },
            };
            try self.setReplicaVersionForPathHash(
                conflict.workspace_id,
                conflict.device_id,
                conflict.pathSlice(),
                workspace.pathHash(conflict.pathSlice()),
                conflict.object_id,
                selected_version_id,
                0,
            );
            slot.* = .{};
            try self.checkpoint();
            return conflictReviewRecord(&conflict, decision, true);
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

        pub fn authorizeTransport(
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

        fn authorizeWorkspaceAnyShare(
            self: *Self,
            store: *const storage_service.Service,
            policy: *const WorkspacePolicy,
            target_device: principal.PrincipalId,
            transport: TransportMode,
        ) Error!void {
            _ = self;
            if (!policy.require_shared_access) return;
            const scope = shareNetworkScopeForTransport(transport);
            if (!store.workspaceHasAnyAccess(policy.workspace_id, .{
                .principal_id = target_device,
                .network_scope = scope,
                .now_ticks = 0,
            })) return error.TransportDenied;
        }

        fn workspaceEntryShareAllowed(
            self: *Self,
            store: *const storage_service.Service,
            policy: *const WorkspacePolicy,
            target_device: principal.PrincipalId,
            transport: TransportMode,
            entry: workspace.Entry,
        ) bool {
            _ = self;
            if (!policy.require_shared_access) return true;
            return store.workspaceHasAccess(policy.workspace_id, .{
                .principal_id = target_device,
                .object_id = entry.object_id,
                .path = entry.pathSlice(),
                .network_scope = shareNetworkScopeForTransport(transport),
                .now_ticks = 0,
            });
        }

        fn authorizeWorkspaceFrameShare(
            self: *Self,
            store: *const storage_service.Service,
            policy: *const WorkspacePolicy,
            request: TransportFrameRequest,
        ) Error!void {
            _ = self;
            if (!policy.require_shared_access) return;
            if (!store.workspaceHasAccess(policy.workspace_id, .{
                .principal_id = request.target_device,
                .object_id = object_store.ids.object(request.object_id),
                .path = request.path,
                .network_scope = shareNetworkScopeForTransport(request.transport),
                .now_ticks = 0,
            })) return error.TransportDenied;
        }

        fn shareNetworkScopeForTransport(transport: TransportMode) workspace.ShareNetworkScope {
            return switch (transport) {
                .device_to_device => .local_only,
                .relay_assisted => .relay_assisted,
            };
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

        pub fn ensureTrustedDevices(self: *Self, from_device: principal.PrincipalId, to_device: principal.PrincipalId) Error!void {
            if (!self.state().graph.isTrusted(from_device) or !self.state().graph.isTrusted(to_device)) {
                return error.DeviceNotTrusted;
            }
        }

        fn allocateOverlaySessionSlot(self: *Self, session_id: u64) ?*OverlaySessionSlot {
            if (self.overlay_sessions.reserve(session_id)) |slot| return slot;

            const slot_index = self.closed_overlay_sessions.head(overlay_model.closed_session_key);
            if (slot_index == indexed_arena.no_index) return null;
            if (slot_index >= MAX_SERVICE_OVERLAY_SESSIONS) native_util.impossibleByInvariant("closed overlay session index points outside slots");
            _ = self.closed_overlay_sessions.remove(overlay_model.closed_session_key, slot_index);
            _ = self.overlay_sessions.removeIndex(slot_index);
            return self.overlay_sessions.reserveAtIndex(session_id, slot_index);
        }

        fn nextOverlaySessionId(self: *Self) u64 {
            defer self.next_overlay_session_id += 1;
            return self.next_overlay_session_id;
        }

        pub fn recordConflict(
            self: *Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            object_id: u64,
            path: []const u8,
            local_version_id: u64,
            remote_version_id: u64,
            semantic: SyncSemantic,
        ) Error!void {
            const slot = self.findConflictSlot(workspace_id, device_id, path) orelse self.allocateConflict() orelse return error.ConflictTableFull;
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

        fn findConflictSlot(
            self: *Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?*ConflictSlot {
            for (&self.state().conflicts) |*slot| {
                if (!slot.in_use) continue;
                if (slot.conflict.workspace_id != workspace_id) continue;
                if (!slot.conflict.device_id.eql(device_id)) continue;
                if (!std.mem.eql(u8, slot.conflict.pathSlice(), path)) continue;
                return slot;
            }
            return null;
        }

        fn conflictReviewRecord(
            conflict: *const ConflictRecord,
            decision: ConflictReviewDecision,
            resolved: bool,
        ) ConflictReviewRecord {
            return .{
                .workspace_id = conflict.workspace_id,
                .device_id = conflict.device_id,
                .object_id = conflict.object_id,
                .path_len = conflict.path_len,
                .path = conflict.path,
                .local_version_id = conflict.local_version_id,
                .remote_version_id = conflict.remote_version_id,
                .semantic = conflict.semantic,
                .decision = decision,
                .resolved = resolved,
            };
        }

        fn preflightTransactionalEntries(
            self: *Self,
            workspace_id: u64,
            to_device: principal.PrincipalId,
            changes: []const workspace.EntryMutation,
            latest_mutation_index: latest_mutations.Index,
            policy: *const WorkspacePolicy,
        ) Error!void {
            for (changes, 0..) |mutation, mutation_index| {
                const entry = mutation.entry;
                if (!latest_mutation_index.isLatest(changes, mutation_index)) continue;
                if (!policy.matchesPath(entry.pathSlice())) continue;
                if (sync_semantics.classifyEntry(entry) != .transactional_contract) continue;

                const remote_version_id = self.replicaVersionForPathHash(workspace_id, to_device, entry.pathSlice(), entry.pathHash()) orelse 0;
                if (remote_version_id == entry.version_id.raw()) continue;
                _ = self.findDatabaseContractForEntry(workspace_id, entry) orelse return error.DatabaseContractNotFound;
            }
        }

        fn findDatabaseContract(self: *Self, contract_id: u64) ?*DatabaseContract {
            const slot = fixed_table.findSlot(DatabaseContractSlot, MAX_DATABASE_CONTRACTS, &self.state().database_contracts, DatabaseContractLookup{
                .id = contract_id,
            }, sync_indexes.databaseContractSlotMatches) orelse return null;
            return &slot.contract;
        }

        fn findDatabaseContractForEntry(self: *Self, workspace_id: u64, entry: workspace.Entry) ?*DatabaseContract {
            return self.findDatabaseContractForPath(workspace_id, entry.pathSlice());
        }

        pub fn findDatabaseContractForPath(self: *Self, workspace_id: u64, path: []const u8) ?*DatabaseContract {
            const bundle_id = sync_contracts.databaseBundleIdFromPath(path) orelse return null;
            for (&self.state().database_contracts) |*slot| {
                if (!slot.in_use) continue;
                if (slot.contract.workspace_id != workspace_id) continue;
                if (!std.mem.eql(u8, slot.contract.bundleIdSlice(), bundle_id)) continue;
                return &slot.contract;
            }
            return null;
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
            }, sync_indexes.equivalentDatabaseContractSlotMatches) orelse return null;
            return &slot.contract;
        }

        fn lookupWorkspacePolicySlot(self: *Self, workspace_id: u64) ?*WorkspacePolicySlot {
            return fixed_table.findSlot(WorkspacePolicySlot, MAX_WORKSPACE_POLICIES, &self.state().workspace_policies, WorkspacePolicyLookup{
                .workspace_id = workspace_id,
            }, sync_indexes.workspacePolicySlotMatches);
        }

        fn allocateWorkspacePolicy(self: *Self) ?*WorkspacePolicySlot {
            return fixed_table.firstFreeSlot(WorkspacePolicySlot, MAX_WORKSPACE_POLICIES, &self.state().workspace_policies);
        }

        fn lookupOverlaySlot(self: *Self, workspace_id: u64) ?*OverlaySlot {
            return fixed_table.findSlot(OverlaySlot, MAX_OVERLAYS, &self.state().overlays, OverlayLookup{
                .workspace_id = workspace_id,
            }, sync_indexes.overlaySlotMatches);
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
            const slot_index = self.replica_index.lookup(sync_indexes.replicaIndexLookupKey(workspace_id, device_id, path_hash)) orelse return null;
            if (slot_index >= MAX_REPLICA_ENTRIES) native_util.impossibleByInvariant("replica index points outside slots");
            const slot = &self.stateConst().replica_entries[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("replica index points at a free slot");
            if (!sync_indexes.replicaSlotMatches(.{
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
            workspace_generation: u32,
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
            slot.entry.workspace_generation = workspace_generation;
            self.replica_index.insert(sync_indexes.replicaIndexLookupKey(workspace_id, device_id, path_hash), slot_index);
            self.resident().markDirty();
        }

        fn replicaWorkspaceGeneration(self: *const Self, workspace_id: u64, device_id: principal.PrincipalId) u32 {
            var generation: u32 = 0;
            for (self.stateConst().replica_entries) |slot| {
                if (!slot.in_use) continue;
                if (slot.entry.workspace_id != workspace_id or !slot.entry.device_id.eql(device_id)) continue;
                generation = @max(generation, slot.entry.workspace_generation);
            }
            return generation;
        }

        fn rebuildReplicaIndex(self: *Self) void {
            self.replica_index.reset();
            for (self.stateConst().replica_entries, 0..) |slot, slot_index| {
                if (!slot.in_use) continue;
                self.replica_index.insert(sync_indexes.replicaIndexLookupKey(slot.entry.workspace_id, slot.entry.device_id, slot.entry.pathHash()), slot_index);
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

        fn enqueueTransportFrame(self: *Self, queue_kind: TransportQueueKind, request: TransportFrameRequest) Error!TransportFrame {
            const slot = self.allocateTransportFrameSlot(queue_kind) orelse return error.TransportQueueFull;
            const frame_id = self.nextTransportFrameId();
            slot.* = .{};
            slot.in_use = true;
            slot.frame = .{
                .id = frame_id,
                .source_frame_id = if (request.source_frame_id == 0) frame_id else request.source_frame_id,
                .workspace_id = request.workspace_id,
                .object_id = request.object_id,
                .version_id = request.version_id,
                .source_device = request.source_device,
                .target_device = request.target_device,
                .transport = request.transport,
                .semantic = request.semantic,
                .encrypted = request.encrypted,
                .workspace_generation = request.workspace_generation,
            };
            slot.frame.path_len = try state_support.copyTransportPath(&slot.frame.path, request.path);
            self.resident().markDirty();
            return slot.frame;
        }

        fn nextTransportFrameId(self: *Self) u64 {
            const frame_id = self.stateConst().next_transport_frame_id;
            self.state().next_transport_frame_id +%= 1;
            if (self.stateConst().next_transport_frame_id == 0) self.state().next_transport_frame_id = 1;
            return frame_id;
        }

        fn allocateTransportFrameSlot(self: *Self, queue_kind: TransportQueueKind) ?*DurableTransportFrameSlot {
            for (self.transportFrameSlots(queue_kind)) |*slot| {
                if (!slot.in_use) return slot;
            }
            return null;
        }

        fn transportFrameSlotCount(self: *const Self, queue_kind: TransportQueueKind) usize {
            var count: usize = 0;
            for (self.transportFrameSlotsConst(queue_kind)) |slot| {
                if (slot.in_use) count += 1;
            }
            return count;
        }

        fn transportFrameSlotCountFor(self: *const Self, queue_kind: TransportQueueKind, workspace_id: u64, target_device: principal.PrincipalId) usize {
            var count: usize = 0;
            for (self.transportFrameSlotsConst(queue_kind)) |slot| {
                if (!slot.in_use) continue;
                if (slot.frame.workspace_id == workspace_id and slot.frame.target_device.eql(target_device)) {
                    count += 1;
                }
            }
            return count;
        }

        fn copyTransportFrameSlotsForSince(
            self: *const Self,
            queue_kind: TransportQueueKind,
            workspace_id: u64,
            target_device: principal.PrincipalId,
            min_frame_id: u64,
            out: []TransportFrame,
        ) usize {
            var copied: usize = 0;
            for (self.transportFrameSlotsConst(queue_kind)) |slot| {
                if (!slot.in_use or slot.acked) continue;
                if (slot.frame.workspace_id != workspace_id or !slot.frame.target_device.eql(target_device)) continue;
                if (slot.frame.id <= min_frame_id) continue;
                if (copied >= out.len) return copied;
                out[copied] = slot.frame;
                copied += 1;
            }
            return copied;
        }

        fn latestTransportFrameSlotForPath(
            self: *const Self,
            queue_kind: TransportQueueKind,
            workspace_id: u64,
            target_device: principal.PrincipalId,
            path: []const u8,
        ) ?TransportFrame {
            var latest: ?TransportFrame = null;
            for (self.transportFrameSlotsConst(queue_kind)) |slot| {
                if (!slot.in_use) continue;
                if (slot.frame.workspace_id != workspace_id or !slot.frame.target_device.eql(target_device)) continue;
                if (!std.mem.eql(u8, slot.frame.pathSlice(), path)) continue;
                if (latest == null or slot.frame.id > latest.?.id) latest = slot.frame;
            }
            return latest;
        }

        fn findDuplicateInboundFrame(self: *Self, request: TransportFrameRequest) ?*DurableTransportFrameSlot {
            if (request.source_frame_id == 0) return null;
            for (&self.state().inbound_transport_frames) |*slot| {
                if (!slot.in_use) continue;
                if (slot.frame.source_frame_id != request.source_frame_id) continue;
                if (slot.frame.workspace_id != request.workspace_id) continue;
                if (!slot.frame.source_device.eql(request.source_device)) continue;
                if (!slot.frame.target_device.eql(request.target_device)) continue;
                return slot;
            }
            return null;
        }

        fn recordDuplicateInboundFrame(self: *Self, frame_id: u64) Error!void {
            for (&self.state().inbound_transport_frames) |*slot| {
                if (!slot.in_use or slot.frame.id != frame_id) continue;
                if (slot.duplicate_count != std.math.maxInt(u16)) {
                    slot.duplicate_count += 1;
                }
                try self.checkpoint();
                return;
            }
        }

        fn replayWindowRejects(self: *const Self, request: TransportFrameRequest) bool {
            if (request.source_frame_id == 0) return false;
            var latest_source_frame_id: u64 = 0;
            for (self.stateConst().inbound_transport_frames) |slot| {
                if (!slot.in_use) continue;
                if (slot.frame.workspace_id != request.workspace_id) continue;
                if (!slot.frame.source_device.eql(request.source_device)) continue;
                if (!slot.frame.target_device.eql(request.target_device)) continue;
                latest_source_frame_id = @max(latest_source_frame_id, slot.frame.source_frame_id);
            }
            if (latest_source_frame_id < state_support.TRANSPORT_REPLAY_WINDOW) return false;
            return request.source_frame_id + state_support.TRANSPORT_REPLAY_WINDOW <= latest_source_frame_id;
        }

        fn transportFrameSlots(self: *Self, queue_kind: TransportQueueKind) []DurableTransportFrameSlot {
            return switch (queue_kind) {
                .outbound => self.state().outbound_transport_frames[0..],
                .inbound => self.state().inbound_transport_frames[0..],
            };
        }

        fn transportFrameSlotsConst(self: *const Self, queue_kind: TransportQueueKind) []const DurableTransportFrameSlot {
            return switch (queue_kind) {
                .outbound => self.stateConst().outbound_transport_frames[0..],
                .inbound => self.stateConst().inbound_transport_frames[0..],
            };
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
