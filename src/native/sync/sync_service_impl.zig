const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const device_graph = @import("device_graph.zig");
const fixed_table = @import("../core/fixed_table.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const network_policy = @import("network_policy.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const service_authority = @import("../services/service_authority.zig");
const signing = @import("../core/signing.zig");
const sync_adapters = @import("sync_adapters.zig");
const state_store = @import("sync_state_store.zig");
const state_support = @import("sync_state_support.zig");
const sync_transport = @import("sync_transport_harness.zig");
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
pub const MAX_TRANSPORT_FRAMES = state_support.MAX_TRANSPORT_FRAMES;
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
pub const OverlayRelayFrameRequest = struct {
    workspace_id: u64,
    from_device: principal.PrincipalId,
    to_device: principal.PrincipalId,
    usage: OverlaySessionUse,
    private_service_label: ?[]const u8 = null,
    relay_capability_id: u64,
    payload: []const u8,
    signer: signing.SignerIdentity,
    tick: u64,
};
pub const OverlayRelayFrameResult = struct {
    overlay_session_id: u64,
    transport_session_id: u64,
    usage: OverlaySessionUse,
    encrypted: bool,
    relay_encrypted: bool,
    remote_access: bool,
    egress_allowed: bool,
    delivered: bool,
    delivered_len: usize,
    packet_digest: [32]u8,
    service_identity_len: usize = 0,
    service_identity: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    relay_domain_len: usize = 0,
    relay_domain: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    private_service_len: usize = 0,
    private_service: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,

    pub fn serviceIdentitySlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.service_identity[0..self.service_identity_len];
    }

    pub fn relayDomainSlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.relay_domain[0..self.relay_domain_len];
    }

    pub fn privateServiceSlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.private_service[0..self.private_service_len];
    }
};
pub const ReplicaEntry = state_support.ReplicaEntry;
pub const ConflictRecord = state_support.ConflictRecord;
pub const DatabaseContract = state_support.DatabaseContract;
pub const ReplicationSummary = state_support.ReplicationSummary;
pub const PeerReplicationRequest = struct {
    source_storage: *const storage_service.Service,
    target_storage: *storage_service.Service,
    workspace_id: u64,
    from_device: principal.PrincipalId,
    to_device: principal.PrincipalId,
    transport: TransportMode,
    network_capabilities: ?*const capability.CapabilityTable = null,
    relay_service: ?*sync_transport.BootedOverlayRelayService = null,
    relay_capability_id: u64 = 0,
    signer: signing.SignerIdentity,
    tick: u64,
};
pub const PeerReplicationResult = struct {
    summary: ReplicationSummary,
    accepted_frame_count: usize = 0,
    persisted_object_count: usize = 0,
    relay_delivery_count: usize = 0,
    payload_bytes: usize = 0,
    used_booted_relay_service: bool = false,
};
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

const ReplicaIndex = indexed_arena.UniqueIndex(REPLICA_INDEX_CAPACITY);
const CLOSED_OVERLAY_SESSION_KEY: u64 = 1;

fn replicaIndexKey(workspace_id: u64, device_id: principal.PrincipalId, path_hash: u64) ReplicaIndexKey {
    return .{
        .workspace_id = workspace_id,
        .device_id = device_id,
        .path_hash = path_hash,
    };
}

fn replicaIndexLookupKey(workspace_id: u64, device_id: principal.PrincipalId, path_hash: u64) u64 {
    return indexed_arena.nonZeroKey(replicaIndexHash(replicaIndexKey(workspace_id, device_id, path_hash)));
}

fn replicaIndexHash(key: ReplicaIndexKey) u64 {
    var hash: u64 = 0xCBF2_9CE4_8422_2325;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.workspace_id);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(key.device_id.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.device_id.serial);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, key.path_hash);
    return hash;
}

fn overlaySessionSlotId(slot: *const OverlaySessionSlot) u64 {
    return slot.session.session_id;
}

pub const Service = ServiceWith(.{});

pub const SyncPort = struct {
    service: *Service,
    capability_table: *const capability.CapabilityTable,

    pub fn init(service: *Service, capability_table: *const capability.CapabilityTable) SyncPort {
        return .{
            .service = service,
            .capability_table = capability_table,
        };
    }

    pub fn ensureUserRoot(
        self: *SyncPort,
        authority: AuthorityContext,
        user_principal: principal.PrincipalId,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) (AuthorityError || Error)!*device_graph.UserRootRecord {
        _ = try self.requireSyncAuthority(authority);
        return self.service.ensureUserRoot(user_principal, label, identity);
    }

    pub fn enrollTrustedDevice(
        self: *SyncPort,
        authority: AuthorityContext,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        label: []const u8,
        authorizer: signing.SignerIdentity,
        device_identity: signing.SignerIdentity,
        tick: u64,
    ) (AuthorityError || Error)!*device_graph.DeviceRecord {
        _ = try self.requireSyncAuthority(authority);
        return self.service.enrollTrustedDevice(user_principal, device_principal, label, authorizer, device_identity, tick);
    }

    pub fn enrollPlatformBackedDevice(
        self: *SyncPort,
        authority: AuthorityContext,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        label: []const u8,
        authorizer: signing.SignerIdentity,
        device_identity: signing.SignerIdentity,
        platform_key: device_graph.PlatformKeyBindingRequest,
        tick: u64,
    ) (AuthorityError || Error)!*device_graph.DeviceRecord {
        _ = try self.requireSyncAuthority(authority);
        return self.service.enrollPlatformBackedDevice(user_principal, device_principal, label, authorizer, device_identity, platform_key, tick);
    }

    pub fn rotateDeviceKey(
        self: *SyncPort,
        authority: AuthorityContext,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        next_device_identity: signing.SignerIdentity,
        tick: u64,
    ) (AuthorityError || Error)!*device_graph.DeviceRecord {
        _ = try self.requireSyncAuthority(authority);
        return self.service.rotateDeviceKey(user_principal, device_principal, authorizer, next_device_identity, tick);
    }

    pub fn rotatePlatformBackedDeviceKey(
        self: *SyncPort,
        authority: AuthorityContext,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        next_device_identity: signing.SignerIdentity,
        platform_key: device_graph.PlatformKeyBindingRequest,
        tick: u64,
    ) (AuthorityError || Error)!*device_graph.DeviceRecord {
        _ = try self.requireSyncAuthority(authority);
        return self.service.rotatePlatformBackedDeviceKey(user_principal, device_principal, authorizer, next_device_identity, platform_key, tick);
    }

    pub fn revokeTrustedDevice(
        self: *SyncPort,
        authority: AuthorityContext,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        tick: u64,
    ) (AuthorityError || Error)!void {
        _ = try self.requireSyncAuthority(authority);
        return self.service.revokeTrustedDevice(user_principal, device_principal, authorizer, tick);
    }

    pub fn createNetworkPolicy(
        self: *SyncPort,
        authority: AuthorityContext,
        request: network_policy.CreateRequest,
    ) (AuthorityError || Error)!*network_policy.PolicyRecord {
        _ = try self.requireSyncAuthority(authority);
        return self.service.createNetworkPolicy(request);
    }

    pub fn evaluateNetworkPolicy(
        self: *SyncPort,
        authority: AuthorityContext,
        policy_id: u64,
        destination: network_policy.Destination,
    ) (AuthorityError || Error)!network_policy.Decision {
        _ = try self.requireSyncAuthority(authority);
        return self.service.evaluateNetworkPolicy(policy_id, destination);
    }

    pub fn configureWorkspacePolicy(
        self: *SyncPort,
        authority: AuthorityContext,
        request: WorkspacePolicyRequest,
    ) (AuthorityError || Error)!*WorkspacePolicy {
        _ = try self.requireSyncAuthority(authority);
        return self.service.configureWorkspacePolicy(request);
    }

    pub fn configureOverlay(
        self: *SyncPort,
        authority: AuthorityContext,
        workspace_id: u64,
        home_device: principal.PrincipalId,
        service_identity: []const u8,
        remote_access_enabled: bool,
    ) (AuthorityError || Error)!*OverlayRecord {
        _ = try self.requireSyncAuthority(authority);
        return self.service.configureOverlay(workspace_id, home_device, service_identity, remote_access_enabled);
    }

    pub fn publishPrivateService(
        self: *SyncPort,
        authority: AuthorityContext,
        workspace_id: u64,
        label: []const u8,
    ) (AuthorityError || Error)!*OverlayRecord {
        _ = try self.requireSyncAuthority(authority);
        return self.service.publishPrivateService(workspace_id, label);
    }

    pub fn openOverlaySession(
        self: *SyncPort,
        authority: AuthorityContext,
        workspace_id: u64,
        from_device: principal.PrincipalId,
        to_device: principal.PrincipalId,
        usage: OverlaySessionUse,
        transport: TransportMode,
        private_service_label: ?[]const u8,
        tick: u64,
    ) (AuthorityError || Error)!OverlaySession {
        _ = try self.requireSyncAuthority(authority);
        return self.service.openOverlaySession(workspace_id, from_device, to_device, usage, transport, private_service_label, tick);
    }

    pub fn probeOverlaySession(
        self: *SyncPort,
        authority: AuthorityContext,
        session_id: u64,
        tick: u64,
    ) (AuthorityError || Error)!bool {
        _ = try self.requireSyncAuthority(authority);
        return self.service.probeOverlaySession(session_id, tick);
    }

    pub fn closeOverlaySession(
        self: *SyncPort,
        authority: AuthorityContext,
        session_id: u64,
        tick: u64,
    ) (AuthorityError || Error)!bool {
        _ = try self.requireSyncAuthority(authority);
        return self.service.closeOverlaySession(session_id, tick);
    }

    pub fn sendOverlayRelayFrame(
        self: *SyncPort,
        authority: AuthorityContext,
        network_capabilities: *const capability.CapabilityTable,
        relay: *sync_transport.Relay,
        request: OverlayRelayFrameRequest,
    ) (AuthorityError || Error || sync_transport.Error)!OverlayRelayFrameResult {
        _ = try self.requireSyncAuthority(authority);
        return self.service.sendOverlayRelayFrame(network_capabilities, relay, request);
    }

    pub fn sendOverlayRelayFrameViaService(
        self: *SyncPort,
        authority: AuthorityContext,
        network_capabilities: *const capability.CapabilityTable,
        relay_service: *sync_transport.BootedOverlayRelayService,
        request: OverlayRelayFrameRequest,
    ) (AuthorityError || Error || sync_transport.Error)!OverlayRelayFrameResult {
        _ = try self.requireSyncAuthority(authority);
        return self.service.sendOverlayRelayFrameViaService(network_capabilities, relay_service, request);
    }

    pub fn setReplicaVersion(
        self: *SyncPort,
        authority: AuthorityContext,
        workspace_id: u64,
        device_id: principal.PrincipalId,
        path: []const u8,
        object_id: anytype,
        version_id: anytype,
    ) (AuthorityError || Error)!void {
        _ = try self.requireSyncAuthority(authority);
        return self.service.setReplicaVersion(workspace_id, device_id, path, object_id, version_id);
    }

    pub fn registerDatabaseContract(
        self: *SyncPort,
        authority: AuthorityContext,
        workspace_id: u64,
        bundle_id: []const u8,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) (AuthorityError || Error)!*DatabaseContract {
        _ = try self.requireSyncAuthority(authority);
        return self.service.registerDatabaseContract(workspace_id, bundle_id, label, identity);
    }

    pub fn replicateWorkspace(
        self: *SyncPort,
        authority: AuthorityContext,
        store: *const storage_service.Service,
        workspace_id: u64,
        from_device: principal.PrincipalId,
        to_device: principal.PrincipalId,
        transport: TransportMode,
    ) (AuthorityError || Error)!ReplicationSummary {
        _ = try self.requireSyncAuthority(authority);
        return self.service.replicateWorkspace(store, workspace_id, from_device, to_device, transport);
    }

    pub fn replicateWorkspaceToPeer(
        self: *SyncPort,
        authority: AuthorityContext,
        peer: *SyncPort,
        peer_authority: AuthorityContext,
        request: PeerReplicationRequest,
    ) PeerReplicationError!PeerReplicationResult {
        _ = try self.requireSyncAuthority(authority);
        _ = try peer.requireSyncAuthority(peer_authority);
        try self.validatePeerReplicationRequest(request);

        const starting_frame_id = self.service.latestTransportFrameId();
        const summary = try self.service.replicateWorkspace(
            request.source_storage,
            request.workspace_id,
            request.from_device,
            request.to_device,
            request.transport,
        );

        var result = PeerReplicationResult{ .summary = summary };
        var frames: [MAX_TRANSPORT_FRAMES]TransportFrame = undefined;
        const frame_count = self.service.copyTransportFramesForSince(
            request.workspace_id,
            request.to_device,
            starting_frame_id,
            frames[0..],
        );
        sortTransportFramesById(frames[0..frame_count]);

        for (frames[0..frame_count]) |frame| {
            const delivery = try self.replicateFramePayloadToPeer(peer, request, frame);
            result.accepted_frame_count += 1;
            result.persisted_object_count += 1;
            result.payload_bytes += delivery.payload_len;
            if (delivery.used_booted_relay_service) {
                result.used_booted_relay_service = true;
                result.relay_delivery_count += 1;
            }
        }
        return result;
    }

    pub fn acceptTransportFrame(
        self: *SyncPort,
        authority: AuthorityContext,
        store: *const storage_service.Service,
        request: TransportFrameRequest,
    ) (AuthorityError || Error)!TransportFrame {
        _ = try self.requireSyncAuthority(authority);
        return self.service.acceptTransportFrame(store, request);
    }

    pub fn transferSecretObject(
        self: *SyncPort,
        authority: AuthorityContext,
        storage: *const storage_service.Service,
        workspace_id: u64,
        object_id: anytype,
        from_device: principal.PrincipalId,
        to_device: principal.PrincipalId,
        transport: TransportMode,
    ) (AuthorityError || Error)!bool {
        _ = try self.requireSyncAuthority(authority);
        return self.service.transferSecretObject(storage, workspace_id, object_id, from_device, to_device, transport);
    }

    pub fn replicateDatabaseContract(
        self: *SyncPort,
        authority: AuthorityContext,
        contract_id: u64,
        workspace_id: u64,
        from_device: principal.PrincipalId,
        to_device: principal.PrincipalId,
        transport: TransportMode,
    ) (AuthorityError || Error)!bool {
        _ = try self.requireSyncAuthority(authority);
        return self.service.replicateDatabaseContract(contract_id, workspace_id, from_device, to_device, transport);
    }

    pub fn repairWorkspaceMetadata(
        self: *SyncPort,
        authority: AuthorityContext,
        store: *const storage_service.Service,
        workspace_id: u64,
        device_id: principal.PrincipalId,
    ) (AuthorityError || Error)!bool {
        _ = try self.requireSyncAuthority(authority);
        return self.service.repairWorkspaceMetadata(store, workspace_id, device_id);
    }

    fn requireSyncAuthority(self: *SyncPort, authority: AuthorityContext) AuthorityError!*const capability.Capability {
        return service_authority.requireServiceAuthority(
            self.capability_table,
            self.service.service_id,
            authority,
            .endpoint_connect,
        );
    }

    fn validatePeerReplicationRequest(
        self: *SyncPort,
        request: PeerReplicationRequest,
    ) PeerReplicationError!void {
        try self.service.ensureTrustedDevices(request.from_device, request.to_device);
        const policy = self.service.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
        try self.service.authorizeTransport(policy, request.transport, null);
        if (request.transport != .relay_assisted) return;

        const relay_service = request.relay_service orelse return error.TransportDenied;
        if (!std.mem.eql(u8, relay_service.relayDomainSlice(), policy.relayDomainSlice())) {
            return error.EgressDenied;
        }
        const network_capabilities = request.network_capabilities orelse return error.TransportDenied;
        const relay_policy_id = policy.relay_policy_id orelse return error.TransportDenied;

        var broker = self.service.egressBroker(network_capabilities);
        var transport = sync_transport.Harness.init();
        _ = try transport.openRelay(&broker, .{
            .task_id = self.service.task_id,
            .principal_id = self.service.owner,
            .capability_id = request.relay_capability_id,
            .policy_id = relay_policy_id,
            .evidence = .{ .destination = .{ .domain = policy.relayDomainSlice() } },
            .now_ticks = request.tick,
        }, request.from_device, request.to_device, policy.relayDomainSlice());
    }

    const PeerFrameDelivery = struct {
        payload_len: usize,
        used_booted_relay_service: bool,
    };

    fn replicateFramePayloadToPeer(
        self: *SyncPort,
        peer: *SyncPort,
        request: PeerReplicationRequest,
        frame: TransportFrame,
    ) PeerReplicationError!PeerFrameDelivery {
        const source_version = request.source_storage.version(frame.version_id) orelse return error.VersionNotFound;
        const payload = try request.source_storage.versionPayload(source_version);
        var used_booted_relay_service = false;

        if (request.transport == .relay_assisted) {
            const relay_service = request.relay_service orelse return error.TransportDenied;
            const network_capabilities = request.network_capabilities orelse return error.TransportDenied;
            const relay_result = try self.service.sendOverlayRelayFrameViaService(network_capabilities, relay_service, .{
                .workspace_id = request.workspace_id,
                .from_device = request.from_device,
                .to_device = request.to_device,
                .usage = .sync_replication,
                .relay_capability_id = request.relay_capability_id,
                .payload = payload,
                .signer = request.signer,
                .tick = request.tick,
            });
            if (!relay_result.delivered or relay_result.delivered_len != payload.len) {
                return error.RelayDeliveryMissing;
            }
            used_booted_relay_service = true;
        }

        const parent_version_id = if (request.target_storage.resolve(frame.workspace_id, frame.pathSlice())) |current|
            if (current.object_id.raw() == frame.object_id) current.version_id else null
        else |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };
        const persisted = try request.target_storage.putVersion(.{
            .preferred_object_id = object_store.ids.object(frame.object_id),
            .object_type = source_version.object_type,
            .payload = payload,
            .metadata = source_version.metadata,
            .parent_version_id = parent_version_id,
        });
        try request.target_storage.beginTransaction(frame.workspace_id);
        try request.target_storage.stagePut(
            frame.workspace_id,
            frame.pathSlice(),
            persisted.object_id,
            persisted.version_id,
            source_version.object_type,
        );
        const generation = try request.target_storage.commit(frame.workspace_id, request.tick);

        _ = try peer.service.acceptTransportFrame(request.target_storage, .{
            .workspace_id = frame.workspace_id,
            .object_id = persisted.object_id.raw(),
            .version_id = persisted.version_id.raw(),
            .source_device = frame.source_device,
            .target_device = frame.target_device,
            .transport = frame.transport,
            .semantic = frame.semantic,
            .encrypted = frame.encrypted,
            .workspace_generation = generation,
            .path = frame.pathSlice(),
        });
        return .{
            .payload_len = payload.len,
            .used_booted_relay_service = used_booted_relay_service,
        };
    }
};

pub fn ServiceWith(comptime config: ServiceConfig) type {
    config.validate();
    return struct {
        const Self = @This();
        const MAX_SERVICE_OVERLAY_SESSIONS = config.max_overlay_sessions;
        const OVERLAY_SESSION_INDEX_CAPACITY: usize = MAX_SERVICE_OVERLAY_SESSIONS * 2;
        const OverlaySessionArena = indexed_arena.IndexedArenaWithKey(u64, OverlaySessionSlot, MAX_SERVICE_OVERLAY_SESSIONS, OVERLAY_SESSION_INDEX_CAPACITY, overlaySessionSlotId);
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
            return self.transport_queue.count();
        }

        pub fn latestTransportFrameId(self: *const Self) u64 {
            return self.transport_queue.latestFrameId();
        }

        pub fn overlaySessionCapacity(self: *const Self) usize {
            _ = self;
            return MAX_SERVICE_OVERLAY_SESSIONS;
        }

        pub fn transportFrameCountFor(self: *const Self, workspace_id: u64, device_id: principal.PrincipalId) usize {
            return self.transport_queue.countFor(workspace_id, device_id);
        }

        pub fn copyTransportFramesForSince(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            min_frame_id: u64,
            out: []TransportFrame,
        ) usize {
            return self.transport_queue.copyForSince(workspace_id, device_id, min_frame_id, out);
        }

        pub fn latestTransportFrameForPath(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?TransportFrame {
            return self.transport_queue.latestForPath(workspace_id, device_id, path);
        }

        fn ensureUserRoot(
            self: *Self,
            user_principal: principal.PrincipalId,
            label: []const u8,
            identity: signing.SignerIdentity,
        ) Error!*device_graph.UserRootRecord {
            const root = try self.state().graph.ensureUserRoot(user_principal, label, identity);
            self.resident().markDirty();
            return root;
        }

        fn enrollTrustedDevice(
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

        fn enrollPlatformBackedDevice(
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

        fn rotateDeviceKey(
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

        fn rotatePlatformBackedDeviceKey(
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

        fn revokeTrustedDevice(
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

        fn createNetworkPolicy(self: *Self, request: network_policy.CreateRequest) Error!*network_policy.PolicyRecord {
            const record = try self.state().network_policies.create(request);
            self.resident().markDirty();
            return record;
        }

        fn evaluateNetworkPolicy(
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

        fn configureWorkspacePolicy(
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

        fn configureOverlay(
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

        fn publishPrivateService(
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

        fn openOverlaySession(
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

        fn probeOverlaySession(self: *Self, session_id: u64, tick: u64) Error!bool {
            const session = self.findOverlaySession(session_id) orelse return error.OverlaySessionNotFound;
            if (session.state != .established) return false;
            session.keepalive_count += 1;
            session.last_activity_tick = tick;
            return true;
        }

        fn closeOverlaySession(self: *Self, session_id: u64, tick: u64) Error!bool {
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
            if (!self.closed_overlay_sessions.append(CLOSED_OVERLAY_SESSION_KEY, slot_index)) {
                native_util.impossibleByInvariant("closed overlay session index capacity covers overlay session slots");
            }
            return true;
        }

        fn sendOverlayRelayFrame(
            self: *Self,
            network_capabilities: *const capability.CapabilityTable,
            relay: *sync_transport.Relay,
            request: OverlayRelayFrameRequest,
        ) (Error || sync_transport.Error)!OverlayRelayFrameResult {
            const policy = self.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
            const relay_policy_id = policy.relay_policy_id orelse return error.TransportDenied;

            var broker = self.egressBroker(network_capabilities);
            var transport = sync_transport.Harness.init();
            const transport_session = try transport.openRelay(&broker, .{
                .task_id = self.task_id,
                .principal_id = self.owner,
                .capability_id = request.relay_capability_id,
                .policy_id = relay_policy_id,
                .evidence = .{ .destination = .{ .domain = policy.relayDomainSlice() } },
                .now_ticks = request.tick,
            }, request.from_device, request.to_device, policy.relayDomainSlice());
            const overlay_session = try self.openOverlaySession(
                request.workspace_id,
                request.from_device,
                request.to_device,
                request.usage,
                .relay_assisted,
                request.private_service_label,
                request.tick,
            );

            const signed_frame = try transport.encryptSignedFrame(&transport_session, request.payload, request.signer);
            try relay.submit(signed_frame.packet);
            var delivered_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
            const delivered = (try relay.deliverNext(&transport_session, delivered_buffer[0..])) orelse return error.RelayDeliveryMissing;
            if (!std.mem.eql(u8, delivered, request.payload)) return error.PacketAuthenticationFailed;

            return overlayRelayFrameResult(overlay_session, transport_session, signed_frame, delivered.len);
        }

        fn sendOverlayRelayFrameViaService(
            self: *Self,
            network_capabilities: *const capability.CapabilityTable,
            relay_service: *sync_transport.BootedOverlayRelayService,
            request: OverlayRelayFrameRequest,
        ) (Error || sync_transport.Error)!OverlayRelayFrameResult {
            const policy = self.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
            const relay_policy_id = policy.relay_policy_id orelse return error.TransportDenied;

            var broker = self.egressBroker(network_capabilities);
            var transport = sync_transport.Harness.init();
            const transport_session = try transport.openRelay(&broker, .{
                .task_id = self.task_id,
                .principal_id = self.owner,
                .capability_id = request.relay_capability_id,
                .policy_id = relay_policy_id,
                .evidence = .{ .destination = .{ .domain = policy.relayDomainSlice() } },
                .now_ticks = request.tick,
            }, request.from_device, request.to_device, policy.relayDomainSlice());
            const overlay_session = try self.openOverlaySession(
                request.workspace_id,
                request.from_device,
                request.to_device,
                request.usage,
                .relay_assisted,
                request.private_service_label,
                request.tick,
            );

            const signed_frame = try transport.encryptSignedFrame(&transport_session, request.payload, request.signer);
            try relay_service.submitSignedFrame(self.task_id, &transport_session, signed_frame);
            var delivered_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
            const delivered = (try relay_service.deliverNext(self.task_id, &transport_session, delivered_buffer[0..])) orelse return error.RelayDeliveryMissing;
            if (!std.mem.eql(u8, delivered, request.payload)) return error.PacketAuthenticationFailed;

            return overlayRelayFrameResult(overlay_session, transport_session, signed_frame, delivered.len);
        }

        fn overlayRelayFrameResult(
            overlay_session: OverlaySession,
            transport_session: sync_transport.TransportSession,
            signed_frame: sync_transport.SignedEncryptedFrame,
            delivered_len: usize,
        ) Error!OverlayRelayFrameResult {
            var result = OverlayRelayFrameResult{
                .overlay_session_id = overlay_session.session_id,
                .transport_session_id = transport_session.id,
                .usage = overlay_session.usage,
                .encrypted = overlay_session.encrypted and signed_frame.packet.encrypted,
                .relay_encrypted = overlay_session.relay_encrypted,
                .remote_access = overlay_session.remote_access,
                .egress_allowed = signed_frame.packet.egress_allowed,
                .delivered = true,
                .delivered_len = delivered_len,
                .packet_digest = signed_frame.packet_digest,
            };
            result.service_identity_len = native_util.copyTextExact(&result.service_identity, overlay_session.serviceIdentitySlice()) catch return error.ServiceIdentityTooLong;
            result.relay_domain_len = native_util.copyTextExact(&result.relay_domain, overlay_session.relayDomainSlice()) catch return error.NetworkTargetTooLong;
            if (overlay_session.private_service_len != 0) {
                result.private_service_len = native_util.copyTextExact(&result.private_service, overlay_session.privateServiceSlice()) catch return error.ServiceIdentityTooLong;
            }
            return result;
        }

        fn setReplicaVersion(
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

        fn registerDatabaseContract(
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

        fn replicateWorkspace(
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

            const last_replicated_generation = self.replicaWorkspaceGeneration(workspace_id, to_device);
            const changes = try store.entryChangesSince(workspace_id, last_replicated_generation);
            const latest_mutation_index = buildLatestMutationIndex(changes);
            for (changes, 0..) |mutation, mutation_index| {
                const entry = mutation.entry;
                if (!latest_mutation_index.isLatest(changes, mutation_index)) continue;
                if (!policy.matchesPath(entry.pathSlice())) {
                    summary.skipped_entry_count += 1;
                    continue;
                }

                const semantic = classifyEntry(entry);
                const entry_path = entry.pathSlice();
                const entry_path_hash = entry.pathHash();
                const remote_version_id = self.replicaVersionForPathHash(workspace_id, to_device, entry_path, entry_path_hash) orelse 0;
                if (remote_version_id == entry.version_id.raw()) continue;
                summary.selected_entry_count += 1;

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

        fn acceptTransportFrame(
            self: *Self,
            store: *const storage_service.Service,
            request: TransportFrameRequest,
        ) Error!TransportFrame {
            try self.ensureTrustedDevices(request.source_device, request.target_device);
            const policy = self.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
            try self.authorizeTransport(policy, request.transport, null);
            if (policy.personal_e2ee and !request.encrypted) return error.TransportDenied;

            const entry = store.resolve(request.workspace_id, request.path) catch |err| switch (err) {
                error.EntryNotFound => return error.VersionNotFound,
                else => return err,
            };
            if (entry.object_id.raw() != request.object_id or entry.version_id.raw() != request.version_id) {
                return error.VersionNotFound;
            }
            const expected_semantic = classifyEntry(entry);
            if (request.semantic != expected_semantic) return error.SyncSemanticMismatch;

            switch (expected_semantic) {
                .mergeable_crdt => _ = try self.mergeable_document_adapter.merge(.{
                    .store = store,
                    .entry = entry,
                    .remote_version_id = request.version_id,
                }),
                .chunked_snapshot => _ = try self.chunk_media_adapter.replicate(.{
                    .store = store,
                    .entry = entry,
                }),
                .secure_transfer => _ = try self.secret_transfer_adapter.transfer(.{
                    .store = store,
                    .workspace_id = request.workspace_id,
                    .object_id = request.object_id,
                    .from_device = request.source_device,
                    .to_device = request.target_device,
                    .personal_e2ee = policy.personal_e2ee,
                }),
                .transactional_contract => {},
            }

            const accepted = try self.transport_queue.enqueue(request);
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

        fn transferSecretObject(
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

        fn replicateDatabaseContract(
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

        fn repairWorkspaceMetadata(
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

        fn allocateOverlaySessionSlot(self: *Self, session_id: u64) ?*OverlaySessionSlot {
            if (self.overlay_sessions.reserve(session_id)) |slot| return slot;

            const slot_index = self.closed_overlay_sessions.head(CLOSED_OVERLAY_SESSION_KEY);
            if (slot_index == indexed_arena.no_index) return null;
            if (slot_index >= MAX_SERVICE_OVERLAY_SESSIONS) native_util.impossibleByInvariant("closed overlay session index points outside slots");
            _ = self.closed_overlay_sessions.remove(CLOSED_OVERLAY_SESSION_KEY, slot_index);
            _ = self.overlay_sessions.removeIndex(slot_index);
            return self.overlay_sessions.reserveAtIndex(session_id, slot_index);
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
            const slot_index = self.replica_index.lookup(replicaIndexLookupKey(workspace_id, device_id, path_hash)) orelse return null;
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
            self.replica_index.insert(replicaIndexLookupKey(workspace_id, device_id, path_hash), slot_index);
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
                self.replica_index.insert(replicaIndexLookupKey(slot.entry.workspace_id, slot.entry.device_id, slot.entry.pathHash()), slot_index);
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

fn sortTransportFramesById(frames: []TransportFrame) void {
    var index: usize = 1;
    while (index < frames.len) : (index += 1) {
        const value = frames[index];
        var insert_at = index;
        while (insert_at > 0 and frames[insert_at - 1].id > value.id) : (insert_at -= 1) {
            frames[insert_at] = frames[insert_at - 1];
        }
        frames[insert_at] = value;
    }
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

const LATEST_MUTATION_INDEX_CAPACITY: usize = workspace.MAX_WORKSPACE_ENTRY_MUTATIONS * 2;

const LatestMutationIndexSlot = struct {
    in_use: bool = false,
    path_hash: u64 = 0,
    mutation_index: usize = 0,
};

const LatestMutationIndex = struct {
    slots: [LATEST_MUTATION_INDEX_CAPACITY]LatestMutationIndexSlot = [_]LatestMutationIndexSlot{LatestMutationIndexSlot{}} ** LATEST_MUTATION_INDEX_CAPACITY,

    fn put(self: *LatestMutationIndex, changes: []const workspace.EntryMutation, mutation_index: usize) void {
        const entry = &changes[mutation_index].entry;
        const path_hash = entry.pathHash();
        const path = entry.pathSlice();
        var slot_index = latestMutationSlotStart(path_hash);
        var probes: usize = 0;
        while (probes < self.slots.len) : ({
            probes += 1;
            slot_index = (slot_index + 1) % self.slots.len;
        }) {
            const slot = &self.slots[slot_index];
            if (!slot.in_use) {
                slot.* = .{
                    .in_use = true,
                    .path_hash = path_hash,
                    .mutation_index = mutation_index,
                };
                return;
            }
            if (slot.path_hash == path_hash and std.mem.eql(u8, changes[slot.mutation_index].entry.pathSlice(), path)) {
                slot.mutation_index = mutation_index;
                return;
            }
        }
        native_util.impossibleByInvariant("latest mutation index capacity covers workspace changes");
    }

    fn latestIndexFor(
        self: *const LatestMutationIndex,
        changes: []const workspace.EntryMutation,
        path_hash: u64,
        path: []const u8,
    ) ?usize {
        var slot_index = latestMutationSlotStart(path_hash);
        var probes: usize = 0;
        while (probes < self.slots.len) : ({
            probes += 1;
            slot_index = (slot_index + 1) % self.slots.len;
        }) {
            const slot = &self.slots[slot_index];
            if (!slot.in_use) return null;
            if (slot.path_hash == path_hash and std.mem.eql(u8, changes[slot.mutation_index].entry.pathSlice(), path)) {
                return slot.mutation_index;
            }
        }
        return null;
    }

    fn isLatest(self: *const LatestMutationIndex, changes: []const workspace.EntryMutation, mutation_index: usize) bool {
        const entry = &changes[mutation_index].entry;
        return self.latestIndexFor(changes, entry.pathHash(), entry.pathSlice()) == mutation_index;
    }
};

fn buildLatestMutationIndex(changes: []const workspace.EntryMutation) LatestMutationIndex {
    var index = LatestMutationIndex{};
    for (changes, 0..) |_, mutation_index| {
        index.put(changes, mutation_index);
    }
    return index;
}

fn latestMutationSlotStart(path_hash: u64) usize {
    return @intCast(path_hash % LATEST_MUTATION_INDEX_CAPACITY);
}

test "latest mutation index tracks newest mutation per path hash" {
    var changes: [4]workspace.EntryMutation = undefined;
    changes[0] = .{
        .generation = 1,
        .entry = try workspace.Entry.init("documents/notes.md", object_store.ids.object(1), object_store.ids.version(10), .document),
    };
    changes[1] = .{
        .generation = 2,
        .entry = try workspace.Entry.init("assets/cover.jpg", object_store.ids.object(2), object_store.ids.version(20), .media_asset),
    };
    changes[2] = .{
        .generation = 3,
        .entry = try workspace.Entry.init("documents/notes.md", object_store.ids.object(1), object_store.ids.version(11), .document),
    };
    changes[3] = .{
        .generation = 4,
        .entry = try workspace.Entry.init("documents/todo.md", object_store.ids.object(3), object_store.ids.version(30), .document),
    };

    const latest_mutations = buildLatestMutationIndex(changes[0..]);
    try std.testing.expect(!latest_mutations.isLatest(changes[0..], 0));
    try std.testing.expect(latest_mutations.isLatest(changes[0..], 1));
    try std.testing.expect(latest_mutations.isLatest(changes[0..], 2));
    try std.testing.expect(latest_mutations.isLatest(changes[0..], 3));
    try std.testing.expectEqual(@as(?usize, 2), latest_mutations.latestIndexFor(
        changes[0..],
        changes[0].entry.pathHash(),
        "documents/notes.md",
    ));
}
