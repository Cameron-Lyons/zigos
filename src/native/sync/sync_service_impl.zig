const std = @import("std");
const device_graph = @import("device_graph.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const network_policy = @import("network_policy.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const state_store = @import("sync_state_store.zig");
const state_support = @import("sync_state_support.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");
const copyText = native_util.copyText;

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
        next_overlay_session_id: u64 = 1,
        overlay_sessions: [MAX_SERVICE_OVERLAY_SESSIONS]OverlaySessionSlot = [_]OverlaySessionSlot{OverlaySessionSlot{}} ** MAX_SERVICE_OVERLAY_SESSIONS,

        pub fn init(service_id: u64, task_id: u64, owner: principal.PrincipalId) Self {
            var service = Self{
                .service_id = service_id,
                .task_id = task_id,
                .owner = owner,
                .storage = null,
                .state_workspace_id = 0,
                .next_overlay_session_id = 1,
                .overlay_sessions = [_]OverlaySessionSlot{OverlaySessionSlot{}} ** MAX_SERVICE_OVERLAY_SESSIONS,
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
            return .{
                .service_id = service_id,
                .task_id = task_id,
                .owner = owner,
                .loaded_existing_state = loaded_existing_state,
                .storage = null,
                .state_workspace_id = 0,
                .resident_store = resident_state,
                .next_overlay_session_id = 1,
                .overlay_sessions = [_]OverlaySessionSlot{OverlaySessionSlot{}} ** MAX_SERVICE_OVERLAY_SESSIONS,
            };
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

            return .{
                .service_id = service_id,
                .task_id = task_id,
                .owner = owner,
                .loaded_existing_state = loaded_existing_state,
                .storage = storage,
                .state_workspace_id = workspace_id,
                .resident_store = resident_state,
                .next_overlay_session_id = 1,
                .overlay_sessions = [_]OverlaySessionSlot{OverlaySessionSlot{}} ** MAX_SERVICE_OVERLAY_SESSIONS,
            };
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
            slot.policy.relay_domain_len = copyText(&slot.policy.relay_domain, request.relay_domain);

            for (request.selective_prefixes, 0..) |prefix, index| {
                slot.policy.selective_prefix_lens[index] = copyText(&slot.policy.selective_prefixes[index], prefix);
                slot.policy.selective_prefix_count += 1;
            }

            try self.checkpoint();
            return &slot.policy;
        }

        pub fn findWorkspacePolicy(self: *Self, workspace_id: u64) ?*WorkspacePolicy {
            const slot = self.lookupWorkspacePolicySlot(workspace_id) orelse return null;
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
            slot.overlay.service_identity_len = copyText(&slot.overlay.service_identity, service_identity);
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
            overlay.private_service_lens[slot_index] = copyText(&overlay.private_services[slot_index], label);
            overlay.private_service_count += 1;
            try self.checkpoint();
            return overlay;
        }

        pub fn findOverlay(self: *Self, workspace_id: u64) ?*OverlayRecord {
            const slot = self.lookupOverlaySlot(workspace_id) orelse return null;
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
            session.service_identity_len = copyText(&session.service_identity, overlay.serviceIdentitySlice());

            switch (usage) {
                .sync_replication => {},
                .remote_access => {
                    if (!overlay.remote_access_enabled) return error.RemoteAccessDisabled;
                    session.remote_access = true;
                },
                .private_service => {
                    const label = private_service_label orelse return error.PrivateServiceNotPublished;
                    if (!overlay.hasPrivateService(label)) return error.PrivateServiceNotPublished;
                    session.private_service_len = copyText(&session.private_service, label);
                    session.remote_access = overlay.remote_access_enabled and transport == .relay_assisted;
                },
            }

            if (transport == .relay_assisted) {
                session.relay_domain_len = copyText(&session.relay_domain, policy.relayDomainSlice());
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
            self.resident().markDirty();
        }

        pub fn replicaVersion(
            self: *const Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?u64 {
            for (&self.stateConst().replica_entries) |*slot| {
                if (!slot.in_use) continue;
                if (slot.entry.workspace_id != workspace_id) continue;
                if (!slot.entry.device_id.eql(device_id)) continue;
                if (!std.mem.eql(u8, slot.entry.pathSlice(), path)) continue;
                return slot.entry.version_id;
            }
            return null;
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
            slot.contract.bundle_id_len = copyText(&slot.contract.bundle_id, bundle_id);
            slot.contract.label_len = copyText(&slot.contract.label, label);
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
            self: *Self,
            storage: *const storage_service.Service,
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

            const object_record = storage.object(object_id) orelse return error.ObjectNotFound;
            if (object_record.object_type != .secret) return error.TypeMismatch;
            return true;
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
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?*ConflictRecord {
            for (&self.state().conflicts) |*slot| {
                if (!slot.in_use) continue;
                if (slot.conflict.workspace_id != workspace_id) continue;
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
            slot.conflict.path_len = copyText(&slot.conflict.path, path);
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
            for (&self.state().database_contracts) |*slot| {
                if (slot.in_use and slot.contract.id == contract_id) return &slot.contract;
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
            for (&self.state().database_contracts) |*slot| {
                if (!slot.in_use) continue;
                if (slot.contract.workspace_id != workspace_id) continue;
                if (!std.mem.eql(u8, slot.contract.bundleIdSlice(), bundle_id)) continue;
                if (!std.mem.eql(u8, slot.contract.labelSlice(), label)) continue;
                if (!signatureEql(slot.contract.signature, signature)) continue;
                return &slot.contract;
            }
            return null;
        }

        fn lookupWorkspacePolicySlot(self: *Self, workspace_id: u64) ?*WorkspacePolicySlot {
            for (&self.state().workspace_policies) |*slot| {
                if (slot.in_use and slot.policy.workspace_id == workspace_id) return slot;
            }
            return null;
        }

        fn allocateWorkspacePolicy(self: *Self) ?*WorkspacePolicySlot {
            for (&self.state().workspace_policies) |*slot| {
                if (!slot.in_use) return slot;
            }
            return null;
        }

        fn lookupOverlaySlot(self: *Self, workspace_id: u64) ?*OverlaySlot {
            for (&self.state().overlays) |*slot| {
                if (slot.in_use and slot.overlay.workspace_id == workspace_id) return slot;
            }
            return null;
        }

        fn allocateOverlay(self: *Self) ?*OverlaySlot {
            for (&self.state().overlays) |*slot| {
                if (!slot.in_use) return slot;
            }
            return null;
        }

        fn nextOverlayId(self: *Self) u64 {
            defer self.state().next_overlay_id += 1;
            return self.stateConst().next_overlay_id;
        }

        fn lookupReplicaSlot(
            self: *Self,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) ?*ReplicaSlot {
            for (&self.state().replica_entries) |*slot| {
                if (!slot.in_use) continue;
                if (slot.entry.workspace_id != workspace_id) continue;
                if (!slot.entry.device_id.eql(device_id)) continue;
                if (!std.mem.eql(u8, slot.entry.pathSlice(), path)) continue;
                return slot;
            }
            return null;
        }

        fn allocateReplicaSlot(self: *Self) ?*ReplicaSlot {
            for (&self.state().replica_entries) |*slot| {
                if (!slot.in_use) return slot;
            }
            return null;
        }

        fn allocateConflict(self: *Self) ?*ConflictSlot {
            for (&self.state().conflicts) |*slot| {
                if (!slot.in_use) return slot;
            }
            return null;
        }

        fn allocateDatabaseContract(self: *Self) ?*DatabaseContractSlot {
            for (&self.state().database_contracts) |*slot| {
                if (!slot.in_use) return slot;
            }
            return null;
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

test "sync service covers device graph policy replication semantics and restart recovery" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

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

    var storage = storage_service.Service.initWithStore(40, 4, storage_owner, &storage_checkpoint_store);
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

    var resident = ResidentState{};
    var service = try Service.initWithStorage(80, 8, sync_owner, &storage, &resident);
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

    try std.testing.expect(try service.transferSecretObject(&storage, notes.id, secret.object_id, laptop, tablet, .device_to_device));
    const contract = try service.registerDatabaseContract(notes.id, "app.db.notes", "notes-db", contract_signer);
    try std.testing.expect(try service.replicateDatabaseContract(contract.id, notes.id, laptop, tablet, .relay_assisted));
    try std.testing.expectError(error.DeviceNotTrusted, service.replicateWorkspace(&storage, notes.id, laptop, phone, .device_to_device));

    var restarted_resident = ResidentState{};
    var restarted = try Service.initWithStorage(80, 9, sync_owner, &storage, &restarted_resident);
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

    storage_checkpoint_store.resetPersistent();
}

test "overlay sessions cover sync remote access private service publishing and encrypted relay" {
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 91 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 19 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 191 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 192 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 193 };
    const user_signer = signing.SignerIdentity{
        .label = "overlay-user",
        .seed = [_]u8{0x61} ** 32,
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "overlay-laptop",
        .seed = [_]u8{0x62} ** 32,
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "overlay-tablet",
        .seed = [_]u8{0x63} ** 32,
    };
    const phone_signer = signing.SignerIdentity{
        .label = "overlay-phone",
        .seed = [_]u8{0x64} ** 32,
    };

    var service = Service.init(901, 92, sync_owner);
    _ = try service.ensureUserRoot(user, "owner", user_signer);
    _ = try service.enrollTrustedDevice(user, laptop, "laptop", user_signer, laptop_signer, 10);
    _ = try service.enrollTrustedDevice(user, tablet, "tablet", user_signer, tablet_signer, 11);
    _ = try service.enrollTrustedDevice(user, phone, "phone", user_signer, phone_signer, 12);

    const workspace_id: u64 = 4_200;
    const local_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "local",
        .mode = .local_network,
    });
    const overlay_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.workspace.sync",
    });
    const relay_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    _ = try service.configureWorkspacePolicy(.{
        .workspace_id = workspace_id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    });

    _ = try service.configureOverlay(workspace_id, laptop, "overlay.workspace.sync", true);
    _ = try service.publishPrivateService(workspace_id, "notes.remote");

    const sync_session = try service.openOverlaySession(
        workspace_id,
        laptop,
        tablet,
        .sync_replication,
        .device_to_device,
        null,
        13,
    );
    try std.testing.expectEqual(OverlaySessionUse.sync_replication, sync_session.usage);
    try std.testing.expect(sync_session.isActive());
    try std.testing.expect(sync_session.encrypted);
    try std.testing.expect(!sync_session.relay_encrypted);
    try std.testing.expectEqualStrings("overlay.workspace.sync", sync_session.serviceIdentitySlice());
    try std.testing.expectEqual(@as(usize, 1), service.activeOverlaySessionCount());
    try std.testing.expect(try service.probeOverlaySession(sync_session.session_id, 14));
    try std.testing.expectEqual(@as(u16, 1), service.findOverlaySession(sync_session.session_id).?.keepalive_count);

    const remote_session = try service.openOverlaySession(
        workspace_id,
        laptop,
        tablet,
        .remote_access,
        .relay_assisted,
        null,
        15,
    );
    try std.testing.expectEqual(OverlaySessionUse.remote_access, remote_session.usage);
    try std.testing.expect(remote_session.remote_access);
    try std.testing.expect(remote_session.relay_encrypted);
    try std.testing.expectEqualStrings("relay.zigos.dev", remote_session.relayDomainSlice());

    const private_service = try service.openOverlaySession(
        workspace_id,
        tablet,
        laptop,
        .private_service,
        .relay_assisted,
        "notes.remote",
        16,
    );
    try std.testing.expectEqual(OverlaySessionUse.private_service, private_service.usage);
    try std.testing.expect(private_service.remote_access);
    try std.testing.expect(private_service.relay_encrypted);
    try std.testing.expectEqualStrings("notes.remote", private_service.privateServiceSlice());
    try std.testing.expectEqual(@as(usize, 3), service.activeOverlaySessionCount());
    try std.testing.expect(try service.closeOverlaySession(remote_session.session_id, 17));
    try std.testing.expectEqual(OverlaySessionState.closed, service.findOverlaySession(remote_session.session_id).?.state);
    try std.testing.expectEqual(@as(usize, 2), service.activeOverlaySessionCount());

    try std.testing.expectError(error.PrivateServiceNotPublished, service.openOverlaySession(
        workspace_id,
        laptop,
        tablet,
        .private_service,
        .relay_assisted,
        "notes.missing",
        18,
    ));

    _ = try service.configureOverlay(workspace_id, laptop, "overlay.workspace.sync", false);
    try std.testing.expectError(error.RemoteAccessDisabled, service.openOverlaySession(
        workspace_id,
        laptop,
        phone,
        .remote_access,
        .relay_assisted,
        null,
        19,
    ));
}

test "sync service overlay session capacity is configurable" {
    const SmallService = ServiceWith(.{ .max_overlay_sessions = 2 });
    const service = SmallService.init(1, 2, .{ .kind = .service, .serial = 3 });

    try std.testing.expectEqual(@as(usize, 2), service.overlay_sessions.len);
}
