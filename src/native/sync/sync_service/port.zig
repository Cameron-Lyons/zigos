const std = @import("std");
const capability = @import("../../kernel_api/capability.zig");
const device_graph = @import("../device_graph.zig");
const network_policy = @import("../network_policy.zig");
const object_store = @import("../../storage/object_store.zig");
const principal = @import("../../core/principal.zig");
const service_authority = @import("../../services/service_authority.zig");
const signing = @import("../../core/signing.zig");
const state_support = @import("../sync_state_support.zig");
const sync_adapters = @import("../sync_adapters.zig");
const sync_transport = @import("../sync_transport.zig");
const storage_service = @import("../../storage/storage_service.zig");
const transport_frames = @import("transport_frames.zig");
const workspace = @import("../../storage/workspace.zig");

pub const MAX_TRANSPORT_FRAMES = state_support.MAX_TRANSPORT_FRAMES;
pub const Error = state_support.Error;
pub const AuthorityContext = service_authority.Context;
pub const AuthorityError = service_authority.Error;
pub const PeerReplicationError = AuthorityError || Error || sync_transport.Error;
pub const TransportMode = state_support.TransportMode;
pub const WorkspacePolicyRequest = state_support.WorkspacePolicyRequest;
pub const WorkspacePolicy = state_support.WorkspacePolicy;
pub const OverlayRecord = state_support.OverlayRecord;
pub const DatabaseContract = state_support.DatabaseContract;
pub const ReplicationSummary = state_support.ReplicationSummary;
pub const ConflictReviewDecision = state_support.ConflictReviewDecision;
pub const ConflictReviewRecord = state_support.ConflictReviewRecord;
pub const TransportFrame = sync_adapters.TransportFrame;
pub const TransportFrameRequest = sync_adapters.QueueFrameRequest;
pub const OverlaySession = @import("overlay.zig").OverlaySession;
pub const OverlaySessionUse = @import("overlay.zig").OverlaySessionUse;
pub const OverlayRelayFrameRequest = @import("overlay.zig").OverlayRelayFrameRequest;
pub const OverlayRelayFrameResult = @import("overlay.zig").OverlayRelayFrameResult;
pub const PeerReplicationRequest = @import("replication_model.zig").PeerReplicationRequest;
pub const PeerReplicationResult = @import("replication_model.zig").PeerReplicationResult;

pub fn SyncPortWith(comptime ServiceType: type) type {
    return struct {
        const Self = @This();

        service: *ServiceType,
        capability_table: *const capability.CapabilityTable,

        pub fn init(service: *ServiceType, capability_table: *const capability.CapabilityTable) Self {
            return .{
                .service = service,
                .capability_table = capability_table,
            };
        }

        pub fn ensureUserRoot(
            self: *Self,
            authority: AuthorityContext,
            user_principal: principal.PrincipalId,
            label: []const u8,
            identity: signing.SignerIdentity,
        ) (AuthorityError || Error)!*device_graph.UserRootRecord {
            _ = try self.requireSyncAuthority(authority);
            return self.service.ensureUserRoot(user_principal, label, identity);
        }

        pub fn enrollTrustedDevice(
            self: *Self,
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
            self: *Self,
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
            self: *Self,
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
            self: *Self,
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
            self: *Self,
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
            self: *Self,
            authority: AuthorityContext,
            request: network_policy.CreateRequest,
        ) (AuthorityError || Error)!*network_policy.PolicyRecord {
            _ = try self.requireSyncAuthority(authority);
            return self.service.createNetworkPolicy(request);
        }

        pub fn evaluateNetworkPolicy(
            self: *Self,
            authority: AuthorityContext,
            policy_id: u64,
            destination: network_policy.Destination,
        ) (AuthorityError || Error)!network_policy.Decision {
            _ = try self.requireSyncAuthority(authority);
            return self.service.evaluateNetworkPolicy(policy_id, destination);
        }

        pub fn configureWorkspacePolicy(
            self: *Self,
            authority: AuthorityContext,
            request: WorkspacePolicyRequest,
        ) (AuthorityError || Error)!*WorkspacePolicy {
            _ = try self.requireSyncAuthority(authority);
            return self.service.configureWorkspacePolicy(request);
        }

        pub fn configureOverlay(
            self: *Self,
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
            self: *Self,
            authority: AuthorityContext,
            workspace_id: u64,
            label: []const u8,
        ) (AuthorityError || Error)!*OverlayRecord {
            _ = try self.requireSyncAuthority(authority);
            return self.service.publishPrivateService(workspace_id, label);
        }

        pub fn openOverlaySession(
            self: *Self,
            authority: AuthorityContext,
            workspace_id: u64,
            from_device: principal.PrincipalId,
            to_device: principal.PrincipalId,
            usage: OverlaySessionUse,
            transport: TransportMode,
            private_service_label: ?[]const u8,
            tick: u64,
        ) (AuthorityError || Error)!*const OverlaySession {
            _ = try self.requireSyncAuthority(authority);
            return self.service.openOverlaySession(workspace_id, from_device, to_device, usage, transport, private_service_label, tick);
        }

        pub fn probeOverlaySession(
            self: *Self,
            authority: AuthorityContext,
            session_id: u64,
            tick: u64,
        ) (AuthorityError || Error)!bool {
            _ = try self.requireSyncAuthority(authority);
            return self.service.probeOverlaySession(session_id, tick);
        }

        pub fn closeOverlaySession(
            self: *Self,
            authority: AuthorityContext,
            session_id: u64,
            tick: u64,
        ) (AuthorityError || Error)!bool {
            _ = try self.requireSyncAuthority(authority);
            return self.service.closeOverlaySession(session_id, tick);
        }

        pub fn sendOverlayRelayFrameViaService(
            self: *Self,
            authority: AuthorityContext,
            network_capabilities: *const capability.CapabilityTable,
            relay_service: *sync_transport.BootedOverlayRelayService,
            request: OverlayRelayFrameRequest,
        ) (AuthorityError || Error || sync_transport.Error)!OverlayRelayFrameResult {
            _ = try self.requireSyncAuthority(authority);
            return self.service.sendOverlayRelayFrameViaService(network_capabilities, relay_service, request);
        }

        pub fn setReplicaVersion(
            self: *Self,
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
            self: *Self,
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
            self: *Self,
            authority: AuthorityContext,
            store: *const storage_service.Service,
            workspace_id: u64,
            from_device: principal.PrincipalId,
            to_device: principal.PrincipalId,
            transport: TransportMode,
        ) (AuthorityError || Error)!ReplicationSummary {
            _ = try self.requireSyncAuthority(authority);
            const policy = self.service.findWorkspacePolicy(workspace_id) orelse return error.WorkspacePolicyNotFound;
            try self.authorizeWorkspaceAnyShare(store, policy, to_device, transport, authority.now_ticks);
            return self.service.replicateWorkspace(store, workspace_id, from_device, to_device, transport);
        }

        pub fn replicateWorkspaceToPeer(
            self: *Self,
            authority: AuthorityContext,
            peer: *Self,
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
            transport_frames.sortById(frames[0..frame_count]);

            var acked_ids: [MAX_TRANSPORT_FRAMES]u64 = undefined;
            var acked_count: usize = 0;

            peer.service.beginReplicationBatch();
            errdefer peer.service.cancelReplicationBatch();
            for (frames[0..frame_count]) |frame| {
                const delivery = try self.replicateFramePayloadToPeer(peer, request, frame);
                result.accepted_frame_count += 1;
                result.persisted_object_count += 1;
                result.payload_bytes += delivery.payload_len;
                acked_ids[acked_count] = frame.id;
                acked_count += 1;
                if (delivery.used_booted_relay_service) {
                    result.used_booted_relay_service = true;
                    result.relay_delivery_count += delivery.relay_delivery_count;
                }
            }
            try peer.service.endReplicationBatch();

            _ = try self.service.ackOutboundTransportFrames(acked_ids[0..acked_count]);
            return result;
        }

        pub fn acceptTransportFrame(
            self: *Self,
            authority: AuthorityContext,
            store: *const storage_service.Service,
            request: TransportFrameRequest,
        ) (AuthorityError || Error)!TransportFrame {
            _ = try self.requireSyncAuthority(authority);
            const policy = self.service.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
            try self.authorizeWorkspaceFrameShare(store, policy, request, authority.now_ticks);
            return self.service.acceptTransportFrame(store, request);
        }

        pub fn transferSecretObject(
            self: *Self,
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
            self: *Self,
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
            self: *Self,
            authority: AuthorityContext,
            store: *const storage_service.Service,
            workspace_id: u64,
            device_id: principal.PrincipalId,
        ) (AuthorityError || Error)!bool {
            _ = try self.requireSyncAuthority(authority);
            return self.service.repairWorkspaceMetadata(store, workspace_id, device_id);
        }

        pub fn reviewConflict(
            self: *Self,
            authority: AuthorityContext,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
        ) (AuthorityError || Error)!ConflictReviewRecord {
            _ = try self.requireSyncAuthority(authority);
            return self.service.reviewConflict(workspace_id, device_id, path);
        }

        pub fn reviewConflictForObject(
            self: *Self,
            authority: AuthorityContext,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            object_id: anytype,
        ) (AuthorityError || Error)!ConflictReviewRecord {
            _ = try self.requireSyncAuthority(authority);
            return self.service.reviewConflictForObject(workspace_id, device_id, object_id);
        }

        pub fn resolveConflict(
            self: *Self,
            authority: AuthorityContext,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            path: []const u8,
            decision: ConflictReviewDecision,
        ) (AuthorityError || Error)!ConflictReviewRecord {
            _ = try self.requireSyncAuthority(authority);
            return self.service.resolveConflict(workspace_id, device_id, path, decision);
        }

        pub fn resolveConflictForObject(
            self: *Self,
            authority: AuthorityContext,
            workspace_id: u64,
            device_id: principal.PrincipalId,
            object_id: anytype,
            decision: ConflictReviewDecision,
        ) (AuthorityError || Error)!ConflictReviewRecord {
            _ = try self.requireSyncAuthority(authority);
            return self.service.resolveConflictForObject(workspace_id, device_id, object_id, decision);
        }

        fn requireSyncAuthority(self: *Self, authority: AuthorityContext) AuthorityError!*const capability.Capability {
            return service_authority.requireServiceAuthority(
                self.capability_table,
                self.service.service_id,
                authority,
                .endpoint_connect,
            );
        }

        fn validatePeerReplicationRequest(
            self: *Self,
            request: PeerReplicationRequest,
        ) PeerReplicationError!void {
            try self.service.ensureTrustedDevices(request.from_device, request.to_device);
            const policy = self.service.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
            try self.service.authorizeTransport(policy, request.transport, null);
            try self.authorizeWorkspaceAnyShare(request.source_storage, policy, request.to_device, request.transport, request.tick);
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

        fn authorizeWorkspaceAnyShare(
            self: *Self,
            store: *const storage_service.Service,
            policy: *const WorkspacePolicy,
            target_device: principal.PrincipalId,
            transport: TransportMode,
            now_ticks: u64,
        ) Error!void {
            _ = self;
            if (!policy.require_shared_access) return;
            if (!store.workspaceHasAnyAccess(policy.workspace_id, .{
                .principal_id = target_device,
                .network_scope = shareNetworkScopeForTransport(transport),
                .now_ticks = now_ticks,
            })) return error.TransportDenied;
        }

        fn authorizeWorkspaceFrameShare(
            self: *Self,
            store: *const storage_service.Service,
            policy: *const WorkspacePolicy,
            request: TransportFrameRequest,
            now_ticks: u64,
        ) Error!void {
            _ = self;
            if (!policy.require_shared_access) return;
            if (!store.workspaceHasAccess(policy.workspace_id, .{
                .principal_id = request.target_device,
                .object_id = object_store.ids.object(request.object_id),
                .path = request.path,
                .network_scope = shareNetworkScopeForTransport(request.transport),
                .now_ticks = now_ticks,
            })) return error.TransportDenied;
        }

        fn shareNetworkScopeForTransport(transport: TransportMode) workspace.ShareNetworkScope {
            return switch (transport) {
                .device_to_device => .local_only,
                .relay_assisted => .relay_assisted,
            };
        }

        const PeerFrameDelivery = struct {
            payload_len: usize,
            relay_delivery_count: usize = 0,
            used_booted_relay_service: bool,
        };

        fn replicateFramePayloadToPeer(
            self: *Self,
            peer: *Self,
            request: PeerReplicationRequest,
            frame: TransportFrame,
        ) PeerReplicationError!PeerFrameDelivery {
            const source_version = request.source_storage.version(frame.version_id) orelse return error.VersionNotFound;
            const payload = try request.source_storage.versionPayload(source_version);
            var used_booted_relay_service = false;
            var relay_delivery_count: usize = 0;

            if (request.transport == .relay_assisted) {
                relay_delivery_count = try self.relayPayloadToPeer(request, payload);
                used_booted_relay_service = true;
            }

            const parent_version_id = if (request.target_storage.resolve(frame.workspace_id, frame.pathSlice())) |current|
                if (current.object_id.raw() == frame.object_id) current.version_id else null
            else |err| switch (err) {
                error.EntryNotFound => null,
                else => return err,
            };
            if (frame.semantic == .transactional_contract) {
                try self.replicateDatabaseContractMetadataToPeer(peer, frame.workspace_id, frame.pathSlice());
            }
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
                .source_frame_id = frame.id,
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
                .relay_delivery_count = relay_delivery_count,
                .used_booted_relay_service = used_booted_relay_service,
            };
        }

        fn relayPayloadToPeer(
            self: *Self,
            request: PeerReplicationRequest,
            payload: []const u8,
        ) PeerReplicationError!usize {
            if (payload.len == 0) {
                return try self.relayPayloadChunkToPeer(request, payload);
            }

            var offset: usize = 0;
            var delivery_count: usize = 0;
            while (offset < payload.len) {
                const end = @min(offset + sync_transport.MAX_NATIVE_PAYLOAD_BYTES, payload.len);
                delivery_count += try self.relayPayloadChunkToPeer(request, payload[offset..end]);
                offset = end;
            }
            return delivery_count;
        }

        fn relayPayloadChunkToPeer(
            self: *Self,
            request: PeerReplicationRequest,
            payload: []const u8,
        ) PeerReplicationError!usize {
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
            _ = try self.service.closeOverlaySession(relay_result.overlay_session_id, request.tick);
            return 1;
        }

        fn replicateDatabaseContractMetadataToPeer(
            self: *Self,
            peer: *Self,
            workspace_id: u64,
            path: []const u8,
        ) PeerReplicationError!void {
            const contract = self.service.findDatabaseContractForPath(workspace_id, path) orelse return error.DatabaseContractNotFound;
            _ = try peer.service.importDatabaseContract(contract);
        }
    };
}
