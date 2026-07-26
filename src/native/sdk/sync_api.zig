const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const network_policy = @import("../sync/network_policy.zig");
const object_store = @import("../storage/object_store.zig");
const object_store_api = @import("object_store_api.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sync_service_facade = @import("../sync/sync_service.zig");

const sync_service = sync_service_facade;

pub const TransportMode = sync_service.TransportMode;
pub const WorkspacePolicy = sync_service.WorkspacePolicy;
pub const DatabaseContract = sync_service.DatabaseContract;
pub const OverlaySession = sync_service.OverlaySession;
pub const OverlaySessionUse = sync_service.OverlaySessionUse;
pub const Error = sync_service.AuthorityError || sync_service.Error || error{
    PathNotSelected,
    PrefixTooLong,
};

pub const DEFAULT_SERVICE_ID: u64 = 64_100;
pub const DEFAULT_TASK_ID: u64 = 64_101;
pub const DEFAULT_OWNER = principal.PrincipalId{ .kind = .service, .serial = 64_102 };
pub const DEFAULT_USER = principal.PrincipalId{ .kind = .user, .serial = 64_103 };
pub const DEFAULT_LOCAL_DEVICE = principal.PrincipalId{ .kind = .device, .serial = 64_104 };
pub const DEFAULT_PEER_DEVICE = principal.PrincipalId{ .kind = .device, .serial = 64_105 };

pub const user_identity = signing.SignerIdentity{
    .label = "sdk.sync.user",
    .seed = signing.seedFromByte(0x41),
};
pub const local_device_identity = signing.SignerIdentity{
    .label = "sdk.sync.local",
    .seed = signing.seedFromByte(0x42),
};
pub const peer_device_identity = signing.SignerIdentity{
    .label = "sdk.sync.peer",
    .seed = signing.seedFromByte(0x43),
};

pub const LocalFirstWorkspace = struct {
    workspace_id: u64,
    offline_first: bool = true,
    personal_e2ee: bool = true,
    prefix_count: usize = 0,
    prefixes: [sync_service.MAX_SELECTIVE_PREFIXES][sync_service.MAX_PREFIX_BYTES]u8 =
        [_][sync_service.MAX_PREFIX_BYTES]u8{[_]u8{0} ** sync_service.MAX_PREFIX_BYTES} ** sync_service.MAX_SELECTIVE_PREFIXES,
    prefix_lens: [sync_service.MAX_SELECTIVE_PREFIXES]usize = [_]usize{0} ** sync_service.MAX_SELECTIVE_PREFIXES,

    pub fn matchesPath(self: *const LocalFirstWorkspace, path: []const u8) bool {
        if (self.prefix_count == 0) return true;
        for (self.prefixes[0..self.prefix_count], 0..) |prefix, index| {
            if (std.mem.startsWith(u8, path, prefix[0..self.prefix_lens[index]])) return true;
        }
        return false;
    }
};

pub const DevNode = struct {
    service: sync_service.Service,
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    authority_capability: capability.Capability = undefined,
    authority_ready: bool = false,
    now_ticks: u64 = 1,

    pub fn init() DevNode {
        return .{
            .service = sync_service.Service.init(DEFAULT_SERVICE_ID, DEFAULT_TASK_ID, DEFAULT_OWNER),
        };
    }

    pub fn bootstrap(self: *DevNode) !void {
        if (self.authority_ready) return;
        self.authority_capability = try sync_service.mintEndpointConnectAuthority(
            &self.capabilities,
            &self.service,
            0,
            std.math.maxInt(u64),
        );
        var sync_port = self.port();
        const sync_authority = self.authority();
        _ = try sync_port.ensureUserRoot(sync_authority, DEFAULT_USER, "sdk-user", user_identity);
        _ = try sync_port.enrollTrustedDevice(sync_authority, DEFAULT_USER, DEFAULT_LOCAL_DEVICE, "local", user_identity, local_device_identity, self.nextTick());
        _ = try sync_port.enrollTrustedDevice(sync_authority, DEFAULT_USER, DEFAULT_PEER_DEVICE, "peer", user_identity, peer_device_identity, self.nextTick());
        self.authority_ready = true;
    }

    pub fn configureLocalFirstWorkspace(self: *DevNode, workspace_id: u64, prefixes: []const []const u8) !*WorkspacePolicy {
        try self.bootstrap();
        var sync_port = self.port();
        const local_policy = try sync_port.createNetworkPolicy(self.authority(), .{
            .owner = DEFAULT_OWNER,
            .workspace_id = workspace_id,
            .label = "sdk-local",
            .mode = .local_network,
        });
        return sync_port.configureWorkspacePolicy(self.authority(), .{
            .workspace_id = workspace_id,
            .owner = DEFAULT_USER,
            .offline_first = true,
            .personal_e2ee = true,
            .selective_prefixes = prefixes,
            .device_to_device_policy_id = local_policy.id,
        });
    }

    pub fn openLocalFirstWorkspace(self: *DevNode, workspace_id: u64, prefixes: []const []const u8) !LocalFirstWorkspace {
        const policy = try self.configureLocalFirstWorkspace(workspace_id, prefixes);
        return workspaceHandleFromPolicy(policy);
    }

    pub fn recordReplicaVersion(
        self: *DevNode,
        workspace_id: u64,
        path: []const u8,
        object_id: anytype,
        version_id: anytype,
    ) !void {
        try self.bootstrap();
        var sync_port = self.port();
        return sync_port.setReplicaVersion(self.authority(), workspace_id, DEFAULT_PEER_DEVICE, path, object_id, version_id);
    }

    pub fn publishObject(
        self: *DevNode,
        workspace: LocalFirstWorkspace,
        path: []const u8,
        handle: object_store_api.ObjectHandle,
    ) !void {
        if (!workspace.matchesPath(path)) return error.PathNotSelected;
        try self.recordReplicaVersion(workspace.workspace_id, path, handle.object_id, handle.version_id);
    }

    pub fn replicaVersion(self: *const DevNode, workspace_id: u64, path: []const u8) ?u64 {
        return self.service.replicaVersion(workspace_id, DEFAULT_PEER_DEVICE, path);
    }

    pub fn replicaVersionFor(self: *const DevNode, workspace: LocalFirstWorkspace, path: []const u8) ?u64 {
        if (!workspace.matchesPath(path)) return null;
        return self.replicaVersion(workspace.workspace_id, path);
    }

    pub fn registerDatabaseContract(
        self: *DevNode,
        workspace_id: u64,
        bundle_id: []const u8,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) !*DatabaseContract {
        try self.bootstrap();
        var sync_port = self.port();
        return sync_port.registerDatabaseContract(self.authority(), workspace_id, bundle_id, label, identity);
    }

    pub fn evaluateLocalNetwork(self: *DevNode, workspace_id: u64) !bool {
        try self.bootstrap();
        const policy = self.service.findWorkspacePolicy(workspace_id) orelse return error.WorkspacePolicyNotFound;
        var sync_port = self.port();
        const decision = try sync_port.evaluateNetworkPolicy(self.authority(), policy.device_to_device_policy_id.?, .local_network);
        return decision.allowed;
    }

    /// Returns an in-process, read-only borrow from this node's embedded service.
    /// Keep this `DevNode` at a stable address. Closing remains observable as
    /// `.closed`; after a later open reuses the slot, the pointer must not be
    /// dereferenced.
    pub fn openPrivateServiceSession(
        self: *DevNode,
        workspace_id: u64,
        service_identity: []const u8,
        private_service_label: []const u8,
    ) !*const OverlaySession {
        try self.bootstrap();
        const existing = self.service.findWorkspacePolicy(workspace_id) orelse
            try self.configureLocalFirstWorkspace(workspace_id, &.{});

        var prefixes: [sync_service.MAX_SELECTIVE_PREFIXES][]const u8 = undefined;
        for (existing.selective_prefixes[0..existing.selective_prefix_count], 0..) |prefix, index| {
            prefixes[index] = prefix[0..existing.selective_prefix_lens[index]];
        }

        var sync_port = self.port();
        const overlay_policy = try sync_port.createNetworkPolicy(self.authority(), .{
            .owner = DEFAULT_OWNER,
            .workspace_id = workspace_id,
            .label = "sdk-private-service",
            .mode = .named_service_identity,
            .target = service_identity,
        });
        _ = try sync_port.configureWorkspacePolicy(self.authority(), .{
            .workspace_id = workspace_id,
            .owner = DEFAULT_USER,
            .offline_first = existing.offline_first,
            .personal_e2ee = existing.personal_e2ee,
            .require_shared_access = existing.require_shared_access,
            .selective_prefixes = prefixes[0..existing.selective_prefix_count],
            .device_to_device_policy_id = existing.device_to_device_policy_id,
            .overlay_policy_id = overlay_policy.id,
        });
        _ = try sync_port.configureOverlay(self.authority(), workspace_id, DEFAULT_LOCAL_DEVICE, service_identity, false);
        _ = try sync_port.publishPrivateService(self.authority(), workspace_id, private_service_label);
        return sync_port.openOverlaySession(
            self.authority(),
            workspace_id,
            DEFAULT_LOCAL_DEVICE,
            DEFAULT_PEER_DEVICE,
            .private_service,
            .device_to_device,
            private_service_label,
            self.nextTick(),
        );
    }

    pub fn port(self: *DevNode) sync_service.SyncPort {
        return sync_service.SyncPort.init(&self.service, &self.capabilities);
    }

    pub fn authority(self: *const DevNode) sync_service.AuthorityContext {
        return sync_service.authorityContext(&self.service, self.authority_capability, self.now_ticks);
    }

    fn nextTick(self: *DevNode) u64 {
        defer self.now_ticks += 1;
        return self.now_ticks;
    }
};

fn workspaceHandleFromPolicy(policy: *const WorkspacePolicy) Error!LocalFirstWorkspace {
    var handle = LocalFirstWorkspace{
        .workspace_id = policy.workspace_id,
        .offline_first = policy.offline_first,
        .personal_e2ee = policy.personal_e2ee,
        .prefix_count = policy.selective_prefix_count,
    };
    for (policy.selective_prefixes[0..policy.selective_prefix_count], 0..) |prefix, index| {
        const len = policy.selective_prefix_lens[index];
        if (len > handle.prefixes[index].len) return error.PrefixTooLong;
        @memcpy(handle.prefixes[index][0..len], prefix[0..len]);
        handle.prefix_lens[index] = len;
    }
    return handle;
}

pub fn objectId(raw: u64) object_store.ids.ObjectId {
    return object_store.ids.object(raw);
}

pub fn versionId(raw: u64) object_store.ids.VersionId {
    return object_store.ids.version(raw);
}

test "sync SDK configures local-first policy and records replica state" {
    var node = DevNode.init();
    const workspace_id: u64 = 9_001;
    const policy = try node.configureLocalFirstWorkspace(workspace_id, &.{"documents/"});
    try std.testing.expect(policy.offline_first);
    try std.testing.expect(policy.personal_e2ee);
    try std.testing.expect(try node.evaluateLocalNetwork(workspace_id));

    try node.recordReplicaVersion(workspace_id, "documents/notes.md", objectId(11), versionId(12));
    try std.testing.expectEqual(@as(?u64, 12), node.replicaVersion(workspace_id, "documents/notes.md"));
    try std.testing.expectEqual(@as(?u64, null), node.replicaVersion(workspace_id, "media/photo.png"));

    const contract_signer = signing.SignerIdentity{
        .label = "sdk.sync.contract",
        .seed = signing.seedFromByte(0x44),
    };
    const contract = try node.registerDatabaseContract(workspace_id, "app.zigos.writer", "writer-db", contract_signer);
    try std.testing.expectEqualStrings("app.zigos.writer", contract.bundleIdSlice());
}

test "sync SDK publishes object handles through selective local-first workspaces" {
    var node = DevNode.init();
    const workspace = try node.openLocalFirstWorkspace(9_101, &.{"documents/"});

    var objects = object_store_api.Client.init(user_identity);
    const handle = try objects.putDocumentObject("notes.md", "text/markdown", "# Notes");
    try node.publishObject(workspace, "documents/notes.md", handle);
    try std.testing.expectEqual(@as(?u64, handle.version_id.raw()), node.replicaVersionFor(workspace, "documents/notes.md"));
    try std.testing.expectError(error.PathNotSelected, node.publishObject(workspace, "media/notes.md", handle));

    const session = try node.openPrivateServiceSession(workspace.workspace_id, "overlay.sdk.notes", "notes-private-api");
    try std.testing.expectEqual(OverlaySessionUse.private_service, session.usage);
    try std.testing.expect(session.encrypted);
}
