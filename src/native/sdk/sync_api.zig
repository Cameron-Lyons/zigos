const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const network_policy = @import("../sync/network_policy.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sync_service = @import("../sync/sync_service.zig");

pub const TransportMode = sync_service.TransportMode;
pub const WorkspacePolicy = sync_service.WorkspacePolicy;
pub const DatabaseContract = sync_service.DatabaseContract;
pub const Error = sync_service.AuthorityError || sync_service.Error;

pub const DEFAULT_SERVICE_ID: u64 = 64_100;
pub const DEFAULT_TASK_ID: u64 = 64_101;
pub const DEFAULT_OWNER = principal.PrincipalId{ .kind = .service, .serial = 64_102 };
pub const DEFAULT_USER = principal.PrincipalId{ .kind = .user, .serial = 64_103 };
pub const DEFAULT_LOCAL_DEVICE = principal.PrincipalId{ .kind = .device, .serial = 64_104 };
pub const DEFAULT_PEER_DEVICE = principal.PrincipalId{ .kind = .device, .serial = 64_105 };

pub const user_identity = signing.SignerIdentity{
    .label = "sdk.sync.user",
    .seed = [_]u8{0x41} ** signing.SEED_BYTES,
};
pub const local_device_identity = signing.SignerIdentity{
    .label = "sdk.sync.local",
    .seed = [_]u8{0x42} ** signing.SEED_BYTES,
};
pub const peer_device_identity = signing.SignerIdentity{
    .label = "sdk.sync.peer",
    .seed = [_]u8{0x43} ** signing.SEED_BYTES,
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

    pub fn replicaVersion(self: *const DevNode, workspace_id: u64, path: []const u8) ?u64 {
        return self.service.replicaVersion(workspace_id, DEFAULT_PEER_DEVICE, path);
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
        .seed = [_]u8{0x44} ** signing.SEED_BYTES,
    };
    const contract = try node.registerDatabaseContract(workspace_id, "app.zigos.writer", "writer-db", contract_signer);
    try std.testing.expectEqualStrings("app.zigos.writer", contract.bundleIdSlice());
}
