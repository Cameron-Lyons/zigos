const std = @import("std");
const immutable_base = @import("immutable_base.zig");
const object_store = @import("object_store.zig");
const principal = @import("principal.zig");
const signing = @import("signing.zig");
const storage_service = @import("storage_service.zig");
const sync_service = @import("sync_service.zig");
const workspace = @import("workspace.zig");

pub const RecoveryReport = struct {
    image_verified: bool = false,
    image_reinstalled: bool = false,
    device_trust_revoked: bool = false,
    snapshot_restored: bool = false,
    sync_metadata_repaired: bool = false,
    device_keys_rotated: bool = false,
};

pub const Environment = struct {
    owner: principal.PrincipalId,
    report: RecoveryReport = .{},

    pub fn init(owner: principal.PrincipalId) Environment {
        return .{ .owner = owner };
    }

    pub fn verifyAndReinstallImage(
        self: *Environment,
        manager: *immutable_base.Manager,
        payload: []const u8,
        signer: signing.SignerIdentity,
        tick: u64,
    ) immutable_base.Error!bool {
        const verified = manager.verifyActiveImage();
        _ = try manager.stageImage(manager.inactiveSlotIndex(), "recovery-reinstall", payload, signer, tick);
        self.report.image_verified = verified;
        self.report.image_reinstalled = manager.verifySlot(manager.inactiveSlotIndex());
        return self.report.image_verified and self.report.image_reinstalled;
    }

    pub fn revokeDeviceTrust(
        self: *Environment,
        sync: *sync_service.Service,
        user: principal.PrincipalId,
        device: principal.PrincipalId,
        signer: signing.SignerIdentity,
        tick: u64,
    ) sync_service.Error!bool {
        try sync.revokeTrustedDevice(user, device, signer, tick);
        self.report.device_trust_revoked = !sync.isTrustedDevice(device);
        return self.report.device_trust_revoked;
    }

    pub fn restoreWorkspaceSnapshot(
        self: *Environment,
        storage: *storage_service.Service,
        workspace_id: u64,
        snapshot_id: u64,
        tick: u64,
    ) workspace.Error!bool {
        _ = try storage.restore(workspace_id, snapshot_id, tick);
        self.report.snapshot_restored = true;
        return true;
    }

    pub fn repairSyncMetadata(
        self: *Environment,
        sync: *sync_service.Service,
        storage: *const storage_service.Service,
        workspace_id: u64,
        device_id: principal.PrincipalId,
    ) sync_service.Error!bool {
        self.report.sync_metadata_repaired = try sync.repairWorkspaceMetadata(storage, workspace_id, device_id);
        return self.report.sync_metadata_repaired;
    }

    pub fn rotateDeviceKeys(
        self: *Environment,
        sync: *sync_service.Service,
        user: principal.PrincipalId,
        device: principal.PrincipalId,
        signer: signing.SignerIdentity,
        next_signer: signing.SignerIdentity,
        tick: u64,
    ) sync_service.Error!u32 {
        const record = try sync.rotateDeviceKey(user, device, signer, next_signer, tick);
        self.report.device_keys_rotated = record.key_rotation_generation >= 2;
        return record.key_rotation_generation;
    }
};

test "recovery environment verifies reinstalls restores repairs and rotates" {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const primary_device = principal.PrincipalId{ .kind = .device, .serial = 21 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 22 };

    const state_signer = signing.SignerIdentity{
        .label = "phase6-state",
        .seed = [_]u8{0x71} ** 32,
    };
    const image_signer = signing.SignerIdentity{
        .label = "phase6-image",
        .seed = [_]u8{0x72} ** 32,
    };
    const object_signer = signing.SignerIdentity{
        .label = "phase6-storage",
        .seed = [_]u8{0x73} ** 32,
    };
    const user_signer = signing.SignerIdentity{
        .label = "phase6-user",
        .seed = [_]u8{0x74} ** 32,
    };
    const device_signer = signing.SignerIdentity{
        .label = "primary-device",
        .seed = [_]u8{0x75} ** 32,
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "tablet-device",
        .seed = [_]u8{0x76} ** 32,
    };
    const tablet_rotated_signer = signing.SignerIdentity{
        .label = "tablet-device-v2",
        .seed = [_]u8{0x77} ** 32,
    };

    var storage = storage_service.Service.init(920, 51, storage_owner);
    var manager = try immutable_base.Manager.init(&storage, storage_owner, state_signer);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    _ = try manager.activate(0, .{}, 11);

    const notes = try storage.putVersion(.{
        .preferred_object_id = 980,
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(object_signer, "notes", "text/plain", .document, "notes-v1", 12),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "recovery-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes.object_id, notes.version_id, .document);
    _ = try storage.commit(workspace_record.id, 13);
    const snapshot = try storage.snapshot(workspace_record.id, "baseline", object_signer);

    var sync = sync_service.Service.init(921, 52, sync_owner);
    _ = try sync.ensureUserRoot(user, "cameron", user_signer);
    _ = try sync.enrollTrustedDevice(user, primary_device, "primary", user_signer, device_signer, 14);
    _ = try sync.enrollTrustedDevice(user, tablet, "tablet", user_signer, tablet_signer, 15);
    const local_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "local-net",
        .mode = .local_network,
    });
    _ = try sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_record.id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
    });
    try sync.setReplicaVersion(workspace_record.id, tablet, "documents/notes.md", notes.object_id, notes.version_id + 1);
    _ = try sync.replicateWorkspace(&storage, workspace_record.id, primary_device, tablet, .device_to_device);

    var recovery = Environment.init(storage_owner);
    try std.testing.expect(try recovery.verifyAndReinstallImage(&manager, "kernel=v2", image_signer, 16));
    try std.testing.expect(try recovery.restoreWorkspaceSnapshot(&storage, workspace_record.id, snapshot.id, 17));
    try std.testing.expect(try recovery.repairSyncMetadata(&sync, &storage, workspace_record.id, tablet));
    try std.testing.expectEqual(@as(u32, 2), try recovery.rotateDeviceKeys(&sync, user, tablet, user_signer, tablet_rotated_signer, 18));
    try std.testing.expect(try recovery.revokeDeviceTrust(&sync, user, tablet, user_signer, 19));
    try std.testing.expect(recovery.report.image_verified);
    try std.testing.expect(recovery.report.image_reinstalled);
    try std.testing.expect(recovery.report.snapshot_restored);
    try std.testing.expect(recovery.report.sync_metadata_repaired);
    try std.testing.expect(recovery.report.device_keys_rotated);
    try std.testing.expect(recovery.report.device_trust_revoked);

    sync_service.Service.resetPersistentState();
    storage_service.Service.resetPersistentState();
}
