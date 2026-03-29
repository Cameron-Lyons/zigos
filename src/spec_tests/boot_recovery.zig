const std = @import("std");
const spec_support = @import("support.zig");
const immutable_base = @import("../kernel/process/native/immutable_base.zig");
const measured_boot = @import("../kernel/process/native/measured_boot.zig");
const object_store = @import("../kernel/process/native/object_store.zig");
const recovery_environment = @import("../kernel/process/native/recovery_environment.zig");
const storage_service = @import("../kernel/process/native/storage_service.zig");
const sync_service = @import("../kernel/process/native/sync_service.zig");

pub fn baseImageStaysSignedMeasuredAtomicAndRollbackCapable() !void {
    storage_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();

    const owner = spec_support.service(40);
    const state_signer = spec_support.signer("spec.base.state", 0x51);
    const image_signer = spec_support.signer("spec.base.image", 0x52);

    var storage = storage_service.Service.init(700, 70, owner);
    var manager = try immutable_base.Manager.init(&storage, owner, state_signer);

    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    const first_activation = try manager.activate(0, .{}, 11);
    try std.testing.expectEqual(@as(?usize, 0), first_activation.active_slot);
    try std.testing.expect(!first_activation.rolled_back);
    try std.testing.expect(manager.verifyActiveImage());

    _ = try manager.stageImage(1, "stable-b", "kernel=v2", image_signer, 12);
    const rollback = try manager.activate(1, .{
        .network_ok = false,
    }, 13);
    try std.testing.expect(rollback.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.network, rollback.failure);
    try std.testing.expectEqual(@as(?usize, 0), rollback.active_slot);
    try std.testing.expectEqual(@as(u64, 1), rollback.rollback_generation);

    const active = manager.activeImage().?;
    try std.testing.expectEqualStrings("stable-a", active.labelSlice());
    try std.testing.expect(manager.verifySlot(0));
    try std.testing.expect(manager.verifySlot(1));

    var recorder = measured_boot.Recorder.init();
    recorder.begin(rollback.activation_generation);
    try recorder.add(.kernel, "kernel-zigos-native", "kernel=v1");
    try recorder.add(.base_image, active.labelSlice(), active.measurement[0..]);
    try recorder.add(.critical_service, "storage", "healthy");
    try recorder.add(.policy, "network-egress", "explicit-grants");
    try recorder.add(.driver_set, "signed-drivers", "network+storage+graphics");
    const boot = recorder.finalize();

    try std.testing.expectEqual(rollback.activation_generation, boot.generation);
    try std.testing.expectEqual(@as(usize, 5), boot.record_count);
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.kernel));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.base_image));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.critical_service));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.policy));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.driver_set));
    try std.testing.expect(!std.mem.allEqual(u8, &boot.root_digest, 0));
}

pub fn recoveryModeCanReinstallRestoreRepairRotateAndRevoke() !void {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

    const storage_owner = spec_support.service(50);
    const sync_owner = spec_support.service(51);
    const person = spec_support.user(5);
    const primary = spec_support.device(51);
    const tablet = spec_support.device(52);
    const state_signer = spec_support.signer("spec.recovery.state", 0x61);
    const image_signer = spec_support.signer("spec.recovery.image", 0x62);
    const object_signer = spec_support.signer("spec.recovery.object", 0x63);
    const user_signer = spec_support.signer("spec.recovery.user", 0x64);
    const primary_signer = spec_support.signer("spec.recovery.primary", 0x65);
    const tablet_signer = spec_support.signer("spec.recovery.tablet", 0x66);
    const rotated_tablet_signer = spec_support.signer("spec.recovery.tablet.v2", 0x67);

    var storage = storage_service.Service.init(800, 80, storage_owner);
    var manager = try immutable_base.Manager.init(&storage, storage_owner, state_signer);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    _ = try manager.activate(0, .{}, 11);

    const notes = try storage.putVersion(.{
        .preferred_object_id = 1_200,
        .object_type = .document,
        .payload = "incident-v1",
        .metadata = try object_store.signMetadata(object_signer, "incident", "text/plain", .document, "incident-v1", 12),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "incident",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/incident.md", notes.object_id, notes.version_id, .document);
    _ = try storage.commit(workspace_record.id, 13);
    const snapshot = try storage.snapshot(workspace_record.id, "clean", object_signer);

    var sync = sync_service.Service.init(801, 81, sync_owner);
    _ = try sync.ensureUserRoot(person, "owner", user_signer);
    _ = try sync.enrollTrustedDevice(person, primary, "primary", user_signer, primary_signer, 14);
    _ = try sync.enrollTrustedDevice(person, tablet, "tablet", user_signer, tablet_signer, 15);

    const local_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "local",
        .mode = .local_network,
    });
    _ = try sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_record.id,
        .owner = person,
        .device_to_device_policy_id = local_policy.id,
    });
    try sync.setReplicaVersion(workspace_record.id, tablet, "documents/incident.md", notes.object_id, notes.version_id + 1);
    _ = try sync.replicateWorkspace(&storage, workspace_record.id, primary, tablet, .device_to_device);

    var recovery = recovery_environment.Environment.init(storage_owner);
    try std.testing.expect(try recovery.verifyAndReinstallImage(&manager, "kernel=v2", image_signer, 16));
    try std.testing.expect(try recovery.restoreWorkspaceSnapshot(&storage, workspace_record.id, snapshot.id, 17));
    try std.testing.expect(try recovery.repairSyncMetadata(&sync, &storage, workspace_record.id, tablet));
    try std.testing.expectEqual(@as(u32, 2), try recovery.rotateDeviceKeys(&sync, person, tablet, user_signer, rotated_tablet_signer, 18));
    try std.testing.expect(try recovery.revokeDeviceTrust(&sync, person, tablet, user_signer, 19));

    try std.testing.expect(recovery.report.image_verified);
    try std.testing.expect(recovery.report.image_reinstalled);
    try std.testing.expect(recovery.report.snapshot_restored);
    try std.testing.expect(recovery.report.sync_metadata_repaired);
    try std.testing.expect(recovery.report.device_keys_rotated);
    try std.testing.expect(recovery.report.device_trust_revoked);
    try std.testing.expect(!sync.isTrustedDevice(tablet));
}
