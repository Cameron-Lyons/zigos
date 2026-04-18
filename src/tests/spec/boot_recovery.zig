const std = @import("std");
const spec_support = @import("support.zig");
const compositor_session = @import("../../native/platform/compositor_session.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const immutable_base = @import("../../native/platform/immutable_base.zig");
const measured_boot = @import("../../native/platform/measured_boot.zig");
const object_store = @import("../../native/storage/object_store.zig");
const recovery_environment = @import("../../native/platform/recovery_environment.zig");
const supervisor = @import("../../native/session/supervisor.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const sync_service = @import("../../native/sync/sync_service.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const update_health = @import("../../native/platform/update_health.zig");

const PendingActivationFailureCase = struct {
    expected_failure: immutable_base.HealthFailure,
    begin_tick: u64,
    validation_tick: u64,
    boot_success_tick: ?u64 = null,
    storage_probe_path: []const u8 = "documents/notes.md",
    crash_service_id: ?u64 = null,
    crash_tick: u64 = 0,
    crash_reason: u32 = 0,
    mark_healthy_tick: ?u64 = null,
};

fn expectPendingActivationFailure(
    manager: *immutable_base.Manager,
    supervisor_instance: *supervisor.Supervisor,
    storage: *storage_service.Service,
    ledger: *event_ledger.Ledger,
    base_request: update_health.CheckRequest,
    case: PendingActivationFailureCase,
) !void {
    try manager.beginActivation(1, case.begin_tick);
    if (case.boot_success_tick) |tick| {
        try update_health.recordBootSuccess(manager, tick);
    }
    if (case.crash_service_id) |service_id| {
        try std.testing.expect(supervisor_instance.recordCrash(service_id, case.crash_tick, case.crash_reason));
    }

    const request = update_health.CheckRequest{
        .core_service_ids = base_request.core_service_ids,
        .storage_workspace_id = base_request.storage_workspace_id,
        .storage_probe_path = case.storage_probe_path,
        .network_service_id = base_request.network_service_id,
        .ui_service_id = base_request.ui_service_id,
        .network_probe = base_request.network_probe,
        .ui_probe = base_request.ui_probe,
    };
    const failure = try update_health.validatePendingActivation(
        manager,
        supervisor_instance,
        storage,
        request,
        ledger,
        case.validation_tick,
    );
    try std.testing.expectEqual(case.expected_failure, failure.activation.failure);

    if (case.crash_service_id) |service_id| {
        try std.testing.expect(supervisor_instance.markHealthy(service_id, case.mark_healthy_tick.?));
    }
}

pub fn baseImageStaysSignedMeasuredAtomicAndRollbackCapable() !void {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const owner = spec_support.service(40);
    const state_signer = spec_support.signer("spec.base.state", 0x51);
    const image_signer = spec_support.signer("spec.base.image", 0x52);

    var storage = storage_service.Service.initWithStore(700, 70, owner, &storage_checkpoint_store);
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
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

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

    var storage = storage_service.Service.initWithStore(800, 80, storage_owner, &storage_checkpoint_store);
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

pub fn baseOsHealthChecksValidateBootCoreStorageNetworkAndUi() !void {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const owner = spec_support.service(41);
    const state_signer = spec_support.signer("spec.health.state", 0x53);
    const image_signer = spec_support.signer("spec.health.image", 0x54);
    const object_signer = spec_support.signer("spec.health.object", 0x55);
    const user = spec_support.user(41);
    const source_device = spec_support.device(411);
    const target_device = spec_support.device(412);
    const user_signer = spec_support.signer("spec.health.user", 0x56);
    const source_signer = spec_support.signer("spec.health.source", 0x57);
    const target_signer = spec_support.signer("spec.health.target", 0x58);

    var storage = storage_service.Service.initWithStore(701, 71, owner, &storage_checkpoint_store);
    var manager = try immutable_base.Manager.init(&storage, owner, state_signer);
    var sync = sync_service.Service.init(702, 72, owner);
    var compositor = compositor_session.Session.init();

    const probe_record = try storage.putVersion(.{
        .preferred_object_id = 1_210,
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(object_signer, "notes", "text/plain", .document, "notes-v1", 10),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = owner,
        .label = "health-checks",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", probe_record.object_id, probe_record.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);

    _ = try sync.ensureUserRoot(user, "owner", user_signer);
    _ = try sync.enrollTrustedDevice(user, source_device, "source", user_signer, source_signer, 12);
    _ = try sync.enrollTrustedDevice(user, target_device, "target", user_signer, target_signer, 13);
    const local_policy = try sync.createNetworkPolicy(.{
        .owner = owner,
        .workspace_id = workspace_record.id,
        .label = "health-local",
        .mode = .local_network,
    });
    const overlay_policy = try sync.createNetworkPolicy(.{
        .owner = owner,
        .workspace_id = workspace_record.id,
        .label = "health-overlay",
        .mode = .named_service_identity,
        .target = "overlay.health.sync",
    });
    _ = try sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_record.id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
    });
    _ = try sync.configureOverlay(workspace_record.id, source_device, "overlay.health.sync", true);

    var ui_runtime = task_runtime.Runtime.init();
    const ui_task = try ui_runtime.createTask(.{
        .owner = owner,
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 4 * 1024,
        },
        .ui_surface_id = 7,
        .initial_component = .{
            .label = "health-ui",
            .entry = "zigos.health.ui",
        },
    });
    _ = try compositor.openTaskView(ui_task, "Update Health");

    var supervisor_instance = supervisor.Supervisor.init();
    const policy_service = try supervisor_instance.register(.policy_mediation, owner);
    const package_service = try supervisor_instance.register(.package_install_update, owner);
    const sync_service_record = try supervisor_instance.register(.sync_replication, owner);
    const network_service = try supervisor_instance.register(.network_stack, owner);
    const compositor_service = try supervisor_instance.register(.compositor_ui_session, owner);
    try std.testing.expect(supervisor_instance.noteContractBound(policy_service.id, 5001, 12));
    try std.testing.expect(supervisor_instance.noteContractBound(package_service.id, 5002, 12));
    try std.testing.expect(supervisor_instance.noteContractBound(sync_service_record.id, 5003, 12));
    try std.testing.expect(supervisor_instance.noteContractBound(network_service.id, 5004, 12));
    try std.testing.expect(supervisor_instance.noteContractBound(compositor_service.id, 5005, 12));
    try std.testing.expect(supervisor_instance.markHealthy(policy_service.id, 12));
    try std.testing.expect(supervisor_instance.markHealthy(package_service.id, 12));
    try std.testing.expect(supervisor_instance.markHealthy(sync_service_record.id, 12));
    try std.testing.expect(supervisor_instance.markHealthy(network_service.id, 12));
    try std.testing.expect(supervisor_instance.markHealthy(compositor_service.id, 12));

    const core_service_ids = [_]u64{
        policy_service.id,
        package_service.id,
        sync_service_record.id,
    };
    const request = update_health.CheckRequest{
        .core_service_ids = core_service_ids[0..],
        .storage_workspace_id = workspace_record.id,
        .storage_probe_path = "documents/notes.md",
        .network_service_id = network_service.id,
        .ui_service_id = compositor_service.id,
        .network_probe = .{
            .sync = &sync,
            .workspace_id = workspace_record.id,
            .source_device = source_device,
            .target_device = target_device,
            .tick = 14,
        },
        .ui_probe = .{ .session = &compositor },
    };
    var ledger = event_ledger.Ledger.init();

    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 13);
    try manager.beginActivation(0, 14);
    try update_health.recordBootSuccess(&manager, 15);
    const initial = try update_health.validatePendingActivation(&manager, &supervisor_instance, &storage, request, &ledger, 16);
    try std.testing.expect(initial.evaluation.report.isHealthy());

    _ = try manager.stageImage(1, "stable-b", "kernel=v2", image_signer, 17);

    const failure_cases = [_]PendingActivationFailureCase{
        .{
            .expected_failure = .boot,
            .begin_tick = 18,
            .validation_tick = 19,
        },
        .{
            .expected_failure = .core_service,
            .begin_tick = 20,
            .boot_success_tick = 21,
            .crash_service_id = sync_service_record.id,
            .crash_tick = 22,
            .crash_reason = 0xCA11,
            .validation_tick = 23,
            .mark_healthy_tick = 24,
        },
        .{
            .expected_failure = .storage,
            .begin_tick = 25,
            .boot_success_tick = 26,
            .storage_probe_path = "documents/missing.md",
            .validation_tick = 27,
        },
        .{
            .expected_failure = .network,
            .begin_tick = 28,
            .boot_success_tick = 29,
            .crash_service_id = network_service.id,
            .crash_tick = 30,
            .crash_reason = 0xCA12,
            .validation_tick = 31,
            .mark_healthy_tick = 32,
        },
        .{
            .expected_failure = .ui,
            .begin_tick = 33,
            .boot_success_tick = 34,
            .crash_service_id = compositor_service.id,
            .crash_tick = 35,
            .crash_reason = 0xCA13,
            .validation_tick = 36,
            .mark_healthy_tick = 37,
        },
    };
    for (failure_cases) |case| {
        try expectPendingActivationFailure(&manager, &supervisor_instance, &storage, &ledger, request, case);
    }

    try manager.beginActivation(1, 38);
    try update_health.recordBootSuccess(&manager, 39);
    const success = try update_health.validatePendingActivation(&manager, &supervisor_instance, &storage, request, &ledger, 40);
    try std.testing.expect(!success.activation.rolled_back);
    try std.testing.expectEqual(@as(?usize, 1), success.activation.active_slot);
    try std.testing.expectEqual(@as(u64, 5), success.activation.rollback_generation);

    var export_buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=update_transition") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=boot") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=core_service") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=storage") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=network") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=ui") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "rollback=yes") != null);
}
