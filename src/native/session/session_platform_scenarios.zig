const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const contract = @import("contract.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const immutable_base = @import("../platform/immutable_base.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_ux = @import("../platform/native_ux.zig");
const object_store_mod = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const recovery_environment = @import("../platform/recovery_environment.zig");
const signing = @import("../core/signing.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const update_health = @import("../platform/update_health.zig");
const workspace_mod = @import("../storage/workspace.zig");
const support = @import("session_lifecycle_support.zig");

pub fn run(
    context: *support.Context,
    sync_service: *sync_service_mod.Service,
    storage_state: support.StorageScenarioState,
    sync_state: support.SyncScenarioState,
) void {
    const platform_state_signer = signing.SignerIdentity{
        .label = "zigos-base-state",
        .seed = [_]u8{0xA1} ** 32,
    };
    const platform_image_signer = signing.SignerIdentity{
        .label = "zigos-base-image",
        .seed = [_]u8{0xA2} ** 32,
    };
    const recovery_device_signer = signing.SignerIdentity{
        .label = "recovery-device",
        .seed = [_]u8{0xA3} ** 32,
    };
    const recovery_rotated_signer = signing.SignerIdentity{
        .label = "recovery-device-v2",
        .seed = [_]u8{0xA4} ** 32,
    };
    const paired_device_signer = signing.SignerIdentity{
        .label = "paired-device",
        .seed = [_]u8{0xA5} ** 32,
    };
    const local_device_principal = principal.PrincipalId{ .kind = .device, .serial = 1 };
    const recovery_device_principal = principal.PrincipalId{
        .kind = .device,
        .serial = 4,
    };
    const paired_device_principal = principal.PrincipalId{ .kind = .device, .serial = 5 };

    support.common.printBootMarker("ZIGOS:PLATFORM:INIT_START");
    support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:LOOKUP_START");
    var immutable_base_workspace_found = true;
    const immutable_base_workspace = context.storage_service_instance.findWorkspace(
        context.package_service_principal,
        immutable_base.state_workspace_label,
    ) orelse context.storage_service_instance.findWorkspaceByLabel(immutable_base.state_workspace_label) orelse blk: {
        immutable_base_workspace_found = false;
        support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:LOOKUP_MISS");
        const request = workspace_mod.CreateRequest{
            .owner = context.package_service_principal,
            .label = immutable_base.state_workspace_label,
        };
        support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:CREATE_START");
        break :blk context.storage_service_instance.createWorkspaceRef(&request) catch unreachable;
    };
    if (immutable_base_workspace_found) {
        support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:LOOKUP_HIT");
    }
    support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:WORKSPACE_READY");
    var immutable_base_manager = immutable_base.Manager.initWithWorkspace(
        context.storage_service_instance,
        context.package_service_principal,
        platform_state_signer,
        immutable_base_workspace.id,
    ) catch unreachable;
    const core_health_service_ids = [_]u64{
        context.policy_service_id,
        context.package_service_id,
        context.sync_service_id,
    };
    support.common.printBootMarker("ZIGOS:PLATFORM:INIT_READY");
    if (immutable_base_manager.activeImage() == null) {
        support.common.printBootMarker("ZIGOS:PLATFORM:SEED_START");
        _ = immutable_base_manager.stageImage(
            0,
            "stable-a",
            "kernel=v1;base=stable-a;mode=ro",
            platform_image_signer,
            108,
        ) catch unreachable;
        support.common.printBootMarker("ZIGOS:PLATFORM:SEED_SLOT0");
        immutable_base_manager.beginActivation(0, 109) catch unreachable;
        update_health.recordBootSuccess(&immutable_base_manager, 110) catch unreachable;
        _ = update_health.validatePendingActivation(
            &immutable_base_manager,
            context.supervisor,
            context.storage_service_instance,
            .{
                .core_service_ids = core_health_service_ids[0..],
                .storage_workspace_id = storage_state.notes_workspace_id,
                .storage_probe_path = "documents/notes.md",
                .network_service_id = context.network_service_id,
                .ui_service_id = context.compositor_service_id,
                .network_probe = .{
                    .sync = sync_service,
                    .workspace_id = storage_state.notes_workspace_id,
                    .source_device = local_device_principal,
                    .target_device = sync_state.tablet_device_principal,
                    .tick = 110,
                },
                .ui_probe = .{ .session = context.compositor },
            },
            context.update_ledger,
            111,
        ) catch unreachable;
        support.common.printBootMarker("ZIGOS:PLATFORM:SEED_SLOT0_ACTIVE");
        _ = immutable_base_manager.stageImage(
            1,
            "stable-b",
            "kernel=v2;base=stable-b;mode=ro",
            platform_image_signer,
            112,
        ) catch unreachable;
        support.common.printBootMarker("ZIGOS:PLATFORM:SEED_SLOT1");

        immutable_base_manager.beginActivation(1, 113) catch unreachable;
        const boot_failure = update_health.validatePendingActivation(
            &immutable_base_manager,
            context.supervisor,
            context.storage_service_instance,
            .{
                .core_service_ids = core_health_service_ids[0..],
                .storage_workspace_id = storage_state.notes_workspace_id,
                .storage_probe_path = "documents/notes.md",
                .network_service_id = context.network_service_id,
                .ui_service_id = context.compositor_service_id,
                .network_probe = .{
                    .sync = sync_service,
                    .workspace_id = storage_state.notes_workspace_id,
                    .source_device = local_device_principal,
                    .target_device = sync_state.tablet_device_principal,
                    .tick = 113,
                },
                .ui_probe = .{ .session = context.compositor },
            },
            context.update_ledger,
            114,
        ) catch unreachable;
        if (boot_failure.activation.rolled_back and boot_failure.activation.failure == .boot) {
            support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:BOOT_ROLLBACK");
        }
        immutable_base_manager.beginActivation(1, 115) catch unreachable;
        update_health.recordBootSuccess(&immutable_base_manager, 116) catch unreachable;
        _ = context.supervisor.recordCrash(context.sync_service_id, 117, 0x0602);
        const core_failure = update_health.validatePendingActivation(
            &immutable_base_manager,
            context.supervisor,
            context.storage_service_instance,
            .{
                .core_service_ids = core_health_service_ids[0..],
                .storage_workspace_id = storage_state.notes_workspace_id,
                .storage_probe_path = "documents/notes.md",
                .network_service_id = context.network_service_id,
                .ui_service_id = context.compositor_service_id,
                .network_probe = .{
                    .sync = sync_service,
                    .workspace_id = storage_state.notes_workspace_id,
                    .source_device = local_device_principal,
                    .target_device = sync_state.tablet_device_principal,
                    .tick = 117,
                },
                .ui_probe = .{ .session = context.compositor },
            },
            context.update_ledger,
            118,
        ) catch unreachable;
        _ = context.supervisor.markHealthy(context.sync_service_id, 119);
        if (core_failure.activation.rolled_back and core_failure.activation.failure == .core_service) {
            support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:CORE_ROLLBACK");
        }
        immutable_base_manager.beginActivation(1, 120) catch unreachable;
        update_health.recordBootSuccess(&immutable_base_manager, 121) catch unreachable;
        _ = context.supervisor.recordCrash(context.compositor_service_id, 122, 0x0603);
        const ui_failure = update_health.validatePendingActivation(
            &immutable_base_manager,
            context.supervisor,
            context.storage_service_instance,
            .{
                .core_service_ids = core_health_service_ids[0..],
                .storage_workspace_id = storage_state.notes_workspace_id,
                .storage_probe_path = "documents/notes.md",
                .network_service_id = context.network_service_id,
                .ui_service_id = context.compositor_service_id,
                .network_probe = .{
                    .sync = sync_service,
                    .workspace_id = storage_state.notes_workspace_id,
                    .source_device = local_device_principal,
                    .target_device = sync_state.tablet_device_principal,
                    .tick = 122,
                },
                .ui_probe = .{ .session = context.compositor },
            },
            context.update_ledger,
            123,
        ) catch unreachable;
        _ = context.supervisor.markHealthy(context.compositor_service_id, 124);
        if (ui_failure.activation.rolled_back and ui_failure.activation.failure == .ui) {
            support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:UI_ROLLBACK");
        }
        immutable_base_manager.beginActivation(1, 125) catch unreachable;
        update_health.recordBootSuccess(&immutable_base_manager, 126) catch unreachable;
        const storage_failure = update_health.validatePendingActivation(
            &immutable_base_manager,
            context.supervisor,
            context.storage_service_instance,
            .{
                .core_service_ids = core_health_service_ids[0..],
                .storage_workspace_id = storage_state.notes_workspace_id,
                .storage_probe_path = "documents/missing.md",
                .network_service_id = context.network_service_id,
                .ui_service_id = context.compositor_service_id,
                .network_probe = .{
                    .sync = sync_service,
                    .workspace_id = storage_state.notes_workspace_id,
                    .source_device = local_device_principal,
                    .target_device = sync_state.tablet_device_principal,
                    .tick = 126,
                },
                .ui_probe = .{ .session = context.compositor },
            },
            context.update_ledger,
            127,
        ) catch unreachable;
        if (storage_failure.activation.rolled_back and storage_failure.activation.failure == .storage) {
            support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:STORAGE_ROLLBACK");
        }
        immutable_base_manager.beginActivation(1, 128) catch unreachable;
        update_health.recordBootSuccess(&immutable_base_manager, 129) catch unreachable;
        _ = context.supervisor.recordCrash(context.network_service_id, 130, 0x0604);
        const network_failure = update_health.validatePendingActivation(
            &immutable_base_manager,
            context.supervisor,
            context.storage_service_instance,
            .{
                .core_service_ids = core_health_service_ids[0..],
                .storage_workspace_id = storage_state.notes_workspace_id,
                .storage_probe_path = "documents/notes.md",
                .network_service_id = context.network_service_id,
                .ui_service_id = context.compositor_service_id,
                .network_probe = .{
                    .sync = sync_service,
                    .workspace_id = storage_state.notes_workspace_id,
                    .source_device = local_device_principal,
                    .target_device = sync_state.tablet_device_principal,
                    .tick = 130,
                },
                .ui_probe = .{ .session = context.compositor },
            },
            context.update_ledger,
            131,
        ) catch unreachable;
        _ = context.supervisor.markHealthy(context.network_service_id, 132);
        if (network_failure.activation.rolled_back and network_failure.activation.failure == .network) {
            support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:NETWORK_ROLLBACK");
        }
        immutable_base_manager.beginActivation(1, 133) catch unreachable;
        update_health.recordBootSuccess(&immutable_base_manager, 134) catch unreachable;
        _ = update_health.validatePendingActivation(
            &immutable_base_manager,
            context.supervisor,
            context.storage_service_instance,
            .{
                .core_service_ids = core_health_service_ids[0..],
                .storage_workspace_id = storage_state.notes_workspace_id,
                .storage_probe_path = "documents/notes.md",
                .network_service_id = context.network_service_id,
                .ui_service_id = context.compositor_service_id,
                .network_probe = .{
                    .sync = sync_service,
                    .workspace_id = storage_state.notes_workspace_id,
                    .source_device = local_device_principal,
                    .target_device = sync_state.tablet_device_principal,
                    .tick = 134,
                },
                .ui_probe = .{ .session = context.compositor },
            },
            context.update_ledger,
            135,
        ) catch unreachable;
    }

    if (immutable_base_manager.rollback_generation >= 1) {
        support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:BOOT_ROLLBACK");
    }
    if (immutable_base_manager.rollback_generation >= 2) {
        support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:CORE_ROLLBACK");
    }
    if (immutable_base_manager.rollback_generation >= 3) {
        support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:UI_ROLLBACK");
    }
    if (immutable_base_manager.rollback_generation >= 4) {
        support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:STORAGE_ROLLBACK");
    }
    if (immutable_base_manager.rollback_generation >= 5) {
        support.common.printBootMarker("ZIGOS:PLATFORM:HEALTHCHECK:NETWORK_ROLLBACK");
    }

    const active_base_image = immutable_base_manager.activeImage().?;
    if (immutable_base_manager.verifyActiveImage() and active_base_image.read_only) {
        support.common.printBootMarker(boot_markers.platform_immutable_base_active);
    }
    if (immutable_base_manager.rollback_generation >= 5) {
        support.common.printBootMarker(boot_markers.platform_activation_rollback_ok);
    }

    var measured = measured_boot.Recorder.init();
    measured.begin(immutable_base_manager.activation_generation);
    measured.add(.kernel, "kernel-zigos-native", "platform-native-kernel") catch unreachable;
    measured.add(.base_image, active_base_image.labelSlice(), &active_base_image.measurement) catch unreachable;
    var policy_measure: [96]u8 = undefined;
    const policy_measure_text = std.fmt.bufPrint(
        &policy_measure,
        "offline={d}:e2ee={d}:overlay={d}",
        .{
            @intFromBool(sync_state.workspace_policy.offline_first),
            @intFromBool(sync_state.workspace_policy.personal_e2ee),
            sync_state.workspace_policy.overlay_policy_id orelse 0,
        },
    ) catch unreachable;
    measured.add(.policy, "workspace-policy", policy_measure_text) catch unreachable;
    const critical_services = [_]*supervisor_mod.ServiceRecord{
        context.supervisor.find(context.policy_service_id).?,
        context.supervisor.find(context.storage_service_id).?,
        context.supervisor.find(context.compositor_service_id).?,
        context.supervisor.find(context.network_service_id).?,
    };
    for (critical_services) |service_record| {
        var service_measure: [96]u8 = undefined;
        const service_measure_text = std.fmt.bufPrint(
            &service_measure,
            "{s}:{d}:{d}",
            .{
                contract.serviceName(service_record.class),
                @intFromEnum(service_record.state),
                service_record.restart_count,
            },
        ) catch unreachable;
        measured.add(.critical_service, contract.serviceName(service_record.class), service_measure_text) catch unreachable;
    }
    var driver_measure: [192]u8 = undefined;
    const driver_measure_text = std.fmt.bufPrint(
        &driver_measure,
        "{s}:{d}:{s}|{s}:{d}:{s}|{s}:{d}:{s}",
        .{
            context.driver_directory.findByClass(.network_adapter).?.signerSlice(),
            context.driver_directory.findByClass(.network_adapter).?.restart_generation,
            device_inventory.sourceName(device_inventory.recordForClass(.network_adapter).source),
            context.driver_directory.findByClass(.storage_controller).?.signerSlice(),
            context.driver_directory.findByClass(.storage_controller).?.restart_generation,
            device_inventory.sourceName(device_inventory.recordForClass(.storage_controller).source),
            context.driver_directory.findByClass(.graphics_adapter).?.signerSlice(),
            context.driver_directory.findByClass(.graphics_adapter).?.restart_generation,
            device_inventory.sourceName(device_inventory.recordForClass(.graphics_adapter).source),
        },
    ) catch unreachable;
    measured.add(.driver_set, "core-driver-set", driver_measure_text) catch unreachable;
    const measured_boot_record = measured.finalize();
    if (measured_boot_record.countKind(.kernel) == 1 and
        measured_boot_record.countKind(.base_image) == 1 and
        measured_boot_record.countKind(.critical_service) == 4 and
        measured_boot_record.countKind(.policy) == 1 and
        measured_boot_record.countKind(.driver_set) == 1 and
        !std.mem.allEqual(u8, &measured_boot_record.root_digest, 0))
    {
        support.common.printBootMarker(boot_markers.platform_measured_boot_recorded);
    }

    if (sync_service.findDeviceRecord(recovery_device_principal) == null) {
        _ = sync_service.enrollTrustedDevice(
            context.session_user,
            recovery_device_principal,
            "recovery-device",
            sync_state.user_root_signer,
            recovery_device_signer,
            117,
        ) catch unreachable;
    }

    var recovery = recovery_environment.Environment.init(context.session_service);
    if (recovery.verifyAndReinstallImage(
        &immutable_base_manager,
        "kernel=v2;base=reinstalled;mode=ro",
        platform_image_signer,
        118,
    ) catch unreachable) {
        support.common.printBootMarker(boot_markers.platform_recovery_verify_reinstall);
    }

    if (context.export_package.workspace_id != storage_state.notes_workspace_id or
        context.export_package.snapshot_id == 0)
    {
        const recovery_snapshot_id = if (context.storage_service_instance.findSnapshot(storage_state.notes_workspace_id, "platform-recovery")) |snapshot|
            snapshot.id
        else created: {
            const snapshot = context.storage_service_instance.snapshot(
                storage_state.notes_workspace_id,
                "platform-recovery",
                support.workspace_signer,
            ) catch unreachable;
            break :created snapshot.id;
        };
        context.storage_service_instance.exportSnapshotInto(
            storage_state.notes_workspace_id,
            recovery_snapshot_id,
            support.export_signer,
            context.export_package,
        ) catch unreachable;
    }

    support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:NOTES_V3_START");
    const notes_v3_request = object_store_mod.PutRequest{
        .object_type = .document,
        .payload = "# Notes\n- platform recovery drift\n",
        .metadata = object_store_mod.signMetadata(
            support.storage_signer,
            "notes",
            "text/markdown",
            .document,
            "# Notes\n- platform recovery drift\n",
            136,
        ) catch unreachable,
        .preferred_object_id = null,
        .parent_version_id = storage_state.latest_notes_version_id,
    };
    _ = context.storage_service_instance.putVersionRef(&notes_v3_request) catch unreachable;
    support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:NOTES_V3_PUT");
    const notes_v3 = support.latestInsertedVersion(context.storage_service_instance).?;
    const notes_object_id = notes_v3.object_id;
    const notes_v3_version_id = notes_v3.id;
    support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:NOTES_V3_LATEST");
    context.storage_service_instance.beginTransaction(storage_state.notes_workspace_id) catch unreachable;
    context.storage_service_instance.stagePut(
        storage_state.notes_workspace_id,
        "documents/notes.md",
        notes_object_id,
        notes_v3_version_id,
        .document,
    ) catch unreachable;
    _ = context.storage_service_instance.commit(storage_state.notes_workspace_id, 137) catch unreachable;
    support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:NOTES_V3_COMMIT");
    _ = recovery.restoreWorkspaceExport(
        context.storage_service_instance,
        storage_state.notes_workspace_id,
        context.export_package,
        138,
    ) catch unreachable;
    support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:RESTORE_APPLIED");
    const restored_notes = context.storage_service_instance.resolve(storage_state.notes_workspace_id, "documents/notes.md") catch unreachable;
    _ = restored_notes;

    if (sync_service.findWorkspacePolicy(storage_state.notes_workspace_id) == null) {
        _ = sync_service.configureWorkspacePolicy(.{
            .workspace_id = storage_state.notes_workspace_id,
            .owner = context.session_user,
            .offline_first = true,
            .personal_e2ee = true,
            .selective_prefixes = &.{ "documents/", "assets/" },
            .device_to_device_policy_id = sync_state.local_network_policy_id,
            .relay_policy_id = sync_state.relay_policy_id,
            .overlay_policy_id = sync_state.overlay_policy_id,
            .relay_domain = "relay.zigos.dev",
        }) catch unreachable;
    }
    if (recovery.repairSyncMetadata(
        sync_service,
        context.storage_service_instance,
        storage_state.notes_workspace_id,
        sync_state.tablet_device_principal,
    ) catch unreachable and sync_service.findConflict(storage_state.notes_workspace_id, sync_state.tablet_device_principal, "documents/notes.md") == null) {
        support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:REPAIR_SYNC");
    }

    const recovery_device_record = sync_service.findDeviceRecord(recovery_device_principal).?;
    if (recovery_device_record.isTrusted() and recovery_device_record.key_rotation_generation < 2) {
        _ = recovery.rotateDeviceKeys(
            sync_service,
            context.session_user,
            recovery_device_principal,
            sync_state.user_root_signer,
            recovery_rotated_signer,
            139,
        ) catch unreachable;
    }
    if (sync_service.findDeviceRecord(recovery_device_principal).?.key_rotation_generation >= 2) {
        support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:ROTATE_KEYS");
    }
    if (sync_service.isTrustedDevice(recovery_device_principal)) {
        _ = recovery.revokeDeviceTrust(
            sync_service,
            context.session_user,
            recovery_device_principal,
            sync_state.user_root_signer,
            140,
        ) catch unreachable;
    }
    if (!sync_service.isTrustedDevice(recovery_device_principal)) {
        support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:REVOKE_TRUST");
    }

    var ux = native_ux.Controller.init();
    const notes_task = ux.startTask(context.runtime, .{
        .owner = context.session_user,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 6_000,
            .memory_bytes = 512 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 32 * 1024,
            .background_allowed = false,
        },
        .ui_surface_id = 2,
        .local_only = true,
        .initial_component = .{
            .label = "notes-task",
            .entry = "app.notes",
        },
    }) catch unreachable;
    if (notes_task.component_class == .app_component) {
        support.common.printBootMarker("ZIGOS:PLATFORM:UX:START_TASK");
    }
    const task_view = context.compositor.openTaskView(notes_task, "Edit Notes") catch unreachable;
    if (task_view.id != 0) {
        support.common.printBootMarker("ZIGOS:PLATFORM:UX:TASK_VIEW");
    }

    const opened_workspace = ux.openWorkspace(
        context.storage_service_instance,
        storage_state.notes_workspace_id,
        "documents/notes.md",
        context.session_user,
    ) catch unreachable;
    const workspace_record = context.storage_service_instance.findWorkspaceRecord(storage_state.notes_workspace_id).?;
    const workspace_view = context.compositor.openWorkspaceView(
        notes_task,
        storage_state.notes_workspace_id,
        workspace_record.labelSlice(),
    ) catch unreachable;
    const document_view = context.compositor.openDocumentView(
        notes_task,
        storage_state.notes_workspace_id,
        "documents/notes.md",
    ) catch unreachable;
    if (opened_workspace.version_id != 0) {
        support.common.printBootMarker("ZIGOS:PLATFORM:UX:OPEN_WORKSPACE");
    }
    if (workspace_view.id != 0 and document_view.id != 0) {
        support.common.printBootMarker("ZIGOS:PLATFORM:UX:WINDOW_VIEWS");
    }

    ux.pairDevice(
        sync_service,
        context.session_user,
        paired_device_principal,
        "paired-device",
        sync_state.user_root_signer,
        paired_device_signer,
        141,
    ) catch unreachable;
    context.update_ledger.recordDeviceTrustChange(
        context.session_user,
        paired_device_principal,
        true,
        141,
        "device paired",
    ) catch unreachable;
    if (sync_service.isTrustedDevice(paired_device_principal)) {
        support.common.printBootMarker("ZIGOS:PLATFORM:UX:PAIR_DEVICE");
    }

    if (ux.reviewPermissionRequest(
        notes_task.id,
        context.session_user,
        .object_access,
        true,
    ) catch unreachable) {
        support.common.printBootMarker("ZIGOS:PLATFORM:UX:REVIEW_PERMISSION");
    }
    ux.recoverSystem(notes_task.id, context.session_user, "recovery-environment") catch unreachable;
    if (ux.flow_count == 5) {
        support.common.printBootMarker(boot_markers.platform_ux_recover_system);
    }

    context.runtime_service.checkpoint(142);
    context.storage_service_instance.checkpoint_enabled = true;
    context.storage_service_instance.checkpoint();
    support.common.printBootMarker(boot_markers.task_session_ready);
    support.common.printBootMarker(boot_markers.native_ready);
}
