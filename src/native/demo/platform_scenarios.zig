const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const contract = @import("../session/contract.zig");
const immutable_base = @import("../platform/immutable_base.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const measured_boot_console = @import("../platform/measured_boot_console.zig");
const native_ux = @import("../platform/native_ux.zig");
const object_store_mod = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const recovery_environment = @import("../platform/recovery_environment.zig");
const signing = @import("../core/signing.zig");
const supervisor_mod = @import("../session/supervisor.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const update_health = @import("../platform/update_health.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const workspace_mod = @import("../storage/workspace.zig");
const support = @import("scenario_support.zig");

const paired_device_tick: u64 = 141;
const ux_flow_ledger_start_tick: u64 = paired_device_tick + 1;

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
    const sync_authority_capability = context.capability_table.mintBootRoot(.{
        .holder = context.sync_service_principal,
        .issuer = context.policy_authority,
        .target = .{ .kind = .service, .id = context.sync_service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = context.sync_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 1_000,
        },
        .audit = .{},
    }) catch unreachable;
    var sync_port = sync_service_mod.SyncPort.init(sync_service, context.capability_table);
    const sync_authority = sync_service_mod.AuthorityContext{
        .task_id = context.sync_task_id,
        .principal = context.sync_service_principal,
        .capability_id = sync_authority_capability.id,
        .now_ticks = 117,
    };

    support.common.printBootMarker("ZIGOS:PLATFORM:INIT_START");
    support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:LOOKUP_START");
    const immutable_base_workspace_state = ensureImmutableBaseWorkspace(context);
    if (immutable_base_workspace_state.found_existing) {
        support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:LOOKUP_HIT");
    }
    support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:WORKSPACE_READY");
    var immutable_base_manager = immutable_base.Manager.initWithWorkspace(
        context.storage_service_instance,
        context.package_service_principal,
        platform_state_signer,
        immutable_base_workspace_state.workspace.id,
    ) catch unreachable;
    const core_health_service_ids = [_]u64{
        context.policy_service_id,
        context.package_service_id,
        context.sync_service_id,
    };
    const activation_probe = ActivationProbeContext{
        .context = context,
        .sync_service = sync_service,
        .storage_state = storage_state,
        .sync_state = sync_state,
        .core_health_service_ids = core_health_service_ids[0..],
        .local_device_principal = local_device_principal,
        .capability_table = context.capability_table,
        .sync_authority = sync_authority,
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
        _ = beginSuccessfulActivation(
            &activation_probe,
            &immutable_base_manager,
            0,
            "documents/notes.md",
            109,
            110,
            110,
            111,
        );
        support.common.printBootMarker("ZIGOS:PLATFORM:SEED_SLOT0_ACTIVE");
        _ = immutable_base_manager.stageImage(
            1,
            "stable-b",
            "kernel=v2;base=stable-b;mode=ro",
            platform_image_signer,
            112,
        ) catch unreachable;
        support.common.printBootMarker("ZIGOS:PLATFORM:SEED_SLOT1");

        const boot_failure = beginValidatedActivation(
            &activation_probe,
            &immutable_base_manager,
            1,
            "documents/notes.md",
            113,
            113,
            114,
        );
        emitRollbackMarker(
            boot_failure,
            .boot,
            "ZIGOS:PLATFORM:HEALTHCHECK:BOOT_ROLLBACK",
        );
        _ = context.supervisor.recordCrash(context.sync_service_id, 117, 0x0602);
        const core_failure = beginSuccessfulActivation(
            &activation_probe,
            &immutable_base_manager,
            1,
            "documents/notes.md",
            115,
            116,
            117,
            118,
        );
        _ = context.supervisor.markHealthy(context.sync_service_id, 119);
        emitRollbackMarker(
            core_failure,
            .core_service,
            "ZIGOS:PLATFORM:HEALTHCHECK:CORE_ROLLBACK",
        );
        _ = context.supervisor.recordCrash(context.compositor_service_id, 122, 0x0603);
        const ui_failure = beginSuccessfulActivation(
            &activation_probe,
            &immutable_base_manager,
            1,
            "documents/notes.md",
            120,
            121,
            122,
            123,
        );
        _ = context.supervisor.markHealthy(context.compositor_service_id, 124);
        emitRollbackMarker(
            ui_failure,
            .ui,
            "ZIGOS:PLATFORM:HEALTHCHECK:UI_ROLLBACK",
        );
        const storage_failure = beginSuccessfulActivation(
            &activation_probe,
            &immutable_base_manager,
            1,
            "documents/missing.md",
            125,
            126,
            126,
            127,
        );
        emitRollbackMarker(
            storage_failure,
            .storage,
            "ZIGOS:PLATFORM:HEALTHCHECK:STORAGE_ROLLBACK",
        );
        _ = context.supervisor.recordCrash(context.network_service_id, 130, 0x0604);
        const network_failure = beginSuccessfulActivation(
            &activation_probe,
            &immutable_base_manager,
            1,
            "documents/notes.md",
            128,
            129,
            130,
            131,
        );
        _ = context.supervisor.markHealthy(context.network_service_id, 132);
        emitRollbackMarker(
            network_failure,
            .network,
            "ZIGOS:PLATFORM:HEALTHCHECK:NETWORK_ROLLBACK",
        );
        _ = beginSuccessfulActivation(
            &activation_probe,
            &immutable_base_manager,
            1,
            "documents/notes.md",
            133,
            134,
            134,
            135,
        );
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
        if (criticalServiceImage(context, service_record)) |image| {
            measured.addCriticalServiceImage(service_record, image) catch unreachable;
        } else {
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
    }
    measured.addDriverSet("core-driver-set", context.driver_directory) catch unreachable;
    const measured_boot_record = measured.finalize();
    measured_boot_console.printMeasurementSummary(&measured_boot_record);
    if (measured_boot_record.countKind(.kernel) == 1 and
        measured_boot_record.countKind(.base_image) == 1 and
        measured_boot_record.countKind(.critical_service) == 4 and
        measured_boot_record.countKind(.policy) == 1 and
        measured_boot_record.countKind(.driver_set) == 1 and
        !std.mem.allEqual(u8, &measured_boot_record.root_digest, 0))
    {
        support.common.printBootMarker(boot_markers.platform_measured_boot_recorded);
    }
    recordMeasuredBootComparison(context, &measured_boot_record);

    if (sync_service.findDeviceRecord(recovery_device_principal) == null) {
        _ = sync_port.enrollTrustedDevice(
            sync_authority,
            context.session_user,
            recovery_device_principal,
            "recovery-device",
            sync_state.user_root_signer,
            recovery_device_signer,
            117,
        ) catch unreachable;
    }

    var recovery = recovery_environment.Environment.init(context.session_service);
    const recovery_boot = recovery.enterRecoveryBootProfile(.{
        .profile = .recovery,
        .requester = context.session_service,
        .actions = &.{
            .reinstall_base_image,
            .restore_workspace_export,
            .repair_sync_metadata,
            .rotate_device_keys,
            .revoke_device_trust,
        },
    }, 118) catch unreachable;
    if (recovery.verifyAndReinstallImage(
        recovery_boot.session(),
        &immutable_base_manager,
        "kernel=v2;base=reinstalled;mode=ro",
        platform_image_signer,
        118,
    ) catch unreachable) {
        support.common.printBootMarker(boot_markers.platform_recovery_verify_reinstall);
    }

    if (context.export_package.workspace_id.raw() != storage_state.notes_workspace_id or
        context.export_package.snapshot_id.isZero())
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
        .parent_version_id = object_store_mod.ids.version(storage_state.latest_notes_version_id),
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
        recovery_boot.session(),
        context.storage_service_instance,
        storage_state.notes_workspace_id,
        context.export_package,
        138,
    ) catch unreachable;
    support.common.printBootMarker("ZIGOS:PLATFORM:RECOVERY:RESTORE_APPLIED");
    const restored_notes = context.storage_service_instance.resolve(storage_state.notes_workspace_id, "documents/notes.md") catch unreachable;
    _ = restored_notes;

    if (sync_service.findWorkspacePolicy(storage_state.notes_workspace_id) == null) {
        _ = sync_port.configureWorkspacePolicy(sync_authority, .{
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
        recovery_boot.session(),
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
            recovery_boot.session(),
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
            recovery_boot.session(),
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
    if (!opened_workspace.version_id.isZero()) {
        support.common.printBootMarker("ZIGOS:PLATFORM:UX:OPEN_WORKSPACE");
    }
    if (workspace_view.id != 0 and document_view.id != 0) {
        support.common.printBootMarker("ZIGOS:PLATFORM:UX:WINDOW_VIEWS");
    }

    ux.pairDevice(
        &sync_port,
        sync_authority,
        context.session_user,
        paired_device_principal,
        "paired-device",
        sync_state.user_root_signer,
        paired_device_signer,
        paired_device_tick,
    ) catch unreachable;
    context.update_ledger.recordDeviceTrustChange(
        context.session_user,
        paired_device_principal,
        true,
        paired_device_tick,
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
    recordUxFlows(context, &ux, ux_flow_ledger_start_tick);
    if (ux.flow_count == 5) {
        support.common.printBootMarker(boot_markers.platform_ux_recover_system);
    }

    context.runtime_service.checkpoint(ux_flow_ledger_start_tick);
    context.storage_service_instance.checkpoint_enabled = true;
    context.storage_service_instance.checkpoint();
    support.common.printBootMarker(boot_markers.task_session_ready);
    support.common.printBootMarker(boot_markers.native_ready);
}

fn recordUxFlows(context: *support.Context, ux: *const native_ux.Controller, first_tick: u64) void {
    var index: usize = 0;
    while (index < ux.flow_count) : (index += 1) {
        const flow = ux.flowAtOrder(index) orelse continue;
        context.update_ledger.recordTaskFlow(flow.*, first_tick + @as(u64, @intCast(index))) catch unreachable;
    }
}

const ImmutableBaseWorkspaceState = struct {
    workspace: *workspace_mod.WorkspaceRecord,
    found_existing: bool,
};

const ActivationProbeContext = struct {
    context: *support.Context,
    sync_service: *sync_service_mod.Service,
    capability_table: *const capability.CapabilityTable,
    sync_authority: sync_service_mod.AuthorityContext,
    storage_state: support.StorageScenarioState,
    sync_state: support.SyncScenarioState,
    core_health_service_ids: []const u64,
    local_device_principal: principal.PrincipalId,
};

fn ensureImmutableBaseWorkspace(context: *support.Context) ImmutableBaseWorkspaceState {
    const existing = context.storage_service_instance.findWorkspace(
        context.package_service_principal,
        immutable_base.state_workspace_label,
    ) orelse context.storage_service_instance.findWorkspaceByLabel(immutable_base.state_workspace_label);
    if (existing) |workspace| {
        return .{
            .workspace = workspace,
            .found_existing = true,
        };
    }

    support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:LOOKUP_MISS");
    const request = workspace_mod.CreateRequest{
        .owner = context.package_service_principal,
        .label = immutable_base.state_workspace_label,
    };
    support.common.printBootMarker("ZIGOS:PLATFORM:IMMUTABLE_BASE:CREATE_START");
    return .{
        .workspace = context.storage_service_instance.createWorkspaceRef(&request) catch unreachable,
        .found_existing = false,
    };
}

fn criticalServiceImage(
    context: *const support.Context,
    service_record: *const supervisor_mod.ServiceRecord,
) ?*const userspace_loader.ImageRecord {
    const task = taskForOwner(context.runtime, service_record.owner) orelse return null;
    if (!task.runsAsUserspaceProcess()) return null;
    if (task.launch.image_id == 0) return null;
    return context.userspace_catalog.findById(task.launch.image_id);
}

fn taskForOwner(
    runtime: *const task_runtime.Runtime,
    owner: principal.PrincipalId,
) ?*const task_runtime.TaskRecord {
    return runtime.findByOwner(owner);
}

fn beginValidatedActivation(
    probe: *const ActivationProbeContext,
    manager: *immutable_base.Manager,
    slot_index: u8,
    storage_probe_path: []const u8,
    activation_tick: u64,
    probe_tick: u64,
    validation_tick: u64,
) update_health.ActivationCheckResult {
    manager.beginActivation(slot_index, activation_tick) catch unreachable;
    return validateActivation(probe, manager, storage_probe_path, probe_tick, validation_tick);
}

fn beginSuccessfulActivation(
    probe: *const ActivationProbeContext,
    manager: *immutable_base.Manager,
    slot_index: u8,
    storage_probe_path: []const u8,
    activation_tick: u64,
    boot_success_tick: u64,
    probe_tick: u64,
    validation_tick: u64,
) update_health.ActivationCheckResult {
    manager.beginActivation(slot_index, activation_tick) catch unreachable;
    update_health.recordBootSuccess(manager, boot_success_tick) catch unreachable;
    return validateActivation(probe, manager, storage_probe_path, probe_tick, validation_tick);
}

fn validateActivation(
    probe: *const ActivationProbeContext,
    manager: *immutable_base.Manager,
    storage_probe_path: []const u8,
    probe_tick: u64,
    validation_tick: u64,
) update_health.ActivationCheckResult {
    return update_health.validatePendingActivation(
        manager,
        probe.context.supervisor,
        probe.context.storage_service_instance,
        .{
            .core_service_ids = probe.core_health_service_ids,
            .storage_workspace_id = probe.storage_state.notes_workspace_id,
            .storage_probe_path = storage_probe_path,
            .network_service_id = probe.context.network_service_id,
            .ui_service_id = probe.context.compositor_service_id,
            .network_probe = .{
                .sync = probe.sync_service,
                .capability_table = probe.capability_table,
                .authority = probe.sync_authority,
                .workspace_id = probe.storage_state.notes_workspace_id,
                .source_device = probe.local_device_principal,
                .target_device = probe.sync_state.tablet_device_principal,
                .tick = probe_tick,
            },
            .ui_probe = .{ .session = probe.context.compositor },
        },
        probe.context.update_ledger,
        validation_tick,
    ) catch unreachable;
}

fn emitRollbackMarker(
    result: update_health.ActivationCheckResult,
    failure: immutable_base.HealthFailure,
    marker: []const u8,
) void {
    if (result.activation.rolled_back and result.activation.failure == failure) {
        support.common.printBootMarker(marker);
    }
}

fn recordMeasuredBootComparison(
    context: *support.Context,
    boot: *const measured_boot.BootRecord,
) void {
    const measurement_owner = context.package_service_principal;
    const measurement_signer = signing.SignerIdentity{
        .label = "zigos-measured-boot-state",
        .seed = [_]u8{0xA6} ** 32,
    };
    var journal = measured_boot.MeasurementJournal.init(
        context.storage_service_instance,
        measurement_owner,
        measurement_signer,
    ) catch unreachable;
    const comparison = journal.record(boot.*, 130) catch unreachable;
    if (comparison.previous == null) {
        support.common.printBootMarker(boot_markers.platform_measured_boot_first);
        return;
    }
    if (comparison.same_root_digest) {
        support.common.printBootMarker(boot_markers.platform_measured_boot_same_root);
    }
    if (comparison.same_record_shape) {
        support.common.printBootMarker(boot_markers.platform_measured_boot_same_shape);
    }
}
