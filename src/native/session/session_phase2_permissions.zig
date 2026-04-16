const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const component_port = @import("../kernel_api/component_port.zig");
const manifest = @import("../policy/manifest.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const policy_component_port = @import("../policy/policy_component_port.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const review_component_port = @import("../policy/review_component_port.zig");
const support = @import("session_manager_support.zig");
const userspace_boot_registry = @import("../task/userspace_boot_registry.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

fn scheduleUserspaceTask(task_id: u64) bool {
    return userspace_scheduler.registerTask(task_id);
}

pub fn run(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) support.NotesPhaseState {
    runViewerPermissionFlow(env, state, policy_port);
    const notes_phase = runNotesPermissionFlow(env, state, kernel_port, review_port, policy_port);
    runSyncPermissionFlow(env, state, review_port, policy_port);
    runCapturePermissionFlow(env, state, review_port, policy_port);

    const expired_network_decision = policy_port.authorizeRequest(.{
        .header = policy_component_port.makeHeader(.authorize_request, 28, notes_phase.task_id),
        .task_id = notes_phase.task_id,
        .request = notes_phase.network_permission,
        .grants = notes_phase.grantsSlice(),
    }, 80) catch unreachable;
    if (!expired_network_decision.allowed and expired_network_decision.reason == .capability_expired) {
        common.printBootMarker(boot_markers.phase2_lease_expired);
    }

    return notes_phase;
}

fn runViewerPermissionFlow(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    policy_port: *policy_component_port.Port,
) void {
    const viewer_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 20,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .clipboard_read = true, .clipboard_write = true },
            .required = false,
        },
    };
    const viewer_bundle = userspace_boot_registry.manifestFor("app.viewer") catch unreachable;
    const viewer_manifest = manifest.BundleManifest{
        .bundle_id = viewer_bundle.bundle_id,
        .display_name = viewer_bundle.display_name,
        .publisher = viewer_bundle.publisher,
        .requested_permissions = &viewer_permissions,
    };
    manifest.validate(viewer_manifest) catch unreachable;
    common.printBootMarker(boot_markers.phase2_manifest_valid);

    const viewer_task = userspace_launch.launchRegisteredDirect(
        env.userspace_catalog,
        env.runtime,
        "app.viewer",
        .{
            .owner = state.ids.session_user,
            .budget = .{
                .cpu_time_ticks = 15_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 8,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 2,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    const viewer_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 20, viewer_task.id),
        .task_id = viewer_task.id,
        .bundle = viewer_manifest,
        .grants = &.{},
    }, 10) catch unreachable;
    if (viewer_summary.decisionForKind(.network_egress)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.phase2_zero_authority_deny_network);
        }
    }
    if (viewer_summary.decisionForKind(.clipboard)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.phase2_zero_authority_deny_clipboard);
        }
    }
}

fn runNotesPermissionFlow(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) support.NotesPhaseState {
    const notes_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 50,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .clipboard_read = true, .clipboard_write = true },
            .required = false,
        },
    };
    const notes_bundle = userspace_boot_registry.manifestFor("app.notes") catch unreachable;
    const notes_manifest = manifest.BundleManifest{
        .bundle_id = notes_bundle.bundle_id,
        .display_name = notes_bundle.display_name,
        .publisher = notes_bundle.publisher,
        .provided_interfaces = &[_]manifest.InterfaceDecl{
            .{ .name = "zigos.workspace.document" },
        },
        .consumed_interfaces = &[_]manifest.InterfaceDecl{
            .{ .name = "zigos.object.workspace" },
        },
        .requested_permissions = &notes_permissions,
        .ai_metadata = .{
            .model_family = "tiny-embed",
            .locality = .local_only,
            .offline_required = true,
        },
        .update_channel = .beta,
        .signature = notes_bundle.signature,
    };
    manifest.validate(notes_manifest) catch unreachable;

    const notes_task = userspace_launch.launchRegisteredDirect(
        env.userspace_catalog,
        env.runtime,
        "app.notes",
        .{
            .owner = state.ids.session_user,
            .budget = .{
                .cpu_time_ticks = 30_000,
                .memory_bytes = 4 * 1024 * 1024,
                .endpoint_slots = 8,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 3,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var notes_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const notes_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 21, notes_task.id),
        .app_task_id = notes_task.id,
        .bundle = notes_manifest,
        .output = &notes_grants_buffer,
    }, 10) catch unreachable;
    if (support.hasGrantForKind(notes_grants, .object_access)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_OBJECT");
    }
    if (support.hasGrantForKind(notes_grants, .network_egress)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_NETWORK");
    }
    if (!support.hasGrantForKind(notes_grants, .clipboard)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:DENY_CLIPBOARD");
    }

    const notes_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 22, notes_task.id),
        .task_id = notes_task.id,
        .bundle = notes_manifest,
        .grants = notes_grants,
    }, 10) catch unreachable;
    const notes_object_capability = env.capability_table.query(
        notes_summary.decisionForKind(.object_access).?.capability_id.?,
    ).?;
    if (notes_summary.decisionForKind(.object_access)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_object_local);
        }
    }
    if (notes_summary.decisionForKind(.network_egress)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_network_local);
        }
    }
    if (notes_summary.decisionForKind(.clipboard)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.phase2_deny_clipboard);
        }
    }

    _ = env.runtime.attachComponent(notes_task.id, .{
        .substrate = .early_elf_runner,
        .label = "notes-sync-helper",
        .entry = "/system/components/notes-sync.elf",
    }, 11) catch unreachable;
    const notes_accounting = kernel_port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 221, notes_task.id),
        .authority_capability_id = state.session_capability.id,
        .task_id = notes_task.id,
    }, 11) catch unreachable;
    if (notes_accounting.component_count == 2) {
        common.printBootMarker(boot_markers.phase2_elf_substrate_ok);
    }

    return .{
        .task_id = notes_task.id,
        .network_permission = notes_permissions[1],
        .grants_len = notes_grants.len,
        .grants = notes_grants_buffer,
        .object_capability = notes_object_capability,
    };
}

fn runSyncPermissionFlow(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) void {
    const sync_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
        },
    };
    const sync_background_tasks = [_]manifest.BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 2_000,
                .memory_bytes = 128 * 1024,
                .shared_memory_bytes = 8 * 1024,
            },
            .network = .local_network_only,
            .visibility = .status_only,
        },
    };
    const sync_bundle = userspace_boot_registry.manifestFor("app.sync") catch unreachable;
    const sync_manifest = manifest.BundleManifest{
        .bundle_id = sync_bundle.bundle_id,
        .display_name = sync_bundle.display_name,
        .publisher = sync_bundle.publisher,
        .requested_permissions = &sync_permissions,
        .background_tasks = &sync_background_tasks,
    };
    manifest.validate(sync_manifest) catch unreachable;

    const sync_task = userspace_launch.launchRegisteredDirect(
        env.userspace_catalog,
        env.runtime,
        "app.sync",
        .{
            .owner = state.ids.session_user,
            .budget = .{
                .cpu_time_ticks = 20_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 4,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var sync_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const sync_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 23, sync_task.id),
        .app_task_id = sync_task.id,
        .bundle = sync_manifest,
        .output = &sync_grants_buffer,
    }, 20) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE2:UI:REVIEW_SYNC");
    const sync_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 24, sync_task.id),
        .task_id = sync_task.id,
        .bundle = sync_manifest,
        .grants = sync_grants,
    }, 20) catch unreachable;
    if (sync_summary.decisionForKind(.background_execution)) |decision| {
        if (!decision.allowed and decision.reason == .budget_exhausted) {
            common.printBootMarker("ZIGOS:PHASE2:DENY:BACKGROUND");
        }
    }
}

fn runCapturePermissionFlow(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) void {
    const capture_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .device_access,
            .resource = "capture.card0",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 30,
            .target_id = 700,
        },
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 701,
        },
        .{
            .kind = .mic,
            .resource = "mic.array",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 702,
        },
        .{
            .kind = .sensor,
            .resource = "sensor.lid",
            .rights = .{ .sensor_read = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 25,
            .target_id = 703,
        },
        .{
            .kind = .peer_ipc,
            .resource = "zigos.peer.share",
            .rights = .{ .ipc_peer = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 15,
        },
    };
    const capture_bundle = userspace_boot_registry.manifestFor("app.capture") catch unreachable;
    const capture_manifest = manifest.BundleManifest{
        .bundle_id = capture_bundle.bundle_id,
        .display_name = capture_bundle.display_name,
        .publisher = capture_bundle.publisher,
        .requested_permissions = &capture_permissions,
        .signature = capture_bundle.signature,
    };

    const capture_task = userspace_launch.launchRegisteredDirect(
        env.userspace_catalog,
        env.runtime,
        "app.capture",
        .{
            .owner = state.ids.session_user,
            .budget = .{
                .cpu_time_ticks = 20_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 5,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var capture_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const capture_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 26, capture_task.id),
        .app_task_id = capture_task.id,
        .bundle = capture_manifest,
        .output = &capture_grants_buffer,
    }, 30) catch unreachable;
    if (support.hasGrantForKind(capture_grants, .device_access)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_DEVICE");
    }
    if (support.hasGrantForKind(capture_grants, .camera)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_CAMERA");
    }
    if (!support.hasGrantForKind(capture_grants, .mic)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:DENY_MIC");
    }
    if (support.hasGrantForKind(capture_grants, .sensor)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_SENSOR");
    }
    if (support.hasGrantForKind(capture_grants, .peer_ipc)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_PEER_IPC");
    }

    const capture_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 27, capture_task.id),
        .task_id = capture_task.id,
        .bundle = capture_manifest,
        .grants = capture_grants,
    }, 30) catch unreachable;
    if (capture_summary.decisionForKind(.device_access)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_device_local);
        }
    }
    if (capture_summary.decisionForKind(.camera)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_camera);
        }
    }
    if (capture_summary.decisionForKind(.mic)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.phase2_deny_mic);
        }
    }
    if (capture_summary.decisionForKind(.sensor)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_sensor_local);
        }
    }
    if (capture_summary.decisionForKind(.peer_ipc)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_peer_ipc_local);
        }
    }
}
