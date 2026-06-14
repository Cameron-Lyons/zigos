const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const component_port = @import("../kernel_api/component_port.zig");
const manifest = @import("../policy/manifest.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const policy_component_port = @import("../policy/policy_component_port.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const review_component_port = @import("../policy/review_component_port.zig");
const package_service = @import("../services/package_service.zig");
const support = @import("../session/session_manager_support.zig");
const units = @import("../core/units.zig");
const userspace_launch = @import("../task/userspace_launch.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

pub fn run(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) support.NotesReviewState {
    runViewerPermissionFlow(env, state, policy_port);
    const notes_review = runNotesPermissionFlow(env, state, kernel_port, review_port, policy_port);
    runSyncPermissionFlow(env, state, review_port, policy_port);
    runCapturePermissionFlow(env, state, review_port, policy_port);

    const expired_network_decision = policy_port.authorizeRequest(.{
        .header = policy_component_port.makeHeader(.authorize_request, 28, notes_review.task_id),
        .task_id = notes_review.task_id,
        .request = notes_review.network_permission,
        .grants = notes_review.grantsSlice(),
    }, 80) catch unreachable;
    if (!expired_network_decision.allowed and expired_network_decision.reason == .capability_expired) {
        common.printBootMarker(boot_markers.permission_lease_expired);
    }

    return notes_review;
}

fn runViewerPermissionFlow(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    policy_port: *policy_component_port.Port,
) void {
    var viewer_resolved: package_service.ResolvedManifest = undefined;
    const viewer_manifest = env.package_service.resolveCurrentManifest("app.viewer", &viewer_resolved) catch unreachable;
    manifest.validate(viewer_manifest) catch unreachable;
    common.printBootMarker(boot_markers.permission_manifest_valid);

    const viewer_task = userspace_launch.launchInstalledDirect(
        env.package_service,
        env.userspace_catalog,
        env.runtime,
        "app.viewer",
        .app_component,
        .{
            .owner = state.ids.session_user,
            .budget = .{
                .cpu_time_ticks = 15_000,
                .memory_bytes = units.mebibytes(2),
                .endpoint_slots = 8,
                .shared_memory_bytes = units.kibibytes(64),
                .background_allowed = false,
            },
            .ui_surface_id = 2,
            .local_only = true,
        },
        env.userspace_scheduler,
    ) catch unreachable;
    const viewer_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 20, viewer_task.id),
        .task_id = viewer_task.id,
        .bundle = viewer_manifest,
        .grants = &.{},
    }, 10) catch unreachable;
    if (viewer_summary.decisionForKind(.network_egress)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.permission_zero_authority_deny_network);
        }
    }
    if (viewer_summary.decisionForKind(.clipboard)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.permission_zero_authority_deny_clipboard);
        }
    }
}

fn runNotesPermissionFlow(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) support.NotesReviewState {
    var notes_resolved: package_service.ResolvedManifest = undefined;
    const notes_manifest = env.package_service.resolveCurrentManifest("app.notes", &notes_resolved) catch unreachable;
    manifest.validate(notes_manifest) catch unreachable;

    const notes_task = userspace_launch.launchInstalledDirect(
        env.package_service,
        env.userspace_catalog,
        env.runtime,
        "app.notes",
        .app_component,
        .{
            .owner = state.ids.session_user,
            .budget = .{
                .cpu_time_ticks = 30_000,
                .memory_bytes = units.mebibytes(4),
                .endpoint_slots = 8,
                .shared_memory_bytes = units.kibibytes(128),
                .background_allowed = false,
            },
            .ui_surface_id = 3,
            .local_only = true,
        },
        env.userspace_scheduler,
    ) catch unreachable;

    var notes_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const notes_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 21, notes_task.id),
        .app_task_id = notes_task.id,
        .bundle = notes_manifest,
        .output = &notes_grants_buffer,
    }, 10) catch unreachable;

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
            common.printBootMarker(boot_markers.permission_grant_object_local);
        }
    }
    if (notes_summary.decisionForKind(.network_egress)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.permission_grant_network_local);
        }
    }
    if (notes_summary.decisionForKind(.clipboard)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.permission_deny_clipboard);
        }
    }

    _ = env.runtime.attachComponent(notes_task.id, .{
        .substrate = .early_elf_runner,
        .label = "notes-sync-helper",
        .entry = "/system/components/notes-sync.elf",
    }, 11) catch unreachable;
    const notes_accounting = kernel_port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 221, state.session_task.id),
        .authority_capability_id = state.session_capability.id,
        .task_id = notes_task.id,
    }, 11) catch unreachable;
    if (notes_accounting.component_count == 2) {
        common.printBootMarker(boot_markers.permission_elf_substrate_ok);
    }

    return .{
        .task_id = notes_task.id,
        .network_permission = notes_manifest.requested_permissions[1],
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
    var sync_resolved: package_service.ResolvedManifest = undefined;
    const sync_manifest = env.package_service.resolveCurrentManifest("app.sync", &sync_resolved) catch unreachable;
    manifest.validate(sync_manifest) catch unreachable;

    const sync_task = userspace_launch.launchInstalledDirect(
        env.package_service,
        env.userspace_catalog,
        env.runtime,
        "app.sync",
        .app_component,
        .{
            .owner = state.ids.session_user,
            .budget = .{
                .cpu_time_ticks = 20_000,
                .memory_bytes = units.mebibytes(2),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(64),
                .background_allowed = true,
            },
            .ui_surface_id = 4,
            .local_only = true,
        },
        env.userspace_scheduler,
    ) catch unreachable;

    var sync_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const sync_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 23, sync_task.id),
        .app_task_id = sync_task.id,
        .bundle = sync_manifest,
        .output = &sync_grants_buffer,
    }, 20) catch unreachable;
    const sync_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 24, sync_task.id),
        .task_id = sync_task.id,
        .bundle = sync_manifest,
        .grants = sync_grants,
    }, 20) catch unreachable;
    if (sync_summary.decisionForKind(.background_execution)) |decision| {
        if (!decision.allowed and decision.reason == .budget_exhausted) {
            common.printBootMarker("ZIGOS:PERMISSION:DENY:BACKGROUND");
        } else if (decision.allowed) {
            const dispatch = env.background_dispatcher.dispatch(
                env.runtime,
                sync_task.id,
                sync_manifest,
                "sync",
                .sync_completion,
                21,
            ) catch unreachable;
            if (dispatch.allowed and !dispatch.delayed) {
                _ = env.background_dispatcher.complete(env.runtime, dispatch.record_id.?) catch unreachable;
                common.printBootMarker("ZIGOS:PERMISSION:BACKGROUND:SYNC_DISPATCHED");
            } else if (dispatch.delayed) {
                common.printBootMarker("ZIGOS:PERMISSION:BACKGROUND:SYNC_DELAYED");
            } else if (dispatch.reason == .budget_exceeded) {
                common.printBootMarker("ZIGOS:PERMISSION:DENY:BACKGROUND");
            }
        }
    }
}

fn runCapturePermissionFlow(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) void {
    var capture_resolved: package_service.ResolvedManifest = undefined;
    const capture_manifest = env.package_service.resolveCurrentManifest("app.capture", &capture_resolved) catch unreachable;

    const capture_task = userspace_launch.launchInstalledDirect(
        env.package_service,
        env.userspace_catalog,
        env.runtime,
        "app.capture",
        .app_component,
        .{
            .owner = state.ids.session_user,
            .budget = .{
                .cpu_time_ticks = 20_000,
                .memory_bytes = units.mebibytes(2),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(64),
                .background_allowed = false,
            },
            .ui_surface_id = 5,
            .local_only = true,
        },
        env.userspace_scheduler,
    ) catch unreachable;

    var capture_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const capture_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 26, capture_task.id),
        .app_task_id = capture_task.id,
        .bundle = capture_manifest,
        .output = &capture_grants_buffer,
    }, 30) catch unreachable;

    const capture_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 27, capture_task.id),
        .task_id = capture_task.id,
        .bundle = capture_manifest,
        .grants = capture_grants,
    }, 30) catch unreachable;
    if (capture_summary.decisionForKind(.device_access)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.permission_grant_device_local);
        }
    }
    if (capture_summary.decisionForKind(.camera)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.permission_grant_camera);
        }
    }
    if (capture_summary.decisionForKind(.mic)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.permission_deny_mic);
        }
    }
    if (capture_summary.decisionForKind(.sensor)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.permission_grant_sensor_local);
        }
    }
    if (capture_summary.decisionForKind(.peer_ipc)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.permission_grant_peer_ipc_local);
        }
    }
}
