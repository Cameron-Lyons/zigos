const std = @import("std");
const abi = @import("../../core/abi.zig");
const capability = @import("../../kernel_api/capability.zig");
const component_port = @import("../../kernel_api/component_port.zig");
const event_ledger = @import("../../platform/event_ledger.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("../../task/generated_image_fixtures.zig") else struct {};
const ids = @import("../../core/ids.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const native_ux = @import("../../platform/native_ux.zig");
const object_store = @import("../../storage/object_store.zig");
const permission_review_service = @import("../../policy/permission_review_service.zig");
const policy_mediation = @import("../../policy/policy_mediation.zig");
const principal = @import("../../core/principal.zig");
const rendered_shell = @import("../../platform/rendered_shell.zig");
const shared_memory = @import("../../kernel_api/shared_memory.zig");
const units = @import("../../core/units.zig");
const storage_service = @import("../../storage/storage_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const task_runtime_service = @import("../../task/task_runtime_service.zig");
const compositor_display = @import("../../platform/compositor_display.zig");
const compositor_session = @import("../../platform/compositor_session.zig");
const common = @import("service_path_proofs_common.zig");

const expectEndpointConnect = common.expectEndpointConnect;
const expectEndpointCreateWithFlags = common.expectEndpointCreateWithFlags;
const expectEndpointRecv = common.expectEndpointRecv;
const expectEndpointSend = common.expectEndpointSend;
const signer = common.signer;
const HEADLESS_TEST_SHARED_MEMORY_BYTES: usize = 512;
const REVIEW_CARD_BUFFER_BYTES: usize = 512;
const REVIEW_DECISION_BUFFER_BYTES: usize = 256;
const SHELL_RENDER_BUFFER_BYTES: usize = 768;
const LEDGER_EXPORT_BUFFER_BYTES: usize = units.kibibytes(1);
const WINDOW_RENDER_BUFFER_BYTES: usize = 512;
const WORKSPACE_NEEDLE_BUFFER_BYTES: usize = 32;

pub fn proveBootedCompositorServicePath(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    storage: *storage_service.Service,
    runtime_service: *task_runtime_service.Service,
    compositor_record: *const @import("../supervisor.zig").ServiceRecord,
    compositor_task: *task_runtime.TaskRecord,
    session: *compositor_session.Session,
) !void {
    session.reset();
    runtime.allowHostPointerSyscallsForTask(compositor_task.id);

    const app_owner = principal.PrincipalId{ .kind = .app, .serial = 82_001 };
    const app_image = try generated_image_fixtures.appImage();
    var ux_controller = native_ux.Controller.init();
    const app_task = try ux_controller.startTask(runtime, .{
        .owner = app_owner,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_200,
            .memory_bytes = units.kibibytes(64),
            .endpoint_slots = 2,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
        },
        .ui_surface_id = 77,
        .local_only = true,
        .initial_component = .{
            .label = "trip-coordinator",
            .entry = "app.trip.coordinate",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 82_001,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = "app.trip",
        },
        .userspace_image = &app_image,
    });
    try std.testing.expect(app_task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(?u64, 77), app_task.ui_surface_id);

    const workspace_id = try seedBootedCompositorWorkspace(storage, app_owner);
    _ = try ux_controller.openWorkspace(storage, ids.workspace(workspace_id), "trip/brief.md", app_owner);

    const authority = try capability_table.mintBootRoot(.{
        .holder = compositor_record.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = compositor_record.id },
        .rights = .{ .service = .{
            .endpoint_create = true,
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
        } },
        .scope = .{
            .task_id = compositor_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 120,
            .expires_at_ticks = 1_200,
        },
    });
    try runtime.grantCapability(compositor_task.id, authority.id);

    const service_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        compositor_task.id,
        authority.id,
        compositor_task.id,
        "zigos.ui.compositor",
        .{ .local_only = true, .service_port = true },
        121,
    );
    const peer_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        compositor_task.id,
        authority.id,
        compositor_task.id,
        "zigos.ui.client",
        .{ .local_only = true },
        122,
    );
    _ = try expectEndpointConnect(
        kernel_port,
        compositor_task.id,
        peer_endpoint.capability_id,
        service_endpoint.capability_id,
        service_endpoint.endpoint.endpoint_id,
        123,
    );

    var checkpoint_store = compositor_session.CheckpointStore{};
    var service = compositor_session.Service.initWithCheckpoint(
        compositor_record.id,
        compositor_task.id,
        runtime,
        session,
        &checkpoint_store,
    );

    var tick: u64 = 124;
    {
        const shell_snapshot = session.snapshot();
        defer session.restore(shell_snapshot) catch |err|
            native_util.impossibleByInvariantError("compositor proof restores its retained shell snapshot", err);
        try proveBootedRenderedTaskShell(
            kernel_port,
            runtime_service,
            storage,
            &service,
            session,
            workspace_id,
            app_owner,
            compositor_task.id,
            authority.id,
            &tick,
        );
    }

    {
        const permission_snapshot = session.snapshot();
        defer session.restore(permission_snapshot) catch |err|
            native_util.impossibleByInvariantError("compositor proof restores its retained permission snapshot", err);
        try proveBootedRenderedPermissionReviewSurface(runtime, &service, session, app_task.id, capability_table);
    }

    const headless_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 82_099 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 1,
            .shared_memory_bytes = HEADLESS_TEST_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
        .initial_component = .{
            .label = "headless-trip-helper",
            .entry = "app.trip.headless",
        },
    });
    const invalid_surface_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .open_view,
        .view_type = .document_view,
        .subject_task_id = headless_task.id,
        .workspace_id = workspace_id,
        .detail = "trip/headless.md",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.invalid_request, invalid_surface_response.status);
    try std.testing.expectEqual(@as(usize, 0), session.window_count);

    const document_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .open_view,
        .view_type = .document_view,
        .subject_task_id = app_task.id,
        .workspace_id = workspace_id,
        .detail = "trip/brief.md",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, document_response.status);
    try std.testing.expectEqual(@as(u16, 1), document_response.visible_window_count);
    try std.testing.expectEqual(document_response.window_id, session.active_window_id);
    try assertRenderedWindowContains(session, document_response.window_id, "type=document_view");
    try assertRenderedWindowContains(session, document_response.window_id, "surface=77");
    var workspace_needle_buffer: [WORKSPACE_NEEDLE_BUFFER_BYTES]u8 = undefined;
    const workspace_needle = try std.fmt.bufPrint(&workspace_needle_buffer, "workspace={d}", .{workspace_id});
    try assertRenderedWindowContains(session, document_response.window_id, workspace_needle);
    try assertRenderedWindowContains(session, document_response.window_id, "detail=trip/brief.md");
    try assertDisplayContains(session, "active_type=document_view");
    try assertDisplayContains(session, "title=Document: trip/brief.md");
    try assertDisplayContains(session, "surface=77");
    try assertDisplayContains(session, workspace_needle);

    const workspace_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .open_view,
        .view_type = .workspace_view,
        .subject_task_id = app_task.id,
        .workspace_id = workspace_id,
        .detail = "Trip Workspace",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, workspace_response.status);
    try assertRenderedWindowContains(session, workspace_response.window_id, "type=workspace_view");
    try assertRenderedWindowContains(session, workspace_response.window_id, "detail=Trip Workspace");
    try assertDisplayContains(session, "active_type=workspace_view");
    try assertDisplayContains(session, "title=Workspace: Trip Workspace");

    const panel_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .open_view,
        .view_type = .app_panel,
        .subject_task_id = app_task.id,
        .workspace_id = workspace_id,
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .detail = "Calendar Panel",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, panel_response.status);
    try assertRenderedWindowContains(session, panel_response.window_id, "type=app_panel");
    try assertRenderedWindowContains(session, panel_response.window_id, "modal=yes");
    try assertRenderedWindowContains(session, panel_response.window_id, "bundle=app.trip");
    try assertRenderedWindowContains(session, panel_response.window_id, "display=Trip");
    try assertDisplayContains(session, "active_type=app_panel");
    try assertDisplayContains(session, "title=Panel: Calendar Panel");
    try assertDisplayContains(session, "active_app bundle=app.trip display=Trip");

    const task_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .open_view,
        .view_type = .full_screen_task_view,
        .subject_task_id = app_task.id,
        .workspace_id = workspace_id,
        .detail = "Coordinate Trip",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, task_response.status);
    try assertRenderedWindowContains(session, task_response.window_id, "type=full_screen_task_view");
    try assertRenderedWindowContains(session, task_response.window_id, "title=Task: Coordinate Trip");
    try assertDisplayContains(session, "active_type=full_screen_task_view");
    try assertDisplayContains(session, "title=Task: Coordinate Trip");

    const missing_switch = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .switch_view,
        .window_id = 99_999,
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.not_found, missing_switch.status);

    const switch_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .switch_view,
        .window_id = workspace_response.window_id,
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, switch_response.status);
    try std.testing.expectEqual(workspace_response.window_id, switch_response.active_window_id);
    try assertDisplayContains(session, "active_type=workspace_view");
    try assertDisplayContains(session, "title=Workspace: Trip Workspace");

    const object_review_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .review_permission,
        .subject_task_id = app_task.id,
        .reviewer_task_id = compositor_task.id,
        .permission_kind = .object_access,
        .local_only = true,
        .max_lease_ticks = 400,
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .resource = "ws:trip",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, object_review_response.status);
    try std.testing.expectEqual(@as(u16, 1), object_review_response.review_item_count);
    const review_window = session.findWindowConst(object_review_response.window_id) orelse return error.MissingBootedCompositorWindow;
    try std.testing.expectEqual(@as(?u64, 77), review_window.ui_surface_id);
    try std.testing.expectEqual(app_task.id, review_window.subject_task_id);

    const network_review_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .review_permission,
        .subject_task_id = app_task.id,
        .reviewer_task_id = compositor_task.id,
        .permission_kind = .network_egress,
        .local_only = false,
        .max_lease_ticks = 80,
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .resource = "net:trip",
        .egress_intent = .{
            .kind = .call_service,
            .service = "trip.remote",
        },
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, network_review_response.status);
    try std.testing.expectEqual(object_review_response.window_id, network_review_response.window_id);
    try std.testing.expectEqual(@as(u16, 2), network_review_response.review_item_count);

    const object_decision_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .record_decision,
        .window_id = object_review_response.window_id,
        .permission_kind = .object_access,
        .allow = true,
        .local_only = true,
        .has_lease = true,
        .lease_ticks = 240,
        .resource = "ws:trip",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, object_decision_response.status);
    try std.testing.expectEqual(compositor_session.DecisionState.allow, object_decision_response.decision);

    const network_decision_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .record_decision,
        .window_id = network_review_response.window_id,
        .permission_kind = .network_egress,
        .allow = false,
        .resource = "net:trip",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, network_decision_response.status);
    try std.testing.expectEqual(compositor_session.DecisionState.deny, network_decision_response.decision);
    try assertDisplayContains(session, "active_type=app_panel");
    try assertDisplayContains(session, "permission kind=object_access resource=ws:trip");
    try assertDisplayContains(session, "permission_scope object=ws:trip network=none local=yes lease=400");
    try assertDisplayContains(session, "permission_decision kind=object_access resource=ws:trip decision=allow");
    try assertDisplayContains(session, "permission_scope object=none network=net:trip local=no lease=80");
    try assertDisplayContains(session, "permission_decision kind=network_egress resource=net:trip decision=deny");

    const object_item = session.findReviewItemConst(object_review_response.window_id, .object_access, "ws:trip") orelse return error.MissingBootedCompositorReviewItem;
    const network_item = session.findReviewItemConst(network_review_response.window_id, .network_egress, "net:trip") orelse return error.MissingBootedCompositorReviewItem;
    var object_card_buffer: [REVIEW_CARD_BUFFER_BYTES]u8 = undefined;
    var network_card_buffer: [REVIEW_CARD_BUFFER_BYTES]u8 = undefined;
    var object_decision_buffer: [REVIEW_DECISION_BUFFER_BYTES]u8 = undefined;
    var network_decision_buffer: [REVIEW_DECISION_BUFFER_BYTES]u8 = undefined;
    const object_card = try compositor_session.renderReviewItemToBuffer(&object_card_buffer, object_review_response.window_id, object_item);
    try expectContains(object_card, "why=Trip needs access to local task objects");
    try expectContains(object_card, "object_scope=ws:trip");
    try expectContains(object_card, "network_path=none");
    try expectContains(object_card, "requested_local_only=yes");
    try expectContains(object_card, "requested_lease=400");
    const network_card = try compositor_session.renderReviewItemToBuffer(&network_card_buffer, network_review_response.window_id, network_item);
    try expectContains(network_card, "why=Trip needs to call service trip.remote");
    try expectContains(network_card, "object_scope=none");
    try expectContains(network_card, "network_path=net:trip");
    try expectContains(network_card, "requested_lease=80");
    const object_decision = try compositor_session.renderDecisionToBuffer(&object_decision_buffer, object_review_response.window_id, object_item);
    try expectContains(object_decision, "decision=allow");
    try expectContains(object_decision, "decision_local_only=yes");
    try expectContains(object_decision, "decision_lease=240");
    const network_decision = try compositor_session.renderDecisionToBuffer(&network_decision_buffer, network_review_response.window_id, network_item);
    try expectContains(network_decision, "decision=deny");

    const object_permission_request = manifest.PermissionRequest{
        .kind = .object_access,
        .resource = "ws:trip",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .max_lease_ticks = 400,
    };
    _ = try ux_controller.reviewPermissionDecision(
        app_task.id,
        app_owner,
        "app.trip",
        object_permission_request,
        true,
        true,
        240,
    );
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    try ledger.recordTaskFlow(ux_controller.flowAtOrder(0).?.*, 160);
    try ledger.recordTaskFlow(ux_controller.flowAtOrder(1).?.*, 161);
    try ledger.recordTaskFlow(ux_controller.flowAtOrder(2).?.*, 162);
    try ledger.recordPermissionReview(app_owner, app_task.id, .object_access, true, 163, object_card, false);
    try ledger.recordPermissionDecision(app_owner, app_task.id, .object_access, true, .none, 164, object_decision, false);
    try ledger.recordPermissionReview(app_owner, app_task.id, .network_egress, false, 165, network_card, false);
    try ledger.recordPermissionDecision(app_owner, app_task.id, .network_egress, false, .policy_denied, 166, network_decision, false);
    try std.testing.expectEqual(@as(usize, 3), ledger.countMatching(.{
        .kind = .task_flow,
    }));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{
        .kind = .task_flow,
        .task_id = app_task.id,
    }));
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{
        .kind = .task_flow,
        .workspace_id = workspace_id,
    }));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{
        .kind = .permission_review,
        .task_id = app_task.id,
    }));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{
        .kind = .permission_decision,
        .task_id = app_task.id,
    }));

    session.reset();
    try std.testing.expectEqual(@as(usize, 0), session.window_count);
    const recover_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .recover_state,
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, recover_response.status);
    try std.testing.expect(recover_response.recovered);
    try std.testing.expectEqual(@as(usize, 5), session.window_count);
    try std.testing.expectEqual(@as(usize, 2), session.item_count);
    try std.testing.expectEqual(
        compositor_session.DecisionState.allow,
        session.findReviewItemConst(object_review_response.window_id, .object_access, "ws:trip").?.decision,
    );
    try std.testing.expectEqual(
        compositor_session.DecisionState.deny,
        session.findReviewItemConst(network_review_response.window_id, .network_egress, "net:trip").?.decision,
    );
    try assertDisplayContains(session, "type=document_view");
    try assertDisplayContains(session, "type=workspace_view");
    try assertDisplayContains(session, "type=app_panel");
    try assertDisplayContains(session, "type=full_screen_task_view");
    try assertDisplayContains(session, "permission_decision kind=object_access resource=ws:trip decision=allow");
    try assertDisplayContains(session, "permission_decision kind=network_egress resource=net:trip decision=deny");
}

fn seedBootedCompositorWorkspace(
    storage: *storage_service.Service,
    owner: principal.PrincipalId,
) !u64 {
    const signer_identity = signer("booted-compositor-workspace", 0x78);
    const document = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(82_100),
        .object_type = .document,
        .payload = "trip brief",
        .metadata = try object_store.signMetadata(
            signer_identity,
            "trip brief",
            "text/markdown",
            .document,
            "trip brief",
            150,
        ),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = owner,
        .label = "booted-trip-workspace",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "trip/brief.md", document.object_id, document.version_id, .document);
    _ = try storage.commit(workspace_record.id, 151);
    return workspace_record.id.raw();
}

fn proveBootedRenderedTaskShell(
    kernel_port: *component_port.KernelPort,
    runtime_service: *task_runtime_service.Service,
    storage: *storage_service.Service,
    compositor_service_instance: *compositor_session.Service,
    session: *compositor_session.Session,
    workspace_id: u64,
    app_owner: principal.PrincipalId,
    reviewer_task_id: u64,
    shell_authority_capability_id: u64,
    tick: *u64,
) !void {
    var ux_controller = native_ux.Controller.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();

    const shell_service_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        reviewer_task_id,
        shell_authority_capability_id,
        reviewer_task_id,
        "zigos.ui.task-shell",
        .{ .local_only = true, .service_port = true },
        tick.*,
    );
    tick.* += 1;
    const shell_peer_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        reviewer_task_id,
        shell_authority_capability_id,
        reviewer_task_id,
        "zigos.ui.task-shell.client",
        .{ .local_only = true },
        tick.*,
    );
    tick.* += 1;
    _ = try expectEndpointConnect(
        kernel_port,
        reviewer_task_id,
        shell_peer_endpoint.capability_id,
        shell_service_endpoint.capability_id,
        shell_service_endpoint.endpoint.endpoint_id,
        tick.*,
    );
    tick.* += 1;

    var shell_checkpoint_store = rendered_shell.TaskShellCheckpointStore{};
    var shell = rendered_shell.TaskShellService.init(
        runtime_service,
        &ux_controller,
        compositor_service_instance,
        storage,
        &ledger,
        .{
            .user = app_owner,
            .app_owner = app_owner,
            .reviewer_task_id = reviewer_task_id,
            .workspace_id = workspace_id,
            .workspace_label = "Trip Workspace",
            .document_path = "trip/brief.md",
            .task_label = "trip-shell",
            .task_entry = "app.trip.shell",
            .task_title = "Coordinate Trip",
            .bundle_id = "app.trip",
            .display_name = "Trip",
            .ui_surface_id = 78,
            .image_id = 82_002,
        },
        &shell_checkpoint_store,
    );

    var render_buffer: [SHELL_RENDER_BUFFER_BYTES]u8 = undefined;
    const initial = try shell.render(&render_buffer);
    try expectContains(initial, "control=start-task");
    try expectContains(initial, "control=open-document");

    const start = try taskShellRoundTrip(kernel_port, reviewer_task_id, shell_peer_endpoint.capability_id, shell_service_endpoint.capability_id, &shell, .{
        .operation = .click,
        .control = .start_task,
        .tick = 152,
    }, tick);
    try std.testing.expectEqual(rendered_shell.TaskShellStatus.ok, start.status);
    const workspace_response = try taskShellRoundTrip(kernel_port, reviewer_task_id, shell_peer_endpoint.capability_id, shell_service_endpoint.capability_id, &shell, .{
        .operation = .click,
        .control = .open_workspace,
        .tick = 153,
    }, tick);
    try std.testing.expectEqual(rendered_shell.TaskShellStatus.ok, workspace_response.status);
    const document_response = try taskShellRoundTrip(kernel_port, reviewer_task_id, shell_peer_endpoint.capability_id, shell_service_endpoint.capability_id, &shell, .{
        .operation = .click,
        .control = .open_document,
        .tick = 154,
    }, tick);
    try std.testing.expectEqual(rendered_shell.TaskShellStatus.ok, document_response.status);
    const panel_response = try taskShellRoundTrip(kernel_port, reviewer_task_id, shell_peer_endpoint.capability_id, shell_service_endpoint.capability_id, &shell, .{
        .operation = .click,
        .control = .open_app_panel,
        .tick = 155,
    }, tick);
    try std.testing.expectEqual(rendered_shell.TaskShellStatus.ok, panel_response.status);
    const focus = try taskShellRoundTrip(kernel_port, reviewer_task_id, shell_peer_endpoint.capability_id, shell_service_endpoint.capability_id, &shell, .{
        .operation = .click,
        .control = .focus_full_screen,
        .tick = 156,
    }, tick);
    try std.testing.expectEqual(rendered_shell.TaskShellStatus.ok, focus.status);

    const task = runtime_service.runtimePtr().find(focus.task_id) orelse return error.MissingBootedRenderedShellTask;
    try std.testing.expect(task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(?u64, 78), task.ui_surface_id);
    try std.testing.expectEqual(@as(usize, 4), session.window_count);
    try std.testing.expectEqual(@as(usize, 1), session.item_count);
    try std.testing.expectEqual(compositor_session.ViewType.full_screen_task_view, session.windowAtOrder(3).?.view_type);

    try std.testing.expectEqual(@as(usize, 5), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 4), ledger.countMatching(.{ .kind = .task_flow, .task_id = task.id }));
    try std.testing.expectEqual(@as(usize, 3), ledger.countMatching(.{ .kind = .task_flow, .workspace_id = workspace_id }));

    var export_buffer: [LEDGER_EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "flow_kind=start_task");
    try expectContains(exported, "flow_kind=open_workspace");
    try expectContains(exported, "flow_kind=open_document");
    try expectContains(exported, "flow_kind=open_app_panel");
    try expectContains(exported, "flow_kind=focus_task");

    const rendered = try shell.render(&render_buffer);
    try expectContains(rendered, "active_type=full_screen_task_view");
    try expectContains(rendered, "active_title=Task: Coordinate Trip");
    try expectContains(rendered, "task_flow_events=5");

    session.reset();
    try std.testing.expect(runtime_service.restartFromCheckpoint(tick.*));
    tick.* += 1;
    const recovered = try taskShellRoundTrip(kernel_port, reviewer_task_id, shell_peer_endpoint.capability_id, shell_service_endpoint.capability_id, &shell, .{
        .operation = .recover_state,
        .tick = 157,
    }, tick);
    try std.testing.expectEqual(rendered_shell.TaskShellStatus.ok, recovered.status);
    try std.testing.expect(recovered.recovered);
    try std.testing.expectEqual(task.id, recovered.task_id);
    try std.testing.expect(runtime_service.runtimePtr().find(task.id) != null);
    try std.testing.expectEqual(@as(usize, 4), session.window_count);
    try std.testing.expectEqual(session.windowAtOrder(3).?.id, session.active_window_id);
}

fn proveBootedRenderedPermissionReviewSurface(
    runtime: *task_runtime.Runtime,
    compositor_service_instance: *compositor_session.Service,
    session: *compositor_session.Session,
    app_task_id: u64,
    capability_table: *capability.CapabilityTable,
) !void {
    var review_service = permission_review_service.Service.init(
        82_030,
        compositor_service_instance.task_id,
        runtime,
        &[_][]const u8{},
    );
    review_service.bindCompositorService(compositor_service_instance);

    var display_storage: [compositor_display.DEFAULT_STORAGE_BYTES]u8 = undefined;
    var display = try compositor_display.Framebuffer.init(
        &display_storage,
        compositor_display.DEFAULT_WIDTH,
        compositor_display.DEFAULT_HEIGHT,
    );
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "ws:trip",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "net:trip",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
            .max_lease_ticks = 80,
            .egress_intent = .{
                .kind = .call_service,
                .service = "trip.remote",
            },
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .publisher = "zigos.local",
        .requested_permissions = &permissions,
        .signature = .{
            .format = .ed25519,
            .signer = "booted-trip-review",
        },
    };
    var grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    var surface = permission_review_service.RenderedReviewSurface.init(&review_service, app_task_id, bundle, 157, &display);
    surface.bindLedger(&ledger);

    try surface.begin();
    try expectDisplayFrameContains(&display, session, "active_type=app_panel");
    try expectDisplayFrameContains(&display, session, "permission_scope object=ws:trip network=none local=yes lease=400");
    try expectDisplayFrameContains(&display, session, "control=allow_local_requested_lease window=1 kind=object_access resource=ws:trip lease=400");

    try surface.click(.allow_local_requested_lease);
    try expectDisplayFrameContains(&display, session, "permission_decision kind=object_access resource=ws:trip decision=allow");
    try expectDisplayFrameContains(&display, session, "permission_scope object=none network=net:trip local=no lease=80");
    try expectDisplayFrameContains(&display, session, "control=deny window=1 kind=network_egress resource=net:trip");

    try surface.click(.deny);
    const grants = try surface.finish(&grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(manifest.PermissionKind.object_access, grants[0].kind);
    try std.testing.expectEqual(@as(?u64, 557), grants[0].expires_at_ticks);
    try expectDisplayFrameContains(&display, session, "permission_decision kind=network_egress resource=net:trip decision=deny");

    var mediator = policy_mediation.PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 82_030 },
        capability_table,
        runtime,
        .{
            .network_service_id = 82_031,
            .compositor_service_id = compositor_service_instance.service_id,
            .policy_service_id = 82_032,
            .service_registry_id = 82_033,
        },
    );
    mediator.attachLedger(&ledger);
    const summary = try mediator.applyManifest(app_task_id, bundle, grants, 158);

    try std.testing.expectEqual(@as(u8, 1), summary.granted_count);
    try std.testing.expectEqual(@as(u8, 1), summary.denied_count);
    try std.testing.expectEqual(@as(u8, 0), summary.required_denials);
    const object_decision = summary.decisionForKind(.object_access).?;
    try std.testing.expect(object_decision.allowed);
    try std.testing.expect(object_decision.local_only);
    try std.testing.expectEqual(@as(u64, 557), object_decision.expires_at_ticks);
    const object_capability = capability_table.query(object_decision.capability_id.?).?;
    try std.testing.expect(runtime.hasCapability(app_task_id, object_capability.id));
    try std.testing.expectEqual(capability.CapabilityTargetKind.object, object_capability.target.kind);
    try std.testing.expectEqual(@as(?u64, app_task_id), object_capability.scope.task_id);
    try std.testing.expect(object_capability.scope.local_only);
    try std.testing.expect(object_capability.scope.broker_only);
    try std.testing.expectEqual(@as(u64, 557), object_capability.lease.expires_at_ticks);
    const network_decision = summary.decisionForKind(.network_egress).?;
    try std.testing.expect(!network_decision.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, network_decision.reason);
    try std.testing.expect(network_decision.capability_id == null);
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{ .kind = .permission_review, .task_id = app_task_id }));
    try std.testing.expectEqual(@as(usize, 4), ledger.countMatching(.{ .kind = .permission_decision, .task_id = app_task_id }));
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .capability_grant, .task_id = app_task_id }));
    try std.testing.expectEqual(@as(usize, 1), session.window_count);
    try std.testing.expectEqual(@as(usize, 2), session.item_count);
}

fn assertRenderedWindowContains(
    session: *const compositor_session.Session,
    window_id: u64,
    needle: []const u8,
) !void {
    const window = session.findWindowConst(window_id) orelse return error.MissingBootedCompositorWindow;
    var buffer: [WINDOW_RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered = try compositor_session.renderWindowToBuffer(&buffer, window);
    try expectContains(rendered, needle);
}

fn assertDisplayContains(session: *const compositor_session.Session, needle: []const u8) !void {
    var storage: [compositor_display.DEFAULT_STORAGE_BYTES]u8 = undefined;
    var display = try compositor_display.Framebuffer.init(
        &storage,
        compositor_display.DEFAULT_WIDTH,
        compositor_display.DEFAULT_HEIGHT,
    );
    try display.renderSession(session);
    const proof = try display.requirePresentation(
        needle,
        session.visibleWindowCount(),
        session.active_window_id,
    );
    try std.testing.expect(proof.verified());
}

fn expectDisplayFrameContains(
    display: *const compositor_display.Framebuffer,
    session: *const compositor_session.Session,
    needle: []const u8,
) !void {
    const proof = try display.requirePresentation(
        needle,
        session.visibleWindowCount(),
        session.active_window_id,
    );
    try std.testing.expect(proof.verified());
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return error.ExpectedSubstringMissing;
}

fn compositorRoundTrip(
    kernel_port: *component_port.KernelPort,
    task_id: u64,
    peer_endpoint_capability_id: u64,
    service_endpoint_capability_id: u64,
    service: *compositor_session.Service,
    request: compositor_session.ServiceRequest,
    tick: *u64,
) !compositor_session.ServiceResponse {
    var request_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const request_payload = try compositor_session.encodeRequest(&request_buffer, request);
    try expectEndpointSend(kernel_port, task_id, peer_endpoint_capability_id, request_payload, tick.*);
    tick.* += 1;

    const received_request = try expectEndpointRecv(kernel_port, task_id, service_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received_request.present);

    var response_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const response_payload = try service.dispatchPayload(
        received_request.payload[0..received_request.message.payload_len],
        &response_buffer,
    );
    try expectEndpointSend(kernel_port, task_id, service_endpoint_capability_id, response_payload, tick.*);
    tick.* += 1;

    const received_response = try expectEndpointRecv(kernel_port, task_id, peer_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received_response.present);
    return compositor_session.decodeResponse(received_response.payload[0..received_response.message.payload_len]);
}

fn taskShellRoundTrip(
    kernel_port: *component_port.KernelPort,
    task_id: u64,
    peer_endpoint_capability_id: u64,
    service_endpoint_capability_id: u64,
    service: *rendered_shell.TaskShellService,
    request: rendered_shell.TaskShellRequest,
    tick: *u64,
) !rendered_shell.TaskShellResponse {
    var request_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const request_payload = try rendered_shell.encodeTaskShellRequest(&request_buffer, request);
    try expectEndpointSend(kernel_port, task_id, peer_endpoint_capability_id, request_payload, tick.*);
    tick.* += 1;

    const received_request = try expectEndpointRecv(kernel_port, task_id, service_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received_request.present);

    var response_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const response_payload = try service.dispatchPayload(
        received_request.payload[0..received_request.message.payload_len],
        &response_buffer,
    );
    try expectEndpointSend(kernel_port, task_id, service_endpoint_capability_id, response_payload, tick.*);
    tick.* += 1;

    const received_response = try expectEndpointRecv(kernel_port, task_id, peer_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received_response.present);
    return rendered_shell.decodeTaskShellResponse(received_response.payload[0..received_response.message.payload_len]);
}
