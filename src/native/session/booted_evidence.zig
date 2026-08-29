const builtin = @import("builtin");
const native_util = @import("../core/util.zig");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const booted_system = @import("../platform/rendered_shell/booted_system.zig");
const bootstrap_packages = @import("../demo/bootstrap_packages.zig");
const compositor_display = @import("../platform/compositor_display.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const daily_journey_state = @import("daily_journey_state.zig");
const humane_shell = @import("../platform/rendered_shell/humane_shell.zig");
const native_ux = @import("../platform/native_ux.zig");
const notification_center = @import("../services/notification_center.zig");
const permission_flows = @import("../demo/permission_flows.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const policy_component_port = @import("../policy/policy_component_port.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const review_component_port = @import("../policy/review_component_port.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const manifest_fixtures = @import("../policy/manifest_fixtures.zig");
const package_service = @import("../services/package_service.zig");
const principal = @import("../core/principal.zig");
const production_journey = @import("../platform/rendered_shell/production_journey.zig");
const public_store = @import("../services/public_store.zig");
const scenario_support = @import("../demo/scenario_support.zig");
const signing = @import("../core/signing.zig");
const storage_scenarios = @import("../demo/storage_scenarios.zig");
const sync_scenarios = @import("../demo/sync_scenarios.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const transient_sync_service = @import("../sync/transient_service.zig");
const xhci = @import("../../kernel/drivers/xhci.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

pub fn runProduction(manager: anytype, graph: anytype) bool {
    var evidence_env = graph.env;
    evidence_env.background_dispatcher = manager.backgroundDispatchPtr() catch |err| native_util.bootProofFailure("booted evidence", err);
    bootstrap_packages.seed(
        manager.packageServicePtr(),
        manager.capabilityTablePtr(),
        graph.state.services.package_service.id,
        graph.state.ids.package_service,
        graph.state.session_task.id,
        graph.state.ids.session_service,
        graph.state.ids.policy_authority,
    );

    var mediator = policy_mediation.PolicyMediator.init(
        graph.state.ids.policy_authority,
        manager.capabilityTablePtr(),
        manager.runtimeServicePtr().runtimePtr(),
        .{
            .network_service_id = graph.state.services.network_service.id,
            .compositor_service_id = graph.state.services.compositor_service.id,
            .policy_service_id = graph.state.services.policy_service.id,
            .service_registry_id = graph.state.services.service_registry.id,
        },
    );
    mediator.attachLedger(manager.updateLedgerPtr());

    const physical_review_commands = [_][]const u8{
        "allow local lease=400",
        "allow local lease=50",
        "deny",
        "allow lease=10",
        "allow local lease=30",
        "allow local lease=35",
        "deny",
        "allow local lease=25",
        "allow local lease=15",
    };
    var modeled_review_input = permission_review_service.ModeledInputSource.initDefault() catch |err| native_util.bootProofFailure("booted evidence", err);
    var expected_physical_review_reports: usize = 0;
    for (physical_review_commands) |command| {
        modeled_review_input.enqueueTextCommand(
            xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID,
            xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID,
            command,
        ) catch |err| native_util.bootProofFailure("booted evidence", err);
        expected_physical_review_reports += command.len + 1;
    }

    var review_service = permission_review_service.Service.init(
        graph.state.services.review_service_record.id,
        graph.state.review_service_task.id,
        manager.runtimePtr(),
        &[_][]const u8{},
    );
    review_service.compositor = manager.compositorSessionPtr();
    review_service.ux = manager.reviewUxControllerPtr() catch |err| native_util.bootProofFailure("booted evidence", err);
    review_service.bindModeledInput(&modeled_review_input);
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(
        graph.state.services.compositor_service.id,
        graph.service_bindings.bindingFor(.compositor_ui_session).task_id,
        manager.runtimePtr(),
        manager.compositorSessionPtr(),
        &compositor_checkpoint_store,
    );
    review_service.bindCompositorService(&compositor_service);
    common.printBootMarker(boot_markers.compositor_service_ready);

    var review_port = review_component_port.Port.init(&review_service);
    var policy_port = policy_component_port.Port.init(&mediator);
    common.printBootMarker(boot_markers.permission_review_port_ready);
    common.printBootMarker(boot_markers.permission_policy_port_ready);

    const notes_review = permission_flows.run(
        &evidence_env,
        &graph.state,
        graph.kernel_port,
        &review_port,
        &policy_port,
    );
    if (review_service.physicalInputReportCount() >= expected_physical_review_reports and
        review_service.physicalInputEventCount() >= expected_physical_review_reports)
    {
        common.printBootMarker(boot_markers.permission_xhci_keyboard_report);
    }
    if (review_service.physicalInputCommandCount() >= 1) {
        common.printBootMarker(boot_markers.permission_xhci_review_command);
    }
    if (review_service.physicalInputCommandCount() >= physical_review_commands.len) {
        common.printBootMarker(boot_markers.permission_xhci_boot_flow_commands);
    }
    const compositor = manager.compositorSessionPtr();
    if (bootedFramebufferContains(compositor, "active_type=")) {
        common.printBootMarker(boot_markers.compositor_framebuffer_presented);
    }
    if (compositor.item_count > 0 and bootedFramebufferContains(compositor, "permission kind=")) {
        common.printBootMarker(boot_markers.compositor_permission_review_rendered);
    }

    var lifecycle_context = scenario_support.Context{
        .capability_table = manager.capabilityTablePtr(),
        .runtime = manager.runtimePtr(),
        .runtime_service = manager.runtimeServicePtr(),
        .userspace_catalog = manager.userspaceCatalogPtr(),
        .supervisor = manager.supervisorPtr(),
        .compositor = manager.compositorSessionPtr(),
        .driver_directory = manager.driverDirectoryPtr(),
        .storage_service_instance = manager.storageServicePtr(),
        .storage_checkpoint_store = manager.storageCheckpointStorePtr(),
        .export_package = manager.exportPackagePtr() catch |err| native_util.bootProofFailure("booted export package", err),
        .policy_authority = graph.state.ids.policy_authority,
        .session_service = graph.state.ids.session_service,
        .session_user = graph.state.ids.session_user,
        .storage_service_id = graph.state.services.storage_service.id,
        .storage_task_id = graph.service_bindings.bindingFor(.storage_object).task_id,
        .storage_service_principal = graph.state.ids.storage_service,
        .sync_service_id = graph.state.services.sync_service.id,
        .sync_task_id = graph.service_bindings.bindingFor(.sync_replication).task_id,
        .sync_service_principal = graph.state.ids.sync_service,
        .sync_resident_state = manager.syncResidentStatePtr() catch |err| native_util.bootProofFailure("booted sync state", err),
        .policy_service_id = graph.state.services.policy_service.id,
        .network_service_id = graph.state.services.network_service.id,
        .compositor_service_id = graph.state.services.compositor_service.id,
        .package_service_id = graph.state.services.package_service.id,
        .package_service_principal = graph.state.ids.package_service,
        .update_ledger = manager.updateLedgerPtr(),
        .notes_task_id = notes_review.task_id,
        .notes_object_capability = notes_review.object_capability,
    };
    const storage_state = storage_scenarios.run(&lifecycle_context);
    var early_boot_ledger = lifecycle_context.update_ledger.*;
    defer early_boot_ledger.deinit();
    lifecycle_context.update_ledger.* = event_ledger.Ledger.initPersistent(
        lifecycle_context.storage_service_instance,
        lifecycle_context.package_service_principal,
        scenario_support.diagnostic_ledger_signer,
    ) catch |err| native_util.bootProofFailure("booted evidence", err);
    lifecycle_context.update_ledger.absorb(&early_boot_ledger) catch |err| native_util.bootProofFailure("booted evidence", err);
    var sync_service_instance: transient_sync_service.Instance = undefined;
    sync_service_instance.initInto(
        lifecycle_context.sync_service_id,
        lifecycle_context.sync_task_id,
        lifecycle_context.sync_service_principal,
        lifecycle_context.storage_service_instance,
        lifecycle_context.sync_resident_state,
    ) catch |err| native_util.bootProofFailure("booted evidence", err);
    defer sync_service_instance.deinit();
    const sync_service = sync_service_instance.ptr();
    _ = sync_scenarios.run(&lifecycle_context, sync_service, storage_state);
    if (!runNotesDailyDriverJourney(manager, graph, &lifecycle_context, sync_service, &compositor_service, storage_state)) {
        return false;
    }
    if (!runBootedNotesTypedInputLoop(graph, &lifecycle_context, sync_service, &compositor_service, storage_state)) {
        return false;
    }
    return true;
}

fn evidenceCheckFailed(comptime step: []const u8) bool {
    common.printBootMarker("ZIGOS:BOOTED_EVIDENCE:CHECK_FAILED step=" ++ step);
    return false;
}

fn evidenceStepFailed(comptime step: []const u8, err: anyerror) bool {
    var line_buffer: [128]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "ZIGOS:BOOTED_EVIDENCE:STEP_FAILED step={s} error={s}",
        .{ step, @errorName(err) },
    ) catch return false;
    common.printBootMarker(line);
    return false;
}

fn bootedFramebufferContains(compositor: *const compositor_session.Session, expected_text: []const u8) bool {
    if (compositor.visibleWindowCount() == 0 or compositor.active_window_id == 0) return false;

    var display_storage: [compositor_display.DEFAULT_STORAGE_BYTES]u8 = undefined;
    var display = compositor_display.Framebuffer.init(
        &display_storage,
        compositor_display.DEFAULT_WIDTH,
        compositor_display.DEFAULT_HEIGHT,
    ) catch return false;
    display.renderSession(compositor) catch return false;
    const proof = display.requirePresentation(
        expected_text,
        compositor.visibleWindowCount(),
        compositor.active_window_id,
    ) catch return false;
    return proof.verified();
}

const notes_daily_bundle_signer = signing.SignerIdentity{
    .label = "zigos-notes-daily-bundle",
    .seed = signing.seedFromByte(0xd1),
};
const notes_daily_policy_signer = signing.SignerIdentity{
    .label = "zigos-notes-daily-policy",
    .seed = signing.seedFromByte(0xd2),
};
const notes_daily_user_signer = signing.SignerIdentity{
    .label = "zigos-notes-daily-user",
    .seed = signing.seedFromByte(0xd3),
};
const notes_daily_primary_device_signer = signing.SignerIdentity{
    .label = "zigos-notes-daily-primary",
    .seed = signing.seedFromByte(0xd4),
};
const notes_daily_paired_device_signer = signing.SignerIdentity{
    .label = "zigos-notes-daily-paired",
    .seed = signing.seedFromByte(0xd5),
};
const notes_daily_snapshot_signer = signing.SignerIdentity{
    .label = "zigos-notes-daily-snapshot",
    .seed = signing.seedFromByte(0xd6),
};
const booted_notes_typed_text = "booted native smoke typed notes edit survived recovery";
const notes_daily_public_store_source = "store:zigos/public";
const notes_daily_v1_manifest_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
    .{ .path = "assets/notes/editor.wasm", .content_type = "application/wasm" },
};
const notes_daily_v2_manifest_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
    .{ .path = "assets/notes/editor.wasm", .content_type = "application/wasm" },
    .{ .path = "assets/notes/offline-index.dat", .content_type = "application/octet-stream" },
};
const notes_daily_v1_store_assets = [_]public_store.ReleaseAsset{
    .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml", .digest = "sha256:5151515151515151515151515151515151515151515151515151515151515151", .size_bytes = 1536 },
    .{ .path = "assets/notes/editor.wasm", .content_type = "application/wasm", .digest = "sha256:5252525252525252525252525252525252525252525252525252525252525252", .size_bytes = 32768 },
};
const notes_daily_v2_store_assets = [_]public_store.ReleaseAsset{
    .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml", .digest = "sha256:5353535353535353535353535353535353535353535353535353535353535353", .size_bytes = 1600 },
    .{ .path = "assets/notes/editor.wasm", .content_type = "application/wasm", .digest = "sha256:5454545454545454545454545454545454545454545454545454545454545454", .size_bytes = 34816 },
    .{ .path = "assets/notes/offline-index.dat", .content_type = "application/octet-stream", .digest = "sha256:5555555555555555555555555555555555555555555555555555555555555555", .size_bytes = 8192 },
};

fn runNotesDailyDriverJourney(
    manager: anytype,
    graph: anytype,
    context: *scenario_support.Context,
    sync_service: *sync_service_mod.Service,
    compositor_service: *compositor_session.Service,
    storage_state: scenario_support.StorageScenarioState,
) bool {
    var package_port = package_service.PackagePort.init(manager.packageServicePtr(), context.capability_table);
    const package_authority = mintNotesDailyPackageAuthority(context, graph.state.session_task.id, 220) catch |err| return evidenceStepFailed("daily.mint_package_authority", err);
    _ = package_port.trustPolicyAuthorityRoot(
        package_authority,
        .{ .kind = .policy_authority, .serial = 1 },
        signing.publicKeyFromByte(0x5A),
    ) catch |err| return evidenceStepFailed("daily.trust_policy_authority_root", err);
    _ = package_port.trustPublisher(
        package_authority,
        .{ .kind = .app, .serial = 26_026 },
        .{ .kind = .policy_authority, .serial = 1 },
        "zigos.dev",
        signing.publicKey(notes_daily_bundle_signer) catch |err| return evidenceStepFailed("daily.bundle_signer_public_key", err),
    ) catch |err| return evidenceStepFailed("daily.trust_publisher", err);

    var sync_port = sync_service_mod.SyncPort.init(sync_service, context.capability_table);
    const sync_authority = scenario_support.mintSyncAuthority(context, 221);
    const install_bundle = signedNotesDailyBundle(0) catch |err| return evidenceStepFailed("daily.sign_install_bundle", err);
    const update_bundle = signedNotesDailyBundle(1) catch |err| return evidenceStepFailed("daily.sign_update_bundle", err);
    var state_instance: daily_journey_state.Instance = undefined;
    state_instance.initInto(notes_daily_public_store_source, .beta) catch |err| return evidenceStepFailed("daily.initialize_state", err);
    defer state_instance.deinit();
    const state = state_instance.ptr();
    state.store_channel.trustPublisher("zigos.dev", signing.publicKey(notes_daily_bundle_signer) catch |err| return evidenceStepFailed("daily.store_signer_public_key", err)) catch |err| return evidenceStepFailed("daily.store_trust_publisher", err);
    state.store_channel.publish(state.store_channel.prepareRelease(install_bundle, &notes_daily_v1_store_assets, 1)) catch |err| return evidenceStepFailed("daily.publish_install_release", err);
    state.store_channel.publish(state.store_channel.prepareRelease(update_bundle, &notes_daily_v2_store_assets, 1)) catch |err| return evidenceStepFailed("daily.publish_update_release", err);
    var journey = production_journey.ProductionJourneyService.init(
        context.runtime_service,
        &state.ux,
        compositor_service,
        context.storage_service_instance,
        &package_port,
        package_authority,
        &sync_port,
        sync_authority,
        &state.policies,
        context.update_ledger,
        .{
            .user = context.session_user,
            .admin = context.policy_authority,
            .app_owner = context.session_user,
            .organization_id = 2_026,
            .reviewer_task_id = graph.state.review_service_task.id,
            .workspace_id = storage_state.notes_workspace_id,
            .workspace_label = "Notes Workspace",
            .document_path = "documents/notes.md",
            .task_label = "notes-daily",
            .task_entry = "app.notes",
            .task_title = "Notes",
            .bundle_id = "app.notes.daily",
            .display_name = "Notes",
            .edit_payload = "Booted native smoke Notes edit persisted through recovery",
            .source_identity = notes_daily_public_store_source,
            .sync_destination = "relay.production.zigos",
            .device_label = "tablet",
            .policy_label = "notes-daily-native-smoke",
            .install_bundle = install_bundle,
            .update_bundle = update_bundle,
            .public_store_channel = &state.store_channel,
            .ui_surface_id = 26_026,
            .image_id = 26_026_001,
            .share_principal = principal.PrincipalId{ .kind = .user, .serial = 26_027 },
            .sync_from_device = principal.PrincipalId{ .kind = .device, .serial = 26_028 },
            .sync_to_device = principal.PrincipalId{ .kind = .device, .serial = 26_029 },
            .policy_signer = notes_daily_policy_signer,
            .user_signer = notes_daily_user_signer,
            .primary_device_signer = notes_daily_primary_device_signer,
            .paired_device_signer = notes_daily_paired_device_signer,
        },
    );

    const controls = [_]production_journey.ProductionJourneyControl{
        .apply_policy,
        .trust_device,
        .install_app,
        .start_task,
        .open_workspace,
        .open_document,
        .edit_document,
        .review_permission,
        .share_document,
        .sync_workspace,
        .update_app,
        .rollback_update,
        .recover_system,
        .remove_app,
        .revoke_device,
        .revoke_policy,
    };
    for (controls, 0..) |control, index| {
        const tick = 230 + @as(u64, @intCast(index));
        const response = journey.dispatch(.{ .control = control, .tick = tick });
        if (response.status != .ok) {
            printJourneyControlRejected(control, response);
            printJourneyStorageDiagnostics(context.storage_service_instance, storage_state.notes_workspace_id);
            return false;
        }
    }

    const snapshot = journey.markerSnapshot();
    if (!snapshot.complete()) {
        common.printBootMarker("ZIGOS:NOTES_DAILY:MARKERS_INCOMPLETE");
        return false;
    }
    emitNotesDailyDriverMarkers(snapshot);
    return true;
}

fn printJourneyControlRejected(
    control: production_journey.ProductionJourneyControl,
    response: production_journey.ProductionJourneyResponse,
) void {
    printJourneyControlRejectedMarker(control);

    var detail_buffer: [96]u8 = undefined;
    const detail = std.fmt.bufPrint(
        &detail_buffer,
        "ZIGOS:NOTES_DAILY:REJECT_DETAIL status={s} error={s}",
        .{
            @tagName(response.status),
            if (response.failure) |err| @errorName(err) else "none",
        },
    ) catch return;
    common.printBootMarker(detail);
}

fn printJourneyStorageDiagnostics(storage: anytype, workspace_id: u64) void {
    const by_id: []const u8 = if (storage.findWorkspaceRecordConst(workspace_id) != null) "hit" else "miss";
    const label_id: u64 = if (storage.findWorkspaceByLabel("notes-workspace")) |record| record.id.raw() else 0;
    const checkpoint_error: []const u8 = if (storage.checkpoint_store.last_checkpoint_error) |err| @errorName(err) else "none";

    var line_buffer: [160]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "ZIGOS:NOTES_DAILY:REJECT_STORAGE probe_id={d} by_id={s} label_id={d} workspaces={d} objects={d} versions={d} checkpoint={s}",
        .{
            workspace_id,
            by_id,
            label_id,
            storage.workspaces.workspaceCount(),
            storage.objectCount(),
            storage.versionCount(),
            checkpoint_error,
        },
    ) catch return;
    common.printBootMarker(line);
}

fn printJourneyControlRejectedMarker(control: production_journey.ProductionJourneyControl) void {
    common.printBootMarker(switch (control) {
        .apply_policy => "ZIGOS:NOTES_DAILY:APPLY_POLICY:REJECTED",
        .trust_device => "ZIGOS:NOTES_DAILY:TRUST_DEVICE:REJECTED",
        .install_app => "ZIGOS:NOTES_DAILY:INSTALL_APP:REJECTED",
        .start_task => "ZIGOS:NOTES_DAILY:START_TASK:REJECTED",
        .open_workspace => "ZIGOS:NOTES_DAILY:OPEN_WORKSPACE:REJECTED",
        .open_document => "ZIGOS:NOTES_DAILY:OPEN_DOCUMENT:REJECTED",
        .edit_document => "ZIGOS:NOTES_DAILY:EDIT_DOCUMENT:REJECTED",
        .review_permission => "ZIGOS:NOTES_DAILY:REVIEW_PERMISSION:REJECTED",
        .share_document => "ZIGOS:NOTES_DAILY:SHARE_DOCUMENT:REJECTED",
        .sync_workspace => "ZIGOS:NOTES_DAILY:SYNC_WORKSPACE:REJECTED",
        .update_app => "ZIGOS:NOTES_DAILY:UPDATE_APP:REJECTED",
        .rollback_update => "ZIGOS:NOTES_DAILY:ROLLBACK_UPDATE:REJECTED",
        .recover_system => "ZIGOS:NOTES_DAILY:RECOVER_SYSTEM:REJECTED",
        .remove_app => "ZIGOS:NOTES_DAILY:REMOVE_APP:REJECTED",
        .revoke_device => "ZIGOS:NOTES_DAILY:REVOKE_DEVICE:REJECTED",
        .revoke_policy => "ZIGOS:NOTES_DAILY:REVOKE_POLICY:REJECTED",
    });
}

fn runBootedNotesTypedInputLoop(
    graph: anytype,
    context: *scenario_support.Context,
    sync_service: *sync_service_mod.Service,
    compositor_service: *compositor_session.Service,
    storage_state: scenario_support.StorageScenarioState,
) bool {
    const local_device = scenario_support.default_local_device_principal;
    const tablet_device = scenario_support.default_tablet_device_principal;
    var sync_port = sync_service_mod.SyncPort.init(sync_service, context.capability_table);
    const sync_authority = scenario_support.mintSyncAuthority(context, 260);
    const local_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = context.sync_service_principal,
        .workspace_id = storage_state.notes_workspace_id,
        .label = "notes-typed-local",
        .mode = .local_network,
    }) catch |err| return evidenceStepFailed("typed.create_network_policy", err);
    _ = sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = storage_state.notes_workspace_id,
        .owner = context.session_user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{"documents/"},
        .device_to_device_policy_id = local_policy.id,
    }) catch |err| return evidenceStepFailed("typed.configure_workspace_policy", err);

    var notifications = notification_center.Center.init();
    var shell_checkpoint_store = humane_shell.HumaneShellCheckpointStore{};
    var shell_ux = native_ux.Controller.init();
    var shell = humane_shell.HumaneShell.init(
        context.runtime_service,
        &shell_ux,
        compositor_service,
        context.storage_service_instance,
        &sync_port,
        sync_authority,
        &notifications,
        context.update_ledger,
        .{
            .user = context.session_user,
            .app_owner = context.session_user,
            .reviewer_task_id = graph.state.review_service_task.id,
            .workspace_id = storage_state.notes_workspace_id,
            .workspace_label = "Notes Workspace",
            .document_path = "documents/notes.md",
            .task_label = "notes-typed",
            .task_entry = "app.notes",
            .task_title = "Notes",
            .bundle_id = "app.notes",
            .display_name = "Notes",
            .ui_surface_id = 26_030,
            .image_id = 26_030_001,
            .object_query_label = "documents/notes.md",
            .sync_from_device = local_device,
            .sync_to_device = tablet_device,
            .paired_device = tablet_device,
            .device_label = "tablet",
            .user_signer = notes_daily_user_signer,
            .device_signer = notes_daily_paired_device_signer,
            .snapshot_label = "booted-native-smoke-notes-edit",
            .snapshot_signer = notes_daily_snapshot_signer,
            .document_edit_signer = notes_daily_user_signer,
        },
        .{},
        &shell_checkpoint_store,
    );
    var system = booted_system.BootedSystem.init(&shell);

    if (!system.dispatchInput(.{ .kind = .boot, .tick = 260 }).accepted) return evidenceCheckFailed("typed.input_boot");
    if (!system.dispatchInput(.{ .kind = .start_task, .tick = 261 }).accepted) return evidenceCheckFailed("typed.input_start_task");
    if (!system.dispatchInput(.{ .kind = .open_workspace, .tick = 262 }).accepted) return evidenceCheckFailed("typed.input_open_workspace");
    if (!system.dispatchInput(.{ .kind = .open_document, .tick = 263 }).accepted) return evidenceCheckFailed("typed.input_open_document");
    const previous_version_id = shell.state.document_version_id;
    if (!system.dispatchInput(.{
        .kind = .text_input,
        .tick = 264,
        .text = booted_notes_typed_text,
    }).accepted) return evidenceCheckFailed("typed.input_text");
    if (!shell.state.document_edited or shell.state.document_version_id == previous_version_id) return evidenceCheckFailed("typed.document_edit_state");
    if (!std.mem.eql(u8, shell.documentTextSlice(), booted_notes_typed_text)) return evidenceCheckFailed("typed.document_text_matches");
    const typed_version = context.storage_service_instance.version(shell.state.document_version_id) orelse return evidenceCheckFailed("typed.stored_version_present");
    const typed_payload = context.storage_service_instance.versionPayload(typed_version) catch |err| return evidenceStepFailed("typed.stored_version_payload", err);
    if (!std.mem.eql(u8, typed_payload, booted_notes_typed_text)) return evidenceCheckFailed("typed.stored_payload_matches");
    common.printBootMarker(boot_markers.notes_daily_driver_typed_edit_ok);

    if (!system.dispatchInput(.{ .kind = .sync_document, .tick = 265 }).accepted) return evidenceCheckFailed("typed.input_sync_document");
    if (!shell.state.document_synced or shell.state.sync_selected_entries == 0 or shell.state.sync_transport_frames == 0) return evidenceCheckFailed("typed.sync_state");
    const synced_replica_version = sync_service.replicaVersion(
        storage_state.notes_workspace_id,
        tablet_device,
        "documents/notes.md",
    ) orelse return evidenceCheckFailed("typed.replica_version_present");
    if (synced_replica_version != shell.state.document_version_id) return evidenceCheckFailed("typed.replica_version_matches");
    common.printBootMarker(boot_markers.notes_daily_driver_typed_sync_ok);

    const previous_restart_generation = context.runtime_service.restart_generation;
    if (!system.dispatchInput(.{ .kind = .recover_state, .tick = 266 }).accepted) return evidenceCheckFailed("typed.input_recover_state");
    if (!shell.state.recovered or context.runtime_service.restart_generation <= previous_restart_generation) return evidenceCheckFailed("typed.recovery_state");
    if (!std.mem.eql(u8, shell.documentTextSlice(), booted_notes_typed_text)) return evidenceCheckFailed("typed.recovered_text_matches");
    common.printBootMarker(boot_markers.notes_daily_driver_typed_recovery_ok);
    common.printBootMarker(boot_markers.notes_daily_driver_typed_loop_complete);
    return true;
}

fn mintNotesDailyPackageAuthority(
    context: *scenario_support.Context,
    session_task_id: u64,
    now_ticks: u64,
) !package_service.AuthorityContext {
    const package_authority = try context.capability_table.mintBootRoot(.{
        .holder = context.session_service,
        .issuer = context.policy_authority,
        .target = .{ .kind = .service, .id = context.package_service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .capability_mint = true,
            .capability_revoke = true,
        } },
        .scope = .{
            .task_id = session_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 1_000,
        },
        .audit = .{},
    });
    return .{
        .task_id = session_task_id,
        .principal = context.session_service,
        .capability_id = package_authority.id,
        .now_ticks = now_ticks,
    };
}

fn signedNotesDailyBundle(version_minor: u16) !manifest.BundleManifest {
    var bundle = manifest_fixtures.notesBundle();
    bundle.bundle_id = "app.notes.daily";
    bundle.version_minor = version_minor;
    bundle.assets = if (version_minor == 0) &notes_daily_v1_manifest_assets else &notes_daily_v2_manifest_assets;
    bundle.supply_chain = notesDailySupplyChain(version_minor);
    bundle.signature = try signing.signWithDefaultRegistry(
        .ed25519,
        notes_daily_bundle_signer,
        &package_service.digestBundle(bundle),
    );
    return bundle;
}

fn notesDailySupplyChain(version_minor: u16) manifest.SupplyChainDecl {
    if (version_minor == 0) {
        return .{
            .sbom_digest = "sha256:5656565656565656565656565656565656565656565656565656565656565656",
            .source_archive_digest = "sha256:5757575757575757575757575757575757575757575757575757575757575757",
            .build_recipe_digest = "sha256:5858585858585858585858585858585858585858585858585858585858585858",
            .vulnerability_scan_digest = "sha256:5959595959595959595959595959595959595959595959595959595959595959",
            .build_provenance_identity = "builder:zigos/native-reproducible",
            .reproducible_build = true,
            .trusted_builder = true,
        };
    }
    return .{
        .sbom_digest = "sha256:6060606060606060606060606060606060606060606060606060606060606060",
        .source_archive_digest = "sha256:6161616161616161616161616161616161616161616161616161616161616161",
        .build_recipe_digest = "sha256:6262626262626262626262626262626262626262626262626262626262626262",
        .vulnerability_scan_digest = "sha256:6363636363636363636363636363636363636363636363636363636363636363",
        .build_provenance_identity = "builder:zigos/native-reproducible",
        .reproducible_build = true,
        .trusted_builder = true,
    };
}

fn emitNotesDailyDriverMarkers(snapshot: production_journey.ProductionJourneyMarkerSnapshot) void {
    if (snapshot.install_open) common.printBootMarker(boot_markers.notes_daily_driver_install_open_ok);
    if (snapshot.edit_saved) common.printBootMarker(boot_markers.notes_daily_driver_edit_saved_ok);
    if (snapshot.share_sync) common.printBootMarker(boot_markers.notes_daily_driver_share_sync_ok);
    if (snapshot.update_rollback) common.printBootMarker(boot_markers.notes_daily_driver_update_rollback_ok);
    if (snapshot.recovery_remove) common.printBootMarker(boot_markers.notes_daily_driver_recovery_remove_ok);
    if (snapshot.authority_revoked) common.printBootMarker(boot_markers.notes_daily_driver_authority_revoked_ok);
    if (snapshot.complete()) common.printBootMarker(boot_markers.notes_daily_driver_complete);
}
