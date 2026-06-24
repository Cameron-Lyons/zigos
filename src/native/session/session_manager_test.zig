const std = @import("std");
const contract = @import("contract.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const immutable_base = @import("../platform/immutable_base.zig");
const manifest = @import("../policy/manifest.zig");
const native_ux = @import("../platform/native_ux.zig");
const principal = @import("../core/principal.zig");
const service_contract = @import("service_contracts.zig");
const session_manager = @import("session_manager.zig");
const signing = @import("../core/signing.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");

test "boot assembles core services without running explicit scenarios" {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    const service_directory = session_manager.testing.serviceDirectoryPtr();
    const runtime_service = session_manager.testing.runtimeServicePtr();
    const driver_directory = session_manager.testing.driverDirectoryPtr();
    const driver_runtime = session_manager.testing.driverRuntimePtr();
    const supervisor = session_manager.testing.supervisorPtr();
    const storage_service_instance = session_manager.testing.storageServicePtr();
    const compositor = session_manager.testing.compositorSessionPtr();
    const dispatcher = session_manager.testing.backgroundDispatchPtr();

    try std.testing.expect(session_manager.testing.isInitialized());
    try std.testing.expectEqual(contract.default_services.len, session_manager.testing.countServices());
    try std.testing.expectEqual(service_contract.ordered_service_contracts.len, service_directory.bindingCount());
    try std.testing.expectEqual(@as(usize, 20), session_manager.testing.countTasks());
    try std.testing.expectEqual(@as(usize, 20), session_manager.testing.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 0), session_manager.testing.countTasksInState(.suspended));
    try std.testing.expectEqual(@as(usize, 0), session_manager.testing.countTasksInState(.terminated));
    try std.testing.expectEqual(@as(usize, 0), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 0), compositor.item_count);

    const runtime_service_record = supervisor.findByClass(.task_runtime).?;
    const network_service = supervisor.findByClass(.network_stack).?;
    const storage_service = supervisor.findByClass(.storage_object).?;
    const sync_service = supervisor.findByClass(.sync_replication).?;
    const package_service = supervisor.findByClass(.package_install_update).?;
    const network_activation = driver_runtime.findByClass(.network_adapter).?;
    const storage_activation = driver_runtime.findByClass(.storage_controller).?;
    const usb_activation = driver_runtime.findByClass(.usb_controller).?;
    const graphics_activation = driver_runtime.findByClass(.graphics_adapter).?;
    const audio_activation = driver_runtime.findByClass(.audio_print_io).?;
    const input_activation = driver_runtime.findByClass(.input_device).?;
    const compositor_policy_activation = driver_runtime.findByClass(.compositor_policy).?;
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, runtime_service_record.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, network_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, storage_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, sync_service.state);
    try std.testing.expect(runtime_service.has_checkpoint);
    try std.testing.expectEqual(@as(u32, 0), runtime_service.restart_generation);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, network_activation.mode);
    try std.testing.expect(storage_activation.mode == .published_data_plane or storage_activation.mode == .userspace_brokered_data_plane);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, usb_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, graphics_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, audio_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, input_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, compositor_policy_activation.mode);
    try std.testing.expectEqual(@as(u16, 1), network_service.restart_count);
    try std.testing.expectEqual(@as(u16, 1), storage_service.restart_count);
    try std.testing.expectEqual(@as(u16, 0), sync_service.restart_count);

    try std.testing.expectEqual(@as(u32, 2), driver_directory.findByClass(.network_adapter).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 2), driver_directory.findByClass(.storage_controller).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.usb_controller).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.graphics_adapter).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.audio_print_io).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.compositor_policy).?.restart_generation);

    for (service_contract.ordered_service_contracts) |entry| {
        const descriptor = service_contract.contractForClass(entry.class).?;
        const connection = try service_directory.connect(descriptor.interface);
        try std.testing.expectEqual(supervisor.findByClass(entry.class).?.id, connection.service_id);
    }
    const network_service_task = session_manager.testing.findTask("network-service").?;
    const storage_driver_task = session_manager.testing.findTask("storage-driver").?;
    const storage_service_task = session_manager.testing.findTask("workspace-storage").?;
    const sync_service_task = session_manager.testing.findTask("sync-service").?;
    const session_task = session_manager.testing.findTask("session-manager").?;
    const review_task = session_manager.testing.findTask("permission-review").?;
    try std.testing.expect(session_manager.testing.findTask("notes") == null);
    try std.testing.expect(session_manager.testing.findTask("sync") == null);
    try std.testing.expect(session_manager.testing.findTask("capture") == null);
    try std.testing.expectEqual(@as(u32, 2), network_service_task.process_generation);
    try std.testing.expectEqual(task_runtime.TaskState.active, storage_driver_task.state);
    try std.testing.expectEqual(@as(u32, 1), storage_service_task.process_generation);
    try std.testing.expectEqual(@as(u32, 1), sync_service_task.process_generation);
    try std.testing.expect(session_task.runsAsUserspaceProcess());
    try std.testing.expect(review_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_driver_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_service_task.runsAsUserspaceProcess());
    try std.testing.expectEqualStrings("zigos.system.session-manager", session_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("zigos.system.storage-driver", storage_driver_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("zigos.system.storage-object", storage_service_task.launchBundleIdSlice());
    try std.testing.expectEqual(storage_driver_task.id, driver_directory.findByClass(.storage_controller).?.owner_task_id);
    try std.testing.expect(storage_driver_task.id != storage_service_task.id);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.activeRecordCount());
    try std.testing.expect(dispatcher.latestRecord() == null);

    const session_user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    try std.testing.expectEqual(storage_service.id, storage_service_instance.service_id);
    try std.testing.expectEqual(storage_service_task.id, storage_service_instance.task_id);
    try std.testing.expect(storage_service_instance.findWorkspace(session_user, "notes-workspace") == null);
    try std.testing.expect(session_manager.testing.packageServicePtr().find("app.notes") == null);

    const base_state_signer = signing.SignerIdentity{
        .label = "zigos-base-state",
        .seed = signing.seedFromByte(0xA1),
    };
    var base_manager = try immutable_base.Manager.init(storage_service_instance, package_service.owner, base_state_signer);
    try std.testing.expect(base_manager.loaded_existing_state);
    try std.testing.expectEqual(@as(u64, 10), base_manager.activation_generation);
    try std.testing.expectEqual(@as(u64, 6), base_manager.rollback_generation);
    try std.testing.expectEqualStrings("stable-a", base_manager.activeImage().?.labelSlice());
    try std.testing.expectEqualStrings("stable-b", base_manager.slots[base_manager.inactiveSlotIndex()].labelSlice());
}

test "bootstrap scenario world wires storage sync recovery and policy flows explicitly" {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.bootScenarioWorld();

    const service_directory = session_manager.testing.serviceDirectoryPtr();
    const runtime_service = session_manager.testing.runtimeServicePtr();
    const driver_directory = session_manager.testing.driverDirectoryPtr();
    const driver_runtime = session_manager.testing.driverRuntimePtr();
    const supervisor = session_manager.testing.supervisorPtr();
    const storage_service_instance = session_manager.testing.storageServicePtr();
    const compositor = session_manager.testing.compositorSessionPtr();
    const dispatcher = session_manager.testing.backgroundDispatchPtr();

    try std.testing.expect(session_manager.testing.isInitialized());
    try std.testing.expectEqual(contract.default_services.len, session_manager.testing.countServices());
    try std.testing.expectEqual(service_contract.ordered_service_contracts.len + 1, service_directory.bindingCount());
    try std.testing.expectEqual(@as(usize, 28), session_manager.testing.countTasks());
    try std.testing.expectEqual(@as(usize, 27), session_manager.testing.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 0), session_manager.testing.countTasksInState(.suspended));
    try std.testing.expectEqual(@as(usize, 1), session_manager.testing.countTasksInState(.terminated));
    try std.testing.expectEqual(@as(usize, 6), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 9), compositor.item_count);

    const runtime_service_record = supervisor.findByClass(.task_runtime).?;
    const network_service = supervisor.findByClass(.network_stack).?;
    const storage_service = supervisor.findByClass(.storage_object).?;
    const sync_service = supervisor.findByClass(.sync_replication).?;
    const network_activation = driver_runtime.findByClass(.network_adapter).?;
    const storage_activation = driver_runtime.findByClass(.storage_controller).?;
    const usb_activation = driver_runtime.findByClass(.usb_controller).?;
    const graphics_activation = driver_runtime.findByClass(.graphics_adapter).?;
    const audio_activation = driver_runtime.findByClass(.audio_print_io).?;
    const input_activation = driver_runtime.findByClass(.input_device).?;
    const compositor_policy_activation = driver_runtime.findByClass(.compositor_policy).?;
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, runtime_service_record.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, network_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, storage_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, sync_service.state);
    try std.testing.expect(runtime_service.has_checkpoint);
    try std.testing.expectEqual(@as(u32, 0), runtime_service.restart_generation);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, network_activation.mode);
    try std.testing.expect(storage_activation.mode == .published_data_plane or storage_activation.mode == .userspace_brokered_data_plane);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, usb_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, graphics_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, audio_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, input_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, compositor_policy_activation.mode);
    try std.testing.expectEqual(@as(u16, 1), network_service.restart_count);
    try std.testing.expectEqual(@as(u16, 2), storage_service.restart_count);
    try std.testing.expectEqual(@as(u16, 1), sync_service.restart_count);

    try std.testing.expectEqual(@as(u32, 2), driver_directory.findByClass(.network_adapter).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 2), driver_directory.findByClass(.storage_controller).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.usb_controller).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.graphics_adapter).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.audio_print_io).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.compositor_policy).?.restart_generation);

    const service_classes = [_]contract.ServiceClass{
        .package_install_update,
        .indexing_search,
        .media_print_helpers,
        .attention_broker,
        .task_lifecycle,
        .sensitive_capture,
        .secret_vault,
    };
    for (service_classes) |class| {
        const descriptor = service_contract.contractForClass(class).?;
        const connection = try service_directory.connect(descriptor.interface);
        try std.testing.expectEqual(supervisor.findByClass(class).?.id, connection.service_id);
    }
    const notes_task = session_manager.testing.findTask("notes").?;
    const sync_task = session_manager.testing.findTask("sync").?;
    const capture_task = session_manager.testing.findTask("capture").?;
    const storage_driver_task = session_manager.testing.findTask("storage-driver").?;
    const storage_service_task = session_manager.testing.findTask("workspace-storage").?;
    const sync_service_task = session_manager.testing.findTask("sync-service").?;
    const session_task = session_manager.testing.findTask("session-manager").?;
    const review_task = session_manager.testing.findTask("permission-review").?;
    try std.testing.expectEqual(@as(usize, 2), notes_task.execution_component_count);
    try std.testing.expectEqual(@as(usize, 2), notes_task.capability_count);
    try std.testing.expectEqual(task_runtime.TaskState.active, sync_task.state);
    try std.testing.expect(sync_task.background_allowed);
    try std.testing.expectEqual(@as(usize, 4), capture_task.capability_count);
    try std.testing.expectEqual(task_runtime.TaskState.active, storage_driver_task.state);
    try std.testing.expectEqual(@as(u32, 2), storage_service_task.process_generation);
    try std.testing.expectEqual(@as(u32, 2), sync_service_task.process_generation);
    try std.testing.expect(session_task.runsAsUserspaceProcess());
    try std.testing.expect(review_task.runsAsUserspaceProcess());
    try std.testing.expect(notes_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_driver_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_service_task.runsAsUserspaceProcess());
    try std.testing.expectEqualStrings("zigos.system.session-manager", session_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("app.notes", notes_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("zigos.system.storage-driver", storage_driver_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("zigos.system.storage-object", storage_service_task.launchBundleIdSlice());
    try std.testing.expectEqual(storage_driver_task.id, driver_directory.findByClass(.storage_controller).?.owner_task_id);
    try std.testing.expect(storage_driver_task.id != storage_service_task.id);
    const notes_review = compositor.findWindowForTaskBundleConst(notes_task.id, "app.notes").?;
    const sync_review = compositor.findWindowForTaskBundleConst(sync_task.id, "app.sync").?;
    const capture_review = compositor.findWindowForTaskBundleConst(capture_task.id, "app.capture").?;
    var app_panel_count: usize = 0;
    var document_view_count: usize = 0;
    var workspace_view_count: usize = 0;
    var task_view_count: usize = 0;
    var window_index: usize = 0;
    while (window_index < compositor.window_count) : (window_index += 1) {
        const window = compositor.windowAtOrder(window_index).?;
        switch (window.view_type) {
            .app_panel => app_panel_count += 1,
            .document_view => document_view_count += 1,
            .workspace_view => workspace_view_count += 1,
            .full_screen_task_view => task_view_count += 1,
            .sync_conflict_review => app_panel_count += 1,
        }
    }
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, notes_review.view_type);
    try std.testing.expectEqual(@as(?u64, 3), notes_review.ui_surface_id);
    try std.testing.expectEqualStrings("Notes permission review", notes_review.titleSlice());
    try std.testing.expectEqual(@as(usize, 3), notes_review.item_count);
    try std.testing.expectEqual(@as(usize, 1), sync_review.item_count);
    try std.testing.expectEqual(@as(usize, 5), capture_review.item_count);
    try std.testing.expectEqual(compositor_session.DecisionState.allow, compositor.findReviewItemConst(notes_review.id, .object_access, "workspace:notes").?.decision);
    try std.testing.expectEqual(compositor_session.DecisionState.deny, compositor.findReviewItemConst(notes_review.id, .clipboard, "clipboard").?.decision);
    try std.testing.expectEqual(compositor_session.DecisionState.allow, compositor.findReviewItemConst(sync_review.id, .background_execution, "sync").?.decision);
    try std.testing.expectEqual(compositor_session.DecisionState.deny, compositor.findReviewItemConst(capture_review.id, .mic, "mic.array").?.decision);
    try std.testing.expectEqual(@as(usize, 3), app_panel_count);
    try std.testing.expectEqual(@as(usize, 1), document_view_count);
    try std.testing.expectEqual(@as(usize, 1), workspace_view_count);
    try std.testing.expectEqual(@as(usize, 1), task_view_count);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.activeRecordCount());
    const latest_dispatch = dispatcher.latestRecord().?;
    try std.testing.expectEqual(sync_task.id, latest_dispatch.task_id);
    try std.testing.expectEqual(background_dispatch.RecordState.completed, latest_dispatch.state);
    try std.testing.expectEqual(manifest.BackgroundTrigger.sync_completion, latest_dispatch.trigger);
    try std.testing.expectEqualStrings("sync", latest_dispatch.backgroundTaskIdSlice());
    try std.testing.expectEqual(task_runtime.AuditEventKind.background_dispatched, sync_task.latestAuditEvent().?.kind);

    const session_user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const storage_service_principal = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const tablet_device_principal = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const notes_workspace = storage_service_instance.findWorkspace(session_user, "notes-workspace").?;
    const imported_workspace = storage_service_instance.findWorkspace(storage_service_principal, "imported-notes").?;
    const notes_entry = try storage_service_instance.resolve(notes_workspace.id, "documents/notes.md");
    const imported_entry = try storage_service_instance.resolve(imported_workspace.id, "documents/notes.md");
    try std.testing.expectEqual(notes_entry.version_id, imported_entry.version_id);
    try std.testing.expect(storage_service_instance.findSnapshot(notes_workspace.id, "baseline") != null);

    var restarted_sync_resident = sync_service_mod.ResidentState{};
    var restarted_sync = try sync_service_mod.Service.initWithStorage(
        sync_service.id,
        0,
        sync_service.owner,
        storage_service_instance,
        &restarted_sync_resident,
    );
    try std.testing.expect(restarted_sync.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 3), restarted_sync.trustedDeviceCount());
    try std.testing.expect(restarted_sync.findWorkspacePolicy(notes_workspace.id) != null);
    try std.testing.expect(restarted_sync.findOverlay(notes_workspace.id) != null);
    try std.testing.expect(restarted_sync.findConflict(notes_workspace.id, tablet_device_principal, "documents/notes.md") == null);

    const state_signer = signing.SignerIdentity{
        .label = "zigos-base-state",
        .seed = signing.seedFromByte(0xA1),
    };
    const package_service = supervisor.findByClass(.package_install_update).?;
    var immutable_base_manager = try immutable_base.Manager.init(storage_service_instance, package_service.owner, state_signer);
    try std.testing.expect(immutable_base_manager.loaded_existing_state);
    try std.testing.expectEqual(@as(u64, 8), immutable_base_manager.activation_generation);
    try std.testing.expectEqual(@as(u64, 5), immutable_base_manager.rollback_generation);
    try std.testing.expectEqualStrings("recovery-reinstall", immutable_base_manager.activeImage().?.labelSlice());
    try std.testing.expectEqualStrings("stable-b", immutable_base_manager.slots[immutable_base_manager.inactiveSlotIndex()].labelSlice());

    const ledger = session_manager.testing.updateLedgerPtr();
    try std.testing.expect(ledger.countMatching(.{ .kind = .permission_decision }) >= 1);
    try std.testing.expect(ledger.countMatching(.{ .kind = .capability_grant }) >= 1);
    try std.testing.expect(ledger.countMatching(.{ .kind = .task_flow }) >= 5);
    try std.testing.expect(ledger.latestKind(.update_transition) != null);
    try std.testing.expectEqual(event_ledger.EventKind.permission_decision, ledger.latestKind(.permission_decision).?.kind);
    try std.testing.expectEqual(event_ledger.EventKind.capability_grant, ledger.latestKind(.capability_grant).?.kind);
    try std.testing.expectEqual(event_ledger.EventKind.sync_conflict, ledger.latestKind(.sync_conflict).?.kind);
    try std.testing.expectEqual(event_ledger.EventKind.device_trust_change, ledger.latestKind(.device_trust_change).?.kind);
    try std.testing.expectEqual(event_ledger.EventKind.driver_restart, ledger.latestKind(.driver_restart).?.kind);

    var task_flow_events: [event_ledger.MAX_EVENTS]event_ledger.Event = undefined;
    const task_flows = ledger.queryEvents(.{ .kind = .task_flow }, &task_flow_events);
    const journey_task = session_manager.testing.findTask("notes-task").?;
    var saw_recovery_flow = false;
    for (task_flows) |event| {
        if (event.detail_code == @intFromEnum(native_ux.FlowKind.recover_system)) {
            saw_recovery_flow = true;
            try std.testing.expectEqual(journey_task.id, event.task_id);
            try std.testing.expectEqualStrings("recovery-environment", event.detailSlice());
        }
    }
    try std.testing.expect(saw_recovery_flow);
}

test "boot is idempotent once initialized" {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();
    const services_after_first_boot = session_manager.testing.countServices();
    const tasks_after_first_boot = session_manager.testing.countTasks();
    const bindings_after_first_boot = session_manager.testing.serviceDirectoryPtr().bindingCount();
    const diagnostics_after_first_boot = session_manager.testing.supervisorPtr().diagnostic_count;

    session_manager.boot();

    try std.testing.expectEqual(services_after_first_boot, session_manager.testing.countServices());
    try std.testing.expectEqual(tasks_after_first_boot, session_manager.testing.countTasks());
    try std.testing.expectEqual(bindings_after_first_boot, session_manager.testing.serviceDirectoryPtr().bindingCount());
    try std.testing.expectEqual(diagnostics_after_first_boot, session_manager.testing.supervisorPtr().diagnostic_count);
}
