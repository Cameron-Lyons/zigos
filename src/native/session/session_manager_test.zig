const std = @import("std");
const contract = @import("contract.zig");
const immutable_base = @import("../platform/immutable_base.zig");
const principal = @import("../core/principal.zig");
const service_contract = @import("service_contract.zig");
const session_manager = @import("session_manager.zig");
const signing = @import("../core/signing.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");

test "boot wires bootstrap services storage sync recovery and phase3 contracts" {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    const service_directory = session_manager.testing.serviceDirectoryPtr();
    const runtime = session_manager.testing.runtimePtr();
    const runtime_service = session_manager.testing.runtimeServicePtr();
    const driver_directory = session_manager.testing.driverDirectoryPtr();
    const driver_runtime = session_manager.testing.driverRuntimePtr();
    const supervisor = session_manager.testing.supervisorPtr();
    const phase4_storage_service = session_manager.testing.storageServicePtr();

    try std.testing.expect(session_manager.testing.isInitialized());
    try std.testing.expectEqual(@as(usize, 13), session_manager.testing.countServices());
    try std.testing.expectEqual(@as(usize, 10), service_directory.bindingCount());
    try std.testing.expectEqual(@as(usize, 21), session_manager.testing.countTasks());
    try std.testing.expectEqual(@as(usize, 19), session_manager.testing.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 1), session_manager.testing.countTasksInState(.suspended));
    try std.testing.expectEqual(@as(usize, 1), session_manager.testing.countTasksInState(.terminated));

    const runtime_service_record = supervisor.findByClass(.task_runtime).?;
    const compatibility_service = supervisor.findByClass(.compatibility_portal).?;
    const network_service = supervisor.findByClass(.network_stack).?;
    const storage_service = supervisor.findByClass(.storage_object).?;
    const sync_service = supervisor.findByClass(.sync_replication).?;
    const network_activation = driver_runtime.findByClass(.network_adapter).?;
    const storage_activation = driver_runtime.findByClass(.storage_controller).?;
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, runtime_service_record.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, compatibility_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, network_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, storage_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, sync_service.state);
    try std.testing.expect(runtime_service.has_checkpoint);
    try std.testing.expectEqual(@as(u32, 0), runtime_service.restart_generation);
    try std.testing.expect(network_activation.mode == .control_only or network_activation.mode == .published_data_plane);
    try std.testing.expect(storage_activation.mode == .control_only or storage_activation.mode == .published_data_plane);
    try std.testing.expectEqual(@as(u16, 1), network_service.restart_count);
    try std.testing.expectEqual(@as(u16, 1), storage_service.restart_count);
    try std.testing.expectEqual(@as(u16, 1), sync_service.restart_count);

    try std.testing.expectEqual(@as(u32, 2), driver_directory.findByClass(.network_adapter).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.storage_controller).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.graphics_adapter).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.audio_print_io).?.restart_generation);

    const phase3_classes = [_]contract.ServiceClass{
        .package_install_update,
        .indexing_search,
        .media_print_helpers,
    };
    for (phase3_classes) |class| {
        const descriptor = service_contract.contractForClass(class).?;
        const connection = try service_directory.connect(descriptor.interface);
        try std.testing.expectEqual(supervisor.findByClass(class).?.id, connection.service_id);
    }
    const compatibility_connection = try service_directory.connect(session_manager.testing.compatibilityPortalInterface());
    try std.testing.expectEqual(compatibility_service.id, compatibility_connection.service_id);

    const notes_task = session_manager.testing.findTask("notes").?;
    const sync_task = session_manager.testing.findTask("sync").?;
    const capture_task = session_manager.testing.findTask("capture").?;
    const compatibility_task = session_manager.testing.findTask("compatibility-portal").?;
    const storage_driver_task = session_manager.testing.findTask("storage-driver").?;
    const storage_service_task = session_manager.testing.findTask("workspace-storage").?;
    const sync_service_task = session_manager.testing.findTask("sync-service").?;
    const session_task = session_manager.testing.findTask("session-manager").?;
    const review_task = session_manager.testing.findTask("permission-review").?;
    try std.testing.expectEqual(@as(usize, 2), notes_task.execution_component_count);
    try std.testing.expectEqual(@as(usize, 2), notes_task.capability_count);
    try std.testing.expectEqual(task_runtime.TaskState.suspended, sync_task.state);
    try std.testing.expectEqual(@as(usize, 4), capture_task.capability_count);
    try std.testing.expectEqual(task_runtime.TaskState.active, compatibility_task.state);
    try std.testing.expect(runtime.processSeparated(notes_task.id, compatibility_task.id));
    try std.testing.expectEqual(task_runtime.TaskState.active, storage_driver_task.state);
    try std.testing.expectEqual(@as(u32, 2), storage_service_task.process_generation);
    try std.testing.expectEqual(@as(u32, 2), sync_service_task.process_generation);
    try std.testing.expect(session_task.runsAsUserspaceProcess());
    try std.testing.expect(review_task.runsAsUserspaceProcess());
    try std.testing.expect(notes_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_driver_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_service_task.runsAsUserspaceProcess());
    try std.testing.expect(compatibility_task.runsAsUserspaceProcess());
    try std.testing.expectEqualStrings("zigos.system.session-manager", session_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("app.notes", notes_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("zigos.system.storage-driver", storage_driver_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("zigos.system.storage-object", storage_service_task.launchBundleIdSlice());
    try std.testing.expectEqual(storage_driver_task.id, driver_directory.findByClass(.storage_controller).?.owner_task_id);
    try std.testing.expect(storage_driver_task.id != storage_service_task.id);

    const session_user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const storage_service_principal = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const tablet_device_principal = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const notes_workspace = phase4_storage_service.findWorkspace(session_user, "notes-workspace").?;
    const imported_workspace = phase4_storage_service.findWorkspace(storage_service_principal, "imported-notes").?;
    const notes_entry = try phase4_storage_service.resolve(notes_workspace.id, "documents/notes.md");
    const imported_entry = try phase4_storage_service.resolve(imported_workspace.id, "documents/notes.md");
    try std.testing.expectEqual(notes_entry.version_id, imported_entry.version_id);
    try std.testing.expect(phase4_storage_service.findSnapshot(notes_workspace.id, "baseline") != null);

    sync_service_mod.Service.resetPersistentState();
    var restarted_sync = try sync_service_mod.Service.initWithStorage(sync_service.id, 0, sync_service.owner, phase4_storage_service);
    try std.testing.expect(restarted_sync.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 3), restarted_sync.trustedDeviceCount());
    try std.testing.expect(restarted_sync.findWorkspacePolicy(notes_workspace.id) != null);
    try std.testing.expect(restarted_sync.findOverlay(notes_workspace.id) != null);
    try std.testing.expect(restarted_sync.findConflict(notes_workspace.id, tablet_device_principal, "documents/notes.md") == null);

    const state_signer = signing.SignerIdentity{
        .label = "zigos-base-state",
        .seed = [_]u8{0xA1} ** 32,
    };
    const package_service = supervisor.findByClass(.package_install_update).?;
    var immutable_base_manager = try immutable_base.Manager.init(phase4_storage_service, package_service.owner, state_signer);
    try std.testing.expect(immutable_base_manager.loaded_existing_state);
    try std.testing.expectEqual(@as(u64, 8), immutable_base_manager.activation_generation);
    try std.testing.expectEqual(@as(u64, 5), immutable_base_manager.rollback_generation);
    try std.testing.expectEqualStrings("recovery-reinstall", immutable_base_manager.activeImage().?.labelSlice());
    try std.testing.expectEqualStrings("stable-b", immutable_base_manager.slots[immutable_base_manager.inactiveSlotIndex()].labelSlice());
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
