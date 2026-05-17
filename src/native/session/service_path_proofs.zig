const std = @import("std");
const abi = @import("../core/abi.zig");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const attestation_service = @import("../platform/attestation_service.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const ids = @import("../core/ids.zig");
const immutable_base = @import("../platform/immutable_base.zig");
const kernel_data_plane_boundary = @import("../../kernel/boot/init/data_plane_boundary.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_ux = @import("../platform/native_ux.zig");
const notification_center = @import("../services/notification_center.zig");
const platform_policy_signals = @import("../platform/platform_policy_signals.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const process_isolation = @import("../task/process_isolation.zig");
const rendered_shell = @import("../platform/rendered_shell.zig");
const native_service_registry = @import("../services/service_registry.zig");
const network_driver_task = @import("../drivers/network_driver_task.zig");
const network_policy = @import("../sync/network_policy.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const session_manager = @import("session_manager.zig");
const service_catalog = @import("service_catalog.zig");
const shared_memory_mod = @import("../kernel_api/shared_memory.zig");
const signing = @import("../core/signing.zig");
const storage_driver_protocol = @import("../drivers/storage_driver_protocol.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const syscall_surface = @import("../kernel_api/syscall_surface.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service = @import("../task/task_runtime_service.zig");
const update_health = @import("../platform/update_health.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const compositor_display = @import("../platform/compositor_display.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const workspace = @import("../storage/workspace.zig");

pub fn bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting() !void {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    const runtime = session_manager.testing.runtimePtr();
    const runtime_service = session_manager.testing.runtimeServicePtr();
    const capability_table = session_manager.system().capabilityTablePtr();
    const supervisor = session_manager.testing.supervisorPtr();
    const service_directory = session_manager.testing.serviceDirectoryPtr();
    const driver_directory = session_manager.testing.driverDirectoryPtr();
    const driver_runtime = session_manager.testing.driverRuntimePtr();
    const storage = session_manager.testing.storageServicePtr();
    const kernel_port = session_manager.kernelPort() orelse return error.KernelPortUnavailable;

    const session_task = session_manager.testing.findTask("session-manager").?;
    const sync_task = session_manager.testing.findTask("sync-service").?;
    const storage_task = session_manager.testing.findTask("workspace-storage").?;
    const storage_driver_task = session_manager.testing.findTask("storage-driver").?;
    const network_service_task = session_manager.testing.findTask("network-service").?;
    const compositor_task = session_manager.testing.findTask("compositor-session").?;

    try std.testing.expect(sync_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_driver_task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(?u64, 2), compositor_task.ui_surface_id);
    try std.testing.expect(runtime.processSeparated(sync_task.id, storage_task.id));
    try std.testing.expect(runtime.processSeparated(sync_task.id, storage_driver_task.id));
    try std.testing.expect(runtime.processSeparated(storage_driver_task.id, storage_task.id));
    try proveBootedProcessIsolationVisibleEntitlementGates(
        runtime,
        capability_table,
        sync_task,
        storage_task,
        compositor_task,
    );

    const session_authority_id = findServiceAuthority(
        capability_table,
        session_task,
        .resource_query,
    ) orelse return error.MissingBootAuthority;

    runtime.allowHostPointerSyscallsForTask(session_task.id);
    try proveResourceAccountingSyscalls(kernel_port, runtime, session_task.id, session_authority_id);
    try proveBootedSharedMemoryMappingRevocation(kernel_port, runtime, capability_table, session_task.id, session_authority_id);
    try proveBootedDriverPermissions(kernel_port, runtime, capability_table, driver_directory, storage_driver_task, network_service_task);
    try proveBootedUserspaceServiceOwnershipAndKernelBoundary(
        kernel_port,
        runtime,
        capability_table,
        supervisor,
        service_directory,
        driver_directory,
        driver_runtime,
    );
    try proveBootedSyncServicePath(
        kernel_port,
        runtime,
        capability_table,
        supervisor.findByClass(.sync_replication).?,
        sync_task,
        network_service_task,
        storage,
        session_task.id,
        session_authority_id,
    );
    try proveBootedCompositorServicePath(
        kernel_port,
        runtime,
        capability_table,
        storage,
        runtime_service,
        supervisor.findByClass(.compositor_ui_session).?,
        compositor_task,
        session_manager.testing.compositorSessionPtr(),
    );
    try proveBootedPostActivationHealthChecks(
        runtime,
        capability_table,
        supervisor,
        storage,
        sync_task,
        session_manager.testing.compositorSessionPtr(),
    );
    try proveBootedSchedulerTelemetryProvider(
        kernel_port,
        runtime,
        session_manager.testing.userspaceSchedulerPtr(),
        session_task.id,
        session_authority_id,
    );
}

fn proveResourceAccountingSyscalls(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    const probe = try createResourceProbeTask(kernel_port, session_task_id, session_authority_id);
    try std.testing.expect(abi.taskFlagsHas(probe.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(abi.taskFlagsHas(probe.flags, abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED));
    runtime.allowHostPointerSyscallsForTask(probe.task_id);

    const resources = try resourceQuery(kernel_port, session_task_id, session_authority_id, probe.task_id, 82);
    try std.testing.expectEqual(@as(u64, 1_200), resources.cpu_time_ticks);
    try std.testing.expectEqual(@as(u64, 64 * 1024), resources.memory_bytes);
    try std.testing.expectEqual(@as(u64, 1024), resources.shared_memory_bytes);
    try std.testing.expectEqual(@as(u16, 0), resources.endpoint_count);

    _ = try expectEndpointCreate(kernel_port, session_task_id, session_authority_id, probe.task_id, "resource.probe", 83);
    const endpoint_over_budget = endpointCreateResult(kernel_port, session_task_id, session_authority_id, probe.task_id, "resource.probe.extra", 84);
    try std.testing.expectEqual(abi.SyscallStatus.conflict, endpoint_over_budget.status);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, endpoint_over_budget.denial_reason);

    const shared_memory = try expectSharedMemoryCreate(kernel_port, session_task_id, session_authority_id, probe.task_id, 1024, 85);
    try expectSharedMemoryMap(kernel_port, probe.task_id, shared_memory.capability_id, probe.task_id, 86);
    const shared_over_budget = sharedMemoryCreateResult(kernel_port, session_task_id, session_authority_id, probe.task_id, 1, 87);
    try std.testing.expectEqual(abi.SyscallStatus.conflict, shared_over_budget.status);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, shared_over_budget.denial_reason);

    const accounting = try accountingQuery(kernel_port, session_task_id, session_authority_id, probe.task_id, 88);
    try std.testing.expectEqual(@as(u16, 1), accounting.endpoint_count);
    try std.testing.expectEqual(@as(u16, 1), accounting.shared_memory_mappings);

    var spoofed_resource_response = std.mem.zeroes(abi.ResourceDescriptor);
    const spoofed_resource_request = component_port.ResourceQueryRequest{
        .header = component_port.makeHeader(.resource_query, 89, probe.task_id),
        .authority_capability_id = session_authority_id,
        .task_id = probe.task_id,
    };
    const spoofed_result = syscall_surface.dispatch(
        kernel_port,
        probe.task_id,
        89,
        @intFromPtr(&spoofed_resource_request),
        @intFromPtr(&spoofed_resource_response),
        @sizeOf(abi.ResourceDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.not_found, spoofed_result.status);
    try std.testing.expectEqual(abi.DenialReason.capability_missing, spoofed_result.denial_reason);
}

fn proveBootedSharedMemoryMappingRevocation(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    const owner = try createBootedProbeTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        8_010,
        8_010,
        "shared-owner",
        "app.service-path.shared-owner",
        8 * 1024,
        130,
    );
    const peer = try createBootedProbeTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        8_010,
        8_011,
        "shared-peer",
        "app.service-path.shared-peer",
        8 * 1024,
        131,
    );
    runtime.allowHostPointerSyscallsForTask(owner.task_id);
    runtime.allowHostPointerSyscallsForTask(peer.task_id);

    const created = try expectSharedMemoryCreate(kernel_port, session_task_id, session_authority_id, owner.task_id, 4096, 132);
    const object_id = ids.sharedMemory(created.object.object_id);
    const peer_capability = try capability_table.mintBootRoot(.{
        .holder = runtime.find(peer.task_id).?.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .shared_memory, .id = object_id.raw() },
        .rights = .{ .shared_memory = .{
            .shared_memory_map = true,
            .shared_memory_unmap = true,
        } },
        .scope = .{
            .task_id = peer.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 132,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(peer.task_id, peer_capability.id);

    const owner_map = try expectSharedMemoryMapDescriptor(kernel_port, owner.task_id, created.capability_id, owner.task_id, 133);
    try std.testing.expectEqual(@as(u16, 1), owner_map.mapped_task_count);
    const peer_map = try expectSharedMemoryMapDescriptor(kernel_port, peer.task_id, peer_capability.id, peer.task_id, 134);
    try std.testing.expectEqual(@as(u16, 2), peer_map.mapped_task_count);

    const owner_mapping = try kernel_port.kernel.shared_memory_table.taskMappingDescriptor(object_id, ids.task(owner.task_id));
    const peer_mapping = try kernel_port.kernel.shared_memory_table.taskMappingDescriptor(object_id, ids.task(peer.task_id));
    const owner_mmu_mapping = try kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(object_id, ids.task(owner.task_id));
    const peer_mmu_mapping = try kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(object_id, ids.task(peer.task_id));
    try std.testing.expectEqual(owner_mapping.page_base, peer_mapping.page_base);
    try std.testing.expectEqual(@as(usize, 1), owner_mapping.page_count);
    try std.testing.expectEqual(@as(usize, 4096), peer_mapping.size_bytes);
    try std.testing.expect(!owner_mapping.zero_copy);
    try std.testing.expectEqual(owner_mapping.page_base, owner_mmu_mapping.physical_base);
    try std.testing.expectEqual(owner_mmu_mapping.physical_base, peer_mmu_mapping.physical_base);
    try std.testing.expect(owner_mmu_mapping.virtual_base != 0);
    try std.testing.expect(peer_mmu_mapping.virtual_base != 0);
    try std.testing.expect(owner_mmu_mapping.virtual_base != peer_mmu_mapping.virtual_base);
    try std.testing.expect(!owner_mmu_mapping.zero_copy);
    try kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(owner_mapping);
    try kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(peer_mapping);
    try kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(owner_mmu_mapping);
    try kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(peer_mmu_mapping);
    try std.testing.expectEqual(@as(usize, 2), kernel_port.kernel.shared_memory_table.activeFreestandingMappings(object_id));

    const revoked = try expectSharedMemoryRevoke(kernel_port, owner.task_id, created.capability_id, 135);
    try std.testing.expectEqual(@as(u16, 0), revoked.mapped_task_count);
    try std.testing.expectEqual(@as(u32, owner_map.revocation_generation + 1), revoked.revocation_generation);
    try std.testing.expectEqual(@as(u16, 1), revoked.flags);
    try std.testing.expectEqual(@as(u16, 0), (try accountingQuery(kernel_port, session_task_id, session_authority_id, owner.task_id, 136)).shared_memory_mappings);
    try std.testing.expectEqual(@as(u16, 0), (try accountingQuery(kernel_port, session_task_id, session_authority_id, peer.task_id, 137)).shared_memory_mappings);

    const post_revoke_map = sharedMemoryMapResult(kernel_port, peer.task_id, peer_capability.id, peer.task_id, 138);
    try std.testing.expectEqual(abi.SyscallStatus.denied, post_revoke_map.status);
    try std.testing.expectEqual(abi.DenialReason.capability_revoked, post_revoke_map.denial_reason);
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.taskMappingDescriptor(object_id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(object_id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(owner_mapping));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(owner_mmu_mapping));
    try std.testing.expectEqual(@as(usize, 0), kernel_port.kernel.shared_memory_table.activeFreestandingMappings(object_id));

    const accelerated = try kernel_port.kernel.shared_memory_table.createLabeledWithAccess(ids.task(owner.task_id), 8192, "booted-accelerator", .{
        .gpu = true,
        .media = true,
    });
    try kernel_port.kernel.shared_memory_table.map(accelerated.id, ids.task(owner.task_id));
    try kernel_port.kernel.shared_memory_table.attachAccelerator(accelerated.id, .gpu);
    const task_mapping = try kernel_port.kernel.shared_memory_table.taskMappingDescriptor(accelerated.id, ids.task(owner.task_id));
    const gpu_mapping = try kernel_port.kernel.shared_memory_table.acceleratorMappingDescriptor(accelerated.id, .gpu);
    const task_mmu_mapping = try kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(accelerated.id, ids.task(owner.task_id));
    const gpu_mmu_mapping = try kernel_port.kernel.shared_memory_table.freestandingAcceleratorMappingDescriptor(accelerated.id, .gpu);
    try std.testing.expect(gpu_mapping.zero_copy);
    try std.testing.expectEqual(task_mapping.page_base, gpu_mapping.page_base);
    try std.testing.expectEqual(task_mapping.page_count, gpu_mapping.page_count);
    try std.testing.expectEqual(task_mapping.page_base, task_mmu_mapping.physical_base);
    try std.testing.expectEqual(task_mmu_mapping.physical_base, gpu_mmu_mapping.physical_base);
    try std.testing.expect(task_mmu_mapping.virtual_base != gpu_mmu_mapping.virtual_base);
    try std.testing.expect(gpu_mmu_mapping.zero_copy);
    try std.testing.expectEqual(shared_memory_mod.ComputeTarget.gpu, gpu_mmu_mapping.target.?);
    try kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(task_mapping);
    try kernel_port.kernel.shared_memory_table.validateAcceleratorMappingDescriptor(gpu_mapping, .gpu);
    try kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(task_mmu_mapping);
    try kernel_port.kernel.shared_memory_table.validateFreestandingAcceleratorMappingDescriptor(gpu_mmu_mapping, .gpu);
    try std.testing.expectEqual(@as(usize, 2), kernel_port.kernel.shared_memory_table.activeFreestandingMappings(accelerated.id));
    try kernel_port.kernel.shared_memory_table.revoke(accelerated.id);
    try std.testing.expectEqual(@as(usize, 0), kernel_port.kernel.shared_memory_table.activeFreestandingMappings(accelerated.id));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.taskMappingDescriptor(accelerated.id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.acceleratorMappingDescriptor(accelerated.id, .gpu));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(accelerated.id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.freestandingAcceleratorMappingDescriptor(accelerated.id, .gpu));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(task_mapping));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateAcceleratorMappingDescriptor(gpu_mapping, .gpu));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(task_mmu_mapping));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateFreestandingAcceleratorMappingDescriptor(gpu_mmu_mapping, .gpu));
}

fn proveBootedDriverPermissions(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *const capability.CapabilityTable,
    driver_directory: *driver_service.Directory,
    storage_driver_task: *task_runtime.TaskRecord,
    network_service_task: *task_runtime.TaskRecord,
) !void {
    const storage_driver = driver_directory.findByClass(.storage_controller).?;
    const network_driver = driver_directory.findByClass(.network_adapter).?;
    try std.testing.expectEqual(storage_driver_task.id, storage_driver.owner_task_id);
    try std.testing.expect(runtime.hasCapability(storage_driver.owner_task_id, storage_driver.authority_capability_id));
    try std.testing.expect(!runtime.hasCapability(network_service_task.id, storage_driver.authority_capability_id));
    try std.testing.expect(!runtime.hasCapability(storage_driver.owner_task_id, network_driver.authority_capability_id));

    const storage_authority = capability_table.query(storage_driver.authority_capability_id).?;
    try std.testing.expect(storage_authority.rights.has(.object_read));
    try std.testing.expect(storage_authority.rights.has(.object_write));
    try std.testing.expect(!storage_authority.rights.has(.network_local));
    try std.testing.expect(storage_driver.allowsDma(storage_driver.dma_ranges[0].base, 4096));
    try std.testing.expect(!storage_driver.allowsDma(storage_driver.dma_ranges[0].base + storage_driver.dma_ranges[0].length - 1024, 4096));

    device_broker.reset();
    defer device_broker.reset();
    try std.testing.expect(device_broker.publishAtaController(storage_driver.device_id, storageGrant()));

    runtime.allowHostPointerSyscallsForTask(storage_driver.owner_task_id);
    const descriptor = try expectDeviceDescribe(kernel_port, storage_driver.owner_task_id, storage_driver.authority_capability_id, 90);
    try std.testing.expectEqual(storage_driver.device_id, descriptor.device_id);
    try std.testing.expectEqual(@as(u16, 0x1F0), descriptor.base_port);

    runtime.allowHostPointerSyscallsForTask(network_service_task.id);
    const cross_task = deviceDescribeResult(kernel_port, network_service_task.id, storage_driver.authority_capability_id, 91);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, cross_task.status);
    try std.testing.expectEqual(abi.DenialReason.capability_missing, cross_task.denial_reason);
}

fn proveBootedProcessIsolationVisibleEntitlementGates(
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    caller: *task_runtime.TaskRecord,
    data_target: *task_runtime.TaskRecord,
    window_target: *task_runtime.TaskRecord,
) !void {
    try std.testing.expect(caller.runsAsUserspaceProcess());
    try std.testing.expect(data_target.runsAsUserspaceProcess());
    try std.testing.expect(window_target.runsAsUserspaceProcess());
    try std.testing.expect(runtime.processSeparated(caller.id, data_target.id));
    try std.testing.expect(runtime.processSeparated(caller.id, window_target.id));

    var broker = process_isolation.Broker.init(runtime, capability_table);
    try std.testing.expectError(error.CapabilityNotFound, broker.authorize(.{
        .caller_task_id = caller.id,
        .target_task_id = data_target.id,
        .capability_id = 90_000,
        .operation = .inspect_memory,
        .user_visible = true,
        .now_ticks = 90,
    }));

    const non_visible = try mintProcessControlCapability(
        capability_table,
        caller,
        data_target.id,
        false,
        91,
    );
    try runtime.grantCapability(caller.id, non_visible.id);
    try std.testing.expectError(error.VisibleEntitlementRequired, broker.authorize(.{
        .caller_task_id = caller.id,
        .target_task_id = data_target.id,
        .capability_id = non_visible.id,
        .operation = .inject_code,
        .user_visible = true,
        .now_ticks = 92,
    }));

    const visible_data = try mintProcessControlCapability(
        capability_table,
        caller,
        data_target.id,
        true,
        93,
    );
    try runtime.grantCapability(caller.id, visible_data.id);
    inline for (.{ process_isolation.Operation.inspect_memory, process_isolation.Operation.inject_code }) |operation| {
        const decision = try broker.authorize(.{
            .caller_task_id = caller.id,
            .target_task_id = data_target.id,
            .capability_id = visible_data.id,
            .operation = operation,
            .user_visible = true,
            .now_ticks = 94 + @intFromEnum(operation),
        });
        try std.testing.expect(decision.allowed);
        try std.testing.expectEqual(data_target.id, decision.target_task_id);
    }

    const visible_window = try mintProcessControlCapability(
        capability_table,
        caller,
        window_target.id,
        true,
        101,
    );
    try runtime.grantCapability(caller.id, visible_window.id);
    const scrape_decision = try broker.authorize(.{
        .caller_task_id = caller.id,
        .target_task_id = window_target.id,
        .capability_id = visible_window.id,
        .operation = .scrape_window,
        .user_visible = true,
        .now_ticks = 102,
    });
    try std.testing.expect(scrape_decision.allowed);
    try std.testing.expectEqual(window_target.id, scrape_decision.target_task_id);

    const visible_self = try mintProcessControlCapability(
        capability_table,
        caller,
        caller.id,
        true,
        103,
    );
    try runtime.grantCapability(caller.id, visible_self.id);
    try std.testing.expectError(error.VisibleEntitlementRequired, broker.authorize(.{
        .caller_task_id = caller.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = false,
        .now_ticks = 104,
    }));
    const clipboard_decision = try broker.authorize(.{
        .caller_task_id = caller.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = true,
        .now_ticks = 105,
    });
    try std.testing.expect(clipboard_decision.allowed);
    try std.testing.expectEqual(caller.id, clipboard_decision.target_task_id);
    try std.testing.expectError(error.HiddenGlobalHookDenied, broker.authorize(.{
        .caller_task_id = caller.id,
        .capability_id = visible_self.id,
        .operation = .register_global_hook,
        .hidden = true,
        .user_visible = true,
        .now_ticks = 106,
    }));
    const hook_decision = try broker.authorize(.{
        .caller_task_id = caller.id,
        .capability_id = visible_self.id,
        .operation = .register_global_hook,
        .user_visible = true,
        .now_ticks = 107,
    });
    try std.testing.expect(hook_decision.allowed);

    const latest = caller.latestAuditEvent() orelse return error.MissingProcessIsolationAudit;
    try std.testing.expectEqual(task_runtime.AuditEventKind.policy_allowed, latest.kind);
    try std.testing.expectEqual(@as(u32, @intFromEnum(process_isolation.Operation.register_global_hook)), latest.detail);
}

fn mintProcessControlCapability(
    capability_table: *capability.CapabilityTable,
    caller: *const task_runtime.TaskRecord,
    target_task_id: u64,
    visible: bool,
    tick: u64,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = caller.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = target_task_id },
        .rights = .{ .task = .{ .process_control = true } },
        .scope = .{
            .task_id = caller.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = tick,
            .expires_at_ticks = 1_000,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = caller.id,
            .broker_service_id = 90,
            .user_visible_entitlement = visible,
        },
    });
}

fn proveBootedDriverHotSwapAndRecoveryRebindLiveBrokeredDeviceAuthority() !void {
    const BootedDriverRuntime = struct {
        tasks: *task_runtime.Runtime,
        activations: *driver_runtime_mod.Runtime,
        rehost_count: usize = 0,
        deactivation_count: usize = 0,
        activation_count: usize = 0,
        last_task_id: u64 = 0,
        last_process_generation: u32 = 0,
        last_dma_domain_id: u64 = 0,

        pub fn deactivate(self: *@This(), service_id: u64) bool {
            const deactivated = self.activations.deactivate(service_id);
            if (deactivated) self.deactivation_count += 1;
            return deactivated;
        }

        pub fn deactivateDriver(self: *@This(), service_id: u64, device_class: driver_service.DeviceClass) bool {
            const deactivated = self.activations.deactivateDriver(service_id, device_class);
            if (deactivated) self.deactivation_count += 1;
            return deactivated;
        }

        pub fn activateAt(self: *@This(), driver: *const driver_service.DriverRecord, tick: u64) !driver_runtime_mod.ActivationRecord {
            const task = self.tasks.find(driver.owner_task_id) orelse return error.TaskNotFound;
            const previous_generation = task.process_generation;
            const rehosted = try self.tasks.rehostTask(driver.owner_task_id, tick);
            const restarted_task = self.tasks.find(driver.owner_task_id) orelse return error.TaskNotFound;
            const activation = try self.activations.activateAt(driver, tick);
            self.activation_count += 1;
            self.last_task_id = driver.owner_task_id;
            self.last_process_generation = restarted_task.process_generation;
            self.last_dma_domain_id = activation.dma_domain_id;
            if (rehosted and restarted_task.process_generation > previous_generation) {
                self.rehost_count += 1;
            }
            return activation;
        }
    };

    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    const runtime = session_manager.testing.runtimePtr();
    const capability_table = session_manager.system().capabilityTablePtr();
    const supervisor = session_manager.testing.supervisorPtr();
    const driver_directory = session_manager.testing.driverDirectoryPtr();
    const driver_runtime = session_manager.testing.driverRuntimePtr();
    const kernel_port = session_manager.kernelPort() orelse return error.KernelPortUnavailable;
    const ledger = session_manager.testing.updateLedgerPtr();

    const storage_service_record = supervisor.findByClass(.storage_object).?;
    const network_service = supervisor.findByClass(.network_stack).?;
    const session_task = session_manager.testing.findTask("session-manager").?;
    const network_task = session_manager.testing.findTask("network-service").?;
    const storage_driver = driver_directory.findByClass(.storage_controller).?;
    const storage_driver_task = runtime.find(storage_driver.owner_task_id).?;

    const service_count_before = session_manager.testing.countServices();
    const task_count_before = session_manager.testing.countTasks();
    const session_process_generation_before = session_task.process_generation;
    const network_restart_count_before = network_service.restart_count;
    const network_process_generation_before = network_task.process_generation;
    const storage_restart_count_before = storage_service_record.restart_count;
    const storage_restart_generation_before = storage_driver.restart_generation;
    const storage_dma_before = storage_driver.dma_domain_id;
    const storage_process_generation_before = storage_driver_task.process_generation;
    const storage_address_space_before = storage_driver_task.address_space_id;

    bootstrap_driver_port.reset();
    try std.testing.expect(device_broker.publishAtaController(storage_driver.device_id, storageGrant()));
    try std.testing.expect(try bootstrap_driver_port.publishStorageAtaBootstrap(
        storage_driver.device_id,
        "zigos.system.storage-driver",
        false,
    ));

    const initial_activation = try driver_runtime.activateAt(storage_driver, 780);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.userspace_brokered_data_plane, initial_activation.mode);
    try std.testing.expect(initial_activation.exclusive_claim);
    try std.testing.expect(initial_activation.iommu_enforced);

    runtime.allowHostPointerSyscallsForTask(storage_driver.owner_task_id);
    const descriptor_before = try expectDeviceDescribe(kernel_port, storage_driver.owner_task_id, storage_driver.authority_capability_id, 781);
    try std.testing.expectEqual(storage_driver.device_id, descriptor_before.device_id);
    try std.testing.expectEqual(@as(u16, 0x1F0), descriptor_before.base_port);

    var booted_runtime = BootedDriverRuntime{
        .tasks = runtime,
        .activations = driver_runtime,
    };

    const recovery = try supervisor.recoverDriverCrash(
        storage_service_record.id,
        driver_directory,
        &booted_runtime,
        null,
        ledger,
        790,
        0x510,
        "storage driver brokered crash",
    );

    const recovered_driver = driver_directory.findByClass(.storage_controller).?;
    const recovered_task = runtime.find(recovered_driver.owner_task_id).?;
    try std.testing.expect(!recovery.visible_impact);
    try std.testing.expect(recovery.notification_id == null);
    try std.testing.expect(recovery.runtime_activation_observed);
    try std.testing.expect(recovery.runtime_activation_generation > initial_activation.activation_generation);
    try std.testing.expectEqual(recovered_driver.dma_domain_id, recovery.runtime_dma_domain_id);
    try std.testing.expect(recovery.runtime_exclusive_claim);
    try std.testing.expect(recovery.userspace_brokered_data_plane);
    try std.testing.expectEqual(@as(usize, 1), booted_runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 1), booted_runtime.activation_count);
    try std.testing.expectEqual(@as(usize, 1), booted_runtime.rehost_count);
    try std.testing.expectEqual(recovered_driver.owner_task_id, booted_runtime.last_task_id);
    try std.testing.expectEqual(recovered_task.process_generation, booted_runtime.last_process_generation);
    try std.testing.expectEqual(recovered_driver.dma_domain_id, booted_runtime.last_dma_domain_id);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, storage_service_record.state);
    try std.testing.expectEqual(storage_restart_count_before + 1, storage_service_record.restart_count);
    try std.testing.expectEqual(storage_restart_generation_before + 1, recovered_driver.restart_generation);
    try std.testing.expect(recovered_driver.dma_domain_id != storage_dma_before);
    try std.testing.expectEqual(storage_process_generation_before + 1, recovered_task.process_generation);
    try std.testing.expect(runtime.findAddressSpaceConst(storage_address_space_before) == null);
    try std.testing.expect(supervisor.hasDiagnostic(storage_service_record.id, .crash));
    try std.testing.expect(supervisor.hasDiagnostic(storage_service_record.id, .restart_completed));
    try std.testing.expectEqual(service_catalog.ServiceClass.storage_object, ledger.latestKind(.process_crash).?.service_class);
    try std.testing.expectEqual(recovered_driver.authority_capability_id, ledger.latestKind(.driver_restart).?.related_id);
    try std.testing.expectEqual(network_restart_count_before, network_service.restart_count);
    try std.testing.expectEqual(network_process_generation_before, network_task.process_generation);
    try std.testing.expect(session_manager.testing.isInitialized());
    try std.testing.expectEqual(service_count_before, session_manager.testing.countServices());
    try std.testing.expectEqual(task_count_before, session_manager.testing.countTasks());
    try std.testing.expectEqual(session_process_generation_before, session_task.process_generation);

    runtime.allowHostPointerSyscallsForTask(recovered_driver.owner_task_id);
    const recovered_descriptor = try expectDeviceDescribe(kernel_port, recovered_driver.owner_task_id, recovered_driver.authority_capability_id, 792);
    try std.testing.expectEqual(recovered_driver.device_id, recovered_descriptor.device_id);

    const recovered_authority_id = recovered_driver.authority_capability_id;
    const hot_swap_process_generation_before = recovered_task.process_generation;
    const hot_swap_address_space_before = recovered_task.address_space_id;
    const hot_swap_restart_generation_before = recovered_driver.restart_generation;
    const hot_swap_dma_before = recovered_driver.dma_domain_id;
    const next_authority = try capability_table.mintBootRoot(.{
        .holder = storage_service_record.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = driver_service.authorityTarget(recovered_driver.device_id),
        .rights = driver_service.allowedRightsFor(.storage_controller),
        .scope = .{
            .task_id = recovered_driver.owner_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 800,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = false,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = session_task.id,
            .broker_service_id = storage_service_record.id,
        },
    });
    try runtime.grantCapability(recovered_driver.owner_task_id, next_authority.id);

    const hot_swap = try supervisor.hotSwapDriver(.{
        .service_id = storage_service_record.id,
        .owner_task_id = recovered_driver.owner_task_id,
        .device_id = recovered_driver.device_id,
        .device_class = .storage_controller,
        .authority_capability_id = next_authority.id,
        .capability_table = capability_table,
        .requester = storage_service_record.owner,
        .now_ticks = 800,
        .signer = "zigos-storage-driver-v2",
        .bootstrap_transport = .kernel_bootstrap_broker,
    }, driver_directory, &booted_runtime, null, ledger, 800, "storage driver hot-swapped through broker");

    const swapped_driver = driver_directory.findByClass(.storage_controller).?;
    const swapped_task = runtime.find(swapped_driver.owner_task_id).?;
    try std.testing.expect(!hot_swap.visible_impact);
    try std.testing.expect(hot_swap.notification_id == null);
    try std.testing.expectEqual(hot_swap_restart_generation_before, hot_swap.previous_restart_generation);
    try std.testing.expectEqual(hot_swap_restart_generation_before + 1, hot_swap.next_restart_generation);
    try std.testing.expectEqual(hot_swap_dma_before, hot_swap.previous_dma_domain_id);
    try std.testing.expect(swapped_driver.dma_domain_id != hot_swap_dma_before);
    try std.testing.expectEqual(swapped_driver.dma_domain_id, hot_swap.next_dma_domain_id);
    try std.testing.expect(hot_swap.runtime_activation_observed);
    try std.testing.expect(hot_swap.runtime_activation_generation > recovery.runtime_activation_generation);
    try std.testing.expectEqual(swapped_driver.dma_domain_id, hot_swap.runtime_dma_domain_id);
    try std.testing.expect(hot_swap.runtime_exclusive_claim);
    try std.testing.expect(hot_swap.userspace_brokered_data_plane);
    try std.testing.expectEqual(next_authority.id, swapped_driver.authority_capability_id);
    try std.testing.expect(swapped_driver.authority_capability_id != recovered_authority_id);
    try std.testing.expectEqualStrings("zigos-storage-driver-v2", swapped_driver.signerSlice());
    try std.testing.expect(runtime.hasCapability(swapped_driver.owner_task_id, next_authority.id));
    try std.testing.expectEqual(hot_swap_process_generation_before + 1, swapped_task.process_generation);
    try std.testing.expect(runtime.findAddressSpaceConst(hot_swap_address_space_before) == null);
    try std.testing.expectEqual(@as(usize, 2), booted_runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 2), booted_runtime.activation_count);
    try std.testing.expectEqual(@as(usize, 2), booted_runtime.rehost_count);
    try std.testing.expectEqual(swapped_driver.owner_task_id, booted_runtime.last_task_id);
    try std.testing.expectEqual(swapped_task.process_generation, booted_runtime.last_process_generation);
    try std.testing.expectEqual(swapped_driver.dma_domain_id, booted_runtime.last_dma_domain_id);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, storage_service_record.state);
    try std.testing.expectEqual(storage_restart_count_before + 2, storage_service_record.restart_count);
    try std.testing.expect(supervisor.hasDiagnostic(storage_service_record.id, .driver_attached));
    try std.testing.expect(supervisor.hasDiagnostic(storage_service_record.id, .restart_completed));
    try std.testing.expectEqual(next_authority.id, ledger.latestKind(.driver_restart).?.related_id);
    try std.testing.expectEqual(network_restart_count_before, network_service.restart_count);
    try std.testing.expectEqual(network_process_generation_before, network_task.process_generation);
    try std.testing.expectEqual(service_count_before, session_manager.testing.countServices());
    try std.testing.expectEqual(task_count_before, session_manager.testing.countTasks());
    try std.testing.expectEqual(session_process_generation_before, session_task.process_generation);

    runtime.allowHostPointerSyscallsForTask(swapped_driver.owner_task_id);
    const swapped_descriptor = try expectDeviceDescribe(kernel_port, swapped_driver.owner_task_id, next_authority.id, 802);
    try std.testing.expectEqual(swapped_driver.device_id, swapped_descriptor.device_id);
    try std.testing.expectEqual(@as(u16, 0x1F0), swapped_descriptor.base_port);
    try std.testing.expectEqual(@as(u8, 14), swapped_descriptor.irq_line);

    const compositor_service_record = supervisor.findByClass(.compositor_ui_session).?;
    const graphics_driver = driver_directory.findByClass(.graphics_adapter).?;
    const input_driver = driver_directory.findByClass(.input_device).?;
    try std.testing.expect(try bootstrap_driver_port.publishDeviceDataPlane(
        .graphics_adapter,
        graphics_driver.device_id,
        "zigos.system.compositor",
        false,
    ));
    try std.testing.expect(try bootstrap_driver_port.publishDeviceDataPlane(
        .input_device,
        input_driver.device_id,
        "zigos.system.compositor",
        false,
    ));
    const graphics_reactivation = try driver_runtime.activateAt(graphics_driver, 818);
    const input_reactivation = try driver_runtime.activateAt(input_driver, 819);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, graphics_reactivation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, input_reactivation.mode);
    const graphics_task = runtime.find(graphics_driver.owner_task_id).?;
    const input_activation_before = driver_runtime.findByClass(.input_device) orelse return error.MissingBootedDriverBinding;
    const graphics_restart_count_before = compositor_service_record.restart_count;
    const graphics_restart_generation_before = graphics_driver.restart_generation;
    const graphics_dma_before = graphics_driver.dma_domain_id;
    const graphics_process_generation_before = graphics_task.process_generation;
    const graphics_address_space_before = graphics_task.address_space_id;
    const graphics_authority = try capability_table.mintBootRoot(.{
        .holder = compositor_service_record.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = driver_service.authorityTarget(graphics_driver.device_id),
        .rights = driver_service.allowedRightsFor(.graphics_adapter),
        .scope = .{
            .task_id = graphics_driver.owner_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 820,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = false,
        },
        .audit = .{
            .policy_generation = 2,
            .source_task_id = session_task.id,
            .broker_service_id = compositor_service_record.id,
        },
    });
    try runtime.grantCapability(graphics_driver.owner_task_id, graphics_authority.id);

    var notifications = notification_center.Center.init();
    const graphics_hot_swap = try supervisor.hotSwapDriver(.{
        .service_id = compositor_service_record.id,
        .owner_task_id = graphics_driver.owner_task_id,
        .device_id = graphics_driver.device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = graphics_authority.id,
        .capability_table = capability_table,
        .requester = compositor_service_record.owner,
        .now_ticks = 820,
        .signer = "zigos-graphics-driver-v2",
    }, driver_directory, &booted_runtime, &notifications, ledger, 820, "graphics driver hot-swapped through compositor service");

    const swapped_graphics = driver_directory.findByClass(.graphics_adapter).?;
    const swapped_graphics_task = runtime.find(swapped_graphics.owner_task_id).?;
    const input_activation_after = driver_runtime.findByClass(.input_device) orelse return error.MissingBootedDriverBinding;
    try std.testing.expect(graphics_hot_swap.visible_impact);
    try std.testing.expect(graphics_hot_swap.notification_id != null);
    try std.testing.expectEqual(notification_center.Reason.driver_restart, notifications.latestVisible(821).?.reason);
    try std.testing.expectEqual(graphics_restart_generation_before, graphics_hot_swap.previous_restart_generation);
    try std.testing.expectEqual(graphics_restart_generation_before + 1, graphics_hot_swap.next_restart_generation);
    try std.testing.expectEqual(graphics_dma_before, graphics_hot_swap.previous_dma_domain_id);
    try std.testing.expect(swapped_graphics.dma_domain_id != graphics_dma_before);
    try std.testing.expectEqual(swapped_graphics.dma_domain_id, graphics_hot_swap.next_dma_domain_id);
    try std.testing.expect(graphics_hot_swap.runtime_activation_observed);
    try std.testing.expectEqual(swapped_graphics.dma_domain_id, graphics_hot_swap.runtime_dma_domain_id);
    try std.testing.expect(graphics_hot_swap.runtime_exclusive_claim);
    try std.testing.expect(!graphics_hot_swap.userspace_brokered_data_plane);
    try std.testing.expectEqual(graphics_authority.id, swapped_graphics.authority_capability_id);
    try std.testing.expectEqualStrings("zigos-graphics-driver-v2", swapped_graphics.signerSlice());
    try std.testing.expect(runtime.hasCapability(swapped_graphics.owner_task_id, graphics_authority.id));
    try std.testing.expectEqual(graphics_process_generation_before + 1, swapped_graphics_task.process_generation);
    try std.testing.expect(runtime.findAddressSpaceConst(graphics_address_space_before) == null);
    try std.testing.expectEqual(@as(usize, 3), booted_runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 3), booted_runtime.activation_count);
    try std.testing.expectEqual(@as(usize, 3), booted_runtime.rehost_count);
    try std.testing.expectEqual(swapped_graphics.owner_task_id, booted_runtime.last_task_id);
    try std.testing.expectEqual(swapped_graphics_task.process_generation, booted_runtime.last_process_generation);
    try std.testing.expectEqual(swapped_graphics.dma_domain_id, booted_runtime.last_dma_domain_id);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, compositor_service_record.state);
    try std.testing.expectEqual(graphics_restart_count_before + 1, compositor_service_record.restart_count);
    try std.testing.expect(supervisor.hasDiagnostic(compositor_service_record.id, .driver_attached));
    try std.testing.expect(supervisor.hasDiagnostic(compositor_service_record.id, .restart_completed));
    try std.testing.expectEqual(graphics_authority.id, ledger.latestKind(.driver_restart).?.related_id);
    try std.testing.expectEqual(input_driver.service_id, compositor_service_record.id);
    try std.testing.expectEqual(input_activation_before.activation_generation, input_activation_after.activation_generation);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, input_activation_after.mode);
    try std.testing.expect(input_activation_after.exclusive_claim);
    try std.testing.expectEqual(compositor_service_record.id, bootstrap_driver_port.deviceDataPlanePublication(.input_device).?.active_service_id);
    try std.testing.expectEqual(network_restart_count_before, network_service.restart_count);
    try std.testing.expectEqual(network_process_generation_before, network_task.process_generation);
    try std.testing.expectEqual(storage_restart_count_before + 2, storage_service_record.restart_count);
    try std.testing.expectEqual(service_count_before, session_manager.testing.countServices());
    try std.testing.expectEqual(task_count_before, session_manager.testing.countTasks());
    try std.testing.expectEqual(session_process_generation_before, session_task.process_generation);
}

const BootedServiceBinding = struct {
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
};

fn proveBootedUserspaceServiceOwnershipAndKernelBoundary(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *const capability.CapabilityTable,
    supervisor: *supervisor_mod.Supervisor,
    service_directory: *const native_service_registry.Service,
    driver_directory: *driver_service.Directory,
    driver_runtime: *const driver_runtime_mod.Runtime,
) !void {
    const excluded_services = [_]struct {
        class: service_catalog.ServiceClass,
        data_plane: kernel_data_plane_boundary.DataPlaneKind,
    }{
        .{ .class = .network_stack, .data_plane = .network_stack },
        .{ .class = .storage_object, .data_plane = .storage_object },
        .{ .class = .compositor_ui_session, .data_plane = .windowing },
        .{ .class = .package_install_update, .data_plane = .package_install },
        .{ .class = .indexing_search, .data_plane = .indexing },
        .{ .class = .sync_replication, .data_plane = .sync_replication },
    };

    for (excluded_services) |entry| {
        const binding = try assertBootedUserspaceServiceBinding(
            kernel_port,
            runtime,
            capability_table,
            supervisor,
            service_directory,
            entry.class,
        );
        try std.testing.expectError(error.KernelSubsystemDataPlaneDisabled, kernel_data_plane_boundary.rejectKernelSubsystemDataPlane(.{
            .kind = entry.data_plane,
            .service_id = binding.service_id,
            .owner_task_id = binding.owner_task_id,
            .endpoint_id = binding.endpoint_id,
        }));
        try expectRootKernelCallerDenied(kernel_port, binding.endpoint_capability_id, binding.owner_task_id, 170 + @intFromEnum(entry.class));
    }

    const driver_expectations = [_]struct {
        device_class: driver_service.DeviceClass,
        service_class: service_catalog.ServiceClass,
    }{
        .{ .device_class = .network_adapter, .service_class = .network_stack },
        .{ .device_class = .storage_controller, .service_class = .storage_object },
        .{ .device_class = .graphics_adapter, .service_class = .compositor_ui_session },
        .{ .device_class = .input_device, .service_class = .compositor_ui_session },
        .{ .device_class = .audio_print_io, .service_class = .media_print_helpers },
    };

    for (driver_expectations) |expectation| {
        const driver = driver_directory.findByClass(expectation.device_class) orelse return error.MissingBootedDriverBinding;
        const service_record = supervisor.findByClass(expectation.service_class) orelse return error.MissingBootedServiceBinding;
        const driver_task = runtime.find(driver.owner_task_id) orelse return error.MissingBootedDriverTask;
        try std.testing.expectEqual(service_record.id, driver.service_id);
        try std.testing.expect(driver_task.runsAsUserspaceProcess());
        try std.testing.expect(driver_task.hasLoadedExecutable());
        try std.testing.expect(driver_task.launch.signed);
        try std.testing.expect(driver_service.requiresUserspaceDataPlane(expectation.device_class));
        try std.testing.expect(!driver_service.permitsKernelDataPlane(expectation.device_class));
        try std.testing.expect(driver.dma_domain_id != 0);
        try std.testing.expectEqual(driver_service.DmaProtection.iommu_enforced, driver.dma_protection);
        try std.testing.expectError(error.KernelDeviceDataPlaneDisabled, kernel_data_plane_boundary.rejectKernelDeviceDataPlane(.{
            .service_id = driver.service_id,
            .device_id = driver.device_id,
            .device_class = @intFromEnum(driver.device_class),
        }));

        const activation = driver_runtime.findByClass(expectation.device_class) orelse return error.MissingBootedDriverBinding;
        try std.testing.expectEqual(driver.service_id, activation.service_id);
        try std.testing.expectEqual(driver.device_id, activation.device_id);
        try std.testing.expect(activation.iommu_enforced);
        try std.testing.expect(!activation.kernel_bootstrap);
        try std.testing.expect(activation.exclusive_claim);
        switch (expectation.device_class) {
            .storage_controller => try std.testing.expect(
                activation.mode == .published_data_plane or
                    activation.mode == .userspace_brokered_data_plane,
            ),
            .network_adapter, .graphics_adapter, .audio_print_io, .input_device => {
                try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, activation.mode);
            },
        }
        try std.testing.expect(activation.publisherSlice().len != 0);
    }
}

fn assertBootedUserspaceServiceBinding(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *const capability.CapabilityTable,
    supervisor: *supervisor_mod.Supervisor,
    service_directory: *const native_service_registry.Service,
    class: service_catalog.ServiceClass,
) !BootedServiceBinding {
    const descriptor = service_catalog.serviceDescriptor(class) orelse return error.MissingBootedServiceBinding;
    try std.testing.expectEqual(service_catalog.ServiceBoundary.userspace_service, descriptor.boundary);
    try std.testing.expect(descriptor.restartable);
    try std.testing.expect(descriptor.isolation.namespace_isolated);
    try std.testing.expect(descriptor.isolation.zero_ambient_authority);
    try std.testing.expect(service_catalog.publishedNativeServiceContractForClass(class) != null);

    const contract = service_catalog.serviceContractForClass(class) orelse return error.MissingBootedServiceBinding;
    const service_record = supervisor.findByClass(class) orelse return error.MissingBootedServiceBinding;
    const connection = try service_directory.connect(contract.interface);
    try std.testing.expectEqual(service_record.id, connection.service_id);
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE));

    const endpoint_descriptor = try kernel_port.kernel.endpoint_table.descriptor(ids.endpoint(connection.endpoint_id));
    const endpoint_flags: endpoint.EndpointFlags = @bitCast(endpoint_descriptor.flags);
    try std.testing.expect(endpoint_flags.local_only);
    try std.testing.expect(endpoint_flags.service_port);
    try std.testing.expectEqual(connection.endpoint_id, endpoint_descriptor.endpoint_id);

    const task = runtime.find(endpoint_descriptor.owner_task_id) orelse return error.MissingBootedServiceTask;
    const image = service_catalog.imageForClass(class) orelse return error.MissingBootedServiceBinding;
    try std.testing.expectEqual(service_record.owner, task.owner);
    try std.testing.expectEqual(task_runtime.ComponentClass.service_component, task.component_class);
    try std.testing.expect(task.zero_ambient_authority);
    try std.testing.expect(task.local_only);
    try std.testing.expect(task.runsAsUserspaceProcess());
    try std.testing.expect(task.hasLoadedExecutable());
    try std.testing.expect(task.launch.signed);
    try std.testing.expectEqualStrings(image.bundle_id, task.launchBundleIdSlice());

    const endpoint_capability = capability_table.query(connection.endpoint_capability_id) orelse return error.MissingBootedServiceCapability;
    try std.testing.expectEqual(capability.CapabilityTargetKind.endpoint, endpoint_capability.target.kind);
    try std.testing.expectEqual(connection.endpoint_id, endpoint_capability.target.id);
    try std.testing.expectEqual(@as(?u64, task.id), endpoint_capability.scope.task_id);
    try std.testing.expect(endpoint_capability.scope.local_only);
    try std.testing.expect(endpoint_capability.rights.has(.endpoint_connect));
    try std.testing.expect(endpoint_capability.rights.has(.endpoint_send));
    try std.testing.expect(endpoint_capability.rights.has(.endpoint_recv));

    return .{
        .service_id = service_record.id,
        .owner_task_id = task.id,
        .endpoint_id = connection.endpoint_id,
        .endpoint_capability_id = connection.endpoint_capability_id,
    };
}

fn expectRootKernelCallerDenied(
    kernel_port: *component_port.KernelPort,
    endpoint_capability_id: u64,
    owner_task_id: u64,
    tick: u64,
) !void {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    const request = component_port.EndpointCreateRequest{
        .header = component_port.makeHeader(.endpoint_create, tick, 0),
        .authority_capability_id = endpoint_capability_id,
        .owner_task_id = owner_task_id,
        .label = "kernel.data-plane.export",
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    };
    const result = syscall_surface.dispatch(
        kernel_port,
        0,
        tick,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointCreateResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.denied, result.status);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, result.denial_reason);
}

fn proveBootedSyncServicePath(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    sync_record: *const @import("supervisor.zig").ServiceRecord,
    sync_task: *task_runtime.TaskRecord,
    network_service_task: *task_runtime.TaskRecord,
    storage: *@import("../storage/storage_service.zig").Service,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    const sync_owner = sync_record.owner;
    const peer_owner = principal.PrincipalId{ .kind = .service, .serial = 7_008 };
    const overlay_relay_owner = principal.PrincipalId{ .kind = .service, .serial = 7_009 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 7_001 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 7_002 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 7_003 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 7_004 };
    const storage_signer = signer("service-path-storage", 0x61);
    const user_signer = signer("service-path-user", 0x62);
    const laptop_signer = signer("service-path-laptop", 0x63);
    const tablet_signer = signer("service-path-tablet", 0x64);
    const contract_signer = signer("service-path-contract", 0x65);

    var sync_instance = try sync_service.Service.initWithStorage(
        sync_record.id,
        sync_task.id,
        sync_owner,
        storage,
        session_manager.system().syncResidentStatePtr(),
    );
    const authority = try capability_table.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = sync_instance.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .endpoint_create = true,
            .endpoint_send = true,
            .endpoint_recv = true,
        } },
        .scope = .{
            .task_id = sync_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 100,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(sync_task.id, authority.id);

    var sync_port = sync_service.SyncPort.init(&sync_instance, capability_table);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync_task.id,
        .principal = sync_owner,
        .capability_id = authority.id,
        .now_ticks = 101,
    };
    const peer_task = try createBootedServiceTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        peer_owner,
        7_008,
        "sync-peer-service",
        "zigos.system.sync-service.peer",
        111,
    );
    runtime.allowHostPointerSyscallsForTask(sync_task.id);
    runtime.allowHostPointerSyscallsForTask(peer_task.task_id);
    try std.testing.expect(runtime.processSeparated(sync_task.id, peer_task.task_id));

    var peer_resident = sync_service.ResidentState{};
    var peer_instance = try sync_service.Service.initWithStorage(
        sync_record.id + 10_000,
        peer_task.task_id,
        peer_owner,
        storage,
        &peer_resident,
    );
    const peer_authority_capability = try capability_table.mintBootRoot(.{
        .holder = peer_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = peer_instance.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .endpoint_create = true,
            .endpoint_send = true,
            .endpoint_recv = true,
        } },
        .scope = .{
            .task_id = peer_task.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 101,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(peer_task.task_id, peer_authority_capability.id);
    var peer_port = sync_service.SyncPort.init(&peer_instance, capability_table);
    const peer_authority = sync_service.AuthorityContext{
        .task_id = peer_task.task_id,
        .principal = peer_owner,
        .capability_id = peer_authority_capability.id,
        .now_ticks = 112,
    };

    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_000),
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v1", 101),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_000),
        .object_type = .document,
        .payload = "notes-v2",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v2", 102),
        .parent_version_id = notes_v1.version_id,
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_001),
        .object_type = .media_asset,
        .payload = "cover-bytes",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "cover-bytes", 103),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_002),
        .object_type = .secret,
        .payload = "enc:service-path-secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:service-path-secret", 104),
    });
    const db_events = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_003),
        .object_type = .event_stream,
        .payload = "txn:service-path-event",
        .metadata = try object_store.signMetadata(storage_signer, "db-events", "application/zigos-event-stream", .event_stream, "txn:service-path-event", 105),
    });

    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "service-path-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes_v2.object_id, notes_v2.version_id, .document);
    try storage.stagePut(workspace_record.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    try storage.stagePut(workspace_record.id, "secrets/token", secret.object_id, secret.version_id, .secret);
    try storage.stagePut(workspace_record.id, "databases/app.notes.db/events", db_events.object_id, db_events.version_id, .event_stream);
    _ = try storage.commit(workspace_record.id, 105);
    const workspace_id = workspace_record.id.raw();

    _ = try sync_port.ensureUserRoot(sync_authority, user, "owner", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, laptop, "laptop", user_signer, laptop_signer, 106);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, tablet, "tablet", user_signer, tablet_signer, 107);
    _ = try peer_port.ensureUserRoot(peer_authority, user, "owner", user_signer);
    _ = try peer_port.enrollTrustedDevice(peer_authority, user, laptop, "laptop", user_signer, laptop_signer, 112);
    _ = try peer_port.enrollTrustedDevice(peer_authority, user, tablet, "tablet", user_signer, tablet_signer, 113);
    const local_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "local",
        .mode = .local_network,
    });
    const relay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.service-path.zigos",
    });
    const overlay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.service-path.notes",
    });
    const discovery_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const network_attestation_root = signer("booted-network-attestation-root", 0x7B);
    var network_attestation_provider = attestation_service.FakeTpmRootProvider.init(network_attestation_root);
    const network_attestation_identity = try network_attestation_provider.publicIdentity();
    const peer_boot = try verifiedBootedNetworkPeer(7_050);
    var peer_attestation = attestation_service.Service.init(tablet);
    try peer_attestation.provisionRootProvider(network_attestation_provider.provider());
    const native_identity_statement = try peer_attestation.attestWithProvisionedRoot(
        peer_boot,
        "overlay.service-path.notes",
        "native-net-1",
        true,
    );
    try std.testing.expect(attestation_service.Service.verifyForBoot(native_identity_statement, .{
        .boot = &peer_boot,
        .remote_party = "overlay.service-path.notes",
        .nonce = "native-net-1",
        .user_visible = true,
        .key_origin = .tpm,
        .attestation_root = network_attestation_identity,
    }));
    const native_identity_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "native-service-identity",
        .mode = .named_service_identity,
        .target = "overlay.service-path.notes",
        .require_remote_attestation = true,
        .pinned_root_digest = native_identity_statement.root_digest,
    });
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/", "secrets/", "databases/" },
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.service-path.zigos",
    });
    _ = try sync_port.configureOverlay(sync_authority, workspace_id, laptop, "overlay.service-path.notes", true);
    _ = try sync_port.publishPrivateService(sync_authority, workspace_id, "notes.remote");
    const peer_local_policy = try peer_port.createNetworkPolicy(peer_authority, .{
        .owner = peer_owner,
        .workspace_id = workspace_id,
        .label = "peer-local",
        .mode = .local_network,
    });
    _ = try peer_port.configureWorkspacePolicy(peer_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/", "secrets/", "databases/" },
        .device_to_device_policy_id = peer_local_policy.id,
    });
    const source_database_contract = try sync_port.registerDatabaseContract(sync_authority, workspace_id, "app.notes.db", "notes-db", contract_signer);
    const peer_database_contract = try peer_port.registerDatabaseContract(peer_authority, workspace_id, "app.notes.db", "notes-db", contract_signer);
    try std.testing.expectEqual(source_database_contract.id, peer_database_contract.id);

    const source_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        sync_task.id,
        authority.id,
        sync_task.id,
        "zigos.sync.source",
        .{ .local_only = true, .service_port = true },
        114,
    );
    const peer_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        peer_task.task_id,
        peer_authority_capability.id,
        peer_task.task_id,
        "zigos.sync.peer",
        .{ .local_only = true, .service_port = true },
        115,
    );
    _ = try expectEndpointConnect(
        kernel_port,
        sync_task.id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        peer_endpoint.endpoint.endpoint_id,
        116,
    );
    try proveBootedIdentityFirstNativeNetworkStack(
        runtime,
        capability_table,
        &sync_instance,
        network_service_task,
        native_identity_policy.id,
        discovery_policy.id,
        native_identity_statement.root_digest,
        laptop,
        tablet,
    );
    const overlay_relay_task = try createBootedServiceTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        overlay_relay_owner,
        7_009,
        "overlay-relay-service",
        "zigos.system.overlay-relay",
        122,
    );
    try std.testing.expect(runtime.processSeparated(sync_task.id, overlay_relay_task.task_id));
    try std.testing.expect(runtime.processSeparated(peer_task.task_id, overlay_relay_task.task_id));
    var booted_relay_service = try sync_service.transport_harness.BootedOverlayRelayService.init(
        sync_record.id + 20_000,
        overlay_relay_task.task_id,
        "relay.service-path.zigos",
    );
    const relay_capability = try capability_table.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = relay_policy.id },
        .rights = .{ .network_policy = .{
            .network_remote = true,
        } },
        .scope = .{
            .task_id = sync_task.id,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 123,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(sync_task.id, relay_capability.id);

    try sync_port.setReplicaVersion(sync_authority, workspace_id, tablet, "documents/notes.md", notes_v1.object_id, cover.version_id);
    const summary = try sync_port.replicateWorkspace(sync_authority, storage, workspace_id, laptop, tablet, .device_to_device);
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_device_to_device);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expect(summary.remote_access_ready);
    try std.testing.expectEqual(@as(usize, 4), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.snapshot_count);
    try std.testing.expectEqual(@as(usize, 1), summary.secret_transfer_count);
    try std.testing.expectEqual(@as(usize, 1), summary.transactional_count);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expectEqual(summary.transport_frame_count, summary.encrypted_transport_count);
    try std.testing.expect(sync_instance.findConflict(workspace_id, tablet, "documents/notes.md") != null);

    var exchange_tick: u64 = 124;
    try exchangeSyncFrameOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        sync_instance.latestTransportFrameForPath(workspace_id, tablet, "documents/notes.md").?,
        &exchange_tick,
    );
    try exchangeSyncFrameOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        sync_instance.latestTransportFrameForPath(workspace_id, tablet, "assets/cover.jpg").?,
        &exchange_tick,
    );
    const secret_frame = sync_instance.latestTransportFrameForPath(workspace_id, tablet, "secrets/token").?;
    try std.testing.expectEqual(sync_service.SyncSemantic.secure_transfer, secret_frame.semantic);
    try exchangeSyncFrameOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        secret_frame,
        &exchange_tick,
    );
    const db_frame = sync_instance.latestTransportFrameForPath(workspace_id, tablet, "databases/app.notes.db/events").?;
    try std.testing.expectEqual(sync_service.SyncSemantic.transactional_contract, db_frame.semantic);
    try exchangeSyncFrameOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        db_frame,
        &exchange_tick,
    );
    try std.testing.expectEqual(@as(usize, 4), peer_instance.transportFrameCountFor(workspace_id, tablet));
    try std.testing.expectEqual(notes_v2.version_id.raw(), peer_instance.replicaVersion(workspace_id, tablet, "documents/notes.md").?);
    try std.testing.expectEqual(cover.version_id.raw(), peer_instance.replicaVersion(workspace_id, tablet, "assets/cover.jpg").?);
    try std.testing.expectEqual(secret.version_id.raw(), peer_instance.replicaVersion(workspace_id, tablet, "secrets/token").?);
    try std.testing.expectEqual(db_events.version_id.raw(), peer_instance.replicaVersion(workspace_id, tablet, "databases/app.notes.db/events").?);

    var wrong_semantic_frame = sync_instance.latestTransportFrameForPath(workspace_id, tablet, "documents/notes.md").?;
    wrong_semantic_frame.semantic = .chunked_snapshot;
    try expectSyncFrameRejectedOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        wrong_semantic_frame,
        error.SyncSemanticMismatch,
        &exchange_tick,
    );
    var plaintext_secret_frame = secret_frame;
    plaintext_secret_frame.encrypted = false;
    try expectSyncFrameRejectedOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        plaintext_secret_frame,
        error.TransportDenied,
        &exchange_tick,
    );
    var revoked_target_frame = sync_instance.latestTransportFrameForPath(workspace_id, tablet, "assets/cover.jpg").?;
    revoked_target_frame.target_device = phone;
    try expectSyncFrameRejectedOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        revoked_target_frame,
        error.DeviceNotTrusted,
        &exchange_tick,
    );
    try std.testing.expectEqual(@as(usize, 4), peer_instance.transportFrameCountFor(workspace_id, tablet));

    const relay_session = try sync_port.openOverlaySession(
        sync_authority,
        workspace_id,
        laptop,
        tablet,
        .private_service,
        .relay_assisted,
        "notes.remote",
        140,
    );
    try std.testing.expect(relay_session.encrypted);
    try std.testing.expect(relay_session.relay_encrypted);
    try std.testing.expectEqualStrings("notes.remote", relay_session.privateServiceSlice());
    try std.testing.expect(!(try sync_port.evaluateNetworkPolicy(sync_authority, relay_policy.id, .{ .domain = "other.service-path.zigos" })).allowed);
    try std.testing.expectError(error.EgressDenied, sync_port.sendOverlayRelayFrameViaService(
        sync_authority,
        capability_table,
        &booted_relay_service,
        .{
            .workspace_id = workspace_id,
            .from_device = laptop,
            .to_device = tablet,
            .usage = .private_service,
            .private_service_label = "notes.remote",
            .relay_capability_id = relay_capability.id + 1,
            .payload = "remote-open",
            .signer = laptop_signer,
            .tick = 141,
        },
    ));
    try std.testing.expectEqual(@as(usize, 0), booted_relay_service.accepted_packets);

    const relay_exchange = try sync_port.sendOverlayRelayFrameViaService(
        sync_authority,
        capability_table,
        &booted_relay_service,
        .{
            .workspace_id = workspace_id,
            .from_device = laptop,
            .to_device = tablet,
            .usage = .private_service,
            .private_service_label = "notes.remote",
            .relay_capability_id = relay_capability.id,
            .payload = "remote-open",
            .signer = laptop_signer,
            .tick = 142,
        },
    );
    try std.testing.expect(relay_exchange.encrypted);
    try std.testing.expect(relay_exchange.relay_encrypted);
    try std.testing.expect(relay_exchange.remote_access);
    try std.testing.expect(relay_exchange.egress_allowed);
    try std.testing.expect(relay_exchange.delivered);
    try std.testing.expectEqual(@as(usize, "remote-open".len), relay_exchange.delivered_len);
    try std.testing.expectEqual(sync_service.OverlaySessionUse.private_service, relay_exchange.usage);
    try std.testing.expectEqualStrings("overlay.service-path.notes", relay_exchange.serviceIdentitySlice());
    try std.testing.expectEqualStrings("relay.service-path.zigos", relay_exchange.relayDomainSlice());
    try std.testing.expectEqualStrings("notes.remote", relay_exchange.privateServiceSlice());
    try std.testing.expectEqual(@as(usize, 1), booted_relay_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay_service.delivered_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay_service.relay.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay_service.relay.delivered_packets);

    try std.testing.expect(try sync_port.transferSecretObject(sync_authority, storage, workspace_id, secret.object_id, laptop, tablet, .device_to_device));
    try std.testing.expect(try sync_port.replicateDatabaseContract(sync_authority, source_database_contract.id, workspace_id, laptop, tablet, .relay_assisted));
    try std.testing.expectError(sync_service.Error.DeviceNotTrusted, sync_port.replicateWorkspace(sync_authority, storage, workspace_id, laptop, phone, .device_to_device));

    var restarted_source_resident = sync_service.ResidentState{};
    var restarted_source = try sync_service.Service.initWithStorage(
        sync_record.id,
        sync_task.id,
        sync_owner,
        storage,
        &restarted_source_resident,
    );
    var restarted_peer_resident = sync_service.ResidentState{};
    var restarted_peer = try sync_service.Service.initWithStorage(
        peer_instance.service_id,
        peer_task.task_id,
        peer_owner,
        storage,
        &restarted_peer_resident,
    );
    try std.testing.expect(restarted_source.loaded_existing_state);
    try std.testing.expect(restarted_peer.loaded_existing_state);
    try std.testing.expectEqual(notes_v2.version_id.raw(), restarted_source.replicaVersion(workspace_id, tablet, "documents/notes.md").?);
    try std.testing.expectEqual(notes_v2.version_id.raw(), restarted_peer.replicaVersion(workspace_id, tablet, "documents/notes.md").?);
    try std.testing.expectEqual(cover.version_id.raw(), restarted_peer.replicaVersion(workspace_id, tablet, "assets/cover.jpg").?);
    try std.testing.expectEqual(secret.version_id.raw(), restarted_peer.replicaVersion(workspace_id, tablet, "secrets/token").?);
    try std.testing.expectEqual(db_events.version_id.raw(), restarted_peer.replicaVersion(workspace_id, tablet, "databases/app.notes.db/events").?);
    var restarted_peer_port = sync_service.SyncPort.init(&restarted_peer, capability_table);
    const clean_peer_summary = try restarted_peer_port.replicateWorkspace(peer_authority, storage, workspace_id, laptop, tablet, .device_to_device);
    try std.testing.expectEqual(@as(usize, 0), clean_peer_summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 0), clean_peer_summary.transport_frame_count);
}

fn proveBootedIdentityFirstNativeNetworkStack(
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    sync: *sync_service.Service,
    network_service_task: *task_runtime.TaskRecord,
    policy_id: u64,
    discovery_policy_id: u64,
    peer_root_digest: [32]u8,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
) !void {
    try std.testing.expect(runtime.processSeparated(sync.task_id, network_service_task.id));
    const policy_capability = try capability_table.mintBootRoot(.{
        .holder = network_service_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = policy_id },
        .rights = .{ .network_policy = .{
            .network_remote = true,
        } },
        .scope = .{
            .task_id = network_service_task.id,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 117,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(network_service_task.id, policy_capability.id);

    const Harness = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;

        fn send(frame: []const u8) void {
            send_count += 1;
            last_frame_len = frame.len;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0x5A, 0x47, 0, 0, 1 };
        }
    };
    Harness.send_count = 0;
    Harness.last_frame_len = 0;
    network_driver_task.reset();
    defer network_driver_task.reset();

    const device = network_driver_task.NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(network_driver_task.activateDevice(&device, network_service_task.id));

    var broker = sync.egressBroker(capability_table);
    var stack = network_driver_task.NativeNetworkStack.init();
    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = policy_capability.id,
        .policy_id = policy_id,
        .evidence = .{ .destination = .{ .service_identity = "overlay.service-path.notes" } },
        .now_ticks = 118,
    }, source_device, target_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.attestation_required, stack.last_denial_reason);

    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = sync.task_id,
        .principal_id = network_service_task.owner,
        .capability_id = policy_capability.id,
        .policy_id = policy_id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.service-path.notes" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = peer_root_digest,
        },
        .now_ticks = 119,
    }, source_device, target_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.scope_violation, stack.last_denial_reason);

    var wrong_root_digest = peer_root_digest;
    wrong_root_digest[0] ^= 0xFF;
    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = policy_capability.id,
        .policy_id = policy_id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.service-path.notes" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = wrong_root_digest,
        },
        .now_ticks = 120,
    }, source_device, target_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.identity_pin_mismatch, stack.last_denial_reason);
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    const connection = try stack.openServiceIdentity(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = policy_capability.id,
        .policy_id = policy_id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.service-path.notes" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = peer_root_digest,
        },
        .now_ticks = 121,
    }, source_device, target_device);
    try std.testing.expect(connection.attestation_required);
    try std.testing.expect(connection.identity_pinned);
    try std.testing.expectEqualStrings("overlay.service-path.notes", connection.serviceIdentitySlice());

    const frame = try stack.sendServiceIdentityFrame(&connection, "native service identity payload");
    try std.testing.expect(frame.encrypted);
    try std.testing.expect(frame.egress_allowed);
    try std.testing.expect(frame.attested);
    try std.testing.expect(frame.identity_pinned);
    try std.testing.expect(!std.mem.eql(u8, frame.ciphertextSlice(), "native service identity payload"));
    try std.testing.expectEqual(@as(usize, 4), stack.attempted_connections);
    try std.testing.expectEqual(@as(usize, 3), stack.denied_before_transmit);
    try std.testing.expectEqual(@as(usize, 1), stack.opened_connections);
    try std.testing.expectEqual(@as(usize, 1), stack.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
    try std.testing.expect(Harness.last_frame_len > "native service identity payload".len);

    const discovery_capability = try capability_table.mintBootRoot(.{
        .holder = network_service_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = discovery_policy_id },
        .rights = .{ .network_policy = .{
            .network_local = true,
        } },
        .scope = .{
            .task_id = network_service_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 122,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(network_service_task.id, discovery_capability.id);

    var discovery_stack = network_driver_task.NativeNetworkStack.init();
    try std.testing.expectError(error.EgressDenied, discovery_stack.openLocalDiscovery(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy_id,
        .evidence = .{ .destination = .local_network },
        .now_ticks = 122,
    }, source_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.destination_mismatch, discovery_stack.last_denial_reason);

    try std.testing.expectError(error.EgressDenied, discovery_stack.openLocalDiscovery(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy_id,
        .evidence = .{ .destination = .{ .discovery_class = "camera" } },
        .now_ticks = 123,
    }, source_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.destination_mismatch, discovery_stack.last_denial_reason);

    const discovery_connection = try discovery_stack.openLocalDiscovery(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy_id,
        .evidence = .{ .destination = .{ .discovery_class = "printer" } },
        .now_ticks = 124,
    }, source_device);
    try std.testing.expect(discovery_connection.scoped_discovery);
    try std.testing.expectEqualStrings("printer", discovery_connection.discoveryClassSlice());

    const discovery_frame = try discovery_stack.sendLocalDiscoveryProbe(&discovery_connection, "discover-printer");
    try std.testing.expect(discovery_frame.encrypted);
    try std.testing.expect(discovery_frame.egress_allowed);
    try std.testing.expect(discovery_frame.scoped_discovery);
    try std.testing.expectEqualStrings("printer", discovery_frame.discoveryClassSlice());
    try std.testing.expect(!std.mem.eql(u8, discovery_frame.ciphertextSlice(), "discover-printer"));
    try std.testing.expectEqual(@as(usize, 2), Harness.send_count);
}

fn verifiedBootedNetworkPeer(generation: u64) !measured_boot.BootRecord {
    var recorder = measured_boot.Recorder.init();
    var artifact_manifest = measured_boot.ArtifactManifest.init(generation);
    recorder.begin(generation);
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos", "kernel=network-peer");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .base_image, "base-network-peer", "image=network-peer");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .critical_service, "sync", "healthy");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .policy, "identity-first", "strict");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .driver_set, "signed-network-driver", "net");
    var boot = recorder.finalize();
    try measured_boot.verifyBootRecordAgainstManifest(&boot, &artifact_manifest, .bootloader_provided);
    return boot;
}

fn addMeasuredNetworkArtifact(
    recorder: *measured_boot.Recorder,
    artifact_manifest: *measured_boot.ArtifactManifest,
    kind: measured_boot.MeasurementKind,
    label: []const u8,
    payload: []const u8,
) !void {
    try recorder.add(kind, label, payload);
    try artifact_manifest.add(kind, label, payload);
}

fn proveBootedCompositorServicePath(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    storage: *storage_service.Service,
    runtime_service: *task_runtime_service.Service,
    compositor_record: *const @import("supervisor.zig").ServiceRecord,
    compositor_task: *task_runtime.TaskRecord,
    session: *compositor_session.Session,
) !void {
    session.reset();
    runtime.allowHostPointerSyscallsForTask(compositor_task.id);

    const app_owner = principal.PrincipalId{ .kind = .app, .serial = 82_001 };
    // prod-readiness: model-only synthetic-userspace-image; replace with a generated fixture before launch provenance graduation.
    const app_image = task_runtime.syntheticUserspaceImage("trip-coordinator", "app.trip");
    var ux_controller = native_ux.Controller.init();
    const app_task = try ux_controller.startTask(runtime, .{
        .owner = app_owner,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_200,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 4096,
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
        defer session.restore(shell_snapshot);
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
        defer session.restore(permission_snapshot);
        try proveBootedRenderedPermissionReviewSurface(runtime, &service, session, app_task.id, capability_table);
    }

    const headless_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 82_099 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 1,
            .shared_memory_bytes = 512,
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
    var workspace_needle_buffer: [32]u8 = undefined;
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
    var object_card_buffer: [512]u8 = undefined;
    var network_card_buffer: [512]u8 = undefined;
    var object_decision_buffer: [256]u8 = undefined;
    var network_decision_buffer: [256]u8 = undefined;
    const object_card = try compositor_session.renderReviewItemToBuffer(&object_card_buffer, object_review_response.window_id, object_item);
    try expectContains(object_card, "why=Trip needs access to local task objects");
    try expectContains(object_card, "object_scope=ws:trip");
    try expectContains(object_card, "network_path=none");
    try expectContains(object_card, "requested_local_only=yes");
    try expectContains(object_card, "requested_lease=400");
    const network_card = try compositor_session.renderReviewItemToBuffer(&network_card_buffer, network_review_response.window_id, network_item);
    try expectContains(network_card, "why=Trip needs the named network path");
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

    var render_buffer: [768]u8 = undefined;
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

    var export_buffer: [1024]u8 = undefined;
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
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .publisher = "zigos.local",
        .requested_permissions = &permissions,
        .signature = .{
            .format = "ed25519",
            .signer = "booted-trip-review",
        },
    };
    var grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    var surface = permission_review_service.RenderedReviewSurface.init(&review_service, app_task_id, bundle, 157, &display);
    surface.bindLedger(&ledger);

    try surface.begin();
    try expectDisplayFrameContains(&display, "active_type=app_panel");
    try expectDisplayFrameContains(&display, "permission_scope object=ws:trip network=none local=yes lease=400");
    try expectDisplayFrameContains(&display, "control=allow_local_requested_lease window=1 kind=object_access resource=ws:trip lease=400");

    try surface.click(.allow_local_requested_lease);
    try expectDisplayFrameContains(&display, "permission_decision kind=object_access resource=ws:trip decision=allow");
    try expectDisplayFrameContains(&display, "permission_scope object=none network=net:trip local=no lease=80");
    try expectDisplayFrameContains(&display, "control=deny window=1 kind=network_egress resource=net:trip");

    try surface.click(.deny);
    const grants = try surface.finish(&grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(manifest.PermissionKind.object_access, grants[0].kind);
    try std.testing.expectEqual(@as(?u64, 557), grants[0].expires_at_ticks);
    try expectDisplayFrameContains(&display, "permission_decision kind=network_egress resource=net:trip decision=deny");

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

    try std.testing.expectEqual(@as(usize, 1), summary.granted_count);
    try std.testing.expectEqual(@as(usize, 1), summary.denied_count);
    try std.testing.expectEqual(@as(usize, 0), summary.required_denials);
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
    var buffer: [512]u8 = undefined;
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
    if (!display.containsText(needle)) return error.ExpectedDisplaySubstringMissing;
}

fn expectDisplayFrameContains(display: *const compositor_display.Framebuffer, needle: []const u8) !void {
    if (!display.containsText(needle)) return error.ExpectedDisplaySubstringMissing;
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return error.ExpectedSubstringMissing;
}

fn proveBootedPostActivationHealthChecks(
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    supervisor: *supervisor_mod.Supervisor,
    storage: *storage_service.Service,
    sync_task: *task_runtime.TaskRecord,
    compositor_session_ptr: *compositor_session.Session,
) !void {
    const owner = principal.PrincipalId{ .kind = .service, .serial = 81_200 };
    const state_signer = signer("booted-health-state", 0x72);
    const image_signer = signer("booted-health-image", 0x73);
    const object_signer = signer("booted-health-storage", 0x74);
    const workspace_id = try seedBootedHealthStorageProbe(storage, owner, object_signer);

    const sync_record = supervisor.findByClass(.sync_replication) orelse return error.MissingBootedHealthService;
    var sync_instance = try sync_service.Service.initWithStorage(
        sync_record.id,
        sync_task.id,
        sync_record.owner,
        storage,
        session_manager.system().syncResidentStatePtr(),
    );
    const network_probe = try seedBootedHealthNetworkProbe(&sync_instance, capability_table, workspace_id, 600);

    const policy_service_id = (supervisor.findByClass(.policy_mediation) orelse return error.MissingBootedHealthService).id;
    const package_service_id = (supervisor.findByClass(.package_install_update) orelse return error.MissingBootedHealthService).id;
    const sync_service_id = sync_record.id;
    const network_service_id = (supervisor.findByClass(.network_stack) orelse return error.MissingBootedHealthService).id;
    const ui_service_id = (supervisor.findByClass(.compositor_ui_session) orelse return error.MissingBootedHealthService).id;
    const core_service_ids = [_]u64{ policy_service_id, package_service_id, sync_service_id };
    const healthy_request = update_health.CheckRequest{
        .core_service_ids = core_service_ids[0..],
        .storage_workspace_id = workspace_id,
        .storage_probe_path = "health/state.txt",
        .network_service_id = network_service_id,
        .ui_service_id = ui_service_id,
        .network_probe = network_probe,
        .ui_probe = .{ .session = compositor_session_ptr },
        .require_service_path_probes = true,
    };

    var manager = try immutable_base.Manager.init(storage, owner, state_signer);
    var ledger = event_ledger.Ledger.init();
    _ = try manager.stageImage(0, "booted-stable-a", "kernel=booted-v1", image_signer, 610);
    try manager.beginActivation(0, 611);
    try update_health.recordBootSuccess(&manager, 612);
    const first_activation = try update_health.validatePendingActivation(&manager, supervisor, storage, healthy_request, &ledger, 613);
    try std.testing.expect(!first_activation.activation.rolled_back);
    try std.testing.expectEqual(@as(?usize, 0), first_activation.activation.active_slot);

    _ = try manager.stageImage(1, "booted-stable-b", "kernel=booted-v2", image_signer, 614);

    const FailureCase = struct {
        expected: immutable_base.HealthFailure,
        request: update_health.CheckRequest,
        crash_service_id: ?u64 = null,
    };
    const cases = [_]FailureCase{
        .{
            .expected = .boot,
            .request = healthy_request,
        },
        .{
            .expected = .core_service,
            .request = healthy_request,
            .crash_service_id = sync_service_id,
        },
        .{
            .expected = .storage,
            .request = .{
                .core_service_ids = core_service_ids[0..],
                .storage_workspace_id = workspace_id,
                .storage_probe_path = "health/missing.txt",
                .network_service_id = network_service_id,
                .ui_service_id = ui_service_id,
                .network_probe = network_probe,
                .ui_probe = .{ .session = compositor_session_ptr },
                .require_service_path_probes = true,
            },
        },
        .{
            .expected = .network,
            .request = .{
                .core_service_ids = core_service_ids[0..],
                .storage_workspace_id = workspace_id,
                .storage_probe_path = "health/state.txt",
                .network_service_id = network_service_id,
                .ui_service_id = ui_service_id,
                .ui_probe = .{ .session = compositor_session_ptr },
                .require_service_path_probes = true,
            },
        },
        .{
            .expected = .ui,
            .request = .{
                .core_service_ids = core_service_ids[0..],
                .storage_workspace_id = workspace_id,
                .storage_probe_path = "health/state.txt",
                .network_service_id = network_service_id,
                .ui_service_id = ui_service_id,
                .network_probe = network_probe,
                .require_service_path_probes = true,
            },
        },
    };

    for (cases, 0..) |case, index| {
        const tick_base = 620 + @as(u64, @intCast(index * 10));
        try manager.beginActivation(1, tick_base);
        if (case.expected != .boot) try update_health.recordBootSuccess(&manager, tick_base + 1);
        if (case.crash_service_id) |service_id| {
            try std.testing.expect(supervisor.recordCrash(service_id, tick_base + 2, 0xB007_0000 + @as(u32, @intCast(index))));
        }
        const result = try update_health.validatePendingActivation(&manager, supervisor, storage, case.request, &ledger, tick_base + 3);
        try std.testing.expect(result.activation.rolled_back);
        try std.testing.expectEqual(case.expected, result.activation.failure);
        try std.testing.expectEqual(@as(?usize, 0), result.activation.active_slot);
        if (case.crash_service_id) |service_id| {
            try std.testing.expect(supervisor.markHealthy(service_id, tick_base + 4));
        }
    }

    try manager.beginActivation(1, 680);
    try update_health.recordBootSuccess(&manager, 681);
    const success = try update_health.validatePendingActivation(&manager, supervisor, storage, healthy_request, &ledger, 682);
    try std.testing.expect(!success.activation.rolled_back);
    try std.testing.expectEqual(@as(?usize, 1), success.activation.active_slot);
    try std.testing.expectEqual(@as(u64, cases.len), success.activation.rollback_generation);
    try std.testing.expect(manager.verifyActiveImage());

    var export_buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    for (cases) |case| {
        var needle_buffer: [48]u8 = undefined;
        const needle = try std.fmt.bufPrint(&needle_buffer, "failure={s}", .{@tagName(case.expected)});
        try std.testing.expect(std.mem.indexOf(u8, exported, needle) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=none") != null);
    _ = runtime;
}

fn seedBootedHealthStorageProbe(
    storage: *storage_service.Service,
    owner: principal.PrincipalId,
    signer_identity: signing.SignerIdentity,
) !u64 {
    const record = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(81_200),
        .object_type = .document,
        .payload = "booted-health-ok",
        .metadata = try object_store.signMetadata(
            signer_identity,
            "booted-health-state",
            "text/plain",
            .document,
            "booted-health-ok",
            590,
        ),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = owner,
        .label = "booted-health-checks",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "health/state.txt", record.object_id, record.version_id, .document);
    _ = try storage.commit(workspace_record.id, 591);
    return workspace_record.id.raw();
}

fn seedBootedHealthNetworkProbe(
    sync: *sync_service.Service,
    capability_table: *capability.CapabilityTable,
    workspace_id: u64,
    tick_base: u64,
) !update_health.NetworkProbe {
    const user = principal.PrincipalId{ .kind = .user, .serial = 81_201 };
    const source_device = principal.PrincipalId{ .kind = .device, .serial = 81_202 };
    const target_device = principal.PrincipalId{ .kind = .device, .serial = 81_203 };
    const user_signer = signer("booted-health-user", 0x75);
    const source_signer = signer("booted-health-source", 0x76);
    const target_signer = signer("booted-health-target", 0x77);

    const authority_capability = try capability_table.mintBootRoot(.{
        .holder = sync.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = sync.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = sync.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = tick_base,
            .expires_at_ticks = tick_base + 1_000,
        },
    });
    var port = sync_service.SyncPort.init(sync, capability_table);
    const authority = sync_service.AuthorityContext{
        .task_id = sync.task_id,
        .principal = sync.owner,
        .capability_id = authority_capability.id,
        .now_ticks = tick_base,
    };

    _ = try port.ensureUserRoot(authority, user, "booted-health", user_signer);
    _ = try port.enrollTrustedDevice(authority, user, source_device, "source", user_signer, source_signer, tick_base + 1);
    _ = try port.enrollTrustedDevice(authority, user, target_device, "target", user_signer, target_signer, tick_base + 2);

    const local_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "booted-health-local",
        .mode = .local_network,
    });
    const overlay_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "booted-health-overlay",
        .mode = .named_service_identity,
        .target = "overlay.booted.health",
    });
    _ = try port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
    });
    _ = try port.configureOverlay(authority, workspace_id, source_device, "overlay.booted.health", true);

    return .{
        .sync = sync,
        .capability_table = capability_table,
        .authority = authority,
        .workspace_id = workspace_id,
        .source_device = source_device,
        .target_device = target_device,
        .tick = tick_base + 3,
    };
}

fn proveBootedSchedulerTelemetryProvider(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    scheduler: *userspace_scheduler.Scheduler,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    parkBootedSchedulerTasks(runtime, scheduler);

    const provider_owner = principal.PrincipalId{ .kind = .service, .serial = 81_000 };
    const provider_task = try createBootedServiceTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        provider_owner,
        81_000,
        "platform-resource-provider",
        "zigos.system.resource-telemetry",
        700,
    );
    // prod-readiness: model-only synthetic-userspace-image; replace with a generated fixture before launch provenance graduation.
    const foreground_image = task_runtime.syntheticUserspaceImage("booted-telemetry-ui", "app.service-path.telemetry-ui");
    const foreground = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 81_001 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 1,
            .shared_memory_bytes = 4096,
            .resource_class = .foreground_interactive,
        },
        .ui_surface_id = 44,
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 81_001,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = "app.service-path.telemetry-ui",
        },
        .userspace_image = &foreground_image,
    });
    try std.testing.expect(runtime.processSeparated(provider_task.task_id, foreground.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(foreground.id, .{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = 4096,
    }, false));

    var provider = try platform_policy_signals.FreestandingPlatformTelemetryProvider.initForBootedService(
        44,
        provider_task.task_id,
        701,
        platform_policy_signals.collectLiveCounters(runtime, scheduler, .{
            .thermal_milli_celsius = 91_000,
            .battery_percent = 15,
            .battery_charging = false,
            .gpu_driver_online = true,
            .npu_driver_online = false,
            .media_driver_online = true,
        }),
    );
    try std.testing.expectError(error.TelemetryProviderUnauthorized, provider.observeLive(
        session_task_id,
        701,
        platform_policy_signals.collectLiveCounters(runtime, scheduler, .{}),
    ));
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expectEqual(accelerator_scheduler.TelemetrySource.hardware, scheduler.resource_telemetry_source);
    try std.testing.expectEqual(@as(u64, 701), scheduler.resource_telemetry_observed_tick);
    try std.testing.expectEqual(accelerator_scheduler.ThermalPressure.critical, scheduler.resource_state.thermal_pressure);
    try std.testing.expect(scheduler.resource_state.battery_saver);
    try std.testing.expect(scheduler.resource_state.gpu_available);
    try std.testing.expect(!scheduler.resource_state.npu_available);
    try std.testing.expect(scheduler.resource_state.media_available);
    try std.testing.expect(scheduler.resource_state.cpu_budget_ticks > 0);
    try std.testing.expect(scheduler.resource_state.memory_bandwidth_units > 0);
    try std.testing.expectEqual(@as(u32, 1), provider.liveObservationCount());
    try std.testing.expectEqual(@as(u32, 1), provider.rejectedObservationCount());

    try std.testing.expect(!scheduler.runNext(701));
    const foreground_slot = scheduler.slots.getConst(foreground.id).?;
    try std.testing.expectEqual(@as(u64, 1), foreground_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, foreground_slot.last_dispatch_engine);
    try std.testing.expect(foreground_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, foreground_slot.last_dispatch_reason);

    // prod-readiness: model-only synthetic-userspace-image; replace with a generated fixture before launch provenance graduation.
    const media_image = task_runtime.syntheticUserspaceImage("booted-telemetry-media", "app.service-path.telemetry-media");
    const media = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 81_002 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 1,
            .shared_memory_bytes = 8192,
            .resource_class = .media_export,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 81_002,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = "app.service-path.telemetry-media",
        },
        .userspace_image = &media_image,
    });
    try std.testing.expect(runtime.processSeparated(provider_task.task_id, media.id));
    try std.testing.expect(scheduler.registerTask(media.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(media.id, .{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = 8192,
    }, true));

    const media_denials_before = scheduler.engineDenialCount(.media);
    try provider.observeLive(provider_task.task_id, 702, platform_policy_signals.collectLiveCounters(runtime, scheduler, .{
        .thermal_milli_celsius = 45_000,
        .battery_percent = 15,
        .battery_charging = false,
        .gpu_driver_online = false,
        .npu_driver_online = false,
        .media_driver_online = false,
    }));
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expectEqual(@as(u64, 702), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(scheduler.resource_state.battery_saver);
    try std.testing.expect(!scheduler.resource_state.gpu_available);
    try std.testing.expect(!scheduler.resource_state.npu_available);
    try std.testing.expect(!scheduler.resource_state.media_available);
    try std.testing.expect(!scheduler.runNext(702));
    const denied_media_slot = scheduler.slots.getConst(media.id).?;
    try std.testing.expectEqual(@as(u64, 0), denied_media_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), denied_media_slot.denied_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.accelerator_unavailable, denied_media_slot.last_dispatch_reason);
    try std.testing.expectEqual(media_denials_before + 1, scheduler.engineDenialCount(.media));
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    try provider.observeLive(provider_task.task_id, 703, platform_policy_signals.collectLiveCounters(runtime, scheduler, .{
        .thermal_milli_celsius = 45_000,
        .battery_percent = 15,
        .battery_charging = false,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
    }));
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expectEqual(@as(u64, 703), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(scheduler.resource_state.gpu_available);
    try std.testing.expect(scheduler.resource_state.npu_available);
    try std.testing.expect(scheduler.resource_state.media_available);
    try std.testing.expect(!scheduler.runNext(703));
    const dispatched_media_slot = scheduler.slots.getConst(media.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_media_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, dispatched_media_slot.last_dispatch_engine);
    try std.testing.expect(dispatched_media_slot.last_dispatch_zero_copy);
    try std.testing.expect(dispatched_media_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.battery_preserve, dispatched_media_slot.last_dispatch_reason);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u32, 3), provider.liveObservationCount());
    try std.testing.expectEqual(@as(u32, 3), provider.readCount());
}

fn parkBootedSchedulerTasks(
    runtime: *task_runtime.Runtime,
    scheduler: *userspace_scheduler.Scheduler,
) void {
    var slot_index: usize = 0;
    while (slot_index < runtime.taskSlotCapacity()) : (slot_index += 1) {
        const slot = runtime.taskSlotAtConst(slot_index);
        if (!slot.in_use) continue;
        _ = scheduler.parkTaskUntilEvent(slot.task.id);
    }
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

fn exchangeSyncFrameOverNativeEndpoint(
    kernel_port: *component_port.KernelPort,
    source_task_id: u64,
    peer_task_id: u64,
    source_endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_port: *sync_service.SyncPort,
    peer_authority: sync_service.AuthorityContext,
    storage: *const storage_service.Service,
    frame: sync_service.TransportFrame,
    tick: *u64,
) !void {
    var payload_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const payload = try encodeSyncFrame(&payload_buffer, frame);
    try expectEndpointSend(kernel_port, source_task_id, source_endpoint_capability_id, payload, tick.*);
    tick.* += 1;

    const received = try expectEndpointRecv(kernel_port, peer_task_id, peer_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received.present);

    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    const request = try decodeSyncFrame(received.payload[0..received.message.payload_len], &path_buffer);
    const accepted = try peer_port.acceptTransportFrame(peer_authority, storage, request);
    try std.testing.expect(accepted.encrypted);
    try std.testing.expectEqual(frame.workspace_generation, accepted.workspace_generation);
}

fn expectSyncFrameRejectedOverNativeEndpoint(
    kernel_port: *component_port.KernelPort,
    source_task_id: u64,
    peer_task_id: u64,
    source_endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_port: *sync_service.SyncPort,
    peer_authority: sync_service.AuthorityContext,
    storage: *const storage_service.Service,
    frame: sync_service.TransportFrame,
    expected_error: anyerror,
    tick: *u64,
) !void {
    var payload_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const payload = try encodeSyncFrame(&payload_buffer, frame);
    try expectEndpointSend(kernel_port, source_task_id, source_endpoint_capability_id, payload, tick.*);
    tick.* += 1;

    const received = try expectEndpointRecv(kernel_port, peer_task_id, peer_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received.present);

    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    const request = try decodeSyncFrame(received.payload[0..received.message.payload_len], &path_buffer);
    try std.testing.expectError(expected_error, peer_port.acceptTransportFrame(peer_authority, storage, request));
}

const sync_frame_magic = [_]u8{ 'Z', 'G', 'S', 'F' };

fn encodeSyncFrame(buffer: []u8, frame: sync_service.TransportFrame) ![]const u8 {
    if (frame.source_device.kind != .device or frame.target_device.kind != .device) return error.InvalidSyncFrame;
    const path = frame.pathSlice();
    if (path.len > workspace.MAX_ENTRY_PATH_BYTES or path.len > std.math.maxInt(u8)) return error.InvalidSyncFrame;
    const required_len = sync_frame_magic.len + (5 * @sizeOf(u64)) + 3 + @sizeOf(u32) + 1 + path.len;
    if (buffer.len < required_len) return error.SyncFrameTooLarge;

    var index: usize = 0;
    @memcpy(buffer[index..][0..sync_frame_magic.len], &sync_frame_magic);
    index += sync_frame_magic.len;
    writeU64(buffer, &index, frame.workspace_id);
    writeU64(buffer, &index, frame.object_id);
    writeU64(buffer, &index, frame.version_id);
    writeU64(buffer, &index, frame.source_device.serial);
    writeU64(buffer, &index, frame.target_device.serial);
    buffer[index] = @intFromEnum(frame.transport);
    index += 1;
    buffer[index] = @intFromEnum(frame.semantic);
    index += 1;
    buffer[index] = @intFromBool(frame.encrypted);
    index += 1;
    std.mem.writeInt(u32, buffer[index..][0..@sizeOf(u32)], frame.workspace_generation, .little);
    index += @sizeOf(u32);
    buffer[index] = @intCast(path.len);
    index += 1;
    @memcpy(buffer[index..][0..path.len], path);
    index += path.len;
    return buffer[0..index];
}

fn decodeSyncFrame(payload: []const u8, path_buffer: *[workspace.MAX_ENTRY_PATH_BYTES]u8) !sync_service.TransportFrameRequest {
    const min_len = sync_frame_magic.len + (5 * @sizeOf(u64)) + 3 + @sizeOf(u32) + 1;
    if (payload.len < min_len) return error.InvalidSyncFrame;
    if (!std.mem.eql(u8, payload[0..sync_frame_magic.len], &sync_frame_magic)) return error.InvalidSyncFrame;

    var index: usize = sync_frame_magic.len;
    const workspace_id = readU64(payload, &index);
    const object_id = readU64(payload, &index);
    const version_id = readU64(payload, &index);
    const source_serial = readU64(payload, &index);
    const target_serial = readU64(payload, &index);
    const transport: sync_service.TransportMode = @enumFromInt(payload[index]);
    index += 1;
    const semantic: sync_service.SyncSemantic = @enumFromInt(payload[index]);
    index += 1;
    const encrypted = payload[index] != 0;
    index += 1;
    const workspace_generation = std.mem.readInt(u32, payload[index..][0..@sizeOf(u32)], .little);
    index += @sizeOf(u32);
    const path_len = payload[index];
    index += 1;
    if (payload.len != index + path_len) return error.InvalidSyncFrame;
    @memset(path_buffer[0..], 0);
    @memcpy(path_buffer[0..path_len], payload[index..][0..path_len]);

    return .{
        .workspace_id = workspace_id,
        .object_id = object_id,
        .version_id = version_id,
        .source_device = .{ .kind = .device, .serial = source_serial },
        .target_device = .{ .kind = .device, .serial = target_serial },
        .transport = transport,
        .semantic = semantic,
        .encrypted = encrypted,
        .workspace_generation = workspace_generation,
        .path = path_buffer[0..path_len],
    };
}

fn writeU64(buffer: []u8, index: *usize, value: u64) void {
    std.mem.writeInt(u64, buffer[index.*..][0..@sizeOf(u64)], value, .little);
    index.* += @sizeOf(u64);
}

fn readU64(buffer: []const u8, index: *usize) u64 {
    const value = std.mem.readInt(u64, buffer[index.*..][0..@sizeOf(u64)], .little);
    index.* += @sizeOf(u64);
    return value;
}

fn createResourceProbeTask(
    kernel_port: *component_port.KernelPort,
    session_task_id: u64,
    session_authority_id: u64,
) !abi.TaskDescriptor {
    return createBootedProbeTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        8_001,
        8_001,
        "resource-proof",
        "app.resource-proof",
        1024,
        81,
    );
}

fn createBootedServiceTask(
    kernel_port: *component_port.KernelPort,
    session_task_id: u64,
    session_authority_id: u64,
    owner: principal.PrincipalId,
    image_id: u64,
    label: []const u8,
    bundle_id: []const u8,
    tick: u64,
) !abi.TaskDescriptor {
    // prod-readiness: model-only synthetic-userspace-image; replace with a generated fixture before launch provenance graduation.
    const image = task_runtime.syntheticUserspaceImage(label, bundle_id);
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, tick, session_task_id),
        .authority_capability_id = session_authority_id,
        .request = .{
            .owner = owner,
            .component_class = .service_component,
            .budget = .{
                .cpu_time_ticks = 1_200,
                .memory_bytes = 64 * 1024,
                .endpoint_slots = 2,
                .shared_memory_bytes = 4096,
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = image_id,
                .component_abi_version = abi.ABI_VERSION,
                .signed = true,
                .bundle_id = bundle_id,
            },
            .userspace_image = &image,
        },
    };
    const result = syscall_surface.dispatch(
        kernel_port,
        session_task_id,
        tick,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn createBootedProbeTask(
    kernel_port: *component_port.KernelPort,
    session_task_id: u64,
    session_authority_id: u64,
    owner_serial: u64,
    image_id: u64,
    label: []const u8,
    bundle_id: []const u8,
    shared_memory_bytes: usize,
    tick: u64,
) !abi.TaskDescriptor {
    // prod-readiness: model-only synthetic-userspace-image; replace with a generated fixture before launch provenance graduation.
    const image = task_runtime.syntheticUserspaceImage(label, bundle_id);
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, tick, session_task_id),
        .authority_capability_id = session_authority_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = owner_serial },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_200,
                .memory_bytes = 64 * 1024,
                .endpoint_slots = 1,
                .shared_memory_bytes = shared_memory_bytes,
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = image_id,
                .component_abi_version = abi.ABI_VERSION,
                .signed = true,
                .bundle_id = bundle_id,
            },
            .userspace_image = &image,
        },
    };
    const result = syscall_surface.dispatch(
        kernel_port,
        session_task_id,
        tick,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn resourceQuery(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    tick: u64,
) !abi.ResourceDescriptor {
    var response = std.mem.zeroes(abi.ResourceDescriptor);
    const request = component_port.ResourceQueryRequest{
        .header = component_port.makeHeader(.resource_query, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .task_id = task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.ResourceDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn accountingQuery(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    tick: u64,
) !abi.AccountingDescriptor {
    var response = std.mem.zeroes(abi.AccountingDescriptor);
    const request = component_port.AccountingQueryRequest{
        .header = component_port.makeHeader(.accounting_query, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .task_id = task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.AccountingDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn expectEndpointCreate(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
) !abi.EndpointCreateResponse {
    return expectEndpointCreateWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, .{ .local_only = true }, tick);
}

fn expectEndpointCreateWithFlags(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    flags: endpoint.EndpointFlags,
    tick: u64,
) !abi.EndpointCreateResponse {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    const result = endpointCreateResultIntoWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, flags, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn endpointCreateResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    return endpointCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, tick, &response);
}

fn endpointCreateResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
    response: *abi.EndpointCreateResponse,
) syscall_surface.DispatchResult {
    return endpointCreateResultIntoWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, .{ .local_only = true }, tick, response);
}

fn endpointCreateResultIntoWithFlags(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    flags: endpoint.EndpointFlags,
    tick: u64,
    response: *abi.EndpointCreateResponse,
) syscall_surface.DispatchResult {
    const request = component_port.EndpointCreateRequest{
        .header = component_port.makeHeader(.endpoint_create, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = owner_task_id,
        .label = label,
        .flags = flags,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.EndpointCreateResponse));
}

fn expectEndpointConnect(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_endpoint_id: u64,
    tick: u64,
) !abi.EndpointDescriptor {
    var response = std.mem.zeroes(abi.EndpointDescriptor);
    const request = component_port.EndpointConnectRequest{
        .header = component_port.makeHeader(.endpoint_connect, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .peer_endpoint_capability_id = peer_endpoint_capability_id,
        .peer_endpoint_id = peer_endpoint_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.EndpointDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn expectEndpointSend(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    payload: []const u8,
    tick: u64,
) !void {
    const request = component_port.EndpointSendRequest{
        .header = component_port.makeHeader(.endpoint_send, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .payload = payload,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), 0, 0);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
}

fn expectEndpointRecv(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    tick: u64,
) !abi.EndpointRecvResponse {
    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    const request = component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .receiver_task_id = caller_task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.EndpointRecvResponse));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn expectSharedMemoryCreate(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
) !abi.SharedMemoryCreateResponse {
    var response = std.mem.zeroes(abi.SharedMemoryCreateResponse);
    const result = sharedMemoryCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, size_bytes, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn sharedMemoryCreateResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.SharedMemoryCreateResponse);
    return sharedMemoryCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, size_bytes, tick, &response);
}

fn sharedMemoryCreateResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
    response: *abi.SharedMemoryCreateResponse,
) syscall_surface.DispatchResult {
    const request = component_port.SharedMemoryCreateRequest{
        .header = component_port.makeHeader(.shared_memory_create, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = owner_task_id,
        .size_bytes = size_bytes,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.SharedMemoryCreateResponse));
}

fn expectSharedMemoryMap(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
) !void {
    _ = try expectSharedMemoryMapDescriptor(kernel_port, caller_task_id, shared_memory_capability_id, task_id, tick);
}

fn expectSharedMemoryMapDescriptor(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
) !abi.SharedMemoryDescriptor {
    var response = std.mem.zeroes(abi.SharedMemoryDescriptor);
    const result = sharedMemoryMapResultInto(kernel_port, caller_task_id, shared_memory_capability_id, task_id, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn sharedMemoryMapResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.SharedMemoryDescriptor);
    return sharedMemoryMapResultInto(kernel_port, caller_task_id, shared_memory_capability_id, task_id, tick, &response);
}

fn sharedMemoryMapResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
    response: *abi.SharedMemoryDescriptor,
) syscall_surface.DispatchResult {
    const request = component_port.SharedMemoryMapRequest{
        .header = component_port.makeHeader(.shared_memory_map, tick, caller_task_id),
        .shared_memory_capability_id = shared_memory_capability_id,
        .task_id = task_id,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.SharedMemoryDescriptor));
}

fn expectSharedMemoryRevoke(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    tick: u64,
) !abi.SharedMemoryDescriptor {
    var response = std.mem.zeroes(abi.SharedMemoryDescriptor);
    const request = component_port.SharedMemoryRevokeRequest{
        .header = component_port.makeHeader(.shared_memory_revoke, tick, caller_task_id),
        .shared_memory_capability_id = shared_memory_capability_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.SharedMemoryDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn expectDeviceDescribe(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
) !abi.DeviceDescriptor {
    var response = std.mem.zeroes(abi.DeviceDescriptor);
    const result = deviceDescribeResultInto(kernel_port, caller_task_id, device_capability_id, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn deviceDescribeResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.DeviceDescriptor);
    return deviceDescribeResultInto(kernel_port, caller_task_id, device_capability_id, tick, &response);
}

fn deviceDescribeResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
    response: *abi.DeviceDescriptor,
) syscall_surface.DispatchResult {
    const request = component_port.DeviceDescribeRequest{
        .header = component_port.makeHeader(.device_describe, tick, caller_task_id),
        .device_capability_id = device_capability_id,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.DeviceDescriptor));
}

fn findServiceAuthority(
    capability_table: *const capability.CapabilityTable,
    task: *const task_runtime.TaskRecord,
    right: capability.CapabilityRight,
) ?u64 {
    for (task.capabilityIds()) |capability_id| {
        const record = capability_table.query(capability_id) orelse continue;
        if (record.target.kind == .service and record.rights.has(right)) return capability_id;
    }
    return null;
}

fn storageGrant() storage_driver_protocol.AtaBrokerGrant {
    return .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = 4096,
    };
}

fn signer(label: []const u8, seed: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = [_]u8{seed} ** 32,
    };
}

test "booted userspace service paths prove sync driver isolation and resource accounting" {
    try bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting();
}

test "booted userspace service paths prove process isolation visible-entitlement gates" {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    try proveBootedProcessIsolationVisibleEntitlementGates(
        session_manager.testing.runtimePtr(),
        session_manager.system().capabilityTablePtr(),
        session_manager.testing.findTask("sync-service").?,
        session_manager.testing.findTask("workspace-storage").?,
        session_manager.testing.findTask("compositor-session").?,
    );
}

test "booted driver hot-swap and crash recovery rebind live brokered device authority" {
    try proveBootedDriverHotSwapAndRecoveryRebindLiveBrokeredDeviceAuthority();
}
