const std = @import("std");
const abi = @import("../core/abi.zig");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const ids = @import("../core/ids.zig");
const immutable_base = @import("../platform/immutable_base.zig");
const kernel_data_plane_boundary = @import("../../kernel/boot/init/data_plane_boundary.zig");
const manifest = @import("../policy/manifest.zig");
const native_ux = @import("../platform/native_ux.zig");
const native_service_registry = @import("../services/service_registry.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const session_manager = @import("session_manager.zig");
const service_catalog = @import("service_catalog.zig");
const signing = @import("../core/signing.zig");
const storage_driver_protocol = @import("../drivers/storage_driver_protocol.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const syscall_surface = @import("../kernel_api/syscall_surface.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const update_health = @import("../platform/update_health.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const compositor_session = @import("../platform/compositor_session.zig");

pub fn bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting() !void {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    const runtime = session_manager.testing.runtimePtr();
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
    try std.testing.expect(runtime.processSeparated(sync_task.id, storage_task.id));
    try std.testing.expect(runtime.processSeparated(sync_task.id, storage_driver_task.id));
    try std.testing.expect(runtime.processSeparated(storage_driver_task.id, storage_task.id));

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
        runtime,
        capability_table,
        supervisor.findByClass(.sync_replication).?,
        sync_task,
        storage,
    );
    try proveBootedCompositorServicePath(
        kernel_port,
        runtime,
        capability_table,
        storage,
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
        runtime,
        session_manager.testing.userspaceSchedulerPtr(),
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
    try std.testing.expectEqual(owner_mapping.page_base, peer_mapping.page_base);
    try std.testing.expectEqual(@as(usize, 1), owner_mapping.page_count);
    try std.testing.expectEqual(@as(usize, 4096), peer_mapping.size_bytes);
    try std.testing.expect(!owner_mapping.zero_copy);

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

    const accelerated = try kernel_port.kernel.shared_memory_table.createLabeledWithAccess(ids.task(owner.task_id), 8192, "booted-accelerator", .{
        .gpu = true,
        .media = true,
    });
    try kernel_port.kernel.shared_memory_table.map(accelerated.id, ids.task(owner.task_id));
    try kernel_port.kernel.shared_memory_table.attachAccelerator(accelerated.id, .gpu);
    const task_mapping = try kernel_port.kernel.shared_memory_table.taskMappingDescriptor(accelerated.id, ids.task(owner.task_id));
    const gpu_mapping = try kernel_port.kernel.shared_memory_table.acceleratorMappingDescriptor(accelerated.id, .gpu);
    try std.testing.expect(gpu_mapping.zero_copy);
    try std.testing.expectEqual(task_mapping.page_base, gpu_mapping.page_base);
    try std.testing.expectEqual(task_mapping.page_count, gpu_mapping.page_count);
    try kernel_port.kernel.shared_memory_table.revoke(accelerated.id);
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.taskMappingDescriptor(accelerated.id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.acceleratorMappingDescriptor(accelerated.id, .gpu));
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

        if (driver_runtime.findByClass(expectation.device_class)) |activation| {
            try std.testing.expectEqual(driver.service_id, activation.service_id);
            try std.testing.expectEqual(driver.device_id, activation.device_id);
            try std.testing.expect(activation.iommu_enforced);
            if (activation.kernel_bootstrap) {
                try std.testing.expectEqual(driver_runtime_mod.ActivationMode.userspace_brokered_data_plane, activation.mode);
            } else {
                try std.testing.expect(activation.mode != .published_data_plane or activation.exclusive_claim);
            }
        }
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
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    sync_record: *const @import("supervisor.zig").ServiceRecord,
    sync_task: *task_runtime.TaskRecord,
    storage: *@import("../storage/storage_service.zig").Service,
) !void {
    const sync_owner = sync_record.owner;
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

    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "service-path-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes_v2.object_id, notes_v2.version_id, .document);
    try storage.stagePut(workspace_record.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    _ = try storage.commit(workspace_record.id, 105);
    const workspace_id = workspace_record.id.raw();

    _ = try sync_port.ensureUserRoot(sync_authority, user, "owner", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, laptop, "laptop", user_signer, laptop_signer, 106);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, tablet, "tablet", user_signer, tablet_signer, 107);
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
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/" },
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.service-path.zigos",
    });
    _ = try sync_port.configureOverlay(sync_authority, workspace_id, laptop, "overlay.service-path.notes", true);
    _ = try sync_port.publishPrivateService(sync_authority, workspace_id, "notes.remote");

    try sync_port.setReplicaVersion(sync_authority, workspace_id, tablet, "documents/notes.md", notes_v1.object_id, cover.version_id);
    const summary = try sync_port.replicateWorkspace(sync_authority, storage, workspace_id, laptop, tablet, .device_to_device);
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_device_to_device);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expect(summary.remote_access_ready);
    try std.testing.expectEqual(@as(usize, 2), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expectEqual(summary.transport_frame_count, summary.encrypted_transport_count);
    try std.testing.expect(sync_instance.findConflict(workspace_id, tablet, "documents/notes.md") != null);

    const relay_session = try sync_port.openOverlaySession(
        sync_authority,
        workspace_id,
        laptop,
        tablet,
        .private_service,
        .relay_assisted,
        "notes.remote",
        108,
    );
    try std.testing.expect(relay_session.encrypted);
    try std.testing.expect(relay_session.relay_encrypted);
    try std.testing.expectEqualStrings("notes.remote", relay_session.privateServiceSlice());
    try std.testing.expect(!(try sync_port.evaluateNetworkPolicy(sync_authority, relay_policy.id, .{ .domain = "other.service-path.zigos" })).allowed);

    try std.testing.expect(try sync_port.transferSecretObject(sync_authority, storage, workspace_id, secret.object_id, laptop, tablet, .device_to_device));
    const contract = try sync_port.registerDatabaseContract(sync_authority, workspace_id, "app.notes.db", "notes-db", contract_signer);
    try std.testing.expect(try sync_port.replicateDatabaseContract(sync_authority, contract.id, workspace_id, laptop, tablet, .relay_assisted));
    try std.testing.expectError(sync_service.Error.DeviceNotTrusted, sync_port.replicateWorkspace(sync_authority, storage, workspace_id, laptop, phone, .device_to_device));
}

fn proveBootedCompositorServicePath(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    storage: *storage_service.Service,
    compositor_record: *const @import("supervisor.zig").ServiceRecord,
    compositor_task: *task_runtime.TaskRecord,
    session: *compositor_session.Session,
) !void {
    session.reset();
    runtime.allowHostPointerSyscallsForTask(compositor_task.id);

    const app_owner = principal.PrincipalId{ .kind = .app, .serial = 82_001 };
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

    const panel_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .open_view,
        .view_type = .app_panel,
        .subject_task_id = app_task.id,
        .workspace_id = workspace_id,
        .detail = "Calendar Panel",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, panel_response.status);
    try assertRenderedWindowContains(session, panel_response.window_id, "type=app_panel");
    try assertRenderedWindowContains(session, panel_response.window_id, "modal=yes");

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
    runtime: *task_runtime.Runtime,
    scheduler: *userspace_scheduler.Scheduler,
) !void {
    parkBootedSchedulerTasks(runtime, scheduler);

    var provider = accelerator_scheduler.BootedPlatformTelemetryProvider.init(44, 140, .{
        .thermal_pressure = .critical,
        .gpu_available = true,
        .media_available = true,
        .npu_available = true,
        .cpu_budget_ticks = 4_000,
        .memory_bandwidth_units = 512,
    });
    scheduler.configureResourceTelemetryFromProvider(&provider);
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expectEqual(accelerator_scheduler.TelemetrySource.boot_provider, scheduler.resource_telemetry_source);
    try std.testing.expectEqual(@as(u64, 140), scheduler.resource_telemetry_observed_tick);

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
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(foreground.id, .{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = 4096,
    }, false));
    try std.testing.expect(!scheduler.runNext(140));
    const foreground_slot = scheduler.slots.getConst(foreground.id).?;
    try std.testing.expectEqual(@as(u64, 1), foreground_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, foreground_slot.last_dispatch_engine);
    try std.testing.expect(foreground_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, foreground_slot.last_dispatch_reason);

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
    try std.testing.expect(scheduler.registerTask(media.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(media.id, .{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = 8192,
    }, true));

    const media_denials_before = scheduler.engineDenialCount(.media);
    provider.observe(141, .{
        .thermal_pressure = .nominal,
        .gpu_available = false,
        .media_available = false,
        .npu_available = true,
        .cpu_budget_ticks = 4_000,
        .memory_bandwidth_units = 512,
    });
    scheduler.configureResourceTelemetryFromProvider(&provider);
    try std.testing.expect(!scheduler.runNext(141));
    const denied_media_slot = scheduler.slots.getConst(media.id).?;
    try std.testing.expectEqual(@as(u64, 0), denied_media_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), denied_media_slot.denied_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.accelerator_unavailable, denied_media_slot.last_dispatch_reason);
    try std.testing.expectEqual(media_denials_before + 1, scheduler.engineDenialCount(.media));
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    provider.observe(142, .{
        .thermal_pressure = .nominal,
        .gpu_available = true,
        .media_available = true,
        .npu_available = true,
        .cpu_budget_ticks = 4_000,
        .memory_bandwidth_units = 512,
    });
    scheduler.configureResourceTelemetryFromProvider(&provider);
    try std.testing.expect(!scheduler.runNext(142));
    const dispatched_media_slot = scheduler.slots.getConst(media.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_media_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, dispatched_media_slot.last_dispatch_engine);
    try std.testing.expect(dispatched_media_slot.last_dispatch_zero_copy);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u32, 3), provider.read_count);
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
