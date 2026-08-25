const std = @import("std");
const abi = @import("../../core/abi.zig");
const capability = @import("../../kernel_api/capability.zig");
const component_port = @import("../../kernel_api/component_port.zig");
const driver_runtime_mod = @import("../../drivers/driver_runtime.zig");
const driver_service = @import("../../drivers/driver_service.zig");
const endpoint = @import("../../kernel_api/endpoint.zig");
const ids = @import("../../core/ids.zig");
const kernel_data_plane_boundary = @import("../../../kernel/boot/init/data_plane_boundary.zig");
const native_service_registry = @import("../../services/service_registry.zig");
const service_catalog = @import("../service_catalog.zig");
const supervisor_mod = @import("../supervisor.zig");
const syscall_surface = @import("../../kernel_api/syscall_surface.zig");
const task_runtime = @import("../../task/task_runtime.zig");

const BootedServiceBinding = struct {
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
};

pub fn proveBootedUserspaceServiceOwnershipAndKernelBoundary(
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
        .{ .device_class = .usb_controller, .service_class = .compositor_ui_session },
        .{ .device_class = .graphics_adapter, .service_class = .compositor_ui_session },
        .{ .device_class = .input_device, .service_class = .compositor_ui_session },
        .{ .device_class = .compositor_policy, .service_class = .compositor_ui_session },
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
            .network_adapter,
            .usb_controller,
            .graphics_adapter,
            .audio_print_io,
            .input_device,
            .compositor_policy,
            => {
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
    const connection = try service_directory.connect(contract.interface_id);
    try std.testing.expectEqual(service_record.id, connection.service_id);
    try std.testing.expect(native_service_registry.AUTHENTICATED_BINDINGS_ONLY);

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
