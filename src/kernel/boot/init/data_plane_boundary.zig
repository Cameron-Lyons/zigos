pub const kernel_boundary_role = "bootstrap_device_inventory_shim";
pub const publishes_device_data_planes = false;
pub const publishes_windowing_data_plane = false;
pub const publishes_package_data_plane = false;
pub const publishes_indexing_data_plane = false;
pub const publishes_sync_data_plane = false;

pub const BoundaryError = error{
    KernelDeviceDataPlaneDisabled,
    KernelSubsystemDataPlaneDisabled,
};

pub const DataPlaneKind = enum(u8) {
    device,
    network_stack,
    storage_object,
    windowing,
    package_install,
    indexing,
    sync_replication,
};

pub const PublicationRequest = struct {
    service_id: u64,
    device_id: u64,
    device_class: u8,
};

pub const SubsystemPublicationRequest = struct {
    kind: DataPlaneKind,
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
};

pub fn rejectKernelDeviceDataPlane(_: PublicationRequest) BoundaryError!void {
    return error.KernelDeviceDataPlaneDisabled;
}

pub fn rejectKernelSubsystemDataPlane(request: SubsystemPublicationRequest) BoundaryError!void {
    return switch (request.kind) {
        .device => error.KernelDeviceDataPlaneDisabled,
        .network_stack,
        .storage_object,
        .windowing,
        .package_install,
        .indexing,
        .sync_replication,
        => error.KernelSubsystemDataPlaneDisabled,
    };
}

test "kernel device init boundary rejects data-plane publication" {
    try @import("std").testing.expectError(error.KernelDeviceDataPlaneDisabled, rejectKernelDeviceDataPlane(.{
        .service_id = 1,
        .device_id = 0x1F001,
        .device_class = 1,
    }));
}

test "kernel device init boundary rejects excluded subsystem data planes" {
    const testing = @import("std").testing;
    const requests = [_]SubsystemPublicationRequest{
        .{ .kind = .network_stack, .service_id = 8, .owner_task_id = 18, .endpoint_id = 28 },
        .{ .kind = .storage_object, .service_id = 9, .owner_task_id = 19, .endpoint_id = 29 },
        .{ .kind = .windowing, .service_id = 10, .owner_task_id = 20, .endpoint_id = 30 },
        .{ .kind = .package_install, .service_id = 11, .owner_task_id = 21, .endpoint_id = 31 },
        .{ .kind = .indexing, .service_id = 12, .owner_task_id = 22, .endpoint_id = 32 },
        .{ .kind = .sync_replication, .service_id = 13, .owner_task_id = 23, .endpoint_id = 33 },
    };
    for (requests) |request| {
        try testing.expectError(error.KernelSubsystemDataPlaneDisabled, rejectKernelSubsystemDataPlane(request));
    }
    try testing.expectError(error.KernelDeviceDataPlaneDisabled, rejectKernelSubsystemDataPlane(.{
        .kind = .device,
        .service_id = 14,
        .owner_task_id = 24,
        .endpoint_id = 34,
    }));
}
