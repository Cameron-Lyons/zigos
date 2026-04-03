const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const endpoint = @import("endpoint.zig");
const manifest = @import("../policy/manifest.zig");
const native_kernel = @import("native_kernel.zig");
const request_header = @import("../core/request_header.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub const Error = native_kernel.Error || error{
    UnexpectedOperation,
    SubjectTaskMismatch,
    UnsupportedAbiVersion,
};

pub const TaskCreateRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    request: task_runtime.TaskCreateRequest,
};

pub const TaskTerminateRequest = struct {
    header: abi.RequestHeader,
    task_capability_id: u64,
};

pub const EndpointCreateRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    flags: endpoint.EndpointFlags,
};

pub const EndpointConnectRequest = struct {
    header: abi.RequestHeader,
    endpoint_capability_id: u64,
    peer_endpoint_id: u64,
};

pub const EndpointSendRequest = struct {
    header: abi.RequestHeader,
    endpoint_capability_id: u64,
    payload: []const u8,
    attached_capability_id: ?u64 = null,
    move_attached_capability: bool = false,
};

pub const EndpointRecvRequest = struct {
    header: abi.RequestHeader,
    endpoint_capability_id: u64,
    receiver_task_id: u64,
};

pub const CapabilityMintRequest = struct {
    header: abi.RequestHeader,
    policy_capability_id: u64,
    request: capability.MintRequest,
};

pub const CapabilityDeriveRequest = struct {
    header: abi.RequestHeader,
    request: capability.DeriveRequest,
};

pub const CapabilityPassRequest = struct {
    header: abi.RequestHeader,
    capability_id: u64,
    receiver_task_id: u64,
    revoke_source: bool = false,
};

pub const CapabilityRevokeRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    capability_id: u64,
};

pub const CapabilityQueryRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    capability_id: u64,
};

pub const SharedMemoryCreateRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
};

pub const SharedMemoryMapRequest = struct {
    header: abi.RequestHeader,
    shared_memory_capability_id: u64,
    task_id: u64,
};

pub const SharedMemoryUnmapRequest = struct {
    header: abi.RequestHeader,
    shared_memory_capability_id: u64,
    task_id: u64,
};

pub const SharedMemoryRevokeRequest = struct {
    header: abi.RequestHeader,
    shared_memory_capability_id: u64,
};

pub const TimeQueryRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
};

pub const ResourceQueryRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    task_id: u64,
};

pub const AccountingQueryRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    task_id: u64,
};

pub const ServiceRegisterRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    service_id: u64,
    owner_task_id: u64,
    endpoint_capability_id: u64,
    interface: manifest.InterfaceDecl,
};

pub const ServiceConnectRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    endpoint_capability_id: u64,
    interface: manifest.InterfaceDecl,
};

pub const DeviceDescribeRequest = struct {
    header: abi.RequestHeader,
    device_capability_id: u64,
};

pub const DeviceMmioWindowRequest = struct {
    header: abi.RequestHeader,
    device_capability_id: u64,
    window_index: u8,
};

pub const DevicePortReadRequest = struct {
    header: abi.RequestHeader,
    device_capability_id: u64,
    port: u16,
    width: abi.DevicePortWidth,
};

pub const DevicePortWriteRequest = struct {
    header: abi.RequestHeader,
    device_capability_id: u64,
    port: u16,
    width: abi.DevicePortWidth,
    value: u32,
};

pub const KernelPort = struct {
    kernel: *native_kernel.Kernel,

    pub fn init(kernel: *native_kernel.Kernel) KernelPort {
        return .{ .kernel = kernel };
    }

    pub fn taskCreate(self: *KernelPort, request: TaskCreateRequest, now_ticks: u64) Error!abi.TaskDescriptor {
        try validateHeader(request.header, .task_create);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        return self.kernel.taskCreate(request.authority_capability_id, request.request, now_ticks);
    }

    pub fn taskTerminate(self: *KernelPort, request: TaskTerminateRequest, now_ticks: u64) Error!bool {
        try validateHeader(request.header, .task_terminate);
        try validateCallerCapability(self, request.header, request.task_capability_id, now_ticks);
        return self.kernel.taskTerminate(request.task_capability_id, now_ticks);
    }

    pub fn endpointCreate(
        self: *KernelPort,
        request: EndpointCreateRequest,
        now_ticks: u64,
    ) Error!native_kernel.EndpointCreateResult {
        try validateHeader(request.header, .endpoint_create);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        return self.kernel.endpointCreate(
            request.authority_capability_id,
            request.owner_task_id,
            request.label,
            request.flags,
            now_ticks,
        );
    }

    pub fn endpointConnect(self: *KernelPort, request: EndpointConnectRequest, now_ticks: u64) Error!abi.EndpointDescriptor {
        try validateHeader(request.header, .endpoint_connect);
        try validateCallerCapability(self, request.header, request.endpoint_capability_id, now_ticks);
        return self.kernel.endpointConnect(request.endpoint_capability_id, request.peer_endpoint_id, now_ticks);
    }

    pub fn endpointSend(self: *KernelPort, request: EndpointSendRequest, now_ticks: u64) Error!void {
        try validateHeader(request.header, .endpoint_send);
        try validateCallerCapability(self, request.header, request.endpoint_capability_id, now_ticks);
        try validateOptionalCallerCapability(self, request.header, request.attached_capability_id, now_ticks);
        return self.kernel.endpointSend(
            request.endpoint_capability_id,
            request.header.correlation_id,
            request.payload,
            request.attached_capability_id,
            request.move_attached_capability,
            now_ticks,
        );
    }

    pub fn endpointRecv(
        self: *KernelPort,
        request: EndpointRecvRequest,
        now_ticks: u64,
    ) Error!?native_kernel.EndpointReceiveResult {
        try validateHeader(request.header, .endpoint_recv);
        try validateSubjectTask(request.header, request.receiver_task_id);
        try validateCallerCapability(self, request.header, request.endpoint_capability_id, now_ticks);
        return self.kernel.endpointRecv(request.endpoint_capability_id, request.receiver_task_id, now_ticks);
    }

    pub fn capabilityMint(
        self: *KernelPort,
        request: CapabilityMintRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try validateHeader(request.header, .capability_mint);
        try validateCallerCapability(self, request.header, request.policy_capability_id, now_ticks);
        return self.kernel.capabilityMint(request.policy_capability_id, request.request, now_ticks);
    }

    pub fn capabilityDerive(self: *KernelPort, request: CapabilityDeriveRequest) Error!abi.CapabilityDescriptor {
        try validateHeader(request.header, .capability_derive);
        try validateCallerCapability(self, request.header, request.request.parent_capability_id, request.request.lease.issued_at_ticks);
        return self.kernel.capabilityDerive(request.request);
    }

    pub fn capabilityPass(
        self: *KernelPort,
        request: CapabilityPassRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try validateHeader(request.header, .capability_pass);
        try validateCallerCapability(self, request.header, request.capability_id, now_ticks);
        return self.kernel.capabilityPass(
            request.capability_id,
            request.receiver_task_id,
            now_ticks,
            request.revoke_source,
        );
    }

    pub fn capabilityRevoke(self: *KernelPort, request: CapabilityRevokeRequest, now_ticks: u64) Error!void {
        try validateHeader(request.header, .capability_revoke);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        return self.kernel.capabilityRevoke(request.authority_capability_id, request.capability_id, now_ticks);
    }

    pub fn capabilityQuery(
        self: *KernelPort,
        request: CapabilityQueryRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try validateHeader(request.header, .capability_query);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        return self.kernel.capabilityQuery(request.authority_capability_id, request.capability_id, now_ticks);
    }

    pub fn sharedMemoryCreate(
        self: *KernelPort,
        request: SharedMemoryCreateRequest,
        now_ticks: u64,
    ) Error!native_kernel.SharedMemoryCreateResult {
        try validateHeader(request.header, .shared_memory_create);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        return self.kernel.sharedMemoryCreate(
            request.authority_capability_id,
            request.owner_task_id,
            request.size_bytes,
            now_ticks,
        );
    }

    pub fn sharedMemoryMap(
        self: *KernelPort,
        request: SharedMemoryMapRequest,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        try validateHeader(request.header, .shared_memory_map);
        try validateSubjectTask(request.header, request.task_id);
        try validateCallerCapability(self, request.header, request.shared_memory_capability_id, now_ticks);
        return self.kernel.sharedMemoryMap(request.shared_memory_capability_id, request.task_id, now_ticks);
    }

    pub fn sharedMemoryUnmap(self: *KernelPort, request: SharedMemoryUnmapRequest, now_ticks: u64) Error!bool {
        try validateHeader(request.header, .shared_memory_unmap);
        try validateSubjectTask(request.header, request.task_id);
        try validateCallerCapability(self, request.header, request.shared_memory_capability_id, now_ticks);
        return self.kernel.sharedMemoryUnmap(request.shared_memory_capability_id, request.task_id, now_ticks);
    }

    pub fn sharedMemoryRevoke(
        self: *KernelPort,
        request: SharedMemoryRevokeRequest,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        try validateHeader(request.header, .shared_memory_revoke);
        try validateCallerCapability(self, request.header, request.shared_memory_capability_id, now_ticks);
        return self.kernel.sharedMemoryRevoke(request.shared_memory_capability_id, now_ticks);
    }

    pub fn timeQuery(self: *KernelPort, request: TimeQueryRequest, now_ticks: u64) Error!u64 {
        try validateHeader(request.header, .time_query);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        return self.kernel.timeQuery(request.authority_capability_id, now_ticks);
    }

    pub fn resourceQuery(
        self: *KernelPort,
        request: ResourceQueryRequest,
        now_ticks: u64,
    ) Error!abi.ResourceDescriptor {
        try validateHeader(request.header, .resource_query);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        return self.kernel.resourceQuery(request.authority_capability_id, request.task_id, now_ticks);
    }

    pub fn accountingQuery(
        self: *KernelPort,
        request: AccountingQueryRequest,
        now_ticks: u64,
    ) Error!abi.AccountingDescriptor {
        try validateHeader(request.header, .accounting_query);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        return self.kernel.accountingQuery(request.authority_capability_id, request.task_id, now_ticks);
    }

    pub fn serviceRegister(self: *KernelPort, request: ServiceRegisterRequest, now_ticks: u64) Error!void {
        try validateHeader(request.header, .service_register);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        try validateCallerCapability(self, request.header, request.endpoint_capability_id, now_ticks);
        return self.kernel.serviceRegister(
            request.authority_capability_id,
            request.service_id,
            request.owner_task_id,
            request.endpoint_capability_id,
            request.interface,
            now_ticks,
        );
    }

    pub fn serviceConnect(
        self: *KernelPort,
        request: ServiceConnectRequest,
        now_ticks: u64,
    ) Error!abi.ServiceConnectionDescriptor {
        try validateHeader(request.header, .service_connect);
        try validateCallerCapability(self, request.header, request.authority_capability_id, now_ticks);
        try validateCallerCapability(self, request.header, request.endpoint_capability_id, now_ticks);
        return self.kernel.serviceConnect(
            request.authority_capability_id,
            request.endpoint_capability_id,
            request.interface,
            now_ticks,
        );
    }

    pub fn deviceDescribe(
        self: *KernelPort,
        request: DeviceDescribeRequest,
        now_ticks: u64,
    ) Error!abi.DeviceDescriptor {
        try validateHeader(request.header, .device_describe);
        try validateCallerCapability(self, request.header, request.device_capability_id, now_ticks);
        return self.kernel.deviceDescribe(request.device_capability_id, now_ticks);
    }

    pub fn deviceMmioWindow(
        self: *KernelPort,
        request: DeviceMmioWindowRequest,
        now_ticks: u64,
    ) Error!abi.DeviceMmioWindowDescriptor {
        try validateHeader(request.header, .device_mmio_window);
        try validateCallerCapability(self, request.header, request.device_capability_id, now_ticks);
        return self.kernel.deviceMmioWindow(
            request.device_capability_id,
            request.window_index,
            now_ticks,
        );
    }

    pub fn devicePortRead(
        self: *KernelPort,
        request: DevicePortReadRequest,
        now_ticks: u64,
    ) Error!u32 {
        try validateHeader(request.header, .device_port_read);
        try validateCallerCapability(self, request.header, request.device_capability_id, now_ticks);
        return self.kernel.devicePortRead(
            request.device_capability_id,
            request.port,
            request.width,
            now_ticks,
        );
    }

    pub fn devicePortWrite(
        self: *KernelPort,
        request: DevicePortWriteRequest,
        now_ticks: u64,
    ) Error!void {
        try validateHeader(request.header, .device_port_write);
        try validateCallerCapability(self, request.header, request.device_capability_id, now_ticks);
        return self.kernel.devicePortWrite(
            request.device_capability_id,
            request.port,
            request.width,
            request.value,
            now_ticks,
        );
    }
};

pub fn makeHeader(operation: abi.NativeOperation, correlation_id: u64, subject_task_id: u64) abi.RequestHeader {
    return request_header.makeHeader(abi.opcode(operation), correlation_id, subject_task_id);
}

fn validateHeader(header: abi.RequestHeader, expected: abi.NativeOperation) Error!void {
    try request_header.validateHeader(header, abi.opcode(expected));
}

fn validateSubjectTask(header: abi.RequestHeader, task_id: u64) Error!void {
    try request_header.validateSubjectTask(header, task_id);
}

fn validateCallerCapability(
    self: *KernelPort,
    header: abi.RequestHeader,
    capability_id: u64,
    now_ticks: u64,
) Error!void {
    if (header.subject_task_id == 0) return;
    try self.kernel.requireTaskCapability(header.subject_task_id, capability_id, now_ticks);
}

fn validateOptionalCallerCapability(
    self: *KernelPort,
    header: abi.RequestHeader,
    capability_id: ?u64,
    now_ticks: u64,
) Error!void {
    if (capability_id) |id| {
        try validateCallerCapability(self, header, id, now_ticks);
    }
}

test "kernel port enforces operation ids and forwards typed task create requests" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = @import("shared_memory.zig").Table.init();
    var registry = @import("service_registry.zig").Registry.init();
    var kernel = native_kernel.Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
        &registry,
    );
    var port = KernelPort.init(&kernel);

    const session_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 1 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 10_000,
            .memory_bytes = 4096,
            .endpoint_slots = 8,
            .shared_memory_bytes = 4096,
        },
        .local_only = true,
    });
    const authority_capability = try capabilities.mint(.{
        .holder = session_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .task_create = true },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });
    try runtime.grantCapability(session_task.id, authority_capability.id);

    const port_test_image = task_runtime.syntheticUserspaceImage("port-test", "app.example.port-test");
    const task = try port.taskCreate(.{
        .header = makeHeader(.task_create, 77, session_task.id),
        .authority_capability_id = authority_capability.id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 2 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = 512,
                .endpoint_slots = 2,
                .shared_memory_bytes = 512,
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 10,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.port-test",
            },
            .userspace_image = &port_test_image,
        },
    }, 5);
    try std.testing.expect(task.task_id != 0);
    try std.testing.expect(abi.taskFlagsHas(task.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(abi.taskFlagsHas(task.flags, abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED));

    try std.testing.expectError(error.UnexpectedOperation, port.taskCreate(.{
        .header = makeHeader(.endpoint_create, 78, session_task.id),
        .authority_capability_id = authority_capability.id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 3 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = 512,
                .endpoint_slots = 2,
                .shared_memory_bytes = 512,
            },
            .local_only = true,
        },
    }, 6));
}

test "kernel port validates and forwards typed device broker requests" {
    const device_broker = @import("device_broker.zig");

    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = @import("shared_memory.zig").Table.init();
    var registry = @import("service_registry.zig").Registry.init();
    var kernel = native_kernel.Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
        &registry,
    );
    var port = KernelPort.init(&kernel);

    const kernel_port_device_image = task_runtime.syntheticUserspaceImage(
        "kernel-port-device-test",
        "zigos.system.storage-driver",
    );
    const driver_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 8 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 18,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.storage-driver",
        },
        .userspace_image = &kernel_port_device_image,
    });
    const device_capability = try capabilities.mint(.{
        .holder = driver_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .device, .id = 0x1F001 },
        .rights = .{ .device_use = true },
        .scope = .{
            .task_id = driver_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 7,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
    });
    try runtime.grantCapability(driver_task.id, device_capability.id);

    device_broker.reset();
    defer device_broker.reset();
    try std.testing.expect(device_broker.publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = 2048,
    }));

    const descriptor = try port.deviceDescribe(.{
        .header = makeHeader(.device_describe, 81, driver_task.id),
        .device_capability_id = device_capability.id,
    }, 7);
    try std.testing.expectEqual(@as(u64, 0x1F001), descriptor.device_id);

    try port.devicePortWrite(.{
        .header = makeHeader(.device_port_write, 82, driver_task.id),
        .device_capability_id = device_capability.id,
        .port = 0x1F0 + 7,
        .width = .u8,
        .value = 0x66,
    }, 7);
    try std.testing.expectEqual(@as(u32, 0x66), try port.devicePortRead(.{
        .header = makeHeader(.device_port_read, 83, driver_task.id),
        .device_capability_id = device_capability.id,
        .port = 0x1F0 + 7,
        .width = .u8,
    }, 7));

    try std.testing.expectError(error.UnexpectedOperation, port.deviceDescribe(.{
        .header = makeHeader(.task_create, 84, driver_task.id),
        .device_capability_id = device_capability.id,
    }, 7));
}
