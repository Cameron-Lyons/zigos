const std = @import("std");
const abi = @import("abi.zig");
const capability = @import("capability.zig");
const endpoint = @import("endpoint.zig");
const manifest = @import("manifest.zig");
const native_kernel = @import("native_kernel.zig");
const task_runtime = @import("task_runtime.zig");

pub const Error = native_kernel.Error || error{
    UnexpectedOperation,
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

pub const KernelPort = struct {
    kernel: *native_kernel.Kernel,

    pub fn init(kernel: *native_kernel.Kernel) KernelPort {
        return .{ .kernel = kernel };
    }

    pub fn taskCreate(self: *KernelPort, request: TaskCreateRequest, now_ticks: u64) Error!abi.TaskDescriptor {
        try validateHeader(request.header, .task_create);
        return self.kernel.taskCreate(request.authority_capability_id, request.request, now_ticks);
    }

    pub fn taskTerminate(self: *KernelPort, request: TaskTerminateRequest, now_ticks: u64) Error!bool {
        try validateHeader(request.header, .task_terminate);
        return self.kernel.taskTerminate(request.task_capability_id, now_ticks);
    }

    pub fn endpointCreate(
        self: *KernelPort,
        request: EndpointCreateRequest,
        now_ticks: u64,
    ) Error!native_kernel.EndpointCreateResult {
        try validateHeader(request.header, .endpoint_create);
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
        return self.kernel.endpointConnect(request.endpoint_capability_id, request.peer_endpoint_id, now_ticks);
    }

    pub fn endpointSend(self: *KernelPort, request: EndpointSendRequest, now_ticks: u64) Error!void {
        try validateHeader(request.header, .endpoint_send);
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
        return self.kernel.endpointRecv(request.endpoint_capability_id, request.receiver_task_id, now_ticks);
    }

    pub fn capabilityMint(
        self: *KernelPort,
        request: CapabilityMintRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try validateHeader(request.header, .capability_mint);
        return self.kernel.capabilityMint(request.policy_capability_id, request.request, now_ticks);
    }

    pub fn capabilityDerive(self: *KernelPort, request: CapabilityDeriveRequest) Error!abi.CapabilityDescriptor {
        try validateHeader(request.header, .capability_derive);
        return self.kernel.capabilityDerive(request.request);
    }

    pub fn capabilityPass(
        self: *KernelPort,
        request: CapabilityPassRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try validateHeader(request.header, .capability_pass);
        return self.kernel.capabilityPass(
            request.capability_id,
            request.receiver_task_id,
            now_ticks,
            request.revoke_source,
        );
    }

    pub fn capabilityRevoke(self: *KernelPort, request: CapabilityRevokeRequest, now_ticks: u64) Error!void {
        try validateHeader(request.header, .capability_revoke);
        return self.kernel.capabilityRevoke(request.authority_capability_id, request.capability_id, now_ticks);
    }

    pub fn capabilityQuery(
        self: *KernelPort,
        request: CapabilityQueryRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try validateHeader(request.header, .capability_query);
        return self.kernel.capabilityQuery(request.authority_capability_id, request.capability_id, now_ticks);
    }

    pub fn sharedMemoryCreate(
        self: *KernelPort,
        request: SharedMemoryCreateRequest,
        now_ticks: u64,
    ) Error!native_kernel.SharedMemoryCreateResult {
        try validateHeader(request.header, .shared_memory_create);
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
        return self.kernel.sharedMemoryMap(request.shared_memory_capability_id, request.task_id, now_ticks);
    }

    pub fn sharedMemoryUnmap(self: *KernelPort, request: SharedMemoryUnmapRequest, now_ticks: u64) Error!bool {
        try validateHeader(request.header, .shared_memory_unmap);
        return self.kernel.sharedMemoryUnmap(request.shared_memory_capability_id, request.task_id, now_ticks);
    }

    pub fn sharedMemoryRevoke(
        self: *KernelPort,
        request: SharedMemoryRevokeRequest,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        try validateHeader(request.header, .shared_memory_revoke);
        return self.kernel.sharedMemoryRevoke(request.shared_memory_capability_id, now_ticks);
    }

    pub fn timeQuery(self: *KernelPort, request: TimeQueryRequest, now_ticks: u64) Error!u64 {
        try validateHeader(request.header, .time_query);
        return self.kernel.timeQuery(request.authority_capability_id, now_ticks);
    }

    pub fn resourceQuery(
        self: *KernelPort,
        request: ResourceQueryRequest,
        now_ticks: u64,
    ) Error!abi.ResourceDescriptor {
        try validateHeader(request.header, .resource_query);
        return self.kernel.resourceQuery(request.authority_capability_id, request.task_id, now_ticks);
    }

    pub fn accountingQuery(
        self: *KernelPort,
        request: AccountingQueryRequest,
        now_ticks: u64,
    ) Error!abi.AccountingDescriptor {
        try validateHeader(request.header, .accounting_query);
        return self.kernel.accountingQuery(request.authority_capability_id, request.task_id, now_ticks);
    }

    pub fn serviceRegister(self: *KernelPort, request: ServiceRegisterRequest, now_ticks: u64) Error!void {
        try validateHeader(request.header, .service_register);
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
        return self.kernel.serviceConnect(
            request.authority_capability_id,
            request.endpoint_capability_id,
            request.interface,
            now_ticks,
        );
    }
};

pub fn makeHeader(operation: abi.NativeOperation, correlation_id: u64, subject_task_id: u64) abi.RequestHeader {
    return .{
        .operation = abi.opcode(operation),
        .correlation_id = correlation_id,
        .subject_task_id = subject_task_id,
    };
}

fn validateHeader(header: abi.RequestHeader, expected: abi.NativeOperation) Error!void {
    if (header.version != abi.ABI_VERSION) return error.UnsupportedAbiVersion;
    if (header.operation != abi.opcode(expected)) return error.UnexpectedOperation;
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
        },
    }, 5);
    try std.testing.expect(task.task_id != 0);

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
