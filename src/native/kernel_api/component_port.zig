const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const endpoint = @import("endpoint.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("../task/generated_image_fixtures.zig") else struct {};
const native_kernel = @import("native_kernel.zig");
const operation_metadata = @import("operation_metadata.zig");
const request_header = @import("../core/request_header.zig");
const shared_memory = @import("shared_memory.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");

pub const Error = native_kernel.Error || error{
    UnexpectedOperation,
    SubjectTaskRequired,
    SubjectTaskMismatch,
    UnsupportedAbiVersion,
};
const TEST_PORT_TASK_BYTES: usize = 512;
pub const PREVALIDATED_SYSCALL_HEADER_RECHECKS: u8 = 0;

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
    peer_endpoint_capability_id: u64,
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
    payload_out: []u8,
    attached_capability_out: *abi.CapabilityDescriptor,
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

pub const InputRecvRequest = struct {
    header: abi.RequestHeader,
    input_capability_id: u64,
    receiver_task_id: u64,
};

pub const SurfacePresentRequest = struct {
    header: abi.RequestHeader,
    presentation_capability_id: u64,
    presenter_task_id: u64,
    presentation: abi.SurfacePresentation,
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

pub const KernelPort = struct {
    kernel: *native_kernel.Kernel,
    syscall_header_prevalidated: bool = false,

    pub fn init(kernel: *native_kernel.Kernel) KernelPort {
        return .{ .kernel = kernel };
    }

    fn validateIncomingHeader(
        self: *const KernelPort,
        header: abi.RequestHeader,
        comptime expected: abi.NativeOperation,
    ) Error!void {
        if (self.syscall_header_prevalidated) return;
        return validateHeader(header, expected);
    }

    pub fn taskCreate(self: *KernelPort, request: TaskCreateRequest, now_ticks: u64) Error!abi.TaskDescriptor {
        try self.validateIncomingHeader(request.header, .task_create);
        return self.kernel.taskCreate(
            callContext(request.header, request.authority_capability_id, .{ .task = 0 }),
            request.request,
            now_ticks,
        );
    }

    pub fn taskTerminate(self: *KernelPort, request: TaskTerminateRequest, now_ticks: u64) Error!bool {
        try self.validateIncomingHeader(request.header, .task_terminate);
        return self.kernel.taskTerminate(
            callContext(request.header, request.task_capability_id, .none),
            now_ticks,
        );
    }

    pub fn endpointCreate(
        self: *KernelPort,
        request: EndpointCreateRequest,
        now_ticks: u64,
    ) Error!native_kernel.EndpointCreateResult {
        try self.validateIncomingHeader(request.header, .endpoint_create);
        return self.kernel.endpointCreate(
            callContext(request.header, request.authority_capability_id, .{ .task = request.owner_task_id }),
            request.owner_task_id,
            request.label,
            request.flags,
            now_ticks,
        );
    }

    pub fn endpointConnect(self: *KernelPort, request: EndpointConnectRequest, now_ticks: u64) Error!abi.EndpointDescriptor {
        try self.validateIncomingHeader(request.header, .endpoint_connect);
        return self.kernel.endpointConnect(
            callContext(request.header, request.endpoint_capability_id, .none),
            request.peer_endpoint_capability_id,
            request.peer_endpoint_id,
            now_ticks,
        );
    }

    pub fn endpointSend(self: *KernelPort, request: EndpointSendRequest, now_ticks: u64) Error!void {
        try self.validateIncomingHeader(request.header, .endpoint_send);
        try validateOptionalCallerCapability(self, request.header, request.attached_capability_id, now_ticks);
        return self.kernel.endpointSend(
            callContext(request.header, request.endpoint_capability_id, .none),
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
        try self.validateIncomingHeader(request.header, .endpoint_recv);
        try validateSubjectTask(request.header, request.receiver_task_id);
        const received = try self.kernel.endpointRecv(
            callContext(request.header, request.endpoint_capability_id, .none),
            request.receiver_task_id,
            request.payload_out,
            now_ticks,
        );
        if (received) |message| {
            if (message.attached_capability) |attached| {
                request.attached_capability_out.* = attached;
            }
            return message;
        }
        return null;
    }

    pub fn capabilityMint(
        self: *KernelPort,
        request: CapabilityMintRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try self.validateIncomingHeader(request.header, .capability_mint);
        return self.kernel.capabilityMint(
            callContext(request.header, request.policy_capability_id, .none),
            request.request,
            now_ticks,
        );
    }

    pub fn capabilityDerive(self: *KernelPort, request: CapabilityDeriveRequest) Error!abi.CapabilityDescriptor {
        try self.validateIncomingHeader(request.header, .capability_derive);
        return self.kernel.capabilityDerive(
            callContext(request.header, request.request.parent_capability_id, .none),
            request.request,
        );
    }

    pub fn capabilityPass(
        self: *KernelPort,
        request: CapabilityPassRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try self.validateIncomingHeader(request.header, .capability_pass);
        return self.kernel.capabilityPass(
            callContext(request.header, request.capability_id, .none),
            request.receiver_task_id,
            now_ticks,
            request.revoke_source,
        );
    }

    pub fn capabilityRevoke(self: *KernelPort, request: CapabilityRevokeRequest, now_ticks: u64) Error!void {
        try self.validateIncomingHeader(request.header, .capability_revoke);
        return self.kernel.capabilityRevoke(
            callContext(request.header, request.authority_capability_id, .{ .capability = request.capability_id }),
            request.capability_id,
            now_ticks,
        );
    }

    pub fn capabilityQuery(
        self: *KernelPort,
        request: CapabilityQueryRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try self.validateIncomingHeader(request.header, .capability_query);
        return self.kernel.capabilityQuery(
            callContext(request.header, request.authority_capability_id, .{ .capability = request.capability_id }),
            request.capability_id,
            now_ticks,
        );
    }

    pub fn sharedMemoryCreate(
        self: *KernelPort,
        request: SharedMemoryCreateRequest,
        now_ticks: u64,
    ) Error!native_kernel.SharedMemoryCreateResult {
        try self.validateIncomingHeader(request.header, .shared_memory_create);
        return self.kernel.sharedMemoryCreate(
            callContext(request.header, request.authority_capability_id, .{ .task = request.owner_task_id }),
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
        try self.validateIncomingHeader(request.header, .shared_memory_map);
        try validateSubjectTask(request.header, request.task_id);
        return self.kernel.sharedMemoryMap(
            callContext(request.header, request.shared_memory_capability_id, .none),
            request.task_id,
            now_ticks,
        );
    }

    pub fn sharedMemoryUnmap(self: *KernelPort, request: SharedMemoryUnmapRequest, now_ticks: u64) Error!bool {
        try self.validateIncomingHeader(request.header, .shared_memory_unmap);
        try validateSubjectTask(request.header, request.task_id);
        return self.kernel.sharedMemoryUnmap(
            callContext(request.header, request.shared_memory_capability_id, .none),
            request.task_id,
            now_ticks,
        );
    }

    pub fn sharedMemoryRevoke(
        self: *KernelPort,
        request: SharedMemoryRevokeRequest,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        try self.validateIncomingHeader(request.header, .shared_memory_revoke);
        return self.kernel.sharedMemoryRevoke(
            callContext(request.header, request.shared_memory_capability_id, .none),
            now_ticks,
        );
    }

    pub fn timeQuery(self: *KernelPort, request: TimeQueryRequest, now_ticks: u64) Error!u64 {
        try self.validateIncomingHeader(request.header, .time_query);
        return self.kernel.timeQuery(callContext(request.header, request.authority_capability_id, .none), now_ticks);
    }

    pub fn resourceQuery(
        self: *KernelPort,
        request: ResourceQueryRequest,
        now_ticks: u64,
    ) Error!abi.ResourceDescriptor {
        try self.validateIncomingHeader(request.header, .resource_query);
        return self.kernel.resourceQuery(
            callContext(request.header, request.authority_capability_id, .{ .task = request.task_id }),
            request.task_id,
            now_ticks,
        );
    }

    pub fn accountingQuery(
        self: *KernelPort,
        request: AccountingQueryRequest,
        now_ticks: u64,
    ) Error!abi.AccountingDescriptor {
        try self.validateIncomingHeader(request.header, .accounting_query);
        return self.kernel.accountingQuery(
            callContext(request.header, request.authority_capability_id, .{ .task = request.task_id }),
            request.task_id,
            now_ticks,
        );
    }

    pub fn inputRecv(
        self: *KernelPort,
        request: InputRecvRequest,
        now_ticks: u64,
    ) Error!?abi.InputEventDescriptor {
        try self.validateIncomingHeader(request.header, .input_recv);
        try validateSubjectTask(request.header, request.receiver_task_id);
        return self.kernel.inputRecv(
            callContext(request.header, request.input_capability_id, .{ .task = request.receiver_task_id }),
            request.receiver_task_id,
            now_ticks,
        );
    }

    pub fn surfacePresent(
        self: *KernelPort,
        request: SurfacePresentRequest,
        now_ticks: u64,
    ) Error!bool {
        try self.validateIncomingHeader(request.header, .surface_present);
        try validateSubjectTask(request.header, request.presenter_task_id);
        return self.kernel.surfacePresent(
            callContext(request.header, request.presentation_capability_id, .{ .task = request.presenter_task_id }),
            request.presenter_task_id,
            &request.presentation,
            now_ticks,
        );
    }

    pub fn deviceDescribe(
        self: *KernelPort,
        request: DeviceDescribeRequest,
        now_ticks: u64,
    ) Error!abi.DeviceDescriptor {
        try self.validateIncomingHeader(request.header, .device_describe);
        return self.kernel.deviceDescribe(callContext(request.header, request.device_capability_id, .none), now_ticks);
    }

    pub fn deviceMmioWindow(
        self: *KernelPort,
        request: DeviceMmioWindowRequest,
        now_ticks: u64,
    ) Error!abi.DeviceMmioWindowDescriptor {
        try self.validateIncomingHeader(request.header, .device_mmio_window);
        return self.kernel.deviceMmioWindow(
            callContext(request.header, request.device_capability_id, .none),
            request.window_index,
            now_ticks,
        );
    }
};

pub const GeneratedWrapper = struct {
    operation: abi.NativeOperation,
    request_type_name: []const u8,
    response_type_name: []const u8,
    port_method_name: []const u8,
    port_invocation: operation_metadata.PortInvocation,
    request_size: usize,
    wire_response_size: usize,
};

fn requestTypeForName(comptime type_name: []const u8) type {
    if (!@hasDecl(@This(), type_name)) {
        @compileError("missing component-port request type " ++ type_name);
    }
    return @field(@This(), type_name);
}

fn wireResponseTypeForName(comptime type_name: []const u8) type {
    if (std.mem.eql(u8, type_name, "void")) return void;
    if (!@hasDecl(abi, type_name)) {
        @compileError("missing syscall ABI response type " ++ type_name);
    }
    return @field(abi, type_name);
}

pub fn PortRequest(comptime operation: abi.NativeOperation) type {
    const descriptor = comptime operation_metadata.declarationFor(operation);
    return requestTypeForName(descriptor.binding.request_type_name);
}

pub fn PortWireResponse(comptime operation: abi.NativeOperation) type {
    const descriptor = comptime operation_metadata.declarationFor(operation);
    return wireResponseTypeForName(descriptor.binding.response_type_name);
}

fn assertPortWrapperShape(comptime descriptor: operation_metadata.Descriptor) void {
    const Request = requestTypeForName(descriptor.binding.request_type_name);
    if (!@hasDecl(KernelPort, descriptor.binding.port_method_name)) {
        @compileError("missing KernelPort method " ++ descriptor.binding.port_method_name);
    }
    const method = @field(KernelPort, descriptor.binding.port_method_name);
    const method_info = @typeInfo(@TypeOf(method)).@"fn";
    const expected_params: usize = switch (descriptor.binding.port_invocation) {
        .with_now_ticks => 3,
        .without_now_ticks => 2,
    };
    if (method_info.params.len != expected_params) {
        @compileError("KernelPort method has wrong arity for " ++ @tagName(descriptor.operation));
    }
    if (method_info.params[0].type.? != *KernelPort) {
        @compileError("KernelPort method has wrong receiver for " ++ @tagName(descriptor.operation));
    }
    if (method_info.params[1].type.? != Request) {
        @compileError("KernelPort method has wrong request type for " ++ @tagName(descriptor.operation));
    }
    if (descriptor.binding.port_invocation == .with_now_ticks and method_info.params[2].type.? != u64) {
        @compileError("KernelPort method must accept now_ticks for " ++ @tagName(descriptor.operation));
    }
}

pub fn PortCallResult(comptime operation: abi.NativeOperation) type {
    const descriptor = comptime operation_metadata.declarationFor(operation);
    assertPortWrapperShape(descriptor);
    return @typeInfo(@TypeOf(@field(KernelPort, descriptor.binding.port_method_name))).@"fn".return_type.?;
}

pub fn invokeGenerated(
    comptime operation: abi.NativeOperation,
    self: *KernelPort,
    request: PortRequest(operation),
    now_ticks: u64,
) PortCallResult(operation) {
    const descriptor = comptime operation_metadata.declarationFor(operation);
    const method = @field(KernelPort, descriptor.binding.port_method_name);
    return switch (descriptor.binding.port_invocation) {
        .with_now_ticks => method(self, request, now_ticks),
        .without_now_ticks => method(self, request),
    };
}

pub fn invokeGeneratedFromValidatedSyscall(
    comptime operation: abi.NativeOperation,
    self: *KernelPort,
    request: PortRequest(operation),
    now_ticks: u64,
) PortCallResult(operation) {
    var validated_port = self.*;
    validated_port.syscall_header_prevalidated = true;
    return invokeGenerated(operation, &validated_port, request, now_ticks);
}

fn generatedWrapperFromMetadata(comptime descriptor: operation_metadata.Descriptor) GeneratedWrapper {
    assertPortWrapperShape(descriptor);
    const Request = requestTypeForName(descriptor.binding.request_type_name);
    const Response = wireResponseTypeForName(descriptor.binding.response_type_name);
    return .{
        .operation = descriptor.operation,
        .request_type_name = descriptor.binding.request_type_name,
        .response_type_name = descriptor.binding.response_type_name,
        .port_method_name = descriptor.binding.port_method_name,
        .port_invocation = descriptor.binding.port_invocation,
        .request_size = @sizeOf(Request),
        .wire_response_size = if (Response == void) 0 else @sizeOf(Response),
    };
}

fn buildGeneratedWrappers() [operation_metadata.operations.len]GeneratedWrapper {
    var table: [operation_metadata.operations.len]GeneratedWrapper = undefined;
    inline for (operation_metadata.operations, 0..) |descriptor, index| {
        table[index] = generatedWrapperFromMetadata(descriptor);
    }
    return table;
}

pub const generated_wrappers = buildGeneratedWrappers();

pub fn generatedWrapperFor(comptime operation: abi.NativeOperation) GeneratedWrapper {
    inline for (generated_wrappers) |wrapper| {
        if (wrapper.operation == operation) return wrapper;
    }
    @compileError("missing generated KernelPort wrapper for " ++ @tagName(operation));
}

pub fn makeHeader(operation: abi.NativeOperation, correlation_id: u64, subject_task_id: u64) abi.RequestHeader {
    return request_header.makeHeader(abi.opcode(operation), correlation_id, subject_task_id);
}

fn validateHeader(header: abi.RequestHeader, comptime expected: abi.NativeOperation) Error!void {
    const descriptor = operation_metadata.declarationFor(expected);
    try request_header.validateHeader(header, abi.opcode(descriptor.operation));
    if (header.subject_task_id == 0) return error.SubjectTaskRequired;
}

fn validateSubjectTask(header: abi.RequestHeader, task_id: u64) Error!void {
    try request_header.validateSubjectTask(header, task_id);
}

fn callContext(
    header: abi.RequestHeader,
    presented_capability_id: u64,
    target: native_kernel.KernelTarget,
) native_kernel.KernelCallContext {
    return .{
        .caller_task_id = header.subject_task_id,
        .presented_capability_id = presented_capability_id,
        .operation = @as(abi.NativeOperation, @enumFromInt(header.operation)),
        .target = target,
    };
}

fn validateCallerCapability(
    self: *KernelPort,
    header: abi.RequestHeader,
    capability_id: u64,
    now_ticks: u64,
) Error!void {
    if (header.subject_task_id == 0) return error.SubjectTaskRequired;
    _ = try self.kernel.requireTaskCapability(header.subject_task_id, capability_id, now_ticks);
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

test "kernel port generated wrappers cover operation metadata" {
    try std.testing.expectEqual(operation_metadata.operations.len, generated_wrappers.len);
    inline for (operation_metadata.operations) |descriptor| {
        const wrapper = generatedWrapperFor(descriptor.operation);
        try std.testing.expectEqual(descriptor.operation, wrapper.operation);
        try std.testing.expectEqualStrings(descriptor.binding.request_type_name, wrapper.request_type_name);
        try std.testing.expectEqualStrings(descriptor.binding.response_type_name, wrapper.response_type_name);
        try std.testing.expectEqualStrings(descriptor.binding.port_method_name, wrapper.port_method_name);
        try std.testing.expectEqual(descriptor.binding.port_invocation, wrapper.port_invocation);
        try std.testing.expectEqual(@sizeOf(PortRequest(descriptor.operation)), wrapper.request_size);
        const Response = PortWireResponse(descriptor.operation);
        try std.testing.expectEqual(if (Response == void) @as(usize, 0) else @sizeOf(Response), wrapper.wire_response_size);
    }
    try std.testing.expectEqual(operation_metadata.PortInvocation.without_now_ticks, generatedWrapperFor(.capability_derive).port_invocation);
}

test "kernel port enforces operation ids and forwards typed task create requests" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = native_kernel.Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    var port = KernelPort.init(&kernel);

    const session_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 1 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 10_000,
            .memory_bytes = shared_memory.PAGE_SIZE,
            .endpoint_slots = 8,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
        },
        .local_only = true,
    });
    const authority_capability = try capabilities.mintBootRoot(.{
        .holder = session_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .task_create = true } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });
    try runtime.grantCapability(session_task.id, authority_capability.id);

    const port_test_image = try generated_image_fixtures.appImage();
    const task = try invokeGenerated(.task_create, &port, .{
        .header = makeHeader(.task_create, 77, session_task.id),
        .authority_capability_id = authority_capability.id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 2 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = TEST_PORT_TASK_BYTES,
                .endpoint_slots = 2,
                .shared_memory_bytes = TEST_PORT_TASK_BYTES,
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
                .memory_bytes = TEST_PORT_TASK_BYTES,
                .endpoint_slots = 2,
                .shared_memory_bytes = TEST_PORT_TASK_BYTES,
            },
            .local_only = true,
        },
    }, 6));
    try std.testing.expectError(error.SubjectTaskRequired, port.taskCreate(.{
        .header = makeHeader(.task_create, 79, 0),
        .authority_capability_id = authority_capability.id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 4 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = TEST_PORT_TASK_BYTES,
                .endpoint_slots = 2,
                .shared_memory_bytes = TEST_PORT_TASK_BYTES,
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
    var shared = shared_memory.Table.init();
    var kernel = native_kernel.Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    var port = KernelPort.init(&kernel);

    const kernel_port_device_image = try generated_image_fixtures.storageDriverImage();
    const driver_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 8 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
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
    const device_capability = try capabilities.mintBootRoot(.{
        .holder = driver_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .device, .id = 0x1F001 },
        .rights = .{ .device = .{ .device_use = true } },
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
    try std.testing.expect(device_broker.publishPciController(0x1F001));

    const descriptor = try port.deviceDescribe(.{
        .header = makeHeader(.device_describe, 81, driver_task.id),
        .device_capability_id = device_capability.id,
    }, 7);
    try std.testing.expectEqual(@as(u64, 0x1F001), descriptor.device_id);

    try std.testing.expectError(error.UnexpectedOperation, port.deviceDescribe(.{
        .header = makeHeader(.task_create, 84, driver_task.id),
        .device_capability_id = device_capability.id,
    }, 7));
}
