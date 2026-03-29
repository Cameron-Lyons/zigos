const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const endpoint = @import("endpoint.zig");
const native_kernel = @import("native_kernel.zig");
const service_registry = @import("service_registry.zig");
const shared_memory = @import("shared_memory.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub const DispatchResult = struct {
    status: abi.SyscallStatus,
    bytes_written: u32 = 0,
    denial_reason: abi.DenialReason = .none,
};

pub fn dispatch(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const header = requestPtr(abi.RequestHeader, request_addr) orelse return .{
        .status = .invalid_request_pointer,
    };
    if (header.version != abi.ABI_VERSION) return .{
        .status = .unsupported_abi_version,
    };

    const operation = nativeOperationFromOpcode(header.operation) orelse return .{
        .status = .unsupported_operation,
        .denial_reason = .unsupported_operation,
    };

    return switch (operation) {
        .task_create => dispatchTaskCreate(port, now_ticks, request_addr, response_addr, response_len),
        .task_terminate => dispatchTaskTerminate(port, now_ticks, request_addr, response_addr, response_len),
        .endpoint_create => dispatchEndpointCreate(port, now_ticks, request_addr, response_addr, response_len),
        .endpoint_connect => dispatchEndpointConnect(port, now_ticks, request_addr, response_addr, response_len),
        .endpoint_send => dispatchEndpointSend(port, now_ticks, request_addr),
        .endpoint_recv => dispatchEndpointRecv(port, now_ticks, request_addr, response_addr, response_len),
        .capability_mint => dispatchCapabilityMint(port, now_ticks, request_addr, response_addr, response_len),
        .capability_derive => dispatchCapabilityDerive(port, request_addr, response_addr, response_len),
        .capability_pass => dispatchCapabilityPass(port, now_ticks, request_addr, response_addr, response_len),
        .capability_revoke => dispatchCapabilityRevoke(port, now_ticks, request_addr),
        .capability_query => dispatchCapabilityQuery(port, now_ticks, request_addr, response_addr, response_len),
        .shared_memory_create => dispatchSharedMemoryCreate(port, now_ticks, request_addr, response_addr, response_len),
        .shared_memory_map => dispatchSharedMemoryMap(port, now_ticks, request_addr, response_addr, response_len),
        .shared_memory_unmap => dispatchSharedMemoryUnmap(port, now_ticks, request_addr, response_addr, response_len),
        .shared_memory_revoke => dispatchSharedMemoryRevoke(port, now_ticks, request_addr, response_addr, response_len),
        .time_query => dispatchTimeQuery(port, now_ticks, request_addr, response_addr, response_len),
        .resource_query => dispatchResourceQuery(port, now_ticks, request_addr, response_addr, response_len),
        .accounting_query => dispatchAccountingQuery(port, now_ticks, request_addr, response_addr, response_len),
        .service_register => dispatchServiceRegister(port, now_ticks, request_addr),
        .service_connect => dispatchServiceConnect(port, now_ticks, request_addr, response_addr, response_len),
    };
}

fn dispatchTaskCreate(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.TaskCreateRequest, request_addr) orelse return invalidRequest();
    const task = port.taskCreate(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, task);
}

fn dispatchTaskTerminate(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.TaskTerminateRequest, request_addr) orelse return invalidRequest();
    const terminated = port.taskTerminate(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, abi.BoolResponse{
        .value = @intFromBool(terminated),
        ._reserved = [_]u8{0} ** 7,
    });
}

fn dispatchEndpointCreate(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.EndpointCreateRequest, request_addr) orelse return invalidRequest();
    const created = port.endpointCreate(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, abi.EndpointCreateResponse{
        .endpoint = created.endpoint,
        .capability = created.capability,
        .capability_id = created.capability_id,
    });
}

fn dispatchEndpointConnect(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.EndpointConnectRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.endpointConnect(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchEndpointSend(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
) DispatchResult {
    const request = requestPtr(component_port.EndpointSendRequest, request_addr) orelse return invalidRequest();
    port.endpointSend(request.*, now_ticks) catch |err| return mapError(err);
    return success();
}

fn dispatchEndpointRecv(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.EndpointRecvRequest, request_addr) orelse return invalidRequest();
    const received = port.endpointRecv(request.*, now_ticks) catch |err| return mapError(err);

    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    if (received) |message| {
        response.present = 1;
        response.has_attached_capability = @intFromBool(message.attached_capability != null);
        response.message = message.message;
        @memcpy(response.payload[0..message.payload_len], message.payload[0..message.payload_len]);
        if (message.attached_capability) |attached| {
            response.attached_capability = attached;
        }
    }
    return writeResponse(response_addr, response_len, response);
}

fn dispatchCapabilityMint(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.CapabilityMintRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.capabilityMint(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchCapabilityDerive(
    port: *component_port.KernelPort,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.CapabilityDeriveRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.capabilityDerive(request.*) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchCapabilityPass(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.CapabilityPassRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.capabilityPass(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchCapabilityRevoke(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
) DispatchResult {
    const request = requestPtr(component_port.CapabilityRevokeRequest, request_addr) orelse return invalidRequest();
    port.capabilityRevoke(request.*, now_ticks) catch |err| return mapError(err);
    return success();
}

fn dispatchCapabilityQuery(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.CapabilityQueryRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.capabilityQuery(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchSharedMemoryCreate(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.SharedMemoryCreateRequest, request_addr) orelse return invalidRequest();
    const created = port.sharedMemoryCreate(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, abi.SharedMemoryCreateResponse{
        .object = created.object,
        .capability = created.capability,
        .capability_id = created.capability_id,
    });
}

fn dispatchSharedMemoryMap(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.SharedMemoryMapRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.sharedMemoryMap(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchSharedMemoryUnmap(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.SharedMemoryUnmapRequest, request_addr) orelse return invalidRequest();
    const unmapped = port.sharedMemoryUnmap(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, abi.BoolResponse{
        .value = @intFromBool(unmapped),
        ._reserved = [_]u8{0} ** 7,
    });
}

fn dispatchSharedMemoryRevoke(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.SharedMemoryRevokeRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.sharedMemoryRevoke(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchTimeQuery(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.TimeQueryRequest, request_addr) orelse return invalidRequest();
    const queried = port.timeQuery(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, abi.TimeQueryResponse{
        .now_ticks = queried,
    });
}

fn dispatchResourceQuery(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.ResourceQueryRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.resourceQuery(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchAccountingQuery(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.AccountingQueryRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.accountingQuery(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchServiceRegister(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
) DispatchResult {
    const request = requestPtr(component_port.ServiceRegisterRequest, request_addr) orelse return invalidRequest();
    port.serviceRegister(request.*, now_ticks) catch |err| return mapError(err);
    return success();
}

fn dispatchServiceConnect(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = requestPtr(component_port.ServiceConnectRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.serviceConnect(request.*, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn requestPtr(comptime T: type, request_addr: usize) ?*const T {
    if (request_addr == 0) return null;
    if (request_addr % @alignOf(T) != 0) return null;
    return @ptrFromInt(request_addr);
}

fn nativeOperationFromOpcode(opcode: u16) ?abi.NativeOperation {
    inline for (std.meta.fields(abi.NativeOperation)) |field| {
        if (field.value == opcode) {
            return @field(abi.NativeOperation, field.name);
        }
    }
    return null;
}

fn responseBuffer(response_addr: usize, response_len: usize) ?[]u8 {
    if (response_len == 0) return &[_]u8{};
    if (response_addr == 0) return null;
    const bytes: [*]u8 = @ptrFromInt(response_addr);
    return bytes[0..response_len];
}

fn writeResponse(response_addr: usize, response_len: usize, value: anytype) DispatchResult {
    const buffer = responseBuffer(response_addr, response_len) orelse return .{
        .status = .invalid_response_buffer,
    };
    const bytes = std.mem.asBytes(&value);
    if (buffer.len < bytes.len) return .{
        .status = .buffer_too_small,
    };
    @memcpy(buffer[0..bytes.len], bytes);
    return .{
        .status = .success,
        .bytes_written = @intCast(bytes.len),
    };
}

fn success() DispatchResult {
    return .{ .status = .success };
}

fn invalidRequest() DispatchResult {
    return .{ .status = .invalid_request_pointer };
}

fn mapError(err: anyerror) DispatchResult {
    if (err == error.UnsupportedAbiVersion) return .{ .status = .unsupported_abi_version };
    if (err == error.UnexpectedOperation) return .{
        .status = .unsupported_operation,
        .denial_reason = .unsupported_operation,
    };
    if (err == error.PermissionDenied or err == error.RightsEscalation) return .{
        .status = .denied,
        .denial_reason = .policy_denied,
    };
    if (err == error.UserspaceLaunchRequired or err == error.InvalidUserspaceImage) return .{
        .status = .denied,
        .denial_reason = .policy_denied,
    };
    if (err == error.CapabilityNotFound) return .{
        .status = .not_found,
        .denial_reason = .capability_missing,
    };
    if (err == error.CapabilityRevoked) return .{
        .status = .denied,
        .denial_reason = .capability_revoked,
    };
    if (err == error.ScopeViolation or err == error.ScopeEscalation) return .{
        .status = .denied,
        .denial_reason = .scope_violation,
    };
    if (err == error.LeaseEscalation) return .{
        .status = .denied,
        .denial_reason = .capability_expired,
    };
    if (err == error.InvalidCapabilityTarget) return .{
        .status = .denied,
        .denial_reason = .invalid_target,
    };
    if (err == error.InterfaceNotFound) return .{
        .status = .not_found,
        .denial_reason = .interface_not_found,
    };
    if (err == error.TaskNotFound or err == error.EndpointNotFound) return .{
        .status = .not_found,
        .denial_reason = .invalid_target,
    };
    if (err == error.TableFull or
        err == error.TargetTableFull or
        err == error.BindingTableFull or
        err == error.ComponentTableFull or
        err == error.CapabilityTableFull or
        err == error.TaskTableFull or
        err == error.EndpointBusy or
        err == error.QueueFull or
        err == error.PeerNotConnected or
        err == error.VersionMismatch)
    {
        return .{
            .status = .conflict,
            .denial_reason = .budget_exhausted,
        };
    }

    return .{ .status = .internal_error };
}

const TestKernel = struct {
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    shared: shared_memory.Table = shared_memory.Table.init(),
    registry: service_registry.Registry = service_registry.Registry.init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    session_task_id: u64 = 0,
    authority_capability_id: u64 = 0,

    fn init(self: *TestKernel) !void {
        self.kernel = native_kernel.Kernel.init(
            .{ .kind = .policy_authority, .serial = 1 },
            &self.runtime,
            &self.capabilities,
            &self.endpoints,
            &self.shared,
            &self.registry,
        );
        self.port = component_port.KernelPort.init(&self.kernel);

        const session_task = try self.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = 2 },
            .component_class = .session_manager,
            .budget = .{
                .cpu_time_ticks = 10_000,
                .memory_bytes = 4096,
                .endpoint_slots = 8,
                .shared_memory_bytes = 4096,
            },
            .local_only = true,
        });
        const authority = try self.capabilities.mint(.{
            .holder = session_task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = 42 },
            .rights = .{
                .task_create = true,
                .task_terminate = true,
                .endpoint_create = true,
                .endpoint_connect = true,
                .endpoint_send = true,
                .endpoint_recv = true,
                .shared_memory_create = true,
                .shared_memory_map = true,
                .shared_memory_unmap = true,
                .shared_memory_revoke = true,
                .resource_query = true,
                .accounting_query = true,
                .time_query = true,
                .ipc_peer = true,
                .capability_query = true,
            },
            .scope = .{ .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
        });
        self.session_task_id = session_task.id;
        self.authority_capability_id = authority.id;
    }
};

test "syscall surface dispatches typed task creation requests" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 77, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 9 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
                .resource_class = .batch_compute,
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 21,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.syscall",
            },
            .userspace_image = task_runtime.syntheticUserspaceImage("syscall-test", "app.example.syscall"),
        },
    };

    const result = dispatch(
        &test_kernel.port,
        5,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );

    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, @sizeOf(abi.TaskDescriptor)), result.bytes_written);
    try std.testing.expectEqual(abi.DenialReason.none, result.denial_reason);
    try std.testing.expect(response.task_id != 0);
    try std.testing.expectEqual(@as(u16, @intFromEnum(task_runtime.ComponentClass.app_component)), response.component_class);
    try std.testing.expect(abi.taskFlagsHas(response.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(abi.taskFlagsHas(response.flags, abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED));
    try std.testing.expectEqual(@as(u8, @intFromEnum(accelerator_scheduler.ResourceClass.batch_compute)), abi.taskFlagsResourceClass(response.flags));
}

test "syscall surface returns an explicit empty receive response when no message is queued" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const app_task = try test_kernel.port.taskCreate(.{
        .header = component_port.makeHeader(.task_create, 88, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 10 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 22,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.empty-queue",
            },
            .userspace_image = task_runtime.syntheticUserspaceImage("empty-queue", "app.example.empty-queue"),
        },
    }, 6);
    const created = try test_kernel.port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 89, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .owner_task_id = app_task.task_id,
        .label = "empty-queue",
        .flags = .{ .local_only = true },
    }, 7);

    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    const request = component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, 90, app_task.task_id),
        .endpoint_capability_id = created.capability_id,
        .receiver_task_id = app_task.task_id,
    };

    const result = dispatch(
        &test_kernel.port,
        8,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointRecvResponse),
    );

    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, @sizeOf(abi.EndpointRecvResponse)), result.bytes_written);
    try std.testing.expectEqual(@as(u8, 0), response.present);
    try std.testing.expectEqual(@as(u8, 0), response.has_attached_capability);
}

test "syscall surface denies task creation without userspace launch provenance" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 91, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 12 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
            },
            .local_only = true,
        },
    };

    const result = dispatch(
        &test_kernel.port,
        9,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );

    try std.testing.expectEqual(abi.SyscallStatus.denied, result.status);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, result.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
}

test "syscall surface rejects unsupported native operations" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const request = abi.RequestHeader{
        .operation = 0xFFFF,
        .correlation_id = 91,
        .subject_task_id = test_kernel.session_task_id,
    };
    const result = dispatch(&test_kernel.port, 9, @intFromPtr(&request), 0, 0);

    try std.testing.expectEqual(abi.SyscallStatus.unsupported_operation, result.status);
    try std.testing.expectEqual(abi.DenialReason.unsupported_operation, result.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
}
