const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const endpoint = @import("endpoint.zig");
const native_kernel = @import("native_kernel.zig");
const service_registry = @import("service_registry.zig");
const shared_memory = @import("shared_memory.zig");
const task_runtime = @import("../task/task_runtime.zig");

const USER_POINTER_FLOOR: usize = 0x10000;
const USER_POINTER_CEILING_32: usize = 0xC0000000;
const MAX_COMPONENT_LABEL_BYTES: usize = 48;
const MAX_COMPONENT_ENTRY_BYTES: usize = 64;

pub const DispatchResult = struct {
    status: abi.SyscallStatus,
    bytes_written: u32 = 0,
    denial_reason: abi.DenialReason = .none,
};

pub fn dispatch(
    port: *component_port.KernelPort,
    caller_task_id: u64,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const header = readRequest(abi.RequestHeader, request_addr) orelse return .{
        .status = .invalid_request_pointer,
    };
    if (header.version != abi.ABI_VERSION) return .{
        .status = .unsupported_abi_version,
    };
    if (caller_task_id != 0 and header.subject_task_id != caller_task_id) return .{
        .status = .denied,
        .denial_reason = .scope_violation,
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
        .device_describe => dispatchDeviceDescribe(port, now_ticks, request_addr, response_addr, response_len),
        .device_mmio_window => dispatchDeviceMmioWindow(port, now_ticks, request_addr, response_addr, response_len),
        .device_port_read => dispatchDevicePortRead(port, now_ticks, request_addr, response_addr, response_len),
        .device_port_write => dispatchDevicePortWrite(port, now_ticks, request_addr),
    };
}

fn dispatchTaskCreate(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    var request = readRequest(component_port.TaskCreateRequest, request_addr) orelse return invalidRequest();
    var bundle_id_buffer: [task_runtime.MAX_TASK_BUNDLE_ID_BYTES]u8 = undefined;
    var component_label_buffer: [MAX_COMPONENT_LABEL_BYTES]u8 = undefined;
    var component_entry_buffer: [MAX_COMPONENT_ENTRY_BYTES]u8 = undefined;
    var image_copy = task_runtime.ExecutableImageSpec{};
    if (!sanitizeTaskCreateRequest(
        &request,
        &bundle_id_buffer,
        &component_label_buffer,
        &component_entry_buffer,
        &image_copy,
    )) return invalidRequest();
    const task = port.taskCreate(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, task);
}

fn dispatchTaskTerminate(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.TaskTerminateRequest, request_addr) orelse return invalidRequest();
    const terminated = port.taskTerminate(request, now_ticks) catch |err| return mapError(err);
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
    var request = readRequest(component_port.EndpointCreateRequest, request_addr) orelse return invalidRequest();
    var label_buffer: [MAX_COMPONENT_LABEL_BYTES]u8 = undefined;
    request.label = copyUserSlice(request.label, &label_buffer) orelse return invalidRequest();
    const created = port.endpointCreate(request, now_ticks) catch |err| return mapError(err);
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
    const request = readRequest(component_port.EndpointConnectRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.endpointConnect(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchEndpointSend(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
) DispatchResult {
    var request = readRequest(component_port.EndpointSendRequest, request_addr) orelse return invalidRequest();
    var payload_buffer: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    request.payload = copyUserSlice(request.payload, &payload_buffer) orelse return invalidRequest();
    port.endpointSend(request, now_ticks) catch |err| return mapError(err);
    return success();
}

fn dispatchEndpointRecv(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.EndpointRecvRequest, request_addr) orelse return invalidRequest();
    const received = port.endpointRecv(request, now_ticks) catch |err| return mapError(err);

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
    const request = readRequest(component_port.CapabilityMintRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.capabilityMint(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchCapabilityDerive(
    port: *component_port.KernelPort,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.CapabilityDeriveRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.capabilityDerive(request) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchCapabilityPass(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.CapabilityPassRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.capabilityPass(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchCapabilityRevoke(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
) DispatchResult {
    const request = readRequest(component_port.CapabilityRevokeRequest, request_addr) orelse return invalidRequest();
    port.capabilityRevoke(request, now_ticks) catch |err| return mapError(err);
    return success();
}

fn dispatchCapabilityQuery(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.CapabilityQueryRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.capabilityQuery(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchSharedMemoryCreate(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.SharedMemoryCreateRequest, request_addr) orelse return invalidRequest();
    const created = port.sharedMemoryCreate(request, now_ticks) catch |err| return mapError(err);
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
    const request = readRequest(component_port.SharedMemoryMapRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.sharedMemoryMap(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchSharedMemoryUnmap(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.SharedMemoryUnmapRequest, request_addr) orelse return invalidRequest();
    const unmapped = port.sharedMemoryUnmap(request, now_ticks) catch |err| return mapError(err);
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
    const request = readRequest(component_port.SharedMemoryRevokeRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.sharedMemoryRevoke(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchTimeQuery(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.TimeQueryRequest, request_addr) orelse return invalidRequest();
    const queried = port.timeQuery(request, now_ticks) catch |err| return mapError(err);
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
    const request = readRequest(component_port.ResourceQueryRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.resourceQuery(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchAccountingQuery(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.AccountingQueryRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.accountingQuery(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchServiceRegister(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
) DispatchResult {
    var request = readRequest(component_port.ServiceRegisterRequest, request_addr) orelse return invalidRequest();
    var interface_name_buffer: [service_registry.MAX_INTERFACE_NAME_BYTES]u8 = undefined;
    request.interface.name = copyUserSlice(request.interface.name, &interface_name_buffer) orelse return invalidRequest();
    port.serviceRegister(request, now_ticks) catch |err| return mapError(err);
    return success();
}

fn dispatchServiceConnect(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    var request = readRequest(component_port.ServiceConnectRequest, request_addr) orelse return invalidRequest();
    var interface_name_buffer: [service_registry.MAX_INTERFACE_NAME_BYTES]u8 = undefined;
    request.interface.name = copyUserSlice(request.interface.name, &interface_name_buffer) orelse return invalidRequest();
    const descriptor = port.serviceConnect(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchDeviceDescribe(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.DeviceDescribeRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.deviceDescribe(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchDeviceMmioWindow(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.DeviceMmioWindowRequest, request_addr) orelse return invalidRequest();
    const descriptor = port.deviceMmioWindow(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, descriptor);
}

fn dispatchDevicePortRead(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.DevicePortReadRequest, request_addr) orelse return invalidRequest();
    const value = port.devicePortRead(request, now_ticks) catch |err| return mapError(err);
    return writeResponse(response_addr, response_len, abi.DevicePortReadResponse{
        .value = value,
    });
}

fn dispatchDevicePortWrite(
    port: *component_port.KernelPort,
    now_ticks: u64,
    request_addr: usize,
) DispatchResult {
    const request = readRequest(component_port.DevicePortWriteRequest, request_addr) orelse return invalidRequest();
    port.devicePortWrite(request, now_ticks) catch |err| return mapError(err);
    return success();
}

fn readRequest(comptime T: type, request_addr: usize) ?T {
    return readUserValue(T, request_addr);
}

fn readUserValue(comptime T: type, addr: usize) ?T {
    if (!validateUserRange(addr, @sizeOf(T), @alignOf(T))) return null;
    const ptr: *const T = @ptrFromInt(addr);
    return ptr.*;
}

fn sanitizeTaskCreateRequest(
    request: *component_port.TaskCreateRequest,
    bundle_id_buffer: []u8,
    component_label_buffer: []u8,
    component_entry_buffer: []u8,
    image_copy: *task_runtime.ExecutableImageSpec,
) bool {
    request.request.launch.bundle_id = copyUserSlice(
        request.request.launch.bundle_id,
        bundle_id_buffer,
    ) orelse return false;
    request.request.initial_component.label = copyUserSlice(
        request.request.initial_component.label,
        component_label_buffer,
    ) orelse return false;
    request.request.initial_component.entry = copyUserSlice(
        request.request.initial_component.entry,
        component_entry_buffer,
    ) orelse return false;

    if (request.request.userspace_image) |image_ptr| {
        image_copy.* = readUserValue(task_runtime.ExecutableImageSpec, @intFromPtr(image_ptr)) orelse return false;
        request.request.userspace_image = image_copy;
    }
    return true;
}

fn copyUserSlice(slice: []const u8, dest: []u8) ?[]const u8 {
    if (slice.len > dest.len) return null;
    if (slice.len == 0) return dest[0..0];
    if (!validateUserRange(@intFromPtr(slice.ptr), slice.len, 1)) return null;
    @memcpy(dest[0..slice.len], slice);
    return dest[0..slice.len];
}

fn validateUserRange(addr: usize, len: usize, alignment: usize) bool {
    if (len == 0) return true;
    if (addr == 0 or addr < USER_POINTER_FLOOR) return false;
    if (alignment != 0 and addr % alignment != 0) return false;
    const end_exclusive = std.math.add(usize, addr, len) catch return false;
    if (end_exclusive <= addr) return false;

    if (builtin.target.os.tag == .freestanding and @bitSizeOf(usize) <= 32) {
        if (end_exclusive > USER_POINTER_CEILING_32) return false;
    }
    return true;
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
    if (!validateUserRange(response_addr, response_len, 1)) return null;
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
    if (err == error.ScopeViolation or err == error.ScopeEscalation or err == error.SubjectTaskMismatch) return .{
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
    if (err == error.InterfaceNameTooLong or err == error.MessageTooLarge) return .{
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
    if (err == error.DeviceNotFound or err == error.UnsupportedMmioWindow) return .{
        .status = .not_found,
        .denial_reason = .invalid_target,
    };
    if (err == error.InvalidPort or err == error.UnsupportedWidth) return .{
        .status = .denied,
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
        try self.runtime.grantCapability(self.session_task_id, self.authority_capability_id);
    }
};

test "syscall surface dispatches typed task creation requests" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const syscall_test_image = task_runtime.syntheticUserspaceImage("syscall-test", "app.example.syscall");
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
            .userspace_image = &syscall_test_image,
        },
    };

    const result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
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

    const empty_queue_image = task_runtime.syntheticUserspaceImage("empty-queue", "app.example.empty-queue");
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
            .userspace_image = &empty_queue_image,
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
        app_task.task_id,
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
        test_kernel.session_task_id,
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
    const result = dispatch(&test_kernel.port, test_kernel.session_task_id, 9, @intFromPtr(&request), 0, 0);

    try std.testing.expectEqual(abi.SyscallStatus.unsupported_operation, result.status);
    try std.testing.expectEqual(abi.DenialReason.unsupported_operation, result.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
}

test "syscall surface rejects invalid request and response pointer ranges" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const low_request = dispatch(&test_kernel.port, test_kernel.session_task_id, 9, 0x1000, 0, 0);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, low_request.status);

    const request = component_port.TimeQueryRequest{
        .header = component_port.makeHeader(.time_query, 92, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
    };
    const bad_response = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        9,
        @intFromPtr(&request),
        std.math.maxInt(usize) - 4,
        16,
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, bad_response.status);
}

test "syscall surface rejects spoofed subject task ids" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const spoofed_subject_image = task_runtime.syntheticUserspaceImage(
        "spoofed-subject",
        "app.example.spoofed-subject",
    );
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 92, test_kernel.session_task_id + 1),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 99 },
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
                .image_id = 23,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.spoofed-subject",
            },
            .userspace_image = &spoofed_subject_image,
        },
    };

    const result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );

    try std.testing.expectEqual(abi.SyscallStatus.denied, result.status);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, result.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
}

test "syscall surface copies and bounds embedded user buffers" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const bad_image_ptr: *const task_runtime.ExecutableImageSpec = @ptrFromInt(0x1000);
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const bad_image_request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 93, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 100 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
            },
            .local_only = true,
            .userspace_image = bad_image_ptr,
        },
    };
    const bad_image = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&bad_image_request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, bad_image.status);

    const oversized_payload = [_]u8{0xAB} ** (endpoint.MAX_MESSAGE_BYTES + 1);
    const send_request = component_port.EndpointSendRequest{
        .header = component_port.makeHeader(.endpoint_send, 94, test_kernel.session_task_id),
        .endpoint_capability_id = test_kernel.authority_capability_id,
        .payload = oversized_payload[0..],
    };
    const oversized = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&send_request),
        0,
        0,
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, oversized.status);
}

test "syscall surface dispatches typed device broker requests" {
    const device_broker = @import("device_broker.zig");

    var test_kernel = TestKernel{};
    try test_kernel.init();
    device_broker.reset();
    defer device_broker.reset();

    const device_capability = try test_kernel.capabilities.mint(.{
        .holder = .{ .kind = .service, .serial = 2 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .device, .id = 0x1F001 },
        .rights = .{ .device_use = true },
        .scope = .{
            .task_id = test_kernel.session_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 12,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
    });
    try test_kernel.runtime.grantCapability(test_kernel.session_task_id, device_capability.id);
    try std.testing.expect(device_broker.publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = 2048,
    }));

    const describe_request = component_port.DeviceDescribeRequest{
        .header = component_port.makeHeader(.device_describe, 101, test_kernel.session_task_id),
        .device_capability_id = device_capability.id,
    };
    var describe_response = std.mem.zeroes(abi.DeviceDescriptor);
    const describe_result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        12,
        @intFromPtr(&describe_request),
        @intFromPtr(&describe_response),
        @sizeOf(abi.DeviceDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, describe_result.status);
    try std.testing.expectEqual(@as(u64, 0x1F001), describe_response.device_id);

    const write_request = component_port.DevicePortWriteRequest{
        .header = component_port.makeHeader(.device_port_write, 102, test_kernel.session_task_id),
        .device_capability_id = device_capability.id,
        .port = 0x1F0 + 7,
        .width = .u8,
        .value = 0x5C,
    };
    try std.testing.expectEqual(abi.SyscallStatus.success, dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        12,
        @intFromPtr(&write_request),
        0,
        0,
    ).status);

    const read_request = component_port.DevicePortReadRequest{
        .header = component_port.makeHeader(.device_port_read, 103, test_kernel.session_task_id),
        .device_capability_id = device_capability.id,
        .port = 0x1F0 + 7,
        .width = .u8,
    };
    var read_response = abi.DevicePortReadResponse{ .value = 0 };
    const read_result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        12,
        @intFromPtr(&read_request),
        @intFromPtr(&read_response),
        @sizeOf(abi.DevicePortReadResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, read_result.status);
    try std.testing.expectEqual(@as(u32, 0x5C), read_response.value);
}
