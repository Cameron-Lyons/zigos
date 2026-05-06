const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const operation_metadata = @import("operation_metadata.zig");
const syscall_dispatch = @import("syscall_dispatch.zig");
const task_syscalls = @import("task_syscalls.zig");
const endpoint_syscalls = @import("endpoint_syscalls.zig");
const capability_syscalls = @import("capability_syscalls.zig");
const shared_memory_syscalls = @import("shared_memory_syscalls.zig");
const device_syscalls = @import("device_syscalls.zig");

pub const Domain = operation_metadata.Domain;
pub const RequestCopyRule = operation_metadata.RequestCopyRule;

pub const DispatchHandler = *const fn (
    port: *component_port.KernelPort,
    memory: syscall_dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) syscall_dispatch.DispatchResult;

pub const Operation = struct {
    operation: abi.NativeOperation,
    domain: Domain,
    Request: type,
    Response: type,
    handler: DispatchHandler,
    request_copy: RequestCopyRule = .plain,
    required_right: capability.CapabilityRight,
    target_kind: operation_metadata.TargetKindRule = .none,
    scope_rule: operation_metadata.ScopeRule = .{},
    auto_grants: []const operation_metadata.AutoGrant = &.{},

    pub fn requestSize(comptime self: Operation) usize {
        return @sizeOf(self.Request);
    }

    pub fn responseSize(comptime self: Operation) usize {
        return if (self.Response == void) 0 else @sizeOf(self.Response);
    }
};

const Binding = struct {
    Request: type,
    Response: type,
    handler: DispatchHandler,
};

fn bindingFor(comptime operation: abi.NativeOperation) Binding {
    return switch (operation) {
        .task_create => .{ .Request = component_port.TaskCreateRequest, .Response = abi.TaskDescriptor, .handler = task_syscalls.dispatchTaskCreate },
        .task_terminate => .{ .Request = component_port.TaskTerminateRequest, .Response = abi.BoolResponse, .handler = task_syscalls.dispatchTaskTerminate },
        .endpoint_create => .{ .Request = component_port.EndpointCreateRequest, .Response = abi.EndpointCreateResponse, .handler = endpoint_syscalls.dispatchEndpointCreate },
        .endpoint_connect => .{ .Request = component_port.EndpointConnectRequest, .Response = abi.EndpointDescriptor, .handler = endpoint_syscalls.dispatchEndpointConnect },
        .endpoint_send => .{ .Request = component_port.EndpointSendRequest, .Response = void, .handler = endpoint_syscalls.dispatchEndpointSend },
        .endpoint_recv => .{ .Request = component_port.EndpointRecvRequest, .Response = abi.EndpointRecvResponse, .handler = endpoint_syscalls.dispatchEndpointRecv },
        .capability_mint => .{ .Request = component_port.CapabilityMintRequest, .Response = abi.CapabilityDescriptor, .handler = capability_syscalls.dispatchCapabilityMint },
        .capability_derive => .{ .Request = component_port.CapabilityDeriveRequest, .Response = abi.CapabilityDescriptor, .handler = capability_syscalls.dispatchCapabilityDerive },
        .capability_pass => .{ .Request = component_port.CapabilityPassRequest, .Response = abi.CapabilityDescriptor, .handler = capability_syscalls.dispatchCapabilityPass },
        .capability_revoke => .{ .Request = component_port.CapabilityRevokeRequest, .Response = void, .handler = capability_syscalls.dispatchCapabilityRevoke },
        .capability_query => .{ .Request = component_port.CapabilityQueryRequest, .Response = abi.CapabilityDescriptor, .handler = capability_syscalls.dispatchCapabilityQuery },
        .shared_memory_create => .{ .Request = component_port.SharedMemoryCreateRequest, .Response = abi.SharedMemoryCreateResponse, .handler = shared_memory_syscalls.dispatchSharedMemoryCreate },
        .shared_memory_map => .{ .Request = component_port.SharedMemoryMapRequest, .Response = abi.SharedMemoryDescriptor, .handler = shared_memory_syscalls.dispatchSharedMemoryMap },
        .shared_memory_unmap => .{ .Request = component_port.SharedMemoryUnmapRequest, .Response = abi.BoolResponse, .handler = shared_memory_syscalls.dispatchSharedMemoryUnmap },
        .shared_memory_revoke => .{ .Request = component_port.SharedMemoryRevokeRequest, .Response = abi.SharedMemoryDescriptor, .handler = shared_memory_syscalls.dispatchSharedMemoryRevoke },
        .time_query => .{ .Request = component_port.TimeQueryRequest, .Response = abi.TimeQueryResponse, .handler = task_syscalls.dispatchTimeQuery },
        .resource_query => .{ .Request = component_port.ResourceQueryRequest, .Response = abi.ResourceDescriptor, .handler = task_syscalls.dispatchResourceQuery },
        .accounting_query => .{ .Request = component_port.AccountingQueryRequest, .Response = abi.AccountingDescriptor, .handler = task_syscalls.dispatchAccountingQuery },
        .device_describe => .{ .Request = component_port.DeviceDescribeRequest, .Response = abi.DeviceDescriptor, .handler = device_syscalls.dispatchDeviceDescribe },
        .device_mmio_window => .{ .Request = component_port.DeviceMmioWindowRequest, .Response = abi.DeviceMmioWindowDescriptor, .handler = device_syscalls.dispatchDeviceMmioWindow },
        .device_port_read => .{ .Request = component_port.DevicePortReadRequest, .Response = abi.DevicePortReadResponse, .handler = device_syscalls.dispatchDevicePortRead },
        .device_port_write => .{ .Request = component_port.DevicePortWriteRequest, .Response = void, .handler = device_syscalls.dispatchDevicePortWrite },
    };
}

fn operationFromMetadata(comptime descriptor: operation_metadata.Descriptor) Operation {
    const binding = bindingFor(descriptor.operation);
    return .{
        .operation = descriptor.operation,
        .domain = descriptor.domain,
        .Request = binding.Request,
        .Response = binding.Response,
        .handler = binding.handler,
        .request_copy = descriptor.request_copy,
        .required_right = descriptor.required_right,
        .target_kind = descriptor.target_kind,
        .scope_rule = descriptor.scope_rule,
        .auto_grants = descriptor.auto_grants,
    };
}

fn buildOperations() [operation_metadata.operations.len]Operation {
    var table: [operation_metadata.operations.len]Operation = undefined;
    inline for (operation_metadata.operations, 0..) |descriptor, index| {
        table[index] = operationFromMetadata(descriptor);
    }
    return table;
}

pub const operations = buildOperations();

pub fn declarationFor(comptime operation: abi.NativeOperation) Operation {
    inline for (operations) |decl| {
        if (decl.operation == operation) return decl;
    }
    @compileError("missing syscall ABI declaration for " ++ @tagName(operation));
}

test "single syscall ABI declaration covers every native operation" {
    try std.testing.expectEqual(std.meta.fields(abi.NativeOperation).len, operations.len);
    try std.testing.expectEqual(operation_metadata.operations.len, operations.len);
    inline for (std.meta.fields(abi.NativeOperation)) |field| {
        const operation: abi.NativeOperation = @enumFromInt(field.value);
        const declaration = declarationFor(operation);
        const kernel_declaration = operation_metadata.declarationFor(operation);
        try std.testing.expectEqual(operation, declaration.operation);
        try std.testing.expectEqual(kernel_declaration.required_right, declaration.required_right);
        try std.testing.expectEqual(kernel_declaration.domain, declaration.domain);
        try std.testing.expectEqual(kernel_declaration.request_copy, declaration.request_copy);
        try std.testing.expect(declaration.requestSize() >= @sizeOf(abi.RequestHeader));
    }
    try std.testing.expect(switch (declarationFor(.endpoint_send).target_kind) {
        .fixed => |kind| kind == .endpoint,
        else => false,
    });
    try std.testing.expect(declarationFor(.task_create).scope_rule.local_scope_requires_request_local);
    try std.testing.expectEqual(@as(usize, 1), declarationFor(.shared_memory_create).auto_grants.len);
}
