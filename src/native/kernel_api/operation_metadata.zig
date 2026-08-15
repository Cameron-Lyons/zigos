const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");

pub const Domain = enum {
    task,
    endpoint,
    capability,
    shared_memory,
    device,
};

pub const RequestCopyRule = enum {
    plain,
    embedded_user_buffers,
};

pub const PortInvocation = enum {
    with_now_ticks,
    without_now_ticks,
};

pub const AbiBinding = struct {
    request_type_name: []const u8,
    response_type_name: []const u8,
    handler_name: []const u8,
    port_method_name: []const u8,
    port_invocation: PortInvocation = .with_now_ticks,
};

pub const TargetKindRule = union(enum) {
    none,
    fixed: capability.CapabilityTargetKind,
    same_as_target_capability,
};

pub const ScopeRule = packed struct {
    task_scope_matches_request_task: bool = false,
    local_scope_requires_request_local: bool = false,
};

pub const AutoGrantKind = enum {
    created_endpoint_owner,
    created_shared_memory_owner,
};

pub const AutoGrantLocality = enum {
    request,
    always_local,
};

pub const AutoGrant = struct {
    kind: AutoGrantKind,
    rights: capability.CapabilityRights,
    task_scoped: bool = true,
    locality: AutoGrantLocality = .always_local,
    broker_only: bool = true,
    renewable: bool = false,
};

pub const Descriptor = struct {
    operation: abi.NativeOperation,
    binding: AbiBinding,
    domain: Domain,
    request_copy: RequestCopyRule = .plain,
    required_right: capability.CapabilityRight,
    target_kind: TargetKindRule = .none,
    scope_rule: ScopeRule = .{},
    auto_grants: []const AutoGrant = &.{},
};

pub const endpoint_owner_auto_grant = AutoGrant{
    .kind = .created_endpoint_owner,
    .rights = .{ .endpoint = .{
        .endpoint_connect = true,
        .endpoint_send = true,
        .endpoint_recv = true,
        .capability_query = true,
        .ipc_peer = true,
    } },
    .locality = .request,
};

pub const shared_memory_owner_auto_grant = AutoGrant{
    .kind = .created_shared_memory_owner,
    .rights = .{ .shared_memory = .{
        .shared_memory_map = true,
        .shared_memory_unmap = true,
        .shared_memory_revoke = true,
        .capability_pass = true,
        .capability_query = true,
    } },
};

pub const operations = [_]Descriptor{
    .{
        .operation = .task_create,
        .binding = .{
            .request_type_name = "TaskCreateRequest",
            .response_type_name = "TaskDescriptor",
            .handler_name = "dispatchTaskCreate",
            .port_method_name = "taskCreate",
        },
        .domain = .task,
        .request_copy = .embedded_user_buffers,
        .required_right = .task_create,
        .scope_rule = .{ .local_scope_requires_request_local = true },
    },
    .{
        .operation = .task_terminate,
        .binding = .{
            .request_type_name = "TaskTerminateRequest",
            .response_type_name = "BoolResponse",
            .handler_name = "dispatchTaskTerminate",
            .port_method_name = "taskTerminate",
        },
        .domain = .task,
        .required_right = .task_terminate,
        .target_kind = .{ .fixed = .task },
    },
    .{
        .operation = .endpoint_create,
        .binding = .{
            .request_type_name = "EndpointCreateRequest",
            .response_type_name = "EndpointCreateResponse",
            .handler_name = "dispatchEndpointCreate",
            .port_method_name = "endpointCreate",
        },
        .domain = .endpoint,
        .request_copy = .embedded_user_buffers,
        .required_right = .endpoint_create,
        .scope_rule = .{
            .task_scope_matches_request_task = true,
            .local_scope_requires_request_local = true,
        },
        .auto_grants = &.{endpoint_owner_auto_grant},
    },
    .{
        .operation = .endpoint_connect,
        .binding = .{
            .request_type_name = "EndpointConnectRequest",
            .response_type_name = "EndpointDescriptor",
            .handler_name = "dispatchEndpointConnect",
            .port_method_name = "endpointConnect",
        },
        .domain = .endpoint,
        .required_right = .endpoint_connect,
        .target_kind = .{ .fixed = .endpoint },
    },
    .{
        .operation = .endpoint_send,
        .binding = .{
            .request_type_name = "EndpointSendRequest",
            .response_type_name = "void",
            .handler_name = "dispatchEndpointSend",
            .port_method_name = "endpointSend",
        },
        .domain = .endpoint,
        .request_copy = .embedded_user_buffers,
        .required_right = .endpoint_send,
        .target_kind = .{ .fixed = .endpoint },
    },
    .{
        .operation = .endpoint_recv,
        .binding = .{
            .request_type_name = "EndpointRecvRequest",
            .response_type_name = "EndpointRecvResponse",
            .handler_name = "dispatchEndpointRecv",
            .port_method_name = "endpointRecv",
        },
        .domain = .endpoint,
        .required_right = .endpoint_recv,
        .target_kind = .{ .fixed = .endpoint },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .capability_mint,
        .binding = .{
            .request_type_name = "CapabilityMintRequest",
            .response_type_name = "CapabilityDescriptor",
            .handler_name = "dispatchCapabilityMint",
            .port_method_name = "capabilityMint",
        },
        .domain = .capability,
        .required_right = .capability_mint,
        .target_kind = .{ .fixed = .policy },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .capability_derive,
        .binding = .{
            .request_type_name = "CapabilityDeriveRequest",
            .response_type_name = "CapabilityDescriptor",
            .handler_name = "dispatchCapabilityDerive",
            .port_method_name = "capabilityDerive",
            .port_invocation = .without_now_ticks,
        },
        .domain = .capability,
        .required_right = .capability_derive,
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .capability_pass,
        .binding = .{
            .request_type_name = "CapabilityPassRequest",
            .response_type_name = "CapabilityDescriptor",
            .handler_name = "dispatchCapabilityPass",
            .port_method_name = "capabilityPass",
        },
        .domain = .capability,
        .required_right = .capability_pass,
    },
    .{
        .operation = .capability_revoke,
        .binding = .{
            .request_type_name = "CapabilityRevokeRequest",
            .response_type_name = "void",
            .handler_name = "dispatchCapabilityRevoke",
            .port_method_name = "capabilityRevoke",
        },
        .domain = .capability,
        .required_right = .capability_revoke,
        .target_kind = .same_as_target_capability,
    },
    .{
        .operation = .capability_query,
        .binding = .{
            .request_type_name = "CapabilityQueryRequest",
            .response_type_name = "CapabilityDescriptor",
            .handler_name = "dispatchCapabilityQuery",
            .port_method_name = "capabilityQuery",
        },
        .domain = .capability,
        .required_right = .capability_query,
        .target_kind = .same_as_target_capability,
    },
    .{
        .operation = .shared_memory_create,
        .binding = .{
            .request_type_name = "SharedMemoryCreateRequest",
            .response_type_name = "SharedMemoryCreateResponse",
            .handler_name = "dispatchSharedMemoryCreate",
            .port_method_name = "sharedMemoryCreate",
        },
        .domain = .shared_memory,
        .required_right = .shared_memory_create,
        .scope_rule = .{ .task_scope_matches_request_task = true },
        .auto_grants = &.{shared_memory_owner_auto_grant},
    },
    .{
        .operation = .shared_memory_map,
        .binding = .{
            .request_type_name = "SharedMemoryMapRequest",
            .response_type_name = "SharedMemoryDescriptor",
            .handler_name = "dispatchSharedMemoryMap",
            .port_method_name = "sharedMemoryMap",
        },
        .domain = .shared_memory,
        .required_right = .shared_memory_map,
        .target_kind = .{ .fixed = .shared_memory },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .shared_memory_unmap,
        .binding = .{
            .request_type_name = "SharedMemoryUnmapRequest",
            .response_type_name = "BoolResponse",
            .handler_name = "dispatchSharedMemoryUnmap",
            .port_method_name = "sharedMemoryUnmap",
        },
        .domain = .shared_memory,
        .required_right = .shared_memory_unmap,
        .target_kind = .{ .fixed = .shared_memory },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .shared_memory_revoke,
        .binding = .{
            .request_type_name = "SharedMemoryRevokeRequest",
            .response_type_name = "SharedMemoryDescriptor",
            .handler_name = "dispatchSharedMemoryRevoke",
            .port_method_name = "sharedMemoryRevoke",
        },
        .domain = .shared_memory,
        .required_right = .shared_memory_revoke,
        .target_kind = .{ .fixed = .shared_memory },
    },
    .{
        .operation = .time_query,
        .binding = .{
            .request_type_name = "TimeQueryRequest",
            .response_type_name = "TimeQueryResponse",
            .handler_name = "dispatchTimeQuery",
            .port_method_name = "timeQuery",
        },
        .domain = .task,
        .required_right = .time_query,
    },
    .{
        .operation = .resource_query,
        .binding = .{
            .request_type_name = "ResourceQueryRequest",
            .response_type_name = "ResourceDescriptor",
            .handler_name = "dispatchResourceQuery",
            .port_method_name = "resourceQuery",
        },
        .domain = .task,
        .required_right = .resource_query,
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .accounting_query,
        .binding = .{
            .request_type_name = "AccountingQueryRequest",
            .response_type_name = "AccountingDescriptor",
            .handler_name = "dispatchAccountingQuery",
            .port_method_name = "accountingQuery",
        },
        .domain = .task,
        .required_right = .accounting_query,
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .input_recv,
        .binding = .{
            .request_type_name = "InputRecvRequest",
            .response_type_name = "InputRecvResponse",
            .handler_name = "dispatchInputRecv",
            .port_method_name = "inputRecv",
        },
        .domain = .task,
        .required_right = .input_recv,
        .target_kind = .{ .fixed = .task },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .device_describe,
        .binding = .{
            .request_type_name = "DeviceDescribeRequest",
            .response_type_name = "DeviceDescriptor",
            .handler_name = "dispatchDeviceDescribe",
            .port_method_name = "deviceDescribe",
        },
        .domain = .device,
        .required_right = .device_use,
        .target_kind = .{ .fixed = .device },
    },
    .{
        .operation = .device_mmio_window,
        .binding = .{
            .request_type_name = "DeviceMmioWindowRequest",
            .response_type_name = "DeviceMmioWindowDescriptor",
            .handler_name = "dispatchDeviceMmioWindow",
            .port_method_name = "deviceMmioWindow",
        },
        .domain = .device,
        .required_right = .device_use,
        .target_kind = .{ .fixed = .device },
    },
};

pub fn declarationFor(comptime operation: abi.NativeOperation) Descriptor {
    inline for (operations) |declaration| {
        if (declaration.operation == operation) return declaration;
    }
    @compileError("missing native operation metadata for " ++ @tagName(operation));
}

pub fn autoGrantFor(comptime operation: abi.NativeOperation, comptime kind: AutoGrantKind) AutoGrant {
    const descriptor = comptime declarationFor(operation);
    inline for (descriptor.auto_grants) |grant| {
        if (grant.kind == kind) return grant;
    }
    @compileError("operation " ++ @tagName(operation) ++ " does not declare auto-grant " ++ @tagName(kind));
}

test "native operation metadata covers every operation once" {
    try std.testing.expectEqual(std.meta.fields(abi.NativeOperation).len, operations.len);
    inline for (std.meta.fields(abi.NativeOperation)) |field| {
        const operation: abi.NativeOperation = @enumFromInt(field.value);
        const declaration = declarationFor(operation);
        try std.testing.expectEqual(operation, declaration.operation);
        try std.testing.expect(declaration.binding.request_type_name.len != 0);
        try std.testing.expect(declaration.binding.response_type_name.len != 0);
        try std.testing.expect(declaration.binding.handler_name.len != 0);
        try std.testing.expect(declaration.binding.port_method_name.len != 0);
    }

    try std.testing.expectEqual(Domain.task, declarationFor(.task_create).domain);
    try std.testing.expectEqual(RequestCopyRule.embedded_user_buffers, declarationFor(.task_create).request_copy);
    try std.testing.expectEqual(RequestCopyRule.embedded_user_buffers, declarationFor(.endpoint_send).request_copy);
    try std.testing.expectEqual(capability.CapabilityRight.device_use, declarationFor(.device_describe).required_right);
    try std.testing.expect(switch (declarationFor(.capability_query).target_kind) {
        .same_as_target_capability => true,
        else => false,
    });
    try std.testing.expectEqual(AutoGrantKind.created_endpoint_owner, autoGrantFor(.endpoint_create, .created_endpoint_owner).kind);
}
