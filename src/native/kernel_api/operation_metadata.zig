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
        .domain = .task,
        .request_copy = .embedded_user_buffers,
        .required_right = .task_create,
        .scope_rule = .{ .local_scope_requires_request_local = true },
    },
    .{
        .operation = .task_terminate,
        .domain = .task,
        .required_right = .task_terminate,
        .target_kind = .{ .fixed = .task },
    },
    .{
        .operation = .endpoint_create,
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
        .domain = .endpoint,
        .required_right = .endpoint_connect,
        .target_kind = .{ .fixed = .endpoint },
    },
    .{
        .operation = .endpoint_send,
        .domain = .endpoint,
        .request_copy = .embedded_user_buffers,
        .required_right = .endpoint_send,
        .target_kind = .{ .fixed = .endpoint },
    },
    .{
        .operation = .endpoint_recv,
        .domain = .endpoint,
        .required_right = .endpoint_recv,
        .target_kind = .{ .fixed = .endpoint },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .capability_mint,
        .domain = .capability,
        .required_right = .capability_mint,
        .target_kind = .{ .fixed = .policy },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .capability_derive,
        .domain = .capability,
        .required_right = .capability_derive,
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .capability_pass,
        .domain = .capability,
        .required_right = .capability_pass,
    },
    .{
        .operation = .capability_revoke,
        .domain = .capability,
        .required_right = .capability_revoke,
        .target_kind = .same_as_target_capability,
    },
    .{
        .operation = .capability_query,
        .domain = .capability,
        .required_right = .capability_query,
        .target_kind = .same_as_target_capability,
    },
    .{
        .operation = .shared_memory_create,
        .domain = .shared_memory,
        .required_right = .shared_memory_create,
        .scope_rule = .{ .task_scope_matches_request_task = true },
        .auto_grants = &.{shared_memory_owner_auto_grant},
    },
    .{
        .operation = .shared_memory_map,
        .domain = .shared_memory,
        .required_right = .shared_memory_map,
        .target_kind = .{ .fixed = .shared_memory },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .shared_memory_unmap,
        .domain = .shared_memory,
        .required_right = .shared_memory_unmap,
        .target_kind = .{ .fixed = .shared_memory },
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .shared_memory_revoke,
        .domain = .shared_memory,
        .required_right = .shared_memory_revoke,
        .target_kind = .{ .fixed = .shared_memory },
    },
    .{
        .operation = .time_query,
        .domain = .task,
        .required_right = .time_query,
    },
    .{
        .operation = .resource_query,
        .domain = .task,
        .required_right = .resource_query,
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .accounting_query,
        .domain = .task,
        .required_right = .accounting_query,
        .scope_rule = .{ .task_scope_matches_request_task = true },
    },
    .{
        .operation = .device_describe,
        .domain = .device,
        .required_right = .device_use,
        .target_kind = .{ .fixed = .device },
    },
    .{
        .operation = .device_mmio_window,
        .domain = .device,
        .required_right = .device_use,
        .target_kind = .{ .fixed = .device },
    },
    .{
        .operation = .device_port_read,
        .domain = .device,
        .required_right = .device_use,
        .target_kind = .{ .fixed = .device },
    },
    .{
        .operation = .device_port_write,
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
    }

    try std.testing.expectEqual(Domain.task, declarationFor(.task_create).domain);
    try std.testing.expectEqual(RequestCopyRule.embedded_user_buffers, declarationFor(.task_create).request_copy);
    try std.testing.expectEqual(RequestCopyRule.embedded_user_buffers, declarationFor(.endpoint_send).request_copy);
    try std.testing.expectEqual(capability.CapabilityRight.device_use, declarationFor(.device_port_write).required_right);
    try std.testing.expect(switch (declarationFor(.capability_query).target_kind) {
        .same_as_target_capability => true,
        else => false,
    });
    try std.testing.expectEqual(AutoGrantKind.created_endpoint_owner, autoGrantFor(.endpoint_create, .created_endpoint_owner).kind);
}
