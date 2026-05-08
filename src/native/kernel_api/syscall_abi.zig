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
pub const PortInvocation = operation_metadata.PortInvocation;

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
    request_type_name: []const u8,
    response_type_name: []const u8,
    handler_name: []const u8,
    port_method_name: []const u8,
    port_invocation: PortInvocation,
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

fn requestType(comptime type_name: []const u8) type {
    if (!@hasDecl(component_port, type_name)) {
        @compileError("missing component-port request type " ++ type_name);
    }
    return @field(component_port, type_name);
}

fn responseType(comptime type_name: []const u8) type {
    if (std.mem.eql(u8, type_name, "void")) return void;
    if (!@hasDecl(abi, type_name)) {
        @compileError("missing syscall ABI response type " ++ type_name);
    }
    return @field(abi, type_name);
}

fn handlerForModule(comptime module: anytype, comptime handler_name: []const u8) DispatchHandler {
    if (!@hasDecl(module, handler_name)) {
        @compileError("missing syscall dispatch handler " ++ handler_name);
    }
    return @field(module, handler_name);
}

fn handlerFor(comptime descriptor: operation_metadata.Descriptor) DispatchHandler {
    return switch (descriptor.domain) {
        .task => handlerForModule(task_syscalls, descriptor.binding.handler_name),
        .endpoint => handlerForModule(endpoint_syscalls, descriptor.binding.handler_name),
        .capability => handlerForModule(capability_syscalls, descriptor.binding.handler_name),
        .shared_memory => handlerForModule(shared_memory_syscalls, descriptor.binding.handler_name),
        .device => handlerForModule(device_syscalls, descriptor.binding.handler_name),
    };
}

fn operationFromMetadata(comptime descriptor: operation_metadata.Descriptor) Operation {
    const binding = descriptor.binding;
    return .{
        .operation = descriptor.operation,
        .domain = descriptor.domain,
        .request_type_name = binding.request_type_name,
        .response_type_name = binding.response_type_name,
        .handler_name = binding.handler_name,
        .port_method_name = binding.port_method_name,
        .port_invocation = binding.port_invocation,
        .Request = requestType(binding.request_type_name),
        .Response = responseType(binding.response_type_name),
        .handler = handlerFor(descriptor),
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
        const declaration = comptime declarationFor(operation);
        const kernel_declaration = comptime operation_metadata.declarationFor(operation);
        try std.testing.expectEqual(operation, declaration.operation);
        try std.testing.expectEqual(kernel_declaration.required_right, declaration.required_right);
        try std.testing.expectEqual(kernel_declaration.domain, declaration.domain);
        try std.testing.expectEqual(kernel_declaration.request_copy, declaration.request_copy);
        try std.testing.expectEqualStrings(kernel_declaration.binding.request_type_name, declaration.request_type_name);
        try std.testing.expectEqualStrings(kernel_declaration.binding.response_type_name, declaration.response_type_name);
        try std.testing.expectEqualStrings(kernel_declaration.binding.handler_name, declaration.handler_name);
        try std.testing.expectEqualStrings(kernel_declaration.binding.port_method_name, declaration.port_method_name);
        try std.testing.expectEqual(kernel_declaration.binding.port_invocation, declaration.port_invocation);
        try std.testing.expect(declaration.requestSize() >= @sizeOf(abi.RequestHeader));
        comptime {
            if (declaration.Request != requestType(kernel_declaration.binding.request_type_name)) {
                @compileError("request type mismatch for " ++ @tagName(operation));
            }
            if (declaration.Response != responseType(kernel_declaration.binding.response_type_name)) {
                @compileError("response type mismatch for " ++ @tagName(operation));
            }
        }
    }
    try std.testing.expect(switch (declarationFor(.endpoint_send).target_kind) {
        .fixed => |kind| kind == .endpoint,
        else => false,
    });
    try std.testing.expect(declarationFor(.task_create).scope_rule.local_scope_requires_request_local);
    try std.testing.expectEqual(@as(usize, 1), declarationFor(.shared_memory_create).auto_grants.len);
}
