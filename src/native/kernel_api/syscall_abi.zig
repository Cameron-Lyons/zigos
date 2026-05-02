const std = @import("std");
const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const syscall_dispatch = @import("syscall_dispatch.zig");
const task_syscalls = @import("task_syscalls.zig");
const endpoint_syscalls = @import("endpoint_syscalls.zig");
const capability_syscalls = @import("capability_syscalls.zig");
const shared_memory_syscalls = @import("shared_memory_syscalls.zig");
const device_syscalls = @import("device_syscalls.zig");

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

    pub fn requestSize(comptime self: Operation) usize {
        return @sizeOf(self.Request);
    }

    pub fn responseSize(comptime self: Operation) usize {
        return if (self.Response == void) 0 else @sizeOf(self.Response);
    }
};

pub const operations = task_syscalls.operations ++
    endpoint_syscalls.operations ++
    capability_syscalls.operations ++
    shared_memory_syscalls.operations ++
    device_syscalls.operations;

pub fn declarationFor(comptime operation: abi.NativeOperation) Operation {
    inline for (operations) |decl| {
        if (decl.operation == operation) return decl;
    }
    @compileError("missing syscall ABI declaration for " ++ @tagName(operation));
}

test "single syscall ABI declaration covers every native operation" {
    try std.testing.expectEqual(std.meta.fields(abi.NativeOperation).len, operations.len);
    inline for (std.meta.fields(abi.NativeOperation)) |field| {
        const operation: abi.NativeOperation = @enumFromInt(field.value);
        const declaration = declarationFor(operation);
        try std.testing.expectEqual(operation, declaration.operation);
        try std.testing.expect(declaration.requestSize() >= @sizeOf(abi.RequestHeader));
    }
}
