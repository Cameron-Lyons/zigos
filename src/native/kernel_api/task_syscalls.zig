const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    .{ .operation = .task_create, .domain = .task, .Request = component_port.TaskCreateRequest, .Response = abi.TaskDescriptor, .request_copy = .embedded_user_buffers },
    .{ .operation = .task_terminate, .domain = .task, .Request = component_port.TaskTerminateRequest, .Response = abi.BoolResponse },
    .{ .operation = .time_query, .domain = .task, .Request = component_port.TimeQueryRequest, .Response = abi.TimeQueryResponse },
    .{ .operation = .resource_query, .domain = .task, .Request = component_port.ResourceQueryRequest, .Response = abi.ResourceDescriptor },
    .{ .operation = .accounting_query, .domain = .task, .Request = component_port.AccountingQueryRequest, .Response = abi.AccountingDescriptor },
};
