const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const syscall_abi = @import("syscall_abi.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub const operations = [_]syscall_abi.Operation{
    .{ .operation = .task_create, .domain = .task, .Request = component_port.TaskCreateRequest, .Response = abi.TaskDescriptor, .handler = dispatchTaskCreate, .request_copy = .embedded_user_buffers },
    .{ .operation = .task_terminate, .domain = .task, .Request = component_port.TaskTerminateRequest, .Response = abi.BoolResponse, .handler = dispatchTaskTerminate },
    .{ .operation = .time_query, .domain = .task, .Request = component_port.TimeQueryRequest, .Response = abi.TimeQueryResponse, .handler = dispatchTimeQuery },
    .{ .operation = .resource_query, .domain = .task, .Request = component_port.ResourceQueryRequest, .Response = abi.ResourceDescriptor, .handler = dispatchResourceQuery },
    .{ .operation = .accounting_query, .domain = .task, .Request = component_port.AccountingQueryRequest, .Response = abi.AccountingDescriptor, .handler = dispatchAccountingQuery },
};

const MAX_COMPONENT_LABEL_BYTES: usize = 48;
const MAX_COMPONENT_ENTRY_BYTES: usize = 64;

pub fn dispatchTaskCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    var request = dispatch.readRequest(component_port.TaskCreateRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    var bundle_id_buffer: [task_runtime.MAX_TASK_BUNDLE_ID_BYTES]u8 = undefined;
    var component_label_buffer: [MAX_COMPONENT_LABEL_BYTES]u8 = undefined;
    var component_entry_buffer: [MAX_COMPONENT_ENTRY_BYTES]u8 = undefined;
    var image_copy = task_runtime.ExecutableImageSpec{};
    if (!sanitizeTaskCreateRequest(
        memory,
        &request,
        &bundle_id_buffer,
        &component_label_buffer,
        &component_entry_buffer,
        &image_copy,
    )) return dispatch.invalidRequest();
    const task = port.taskCreate(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, task);
}

pub fn dispatchTaskTerminate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.TaskTerminateRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const terminated = port.taskTerminate(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.BoolResponse{
        .value = @intFromBool(terminated),
        ._reserved = [_]u8{0} ** 7,
    });
}

pub fn dispatchTimeQuery(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.TimeQueryRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const queried = port.timeQuery(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.TimeQueryResponse{
        .now_ticks = queried,
    });
}

pub fn dispatchResourceQuery(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.ResourceQueryRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.resourceQuery(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}

pub fn dispatchAccountingQuery(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.AccountingQueryRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.accountingQuery(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}

fn sanitizeTaskCreateRequest(
    memory: dispatch.UserMemoryContext,
    request: *component_port.TaskCreateRequest,
    bundle_id_buffer: []u8,
    component_label_buffer: []u8,
    component_entry_buffer: []u8,
    image_copy: *task_runtime.ExecutableImageSpec,
) bool {
    request.request.launch.bundle_id = dispatch.copyUserSlice(
        memory,
        request.request.launch.bundle_id,
        bundle_id_buffer,
    ) orelse return false;
    request.request.initial_component.label = dispatch.copyUserSlice(
        memory,
        request.request.initial_component.label,
        component_label_buffer,
    ) orelse return false;
    request.request.initial_component.entry = dispatch.copyUserSlice(
        memory,
        request.request.initial_component.entry,
        component_entry_buffer,
    ) orelse return false;

    if (request.request.userspace_image) |image_ptr| {
        image_copy.* = dispatch.readUserValue(task_runtime.ExecutableImageSpec, memory, @intFromPtr(image_ptr)) orelse return false;
        request.request.userspace_image = image_copy;
    }
    return true;
}
