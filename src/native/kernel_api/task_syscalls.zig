const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub fn dispatchTaskCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    var request = dispatch.readRequest(component_port.TaskCreateRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    var image_copy = task_runtime.ExecutableImageSpec{};
    if (!sanitizeTaskCreateRequest(memory, &request, &image_copy)) return dispatch.invalidRequest();
    const task = component_port.invokeGenerated(.task_create, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    const terminated = component_port.invokeGenerated(.task_terminate, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.boolResponse(terminated));
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
    const queried = component_port.invokeGenerated(.time_query, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    return dispatch.invokeAndWriteResponse(.resource_query, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchAccountingQuery(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.accounting_query, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchInputRecv(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.InputRecvRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const received = component_port.invokeGenerated(.input_recv, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    var response = @import("std").mem.zeroes(abi.InputRecvResponse);
    if (received) |event| {
        response.present = 1;
        response.event = event;
    }
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}

pub fn dispatchSurfacePresent(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.SurfacePresentRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const presented = component_port.invokeGenerated(.surface_present, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.boolResponse(presented));
}

fn sanitizeTaskCreateRequest(
    memory: dispatch.UserMemoryContext,
    request: *component_port.TaskCreateRequest,
    image_copy: *task_runtime.ExecutableImageSpec,
) bool {
    request.request.launch.bundle_id = dispatch.borrowImmediateUserSlice(
        memory,
        request.request.launch.bundle_id,
        task_runtime.MAX_TASK_BUNDLE_ID_BYTES,
    ) orelse return false;
    request.request.launch.source_identity = dispatch.borrowImmediateUserSlice(
        memory,
        request.request.launch.source_identity,
        task_runtime.MAX_TASK_SOURCE_IDENTITY_BYTES,
    ) orelse return false;
    request.request.initial_component.label = dispatch.borrowImmediateUserSlice(
        memory,
        request.request.initial_component.label,
        task_runtime.MAX_COMPONENT_LABEL_BYTES,
    ) orelse return false;
    request.request.initial_component.entry = dispatch.borrowImmediateUserSlice(
        memory,
        request.request.initial_component.entry,
        task_runtime.MAX_COMPONENT_ENTRY_BYTES,
    ) orelse return false;

    if (request.request.userspace_image) |image_ptr| {
        image_copy.* = dispatch.readUserValue(task_runtime.ExecutableImageSpec, memory, @intFromPtr(image_ptr)) orelse return false;
        request.request.userspace_image = image_copy;
    }
    return true;
}
