const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_create_wire = @import("task_create_wire.zig");

const TaskCreateScratch = struct {
    image_wire: abi.ExecutableImageWireSpec = undefined,
    image: task_runtime.ExecutableImageSpec = .{},
    bundle_id: [task_runtime.MAX_TASK_BUNDLE_ID_BYTES]u8 = undefined,
    source_identity: [task_runtime.MAX_TASK_SOURCE_IDENTITY_BYTES]u8 = undefined,
    component_label: [task_runtime.MAX_COMPONENT_LABEL_BYTES]u8 = undefined,
    component_entry: [task_runtime.MAX_COMPONENT_ENTRY_BYTES]u8 = undefined,
};

pub fn dispatchTaskCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const wire = dispatch.readRequest(abi.TaskCreateWireRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    if (!task_create_wire.taskCreateWireValid(&wire)) return dispatch.invalidRequest();
    var scratch = TaskCreateScratch{};
    var request = component_port.TaskCreateRequest{
        .header = wire.header,
        .authority_capability_id = wire.authority_capability_id,
        .request = undefined,
    };
    if (!sanitizeTaskCreateRequest(memory, &wire, &scratch, &request.request)) return dispatch.invalidRequest();
    // Keep this single-operation decode and forwarding boundary together;
    // shared image validation and bounded byte copying remain outlined.
    const task = @call(.always_inline, component_port.invokeGeneratedFromValidatedSyscall, .{ .task_create, port, request, now_ticks }) catch |err| return dispatch.mapError(err);
    return @call(.always_inline, dispatch.writeResponse, .{ memory, response_addr, response_len, task });
}

pub fn dispatchTaskTerminate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    // Terminating the caller retires its address-space record during invocation.
    // Acknowledge through the syscall status without copying into retired memory.
    return dispatch.invokeNoResponse(.task_terminate, port, memory, now_ticks, request_addr, response_addr, response_len);
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
    const queried = component_port.invokeGeneratedFromValidatedSyscall(.time_query, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    const received = component_port.invokeGeneratedFromValidatedSyscall(.input_recv, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    const wire = dispatch.readRequest(abi.SurfacePresentWireRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    @import("../core/request_header.zig").validateHeader(wire.header, abi.opcode(.surface_present)) catch |err| return dispatch.mapError(err);
    var request = component_port.SurfacePresentRequest{
        .header = wire.header,
        .presentation_capability_id = wire.presentation_capability_id,
        .presenter_task_id = wire.presenter_task_id,
        .surface_id = wire.surface_id,
        .fence = wire.fence,
        .buffer_object_id = wire.buffer_object_id,
        .buffer_offset = wire.buffer_offset,
        .buffer_bytes = wire.buffer_bytes,
    };
    var text: abi.SurfaceText = undefined;
    if (wire.text_address != 0) {
        const address = @import("std").math.cast(usize, wire.text_address) orelse return dispatch.invalidRequest();
        const encoded = dispatch.readUserValue(abi.SurfaceTextWire, memory, address) orelse return dispatch.invalidRequest();
        text = .{
            .window_id = encoded.window_id,
            .text_length = encoded.text_length,
            .cursor = encoded.cursor,
            .state = @bitCast(encoded.state),
            .text = encoded.text,
        };
        request.text = &text;
    }
    const presented = component_port.invokeGeneratedFromValidatedSyscall(.surface_present, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.boolResponse(presented));
}

inline fn sanitizeTaskCreateRequest(
    memory: dispatch.UserMemoryContext,
    wire: *const abi.TaskCreateWireRequest,
    scratch: *TaskCreateScratch,
    out: *task_runtime.TaskCreateRequest,
) bool {
    const staged = task_create_wire.StagedStrings{
        .bundle_id = dispatch.copyUserBytes(memory, wire.bundle_id_address, wire.bundle_id_bytes, &scratch.bundle_id) orelse return false,
        .source_identity = dispatch.copyUserBytes(memory, wire.source_identity_address, wire.source_identity_bytes, &scratch.source_identity) orelse return false,
        .component_label = dispatch.copyUserBytes(memory, wire.component_label_address, wire.component_label_bytes, &scratch.component_label) orelse return false,
        .component_entry = dispatch.copyUserBytes(memory, wire.component_entry_address, wire.component_entry_bytes, &scratch.component_entry) orelse return false,
    };
    var image: ?*const task_runtime.ExecutableImageSpec = null;
    if (wire.userspace_image_address != 0) {
        if (wire.userspace_image_address % @alignOf(abi.ExecutableImageWireSpec) != 0) return false;
        _ = dispatch.copyUserBytes(memory, wire.userspace_image_address, @sizeOf(abi.ExecutableImageWireSpec), @import("std").mem.asBytes(&scratch.image_wire)) orelse return false;
        if (!task_create_wire.executableImageFromWireInto(&scratch.image_wire, &scratch.image)) return false;
        image = &scratch.image;
    }
    return task_create_wire.taskCreateFromWireInto(wire, staged, image, out);
}
