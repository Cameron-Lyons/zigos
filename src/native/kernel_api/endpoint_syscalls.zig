const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const endpoint = @import("endpoint.zig");

pub fn dispatchEndpointCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    var request = dispatch.readRequest(component_port.EndpointCreateRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    var label_buffer: [endpoint.MAX_ENDPOINT_LABEL_BYTES]u8 = undefined;
    request.label = dispatch.copyUserSlice(memory, request.label, &label_buffer) orelse return dispatch.invalidRequest();
    const created = component_port.invokeGenerated(.endpoint_create, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.EndpointCreateResponse{
        .endpoint = created.endpoint,
        .capability = created.capability,
        .capability_id = created.capability_id,
    });
}

pub fn dispatchEndpointConnect(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.endpoint_connect, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchEndpointSend(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    _ = response_len;
    _ = response_addr;
    var request = dispatch.readRequest(component_port.EndpointSendRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    request.payload = dispatch.borrowImmediateUserSlice(memory, request.payload, endpoint.MAX_MESSAGE_BYTES) orelse return dispatch.invalidRequest();
    component_port.invokeGenerated(.endpoint_send, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.success();
}

pub fn dispatchEndpointRecv(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.EndpointRecvRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    if (response_len < @sizeOf(abi.EndpointRecvResponse)) return .{ .status = .buffer_too_small };
    if (!dispatch.validateUserRange(memory, response_addr, response_len, 1, .write)) {
        return .{ .status = .invalid_response_buffer };
    }
    if (request.payload_out.len > endpoint.MAX_MESSAGE_BYTES or
        !dispatch.validateUserRange(
            memory,
            @intFromPtr(request.payload_out.ptr),
            request.payload_out.len,
            1,
            .write,
        ) or
        !dispatch.validateUserRange(
            memory,
            @intFromPtr(request.attached_capability_out),
            @sizeOf(abi.CapabilityDescriptor),
            @alignOf(abi.CapabilityDescriptor),
            .write,
        ))
    {
        return .{ .status = .invalid_response_buffer };
    }
    const received = component_port.invokeGenerated(.endpoint_recv, port, request, now_ticks) catch |err| return dispatch.mapError(err);

    var response = @import("std").mem.zeroes(abi.EndpointRecvResponse);
    if (received) |message| {
        response.present = 1;
        response.has_attached_capability = @intFromBool(message.attached_capability != null);
        response.message = message.message;
    }
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}
