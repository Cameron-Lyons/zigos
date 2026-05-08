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
    const request = dispatch.readRequest(component_port.EndpointConnectRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = component_port.invokeGenerated(.endpoint_connect, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
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
    var payload_buffer: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    request.payload = dispatch.copyUserSlice(memory, request.payload, &payload_buffer) orelse return dispatch.invalidRequest();
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
    const received = component_port.invokeGenerated(.endpoint_recv, port, request, now_ticks) catch |err| return dispatch.mapError(err);

    var response = @import("std").mem.zeroes(abi.EndpointRecvResponse);
    if (received) |message| {
        response.present = 1;
        response.has_attached_capability = @intFromBool(message.attached_capability != null);
        response.message = message.message;
        @memcpy(response.payload[0..message.payload_len], message.payload[0..message.payload_len]);
        if (message.attached_capability) |attached| {
            response.attached_capability = attached;
        }
    }
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}
