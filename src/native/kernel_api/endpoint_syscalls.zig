const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const endpoint = @import("endpoint.zig");
const std = @import("std");

fn rangesOverlap(first: usize, first_len: usize, second: usize, second_len: usize) bool {
    if (first_len == 0 or second_len == 0) return false;
    const first_end = std.math.add(usize, first, first_len) catch return true;
    const second_end = std.math.add(usize, second, second_len) catch return true;
    return first < second_end and second < first_end;
}

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
    const created = component_port.invokeGeneratedFromValidatedSyscall(.endpoint_create, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    request.payload = dispatch.copyUserSlice(memory, request.payload, &payload) orelse return dispatch.invalidRequest();
    component_port.invokeGeneratedFromValidatedSyscall(.endpoint_send, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.success();
}

pub fn dispatchEndpointClose(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeNoResponse(.endpoint_close, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchEndpointRecv(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    var request = dispatch.readRequest(component_port.EndpointRecvRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    if (dispatch.preflightResponse(memory, response_addr, response_len, @sizeOf(abi.EndpointRecvResponse))) |failure| return failure;
    if (request.payload_out.len > endpoint.MAX_MESSAGE_BYTES or
        !dispatch.prepareUserRange(
            memory,
            @intFromPtr(request.payload_out.ptr),
            request.payload_out.len,
            1,
            .write,
        ) or
        !dispatch.prepareUserRange(
            memory,
            @intFromPtr(request.attached_capability_out),
            @sizeOf(abi.CapabilityDescriptor),
            @alignOf(abi.CapabilityDescriptor),
            .write,
        ))
    {
        return .{ .status = .invalid_response_buffer };
    }
    const user_payload = request.payload_out;
    const user_capability_address = @intFromPtr(request.attached_capability_out);
    if (rangesOverlap(response_addr, response_len, @intFromPtr(user_payload.ptr), user_payload.len) or
        rangesOverlap(response_addr, response_len, user_capability_address, @sizeOf(abi.CapabilityDescriptor)) or
        rangesOverlap(@intFromPtr(user_payload.ptr), user_payload.len, user_capability_address, @sizeOf(abi.CapabilityDescriptor)))
    {
        return .{ .status = .invalid_response_buffer };
    }
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    var attached_capability: abi.CapabilityDescriptor = undefined;
    request.payload_out = payload[0..user_payload.len];
    request.attached_capability_out = &attached_capability;
    const received = component_port.invokeGeneratedFromValidatedSyscall(.endpoint_recv, port, request, now_ticks) catch |err| return dispatch.mapError(err);

    var response = @import("std").mem.zeroes(abi.EndpointRecvResponse);
    if (received) |message| {
        if (!dispatch.copyToUser(memory, user_payload, payload[0..message.message.payload_len])) {
            return .{ .status = .invalid_response_buffer };
        }
        if (message.attached_capability != null and !dispatch.writeUserValue(memory, user_capability_address, attached_capability)) {
            return .{ .status = .invalid_response_buffer };
        }
        response.present = 1;
        response.has_attached_capability = @intFromBool(message.attached_capability != null);
        response.message = message.message;
    }
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}
