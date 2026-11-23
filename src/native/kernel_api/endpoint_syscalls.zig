const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const endpoint = @import("endpoint.zig");
const std = @import("std");

pub fn dispatchEndpointCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const wire = dispatch.decode(abi.EndpointCreateWireRequest, request);
    if (wire.reserved != 0 or wire.flags & ~abi.ENDPOINT_CREATE_KNOWN_FLAGS != 0) return dispatch.invalidRequest();
    var label_buffer: [endpoint.MAX_ENDPOINT_LABEL_BYTES]u8 = undefined;
    const label = dispatch.copyUserBytes(memory, wire.label_address, wire.label_bytes, &label_buffer) orelse return dispatch.invalidRequest();
    const created = component_port.invokeGenerated(.endpoint_create, port, .{
        .header = wire.header,
        .authority_capability_id = wire.authority_capability_id,
        .owner_task_id = wire.owner_task_id,
        .label = label,
        .flags = @bitCast(wire.flags),
    }, now_ticks) catch |err| return dispatch.mapError(err);
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
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.endpoint_connect, port, memory, now_ticks, request, response_addr, response_len);
}

pub fn dispatchEndpointSend(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    _ = response_len;
    _ = response_addr;
    const wire = dispatch.decode(abi.EndpointSendWireRequest, request);
    if (!wire.validEncoding()) return dispatch.invalidRequest();
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    const staged = dispatch.copyUserBytes(memory, wire.payload_address, wire.payload_bytes, &payload) orelse return dispatch.invalidRequest();
    var send: component_port.EndpointSendRequest = undefined;
    if (!component_port.endpointSendFromWireInto(wire, staged, &send)) return dispatch.invalidRequest();
    component_port.invokeGenerated(.endpoint_send, port, send, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.success();
}

pub fn dispatchEndpointClose(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeNoResponse(.endpoint_close, port, memory, now_ticks, request, response_addr, response_len);
}

pub fn dispatchEndpointRecv(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const wire = dispatch.decode(abi.EndpointRecvWireRequest, request);
    if (!wire.validEncoding() or wire.receiver_task_id != memory.caller_task_id) return dispatch.invalidRequest();
    if (response_len < @sizeOf(abi.EndpointRecvResponse)) return .{ .status = .buffer_too_small };
    const capacity: usize = wire.payload_capacity;
    // Empty payload capacity grants no write authority and ignores its address.
    const outputs = [_]dispatch.OutputRange{
        .{ .address = response_addr, .declared_bytes = response_len, .prepared_bytes = @sizeOf(abi.EndpointRecvResponse), .alignment = 1 },
        .{ .address = if (capacity == 0) 0 else @intCast(wire.payload_address), .declared_bytes = capacity, .prepared_bytes = capacity, .alignment = 1 },
        .{ .address = @intCast(wire.attached_capability_address), .declared_bytes = @sizeOf(abi.CapabilityDescriptor), .prepared_bytes = @sizeOf(abi.CapabilityDescriptor), .alignment = @alignOf(abi.CapabilityDescriptor) },
    };
    // Reject every hostile or aliased geometry before any output callback.
    for (outputs, 0..) |output, index| {
        if (!dispatch.checkedSpan(output.address, output.declared_bytes, output.alignment)) return .{ .status = .invalid_response_buffer };
        for (outputs[0..index]) |previous| {
            if (dispatch.spansOverlap(output.address, output.declared_bytes, previous.address, previous.declared_bytes)) return .{ .status = .invalid_response_buffer };
        }
    }
    for (outputs) |output| {
        if (!dispatch.prepareOutput(memory, output)) return .{ .status = .invalid_response_buffer };
    }
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    // The port initializes this complete descriptor only when the returned
    // message carries one; that same condition guards publication below.
    var attached_capability: abi.CapabilityDescriptor = undefined;
    var receive: component_port.EndpointRecvRequest = undefined;
    if (!component_port.endpointRecvFromWireInto(wire, payload[0..capacity], &attached_capability, &receive)) return dispatch.invalidRequest();
    const received = component_port.invokeGenerated(.endpoint_recv, port, receive, now_ticks) catch |err| return dispatch.mapError(err);

    // Dequeue and capability transfer now belong to this request once. Publish
    // payload, capability and response together, or none of them.
    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    var staged: [dispatch.MAX_OUTPUTS]dispatch.Output = undefined;
    var count: usize = 0;
    if (received) |message| {
        response.present = 1;
        response.has_attached_capability = @intFromBool(message.attached_capability != null);
        response.message = message.message;
        if (message.message.payload_len != 0) {
            staged[count] = .{ .address = outputs[1].address, .bytes = payload[0..message.message.payload_len] };
            count += 1;
        }
        if (message.attached_capability != null) {
            staged[count] = .{ .address = outputs[2].address, .bytes = std.mem.asBytes(&attached_capability) };
            count += 1;
        }
    }
    staged[count] = .{ .address = response_addr, .bytes = std.mem.asBytes(&response) };
    count += 1;
    if (!dispatch.commitOutputs(memory, staged[0..count])) return .{ .status = .invalid_response_buffer };
    return .{ .status = .success, .bytes_written = @sizeOf(abi.EndpointRecvResponse) };
}
