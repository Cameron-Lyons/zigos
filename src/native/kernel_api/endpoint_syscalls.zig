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

fn validOutputSpan(address: usize, length: usize, alignment: usize) bool {
    if (length == 0) return true;
    const end = std.math.add(usize, address, length) catch return false;
    return address >= 0x10000 and address % alignment == 0 and end > address and end <= 0x0000_8000_0000_0000;
}

pub fn dispatchEndpointCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const wire = dispatch.readRequest(abi.EndpointCreateWireRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    if (wire.reserved != 0 or wire.flags & ~@as(u16, 7) != 0 or
        wire.header.subject_task_id != memory.caller_task_id) return dispatch.invalidRequest();
    @import("../core/request_header.zig").validateHeader(wire.header, abi.opcode(.endpoint_create)) catch |err| return dispatch.mapError(err);
    var label_buffer: [endpoint.MAX_ENDPOINT_LABEL_BYTES]u8 = undefined;
    const label = dispatch.copyUserBytes(memory, wire.label_address, wire.label_bytes, &label_buffer) orelse return dispatch.invalidRequest();
    const request = component_port.EndpointCreateRequest{
        .header = wire.header,
        .authority_capability_id = wire.authority_capability_id,
        .owner_task_id = wire.owner_task_id,
        .label = label,
        .flags = @bitCast(wire.flags),
    };
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
    const wire = dispatch.readRequest(abi.EndpointSendWireRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    if (!wire.validEncoding() or wire.header.subject_task_id != memory.caller_task_id) return dispatch.invalidRequest();
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    const length: usize = wire.payload_bytes;
    var staged: []const u8 = payload[0..0];
    if (length != 0) {
        const address = std.math.cast(usize, wire.payload_address) orelse return dispatch.invalidRequest();
        const end = std.math.add(usize, address, length) catch return dispatch.invalidRequest();
        if (address < 0x10000 or end > 0x0000_8000_0000_0000) return dispatch.invalidRequest();
        const source: [*]const u8 = @ptrFromInt(address);
        staged = dispatch.copyUserSlice(memory, source[0..length], &payload) orelse return dispatch.invalidRequest();
    }
    var request: component_port.EndpointSendRequest = undefined;
    if (!component_port.endpointSendFromWireInto(wire, staged, &request)) return dispatch.invalidRequest();
    var local_port = port.*;
    local_port.syscall_caller_task_id = memory.caller_task_id;
    local_port.syscall_header_prevalidated = false;
    component_port.invokeGenerated(.endpoint_send, &local_port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    const wire = dispatch.readRequest(abi.EndpointRecvWireRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    if (!wire.validEncoding() or wire.header.subject_task_id != memory.caller_task_id or
        wire.receiver_task_id != memory.caller_task_id) return dispatch.invalidRequest();
    if (response_len < @sizeOf(abi.EndpointRecvResponse)) return .{ .status = .buffer_too_small };
    const capacity: usize = wire.payload_capacity;
    // Empty payload capacity grants no write authority and ignores its address.
    const payload_address = if (capacity == 0) 0 else std.math.cast(usize, wire.payload_address) orelse return .{ .status = .invalid_response_buffer };
    const user_capability_address = std.math.cast(usize, wire.attached_capability_address) orelse return .{ .status = .invalid_response_buffer };
    if (!validOutputSpan(response_addr, response_len, 1) or
        !validOutputSpan(payload_address, capacity, 1) or
        !validOutputSpan(user_capability_address, @sizeOf(abi.CapabilityDescriptor), @alignOf(abi.CapabilityDescriptor)) or
        rangesOverlap(response_addr, response_len, payload_address, capacity) or
        rangesOverlap(response_addr, response_len, user_capability_address, @sizeOf(abi.CapabilityDescriptor)) or
        rangesOverlap(payload_address, capacity, user_capability_address, @sizeOf(abi.CapabilityDescriptor)))
    {
        return .{ .status = .invalid_response_buffer };
    }
    if (dispatch.preflightResponse(memory, response_addr, response_len, @sizeOf(abi.EndpointRecvResponse))) |failure| return failure;
    if (!dispatch.prepareUserRange(memory, payload_address, capacity, 1, .write) or
        !dispatch.prepareUserRange(memory, user_capability_address, @sizeOf(abi.CapabilityDescriptor), @alignOf(abi.CapabilityDescriptor), .write))
        return .{ .status = .invalid_response_buffer };
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    // The port initializes this complete descriptor only when the returned
    // message carries one; that same condition guards publication below.
    var attached_capability: abi.CapabilityDescriptor = undefined;
    var request: component_port.EndpointRecvRequest = undefined;
    if (!component_port.endpointRecvFromWireInto(wire, payload[0..capacity], &attached_capability, &request)) return dispatch.invalidRequest();
    var local_port = port.*;
    local_port.syscall_caller_task_id = memory.caller_task_id;
    local_port.syscall_header_prevalidated = false;
    const received = component_port.invokeGenerated(.endpoint_recv, &local_port, request, now_ticks) catch |err| return dispatch.mapError(err);

    var response = @import("std").mem.zeroes(abi.EndpointRecvResponse);
    if (received) |message| {
        const user_payload = if (capacity == 0) payload[0..0] else @as([*]u8, @ptrFromInt(payload_address))[0..capacity];
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
