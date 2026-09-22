const std = @import("std");
const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const endpoint = @import("endpoint.zig");
const native_kernel = @import("native_kernel.zig");
const task_runtime = @import("../task/task_runtime.zig");

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
    const request = dispatch.readRequest(component_port.EndpointSendRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    if (request.payload.len > endpoint.MAX_MESSAGE_BYTES) return dispatch.invalidRequest();
    if (request.payload.len != 0 and !dispatch.validateUserRange(
        memory,
        @intFromPtr(request.payload.ptr),
        request.payload.len,
        1,
        .read,
    )) {
        return dispatch.invalidRequest();
    }
    component_port.invokeGeneratedFromValidatedSyscall(.endpoint_send, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    const received = component_port.invokeGeneratedFromValidatedSyscall(.endpoint_recv, port, request, now_ticks) catch |err| return dispatch.mapError(err);

    var response = @import("std").mem.zeroes(abi.EndpointRecvResponse);
    if (received) |message| {
        response.present = 1;
        response.has_attached_capability = @intFromBool(message.attached_capability != null);
        response.message = message.message;
    }
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}

pub const RegisterFrame = struct {
    eax: usize,
    edx: usize,
    esi: usize,
    r8: usize,
    r9: usize,
    r10: usize,
    r14: usize,
    r15: usize,
};

pub const RegisterReply = struct {
    status: abi.SyscallStatus,
    bytes_written: u32 = 0,
    denial_reason: abi.DenialReason = .none,
    attached_slot: u64 = abi.REGISTER_IPC_SLOT_NONE,
    correlation_id: u64 = 0,
    word0: u64 = 0,
    word1: u64 = 0,
    word2: u64 = 0,
};

pub fn dispatchRegister(
    port: *component_port.KernelPort,
    caller_task_id: u64,
    now_ticks: u64,
    frame: RegisterFrame,
) ?RegisterReply {
    if (frame.eax & abi.REGISTER_IPC_SELECT == 0) return null;
    const opcode: u16 = @truncate(frame.eax);
    if (opcode == abi.opcode(.endpoint_send)) {
        return registerSend(port, caller_task_id, now_ticks, frame);
    }
    if (opcode == abi.opcode(.endpoint_recv)) {
        return registerRecv(port, caller_task_id, now_ticks, frame);
    }
    return .{
        .status = .unsupported_operation,
        .denial_reason = .unsupported_operation,
    };
}

pub fn wordsFromPayload(payload: []const u8) [3]u64 {
    var words = [3]u64{ 0, 0, 0 };
    const length = @min(payload.len, abi.REGISTER_IPC_PAYLOAD_BYTES);
    for (payload[0..length], 0..) |byte, index| {
        const shift: u6 = @intCast((index % 8) * 8);
        words[index / 8] |= @as(u64, byte) << shift;
    }
    return words;
}

pub fn payloadFromWords(words: [3]u64, length: usize) [abi.REGISTER_IPC_PAYLOAD_BYTES]u8 {
    var bytes = [_]u8{0} ** abi.REGISTER_IPC_PAYLOAD_BYTES;
    const count = @min(length, abi.REGISTER_IPC_PAYLOAD_BYTES);
    for (bytes[0..count], 0..) |*byte, index| {
        const shift: u6 = @intCast((index % 8) * 8);
        byte.* = @truncate(words[index / 8] >> shift);
    }
    return bytes;
}

fn registerSend(
    port: *component_port.KernelPort,
    caller_task_id: u64,
    now_ticks: u64,
    frame: RegisterFrame,
) RegisterReply {
    const bits = frame.r9;
    const length = abi.registerIpcLength(bits);
    if (length > abi.REGISTER_IPC_PAYLOAD_BYTES) return .{ .status = .invalid_request_pointer, .denial_reason = .invalid_target };
    const task = port.kernel.runtime.find(caller_task_id) orelse return missingCapability();
    const endpoint_capability_id = resolveSelector(task, frame.edx, bits) orelse return missingCapability();
    const attached = if (optionalSelector(frame.r8, bits)) |selector|
        resolveSelector(task, selector, bits) orelse return missingCapability()
    else
        null;
    const payload = payloadFromWords(.{ frame.esi, frame.r14, frame.r15 }, length);
    port.kernel.endpointSend(
        callContext(caller_task_id, endpoint_capability_id),
        frame.r10,
        payload[0..length],
        attached,
        bits & abi.REGISTER_IPC_MOVE != 0,
        now_ticks,
    ) catch |err| return replyFrom(dispatch.mapError(err));
    return .{ .status = .success };
}

fn registerRecv(
    port: *component_port.KernelPort,
    caller_task_id: u64,
    now_ticks: u64,
    frame: RegisterFrame,
) RegisterReply {
    const bits = frame.r9;
    const task = port.kernel.runtime.find(caller_task_id) orelse return missingCapability();
    const endpoint_capability_id = resolveSelector(task, frame.edx, bits) orelse return missingCapability();
    var payload = [_]u8{0} ** abi.REGISTER_IPC_PAYLOAD_BYTES;
    const capacity = @min(frame.r8, abi.REGISTER_IPC_PAYLOAD_BYTES);
    const received = port.kernel.endpointRecv(
        callContext(caller_task_id, endpoint_capability_id),
        caller_task_id,
        payload[0..capacity],
        now_ticks,
    ) catch |err| return replyFrom(dispatch.mapError(err));
    const message = received orelse return .{ .status = .success };
    const payload_len: usize = message.message.payload_len;
    const words = wordsFromPayload(payload[0..payload_len]);
    const attached_slot: u64 = if (message.attached_capability) |descriptor| blk: {
        const slot = task_runtime.cspaceSlotForCapability(task, descriptor.capability_id) orelse
            break :blk abi.REGISTER_IPC_SLOT_NONE;
        break :blk @as(u64, slot);
    } else abi.REGISTER_IPC_SLOT_NONE;
    return .{
        .status = .success,
        .bytes_written = message.message.payload_len,
        .attached_slot = attached_slot,
        .correlation_id = message.message.correlation_id,
        .word0 = words[0],
        .word1 = words[1],
        .word2 = words[2],
    };
}

fn callContext(caller_task_id: u64, capability_id: u64) native_kernel.KernelCallContext {
    return .{
        .caller_task_id = caller_task_id,
        .presented_capability_id = capability_id,
        .target = .none,
    };
}

fn resolveSelector(task: *const task_runtime.TaskRecord, selector: usize, bits: usize) ?u64 {
    if (bits & abi.REGISTER_IPC_CAPABILITY_ID != 0) {
        const capability_id: u64 = @intCast(selector);
        if (capability_id == 0 or !task.hasCapability(capability_id)) return null;
        return capability_id;
    }
    if (selector > std.math.maxInt(u8)) return null;
    return task_runtime.capabilityIdAtCspaceSlot(task, @intCast(selector));
}

fn optionalSelector(selector: usize, bits: usize) ?usize {
    if (bits & abi.REGISTER_IPC_CAPABILITY_ID != 0) {
        if (selector == 0) return null;
        return selector;
    }
    if (selector == abi.REGISTER_IPC_SLOT_NONE) return null;
    return selector;
}

fn missingCapability() RegisterReply {
    return replyFrom(dispatch.mapError(error.CapabilityNotFound));
}

fn replyFrom(result: dispatch.DispatchResult) RegisterReply {
    return .{
        .status = result.status,
        .bytes_written = result.bytes_written,
        .denial_reason = result.denial_reason,
    };
}

test "register ipc payload words round trip" {
    const payload = "notes-2026";
    const words = wordsFromPayload(payload);
    const restored = payloadFromWords(words, payload.len);
    try std.testing.expectEqualStrings(payload, restored[0..payload.len]);
    try std.testing.expectEqual(@as(usize, 10), abi.registerIpcLength(abi.packRegisterIpc(payload.len, false, true)));
}
