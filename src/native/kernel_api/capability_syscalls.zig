const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const abi = @import("../core/abi.zig");
const request_header = @import("../core/request_header.zig");
const capability = @import("capability.zig");
const capability_wire = @import("capability_wire.zig");
const wire = @import("../core/capability_wire.zig");

pub fn dispatchCapabilityMint(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const encoded = dispatch.readRequest(abi.CapabilityMintWireRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    request_header.validateHeader(encoded.header, abi.opcode(.capability_mint)) catch |err| return dispatch.mapError(err);
    var decoded: capability.MintRequest = undefined;
    if (!capability_wire.mintFromWireInto(encoded, &decoded)) return dispatch.invalidRequest();
    var local_port = port.*;
    local_port.syscall_caller_task_id = memory.caller_task_id;
    local_port.syscall_header_prevalidated = false;
    const response = component_port.invokeGenerated(.capability_mint, &local_port, .{ .header = encoded.header, .policy_capability_id = encoded.policy_capability_id, .request = decoded }, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}

pub fn dispatchCapabilityDerive(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const encoded = dispatch.readRequest(abi.CapabilityDeriveWireRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    request_header.validateHeader(encoded.header, abi.opcode(.capability_derive)) catch |err| return dispatch.mapError(err);
    var decoded: capability.DeriveRequest = undefined;
    if (!capability_wire.deriveFromWireInto(encoded, &decoded)) return dispatch.invalidRequest();
    var local_port = port.*;
    local_port.syscall_caller_task_id = memory.caller_task_id;
    local_port.syscall_header_prevalidated = false;
    const response = component_port.invokeGenerated(.capability_derive, &local_port, .{ .header = encoded.header, .request = decoded }, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}

pub fn dispatchCapabilityPass(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const encoded = dispatch.readRequest(abi.CapabilityPassWireRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    request_header.validateHeader(encoded.header, abi.opcode(.capability_pass)) catch |err| return dispatch.mapError(err);
    if (!capability_wire.passEncodingIsValid(encoded)) return dispatch.invalidRequest();
    var local_port = port.*;
    local_port.syscall_caller_task_id = memory.caller_task_id;
    local_port.syscall_header_prevalidated = false;
    const response = component_port.invokeGenerated(.capability_pass, &local_port, .{
        .header = encoded.header,
        .capability_id = encoded.capability_id,
        .receiver_task_id = encoded.receiver_task_id,
        .revoke_source = encoded.flags & wire.PASS_REVOKE_SOURCE != 0,
    }, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}

pub fn dispatchCapabilityRevoke(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeNoResponse(.capability_revoke, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchCapabilityQuery(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.capability_query, port, memory, now_ticks, request_addr, response_addr, response_len);
}
