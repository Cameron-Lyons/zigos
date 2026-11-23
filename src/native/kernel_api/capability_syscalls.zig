const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const capability_wire = @import("capability_wire.zig");
const wire = @import("../core/capability_wire.zig");

pub fn dispatchCapabilityMint(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const encoded = dispatch.decode(abi.CapabilityMintWireRequest, request);
    var decoded: capability.MintRequest = undefined;
    if (!capability_wire.mintFromWireInto(encoded, &decoded)) return dispatch.invalidRequest();
    const response = component_port.invokeGenerated(.capability_mint, port, .{ .header = encoded.header, .policy_capability_id = encoded.policy_capability_id, .request = decoded }, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}

pub fn dispatchCapabilityDerive(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const encoded = dispatch.decode(abi.CapabilityDeriveWireRequest, request);
    var decoded: capability.DeriveRequest = undefined;
    if (!capability_wire.deriveFromWireInto(encoded, &decoded)) return dispatch.invalidRequest();
    const response = component_port.invokeGenerated(.capability_derive, port, .{ .header = encoded.header, .request = decoded }, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, response);
}

pub fn dispatchCapabilityPass(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const encoded = dispatch.decode(abi.CapabilityPassWireRequest, request);
    if (!capability_wire.passEncodingIsValid(encoded)) return dispatch.invalidRequest();
    const response = component_port.invokeGenerated(.capability_pass, port, .{
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
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeNoResponse(.capability_revoke, port, memory, now_ticks, request, response_addr, response_len);
}

pub fn dispatchCapabilityQuery(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.capability_query, port, memory, now_ticks, request, response_addr, response_len);
}
