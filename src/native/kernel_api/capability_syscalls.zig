const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    syscall_abi.declare(.capability_mint, .capability, component_port.CapabilityMintRequest, abi.CapabilityDescriptor, dispatchCapabilityMint, .plain),
    syscall_abi.declare(.capability_derive, .capability, component_port.CapabilityDeriveRequest, abi.CapabilityDescriptor, dispatchCapabilityDerive, .plain),
    syscall_abi.declare(.capability_pass, .capability, component_port.CapabilityPassRequest, abi.CapabilityDescriptor, dispatchCapabilityPass, .plain),
    syscall_abi.declare(.capability_revoke, .capability, component_port.CapabilityRevokeRequest, void, dispatchCapabilityRevoke, .plain),
    syscall_abi.declare(.capability_query, .capability, component_port.CapabilityQueryRequest, abi.CapabilityDescriptor, dispatchCapabilityQuery, .plain),
};

pub fn dispatchCapabilityMint(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.CapabilityMintRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.capabilityMint(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}

pub fn dispatchCapabilityDerive(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    _ = now_ticks;
    const request = dispatch.readRequest(component_port.CapabilityDeriveRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.capabilityDerive(request) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}

pub fn dispatchCapabilityPass(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.CapabilityPassRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.capabilityPass(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}

pub fn dispatchCapabilityRevoke(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    _ = response_len;
    _ = response_addr;
    const request = dispatch.readRequest(component_port.CapabilityRevokeRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    port.capabilityRevoke(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.success();
}

pub fn dispatchCapabilityQuery(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.CapabilityQueryRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.capabilityQuery(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}
