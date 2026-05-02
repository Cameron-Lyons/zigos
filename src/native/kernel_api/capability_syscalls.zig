const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    .{ .operation = .capability_mint, .domain = .capability, .Request = component_port.CapabilityMintRequest, .Response = abi.CapabilityDescriptor, .handler = dispatchCapabilityMint },
    .{ .operation = .capability_derive, .domain = .capability, .Request = component_port.CapabilityDeriveRequest, .Response = abi.CapabilityDescriptor, .handler = dispatchCapabilityDerive },
    .{ .operation = .capability_pass, .domain = .capability, .Request = component_port.CapabilityPassRequest, .Response = abi.CapabilityDescriptor, .handler = dispatchCapabilityPass },
    .{ .operation = .capability_revoke, .domain = .capability, .Request = component_port.CapabilityRevokeRequest, .Response = void, .handler = dispatchCapabilityRevoke },
    .{ .operation = .capability_query, .domain = .capability, .Request = component_port.CapabilityQueryRequest, .Response = abi.CapabilityDescriptor, .handler = dispatchCapabilityQuery },
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
