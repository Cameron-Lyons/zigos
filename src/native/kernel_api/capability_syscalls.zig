const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");

pub fn dispatchCapabilityMint(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.capability_mint, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchCapabilityDerive(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.capability_derive, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchCapabilityPass(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.capability_pass, port, memory, now_ticks, request_addr, response_addr, response_len);
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
