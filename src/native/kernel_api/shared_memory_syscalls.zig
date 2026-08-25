const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");

pub fn dispatchSharedMemoryCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.SharedMemoryCreateRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const created = component_port.invokeGeneratedFromValidatedSyscall(.shared_memory_create, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.SharedMemoryCreateResponse{
        .object = created.object,
        .capability = created.capability,
        .capability_id = created.capability_id,
    });
}

pub fn dispatchSharedMemoryMap(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.shared_memory_map, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchSharedMemoryUnmap(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.SharedMemoryUnmapRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const unmapped = component_port.invokeGeneratedFromValidatedSyscall(.shared_memory_unmap, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.boolResponse(unmapped));
}

pub fn dispatchSharedMemoryRevoke(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.shared_memory_revoke, port, memory, now_ticks, request_addr, response_addr, response_len);
}
