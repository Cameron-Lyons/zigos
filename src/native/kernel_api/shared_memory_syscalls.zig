const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");

pub fn dispatchSharedMemoryCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const created = component_port.invokeGenerated(.shared_memory_create, port, dispatch.decode(component_port.SharedMemoryCreateRequest, request), now_ticks) catch |err| return dispatch.mapError(err);
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
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.shared_memory_map, port, memory, now_ticks, request, response_addr, response_len);
}

pub fn dispatchSharedMemoryUnmap(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const unmapped = component_port.invokeGenerated(.shared_memory_unmap, port, dispatch.decode(component_port.SharedMemoryUnmapRequest, request), now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.boolResponse(unmapped));
}

pub fn dispatchSharedMemoryRevoke(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.shared_memory_revoke, port, memory, now_ticks, request, response_addr, response_len);
}
