const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    syscall_abi.declare(.shared_memory_create, .shared_memory, component_port.SharedMemoryCreateRequest, abi.SharedMemoryCreateResponse, dispatchSharedMemoryCreate, .plain),
    syscall_abi.declare(.shared_memory_map, .shared_memory, component_port.SharedMemoryMapRequest, abi.SharedMemoryDescriptor, dispatchSharedMemoryMap, .plain),
    syscall_abi.declare(.shared_memory_unmap, .shared_memory, component_port.SharedMemoryUnmapRequest, abi.BoolResponse, dispatchSharedMemoryUnmap, .plain),
    syscall_abi.declare(.shared_memory_revoke, .shared_memory, component_port.SharedMemoryRevokeRequest, abi.SharedMemoryDescriptor, dispatchSharedMemoryRevoke, .plain),
};

pub fn dispatchSharedMemoryCreate(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.SharedMemoryCreateRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const created = port.sharedMemoryCreate(request, now_ticks) catch |err| return dispatch.mapError(err);
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
    const request = dispatch.readRequest(component_port.SharedMemoryMapRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.sharedMemoryMap(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
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
    const unmapped = port.sharedMemoryUnmap(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.BoolResponse{
        .value = @intFromBool(unmapped),
        ._reserved = [_]u8{0} ** 7,
    });
}

pub fn dispatchSharedMemoryRevoke(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.SharedMemoryRevokeRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.sharedMemoryRevoke(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}
