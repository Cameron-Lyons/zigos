const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    .{ .operation = .shared_memory_create, .domain = .shared_memory, .Request = component_port.SharedMemoryCreateRequest, .Response = abi.SharedMemoryCreateResponse, .handler = dispatchSharedMemoryCreate },
    .{ .operation = .shared_memory_map, .domain = .shared_memory, .Request = component_port.SharedMemoryMapRequest, .Response = abi.SharedMemoryDescriptor, .handler = dispatchSharedMemoryMap },
    .{ .operation = .shared_memory_unmap, .domain = .shared_memory, .Request = component_port.SharedMemoryUnmapRequest, .Response = abi.BoolResponse, .handler = dispatchSharedMemoryUnmap },
    .{ .operation = .shared_memory_revoke, .domain = .shared_memory, .Request = component_port.SharedMemoryRevokeRequest, .Response = abi.SharedMemoryDescriptor, .handler = dispatchSharedMemoryRevoke },
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
