const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    .{ .operation = .shared_memory_create, .domain = .shared_memory, .Request = component_port.SharedMemoryCreateRequest, .Response = abi.SharedMemoryCreateResponse },
    .{ .operation = .shared_memory_map, .domain = .shared_memory, .Request = component_port.SharedMemoryMapRequest, .Response = abi.SharedMemoryDescriptor },
    .{ .operation = .shared_memory_unmap, .domain = .shared_memory, .Request = component_port.SharedMemoryUnmapRequest, .Response = abi.BoolResponse },
    .{ .operation = .shared_memory_revoke, .domain = .shared_memory, .Request = component_port.SharedMemoryRevokeRequest, .Response = abi.SharedMemoryDescriptor },
};
