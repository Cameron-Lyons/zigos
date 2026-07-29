const std = @import("std");
const abi = @import("../../core/abi.zig");
const capability = @import("../../kernel_api/capability.zig");
const component_port = @import("../../kernel_api/component_port.zig");
const endpoint = @import("../../kernel_api/endpoint.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("../../task/generated_image_fixtures.zig") else struct {};
const principal = @import("../../core/principal.zig");
const shared_memory = @import("../../kernel_api/shared_memory.zig");
const signing = @import("../../core/signing.zig");
const syscall_surface = @import("../../kernel_api/syscall_surface.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const units = @import("../../core/units.zig");

pub const RESOURCE_PROBE_SHARED_MEMORY_BYTES = units.kibibytes(1);

pub fn createResourceProbeTask(
    kernel_port: *component_port.KernelPort,
    session_task_id: u64,
    session_authority_id: u64,
) !abi.TaskDescriptor {
    return createBootedProbeTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        8_001,
        8_001,
        "resource-proof",
        "app.resource-proof",
        RESOURCE_PROBE_SHARED_MEMORY_BYTES,
        81,
    );
}

pub fn createBootedServiceTask(
    kernel_port: *component_port.KernelPort,
    session_task_id: u64,
    session_authority_id: u64,
    owner: principal.PrincipalId,
    image_id: u64,
    label: []const u8,
    bundle_id: []const u8,
    tick: u64,
) !abi.TaskDescriptor {
    const image = try generated_image_fixtures.serviceImage();
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, tick, session_task_id),
        .authority_capability_id = session_authority_id,
        .request = .{
            .owner = owner,
            .component_class = .service_component,
            .budget = .{
                .cpu_time_ticks = 1_200,
                .memory_bytes = units.kibibytes(64),
                .endpoint_slots = 2,
                .shared_memory_bytes = shared_memory.PAGE_SIZE,
            },
            .local_only = true,
            .initial_component = .{
                .label = label,
                .entry = bundle_id,
            },
            .launch = .{
                .boundary = .userspace_process,
                .image_id = image_id,
                .component_abi_version = abi.ABI_VERSION,
                .signed = true,
                .bundle_id = bundle_id,
            },
            .userspace_image = &image,
        },
    };
    const result = syscall_surface.dispatch(
        kernel_port,
        session_task_id,
        tick,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn createBootedProbeTask(
    kernel_port: *component_port.KernelPort,
    session_task_id: u64,
    session_authority_id: u64,
    owner_serial: u64,
    image_id: u64,
    label: []const u8,
    bundle_id: []const u8,
    shared_memory_bytes: usize,
    tick: u64,
) !abi.TaskDescriptor {
    const image = try generated_image_fixtures.appImage();
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, tick, session_task_id),
        .authority_capability_id = session_authority_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = owner_serial },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_200,
                .memory_bytes = units.kibibytes(64),
                .endpoint_slots = 1,
                .shared_memory_bytes = shared_memory_bytes,
            },
            .local_only = true,
            .initial_component = .{
                .label = label,
                .entry = bundle_id,
            },
            .launch = .{
                .boundary = .userspace_process,
                .image_id = image_id,
                .component_abi_version = abi.ABI_VERSION,
                .signed = true,
                .bundle_id = bundle_id,
            },
            .userspace_image = &image,
        },
    };
    const result = syscall_surface.dispatch(
        kernel_port,
        session_task_id,
        tick,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn resourceQuery(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    tick: u64,
) !abi.ResourceDescriptor {
    var response = std.mem.zeroes(abi.ResourceDescriptor);
    const request = component_port.ResourceQueryRequest{
        .header = component_port.makeHeader(.resource_query, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .task_id = task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.ResourceDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn accountingQuery(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    tick: u64,
) !abi.AccountingDescriptor {
    var response = std.mem.zeroes(abi.AccountingDescriptor);
    const request = component_port.AccountingQueryRequest{
        .header = component_port.makeHeader(.accounting_query, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .task_id = task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.AccountingDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn expectEndpointCreate(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
) !abi.EndpointCreateResponse {
    return expectEndpointCreateWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, .{ .local_only = true }, tick);
}

pub fn expectEndpointCreateWithFlags(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    flags: endpoint.EndpointFlags,
    tick: u64,
) !abi.EndpointCreateResponse {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    const result = endpointCreateResultIntoWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, flags, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn endpointCreateResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    return endpointCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, tick, &response);
}

pub fn endpointCreateResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
    response: *abi.EndpointCreateResponse,
) syscall_surface.DispatchResult {
    return endpointCreateResultIntoWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, .{ .local_only = true }, tick, response);
}

pub fn endpointCreateResultIntoWithFlags(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    flags: endpoint.EndpointFlags,
    tick: u64,
    response: *abi.EndpointCreateResponse,
) syscall_surface.DispatchResult {
    const request = component_port.EndpointCreateRequest{
        .header = component_port.makeHeader(.endpoint_create, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = owner_task_id,
        .label = label,
        .flags = flags,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.EndpointCreateResponse));
}

pub fn expectEndpointConnect(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_endpoint_id: u64,
    tick: u64,
) !abi.EndpointDescriptor {
    var response = std.mem.zeroes(abi.EndpointDescriptor);
    const request = component_port.EndpointConnectRequest{
        .header = component_port.makeHeader(.endpoint_connect, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .peer_endpoint_capability_id = peer_endpoint_capability_id,
        .peer_endpoint_id = peer_endpoint_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.EndpointDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn expectEndpointSend(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    payload: []const u8,
    tick: u64,
) !void {
    const request = component_port.EndpointSendRequest{
        .header = component_port.makeHeader(.endpoint_send, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .payload = payload,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), 0, 0);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
}

pub fn expectEndpointRecv(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    tick: u64,
) !abi.EndpointRecvResponse {
    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    const request = component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .receiver_task_id = caller_task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.EndpointRecvResponse));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn expectSharedMemoryCreate(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
) !abi.SharedMemoryCreateResponse {
    var response = std.mem.zeroes(abi.SharedMemoryCreateResponse);
    const result = sharedMemoryCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, size_bytes, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn sharedMemoryCreateResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.SharedMemoryCreateResponse);
    return sharedMemoryCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, size_bytes, tick, &response);
}

pub fn sharedMemoryCreateResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
    response: *abi.SharedMemoryCreateResponse,
) syscall_surface.DispatchResult {
    const request = component_port.SharedMemoryCreateRequest{
        .header = component_port.makeHeader(.shared_memory_create, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = owner_task_id,
        .size_bytes = size_bytes,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.SharedMemoryCreateResponse));
}

pub fn expectSharedMemoryMap(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
) !void {
    _ = try expectSharedMemoryMapDescriptor(kernel_port, caller_task_id, shared_memory_capability_id, task_id, tick);
}

pub fn expectSharedMemoryMapDescriptor(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
) !abi.SharedMemoryDescriptor {
    var response = std.mem.zeroes(abi.SharedMemoryDescriptor);
    const result = sharedMemoryMapResultInto(kernel_port, caller_task_id, shared_memory_capability_id, task_id, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn sharedMemoryMapResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.SharedMemoryDescriptor);
    return sharedMemoryMapResultInto(kernel_port, caller_task_id, shared_memory_capability_id, task_id, tick, &response);
}

pub fn sharedMemoryMapResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
    response: *abi.SharedMemoryDescriptor,
) syscall_surface.DispatchResult {
    const request = component_port.SharedMemoryMapRequest{
        .header = component_port.makeHeader(.shared_memory_map, tick, caller_task_id),
        .shared_memory_capability_id = shared_memory_capability_id,
        .task_id = task_id,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.SharedMemoryDescriptor));
}

pub fn expectSharedMemoryRevoke(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    tick: u64,
) !abi.SharedMemoryDescriptor {
    var response = std.mem.zeroes(abi.SharedMemoryDescriptor);
    const request = component_port.SharedMemoryRevokeRequest{
        .header = component_port.makeHeader(.shared_memory_revoke, tick, caller_task_id),
        .shared_memory_capability_id = shared_memory_capability_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.SharedMemoryDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn expectDeviceDescribe(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
) !abi.DeviceDescriptor {
    var response = std.mem.zeroes(abi.DeviceDescriptor);
    const result = deviceDescribeResultInto(kernel_port, caller_task_id, device_capability_id, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

pub fn deviceDescribeResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.DeviceDescriptor);
    return deviceDescribeResultInto(kernel_port, caller_task_id, device_capability_id, tick, &response);
}

pub fn deviceDescribeResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
    response: *abi.DeviceDescriptor,
) syscall_surface.DispatchResult {
    const request = component_port.DeviceDescribeRequest{
        .header = component_port.makeHeader(.device_describe, tick, caller_task_id),
        .device_capability_id = device_capability_id,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.DeviceDescriptor));
}

pub fn findServiceAuthority(
    capability_table: *const capability.CapabilityTable,
    task: *const task_runtime.TaskRecord,
    right: capability.CapabilityRight,
) ?u64 {
    for (task.capabilityIds()) |capability_id| {
        const record = capability_table.query(capability_id) orelse continue;
        if (record.target.kind == .service and record.rights.has(right)) return capability_id;
    }
    return null;
}

pub fn signer(label: []const u8, seed: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = signing.seedFromByte(seed),
    };
}
