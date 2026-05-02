const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const task_runtime = @import("../task/task_runtime.zig");

const USER_POINTER_FLOOR: usize = 0x10000;
const USER_POINTER_CEILING_32: usize = 0xC0000000;

pub const DispatchResult = struct {
    status: abi.SyscallStatus,
    bytes_written: u32 = 0,
    denial_reason: abi.DenialReason = .none,
};

pub const UserMemoryAccess = enum {
    read,
    write,
};

pub const UserMemoryContext = struct {
    address_space: ?*const task_runtime.AddressSpaceRecord,

    pub fn init(port: *const component_port.KernelPort, caller_task_id: u64) UserMemoryContext {
        const runtime = port.kernel.runtime;
        const task = if (caller_task_id != 0) runtime.find(caller_task_id) else null;
        const address_space = if (task) |caller_task|
            runtime.findAddressSpaceConst(caller_task.address_space_id)
        else
            null;
        return .{ .address_space = address_space };
    }
};

pub fn readRequest(comptime T: type, memory: UserMemoryContext, request_addr: usize) ?T {
    return readUserValue(T, memory, request_addr);
}

pub fn readUserValue(comptime T: type, memory: UserMemoryContext, addr: usize) ?T {
    if (!validateUserRange(memory, addr, @sizeOf(T), @alignOf(T), .read)) return null;
    const ptr: *const T = @ptrFromInt(addr);
    return ptr.*;
}

pub fn copyUserSlice(memory: UserMemoryContext, slice: []const u8, dest: []u8) ?[]const u8 {
    if (slice.len > dest.len) return null;
    if (slice.len == 0) return dest[0..0];
    if (!validateUserRange(memory, @intFromPtr(slice.ptr), slice.len, 1, .read)) return null;
    @memcpy(dest[0..slice.len], slice);
    return dest[0..slice.len];
}

pub fn validateUserRange(memory: UserMemoryContext, addr: usize, len: usize, alignment: usize, access: UserMemoryAccess) bool {
    if (len == 0) return true;
    if (addr == 0 or addr < USER_POINTER_FLOOR) return false;
    if (alignment != 0 and addr % alignment != 0) return false;
    const end_exclusive = std.math.add(usize, addr, len) catch return false;
    if (end_exclusive <= addr) return false;

    if (builtin.target.os.tag == .freestanding and @bitSizeOf(usize) <= 32) {
        if (end_exclusive > USER_POINTER_CEILING_32) return false;
    }

    if (memory.address_space) |address_space| {
        if (address_space.region_count == 0) return true;
        return validateAddressSpaceRange(address_space, addr, end_exclusive, access);
    }
    return true;
}

pub fn validateAddressSpaceRange(
    address_space: *const task_runtime.AddressSpaceRecord,
    addr: usize,
    end_exclusive: usize,
    access: UserMemoryAccess,
) bool {
    if (address_space.region_count == 0) return false;

    var covered_until = addr;
    while (covered_until < end_exclusive) {
        var advanced = false;
        for (address_space.regions[0..address_space.region_count]) |region| {
            const region_start = std.math.cast(usize, region.virtual_address) orelse continue;
            const region_end = std.math.add(usize, region_start, region.size_bytes) catch continue;
            if (covered_until < region_start or covered_until >= region_end) continue;
            if (!regionAllows(region.access, access)) return false;
            covered_until = @min(end_exclusive, region_end);
            advanced = true;
            break;
        }
        if (!advanced) return false;
    }
    return true;
}

pub fn writeResponse(memory: UserMemoryContext, response_addr: usize, response_len: usize, value: anytype) DispatchResult {
    const buffer = responseBuffer(memory, response_addr, response_len) orelse return .{
        .status = .invalid_response_buffer,
    };
    const bytes = std.mem.asBytes(&value);
    if (buffer.len < bytes.len) return .{
        .status = .buffer_too_small,
    };
    @memcpy(buffer[0..bytes.len], bytes);
    return .{
        .status = .success,
        .bytes_written = @intCast(bytes.len),
    };
}

pub fn success() DispatchResult {
    return .{ .status = .success };
}

pub fn invalidRequest() DispatchResult {
    return .{ .status = .invalid_request_pointer };
}

pub fn mapError(err: anyerror) DispatchResult {
    if (err == error.UnsupportedAbiVersion) return .{ .status = .unsupported_abi_version };
    if (err == error.UnexpectedOperation) return .{
        .status = .unsupported_operation,
        .denial_reason = .unsupported_operation,
    };
    if (err == error.PermissionDenied or err == error.RightsEscalation) return .{
        .status = .denied,
        .denial_reason = .policy_denied,
    };
    if (err == error.UserspaceLaunchRequired or err == error.InvalidUserspaceImage) return .{
        .status = .denied,
        .denial_reason = .policy_denied,
    };
    if (err == error.CapabilityNotFound) return .{
        .status = .not_found,
        .denial_reason = .capability_missing,
    };
    if (err == error.CapabilityRevoked) return .{
        .status = .denied,
        .denial_reason = .capability_revoked,
    };
    if (err == error.ScopeViolation or err == error.ScopeEscalation or err == error.SubjectTaskMismatch) return .{
        .status = .denied,
        .denial_reason = .scope_violation,
    };
    if (err == error.LeaseEscalation) return .{
        .status = .denied,
        .denial_reason = .capability_expired,
    };
    if (err == error.InvalidCapabilityTarget or err == error.InvalidCapabilityRights) return .{
        .status = .denied,
        .denial_reason = .invalid_target,
    };
    if (err == error.InterfaceNameTooLong or err == error.MessageTooLarge) return .{
        .status = .denied,
        .denial_reason = .invalid_target,
    };
    if (err == error.InterfaceNotFound) return .{
        .status = .not_found,
        .denial_reason = .interface_not_found,
    };
    if (err == error.TaskNotFound or err == error.EndpointNotFound) return .{
        .status = .not_found,
        .denial_reason = .invalid_target,
    };
    if (err == error.DeviceNotFound or err == error.UnsupportedMmioWindow) return .{
        .status = .not_found,
        .denial_reason = .invalid_target,
    };
    if (err == error.InvalidPort or err == error.UnsupportedWidth) return .{
        .status = .denied,
        .denial_reason = .invalid_target,
    };
    if (err == error.TableFull or
        err == error.TargetTableFull or
        err == error.BindingTableFull or
        err == error.ComponentTableFull or
        err == error.CapabilityTableFull or
        err == error.TaskTableFull or
        err == error.EndpointBusy or
        err == error.QueueFull or
        err == error.PeerNotConnected or
        err == error.VersionMismatch)
    {
        return .{
            .status = .conflict,
            .denial_reason = .budget_exhausted,
        };
    }

    return .{ .status = .internal_error };
}

fn responseBuffer(memory: UserMemoryContext, response_addr: usize, response_len: usize) ?[]u8 {
    if (response_len == 0) return &[_]u8{};
    if (!validateUserRange(memory, response_addr, response_len, 1, .write)) return null;
    const bytes: [*]u8 = @ptrFromInt(response_addr);
    return bytes[0..response_len];
}

fn regionAllows(access: task_runtime.SegmentAccess, requested: UserMemoryAccess) bool {
    return switch (requested) {
        .read => access.read,
        .write => access.write,
    };
}
