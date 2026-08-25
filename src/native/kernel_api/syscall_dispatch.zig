const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const debug_contract = @import("../security/debug_contract.zig");
const task_runtime = @import("../task/task_runtime.zig");

const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn allowSupervisorUserMemory() void {}
        pub fn forbidSupervisorUserMemory() void {}
    };

const USER_POINTER_FLOOR: usize = 0x10000;
const USER_POINTER_CEILING_32: usize = 0xC0000000;
pub const SINGLE_PASS_ADDRESS_SPACE_RANGE_VALIDATION = true;

pub const DispatchResult = struct {
    status: abi.SyscallStatus,
    bytes_written: u32 = 0,
    denial_reason: abi.DenialReason = .none,
    explanation: debug_contract.DenialExplanation = .{},
    provenance: debug_contract.ProvenanceRecord = .{},
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
    x86.allowSupervisorUserMemory();
    defer x86.forbidSupervisorUserMemory();
    return ptr.*;
}

pub fn copyUserSlice(memory: UserMemoryContext, slice: []const u8, dest: []u8) ?[]const u8 {
    if (slice.len > dest.len) return null;
    if (slice.len == 0) return dest[0..0];
    if (!validateUserRange(memory, @intFromPtr(slice.ptr), slice.len, 1, .read)) return null;
    x86.allowSupervisorUserMemory();
    defer x86.forbidSupervisorUserMemory();
    @memcpy(dest[0..slice.len], slice);
    return dest[0..slice.len];
}

pub fn copyToUser(memory: UserMemoryContext, destination: []u8, source: []const u8) bool {
    if (source.len > destination.len) return false;
    if (source.len == 0) return true;
    if (!validateUserRange(memory, @intFromPtr(destination.ptr), source.len, 1, .write)) return false;
    x86.allowSupervisorUserMemory();
    defer x86.forbidSupervisorUserMemory();
    @memcpy(destination[0..source.len], source);
    return true;
}

pub fn writeUserValue(memory: UserMemoryContext, destination: usize, value: anytype) bool {
    const T = @TypeOf(value);
    if (!validateUserRange(memory, destination, @sizeOf(T), @alignOf(T), .write)) return false;
    const ptr: *T = @ptrFromInt(destination);
    x86.allowSupervisorUserMemory();
    defer x86.forbidSupervisorUserMemory();
    ptr.* = value;
    return true;
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
        if (address_space.region_count == 0) {
            if (builtin.target.os.tag == .freestanding) return false;
            return true;
        }
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
    if (address_space.region_count == 0 or address_space.region_count > address_space.regions.len) return false;

    var covered_until = addr;
    var previous_region_end: usize = 0;
    for (address_space.regions[0..address_space.region_count]) |region| {
        const region_start = std.math.cast(usize, region.virtual_address) orelse return false;
        const region_end = std.math.add(usize, region_start, @as(usize, region.size_bytes)) catch return false;
        if (region_end <= region_start or region_start < previous_region_end) return false;
        previous_region_end = region_end;

        if (region_end <= covered_until) continue;
        if (region_start > covered_until) return false;
        if (!regionAllows(region.access, access)) return false;
        covered_until = @min(end_exclusive, region_end);
        if (covered_until == end_exclusive) return true;
    }
    return false;
}

pub fn writeResponse(memory: UserMemoryContext, response_addr: usize, response_len: usize, value: anytype) DispatchResult {
    const buffer = responseBuffer(memory, response_addr, response_len) orelse return .{
        .status = .invalid_response_buffer,
    };
    const bytes = std.mem.asBytes(&value);
    if (buffer.len < bytes.len) return .{
        .status = .buffer_too_small,
    };
    x86.allowSupervisorUserMemory();
    defer x86.forbidSupervisorUserMemory();
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

pub fn invokeAndWriteResponse(
    comptime operation: abi.NativeOperation,
    port: *component_port.KernelPort,
    memory: UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    const request = readRequest(component_port.PortRequest(operation), memory, request_addr) orelse return invalidRequest();
    const response = component_port.invokeGenerated(operation, port, request, now_ticks) catch |err| return mapError(err);
    return writeResponse(memory, response_addr, response_len, response);
}

pub fn invokeNoResponse(
    comptime operation: abi.NativeOperation,
    port: *component_port.KernelPort,
    memory: UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    _ = response_addr;
    _ = response_len;
    const request = readRequest(component_port.PortRequest(operation), memory, request_addr) orelse return invalidRequest();
    _ = component_port.invokeGenerated(operation, port, request, now_ticks) catch |err| return mapError(err);
    return success();
}

pub fn explainedFailure(
    status: abi.SyscallStatus,
    reason: abi.DenialReason,
    operation: []const u8,
    required_authority: []const u8,
    subject_task_id: u64,
    capability_id: u64,
    target_kind: ?capability.CapabilityTargetKind,
    target_id: u64,
    now_ticks: u64,
) DispatchResult {
    const explanation = debug_contract.explainDenied(
        reason,
        operation,
        required_authority,
        subject_task_id,
        capability_id,
        target_kind,
        target_id,
    );
    return .{
        .status = status,
        .denial_reason = reason,
        .explanation = explanation,
        .provenance = debug_contract.provenance(
            .syscall,
            .denied,
            now_ticks,
            subject_task_id,
            0,
            capability_id,
            target_kind,
            target_id,
            operation,
            required_authority,
            explanation,
            0,
        ),
    };
}

pub fn withSyscallContract(
    result: DispatchResult,
    operation: abi.NativeOperation,
    required_right: capability.CapabilityRight,
    caller_task_id: u64,
    now_ticks: u64,
) DispatchResult {
    var out = result;
    const success_status = out.status == .success;
    const decision: debug_contract.Decision = if (success_status) .allowed else .denied;
    if (!success_status and out.denial_reason == .none) {
        out.denial_reason = defaultDenialReasonForStatus(out.status);
    }
    if (!success_status and out.denial_reason != .none and out.explanation.reason == .none) {
        out.explanation = debug_contract.explainDenied(
            out.denial_reason,
            @tagName(operation),
            @tagName(required_right),
            caller_task_id,
            0,
            null,
            0,
        );
    }

    if (!success_status and out.provenance.kind == .none) {
        out.provenance = debug_contract.syscallProvenance(
            decision,
            now_ticks,
            caller_task_id,
            operation,
            required_right,
            out.denial_reason,
        );
    }
    return out;
}

fn defaultDenialReasonForStatus(status: abi.SyscallStatus) abi.DenialReason {
    return switch (status) {
        .success => .none,
        .unavailable,
        .unsupported_operation,
        .unsupported_abi_version,
        .internal_error,
        => .unsupported_operation,
        .invalid_request_pointer,
        .invalid_response_buffer,
        .not_found,
        => .invalid_target,
        .buffer_too_small,
        .conflict,
        => .budget_exhausted,
        .denied => .policy_denied,
    };
}

pub fn mapError(err: anyerror) DispatchResult {
    if (err == error.UnsupportedAbiVersion) return .{ .status = .unsupported_abi_version };
    if (err == error.ReceiveBufferTooSmall) return .{ .status = .buffer_too_small };
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
    if (err == error.Revoked) return .{
        .status = .denied,
        .denial_reason = .capability_revoked,
    };
    if (err == error.ScopeViolation or err == error.ScopeEscalation or err == error.SubjectTaskMismatch or err == error.SubjectTaskRequired) return .{
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
    if (err == error.TaskNotFound or err == error.EndpointNotFound or err == error.SharedMemoryNotFound) return .{
        .status = .not_found,
        .denial_reason = .invalid_target,
    };
    if (err == error.InvalidSurfacePresentation) return .{
        .status = .not_found,
        .denial_reason = .invalid_target,
    };
    if (err == error.SurfacePresentationUnavailable) return .{
        .status = .unavailable,
        .denial_reason = .unsupported_operation,
    };
    if (err == error.StaleSurfacePresentation) return .{
        .status = .conflict,
        .denial_reason = .invalid_target,
    };
    if (err == error.DeviceNotFound or err == error.UnsupportedMmioWindow) return .{
        .status = .not_found,
        .denial_reason = .invalid_target,
    };
    if (err == error.TableFull or
        err == error.TargetTableFull or
        err == error.ComponentTableFull or
        err == error.CapabilityTableFull or
        err == error.TaskTableFull or
        err == error.NoSpaceLeft or
        err == error.ResourceBudgetExceeded or
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

test "user slice copies enforce source and destination bounds" {
    const memory = UserMemoryContext{ .address_space = null };
    const payload = "endpoint-payload";
    var copied_buffer: [32]u8 = undefined;
    const copied = copyUserSlice(memory, payload, &copied_buffer).?;

    try std.testing.expectEqualStrings(payload, copied);
    try std.testing.expect(copyUserSlice(memory, payload, copied_buffer[0 .. payload.len - 1]) == null);

    var destination: [32]u8 = undefined;
    try std.testing.expect(copyToUser(memory, &destination, payload));
    try std.testing.expectEqualStrings(payload, destination[0..payload.len]);
    try std.testing.expect(!copyToUser(memory, destination[0 .. payload.len - 1], payload));

    const invalid_ptr: [*]const u8 = @ptrFromInt(0x1000);
    try std.testing.expect(copyUserSlice(memory, invalid_ptr[0..1], &copied_buffer) == null);
}
