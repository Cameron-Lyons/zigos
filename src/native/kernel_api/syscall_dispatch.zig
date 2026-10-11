const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const debug_contract = @import("../security/debug_contract.zig");
const task_runtime = @import("../task/task_runtime.zig");

const user_memory = if (builtin.target.os.tag == .freestanding) @import("../task/userspace_executor.zig") else struct {};

const USER_POINTER_FLOOR: usize = 0x10000;
pub const SINGLE_PASS_ADDRESS_SPACE_RANGE_VALIDATION = true;
pub const DIRECT_STACK_RANGE_VALIDATION = true;

pub const DispatchResult = struct {
    status: abi.SyscallStatus,
    bytes_written: u32 = 0,
    denial_reason: abi.DenialReason = .none,
};

pub const DispatchDiagnostics = struct {
    explanation: debug_contract.DenialExplanation = .{},
    provenance: debug_contract.ProvenanceRecord = .{},
};

pub const DetailedDispatchResult = struct {
    result: DispatchResult,
    diagnostics: DispatchDiagnostics = .{},
};

comptime {
    if (@sizeOf(DispatchResult) != 12 or @alignOf(DispatchResult) != 4) {
        @compileError("ordinary syscall results must remain 12 bytes with 4-byte alignment");
    }
    if (@sizeOf(DispatchDiagnostics) != 744 or @alignOf(DispatchDiagnostics) != 8) {
        @compileError("explicit syscall diagnostics must remain 744 bytes with 8-byte alignment");
    }
    if (@sizeOf(DetailedDispatchResult) != 760 or @alignOf(DetailedDispatchResult) != 8) {
        @compileError("explicit detailed syscall results must remain 760 bytes with 8-byte alignment");
    }
}

pub const UserMemoryAccess = enum {
    read,
    write,
};

pub const UserMemoryContext = struct {
    address_space: ?*const task_runtime.AddressSpaceRecord,
    caller_task_id: u64 = 0,

    pub fn init(port: *const component_port.KernelPort, caller_task_id: u64) UserMemoryContext {
        const runtime = port.kernel.runtime;
        const task = if (caller_task_id != 0) runtime.find(caller_task_id) else null;
        const address_space = if (task) |caller_task|
            runtime.findAddressSpaceConst(caller_task.address_space_id)
        else
            null;
        return .{ .address_space = address_space, .caller_task_id = caller_task_id };
    }
};

pub fn readRequest(comptime T: type, memory: UserMemoryContext, request_addr: usize) ?T {
    return readUserValue(T, memory, request_addr);
}

pub fn readUserValue(comptime T: type, memory: UserMemoryContext, addr: usize) ?T {
    comptime abi.syscall_wire.requireScalarWire(T);
    const end = std.math.add(usize, addr, @sizeOf(T)) catch return null;
    if (end > 0x0000_8000_0000_0000) return null;
    if (!validateUserRange(memory, addr, @sizeOf(T), @alignOf(T), .read)) return null;
    if (comptime builtin.target.os.tag == .freestanding) {
        var value: T = undefined;
        if (!user_memory.readUserMemory(memory.caller_task_id, addr, std.mem.asBytes(&value))) return null;
        return value;
    }
    const ptr: *const T = @ptrFromInt(addr);
    return ptr.*;
}

pub fn copyUserBytes(memory: UserMemoryContext, address: u64, length: u64, dest: []u8) ?[]const u8 {
    if (length > dest.len) return null;
    if (length == 0) return dest[0..0];
    const start = std.math.cast(usize, address) orelse return null;
    const count = std.math.cast(usize, length) orelse return null;
    const end = std.math.add(usize, start, count) catch return null;
    if (end > 0x0000_8000_0000_0000 or !validateUserRange(memory, start, count, 1, .read)) return null;
    if (comptime builtin.target.os.tag == .freestanding) {
        if (!user_memory.readUserMemory(memory.caller_task_id, start, dest[0..count])) return null;
    } else {
        @memcpy(dest[0..count], @as([*]const u8, @ptrFromInt(start))[0..count]);
    }
    return dest[0..count];
}

test "scalar nested byte copies reject hostile geometry before forming pointers" {
    const memory = UserMemoryContext{ .address_space = null };
    var destination: [4]u8 = @splat(0xa5);
    try std.testing.expectEqual(@as(usize, 0), copyUserBytes(memory, std.math.maxInt(u64), 0, &destination).?.len);
    for ([_]struct { address: u64, count: u64 }{
        .{ .address = 0x1000, .count = 1 },
        .{ .address = std.math.maxInt(u64), .count = 2 },
        .{ .address = 0x0000_8000_0000_0000, .count = 1 },
        .{ .address = 0x0000_7fff_ffff_ffff, .count = 2 },
        .{ .address = 0x10000, .count = 5 },
    }) |input| {
        try std.testing.expect(copyUserBytes(memory, input.address, input.count, &destination) == null);
        try std.testing.expectEqualSlices(u8, &@as([4]u8, @splat(0xa5)), &destination);
    }
    const source = "wire";
    try std.testing.expectEqualStrings(source, copyUserBytes(memory, @intFromPtr(source.ptr), source.len, &destination).?);
}

pub fn copyUserSlice(memory: UserMemoryContext, slice: []const u8, dest: []u8) ?[]const u8 {
    if (slice.len > dest.len) return null;
    if (slice.len == 0) return dest[0..0];
    if (!validateUserRange(memory, @intFromPtr(slice.ptr), slice.len, 1, .read)) return null;
    if (comptime builtin.target.os.tag == .freestanding) {
        if (!user_memory.readUserMemory(memory.caller_task_id, @intFromPtr(slice.ptr), dest[0..slice.len])) return null;
    } else {
        @memcpy(dest[0..slice.len], slice);
    }
    return dest[0..slice.len];
}

pub fn copyToUser(memory: UserMemoryContext, destination: []u8, source: []const u8) bool {
    if (source.len > destination.len) return false;
    if (source.len == 0) return true;
    if (!validateUserRange(memory, @intFromPtr(destination.ptr), source.len, 1, .write)) return false;
    if (comptime builtin.target.os.tag == .freestanding) {
        return user_memory.writeUserMemory(memory.caller_task_id, @intFromPtr(destination.ptr), source);
    }
    @memcpy(destination[0..source.len], source);
    return true;
}

pub fn writeUserValue(memory: UserMemoryContext, destination: usize, value: anytype) bool {
    const T = @TypeOf(value);
    if (!validateUserRange(memory, destination, @sizeOf(T), @alignOf(T), .write)) return false;
    if (comptime builtin.target.os.tag == .freestanding) {
        return user_memory.writeUserMemory(memory.caller_task_id, destination, std.mem.asBytes(&value));
    }
    const ptr: *T = @ptrFromInt(destination);
    ptr.* = value;
    return true;
}

pub inline fn validateUserRange(memory: UserMemoryContext, addr: usize, len: usize, alignment: usize, access: UserMemoryAccess) bool {
    if (len == 0) return true;
    if (addr == 0 or addr < USER_POINTER_FLOOR) return false;
    if (alignment != 0 and addr % alignment != 0) return false;
    const end_exclusive = std.math.add(usize, addr, len) catch return false;
    if (end_exclusive <= addr) return false;

    if (memory.address_space) |address_space| {
        if (comptime builtin.target.os.tag == .freestanding) {
            const layout = @import("../core/userspace_layout.zig");
            if (addr >= layout.shared_start and addr < layout.shared_end_exclusive) {
                return user_memory.validateSharedUserMemory(memory.caller_task_id, addr, len, access == .write);
            }
        }
        if (address_space.region_count == 0) {
            if (builtin.target.os.tag == .freestanding) return false;
            return true;
        }
        if (validateTerminalStackRange(address_space, addr, end_exclusive, access)) |valid| return valid;
        return validateAddressSpaceRange(address_space, addr, end_exclusive, access);
    }
    return builtin.target.os.tag != .freestanding;
}

pub fn prepareUserRange(memory: UserMemoryContext, addr: usize, len: usize, alignment: usize, access: UserMemoryAccess) bool {
    if (!validateUserRange(memory, addr, len, alignment, access)) return false;
    return prepareValidatedUserRange(memory, addr, len, access);
}

// Private and immediate: the caller has validated this span, or a containing
// span, without crossing an operation or callback that could change admission.
fn prepareValidatedUserRange(memory: UserMemoryContext, addr: usize, len: usize, access: UserMemoryAccess) bool {
    if (len == 0) return true;
    if (comptime builtin.target.os.tag == .freestanding) {
        return user_memory.prepareUserMemory(memory.caller_task_id, addr, len, access == .write);
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

fn validateTerminalStackRange(
    address_space: *const task_runtime.AddressSpaceRecord,
    addr: usize,
    end_exclusive: usize,
    access: UserMemoryAccess,
) ?bool {
    if (address_space.region_count == 0 or address_space.region_count > address_space.regions.len) return false;
    const stack = address_space.regions[address_space.region_count - 1];
    if (stack.kind != .stack) return null;

    const stack_start = std.math.cast(usize, stack.virtual_address) orelse return false;
    if (addr < stack_start) return null;
    const stack_end = std.math.add(usize, stack_start, @as(usize, stack.size_bytes)) catch return false;
    if (stack_end <= stack_start or addr >= stack_end or end_exclusive > stack_end) return false;
    return regionAllows(stack.access, access);
}

pub fn preflightResponse(memory: UserMemoryContext, response_addr: usize, response_len: usize, required_size: usize) ?DispatchResult {
    if (required_size == 0) return null;
    if (response_len < required_size) return .{ .status = .buffer_too_small };
    // Validate the declared span, including any tail beyond the wire response,
    // consistently with the final write after the operation has completed.
    if (!validateUserRange(memory, response_addr, response_len, 1, .write)) {
        return .{ .status = .invalid_response_buffer };
    }
    // The required prefix fits the just-validated declared span. Page
    // preparation still checks the current caller's active mapping ownership.
    if (!prepareValidatedUserRange(memory, response_addr, required_size, .write)) {
        return .{ .status = .invalid_response_buffer };
    }
    return null;
}

pub fn writeResponse(memory: UserMemoryContext, response_addr: usize, response_len: usize, value: anytype) DispatchResult {
    const bytes = std.mem.asBytes(&value);
    // The operation may have changed the caller's memory lifetime; never rely
    // solely on dispatch's earlier preflight when writing the response.
    if (preflightResponse(memory, response_addr, response_len, bytes.len)) |failure| return failure;
    if (bytes.len == 0) return success();
    if (comptime builtin.target.os.tag == .freestanding) {
        if (!user_memory.writeUserMemory(memory.caller_task_id, response_addr, bytes)) {
            return .{ .status = .invalid_response_buffer };
        }
        return .{ .status = .success, .bytes_written = @intCast(bytes.len) };
    }
    const buffer: [*]u8 = @ptrFromInt(response_addr);
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
    const request = readRequest(component_port.SyscallWireRequest(operation), memory, request_addr) orelse return invalidRequest();
    if (comptime @hasField(@TypeOf(request), "reserved")) {
        if (!std.mem.allEqual(u8, &request.reserved, 0)) return invalidRequest();
    }
    const response = component_port.invokeGeneratedFromValidatedSyscall(operation, port, request, now_ticks) catch |err| return mapError(err);
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
    const request = readRequest(component_port.SyscallWireRequest(operation), memory, request_addr) orelse return invalidRequest();
    _ = component_port.invokeGeneratedFromValidatedSyscall(operation, port, request, now_ticks) catch |err| return mapError(err);
    return success();
}

pub fn normalizeResult(result: DispatchResult) DispatchResult {
    var out = result;
    if (out.status != .success and out.denial_reason == .none) {
        out.denial_reason = defaultDenialReasonForStatus(out.status);
    }
    return out;
}

// Build cold diagnostics only from the completed result and captured scalars.
// No task, user-memory or capability authority survives an operation here.
pub fn describeResultInto(
    result: DispatchResult,
    operation: []const u8,
    required_authority: []const u8,
    caller_task_id: u64,
    target_id: u64,
    now_ticks: u64,
    out: *DispatchDiagnostics,
) void {
    const normalized = normalizeResult(result);
    if (normalized.status == .success) {
        out.* = .{};
        return;
    }
    const explanation = debug_contract.explainDenied(
        normalized.denial_reason,
        operation,
        required_authority,
        caller_task_id,
        0,
        null,
        target_id,
    );
    out.* = .{
        .explanation = explanation,
        .provenance = debug_contract.provenance(
            .syscall,
            .denied,
            now_ticks,
            caller_task_id,
            0,
            0,
            null,
            target_id,
            operation,
            required_authority,
            explanation,
            0,
        ),
    };
}

pub inline fn defaultDenialReasonForStatus(status: abi.SyscallStatus) abi.DenialReason {
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
        .peer_closed,
        => .invalid_target,
        .buffer_too_small,
        .conflict,
        .would_block,
        => .budget_exhausted,
        .denied => .policy_denied,
    };
}

pub fn mapError(err: anyerror) DispatchResult {
    if (err == error.InvalidRequestFlags) return invalidRequest();
    if (err == error.PeerClosed) return .{ .status = .peer_closed, .denial_reason = .invalid_target };
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
    if (err == error.MappingRegistrationFailed) return .{
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
    if (err == error.RingFull) return .{ .status = .would_block, .denial_reason = .budget_exhausted };

    if (err == error.TableFull or
        err == error.TargetTableFull or
        err == error.ComponentTableFull or
        err == error.CapabilityTableFull or
        err == error.TaskTableFull or
        err == error.NoSpaceLeft or
        err == error.ResourceBudgetExceeded or
        err == error.EndpointBusy or
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

fn regionAllows(access: task_runtime.SegmentAccess, requested: UserMemoryAccess) bool {
    return switch (requested) {
        .read => access.read,
        .write => access.write,
    };
}

test "endpoint queue backpressure is distinct from a disconnected peer" {
    try std.testing.expectEqual(abi.SyscallStatus.would_block, mapError(error.RingFull).status);
    try std.testing.expectEqual(abi.SyscallStatus.conflict, mapError(error.PeerNotConnected).status);
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

test "user range validation resolves the terminal stack mapping directly" {
    var address_space = std.mem.zeroes(task_runtime.AddressSpaceRecord);
    address_space.region_count = 3;
    address_space.regions[0] = .{
        .kind = .load_segment,
        .virtual_address = 0x20000,
        .size_bytes = 0x1000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .execute = true },
    };
    address_space.regions[1] = .{
        .kind = .load_segment,
        .virtual_address = 0x21000,
        .size_bytes = 0x1000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .write = true },
    };
    address_space.regions[2] = .{
        .kind = .stack,
        .virtual_address = 0x30000,
        .size_bytes = 0x2000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .write = true },
    };

    try std.testing.expectEqual(true, validateTerminalStackRange(&address_space, 0x30020, 0x30080, .read).?);
    try std.testing.expectEqual(true, validateTerminalStackRange(&address_space, 0x30020, 0x30080, .write).?);
    try std.testing.expectEqual(false, validateTerminalStackRange(&address_space, 0x31FF0, 0x32010, .write).?);
    try std.testing.expect(validateTerminalStackRange(&address_space, 0x21020, 0x21080, .read) == null);

    const memory = UserMemoryContext{ .address_space = &address_space };
    try std.testing.expect(validateUserRange(memory, 0x30020, 0x60, 8, .write));
    try std.testing.expect(!validateUserRange(memory, 0x31FF0, 0x20, 8, .write));
    try std.testing.expect(validateUserRange(memory, 0x21020, 0x60, 8, .read));

    try std.testing.expect(address_space.relocateStack(0x28000, 0x2000));
    try std.testing.expect(validateUserRange(memory, 0x28020, 0x60, 8, .read));
    try std.testing.expect(!validateUserRange(memory, 0x30020, 0x60, 8, .read));
    try std.testing.expect(validateUserRange(memory, 0x21020, 0x60, 8, .read));
    try std.testing.expectEqual(@as(u64, 0x2A000), address_space.stack_top);
    try std.testing.expectEqual(@as(u64, 0x2A000), address_space.stack_pointer);
}

test "response preflight validates unused tails and publication rechecks current permissions" {
    var storage: [64]u8 = @splat(0xa5);
    const address = @intFromPtr(&storage);
    var address_space = std.mem.zeroes(task_runtime.AddressSpaceRecord);
    address_space.region_count = 2;
    for (address_space.regions[0..2], 0..) |*region, index| {
        region.* = .{
            .kind = .load_segment,
            .virtual_address = address + index * 32,
            .size_bytes = 32,
            .file_offset = 0,
            .file_size = 0,
            .access = .{ .read = true, .write = index == 0 },
        };
    }
    const memory = UserMemoryContext{ .address_space = &address_space, .caller_task_id = 42 };
    const required = @sizeOf(u64);

    try std.testing.expect(preflightResponse(memory, address, 32, required) == null);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, preflightResponse(memory, address, 40, required).?.status);
    try std.testing.expectEqual(abi.SyscallStatus.buffer_too_small, preflightResponse(memory, address, required - 1, required).?.status);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, preflightResponse(memory, 0x1000, required, required).?.status);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, preflightResponse(memory, std.math.maxInt(usize) - 3, required, required).?.status);

    address_space.regions[1].access.write = true;
    address_space.regions[1].virtual_address += 8;
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, preflightResponse(memory, address, 40, required).?.status);
    address_space.regions[1].virtual_address -= 8;
    try std.testing.expect(preflightResponse(memory, address, storage.len, required) == null);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, preflightResponse(memory, address, storage.len + 1, required).?.status);

    // An operation can change permissions after its initial preflight.
    // Even an unused declared tail must be admitted again before publication.
    address_space.regions[1].access.write = false;
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, writeResponse(memory, address, storage.len, @as(u64, 17)).status);
    for (storage) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    address_space.regions[1].access.write = true;
    address_space.regions[0].access.write = false;
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, preflightResponse(memory, address, required, required).?.status);
    try std.testing.expect(!prepareUserRange(memory, address, required, 1, .write));
    try std.testing.expect(preflightResponse(memory, 0, 0, 0) == null);
}

test "compact syscall result normalization preserves all 13 status scalars" {
    const cases = [_]struct { status: abi.SyscallStatus, reason: abi.DenialReason }{
        .{ .status = .success, .reason = .none },
        .{ .status = .unavailable, .reason = .unsupported_operation },
        .{ .status = .invalid_request_pointer, .reason = .invalid_target },
        .{ .status = .invalid_response_buffer, .reason = .invalid_target },
        .{ .status = .buffer_too_small, .reason = .budget_exhausted },
        .{ .status = .unsupported_operation, .reason = .unsupported_operation },
        .{ .status = .unsupported_abi_version, .reason = .unsupported_operation },
        .{ .status = .denied, .reason = .policy_denied },
        .{ .status = .not_found, .reason = .invalid_target },
        .{ .status = .conflict, .reason = .budget_exhausted },
        .{ .status = .internal_error, .reason = .unsupported_operation },
        .{ .status = .would_block, .reason = .budget_exhausted },
        .{ .status = .peer_closed, .reason = .invalid_target },
    };
    try std.testing.expectEqual(@as(usize, 13), cases.len);
    try std.testing.expectEqual(cases.len, @typeInfo(abi.SyscallStatus).@"enum".field_names.len);
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(DispatchResult));
    try std.testing.expectEqual(@as(usize, 4), @alignOf(DispatchResult));
    try std.testing.expectEqual(@as(usize, 744), @sizeOf(DispatchDiagnostics));
    try std.testing.expectEqual(@as(usize, 760), @sizeOf(DetailedDispatchResult));
    for (cases, 0..) |case, index| {
        const bytes: u32 = std.math.maxInt(u32) - @as(u32, @intCast(index));
        const input = DispatchResult{ .status = case.status, .bytes_written = bytes };
        const actual = normalizeResult(input);
        try std.testing.expectEqualDeep(DispatchResult{
            .status = case.status,
            .bytes_written = bytes,
            .denial_reason = case.reason,
        }, actual);
        try std.testing.expectEqualDeep(actual, normalizeResult(actual));
        try std.testing.expectEqual(abi.DenialReason.none, input.denial_reason);
        // Explicit reasons remain observable even for success and statuses
        // whose normal default differs from this reason.
        const explicit = DispatchResult{
            .status = case.status,
            .bytes_written = bytes,
            .denial_reason = .capability_expired,
        };
        try std.testing.expectEqualDeep(explicit, normalizeResult(explicit));
    }
}

test "compact syscall result retains all 42 error mappings and unknown fallback" {
    const cases = [_]struct {
        err: anyerror,
        status: abi.SyscallStatus,
        reason: abi.DenialReason,
        normalized_reason: ?abi.DenialReason = null,
    }{
        .{ .err = error.InvalidRequestFlags, .status = .invalid_request_pointer, .reason = .none, .normalized_reason = .invalid_target },
        .{ .err = error.PeerClosed, .status = .peer_closed, .reason = .invalid_target },
        .{ .err = error.UnsupportedAbiVersion, .status = .unsupported_abi_version, .reason = .none, .normalized_reason = .unsupported_operation },
        .{ .err = error.ReceiveBufferTooSmall, .status = .buffer_too_small, .reason = .none, .normalized_reason = .budget_exhausted },
        .{ .err = error.UnexpectedOperation, .status = .unsupported_operation, .reason = .unsupported_operation },
        .{ .err = error.PermissionDenied, .status = .denied, .reason = .policy_denied },
        .{ .err = error.RightsEscalation, .status = .denied, .reason = .policy_denied },
        .{ .err = error.UserspaceLaunchRequired, .status = .denied, .reason = .policy_denied },
        .{ .err = error.InvalidUserspaceImage, .status = .denied, .reason = .policy_denied },
        .{ .err = error.CapabilityNotFound, .status = .not_found, .reason = .capability_missing },
        .{ .err = error.CapabilityRevoked, .status = .denied, .reason = .capability_revoked },
        .{ .err = error.Revoked, .status = .denied, .reason = .capability_revoked },
        .{ .err = error.ScopeViolation, .status = .denied, .reason = .scope_violation },
        .{ .err = error.ScopeEscalation, .status = .denied, .reason = .scope_violation },
        .{ .err = error.SubjectTaskMismatch, .status = .denied, .reason = .scope_violation },
        .{ .err = error.SubjectTaskRequired, .status = .denied, .reason = .scope_violation },
        .{ .err = error.LeaseEscalation, .status = .denied, .reason = .capability_expired },
        .{ .err = error.InvalidCapabilityTarget, .status = .denied, .reason = .invalid_target },
        .{ .err = error.InvalidCapabilityRights, .status = .denied, .reason = .invalid_target },
        .{ .err = error.InterfaceNameTooLong, .status = .denied, .reason = .invalid_target },
        .{ .err = error.MessageTooLarge, .status = .denied, .reason = .invalid_target },
        .{ .err = error.InterfaceNotFound, .status = .not_found, .reason = .interface_not_found },
        .{ .err = error.TaskNotFound, .status = .not_found, .reason = .invalid_target },
        .{ .err = error.EndpointNotFound, .status = .not_found, .reason = .invalid_target },
        .{ .err = error.SharedMemoryNotFound, .status = .not_found, .reason = .invalid_target },
        .{ .err = error.InvalidSurfacePresentation, .status = .not_found, .reason = .invalid_target },
        .{ .err = error.SurfacePresentationUnavailable, .status = .unavailable, .reason = .unsupported_operation },
        .{ .err = error.MappingRegistrationFailed, .status = .unavailable, .reason = .unsupported_operation },
        .{ .err = error.StaleSurfacePresentation, .status = .conflict, .reason = .invalid_target },
        .{ .err = error.DeviceNotFound, .status = .not_found, .reason = .invalid_target },
        .{ .err = error.UnsupportedMmioWindow, .status = .not_found, .reason = .invalid_target },
        .{ .err = error.RingFull, .status = .would_block, .reason = .budget_exhausted },
        .{ .err = error.TableFull, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.TargetTableFull, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.ComponentTableFull, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.CapabilityTableFull, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.TaskTableFull, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.NoSpaceLeft, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.ResourceBudgetExceeded, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.EndpointBusy, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.PeerNotConnected, .status = .conflict, .reason = .budget_exhausted },
        .{ .err = error.VersionMismatch, .status = .conflict, .reason = .budget_exhausted },
    };
    try std.testing.expectEqual(@as(usize, 42), cases.len);
    for (cases) |case| {
        const actual = mapError(case.err);
        try std.testing.expectEqualDeep(DispatchResult{
            .status = case.status,
            .denial_reason = case.reason,
        }, actual);
        try std.testing.expectEqualDeep(DispatchResult{
            .status = case.status,
            .denial_reason = case.normalized_reason orelse case.reason,
        }, normalizeResult(actual));
    }
    const unknown = mapError(error.UnmappedCompactResultTestError);
    try std.testing.expectEqualDeep(DispatchResult{ .status = .internal_error }, unknown);
    try std.testing.expectEqualDeep(DispatchResult{
        .status = .internal_error,
        .denial_reason = .unsupported_operation,
    }, normalizeResult(unknown));
}

test "compact syscall diagnostics match five frozen complete old results" {
    // Captured from accepted pre-refactor helpers in Debug and ReleaseFast.
    // Full semantic values, array tails and empty/default fields are independently
    // retained in zigos-compact-result-golden-cases.json; object padding excluded.
    const Golden = struct {
        name: []const u8,
        caller_task_id: u64,
        opcode: u16,
        status: u32,
        denial_reason: u16,
        subject_task_id: u64,
        target_id: u64,
        operation: []const u8,
        required_authority: []const u8,
        blocking_policy: []const u8,
        user_action_available: bool,
        retry_safe: bool,
        fingerprint: u64,
        trace_id: u64,
        provenance_kind: u8,
        decision: u8,
        provenance_tick: u64,
        provenance_task_id: u64,
        explanation_render: []const u8,
        provenance_render: []const u8,
    };
    const cases = [_]Golden{
        .{
            .name = "recognized_time_query_invalid_request",
            .caller_task_id = 7,
            .opcode = 272,
            .status = 2,
            .denial_reason = 1,
            .subject_task_id = 7,
            .target_id = 0,
            .operation = "time_query",
            .required_authority = "time_query",
            .blocking_policy = "target-routing-policy",
            .user_action_available = false,
            .retry_safe = false,
            .fingerprint = 0x08eef2f4f1d52347,
            .trace_id = 0xa8bc2962ad9a5724,
            .provenance_kind = 3,
            .decision = 1,
            .provenance_tick = 19,
            .provenance_task_id = 7,
            .explanation_render = "reason=invalid_target operation=time_query required=time_query policy=target-routing-policy subject_task=7 capability=0 target=none:0 user_action=no retry_safe=no fingerprint=0x8eef2f4f1d52347",
            .provenance_render = "trace=0xa8bc2962ad9a5724 parent=0x0 tick=19 kind=syscall decision=denied task=7 artifact=0 service=0 capability=0 target=none:0 operation=time_query detail=time_query source_fingerprint=0x0 seq=0 reason=invalid_target",
        },
        .{
            .name = "caller_zero_scope",
            .caller_task_id = 0,
            .opcode = 272,
            .status = 7,
            .denial_reason = 5,
            .subject_task_id = 0,
            .target_id = 0,
            .operation = "syscall-dispatch",
            .required_authority = "subject-task",
            .blocking_policy = "task-scope-policy",
            .user_action_available = true,
            .retry_safe = false,
            .fingerprint = 0x6e1a9bafeac0a782,
            .trace_id = 0x1d12cb10e5d27baa,
            .provenance_kind = 3,
            .decision = 1,
            .provenance_tick = 19,
            .provenance_task_id = 0,
            .explanation_render = "reason=scope_violation operation=syscall-dispatch required=subject-task policy=task-scope-policy subject_task=0 capability=0 target=none:0 user_action=yes retry_safe=no fingerprint=0x6e1a9bafeac0a782",
            .provenance_render = "trace=0x1d12cb10e5d27baa parent=0x0 tick=19 kind=syscall decision=denied task=0 artifact=0 service=0 capability=0 target=none:0 operation=syscall-dispatch detail=subject-task source_fingerprint=0x0 seq=0 reason=scope_violation",
        },
        .{
            .name = "unknown_opcode",
            .caller_task_id = 7,
            .opcode = 65535,
            .status = 5,
            .denial_reason = 9,
            .subject_task_id = 7,
            .target_id = 65535,
            .operation = "unsupported-operation",
            .required_authority = "declared-native-operation",
            .blocking_policy = "abi-surface-policy",
            .user_action_available = false,
            .retry_safe = false,
            .fingerprint = 0x87bb53df87aab348,
            .trace_id = 0x57340554c5b64de3,
            .provenance_kind = 3,
            .decision = 1,
            .provenance_tick = 19,
            .provenance_task_id = 7,
            .explanation_render = "reason=unsupported_operation operation=unsupported-operation required=declared-native-operation policy=abi-surface-policy subject_task=7 capability=0 target=none:65535 user_action=no retry_safe=no fingerprint=0x87bb53df87aab348",
            .provenance_render = "trace=0x57340554c5b64de3 parent=0x0 tick=19 kind=syscall decision=denied task=7 artifact=0 service=0 capability=0 target=none:65535 operation=unsupported-operation detail=declared-native-operation source_fingerprint=0x0 seq=0 reason=unsupported_operation",
        },
        .{
            .name = "caller_zero_unknown_precedence",
            .caller_task_id = 0,
            .opcode = 65535,
            .status = 7,
            .denial_reason = 5,
            .subject_task_id = 0,
            .target_id = 0,
            .operation = "syscall-dispatch",
            .required_authority = "subject-task",
            .blocking_policy = "task-scope-policy",
            .user_action_available = true,
            .retry_safe = false,
            .fingerprint = 0x6e1a9bafeac0a782,
            .trace_id = 0x1d12cb10e5d27baa,
            .provenance_kind = 3,
            .decision = 1,
            .provenance_tick = 19,
            .provenance_task_id = 0,
            .explanation_render = "reason=scope_violation operation=syscall-dispatch required=subject-task policy=task-scope-policy subject_task=0 capability=0 target=none:0 user_action=yes retry_safe=no fingerprint=0x6e1a9bafeac0a782",
            .provenance_render = "trace=0x1d12cb10e5d27baa parent=0x0 tick=19 kind=syscall decision=denied task=0 artifact=0 service=0 capability=0 target=none:0 operation=syscall-dispatch detail=subject-task source_fingerprint=0x0 seq=0 reason=scope_violation",
        },
        .{
            .name = "success_empty_diagnostics",
            .caller_task_id = 7,
            .opcode = 272,
            .status = 0,
            .denial_reason = 0,
            .subject_task_id = 0,
            .target_id = 0,
            .operation = "",
            .required_authority = "",
            .blocking_policy = "",
            .user_action_available = false,
            .retry_safe = false,
            .fingerprint = 0x0000000000000000,
            .trace_id = 0x0000000000000000,
            .provenance_kind = 0,
            .decision = 0,
            .provenance_tick = 0,
            .provenance_task_id = 0,
            .explanation_render = "reason=none operation= required= policy= subject_task=0 capability=0 target=none:0 user_action=no retry_safe=no fingerprint=0x0",
            .provenance_render = "trace=0x0 parent=0x0 tick=0 kind=none decision=allowed task=0 artifact=0 service=0 capability=0 target=none:0 operation= detail= source_fingerprint=0x0 seq=0 reason=none",
        },
    };

    const Text = struct {
        fn bytes(comptime capacity: usize, value: []const u8) [capacity]u8 {
            var buffer: [capacity]u8 = @splat(0);
            @memcpy(buffer[0..value.len], value);
            return buffer;
        }
    };
    for (cases) |golden| {
        const result = DispatchResult{
            .status = @fromBackingInt(@intCast(golden.status)),
            .denial_reason = @fromBackingInt(@intCast(golden.denial_reason)),
        };
        const expected_explanation = debug_contract.DenialExplanation{
            .reason = @fromBackingInt(@intCast(golden.denial_reason)),
            .subject_task_id = golden.subject_task_id,
            .target_id = golden.target_id,
            .operation_len = @intCast(golden.operation.len),
            .operation = Text.bytes(debug_contract.MAX_LABEL_BYTES, golden.operation),
            .required_authority_len = @intCast(golden.required_authority.len),
            .required_authority = Text.bytes(debug_contract.MAX_LABEL_BYTES, golden.required_authority),
            .blocking_policy_len = @intCast(golden.blocking_policy.len),
            .blocking_policy = Text.bytes(debug_contract.MAX_LABEL_BYTES, golden.blocking_policy),
            .user_action_available = golden.user_action_available,
            .retry_safe = golden.retry_safe,
            .fingerprint = golden.fingerprint,
        };
        const expected_provenance = debug_contract.ProvenanceRecord{
            .kind = @fromBackingInt(@intCast(golden.provenance_kind)),
            .decision = @fromBackingInt(@intCast(golden.decision)),
            .trace_id = golden.trace_id,
            .task_id = golden.provenance_task_id,
            .target_id = golden.target_id,
            .tick = golden.provenance_tick,
            .operation_len = @intCast(golden.operation.len),
            .operation = Text.bytes(debug_contract.MAX_LABEL_BYTES, golden.operation),
            .detail_len = @intCast(golden.required_authority.len),
            .detail = Text.bytes(debug_contract.MAX_DETAIL_BYTES, golden.required_authority),
            .denial = expected_explanation,
        };
        // Seed nonempty fields so success and repeated calls must overwrite
        // caller storage, including all label tails and optional/default IDs.
        var actual = DispatchDiagnostics{
            .explanation = .{ .capability_id = 99, .operation = @splat(0xa5) },
            .provenance = .{ .service_id = 88, .detail = @splat(0xa5) },
        };
        describeResultInto(result, golden.operation, golden.required_authority, golden.caller_task_id, golden.target_id, 19, &actual);
        try std.testing.expectEqualDeep(expected_explanation, actual.explanation);
        try std.testing.expectEqualDeep(expected_provenance, actual.provenance);
        try std.testing.expectEqualDeep(actual.explanation, actual.provenance.denial);
        var explanation_render: [512]u8 = undefined;
        var provenance_render: [512]u8 = undefined;
        try std.testing.expectEqualStrings(golden.explanation_render, actual.explanation.render(&explanation_render));
        try std.testing.expectEqualStrings(golden.provenance_render, actual.provenance.render(&provenance_render));
    }
}
