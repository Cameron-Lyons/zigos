const std = @import("std");
const device_broker = @import("../kernel_api/device_broker.zig");

pub const MAPS_MMIO_INTO_OWNER_TASKS = true;
pub const SEALS_KERNEL_RUNTIME_IO_AFTER_CLAIM = true;
pub const MAX_CLAIMS: usize = device_broker.MAX_DEVICES;
pub const CLAIM_RECORD_SIZE_CEILING_BYTES: usize = 24;
pub const HANDOFF_SIZE_CEILING_BYTES: usize = 128;

pub const Error = error{
    AlreadyClaimed,
    ClaimTableFull,
    DeviceNotClaimed,
    OwnerMismatch,
};

pub const Claim = struct {
    device_id: u64 = 0,
    owner_task_id: u64 = 0,
    process_generation: u32 = 0,
    owned_submit_depth: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > CLAIM_RECORD_SIZE_CEILING_BYTES) {
            @compileError("dataplane claim record exceeds its compact size ceiling");
        }
    }
};

const Handoff = struct {
    claims: [MAX_CLAIMS]Claim = [_]Claim{.{}} ** MAX_CLAIMS,
    used_count: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > HANDOFF_SIZE_CEILING_BYTES) {
            @compileError("dataplane handoff state exceeds its compact size ceiling");
        }
    }
};

var handoff = Handoff{};

pub fn reset() void {
    handoff = .{};
}

pub fn claim(device_id: u64, owner_task_id: u64, process_generation: u32) Error!void {
    if (device_id == 0) return error.DeviceNotClaimed;
    if (findClaim(device_id)) |existing| {
        if (existing.owner_task_id == owner_task_id and existing.process_generation == process_generation) {
            return;
        }
        return error.AlreadyClaimed;
    }
    const slot = unusedSlot() orelse return error.ClaimTableFull;
    slot.* = .{
        .device_id = device_id,
        .owner_task_id = owner_task_id,
        .process_generation = process_generation,
    };
    handoff.used_count += 1;
}

pub fn release(device_id: u64) bool {
    const index = findClaimIndex(device_id) orelse return false;
    handoff.claims[index] = .{};
    handoff.used_count -= 1;
    return true;
}

pub fn claimed(device_id: u64) bool {
    return findClaim(device_id) != null;
}

pub fn ownerTaskId(device_id: u64) ?u64 {
    const record = findClaim(device_id) orelse return null;
    return record.owner_task_id;
}

pub fn allowsKernelRuntimeIo(device_id: u64) bool {
    const record = findClaim(device_id) orelse return true;
    return record.owned_submit_depth != 0;
}

pub fn beginOwnedSubmit(device_id: u64, owner_task_id: u64, process_generation: u32) Error!void {
    const record = findClaim(device_id) orelse return error.DeviceNotClaimed;
    if (record.owner_task_id != owner_task_id or record.process_generation != process_generation) {
        return error.OwnerMismatch;
    }
    if (record.owned_submit_depth == std.math.maxInt(u8)) return error.ClaimTableFull;
    record.owned_submit_depth += 1;
}

pub fn endOwnedSubmit(device_id: u64) void {
    const record = findClaim(device_id) orelse return;
    if (record.owned_submit_depth == 0) return;
    record.owned_submit_depth -= 1;
}

fn findClaim(device_id: u64) ?*Claim {
    const index = findClaimIndex(device_id) orelse return null;
    return &handoff.claims[index];
}

fn findClaimIndex(device_id: u64) ?usize {
    if (device_id == 0) return null;
    for (handoff.claims, 0..) |record, index| {
        if (record.device_id == device_id) return index;
    }
    return null;
}

fn unusedSlot() ?*Claim {
    for (&handoff.claims) |*record| {
        if (record.device_id == 0) return record;
    }
    return null;
}

test "dataplane handoff seals kernel I/O after owner claim" {
    reset();
    defer reset();

    const device_id: u64 = 0x1F001;
    try std.testing.expect(allowsKernelRuntimeIo(device_id));
    try claim(device_id, 41, 1);
    try std.testing.expect(claimed(device_id));
    try std.testing.expectEqual(@as(?u64, 41), ownerTaskId(device_id));
    try std.testing.expect(!allowsKernelRuntimeIo(device_id));

    try beginOwnedSubmit(device_id, 41, 1);
    try std.testing.expect(allowsKernelRuntimeIo(device_id));
    endOwnedSubmit(device_id);
    try std.testing.expect(!allowsKernelRuntimeIo(device_id));
    try std.testing.expectError(error.OwnerMismatch, beginOwnedSubmit(device_id, 99, 1));

    try std.testing.expect(release(device_id));
    try std.testing.expect(allowsKernelRuntimeIo(device_id));
    try std.testing.expect(!claimed(device_id));
}
