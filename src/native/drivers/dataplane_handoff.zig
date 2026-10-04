const std = @import("std");
const device_broker = @import("../kernel_api/device_broker.zig");
const cooperative = @import("../task/cooperative_worker.zig");

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
    SubmissionBusy,
    SubmissionTokenExhausted,
};

pub const Claim = struct {
    device_id: u64 = 0,
    owner_task_id: u64 = 0,
    process_generation: u32 = 0,

    comptime {
        if (@sizeOf(@This()) > CLAIM_RECORD_SIZE_CEILING_BYTES) {
            @compileError("dataplane claim record exceeds its compact size ceiling");
        }
    }
};

const Handoff = struct {
    claims: [MAX_CLAIMS]Claim = @as([MAX_CLAIMS]Claim, @splat(.{})),
    active_worker: ?*cooperative.Worker = null,
    active_token: u64 = 0,
    next_token: u64 = 1,
    used_count: u8 = 0,
    active_claim_index: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > HANDOFF_SIZE_CEILING_BYTES) {
            @compileError("dataplane handoff state exceeds its compact size ceiling");
        }
    }
};

var handoff = Handoff{};

pub fn reset() bool {
    if (operationBusy()) return false;
    const next_token = handoff.next_token;
    handoff = .{ .next_token = next_token };
    return true;
}

pub fn claim(device_id: u64, owner_task_id: u64, process_generation: u32) Error!void {
    if (operationBusy()) return error.SubmissionBusy;
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
    if (operationBusy()) return false;
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
    const index = findClaimIndex(device_id) orelse return true;
    return operationBusy() and handoff.active_claim_index == index and handoff.active_worker == cooperative.current();
}

pub const Lease = struct {
    token: u64,
    worker: ?*cooperative.Worker,
    device_id: u64,
    owner_task_id: u64,
    process_generation: u32,
};

pub fn operationBusy() bool {
    return handoff.active_token != 0;
}

pub fn beginOwnedSubmit(device_id: u64, owner_task_id: u64, process_generation: u32) Error!Lease {
    if (operationBusy()) return error.SubmissionBusy;
    const index = findClaimIndex(device_id) orelse return error.DeviceNotClaimed;
    const record = &handoff.claims[index];
    if (record.owner_task_id != owner_task_id or record.process_generation != process_generation) {
        return error.OwnerMismatch;
    }
    const token = handoff.next_token;
    if (token == 0) return error.SubmissionTokenExhausted;
    handoff.next_token = std.math.add(u64, token, 1) catch 0;
    handoff.active_worker = cooperative.current();
    handoff.active_claim_index = @intCast(index);
    handoff.active_token = token;
    return .{
        .token = token,
        .worker = handoff.active_worker,
        .device_id = record.device_id,
        .owner_task_id = record.owner_task_id,
        .process_generation = record.process_generation,
    };
}

pub fn endOwnedSubmit(lease: Lease) bool {
    if (!leaseCurrent(lease)) return false;
    handoff.active_token = 0;
    handoff.active_worker = null;
    handoff.active_claim_index = 0;
    return true;
}

pub fn leaseCurrent(lease: Lease) bool {
    if (!operationBusy() or lease.token != handoff.active_token or lease.worker != handoff.active_worker or cooperative.current() != lease.worker)
        return false;
    const record = &handoff.claims[handoff.active_claim_index];
    if (lease.device_id != record.device_id or lease.owner_task_id != record.owner_task_id or lease.process_generation != record.process_generation)
        return false;
    return true;
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
    try std.testing.expect(reset());
    defer std.debug.assert(reset());

    const device_id: u64 = 0x1F001;
    try std.testing.expect(allowsKernelRuntimeIo(device_id));
    try claim(device_id, 41, 1);
    try std.testing.expect(claimed(device_id));
    try std.testing.expectEqual(@as(?u64, 41), ownerTaskId(device_id));
    try std.testing.expect(!allowsKernelRuntimeIo(device_id));

    const lease = try beginOwnedSubmit(device_id, 41, 1);
    try std.testing.expect(allowsKernelRuntimeIo(device_id));
    try std.testing.expect(endOwnedSubmit(lease));
    try std.testing.expect(!allowsKernelRuntimeIo(device_id));
    try std.testing.expectError(error.OwnerMismatch, beginOwnedSubmit(device_id, 99, 1));

    try std.testing.expect(release(device_id));
    try std.testing.expect(allowsKernelRuntimeIo(device_id));
    try std.testing.expect(!claimed(device_id));
}

test "dataplane owned storage submit permission remains on its suspended worker" {
    try std.testing.expect(reset());
    defer std.debug.assert(reset());
    try claim(0x1F002, 42, 2);
    const Fixture = struct {
        permitted: bool = false,
        lease: ?Lease = null,
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const lease = beginOwnedSubmit(0x1F002, 42, 2) catch unreachable;
            self.lease = lease;
            defer std.debug.assert(endOwnedSubmit(lease));
            self.permitted = allowsKernelRuntimeIo(0x1F002);
            cooperative.current().?.yield();
            self.permitted = self.permitted and allowsKernelRuntimeIo(0x1F002);
        }
    };
    var stack: [16 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    var fixture = Fixture{};
    try worker.start(&fixture, Fixture.run);
    try worker.step();
    defer if (worker.state == .suspended) worker.step() catch unreachable;
    try std.testing.expect(fixture.permitted);
    try std.testing.expect(!allowsKernelRuntimeIo(0x1F002));
    try std.testing.expect(operationBusy());
    try std.testing.expect(!endOwnedSubmit(fixture.lease.?));
    try std.testing.expect(!release(0x1F002));
    try std.testing.expect(!reset());
    try std.testing.expect(claimed(0x1F002));
    try std.testing.expectError(error.SubmissionBusy, claim(0x1F002, 42, 2));
    try std.testing.expectError(error.SubmissionBusy, beginOwnedSubmit(0x1F002, 42, 2));
    worker.cancel();
    try worker.step();
    try std.testing.expect(fixture.permitted);
    try std.testing.expect(!allowsKernelRuntimeIo(0x1F002));
    try std.testing.expect(!operationBusy());
}

test "dataplane exact synchronous leases reject stale identity and survive reset" {
    try std.testing.expect(reset());
    defer std.debug.assert(reset());
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(Claim));
    try std.testing.expectEqual(@as(usize, 128), @sizeOf(Handoff));
    try claim(17, 23, 4);
    try std.testing.expectError(error.OwnerMismatch, beginOwnedSubmit(17, 23, 3));
    const first = try beginOwnedSubmit(17, 23, 4);
    var forged = first;
    forged.process_generation += 1;
    try std.testing.expect(!endOwnedSubmit(forged));
    forged = first;
    forged.device_id += 1;
    try std.testing.expect(!endOwnedSubmit(forged));
    try std.testing.expectError(error.SubmissionBusy, beginOwnedSubmit(17, 23, 4));
    try std.testing.expect(endOwnedSubmit(first));
    try std.testing.expect(reset());
    try claim(17, 23, 5);
    const second = try beginOwnedSubmit(17, 23, 5);
    try std.testing.expect(second.token > first.token);
    try std.testing.expect(!endOwnedSubmit(first));
    try std.testing.expect(operationBusy());
    try std.testing.expect(endOwnedSubmit(second));
}

test "dataplane stale same worker lease cannot release a later operation" {
    try std.testing.expect(reset());
    defer std.debug.assert(reset());
    try claim(17, 23, 4);
    const Fixture = struct {
        safe: bool = false,
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const first = beginOwnedSubmit(17, 23, 4) catch unreachable;
            std.debug.assert(endOwnedSubmit(first));
            const second = beginOwnedSubmit(17, 23, 4) catch unreachable;
            self.safe = second.token > first.token and !endOwnedSubmit(first) and operationBusy();
            cooperative.current().?.yield();
            self.safe = self.safe and allowsKernelRuntimeIo(17) and endOwnedSubmit(second);
        }
    };
    var stack: [16 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    var fixture = Fixture{};
    try worker.start(&fixture, Fixture.run);
    try worker.step();
    defer if (worker.state == .suspended) worker.step() catch unreachable;
    try std.testing.expect(fixture.safe);
    try worker.step();
    try std.testing.expect(fixture.safe and !operationBusy());
}

test "dataplane submission token exhaustion never reuses an old lease" {
    try std.testing.expect(reset());
    const saved_next = handoff.next_token;
    defer {
        std.debug.assert(reset());
        handoff.next_token = saved_next;
    }
    try claim(17, 23, 4);
    handoff.next_token = std.math.maxInt(u64);
    const last = try beginOwnedSubmit(17, 23, 4);
    try std.testing.expect(endOwnedSubmit(last));
    try std.testing.expectError(error.SubmissionTokenExhausted, beginOwnedSubmit(17, 23, 4));
    try std.testing.expect(reset());
    try claim(17, 23, 4);
    try std.testing.expectError(error.SubmissionTokenExhausted, beginOwnedSubmit(17, 23, 4));
    try std.testing.expect(!operationBusy());
}
