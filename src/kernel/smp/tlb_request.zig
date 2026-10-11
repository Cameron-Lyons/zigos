const std = @import("std");

pub const CAPACITY: usize = 16;
pub const CpuMask = u16;
pub const Target = union(enum) {
    pcid: u16,
    kernel: void,
};

pub const Request = struct {
    generation: u64,
    participants: CpuMask,
    target: Target,
};

pub const Error = error{
    InvalidOwner,
    NotOwner,
    InvalidParticipants,
    InvalidPcid,
    Busy,
    Failed,
    GenerationExhausted,
    InvalidGeneration,
    StaleRequest,
    Incomplete,
};

const idle: u8 = 0;
const preparing: u8 = 1;
const active: u8 = 2;
const failed: u8 = 3;
const pcid_target: u8 = 0;
const kernel_target: u8 = 1;

const Acknowledgment = struct {
    generation: u64 align(64) = 0,
};

pub fn cpuBit(cpu: u8) ?CpuMask {
    if (cpu >= CAPACITY) return null;
    return @as(CpuMask, 1) << @as(u4, @intCast(cpu));
}

// One runtime owner issues synchronous requests. Initialization belongs to boot;
// replacing a live coordinator would reuse generations and is forbidden. A
// timeout/reset closes this coordinator permanently instead of recycling it.
pub const Coordinator = struct {
    owner: u8,
    phase: u8 = idle,
    generation: u64 = 0,
    last_generation: u64 = 0,
    participants: CpuMask = 0,
    target_kind: u8 = pcid_target,
    target_pcid: u16 = 0,
    acknowledgments: [CAPACITY]Acknowledgment = @splat(.{}),

    pub fn init(owner: u8) Error!Coordinator {
        if (cpuBit(owner) == null) return error.InvalidOwner;
        return .{ .owner = owner };
    }

    // The mask is one captured topology snapshot, including the owner. The
    // caller has already completed the local invalidation before begin().
    pub fn begin(self: *Coordinator, caller: u8, target: Target, participants: CpuMask) Error!Request {
        try self.checkOwner(caller);
        if (participants & cpuBit(self.owner).? == 0) return error.InvalidParticipants;
        switch (target) {
            .pcid => |pcid| if (pcid > 4095) return error.InvalidPcid,
            .kernel => {},
        }
        if (@cmpxchgStrong(u8, &self.phase, idle, preparing, .acq_rel, .acquire)) |phase| {
            return if (phase == failed) error.Failed else error.Busy;
        }
        const generation = std.math.add(u64, self.last_generation, 1) catch {
            try self.fail(caller);
            return error.GenerationExhausted;
        };
        self.last_generation = generation;
        // Acquiring any newer payload forces later generation checks past
        // its preceding retirement, even on weakly ordered hosted targets.
        @atomicStore(CpuMask, &self.participants, participants, .release);
        @atomicStore(u8, &self.target_kind, switch (target) {
            .pcid => pcid_target,
            .kernel => kernel_target,
        }, .release);
        @atomicStore(u16, &self.target_pcid, switch (target) {
            .pcid => |pcid| pcid,
            .kernel => 0,
        }, .release);
        @atomicStore(u64, &self.acknowledgments[self.owner].generation, generation, .monotonic);
        @atomicStore(u64, &self.generation, generation, .release);
        if (@cmpxchgStrong(u8, &self.phase, preparing, active, .release, .monotonic) != null) {
            // A reentrant failure must never be undone by publication.
            @atomicStore(u64, &self.generation, 0, .release);
            return error.Failed;
        }
        return .{ .generation = generation, .participants = participants, .target = target };
    }

    pub fn pending(self: *const Coordinator, cpu: u8) ?Request {
        const bit = cpuBit(cpu) orelse return null;
        if (@atomicLoad(u8, &self.phase, .acquire) != active) return null;
        const generation = @atomicLoad(u64, &self.generation, .acquire);
        if (generation == 0) return null;
        const participants = @atomicLoad(CpuMask, &self.participants, .acquire);
        if (participants & bit == 0) return null;
        if (@atomicLoad(u64, &self.acknowledgments[cpu].generation, .acquire) >= generation) return null;
        const kind = @atomicLoad(u8, &self.target_kind, .acquire);
        const pcid = @atomicLoad(u16, &self.target_pcid, .acquire);
        if (!self.isActive(generation)) return null;
        const target: Target = switch (kind) {
            pcid_target => .{ .pcid = pcid },
            kernel_target => .{ .kernel = {} },
            else => return null,
        };
        return .{ .generation = generation, .participants = participants, .target = target };
    }

    // Publish only after this CPU completes the captured invalidation. A late
    // handler can never overwrite a stamp from a newer request.
    pub fn acknowledge(self: *Coordinator, cpu: u8, generation: u64) bool {
        const bit = cpuBit(cpu) orelse return false;
        if (!self.isActive(generation)) return false;
        if (@atomicLoad(CpuMask, &self.participants, .acquire) & bit == 0) return false;
        const stamp = &self.acknowledgments[cpu].generation;
        var previous = @atomicLoad(u64, stamp, .monotonic);
        while (previous < generation) {
            if (!self.isActive(generation)) return false;
            if (@cmpxchgWeak(u64, stamp, previous, generation, .release, .monotonic)) |observed| {
                previous = observed;
            } else {
                return self.isActive(generation);
            }
        }
        return false;
    }

    pub fn complete(self: *const Coordinator, generation: u64) bool {
        if (!self.isActive(generation)) return false;
        var remaining = @atomicLoad(CpuMask, &self.participants, .acquire);
        if (remaining & cpuBit(self.owner).? == 0) return false;
        while (remaining != 0) {
            const cpu: u4 = @intCast(@ctz(remaining));
            if (@atomicLoad(u64, &self.acknowledgments[cpu].generation, .acquire) != generation) return false;
            remaining &= remaining - 1;
        }
        return self.isActive(generation);
    }

    pub fn finish(self: *Coordinator, caller: u8, generation: u64) Error!void {
        try self.checkOwner(caller);
        if (generation == 0) return error.InvalidGeneration;
        if (@atomicLoad(u8, &self.phase, .acquire) == failed) return error.Failed;
        if (!self.isActive(generation)) return error.StaleRequest;
        if (!self.complete(generation)) return error.Incomplete;
        if (@cmpxchgStrong(u8, &self.phase, active, preparing, .acq_rel, .acquire)) |phase| {
            return if (phase == failed) error.Failed else error.Busy;
        }
        // A nested owner operation may have retired and replaced the request
        // before the phase claim. Preserve that new request if its epoch moved.
        if (@atomicLoad(u64, &self.generation, .acquire) != generation) {
            if (@cmpxchgStrong(u8, &self.phase, preparing, active, .release, .monotonic) != null) return error.Failed;
            return error.StaleRequest;
        }
        @atomicStore(u64, &self.generation, 0, .release);
        if (@cmpxchgStrong(u8, &self.phase, preparing, idle, .release, .monotonic) != null) return error.Failed;
    }

    pub fn fail(self: *Coordinator, caller: u8) Error!void {
        try self.checkOwner(caller);
        @atomicStore(u8, &self.phase, failed, .release);
        @atomicStore(u64, &self.generation, 0, .release);
    }

    fn checkOwner(self: *const Coordinator, caller: u8) Error!void {
        if (caller != self.owner) return error.NotOwner;
    }

    fn isActive(self: *const Coordinator, generation: u64) bool {
        if (generation == 0 or @atomicLoad(u64, &self.generation, .acquire) != generation) return false;
        if (@atomicLoad(u8, &self.phase, .acquire) != active) return false;
        return @atomicLoad(u64, &self.generation, .acquire) == generation;
    }
};

test "sixteen CPU barrier requires every unique captured participant" {
    var coordinator = try Coordinator.init(0);
    const request = try coordinator.begin(0, .{ .pcid = 4095 }, std.math.maxInt(CpuMask));
    try std.testing.expectEqual(@as(u64, 1), request.generation);
    try std.testing.expect(coordinator.pending(0) == null);
    try std.testing.expect(!coordinator.acknowledge(0, request.generation));
    for (1..CAPACITY) |index| {
        const cpu: u8 = @intCast(index);
        try std.testing.expect(!coordinator.complete(request.generation));
        const pending_request = coordinator.pending(cpu).?;
        try std.testing.expectEqualDeep(request, pending_request);
        try std.testing.expect(coordinator.acknowledge(cpu, pending_request.generation));
        try std.testing.expect(!coordinator.acknowledge(cpu, pending_request.generation));
        try std.testing.expect(coordinator.pending(cpu) == null);
    }
    try std.testing.expect(coordinator.complete(request.generation));
    try coordinator.finish(0, request.generation);
    try std.testing.expect(!coordinator.complete(request.generation));
    for (0..CAPACITY) |index| try std.testing.expect(coordinator.pending(@intCast(index)) == null);
}

test "snapshot excludes newly online CPUs and rejects nonparticipant acknowledgments" {
    var coordinator = try Coordinator.init(0);
    const mask = cpuBit(0).? | cpuBit(3).? | cpuBit(9).?;
    const request = try coordinator.begin(0, .{ .kernel = {} }, mask);
    try std.testing.expectEqual(mask, request.participants);
    try std.testing.expect(coordinator.pending(12) == null);
    try std.testing.expect(!coordinator.acknowledge(12, request.generation));
    try std.testing.expect(!coordinator.acknowledge(16, request.generation));
    try std.testing.expect(!coordinator.acknowledge(255, request.generation));
    try std.testing.expect(coordinator.pending(255) == null);
    try std.testing.expect(coordinator.acknowledge(3, request.generation));
    try std.testing.expectError(error.Incomplete, coordinator.finish(0, request.generation));
    try std.testing.expect(!coordinator.complete(request.generation));
    try std.testing.expect(coordinator.acknowledge(9, request.generation));
    try coordinator.finish(0, request.generation);
}

test "late snapshots and old stamps cannot acknowledge a subsequent request" {
    var coordinator = try Coordinator.init(0);
    const first = try coordinator.begin(0, .{ .kernel = {} }, cpuBit(0).? | cpuBit(1).?);
    const delayed = coordinator.pending(1).?;
    try std.testing.expect(coordinator.acknowledge(1, first.generation));
    try coordinator.finish(0, first.generation);
    const second = try coordinator.begin(0, .{ .pcid = 17 }, cpuBit(0).? | cpuBit(1).? | cpuBit(2).?);
    try std.testing.expectEqual(first.generation + 1, second.generation);
    try std.testing.expectEqualDeep(second, coordinator.pending(1).?);
    try std.testing.expect(!coordinator.acknowledge(1, delayed.generation));
    try std.testing.expect(!coordinator.complete(second.generation));
    try std.testing.expectError(error.StaleRequest, coordinator.finish(0, first.generation));
    try std.testing.expect(coordinator.acknowledge(1, second.generation));
    try std.testing.expect(!coordinator.acknowledge(1, delayed.generation));
    try std.testing.expectEqual(second.generation, @atomicLoad(u64, &coordinator.acknowledgments[1].generation, .acquire));
    try std.testing.expect(!coordinator.acknowledge(2, second.generation + 1));
    try std.testing.expect(!coordinator.acknowledge(2, first.generation));
    try std.testing.expect(!coordinator.complete(second.generation));
    try std.testing.expect(coordinator.acknowledge(2, second.generation));
    try coordinator.finish(0, second.generation);
}

test "only the captured runtime owner may begin finish or fail a barrier" {
    try std.testing.expectError(error.InvalidOwner, Coordinator.init(16));
    try std.testing.expectError(error.InvalidOwner, Coordinator.init(255));
    var coordinator = try Coordinator.init(7);
    const mask = cpuBit(7).? | cpuBit(15).?;
    try std.testing.expectError(error.NotOwner, coordinator.begin(0, .{ .kernel = {} }, mask));
    const request = try coordinator.begin(7, .{ .kernel = {} }, mask);
    try std.testing.expectError(error.NotOwner, coordinator.finish(0, request.generation));
    try std.testing.expectError(error.NotOwner, coordinator.fail(0));
    try std.testing.expect(coordinator.acknowledge(15, request.generation));
    try coordinator.finish(7, request.generation);
}

test "invalid masks PCIDs and generation zero leave the coordinator usable" {
    var coordinator = try Coordinator.init(0);
    try std.testing.expectError(error.InvalidParticipants, coordinator.begin(0, .{ .kernel = {} }, 0));
    try std.testing.expectError(error.InvalidParticipants, coordinator.begin(0, .{ .kernel = {} }, cpuBit(1).?));
    for ([_]u16{ 4096, std.math.maxInt(u16) }) |pcid| {
        try std.testing.expectError(error.InvalidPcid, coordinator.begin(0, .{ .pcid = pcid }, cpuBit(0).?));
    }
    try std.testing.expectError(error.InvalidGeneration, coordinator.finish(0, 0));
    try std.testing.expect(!coordinator.acknowledge(0, 0));
    try std.testing.expect(!coordinator.complete(0));
    const request = try coordinator.begin(0, .{ .pcid = 0 }, cpuBit(0).?);
    try std.testing.expectEqual(@as(u64, 1), request.generation);
    try std.testing.expect(coordinator.complete(request.generation));
    try coordinator.finish(0, request.generation);
}

test "one outstanding request preserves its payload and rejects owner reentry" {
    var coordinator = try Coordinator.init(0);
    const request = try coordinator.begin(0, .{ .pcid = 23 }, cpuBit(0).? | cpuBit(1).?);
    try std.testing.expectError(error.Busy, coordinator.begin(0, .{ .kernel = {} }, cpuBit(0).?));
    try std.testing.expectEqualDeep(request, coordinator.pending(1).?);
    try std.testing.expect(coordinator.acknowledge(1, request.generation));
    try coordinator.finish(0, request.generation);
    @atomicStore(u8, &coordinator.phase, preparing, .release);
    try std.testing.expect(coordinator.pending(1) == null);
    try std.testing.expect(!coordinator.acknowledge(1, request.generation));
    try std.testing.expectError(error.Busy, coordinator.begin(0, .{ .kernel = {} }, cpuBit(0).?));
    try coordinator.fail(0);
}

test "timeout or reset closes the coordinator without recycling generations" {
    var coordinator = try Coordinator.init(0);
    const request = try coordinator.begin(0, .{ .kernel = {} }, cpuBit(0).? | cpuBit(1).?);
    try coordinator.fail(0);
    try std.testing.expectEqual(request.generation, coordinator.last_generation);
    try std.testing.expectEqual(@as(u64, 0), @atomicLoad(u64, &coordinator.generation, .acquire));
    try std.testing.expect(coordinator.pending(1) == null);
    try std.testing.expect(!coordinator.acknowledge(1, request.generation));
    try std.testing.expect(!coordinator.complete(request.generation));
    try std.testing.expectError(error.Failed, coordinator.finish(0, request.generation));
    try std.testing.expectError(error.Failed, coordinator.begin(0, .{ .pcid = 7 }, cpuBit(0).?));
    try coordinator.fail(0);
}

test "generation exhaustion closes permanently instead of wrapping to a stale epoch" {
    var coordinator = try Coordinator.init(0);
    coordinator.last_generation = std.math.maxInt(u64) - 1;
    const final_request = try coordinator.begin(0, .{ .kernel = {} }, cpuBit(0).?);
    try std.testing.expectEqual(std.math.maxInt(u64), final_request.generation);
    try coordinator.finish(0, final_request.generation);
    try std.testing.expectError(error.GenerationExhausted, coordinator.begin(0, .{ .pcid = 1 }, cpuBit(0).?));
    try std.testing.expectEqual(std.math.maxInt(u64), coordinator.last_generation);
    try std.testing.expect(!coordinator.acknowledge(0, final_request.generation));
    try std.testing.expect(!coordinator.complete(final_request.generation));
    try std.testing.expectError(error.Failed, coordinator.begin(0, .{ .kernel = {} }, cpuBit(0).?));
}

test "completion requires exact stamps rather than future or partially matching stamps" {
    var coordinator = try Coordinator.init(0);
    const request = try coordinator.begin(0, .{ .kernel = {} }, cpuBit(0).? | cpuBit(1).?);
    @atomicStore(u64, &coordinator.acknowledgments[1].generation, request.generation + 1, .release);
    try std.testing.expect(coordinator.pending(1) == null);
    try std.testing.expect(!coordinator.acknowledge(1, request.generation));
    try std.testing.expect(!coordinator.complete(request.generation));
    try std.testing.expectError(error.Incomplete, coordinator.finish(0, request.generation));
    try coordinator.fail(0);
}

test "acknowledgment slots occupy separate cache lines in a bounded coordinator" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(Acknowledgment));
    try std.testing.expectEqual(@as(usize, 64), @alignOf(Acknowledgment));
    try std.testing.expect(@sizeOf(Coordinator) <= 1152);
    var coordinator = try Coordinator.init(0);
    for (&coordinator.acknowledgments) |*stamp| {
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(stamp) % 64);
    }
}
