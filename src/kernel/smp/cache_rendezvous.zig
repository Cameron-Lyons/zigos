const std = @import("std");
const tlb_request = @import("tlb_request.zig");

pub const CAPACITY = tlb_request.CAPACITY;
pub const CpuMask = tlb_request.CpuMask;
pub const Phase = enum(u8) { idle, preparing, parking, flushing, releasing, failed };
pub const Error = error{
    InvalidOwner,
    NotOwner,
    InvalidParticipants,
    Busy,
    Failed,
    GenerationExhausted,
    StaleRequest,
    Incomplete,
};

const Stamp = struct {
    parked: u64 align(64) = 0,
    flushed: u64 = 0,
    released: u64 = 0,
};

// One BSP owner, immutable topology during each transition, no hotplug. APs
// remain in their IF=0 IPI handler from parked until release. A failed epoch
// closes the coordinator permanently; neither generations nor stamps reset.
pub const Coordinator = struct {
    owner: u8,
    phase: u8 = @backingInt(Phase.idle),
    generation: u64 = 0,
    last_generation: u64 = 0,
    participants: CpuMask = 0,
    stamps: [CAPACITY]Stamp = @splat(.{}),

    pub inline fn init(owner: u8) Error!Coordinator {
        if (tlb_request.cpuBit(owner) == null) return error.InvalidOwner;
        return .{ .owner = owner };
    }

    pub inline fn begin(self: *Coordinator, caller: u8, participants: CpuMask) Error!u64 {
        if (caller != self.owner) return error.NotOwner;
        if (participants & tlb_request.cpuBit(self.owner).? == 0) return error.InvalidParticipants;
        if (@cmpxchgStrong(u8, &self.phase, @backingInt(Phase.idle), @backingInt(Phase.preparing), .acq_rel, .acquire)) |phase|
            return if (phase == @backingInt(Phase.failed)) error.Failed else error.Busy;
        const generation = std.math.add(u64, self.last_generation, 1) catch {
            self.fail(caller) catch unreachable;
            return error.GenerationExhausted;
        };
        self.last_generation = generation;
        @atomicStore(CpuMask, &self.participants, participants, .release);
        @atomicStore(u64, &self.stamps[self.owner].parked, generation, .monotonic);
        @atomicStore(u64, &self.generation, generation, .release);
        if (@cmpxchgStrong(u8, &self.phase, @backingInt(Phase.preparing), @backingInt(Phase.parking), .release, .monotonic) != null)
            return error.Failed;
        return generation;
    }

    pub inline fn pending(self: *const Coordinator, cpu: u8) ?u64 {
        if (cpu >= CAPACITY) return null;
        if (cpu == self.owner or tlb_request.cpuBit(cpu) == null) return null;
        const generation = @atomicLoad(u64, &self.generation, .acquire);
        if (!self.isParticipant(cpu, generation, .parking)) return null;
        if (@atomicLoad(u64, &self.stamps[cpu].parked, .acquire) >= generation) return null;
        return generation;
    }

    pub inline fn park(self: *Coordinator, cpu: u8, generation: u64) bool {
        if (cpu >= CAPACITY) return false;
        if (cpu == self.owner or !self.isParticipant(cpu, generation, .parking)) return false;
        return self.publish(&self.stamps[cpu].parked, generation, .parking);
    }

    pub inline fn parked(self: *const Coordinator, generation: u64) bool {
        return self.allStamped(generation, .parking, "parked");
    }

    // Page-table aliases are detached only after parked(). The owner starts
    // this phase after the detach stores, then each participant flushes its
    // caches and all translations before publishing its flush stamp.
    pub inline fn startFlush(self: *Coordinator, caller: u8, generation: u64) Error!void {
        if (caller != self.owner) return error.NotOwner;
        if (!self.matches(generation, .parking)) return error.StaleRequest;
        if (!self.parked(generation)) return error.Incomplete;
        @atomicStore(u8, &self.phase, @backingInt(Phase.flushing), .release);
    }

    pub inline fn recordFlush(self: *Coordinator, cpu: u8, generation: u64) bool {
        if (cpu >= CAPACITY) return false;
        if (!self.isParticipant(cpu, generation, .flushing) or
            @atomicLoad(u64, &self.stamps[cpu].parked, .acquire) != generation) return false;
        return self.publish(&self.stamps[cpu].flushed, generation, .flushing);
    }

    pub inline fn flushed(self: *const Coordinator, generation: u64) bool {
        return self.allStamped(generation, .flushing, "flushed");
    }

    // New leaves are published before release(). APs observe those stores
    // before leaving the handler. No mapping allocation occurs while parked.
    pub inline fn release(self: *Coordinator, caller: u8, generation: u64) Error!void {
        if (caller != self.owner) return error.NotOwner;
        if (!self.matches(generation, .flushing)) return error.StaleRequest;
        if (!self.flushed(generation)) return error.Incomplete;
        @atomicStore(u64, &self.stamps[self.owner].released, generation, .monotonic);
        @atomicStore(u8, &self.phase, @backingInt(Phase.releasing), .release);
    }

    pub inline fn recordRelease(self: *Coordinator, cpu: u8, generation: u64) bool {
        if (cpu >= CAPACITY) return false;
        if (cpu == self.owner or !self.isParticipant(cpu, generation, .releasing) or
            @atomicLoad(u64, &self.stamps[cpu].flushed, .acquire) != generation) return false;
        return self.publish(&self.stamps[cpu].released, generation, .releasing);
    }

    pub inline fn released(self: *const Coordinator, generation: u64) bool {
        return self.allStamped(generation, .releasing, "released");
    }

    pub inline fn finish(self: *Coordinator, caller: u8, generation: u64) Error!void {
        if (caller != self.owner) return error.NotOwner;
        if (!self.matches(generation, .releasing)) return error.StaleRequest;
        if (!self.released(generation)) return error.Incomplete;
        @atomicStore(u64, &self.generation, 0, .release);
        @atomicStore(u8, &self.phase, @backingInt(Phase.idle), .release);
    }

    pub inline fn phaseFor(self: *const Coordinator, generation: u64) ?Phase {
        if (generation == 0 or @atomicLoad(u64, &self.generation, .acquire) != generation) return null;
        const phase: Phase = @fromBackingInt(@intCast(@atomicLoad(u8, &self.phase, .acquire)));
        return if (@atomicLoad(u64, &self.generation, .acquire) == generation) phase else null;
    }

    pub inline fn fail(self: *Coordinator, caller: u8) Error!void {
        if (caller != self.owner) return error.NotOwner;
        @atomicStore(u8, &self.phase, @backingInt(Phase.failed), .release);
        @atomicStore(u64, &self.generation, 0, .release);
    }

    inline fn matches(self: *const Coordinator, generation: u64, phase: Phase) bool {
        return self.phaseFor(generation) == phase;
    }

    inline fn isParticipant(self: *const Coordinator, cpu: u8, generation: u64, phase: Phase) bool {
        const bit = tlb_request.cpuBit(cpu) orelse return false;
        return self.matches(generation, phase) and @atomicLoad(CpuMask, &self.participants, .acquire) & bit != 0 and
            self.matches(generation, phase);
    }

    inline fn publish(self: *Coordinator, stamp: *u64, generation: u64, phase: Phase) bool {
        var previous = @atomicLoad(u64, stamp, .monotonic);
        while (previous < generation) {
            if (!self.matches(generation, phase)) return false;
            if (@cmpxchgWeak(u64, stamp, previous, generation, .release, .monotonic)) |observed| {
                previous = observed;
            } else {
                // This stamp itself authorizes the owner to advance the phase.
                // A post-CAS phase check would race that legal advancement and
                // falsely report failure to the participant that completed it.
                return true;
            }
        }
        return false;
    }

    inline fn allStamped(self: *const Coordinator, generation: u64, phase: Phase, comptime field: []const u8) bool {
        if (!self.matches(generation, phase)) return false;
        var remaining = @atomicLoad(CpuMask, &self.participants, .acquire);
        if (remaining & tlb_request.cpuBit(self.owner).? == 0) return false;
        while (remaining != 0) {
            const cpu: u4 = @intCast(@ctz(remaining));
            if (@atomicLoad(u64, &@field(self.stamps[cpu], field), .acquire) != generation) return false;
            remaining &= remaining - 1;
        }
        return self.matches(generation, phase);
    }
};

test "cache transition holds every CPU through park flush publication and release" {
    var coordinator = try Coordinator.init(0);
    const generation = try coordinator.begin(0, std.math.maxInt(CpuMask));
    try std.testing.expectError(error.Incomplete, coordinator.startFlush(0, generation));
    for (1..CAPACITY) |index| {
        const cpu: u8 = @intCast(index);
        try std.testing.expectEqual(generation, coordinator.pending(cpu).?);
        try std.testing.expect(!coordinator.recordFlush(cpu, generation));
        try std.testing.expect(!coordinator.recordRelease(cpu, generation));
        try std.testing.expect(coordinator.park(cpu, generation));
        try std.testing.expect(!coordinator.park(cpu, generation));
        try std.testing.expect(coordinator.pending(cpu) == null);
    }
    try std.testing.expect(coordinator.parked(generation));
    try coordinator.startFlush(0, generation);
    try std.testing.expectError(error.Incomplete, coordinator.release(0, generation));
    for (0..CAPACITY) |index| {
        try std.testing.expect(!coordinator.flushed(generation));
        try std.testing.expect(coordinator.recordFlush(@intCast(index), generation));
        try std.testing.expect(!coordinator.recordFlush(@intCast(index), generation));
    }
    try coordinator.release(0, generation);
    try std.testing.expectError(error.Incomplete, coordinator.finish(0, generation));
    for (1..CAPACITY) |index| {
        try std.testing.expect(!coordinator.released(generation));
        try std.testing.expect(coordinator.recordRelease(@intCast(index), generation));
        try std.testing.expect(!coordinator.recordRelease(@intCast(index), generation));
    }
    try coordinator.finish(0, generation);
    try std.testing.expect(coordinator.phaseFor(generation) == null);
}

test "cache transition rejects foreign owner stale epochs and nonparticipants" {
    try std.testing.expectError(error.InvalidOwner, Coordinator.init(CAPACITY));
    var coordinator = try Coordinator.init(3);
    try std.testing.expectError(error.NotOwner, coordinator.begin(0, 1));
    try std.testing.expectError(error.InvalidParticipants, coordinator.begin(3, 1));
    const mask = tlb_request.cpuBit(3).? | tlb_request.cpuBit(15).?;
    const first = try coordinator.begin(3, mask);
    try std.testing.expectError(error.Busy, coordinator.begin(3, mask));
    try std.testing.expect(!coordinator.park(0, first));
    try std.testing.expect(!coordinator.park(CAPACITY, first));
    try std.testing.expect(coordinator.park(15, first));
    try coordinator.startFlush(3, first);
    try std.testing.expect(coordinator.recordFlush(3, first));
    try std.testing.expect(coordinator.recordFlush(15, first));
    try coordinator.release(3, first);
    try std.testing.expect(coordinator.recordRelease(15, first));
    try coordinator.finish(3, first);
    const second = try coordinator.begin(3, mask);
    try std.testing.expectEqual(first + 1, second);
    try std.testing.expect(!coordinator.park(15, first));
    try std.testing.expect(!coordinator.recordFlush(15, first));
    try std.testing.expect(!coordinator.recordRelease(15, first));
    try std.testing.expect(!coordinator.parked(second));
    try std.testing.expectError(error.StaleRequest, coordinator.startFlush(3, first));
    try std.testing.expectEqual(first, @atomicLoad(u64, &coordinator.stamps[15].parked, .acquire));
}

test "single CPU transitions and failed epochs do not recycle authority" {
    var coordinator = try Coordinator.init(0);
    const generation = try coordinator.begin(0, 1);
    try std.testing.expect(coordinator.parked(generation));
    try coordinator.startFlush(0, generation);
    try std.testing.expect(coordinator.recordFlush(0, generation));
    try coordinator.release(0, generation);
    try coordinator.finish(0, generation);
    const next = try coordinator.begin(0, 3);
    try std.testing.expectError(error.NotOwner, coordinator.fail(1));
    try coordinator.fail(0);
    try std.testing.expect(!coordinator.park(1, next));
    try std.testing.expect(coordinator.phaseFor(next) == null);
    try std.testing.expectError(error.Failed, coordinator.begin(0, 1));
    var exhausted = try Coordinator.init(0);
    exhausted.last_generation = std.math.maxInt(u64);
    try std.testing.expectError(error.GenerationExhausted, exhausted.begin(0, 1));
    try std.testing.expectError(error.Failed, exhausted.begin(0, 1));
}

test "concurrent participants survive immediate phase advancement over repeated epochs" {
    const Worker = struct {
        coordinator: *Coordinator,
        publication: *u64,
        failed: *bool,
        cancel: *bool,
        cpu: u8,

        fn run(self: @This()) void {
            for (0..100) |_| {
                const generation = wait: while (true) {
                    if (@atomicLoad(bool, self.cancel, .acquire)) return;
                    if (self.coordinator.pending(self.cpu)) |generation| break :wait generation;
                    std.atomic.spinLoopHint();
                };
                if (!self.coordinator.park(self.cpu, generation)) {
                    @atomicStore(bool, self.failed, true, .release);
                    return;
                }
                var flushed = false;
                while (true) {
                    if (@atomicLoad(bool, self.cancel, .acquire)) return;
                    switch (self.coordinator.phaseFor(generation) orelse {
                        @atomicStore(bool, self.failed, true, .release);
                        return;
                    }) {
                        .parking => {},
                        .flushing => if (!flushed) {
                            if (!self.coordinator.recordFlush(self.cpu, generation)) {
                                @atomicStore(bool, self.failed, true, .release);
                                return;
                            }
                            flushed = true;
                        },
                        .releasing => {
                            if (!flushed or @atomicLoad(u64, self.publication, .monotonic) != generation or
                                !self.coordinator.recordRelease(self.cpu, generation))
                                @atomicStore(bool, self.failed, true, .release);
                            break;
                        },
                        else => {
                            @atomicStore(bool, self.failed, true, .release);
                            return;
                        },
                    }
                    std.atomic.spinLoopHint();
                }
            }
        }
    };
    var coordinator = try Coordinator.init(0);
    var publication: u64 = 0;
    var failed = false;
    var cancel = false;
    var threads: [CAPACITY - 1]std.Thread = undefined;
    var started: usize = 0;
    defer {
        @atomicStore(bool, &cancel, true, .release);
        for (threads[0..started]) |thread| thread.join();
    }
    for (&threads, 1..) |*thread, cpu| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{Worker{
            .coordinator = &coordinator,
            .publication = &publication,
            .failed = &failed,
            .cancel = &cancel,
            .cpu = @intCast(cpu),
        }});
        started += 1;
    }
    for (0..100) |_| {
        const generation = try coordinator.begin(0, std.math.maxInt(CpuMask));
        while (!coordinator.parked(generation)) {
            try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
            std.atomic.spinLoopHint();
        }
        try coordinator.startFlush(0, generation);
        try std.testing.expect(coordinator.recordFlush(0, generation));
        while (!coordinator.flushed(generation)) {
            try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
            std.atomic.spinLoopHint();
        }
        @atomicStore(u64, &publication, generation, .monotonic);
        try coordinator.release(0, generation);
        while (!coordinator.released(generation)) {
            try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
            std.atomic.spinLoopHint();
        }
        try coordinator.finish(0, generation);
    }
    for (threads[0..started]) |thread| thread.join();
    started = 0;
    try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
}
