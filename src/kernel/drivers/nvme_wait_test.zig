const std = @import("std");
const poll = @import("nvme_poll.zig");
const operation = @import("nvme_operation.zig");
const pipeline = @import("nvme_pipeline.zig");
const cooperative = @import("../../native/task/cooperative_worker.zig");

const Queue = struct { qid: u16 = 1, entries: u32 = 4, cq_head: u32 = 0, phase: u1 = 1 };
const Command = struct { cid: u16, deadline: u64 };
const Io = struct {
    cq: [4][2]u32 = @splat(.{ 0, 0 }),
    checks: usize = 0,
    fail_after: usize = 3,
    fatal_controller: bool = false,
    dma_failed: bool = false,
    acquire_count: usize = 0,
    acknowledgements: usize = 0,
    acknowledged_head: u32 = 0,
    pauses: usize = 0,
    idles: usize = 0,
    complete_on_pause: bool = false,
    complete_on_pause_qid: u16 = 1,

    pub fn expired(self: *@This(), _: u64) bool {
        self.checks += 1;
        return self.checks >= self.fail_after;
    }
    pub fn fatal(self: *@This()) bool {
        return self.fatal_controller;
    }
    pub fn checkDma(self: *@This()) poll.Error!void {
        if (self.dma_failed) return error.DmaFault;
    }
    pub fn status(self: *@This(), head: u32) u32 {
        return self.cq[head][1];
    }
    pub fn submission(self: *@This(), head: u32) u32 {
        return self.cq[head][0];
    }
    pub fn acquireCompletion(self: *@This()) void {
        self.acquire_count += 1;
    }
    pub fn acknowledge(self: *@This(), head: u32) void {
        self.acknowledgements += 1;
        self.acknowledged_head = head;
    }
    pub fn pause(self: *@This()) void {
        self.pauses += 1;
        if (self.complete_on_pause) self.publish(0, 41, self.complete_on_pause_qid, 1, 0);
    }
    pub fn idle(self: *@This(), _: *Queue) void {
        self.idles += 1;
        self.pause();
    }
    fn publish(self: *@This(), head: u32, cid: u16, qid: u16, phase: u1, status_code: u15) void {
        self.cq[head] = .{ (@as(u32, qid) << 16) | 1, cid | (@as(u32, phase) << 16) | (@as(u32, status_code) << 17) };
    }
};

const WaitFixture = struct {
    io: Io = .{},
    queue: Queue = .{},
    lease: operation.Lease = .{},
    interrupt_wait: bool = true,
    result: ?u16 = null,
    failure: ?anyerror = null,
    contained: bool = false,

    fn run(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const identity = @intFromPtr(cooperative.current().?);
        if (!self.lease.execute(identity, self) and self.failure == null) self.failure = error.Busy;
    }
    pub fn perform(self: *@This()) poll.Error!void {
        const commands = [_]Command{.{ .cid = 41, .deadline = 100 }};
        self.result = try poll.wait(&self.io, &self.queue, &commands, self.interrupt_wait, cooperative.current());
    }
    pub fn contain(self: *@This(), err: anyerror) void {
        if (!self.lease.busy()) @panic("fatal completion containment precedes operation release");
        self.contained = true;
        self.failure = err;
    }
    fn finish(self: *@This(), worker: *cooperative.Worker) void {
        if (worker.state == .suspended) {
            self.io.publish(self.queue.cq_head, 41, self.queue.qid, self.queue.phase, 0);
            worker.step() catch @panic("fixture cleanup resumes its worker");
        }
    }
};

test "NVMe pending completion yields its real Worker and retains operation ownership" {
    var stack: [8192]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    var fixture = WaitFixture{};
    try worker.start(&fixture, WaitFixture.run);
    defer fixture.finish(&worker);
    try worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
    try std.testing.expect(fixture.failure == null and fixture.result == null);
    try std.testing.expect(fixture.lease.busy());
    try std.testing.expect(!fixture.lease.acquire(1));
    try std.testing.expect(!fixture.lease.acquire(@intFromPtr(&worker)));
    try std.testing.expectEqual(@as(usize, 0), fixture.io.pauses + fixture.io.idles);
    fixture.io.publish(0, 41, 1, 1, 0);
    try worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.complete, worker.state);
    try std.testing.expectEqual(@as(?u16, 41), fixture.result);
    try std.testing.expect(!fixture.lease.busy());
    try std.testing.expectEqual(@as(u32, 1), fixture.queue.cq_head);
}

test "NVMe common completion poll authenticates CID queue phase and terminal state" {
    var io = Io{ .fail_after = 100 };
    var queue = Queue{};
    const commands = [_]Command{ .{ .cid = 41, .deadline = 100 }, .{ .cid = 42, .deadline = 100 } };
    try std.testing.expect((try poll.poll(&io, &queue, &commands, true)) == null);
    io.publish(0, 42, 2, 1, 0);
    try std.testing.expectError(error.CompletionOwnershipMismatch, poll.poll(&io, &queue, &commands, true));
    io.publish(0, 99, 1, 1, 0);
    try std.testing.expectError(error.CompletionOwnershipMismatch, poll.poll(&io, &queue, &commands, true));
    io.publish(0, 42, 1, 1, 0);
    io.cq[0][0] = (@as(u32, 1) << 16) | queue.entries;
    try std.testing.expectError(error.CompletionOwnershipMismatch, poll.poll(&io, &queue, &commands, true));
    try std.testing.expectEqual(@as(u32, 0), queue.cq_head);
    try std.testing.expectEqual(@as(usize, 0), io.acknowledgements);
    io.publish(0, 42, 1, 1, 0);
    try std.testing.expectEqual(@as(?u16, 42), try poll.poll(&io, &queue, &commands, true));
    io.publish(1, 41, 1, 1, 1);
    try std.testing.expectError(error.CommandFailed, poll.poll(&io, &queue, commands[0..1], true));
    try std.testing.expectEqual(@as(u32, 2), queue.cq_head);
    io.dma_failed = true;
    try std.testing.expectError(error.DmaFault, poll.poll(&io, &queue, &commands, true));
    io.dma_failed = false;
    io.fatal_controller = true;
    try std.testing.expectError(error.ControllerFatal, poll.poll(&io, &queue, &commands, true));
    io.fatal_controller = false;
    io.fail_after = io.checks;
    try std.testing.expectError(error.CommandTimeout, poll.poll(&io, &queue, &commands, true));
    try std.testing.expectError(error.CompletionOwnershipMismatch, poll.poll(&io, &queue, commands[0..0], true));
}

test "NVMe admin and non-Worker waits preserve synchronous polling and idle paths" {
    const commands = [_]Command{.{ .cid = 41, .deadline = 100 }};
    var queue = Queue{};
    var io = Io{ .complete_on_pause = true, .fail_after = 100 };
    try std.testing.expectEqual(@as(u16, 41), try poll.wait(&io, &queue, &commands, false, null));
    try std.testing.expectEqual(@as(usize, 1), io.pauses);
    try std.testing.expectEqual(@as(usize, 0), io.idles);
    queue = .{};
    io = .{ .complete_on_pause = true, .fail_after = 100 };
    try std.testing.expectEqual(@as(u16, 41), try poll.wait(&io, &queue, &commands, true, null));
    try std.testing.expectEqual(@as(usize, 1), io.idles);
    var stack: [8192]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    var fixture = WaitFixture{ .queue = .{ .qid = 0 }, .io = .{ .complete_on_pause = true, .complete_on_pause_qid = 0, .fail_after = 100 }, .interrupt_wait = false };
    try worker.start(&fixture, WaitFixture.run);
    defer fixture.finish(&worker);
    try worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.complete, worker.state);
    try std.testing.expectEqual(@as(?u16, 41), fixture.result);
    try std.testing.expectEqual(@as(usize, 1), fixture.io.pauses);
}

test "NVMe CQ wrap flips phase and cannot consume a stale entry twice" {
    var io = Io{ .fail_after = 100 };
    var queue = Queue{ .cq_head = 3 };
    const commands = [_]Command{.{ .cid = 41, .deadline = 100 }};
    io.publish(3, 41, 1, 1, 0);
    try std.testing.expectEqual(@as(?u16, 41), try poll.poll(&io, &queue, &commands, true));
    try std.testing.expectEqual(@as(u32, 0), queue.cq_head);
    try std.testing.expectEqual(@as(u1, 0), queue.phase);
    io.publish(0, 41, 1, 1, 0);
    try std.testing.expect((try poll.poll(&io, &queue, &commands, true)) == null);
    try std.testing.expectEqual(@as(usize, 1), io.acknowledgements);
    io.publish(0, 41, 1, 0, 0);
    try std.testing.expectEqual(@as(?u16, 41), try poll.poll(&io, &queue, &commands, true));
    try std.testing.expectEqual(@as(usize, 2), io.acknowledgements);
}

test "NVMe pending Worker failure contains before releasing the physical operation" {
    inline for (.{ error.CommandTimeout, error.ControllerFatal, error.DmaFault, error.CompletionOwnershipMismatch, error.CommandFailed }) |failure| {
        var stack: [8192]u8 align(16) = undefined;
        var worker = cooperative.Worker{ .stack = &stack };
        var fixture = WaitFixture{ .io = .{ .fail_after = 100 } };
        try worker.start(&fixture, WaitFixture.run);
        defer fixture.finish(&worker);
        try worker.step();
        try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
        const cause: poll.Error = failure;
        switch (cause) {
            error.CommandTimeout => fixture.io.fail_after = fixture.io.checks,
            error.ControllerFatal => fixture.io.fatal_controller = true,
            error.DmaFault => fixture.io.dma_failed = true,
            error.CompletionOwnershipMismatch => fixture.io.publish(0, 99, 1, 1, 0),
            error.CommandFailed => fixture.io.publish(0, 41, 1, 1, 1),
            else => unreachable,
        }
        try worker.step();
        try std.testing.expectEqual(cooperative.Worker.State.complete, worker.state);
        try std.testing.expect(fixture.failure.? == failure);
        try std.testing.expect(fixture.contained and !fixture.lease.busy());
    }
}

const PipelineFixture = struct {
    pub const Error = poll.Error || error{ Cancelled, AuthorityRevoked };
    io: Io = .{ .fail_after = 100 },
    queue: Queue = .{},
    lease: operation.Lease = .{},
    authority: bool = true,
    submitted: usize = 0,
    completed_count: usize = 0,
    failure: ?anyerror = null,
    contained: bool = false,
    active: [2]bool = @splat(false),
    slot_cids: [2]u16 = @splat(0),
    bounce: [2][16]u8 = undefined,
    destination: [48]u8 = @splat(0),

    pub fn cancelled(_: *@This()) bool {
        return cooperative.current().?.cancel_requested;
    }
    pub fn authorized(self: *@This()) bool {
        return self.authority;
    }
    pub fn submit(self: *@This(), slot: usize, offset: usize, _: usize) Error!Command {
        if (self.active[slot]) @panic("accepted DMA slot cannot be reused");
        self.active[slot] = true;
        self.submitted += 1;
        const cid: u16 = @intCast(40 + self.submitted);
        self.slot_cids[slot] = cid;
        @memset(&self.bounce[slot], @intCast(offset + 1));
        return .{ .cid = cid, .deadline = 100 };
    }
    pub fn wait(self: *@This(), commands: []const Command) Error!u16 {
        return poll.wait(&self.io, &self.queue, commands, true, cooperative.current());
    }
    pub fn completed(self: *@This(), value: pipeline.SlotSet(Command).Completed) void {
        if (!self.active[value.index] or self.slot_cids[value.index] != value.payload.cid) @panic("completion owns exact accepted slot");
        @memcpy(self.destination[value.sector_offset * 16 ..][0..value.byte_count], self.bounce[value.index][0..value.byte_count]);
        self.active[value.index] = false;
        self.completed_count += 1;
    }
    fn run(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const identity = @intFromPtr(cooperative.current().?);
        if (!self.lease.execute(identity, self) and self.failure == null) @panic("fixture starts with no active operation");
    }
    pub fn perform(self: *@This()) Error!void {
        return pipeline.transfer(Command, self, 3, 1, 16);
    }
    pub fn contain(self: *@This(), err: anyerror) void {
        if (!self.lease.busy()) @panic("fatal pipeline containment precedes operation release");
        self.failure = err;
        if (err != error.Cancelled and err != error.AuthorityRevoked) self.contained = true;
    }
    fn finish(self: *@This(), worker: *cooperative.Worker) void {
        worker.cancel();
        while (worker.state == .suspended) {
            for (self.active, 0..) |active, slot| if (active) {
                self.io.publish(self.queue.cq_head, self.slot_cids[slot], 1, self.queue.phase, 0);
                break;
            };
            worker.step() catch @panic("fixture cleanup drains every accepted command");
        }
    }
};

test "NVMe canceled or revoked Worker drains both accepted slots without refill" {
    inline for (.{ error.Cancelled, error.AuthorityRevoked }) |failure| {
        var stack: [8192]u8 align(16) = undefined;
        var worker = cooperative.Worker{ .stack = &stack };
        var fixture = PipelineFixture{};
        try worker.start(&fixture, PipelineFixture.run);
        defer fixture.finish(&worker);
        try worker.step();
        try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
        try std.testing.expectEqual(@as(usize, 2), fixture.submitted);
        if (failure == error.Cancelled) worker.cancel() else fixture.authority = false;
        fixture.io.publish(0, 42, 1, 1, 0);
        try worker.step();
        try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
        try std.testing.expectEqual(@as(usize, 2), fixture.submitted);
        try std.testing.expectEqual(@as(usize, 1), fixture.completed_count);
        try std.testing.expect(fixture.lease.busy() and fixture.active[0] and !fixture.active[1]);
        fixture.io.publish(1, 41, 1, 1, 0);
        try worker.step();
        try std.testing.expectEqual(cooperative.Worker.State.complete, worker.state);
        try std.testing.expect(fixture.failure.? == failure);
        try std.testing.expectEqual(@as(usize, 2), fixture.completed_count);
        try std.testing.expect(!fixture.contained and !fixture.lease.busy());
        try std.testing.expect(std.mem.allEqual(u8, fixture.destination[0..16], 1));
        try std.testing.expect(std.mem.allEqual(u8, fixture.destination[16..32], 2));
        try std.testing.expect(std.mem.allEqual(u8, fixture.destination[32..48], 0));
    }
}

test "NVMe completed slot alone can refill and read copies retain exact ownership" {
    var stack: [8192]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    var fixture = PipelineFixture{};
    try worker.start(&fixture, PipelineFixture.run);
    defer fixture.finish(&worker);
    try worker.step();
    fixture.io.publish(0, 42, 1, 1, 0);
    try worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
    try std.testing.expectEqual(@as(usize, 3), fixture.submitted);
    try std.testing.expectEqual(@as(u16, 41), fixture.slot_cids[0]);
    try std.testing.expectEqual(@as(u16, 43), fixture.slot_cids[1]);
    fixture.io.publish(1, 41, 1, 1, 0);
    try worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
    fixture.io.publish(2, 43, 1, 1, 0);
    try worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.complete, worker.state);
    try std.testing.expect(fixture.failure == null and !fixture.lease.busy());
    try std.testing.expectEqual(@as(usize, 3), fixture.completed_count);
    try std.testing.expect(std.mem.allEqual(u8, fixture.destination[0..16], 1));
    try std.testing.expect(std.mem.allEqual(u8, fixture.destination[16..32], 2));
    try std.testing.expect(std.mem.allEqual(u8, fixture.destination[32..48], 3));
}

test "NVMe cancellation or authority denial before submission touches no DMA slots" {
    inline for (.{ true, false }) |cancel| {
        var stack: [8192]u8 align(16) = undefined;
        var worker = cooperative.Worker{ .stack = &stack };
        var fixture = PipelineFixture{ .authority = cancel };
        try worker.start(&fixture, PipelineFixture.run);
        defer fixture.finish(&worker);
        if (cancel) worker.cancel();
        try worker.step();
        try std.testing.expectEqual(cooperative.Worker.State.complete, worker.state);
        try std.testing.expect(fixture.failure.? == (if (cancel) error.Cancelled else error.AuthorityRevoked));
        try std.testing.expectEqual(@as(usize, 0), fixture.submitted + fixture.completed_count);
        try std.testing.expect(!fixture.lease.busy() and !fixture.contained);
    }
}

test "NVMe suspended physical operation rejects a second actual Worker" {
    const Contender = struct {
        lease: *operation.Lease,
        accepted: bool = true,
        performed: bool = false,
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.accepted = self.lease.execute(@intFromPtr(cooperative.current().?), self);
        }
        pub fn perform(self: *@This()) error{}!void {
            self.performed = true;
        }
        pub fn contain(_: *@This(), _: anyerror) void {
            @panic("empty operation has no terminal failure");
        }
    };
    var stack: [8192]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    var fixture = WaitFixture{};
    try worker.start(&fixture, WaitFixture.run);
    defer fixture.finish(&worker);
    try worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
    var other_stack: [8192]u8 align(16) = undefined;
    var other_worker = cooperative.Worker{ .stack = &other_stack };
    var contender = Contender{ .lease = &fixture.lease };
    try other_worker.start(&contender, Contender.run);
    try other_worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.complete, other_worker.state);
    try std.testing.expect(!contender.accepted and !contender.performed);
    try std.testing.expect(fixture.lease.busy() and fixture.result == null);
    fixture.io.publish(0, 41, 1, 1, 0);
    try worker.step();
    try std.testing.expectEqual(@as(?u16, 41), fixture.result);
    try std.testing.expect(!fixture.lease.busy());
}

test "NVMe revoked pipeline still contains an unowned completion before operation release" {
    var stack: [8192]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    var fixture = PipelineFixture{};
    try worker.start(&fixture, PipelineFixture.run);
    defer fixture.finish(&worker);
    try worker.step();
    fixture.authority = false;
    fixture.io.publish(0, 99, 1, 1, 0);
    try worker.step();
    try std.testing.expectEqual(cooperative.Worker.State.complete, worker.state);
    try std.testing.expect(fixture.failure.? == error.CompletionOwnershipMismatch);
    try std.testing.expect(fixture.contained and !fixture.lease.busy());
    try std.testing.expectEqual(@as(usize, 0), fixture.completed_count);
    try std.testing.expectEqual(@as(u32, 0), fixture.queue.cq_head);
}
