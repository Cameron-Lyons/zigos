const builtin = @import("builtin");
const std = @import("std");
const cpu_identity = @import("../../kernel/cpu_identity.zig");
const ownership = @import("dispatch_ownership.zig");

pub const CAPACITY = cpu_identity.MAX_CPUS;
pub const Command = struct { ticket: ownership.Ticket, trap_stack_top: usize };
pub const Key = struct { pool: *const Pool, cpu: u8, sequence: u64 };
pub const ClaimedCommand = struct { key: Key, command: Command };
pub const Completion = enum { owner_returned, unstarted };
pub const Error = ownership.Error || error{ InterruptsEnabled, InvalidCommand, StaleKey, NoCommand };

const Phase = enum(u3) { idle, publishing, pending, claimed, completed, collecting };
const PHASE_MASK: u64 = 7;
const UNSTARTED: u64 = 8;
const SEQUENCE_SHIFT = 4;
const MAX_SEQUENCE = std.math.maxInt(u64) >> SEQUENCE_SHIFT;

// Only the BSP changes payload storage. It reserves publishing before writing
// and releases pending after the complete shell is initialized. An owner claims
// before copying it; payload storage cannot be replaced until BSP collection.
const Channel = struct {
    control: u64 align(64) = 0,
    ticket: ownership.Ticket = undefined,
    trap_stack_top: usize = 0,
    prompt: u8 = 0,
    padding: [23]u8 = @splat(0),
};

pub const Pool = struct {
    channels: [CAPACITY]Channel = @splat(.{}),

    // An interrupt records only a coalesced owner-local hint. It neither
    // authenticates nor claims a command; publication and collection preserve
    // the hint so a delayed interrupt may inspect the current replacement.
    pub fn notePrompt(self: *Pool) Error!void {
        const cpu = cpu_identity.currentIndex();
        if (cpu >= CAPACITY) return error.InvalidCpu;
        try requireInterruptsMasked();
        @atomicStore(u8, &self.channels[cpu].prompt, 1, .release);
    }

    pub fn takePrompt(self: *Pool, cpu: u8) Error!bool {
        try requireOwner(cpu);
        return @atomicRmw(u8, &self.channels[cpu].prompt, .Xchg, 0, .acquire) != 0;
    }

    pub fn publishInto(self: *Pool, command: Command, out: *Key) Error!void {
        try requireBsp();
        if (command.ticket.cpu >= CAPACITY) return error.InvalidCpu;
        if (command.trap_stack_top == 0 or command.trap_stack_top % 16 != 0) return error.InvalidCommand;
        try command.ticket.issuer.preparedReady(command.ticket);
        const channel = &self.channels[command.ticket.cpu];
        const previous = @atomicLoad(u64, &channel.control, .acquire);
        if (phaseOf(previous) != .idle) return error.Busy;
        const old_sequence = sequenceOf(previous);
        if (old_sequence == MAX_SEQUENCE) return error.SequenceExhausted;
        const sequence = old_sequence + 1;
        const publishing = pack(sequence, .publishing, .owner_returned);
        if (@cmpxchgStrong(u64, &channel.control, previous, publishing, .acq_rel, .acquire) != null) return error.Busy;
        channel.ticket = command.ticket;
        channel.trap_stack_top = command.trap_stack_top;
        @atomicStore(u64, &channel.control, pack(sequence, .pending, .owner_returned), .release);
        out.* = .{ .pool = self, .cpu = command.ticket.cpu, .sequence = sequence };
    }

    pub fn claimInto(self: *Pool, cpu: u8, out: *ClaimedCommand) Error!void {
        try requireOwner(cpu);
        const control = @atomicLoad(u64, &self.channels[cpu].control, .acquire);
        if (phaseOf(control) != .pending) return error.NoCommand;
        try self.claimKeyInto(.{ .pool = self, .cpu = cpu, .sequence = sequenceOf(control) }, out);
    }

    pub fn claimKeyInto(self: *Pool, key: Key, out: *ClaimedCommand) Error!void {
        try requireOwner(key.cpu);
        try self.checkKey(key);
        const channel = &self.channels[key.cpu];
        const control = @atomicLoad(u64, &channel.control, .acquire);
        try requireKey(control, key);
        if (phaseOf(control) != .pending) return error.NoCommand;
        if (@cmpxchgStrong(u64, &channel.control, control, withPhase(control, .claimed), .acq_rel, .acquire) != null) return error.NoCommand;
        out.* = .{ .key = key, .command = .{ .ticket = channel.ticket, .trap_stack_top = channel.trap_stack_top } };
    }

    // Pending withdrawal wins or loses the same CAS as owner claim. A claimed
    // shell must finish on its owner, even if its lease has been canceled/STOPped.
    pub fn withdraw(self: *Pool, key: Key) Error!void {
        try requireBsp();
        try self.checkKey(key);
        const channel = &self.channels[key.cpu];
        const control = @atomicLoad(u64, &channel.control, .acquire);
        try requireKey(control, key);
        if (phaseOf(control) != .pending) return error.WrongPhase;
        if (@cmpxchgStrong(u64, &channel.control, control, pack(key.sequence, .completed, .unstarted), .release, .acquire) != null) return error.WrongPhase;
    }

    // Call only after the runner's execution ACK, or after it rejects an
    // unstarted command without retaining backing. From ACK onward the owner
    // accesses only this independent static control and its captured scalars:
    // no issuer, Executor, mapping, ticket payload or command-shell reads.
    pub fn complete(self: *Pool, key: Key, completion: Completion) Error!void {
        try requireOwner(key.cpu);
        try self.checkKey(key);
        const channel = &self.channels[key.cpu];
        const control = @atomicLoad(u64, &channel.control, .acquire);
        try requireKey(control, key);
        if (phaseOf(control) != .claimed) return error.WrongPhase;
        if (@cmpxchgStrong(u64, &channel.control, control, pack(key.sequence, .completed, completion), .release, .acquire) != null) return error.WrongPhase;
    }

    pub fn completionInto(self: *Pool, key: Key, out: *Completion) Error!void {
        try requireBsp();
        try self.checkKey(key);
        const control = @atomicLoad(u64, &self.channels[key.cpu].control, .acquire);
        try requireKey(control, key);
        if (phaseOf(control) != .completed) return error.WrongPhase;
        out.* = completionOf(control);
    }

    // A synchronous dispatch has no matching channel and needs no guard. Queued
    // dispatches cannot enter Coordinator collecting until independent static
    // completion is acquired. Keep this guard through every resource callback,
    // retained-borrow release and Coordinator finish; abort on admission errors.
    pub fn beginCollectionInto(self: *Pool, ticket: ownership.Ticket, out: *Key) Error!bool {
        try requireBsp();
        if (ticket.cpu >= CAPACITY) return error.InvalidCpu;
        const channel = &self.channels[ticket.cpu];
        const control = @atomicLoad(u64, &channel.control, .acquire);
        const phase = phaseOf(control);
        if (phase == .idle) return false;
        if (phase == .publishing) return error.Busy;
        if (!sameTicket(channel.ticket, ticket)) return false;
        if (phase != .completed) return error.Busy;
        if (@cmpxchgStrong(u64, &channel.control, control, withPhase(control, .collecting), .acq_rel, .acquire) != null) return error.Busy;
        out.* = .{ .pool = self, .cpu = ticket.cpu, .sequence = sequenceOf(control) };
        return true;
    }

    pub inline fn abortCollection(self: *Pool, key: Key) Error!void {
        try self.endCollection(key, false);
    }

    pub fn finishCollection(self: *Pool, key: Key) Error!void {
        try self.endCollection(key, true);
    }

    fn endCollection(self: *Pool, key: Key, finished: bool) Error!void {
        try requireBsp();
        try self.checkKey(key);
        const channel = &self.channels[key.cpu];
        const control = @atomicLoad(u64, &channel.control, .acquire);
        try requireKey(control, key);
        if (phaseOf(control) != .collecting) return error.WrongPhase;
        const replacement = if (finished) pack(key.sequence, .idle, .owner_returned) else withPhase(control, .completed);
        if (@cmpxchgStrong(u64, &channel.control, control, replacement, .release, .acquire) != null) return error.WrongPhase;
    }

    pub fn hasOutstandingForIssuer(self: *const Pool, issuer: *const ownership.Coordinator) bool {
        if (cpu_identity.currentIndex() != 0) return true;
        for (&self.channels) |*channel| {
            const phase = phaseOf(@atomicLoad(u64, &channel.control, .acquire));
            if (phase == .idle) continue;
            // Payload may be only partially initialized in publishing. Refuse
            // every issuer teardown rather than reading it during publication.
            if (phase == .publishing or channel.ticket.issuer == issuer) return true;
        }
        return false;
    }

    inline fn checkKey(self: *const Pool, key: Key) Error!void {
        if (key.pool != self) return error.WrongCoordinator;
        if (key.cpu >= CAPACITY) return error.InvalidCpu;
        if (key.sequence == 0 or key.sequence > MAX_SEQUENCE) return error.StaleKey;
    }
};

// This image-owned pool outlives every command, issuer and registered domain.
// Never reset/reinitialize it: sequence cursors belong to the pool's lifetime.
pub var global: Pool = .{};

comptime {
    if (@sizeOf(Command) != 32 or @sizeOf(Key) != 24 or @sizeOf(ClaimedCommand) != 56)
        @compileError("dispatch transport command/key geometry changed");
    if (@alignOf(Channel) != 64 or @sizeOf(Channel) != 64 or @sizeOf(Pool) != CAPACITY * 64 or @alignOf(Pool) != 64)
        @compileError("dispatch transport channels must occupy independent cache lines");
}

inline fn requireBsp() Error!void {
    if (cpu_identity.currentIndex() != 0) return error.WrongCpu;
    try requireInterruptsMasked();
}
inline fn requireOwner(cpu: u8) Error!void {
    if (cpu >= CAPACITY) return error.InvalidCpu;
    if (cpu_identity.currentIndex() != cpu) return error.WrongCpu;
    try requireInterruptsMasked();
}
inline fn requireInterruptsMasked() Error!void {
    if (comptime builtin.target.os.tag == .freestanding) {
        if (@import("../../arch/x86.zig").interruptsEnabled()) return error.InterruptsEnabled;
    }
}
inline fn sameTicket(a: ownership.Ticket, b: ownership.Ticket) bool {
    return a.issuer == b.issuer and a.cpu == b.cpu and a.epoch == b.epoch;
}
inline fn pack(sequence: u64, phase: Phase, completion: Completion) u64 {
    return (sequence << SEQUENCE_SHIFT) | @backingInt(phase) | (if (completion == .unstarted) UNSTARTED else @as(u64, 0));
}
inline fn withPhase(control: u64, phase: Phase) u64 {
    return (control & ~PHASE_MASK) | @backingInt(phase);
}
inline fn phaseOf(control: u64) Phase {
    return @fromBackingInt(@intCast(control & PHASE_MASK));
}
inline fn sequenceOf(control: u64) u64 {
    return control >> SEQUENCE_SHIFT;
}
inline fn completionOf(control: u64) Completion {
    return if (control & UNSTARTED == 0) .owner_returned else .unstarted;
}
inline fn requireKey(control: u64, key: Key) Error!void {
    if (phaseOf(control) == .idle or sequenceOf(control) != key.sequence) return error.StaleKey;
}

fn testCollection(pool: *Pool, ticket: ownership.Ticket) Error!?Key {
    if (comptime !builtin.is_test) @compileError("collection convenience is host-test-only");
    var key: Key = undefined;
    return if (try pool.beginCollectionInto(ticket, &key)) key else null;
}

fn testCommand(coordinator: *ownership.Coordinator, cpu: u8, serial: u64) !Command {
    const ticket = try coordinator.prepare(cpu, .{
        .task_handle = serial,
        .task_id = serial,
        .process_generation = 1,
        .address_space_id = serial,
    });
    try coordinator.bindPrepared(ticket, serial, serial * 4096);
    return .{ .ticket = ticket, .trap_stack_top = 0x100000 + @as(usize, cpu) * 0x10000 };
}

test "dispatch transport geometry isolates every static channel without growing Coordinator" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(Command));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(Key));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(ClaimedCommand));
    try std.testing.expectEqual(@as(usize, 1024), @sizeOf(Pool));
    try std.testing.expectEqual(@as(usize, 64), @alignOf(Pool));
    try std.testing.expectEqual(@as(usize, 3080), @sizeOf(ownership.Coordinator));
    var pool: Pool = .{};
    for (&pool.channels, 0..) |*channel, cpu| {
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(channel) % 64);
        try std.testing.expectEqual(@intFromPtr(&pool) + cpu * 64, @intFromPtr(channel));
    }
}

test "dispatch transport all sixteen owners retain exact shells through exclusive collection" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var other: ownership.Coordinator = .{};
    var pool: Pool = .{};
    var commands: [CAPACITY]Command = undefined;
    var keys: [CAPACITY]Key = undefined;
    for (0..CAPACITY) |cpu| {
        commands[cpu] = try testCommand(&coordinator, @intCast(cpu), cpu + 1);
        try pool.publishInto(commands[cpu], &keys[cpu]);
    }
    try std.testing.expect(pool.hasOutstandingForIssuer(&coordinator));
    try std.testing.expect(!pool.hasOutstandingForIssuer(&other));
    for (0..CAPACITY) |cpu| {
        cpu_identity.setIndexForTest(0);
        try std.testing.expectError(error.Busy, testCollection(&pool, commands[cpu].ticket));
        cpu_identity.setIndexForTest(@intCast(cpu));
        var claimed: ClaimedCommand = undefined;
        try pool.claimInto(@intCast(cpu), &claimed);
        try std.testing.expect(std.meta.eql(commands[cpu], claimed.command));
        try std.testing.expect(std.meta.eql(keys[cpu], claimed.key));
        var bound: ownership.BoundIdentity = undefined;
        try coordinator.startPreparedInto(commands[cpu].ticket, &bound);
        try coordinator.ackPreparedReturn(commands[cpu].ticket, .{ .outcome = .yielded, .ui_revision = cpu + 42 });
        cpu_identity.setIndexForTest(0);
        try std.testing.expectError(error.Busy, testCollection(&pool, commands[cpu].ticket));
        cpu_identity.setIndexForTest(@intCast(cpu));
        try pool.complete(claimed.key, .owner_returned);
        try std.testing.expectError(error.WrongPhase, pool.complete(claimed.key, .owner_returned));
        cpu_identity.setIndexForTest(0);
        var completion: Completion = .unstarted;
        try pool.completionInto(keys[cpu], &completion);
        try std.testing.expectEqual(Completion.owner_returned, completion);
        const guard = (try testCollection(&pool, commands[cpu].ticket)).?;
        try std.testing.expectError(error.Busy, testCollection(&pool, commands[cpu].ticket));
        try std.testing.expect(pool.hasOutstandingForIssuer(&coordinator));
        var returned: ownership.ReturnRecord = undefined;
        try coordinator.consumePreparedReturnInto(commands[cpu].ticket, &returned);
        try std.testing.expectEqual(@as(u64, cpu + 42), returned.ui_revision);
        _ = try coordinator.beginCollect(commands[cpu].ticket);
        try coordinator.finishCollect(commands[cpu].ticket);
        try pool.finishCollection(guard);
        try std.testing.expectError(error.StaleKey, pool.finishCollection(guard));
    }
    try std.testing.expect(!pool.hasOutstandingForIssuer(&coordinator));
    try std.testing.expect(!coordinator.hasLeases());
}

test "dispatch transport admission rejects stale foreign stopped and ownership-only tickets unchanged" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var other: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    const foreign = try testCommand(&other, 1, 2);
    const canary: Key = .{ .pool = &pool, .cpu = 15, .sequence = 999 };
    var out = canary;
    var wrong = command;
    wrong.ticket.epoch += 1;
    try std.testing.expectError(error.StaleTicket, pool.publishInto(wrong, &out));
    wrong = command;
    wrong.trap_stack_top += 1;
    try std.testing.expectError(error.InvalidCommand, pool.publishInto(wrong, &out));
    cpu_identity.setIndexForTest(1);
    try std.testing.expectError(error.WrongCpu, pool.publishInto(command, &out));
    try std.testing.expect(pool.hasOutstandingForIssuer(&coordinator));
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(!(try coordinator.requestStop(command.ticket)));
    try std.testing.expectError(error.StopRequested, pool.publishInto(command, &out));
    const owned = try coordinator.prepare(2, .{ .task_handle = 3, .task_id = 3, .process_generation = 1, .address_space_id = 3 });
    try coordinator.bindOwnedRoot(owned, 3, 3 * 4096);
    try std.testing.expectError(error.WrongPurpose, pool.publishInto(.{ .ticket = owned, .trap_stack_top = 0x100000 }, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    try std.testing.expect(!pool.hasOutstandingForIssuer(&coordinator));
    try pool.publishInto(foreign, &out);
    const key = out;
    out = canary;
    try std.testing.expectError(error.Busy, pool.publishInto(foreign, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    try pool.withdraw(key);
    const guard = (try testCollection(&pool, foreign.ticket)).?;
    try pool.finishCollection(guard);
}

test "dispatch transport pending withdrawal excludes owner and preserves once-only unstarted completion" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    var key: Key = undefined;
    try pool.publishInto(command, &key);
    var completion: Completion = .owner_returned;
    try std.testing.expectError(error.WrongPhase, pool.completionInto(key, &completion));
    try std.testing.expectEqual(Completion.owner_returned, completion);
    try pool.withdraw(key);
    try std.testing.expectError(error.WrongPhase, pool.withdraw(key));
    cpu_identity.setIndexForTest(1);
    const canary: ClaimedCommand = .{ .key = key, .command = .{ .ticket = command.ticket, .trap_stack_top = 0xdeadbeef } };
    var claimed = canary;
    try std.testing.expectError(error.NoCommand, pool.claimKeyInto(key, &claimed));
    try std.testing.expect(std.meta.eql(canary, claimed));
    cpu_identity.setIndexForTest(0);
    try pool.completionInto(key, &completion);
    try std.testing.expectEqual(Completion.unstarted, completion);
    try coordinator.cancelUnstarted(command.ticket);
    const guard = (try testCollection(&pool, command.ticket)).?;
    try pool.abortCollection(guard);
    try pool.completionInto(key, &completion);
    try std.testing.expectEqual(Completion.unstarted, completion);
    var returned: ownership.ReturnRecord = undefined;
    try coordinator.consumePreparedReturnInto(command.ticket, &returned);
    try std.testing.expectEqualDeep(ownership.ReturnRecord{}, returned);
    _ = try coordinator.beginCollect(command.ticket);
    try coordinator.finishCollect(command.ticket);
    try pool.finishCollection((try testCollection(&pool, command.ticket)).?);
}

test "dispatch transport exact ticket guard admits synchronous leases but holds queued canceled shells" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var foreign: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    const unrelated = try testCommand(&foreign, 1, 2);
    try std.testing.expectEqual(@as(?Key, null), try testCollection(&pool, command.ticket));
    var key: Key = undefined;
    try pool.publishInto(command, &key);
    try std.testing.expectEqual(@as(?Key, null), try testCollection(&pool, unrelated.ticket));
    var wrong_epoch = command.ticket;
    wrong_epoch.epoch += 1;
    try std.testing.expectEqual(@as(?Key, null), try testCollection(&pool, wrong_epoch));
    cpu_identity.setIndexForTest(1);
    var claimed: ClaimedCommand = undefined;
    try pool.claimInto(1, &claimed);
    cpu_identity.setIndexForTest(0);
    try coordinator.cancelUnstarted(command.ticket);
    var returned: ownership.ReturnRecord = undefined;
    try coordinator.consumePreparedReturnInto(command.ticket, &returned);
    try std.testing.expectError(error.Busy, testCollection(&pool, command.ticket));
    cpu_identity.setIndexForTest(1);
    var bound: ownership.BoundIdentity = undefined;
    try std.testing.expectError(error.WrongPhase, coordinator.startPreparedInto(claimed.command.ticket, &bound));
    try pool.complete(claimed.key, .unstarted);
    cpu_identity.setIndexForTest(0);
    const guard = (try testCollection(&pool, command.ticket)).?;
    _ = try coordinator.beginCollect(command.ticket);
    try coordinator.finishCollect(command.ticket);
    try pool.finishCollection(guard);
}

test "dispatch transport stale sequence pool and CPU keys cannot claim complete or collect replacements" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var pool: Pool = .{};
    var other_pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    var first: Key = undefined;
    try pool.publishInto(command, &first);
    try pool.withdraw(first);
    try pool.finishCollection((try testCollection(&pool, command.ticket)).?);
    var replacement: Key = undefined;
    try pool.publishInto(command, &replacement);
    try std.testing.expect(replacement.sequence > first.sequence);
    cpu_identity.setIndexForTest(1);
    const canary: ClaimedCommand = .{ .key = replacement, .command = command };
    var out = canary;
    try std.testing.expectError(error.StaleKey, pool.claimKeyInto(first, &out));
    try std.testing.expectError(error.WrongCoordinator, other_pool.claimKeyInto(replacement, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    try pool.claimKeyInto(replacement, &out);
    try std.testing.expectError(error.StaleKey, pool.complete(first, .owner_returned));
    try std.testing.expectError(error.WrongCoordinator, other_pool.complete(replacement, .owner_returned));
    cpu_identity.setIndexForTest(2);
    try std.testing.expectError(error.WrongCpu, pool.complete(replacement, .owner_returned));
    try std.testing.expectError(error.WrongCpu, pool.withdraw(replacement));
    cpu_identity.setIndexForTest(1);
    try pool.complete(replacement, .owner_returned);
    cpu_identity.setIndexForTest(0);
    try std.testing.expectError(error.StaleKey, pool.withdraw(first));
    try std.testing.expectError(error.StaleKey, pool.finishCollection(first));
    try std.testing.expectError(error.WrongPhase, pool.finishCollection(replacement));
    const guard = (try testCollection(&pool, command.ticket)).?;
    try std.testing.expectError(error.StaleKey, pool.abortCollection(first));
    try std.testing.expectError(error.WrongCoordinator, other_pool.finishCollection(guard));
    try pool.finishCollection(guard);
}

test "dispatch transport completion after ACK never reads poisoned ticket or trap payload" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    var key: Key = undefined;
    try pool.publishInto(command, &key);
    cpu_identity.setIndexForTest(1);
    var claimed: ClaimedCommand = undefined;
    try pool.claimKeyInto(key, &claimed);
    var bound: ownership.BoundIdentity = undefined;
    try coordinator.startPreparedInto(claimed.command.ticket, &bound);
    try coordinator.ackPreparedReturn(claimed.command.ticket, .{ .outcome = .yielded });
    // Deliberately destroy every payload byte: the captured scalar key and
    // independent atomic control are the complete post-ACK completion authority.
    pool.channels[1].ticket = undefined;
    pool.channels[1].trap_stack_top = 0;
    try pool.complete(claimed.key, .owner_returned);
    cpu_identity.setIndexForTest(0);
    var completion: Completion = .unstarted;
    try pool.completionInto(key, &completion);
    try std.testing.expectEqual(Completion.owner_returned, completion);
    // Restore the BSP-owned authentication payload only for fixture collection.
    pool.channels[1].ticket = command.ticket;
    try pool.finishCollection((try testCollection(&pool, command.ticket)).?);
}

test "dispatch transport publishing fails closed and sequence exhaustion never wraps" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var other: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    pool.channels[1].control = pack(7, .publishing, .owner_returned);
    pool.channels[1].ticket = undefined;
    try std.testing.expectError(error.Busy, testCollection(&pool, command.ticket));
    try std.testing.expect(pool.hasOutstandingForIssuer(&coordinator));
    try std.testing.expect(pool.hasOutstandingForIssuer(&other));
    pool.channels[1].control = pack(MAX_SEQUENCE - 1, .idle, .owner_returned);
    var last: Key = undefined;
    try pool.publishInto(command, &last);
    try std.testing.expectEqual(MAX_SEQUENCE, last.sequence);
    try pool.withdraw(last);
    try pool.finishCollection((try testCollection(&pool, command.ticket)).?);
    const exhausted_control = pool.channels[1].control;
    var out = last;
    try std.testing.expectError(error.SequenceExhausted, pool.publishInto(command, &out));
    try std.testing.expect(std.meta.eql(last, out));
    try std.testing.expectEqual(exhausted_control, pool.channels[1].control);
    try std.testing.expect(std.meta.eql(command.ticket, pool.channels[1].ticket));
    try std.testing.expectEqual(command.trap_stack_top, pool.channels[1].trap_stack_top);
    try std.testing.expect(!pool.hasOutstandingForIssuer(&coordinator));
}

test "dispatch transport owner claim races BSP withdrawal with one immutable winner" {
    const Race = struct {
        pool: *Pool,
        key: Key,
        command: Command,
        claimed: bool = false,
        valid: bool = false,

        fn run(self: *@This()) void {
            cpu_identity.setIndexForTest(1);
            const canary: ClaimedCommand = .{ .key = self.key, .command = .{ .ticket = self.command.ticket, .trap_stack_top = 0x12345678 } };
            var out = canary;
            self.pool.claimKeyInto(self.key, &out) catch |err| {
                self.valid = err == error.NoCommand and std.meta.eql(out, canary);
                return;
            };
            self.claimed = true;
            self.valid = std.meta.eql(out.command, self.command) and std.meta.eql(out.key, self.key);
            self.pool.complete(out.key, .unstarted) catch {
                self.valid = false;
            };
        }
    };
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    for (0..128) |_| {
        var key: Key = undefined;
        try pool.publishInto(command, &key);
        var race: Race = .{ .pool = &pool, .key = key, .command = command };
        const thread = try std.Thread.spawn(.{}, Race.run, .{&race});
        const withdrawn = if (pool.withdraw(key)) |_| true else |err| blk: {
            try std.testing.expectEqual(error.WrongPhase, err);
            break :blk false;
        };
        thread.join();
        try std.testing.expect(race.valid);
        try std.testing.expect(withdrawn != race.claimed);
        var completion: Completion = .owner_returned;
        try pool.completionInto(key, &completion);
        try std.testing.expectEqual(Completion.unstarted, completion);
        try pool.finishCollection((try testCollection(&pool, command.ticket)).?);
    }
}

test "dispatch transport STOP distinguishes unstarted rejection from an acknowledged unavailable return" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var pool: Pool = .{};
    for ([_]bool{ false, true }, 0..) |started, position| {
        const command = try testCommand(&coordinator, 1, position + 1);
        var key: Key = undefined;
        try pool.publishInto(command, &key);
        cpu_identity.setIndexForTest(1);
        var claimed: ClaimedCommand = undefined;
        try pool.claimInto(1, &claimed);
        var bound: ownership.BoundIdentity = undefined;
        if (started) try coordinator.startPreparedInto(claimed.command.ticket, &bound);
        cpu_identity.setIndexForTest(0);
        try std.testing.expectEqual(started, try coordinator.requestStop(command.ticket));
        try std.testing.expectError(error.Busy, testCollection(&pool, command.ticket));
        cpu_identity.setIndexForTest(1);
        if (started) {
            try coordinator.ackPreparedReturn(claimed.command.ticket, .{});
            try pool.complete(claimed.key, .owner_returned);
        } else {
            try std.testing.expectError(error.StopRequested, coordinator.startPreparedInto(claimed.command.ticket, &bound));
            try pool.complete(claimed.key, .unstarted);
        }
        cpu_identity.setIndexForTest(0);
        var completion: Completion = undefined;
        try pool.completionInto(key, &completion);
        try std.testing.expectEqual(if (started) Completion.owner_returned else Completion.unstarted, completion);
        if (!started) try coordinator.cancelUnstarted(command.ticket);
        var returned: ownership.ReturnRecord = undefined;
        try coordinator.consumePreparedReturnInto(command.ticket, &returned);
        try std.testing.expectEqualDeep(ownership.ReturnRecord{}, returned);
        const guard = (try testCollection(&pool, command.ticket)).?;
        _ = try coordinator.beginCollect(command.ticket);
        try coordinator.finishCollect(command.ticket);
        try pool.finishCollection(guard);
    }
}

test "dispatch transport complete lease reuse rejects old keys without holding a different epoch" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const old = try testCommand(&coordinator, 1, 1);
    var old_key: Key = undefined;
    try pool.publishInto(old, &old_key);
    try pool.withdraw(old_key);
    try coordinator.cancelUnstarted(old.ticket);
    var returned: ownership.ReturnRecord = undefined;
    try coordinator.consumePreparedReturnInto(old.ticket, &returned);
    const old_guard = (try testCollection(&pool, old.ticket)).?;
    _ = try coordinator.beginCollect(old.ticket);
    try coordinator.finishCollect(old.ticket);
    try pool.finishCollection(old_guard);
    const replacement = try testCommand(&coordinator, 1, 2);
    var replacement_key: Key = undefined;
    try pool.publishInto(replacement, &replacement_key);
    try std.testing.expect(replacement.ticket.epoch > old.ticket.epoch);
    try std.testing.expect(replacement_key.sequence > old_key.sequence);
    try std.testing.expectEqual(@as(?Key, null), try testCollection(&pool, old.ticket));
    try std.testing.expectError(error.StaleKey, pool.finishCollection(old_guard));
    try std.testing.expect(pool.hasOutstandingForIssuer(&coordinator));
    cpu_identity.setIndexForTest(1);
    const canary: ClaimedCommand = .{ .key = old_key, .command = old };
    var claimed = canary;
    try std.testing.expectError(error.StaleKey, pool.claimKeyInto(old_key, &claimed));
    try std.testing.expect(std.meta.eql(canary, claimed));
    try pool.claimKeyInto(replacement_key, &claimed);
    var bound: ownership.BoundIdentity = undefined;
    try coordinator.startPreparedInto(claimed.command.ticket, &bound);
    try std.testing.expectEqual(@as(u64, 2), bound.identity.task_id);
    try coordinator.ackPreparedReturn(claimed.command.ticket, .{ .outcome = .yielded });
    try pool.complete(claimed.key, .owner_returned);
    cpu_identity.setIndexForTest(0);
    try coordinator.consumePreparedReturnInto(replacement.ticket, &returned);
    const guard = (try testCollection(&pool, replacement.ticket)).?;
    _ = try coordinator.beginCollect(replacement.ticket);
    try coordinator.finishCollect(replacement.ticket);
    try pool.finishCollection(guard);
    try std.testing.expect(!pool.hasOutstandingForIssuer(&coordinator));
}

test "dispatch transport collection Into preserves output until exact successful acquisition" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var foreign: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    const unrelated = try testCommand(&foreign, 1, 2);
    const canary: Key = .{ .pool = &pool, .cpu = 15, .sequence = 0x123456 };
    var out = canary;
    try std.testing.expect(!try pool.beginCollectionInto(command.ticket, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    var key: Key = undefined;
    try pool.publishInto(command, &key);
    try std.testing.expect(!try pool.beginCollectionInto(unrelated.ticket, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    var stale = command.ticket;
    stale.epoch += 1;
    try std.testing.expect(!try pool.beginCollectionInto(stale, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    try std.testing.expectError(error.Busy, pool.beginCollectionInto(command.ticket, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    var malformed = command.ticket;
    malformed.cpu = CAPACITY;
    try std.testing.expectError(error.InvalidCpu, pool.beginCollectionInto(malformed, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    cpu_identity.setIndexForTest(1);
    try std.testing.expectError(error.WrongCpu, pool.beginCollectionInto(command.ticket, &out));
    try std.testing.expect(std.meta.eql(canary, out));
    cpu_identity.setIndexForTest(0);
    try pool.withdraw(key);
    try std.testing.expect(try pool.beginCollectionInto(command.ticket, &out));
    try std.testing.expect(std.meta.eql(key, out));
    try pool.abortCollection(out);
    out = canary;
    try std.testing.expect(try pool.beginCollectionInto(command.ticket, &out));
    try std.testing.expect(std.meta.eql(key, out));
    try coordinator.cancelUnstarted(command.ticket);
    var returned: ownership.ReturnRecord = undefined;
    try coordinator.consumePreparedReturnInto(command.ticket, &returned);
    _ = try coordinator.beginCollect(command.ticket);
    try coordinator.finishCollect(command.ticket);
    try pool.finishCollection(out);
    out = canary;
    try std.testing.expect(!try pool.beginCollectionInto(command.ticket, &out));
    try std.testing.expect(std.meta.eql(canary, out));
}

test "dispatch transport prompts coalesce independently on all sixteen owners" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    var pool: Pool = .{};
    // These deliberately unusable issuer pointers make any attempted authority
    // read fail; prompt recording/consumption needs only permanent local bytes.
    for (&pool.channels, 0..) |*channel, cpu| {
        channel.ticket = .{ .issuer = @ptrFromInt(0x1000), .cpu = @intCast(cpu), .epoch = cpu + 17 };
        channel.trap_stack_top = 0x100000 + cpu * 0x10000;
        channel.control = pack(cpu + 9, .claimed, .unstarted);
        channel.padding = @splat(@intCast(cpu + 0x40));
    }
    for (0..CAPACITY) |cpu| {
        cpu_identity.setIndexForTest(@intCast(cpu));
        const before = pool;
        try pool.notePrompt();
        try pool.notePrompt();
        try pool.notePrompt();
        var expected = before;
        expected.channels[cpu].prompt = 1;
        try std.testing.expect(std.meta.eql(expected, pool));
        try std.testing.expect(try pool.takePrompt(@intCast(cpu)));
        try std.testing.expect(std.meta.eql(before, pool));
        try std.testing.expect(!try pool.takePrompt(@intCast(cpu)));
        try std.testing.expect(std.meta.eql(before, pool));
    }
}

test "dispatch transport foreign and invalid prompt takes preserve every channel" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    var coordinator: ownership.Coordinator = .{};
    var pool: Pool = .{};
    for (&pool.channels, 0..) |*channel, cpu| {
        channel.ticket = .{ .issuer = &coordinator, .cpu = @intCast(cpu), .epoch = cpu + 1 };
        channel.trap_stack_top = 0x200000 + cpu * 0x10000;
        channel.control = pack(cpu + 1, .completed, .owner_returned);
        channel.prompt = 1;
    }
    const before = pool;
    for (0..CAPACITY) |cpu| {
        cpu_identity.setIndexForTest(@intCast(cpu));
        for (0..CAPACITY) |foreign| {
            if (foreign == cpu) continue;
            try std.testing.expectError(error.WrongCpu, pool.takePrompt(@intCast(foreign)));
            try std.testing.expect(std.meta.eql(before, pool));
        }
        for ([_]u8{ CAPACITY, 255 }) |invalid| {
            try std.testing.expectError(error.InvalidCpu, pool.takePrompt(invalid));
            try std.testing.expect(std.meta.eql(before, pool));
        }
    }
}

test "dispatch transport idle hints survive publication collection and replacement without owning a lease" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: ownership.Coordinator = .{};
    var pool: Pool = .{};
    const command = try testCommand(&coordinator, 1, 1);
    cpu_identity.setIndexForTest(1);
    try pool.notePrompt();
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(!pool.hasOutstandingForIssuer(&coordinator));
    var guard: Key = undefined;
    try std.testing.expect(!try pool.beginCollectionInto(command.ticket, &guard));
    try std.testing.expectEqual(@as(u8, 1), pool.channels[1].prompt);
    var key: Key = undefined;
    try pool.publishInto(command, &key);
    try pool.withdraw(key);
    try coordinator.cancelUnstarted(command.ticket);
    var returned: ownership.ReturnRecord = undefined;
    try coordinator.consumePreparedReturnInto(command.ticket, &returned);
    try std.testing.expect(try pool.beginCollectionInto(command.ticket, &guard));
    try pool.abortCollection(guard);
    try std.testing.expectEqual(@as(u8, 1), pool.channels[1].prompt);
    try std.testing.expect(try pool.beginCollectionInto(command.ticket, &guard));
    _ = try coordinator.beginCollect(command.ticket);
    try coordinator.finishCollect(command.ticket);
    try pool.finishCollection(guard);
    try std.testing.expect(!coordinator.hasLeases());
    try std.testing.expect(!pool.hasOutstandingForIssuer(&coordinator));
    try std.testing.expectEqual(@as(u8, 1), pool.channels[1].prompt);

    // An old hint can inspect a new authenticated command. It supplies no key,
    // lease identity or permission to bypass the replacement's normal claim.
    const replacement = try testCommand(&coordinator, 1, 2);
    try pool.publishInto(replacement, &key);
    cpu_identity.setIndexForTest(1);
    try std.testing.expect(try pool.takePrompt(1));
    try std.testing.expect(!try pool.takePrompt(1));
    var claimed: ClaimedCommand = undefined;
    try pool.claimInto(1, &claimed);
    try std.testing.expect(std.meta.eql(replacement, claimed.command));
    var bound: ownership.BoundIdentity = undefined;
    try coordinator.startPreparedInto(claimed.command.ticket, &bound);
    try coordinator.ackPreparedReturn(claimed.command.ticket, .{ .outcome = .yielded });
    try pool.complete(claimed.key, .owner_returned);
    cpu_identity.setIndexForTest(0);
    try coordinator.consumePreparedReturnInto(replacement.ticket, &returned);
    try std.testing.expect(try pool.beginCollectionInto(replacement.ticket, &guard));
    _ = try coordinator.beginCollect(replacement.ticket);
    try coordinator.finishCollect(replacement.ticket);
    try pool.finishCollection(guard);
    cpu_identity.setIndexForTest(1);
    try pool.notePrompt();
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(!coordinator.hasLeases());
    try std.testing.expect(!pool.hasOutstandingForIssuer(&coordinator));
    cpu_identity.setIndexForTest(1);
    try std.testing.expect(try pool.takePrompt(1));
    try std.testing.expect(!try pool.takePrompt(1));
}
