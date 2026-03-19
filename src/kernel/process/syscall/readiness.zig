const process = @import("../process.zig");
const scheduler = @import("../scheduler.zig");
const timer = @import("../../timer/timer.zig");
const sync = @import("../../utils/sync.zig");

const MAX_WAITERS = 256;
const EVENT_CLASS_COUNT: usize = 3;

pub const VFS_EVENT_MASK: u32 = 1 << 0;
pub const SOCKET_EVENT_MASK: u32 = 1 << 1;
pub const PSEUDO_EVENT_MASK: u32 = 1 << 2;
pub const ALL_EVENT_MASKS: u32 = VFS_EVENT_MASK | SOCKET_EVENT_MASK | PSEUDO_EVENT_MASK;

pub const GenerationSnapshot = struct {
    generations: [EVENT_CLASS_COUNT]u64 = [_]u64{0} ** EVENT_CLASS_COUNT,
};

const Waiter = struct {
    proc: ?*process.Process = null,
    mask: u32 = 0,
    armed: bool = false,
    woken: bool = false,
};

var waiters: [MAX_WAITERS]Waiter = [_]Waiter{.{}} ** MAX_WAITERS;
var wait_lock = sync.SpinLock.init();
var event_generations: [EVENT_CLASS_COUNT]u64 = [_]u64{1} ** EVENT_CLASS_COUNT;
var next_waiter_hint: usize = 0;

pub fn init() void {
    for (&waiters) |*waiter| {
        waiter.* = .{};
    }
    wait_lock = sync.SpinLock.init();
    event_generations = [_]u64{1} ** EVENT_CLASS_COUNT;
    next_waiter_hint = 0;
}

pub fn snapshot() GenerationSnapshot {
    wait_lock.acquire();
    defer wait_lock.release();
    return .{ .generations = event_generations };
}

pub fn notify(mask: u32) void {
    if (mask == 0) return;

    var ready: [MAX_WAITERS]*process.Process = undefined;
    var ready_count: usize = 0;

    wait_lock.acquire();
    advanceGenerations(mask);

    for (&waiters) |*waiter| {
        if (!waiter.armed) continue;
        if ((waiter.mask & mask) == 0) continue;
        const proc = waiter.proc orelse continue;
        waiter.armed = false;
        waiter.woken = true;
        ready[ready_count] = proc;
        ready_count += 1;
    }
    wait_lock.release();

    for (ready[0..ready_count]) |proc| {
        scheduler.unblockProcess(proc);
    }
}

pub fn notifyVfs() void {
    notify(VFS_EVENT_MASK);
}

pub fn notifySocket() void {
    notify(SOCKET_EVENT_MASK);
}

pub fn notifyPseudo() void {
    notify(PSEUDO_EVENT_MASK);
}

pub fn notifyAll() void {
    notify(ALL_EVENT_MASKS);
}

pub fn waitForChange(observed_snapshot: GenerationSnapshot, mask: u32, deadline_tick: ?u64) bool {
    if (!hasRemainingTime(deadline_tick)) {
        return false;
    }

    const current = process.getEffectiveCurrent() orelse return fallbackWait(deadline_tick);

    wait_lock.acquire();
    if (hasGenerationChanged(observed_snapshot, mask)) {
        wait_lock.release();
        return true;
    }
    const waiter = reserveWaiter(current, mask) orelse {
        wait_lock.release();
        return fallbackWait(deadline_tick);
    };

    if (deadline_tick) |deadline| {
        if (!timer.scheduleWake(current.pid, deadline)) {
            waiter.* = .{};
            wait_lock.release();
            return fallbackWait(deadline_tick);
        }
    }

    scheduler.blockProcess(current);
    wait_lock.release();
    process.yield();

    if (deadline_tick != null) {
        timer.cancelWake(current.pid);
    }

    wait_lock.acquire();
    const changed = waiter.woken or hasGenerationChanged(observed_snapshot, mask);
    waiter.* = .{};
    wait_lock.release();
    return changed;
}

fn reserveWaiter(current: *process.Process, mask: u32) ?*Waiter {
    var attempts: usize = 0;
    var idx = next_waiter_hint;

    while (attempts < waiters.len) : (attempts += 1) {
        const waiter = &waiters[idx];
        if (waiter.proc == null) {
            waiter.* = .{
                .proc = current,
                .mask = mask,
                .armed = true,
                .woken = false,
            };
            next_waiter_hint = (idx + 1) % waiters.len;
            return waiter;
        }

        idx = (idx + 1) % waiters.len;
    }

    return null;
}

fn advanceGenerations(mask: u32) void {
    var idx: usize = 0;
    while (idx < EVENT_CLASS_COUNT) : (idx += 1) {
        const event_mask = @as(u32, 1) << @intCast(idx);
        if ((mask & event_mask) == 0) continue;

        event_generations[idx] +%= 1;
        if (event_generations[idx] == 0) {
            event_generations[idx] = 1;
        }
    }
}

fn hasGenerationChanged(observed_snapshot: GenerationSnapshot, mask: u32) bool {
    if (mask == 0) return false;

    var idx: usize = 0;
    while (idx < EVENT_CLASS_COUNT) : (idx += 1) {
        const event_mask = @as(u32, 1) << @intCast(idx);
        if ((mask & event_mask) == 0) continue;
        if (event_generations[idx] != observed_snapshot.generations[idx]) {
            return true;
        }
    }

    return false;
}

fn hasRemainingTime(deadline_tick: ?u64) bool {
    if (deadline_tick) |deadline| {
        return timer.getTicks() < deadline;
    }
    return true;
}

fn fallbackWait(deadline_tick: ?u64) bool {
    if (deadline_tick) |deadline| {
        const now = timer.getTicks();
        if (now >= deadline) {
            return false;
        }
        timer.sleepCurrentTicks(@min(@as(u64, 1), deadline - now));
        return true;
    }

    process.yield();
    return true;
}
