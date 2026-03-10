const process = @import("../process.zig");
const scheduler = @import("../scheduler.zig");
const timer = @import("../../timer/timer.zig");
const sync = @import("../../utils/sync.zig");

const MAX_WAITERS = 256;

const Waiter = struct {
    proc: ?*process.Process = null,
    generation: u64 = 0,
    armed: bool = false,
    woken: bool = false,
};

var waiters: [MAX_WAITERS]Waiter = [_]Waiter{.{}} ** MAX_WAITERS;
var wait_lock = sync.SpinLock.init();
var event_generation: u64 = 1;

pub fn snapshot() u64 {
    wait_lock.acquire();
    defer wait_lock.release();
    return event_generation;
}

pub fn notifyAll() void {
    var ready: [MAX_WAITERS]*process.Process = undefined;
    var ready_count: usize = 0;

    wait_lock.acquire();
    event_generation +%= 1;
    if (event_generation == 0) {
        event_generation = 1;
    }

    for (&waiters) |*waiter| {
        if (!waiter.armed) continue;
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

pub fn waitForChange(observed_generation: u64, deadline_tick: ?u64) bool {
    if (!hasRemainingTime(deadline_tick)) {
        return false;
    }

    const current = process.getEffectiveCurrent() orelse return fallbackWait(deadline_tick);

    wait_lock.acquire();
    if (event_generation != observed_generation) {
        wait_lock.release();
        return true;
    }

    const waiter = reserveWaiter(current, observed_generation) orelse {
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
    const changed = waiter.woken or event_generation != observed_generation;
    waiter.* = .{};
    wait_lock.release();
    return changed;
}

fn reserveWaiter(current: *process.Process, observed_generation: u64) ?*Waiter {
    for (&waiters) |*waiter| {
        if (waiter.proc == null) {
            waiter.* = .{
                .proc = current,
                .generation = observed_generation,
                .armed = true,
                .woken = false,
            };
            return waiter;
        }
    }
    return null;
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
