const std = @import("std");
const x86 = @import("../../../arch/x86.zig");
const timer = @import("../../timer/timer.zig");
const abi = @import("abi.zig");
const process_mod = @import("../process.zig");
const signal = @import("../signal.zig");
const protection = @import("../../memory/protection.zig");
const readiness = @import("readiness.zig");

pub const TimeSpec = extern struct {
    tv_sec: i32,
    tv_nsec: i32,
};

pub const ItimerSpec = extern struct {
    it_interval_sec: u32,
    it_interval_nsec: u32,
    it_value_sec: u32,
    it_value_nsec: u32,
};

const Itimerval = process_mod.Itimer;

const Tms = extern struct {
    tms_utime: u32,
    tms_stime: u32,
    tms_cutime: u32,
    tms_cstime: u32,
};

const Rusage = extern struct {
    ru_utime_sec: u32,
    ru_utime_usec: u32,
    ru_stime_sec: u32,
    ru_stime_usec: u32,
    ru_maxrss: u32,
    ru_ixrss: u32,
    ru_idrss: u32,
    ru_isrss: u32,
    ru_minflt: u32,
    ru_majflt: u32,
    ru_nswap: u32,
    ru_inblock: u32,
    ru_oublock: u32,
    ru_msgsnd: u32,
    ru_msgrcv: u32,
    ru_nsignals: u32,
    ru_nvcsw: u32,
    ru_nivcsw: u32,
};

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

const TIMERFD_BASE: i32 = abi.FD_OFFSET + 300;
const TIMERFD_LIMIT: i32 = TIMERFD_BASE + 64;

const TimerFd = struct {
    clockid: u32,
    flags: u32,
    spec: ItimerSpec,
    next_expiration_tick: u64,
    interval_ticks: u64,
    armed: bool,
    in_use: bool,
};

const PosixTimer = struct {
    clock_id: u32,
    interval: ItimerSpec,
    in_use: bool,
};

var timerfd_table: [64]TimerFd = [_]TimerFd{.{
    .clockid = 0,
    .flags = 0,
    .spec = .{ .it_interval_sec = 0, .it_interval_nsec = 0, .it_value_sec = 0, .it_value_nsec = 0 },
    .next_expiration_tick = 0,
    .interval_ticks = 0,
    .armed = false,
    .in_use = false,
}} ** 64;

var posix_timers: [32]PosixTimer = [_]PosixTimer{.{
    .clock_id = 0,
    .interval = .{
        .it_interval_sec = 0,
        .it_interval_nsec = 0,
        .it_value_sec = 0,
        .it_value_nsec = 0,
    },
    .in_use = false,
}} ** 32;

pub fn sys_nanosleep(req_addr: usize, rem_addr: usize) i32 {
    if (!protection.verifyUserPointer(req_addr, @sizeOf(TimeSpec))) return abi.EINVAL;

    var req: TimeSpec = undefined;
    protection.copyFromUser(std.mem.asBytes(&req), req_addr) catch return abi.EINVAL;

    if (req.tv_sec < 0 or req.tv_nsec < 0 or req.tv_nsec >= 1_000_000_000) return abi.EINVAL;

    const total_ms: u64 = @as(u64, @intCast(req.tv_sec)) * 1000 + @as(u64, @intCast(req.tv_nsec)) / 1_000_000;
    const ticks_to_wait = total_ms / 10;

    const start = process_mod.getSystemTime();
    while (process_mod.getSystemTime() - start < ticks_to_wait) {
        signal.handlePendingSignals();
        process_mod.yield();
    }

    if (rem_addr != 0 and protection.verifyUserPointer(rem_addr, @sizeOf(TimeSpec))) {
        var zero = TimeSpec{ .tv_sec = 0, .tv_nsec = 0 };
        protection.copyToUser(rem_addr, std.mem.asBytes(&zero)) catch {};
    }

    return 0;
}

pub fn sys_clock_gettime(clock_id: i32, tp_addr: usize) i32 {
    if (!protection.verifyUserPointer(tp_addr, @sizeOf(TimeSpec))) return abi.EINVAL;

    switch (clock_id) {
        CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID => {},
        else => return abi.EINVAL,
    }

    const ticks = process_mod.getSystemTime();
    const total_ms = ticks * 10;

    const tp = TimeSpec{
        .tv_sec = @intCast(total_ms / 1000),
        .tv_nsec = @intCast((total_ms % 1000) * 1_000_000),
    };

    protection.copyToUser(tp_addr, std.mem.asBytes(&tp)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_getitimer(which: u32, value_addr: usize) i32 {
    if (which > abi.ITIMER_PROF) return abi.EINVAL;
    if (!protection.verifyUserPointer(value_addr, @sizeOf(Itimerval))) return abi.EINVAL;

    const proc = process_mod.getEffectiveCurrent() orelse return abi.ESRCH;
    const which_idx: usize = @intCast(which);
    const timer_value = proc.itimers[which_idx];

    protection.copyToUser(value_addr, std.mem.asBytes(&timer_value)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_setitimer(which: u32, new_value_addr: usize, old_value_addr: usize) i32 {
    if (which > abi.ITIMER_PROF) return abi.EINVAL;
    if (!protection.verifyUserPointer(new_value_addr, @sizeOf(Itimerval))) return abi.EINVAL;
    if (old_value_addr != 0 and !protection.verifyUserPointer(old_value_addr, @sizeOf(Itimerval))) return abi.EINVAL;

    const proc = process_mod.getEffectiveCurrent() orelse return abi.ESRCH;
    const which_idx: usize = @intCast(which);

    if (old_value_addr != 0) {
        const old_timer = proc.itimers[which_idx];
        protection.copyToUser(old_value_addr, std.mem.asBytes(&old_timer)) catch return abi.EINVAL;
    }

    var new_timer: Itimerval = undefined;
    protection.copyFromUser(std.mem.asBytes(&new_timer), new_value_addr) catch return abi.EINVAL;
    proc.itimers[which_idx] = new_timer;
    return 0;
}

pub fn isTimerFd(fd: i32) bool {
    return fd >= TIMERFD_BASE and fd < TIMERFD_LIMIT;
}

pub fn closeTimerFd(fd: i32) i32 {
    const idx = timerFdIndex(fd) orelse return abi.EBADF;
    var tfd = &timerfd_table[idx];
    if (!tfd.in_use) return abi.EBADF;
    tfd.in_use = false;
    tfd.armed = false;
    readiness.notifyAll();
    return 0;
}

pub fn pollTimerFd(fd: i32, requested_events: u16) ?error{BadFd}!u16 {
    const idx = timerFdIndex(fd) orelse return error.BadFd;
    const tfd = &timerfd_table[idx];
    if (!tfd.in_use) return error.BadFd;

    var ready: u16 = 0;
    if ((requested_events & 0x001) != 0 and timerFdExpirations(tfd) != 0) {
        ready |= 0x001;
    }
    return ready;
}

pub fn readTimerFd(fd: i32, buffer: []u8) ?i32 {
    const idx = timerFdIndex(fd) orelse return abi.EBADF;
    const tfd = &timerfd_table[idx];
    if (!tfd.in_use) return abi.EBADF;
    if (buffer.len < @sizeOf(u64)) return abi.EINVAL;

    var expirations = consumeTimerFdExpirations(tfd);
    if (expirations == 0) return abi.EAGAIN;

    @memcpy(buffer[0..@sizeOf(u64)], std.mem.asBytes(&expirations));
    readiness.notifyAll();
    return @sizeOf(u64);
}

pub fn nextTimerFdDeadline(fd: i32) ?u64 {
    const idx = timerFdIndex(fd) orelse return null;
    const tfd = &timerfd_table[idx];
    if (!tfd.in_use or !tfd.armed) return null;
    if (timerFdExpirations(tfd) != 0) return null;
    return tfd.next_expiration_tick;
}

pub fn sys_timerfd_create(clockid: u32, flags: u32) i32 {
    if (clockid != CLOCK_REALTIME and clockid != CLOCK_MONOTONIC) return abi.EINVAL;

    for (&timerfd_table, 0..) |*tfd, i| {
        if (!tfd.in_use) {
            tfd.in_use = true;
            tfd.clockid = clockid;
            tfd.flags = flags;
            tfd.spec = .{ .it_interval_sec = 0, .it_interval_nsec = 0, .it_value_sec = 0, .it_value_nsec = 0 };
            tfd.next_expiration_tick = 0;
            tfd.interval_ticks = 0;
            tfd.armed = false;
            readiness.notifyAll();
            return @as(i32, @intCast(i)) + TIMERFD_BASE;
        }
    }
    return abi.EMFILE;
}

pub fn sys_timerfd_settime(fd: i32, flags: u32, new_value_addr: usize, old_value_addr: usize) i32 {
    const idx = timerFdIndex(fd) orelse return abi.EBADF;
    const tfd = &timerfd_table[idx];
    if (!tfd.in_use) return abi.EBADF;

    if (!protection.verifyUserPointer(new_value_addr, @sizeOf(ItimerSpec))) return abi.EINVAL;

    if (old_value_addr != 0) {
        if (!protection.verifyUserPointer(old_value_addr, @sizeOf(ItimerSpec))) return abi.EINVAL;
        var current_spec = timerFdCurrentSpec(tfd);
        protection.copyToUser(old_value_addr, std.mem.asBytes(&current_spec)) catch return abi.EINVAL;
    }

    protection.copyFromUser(std.mem.asBytes(&tfd.spec), new_value_addr) catch return abi.EINVAL;
    applyTimerFdSpec(tfd, flags);
    readiness.notifyAll();
    return 0;
}

pub fn sys_timerfd_gettime(fd: i32, value_addr: usize) i32 {
    const idx = timerFdIndex(fd) orelse return abi.EBADF;
    const tfd = &timerfd_table[idx];
    if (!tfd.in_use) return abi.EBADF;

    if (!protection.verifyUserPointer(value_addr, @sizeOf(ItimerSpec))) return abi.EINVAL;
    var current_spec = timerFdCurrentSpec(tfd);
    protection.copyToUser(value_addr, std.mem.asBytes(&current_spec)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_times(buf_addr: usize) i32 {
    if (buf_addr != 0) {
        if (!protection.verifyUserPointer(buf_addr, @sizeOf(Tms))) return abi.EINVAL;
        const tms = Tms{
            .tms_utime = 0,
            .tms_stime = 0,
            .tms_cutime = 0,
            .tms_cstime = 0,
        };
        protection.copyToUser(buf_addr, std.mem.asBytes(&tms)) catch return abi.EINVAL;
    }
    return 0;
}

pub fn sys_getrusage(who: i32, usage_addr: usize) i32 {
    if (who != abi.RUSAGE_SELF and who != abi.RUSAGE_CHILDREN) return abi.EINVAL;
    if (!protection.verifyUserPointer(usage_addr, @sizeOf(Rusage))) return abi.EINVAL;

    const usage = Rusage{
        .ru_utime_sec = 0,
        .ru_utime_usec = 0,
        .ru_stime_sec = 0,
        .ru_stime_usec = 0,
        .ru_maxrss = 0,
        .ru_ixrss = 0,
        .ru_idrss = 0,
        .ru_isrss = 0,
        .ru_minflt = 0,
        .ru_majflt = 0,
        .ru_nswap = 0,
        .ru_inblock = 0,
        .ru_oublock = 0,
        .ru_msgsnd = 0,
        .ru_msgrcv = 0,
        .ru_nsignals = 0,
        .ru_nvcsw = 0,
        .ru_nivcsw = 0,
    };

    protection.copyToUser(usage_addr, std.mem.asBytes(&usage)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_clock_settime(clock_id: u32, tp: usize) i32 {
    _ = clock_id;
    if (!protection.verifyUserPointer(tp, @sizeOf(TimeSpec))) return abi.EFAULT;
    return abi.EPERM;
}

pub fn sys_clock_getres(clock_id: u32, res: usize) i32 {
    if (res == 0) return 0;
    if (!protection.verifyUserPointer(res, @sizeOf(TimeSpec))) return abi.EFAULT;

    _ = clock_id;

    const resolution = TimeSpec{
        .tv_sec = 0,
        .tv_nsec = @intCast(timer.NANOSECONDS_PER_TICK),
    };

    protection.copyToUser(res, std.mem.asBytes(&resolution)) catch return abi.EFAULT;
    return 0;
}

pub fn sys_clock_nanosleep(clock_id: u32, flags: u32, request: usize, remain: usize) i32 {
    _ = clock_id;
    _ = flags;
    _ = remain;

    if (!protection.verifyUserPointer(request, @sizeOf(TimeSpec))) return abi.EFAULT;

    var req: TimeSpec = undefined;
    protection.copyFromUser(std.mem.asBytes(&req), request) catch return abi.EFAULT;

    const ticks_to_sleep: u64 = @as(u64, @intCast(@max(0, req.tv_sec))) * timer.TICKS_PER_SECOND + @as(u64, @intCast(@max(0, req.tv_nsec))) / timer.NANOSECONDS_PER_TICK;
    const start_ticks = timer.getTicks();

    while (timer.getTicks() - start_ticks < ticks_to_sleep) {
        x86.hlt();
    }

    return 0;
}

pub fn sys_timer_create(clock_id: u32, sevp: usize, timerid: usize) i32 {
    _ = sevp;

    if (!protection.verifyUserPointer(timerid, @sizeOf(i32))) return abi.EFAULT;

    for (&posix_timers, 0..) |*timer_slot, i| {
        if (!timer_slot.in_use) {
            timer_slot.in_use = true;
            timer_slot.clock_id = clock_id;
            const id: i32 = @intCast(i);
            protection.copyToUser(timerid, std.mem.asBytes(&id)) catch return abi.EFAULT;
            return 0;
        }
    }
    return abi.EAGAIN;
}

pub fn sys_timer_delete(timerid: i32) i32 {
    if (timerid < 0 or timerid >= 32) return abi.EINVAL;
    const idx: usize = @intCast(timerid);
    if (!posix_timers[idx].in_use) return abi.EINVAL;
    posix_timers[idx].in_use = false;
    return 0;
}

pub fn sys_timer_settime(timerid: i32, flags: u32, new_value: usize, old_value: usize) i32 {
    _ = flags;

    if (timerid < 0 or timerid >= 32) return abi.EINVAL;
    const idx: usize = @intCast(timerid);
    if (!posix_timers[idx].in_use) return abi.EINVAL;

    if (!protection.verifyUserPointer(new_value, @sizeOf(ItimerSpec))) return abi.EFAULT;

    if (old_value != 0) {
        if (!protection.verifyUserPointer(old_value, @sizeOf(ItimerSpec))) return abi.EFAULT;
        protection.copyToUser(old_value, std.mem.asBytes(&posix_timers[idx].interval)) catch return abi.EFAULT;
    }

    var new_interval: ItimerSpec = undefined;
    protection.copyFromUser(std.mem.asBytes(&new_interval), new_value) catch return abi.EFAULT;
    posix_timers[idx].interval = new_interval;
    return 0;
}

pub fn sys_timer_gettime(timerid: i32, curr_value: usize) i32 {
    if (timerid < 0 or timerid >= 32) return abi.EINVAL;
    const idx: usize = @intCast(timerid);
    if (!posix_timers[idx].in_use) return abi.EINVAL;

    if (!protection.verifyUserPointer(curr_value, @sizeOf(ItimerSpec))) return abi.EFAULT;
    protection.copyToUser(curr_value, std.mem.asBytes(&posix_timers[idx].interval)) catch return abi.EFAULT;
    return 0;
}

pub fn sys_timer_getoverrun(timerid: i32) i32 {
    if (timerid < 0 or timerid >= 32) return abi.EINVAL;
    const idx: usize = @intCast(timerid);
    if (!posix_timers[idx].in_use) return abi.EINVAL;
    return 0;
}

fn timerFdIndex(fd: i32) ?usize {
    if (!isTimerFd(fd)) return null;
    return @intCast(fd - TIMERFD_BASE);
}

fn applyTimerFdSpec(tfd: *TimerFd, flags: u32) void {
    tfd.interval_ticks = durationToTicks(tfd.spec.it_interval_sec, tfd.spec.it_interval_nsec);

    const initial_ticks = durationToTicks(tfd.spec.it_value_sec, tfd.spec.it_value_nsec);
    if (initial_ticks == 0) {
        tfd.armed = false;
        tfd.next_expiration_tick = 0;
        return;
    }

    const now = timer.getTicks();
    tfd.armed = true;
    if ((flags & abi.TIMER_ABSTIME) != 0) {
        tfd.next_expiration_tick = initial_ticks;
    } else {
        tfd.next_expiration_tick = now + initial_ticks;
    }
}

fn timerFdCurrentSpec(tfd: *const TimerFd) ItimerSpec {
    var current = tfd.spec;
    if (!tfd.armed) {
        current.it_value_sec = 0;
        current.it_value_nsec = 0;
        return current;
    }

    const now = timer.getTicks();
    const remaining_ticks = if (now >= tfd.next_expiration_tick) 0 else tfd.next_expiration_tick - now;
    const remaining = ticksToSpec(remaining_ticks);
    current.it_value_sec = remaining.it_value_sec;
    current.it_value_nsec = remaining.it_value_nsec;
    return current;
}

fn timerFdExpirations(tfd: *const TimerFd) u64 {
    if (!tfd.in_use or !tfd.armed) return 0;

    const now = timer.getTicks();
    if (now < tfd.next_expiration_tick) return 0;
    if (tfd.interval_ticks == 0) return 1;
    return 1 + @divTrunc(now - tfd.next_expiration_tick, tfd.interval_ticks);
}

fn consumeTimerFdExpirations(tfd: *TimerFd) u64 {
    const expirations = timerFdExpirations(tfd);
    if (expirations == 0) return 0;

    if (tfd.interval_ticks == 0) {
        tfd.armed = false;
        tfd.next_expiration_tick = 0;
    } else {
        tfd.next_expiration_tick += expirations * tfd.interval_ticks;
    }

    return expirations;
}

fn durationToTicks(seconds: u32, nanoseconds: u32) u64 {
    const tick_nsec: u64 = 10_000_000;
    const total_nsec = @as(u64, seconds) * 1_000_000_000 + nanoseconds;
    if (total_nsec == 0) return 0;
    return @max(@as(u64, 1), @divTrunc(total_nsec + tick_nsec - 1, tick_nsec));
}

fn ticksToSpec(ticks: u64) ItimerSpec {
    const total_nsec = ticks * 10_000_000;
    return .{
        .it_interval_sec = 0,
        .it_interval_nsec = 0,
        .it_value_sec = @intCast(total_nsec / 1_000_000_000),
        .it_value_nsec = @intCast(total_nsec % 1_000_000_000),
    };
}
