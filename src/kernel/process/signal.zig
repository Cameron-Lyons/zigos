const process = @import("process.zig");
const vga = @import("../drivers/vga.zig");

pub const SIGHUP = 1;
pub const SIGINT = 2;
pub const SIGQUIT = 3;
pub const SIGILL = 4;
pub const SIGTRAP = 5;
pub const SIGABRT = 6;
pub const SIGBUS = 7;
pub const SIGFPE = 8;
pub const SIGKILL = 9;
pub const SIGUSR1 = 10;
pub const SIGSEGV = 11;
pub const SIGUSR2 = 12;
pub const SIGPIPE = 13;
pub const SIGALRM = 14;
pub const SIGTERM = 15;
pub const SIGSTKFLT = 16;
pub const SIGCHLD = 17;
pub const SIGCONT = 18;
pub const SIGSTOP = 19;
pub const SIGTSTP = 20;
pub const SIGTTIN = 21;
pub const SIGTTOU = 22;
pub const SIGURG = 23;
pub const SIGXCPU = 24;
pub const SIGXFSZ = 25;
pub const SIGVTALRM = 26;
pub const SIGPROF = 27;
pub const SIGWINCH = 28;
pub const SIGIO = 29;
pub const SIGPWR = 30;
pub const SIGSYS = 31;
pub const SIGRTMIN = 32;
pub const SIGRTMAX = 64;

pub const SIG_DFL: usize = 1;
pub const SIG_IGN: usize = 2;
pub const SIG_ERR: usize = 0xFFFFFFFF;

pub const SA_NOCLDSTOP = 1 << 0;
pub const SA_NOCLDWAIT = 1 << 1;
pub const SA_SIGINFO = 1 << 2;
pub const SA_ONSTACK = 1 << 3;
pub const SA_RESTART = 1 << 4;
pub const SA_NODEFER = 1 << 5;
pub const SA_RESETHAND = 1 << 6;

pub const SignalHandler = *const fn (sig: i32) void;
pub const SigInfoHandler = *const fn (sig: i32, info: *SigInfo, context: ?*anyopaque) void;

pub const SigAction = struct {
    handler: union {
        sa_handler: SignalHandler,
        sa_sigaction: SigInfoHandler,
    },
    sa_mask: SigSet,
    sa_flags: u32,
};

pub const SigSet = struct {
    sig: [2]u32,

    pub fn empty() SigSet {
        return SigSet{ .sig = [_]u32{0} ** 2 };
    }

    pub fn fill() SigSet {
        return SigSet{ .sig = [_]u32{0xFFFFFFFF} ** 2 };
    }

    pub fn add(self: *SigSet, signum: i32) void {
        if (signum <= 0 or signum > 64) return;
        const idx: usize = @intCast(@divTrunc(signum - 1, 32));
        const bit: u5 = @intCast(@mod(signum - 1, 32));
        self.sig[idx] |= @as(u32, 1) << bit;
    }

    pub fn del(self: *SigSet, signum: i32) void {
        if (signum <= 0 or signum > 64) return;
        const idx: usize = @intCast(@divTrunc(signum - 1, 32));
        const bit: u5 = @intCast(@mod(signum - 1, 32));
        self.sig[idx] &= ~(@as(u32, 1) << bit);
    }

    pub fn ismember(self: *const SigSet, signum: i32) bool {
        if (signum <= 0 or signum > 64) return false;
        const idx: usize = @intCast(@divTrunc(signum - 1, 32));
        const bit: u5 = @intCast(@mod(signum - 1, 32));
        return (self.sig[idx] & (@as(u32, 1) << bit)) != 0;
    }
};

pub const SigInfo = struct {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    si_pid: i32,
    si_uid: u32,
    si_addr: ?*anyopaque,
    si_status: i32,
    si_value: SigVal,
};

pub const SigVal = union {
    sival_int: i32,
    sival_ptr: ?*anyopaque,
};

pub const SignalQueue = struct {
    pending: SigSet,
    queue: [32]QueuedSignal,
    head: u8,
    tail: u8,

    const QueuedSignal = struct {
        signum: i32,
        info: SigInfo,
    };

    pub fn init() SignalQueue {
        return SignalQueue{
            .pending = SigSet.empty(),
            // SAFETY: Array elements set to defaults during init loop below
            .queue = undefined,
            .head = 0,
            .tail = 0,
        };
    }

    pub fn add(self: *SignalQueue, signum: i32, info: *const SigInfo) void {
        self.pending.add(signum);

        const next_tail = (self.tail + 1) % self.queue.len;
        if (next_tail != self.head) {
            self.queue[self.tail] = QueuedSignal{
                .signum = signum,
                .info = info.*,
            };
            self.tail = @as(u8, @intCast(next_tail));
        }
    }

    pub fn get(self: *SignalQueue) ?QueuedSignal {
        if (self.head == self.tail) return null;

        const signal = self.queue[self.head];
        self.head = @as(u8, @intCast((self.head + 1) % self.queue.len));

        var has_more = false;
        var i = self.head;
        while (i != self.tail) : (i = @as(u8, @intCast((i + 1) % self.queue.len))) {
            if (self.queue[i].signum == signal.signum) {
                has_more = true;
                break;
            }
        }

        if (!has_more) {
            self.pending.del(signal.signum);
        }

        return signal;
    }
};

pub const ProcessSignals = struct {
    handlers: [65]SigAction,
    blocked: SigSet,
    pending: SignalQueue,
    alt_stack: ?SignalStack,
    initialized: bool,

    pub fn defaultValue() ProcessSignals {
        return ProcessSignals{
            // SAFETY: handlers initialized at runtime by ensureInit()
            .handlers = undefined,
            .blocked = SigSet.empty(),
            .pending = SignalQueue.init(),
            .alt_stack = null,
            .initialized = false,
        };
    }

    pub fn ensureInit(self: *ProcessSignals) void {
        if (self.initialized) return;
        for (&self.handlers, 0..) |*handler, i| {
            if (i == 0) continue;
            handler.* = getDefaultAction(@as(i32, @intCast(i)));
        }
        self.initialized = true;
    }
};

pub const SignalStack = struct {
    ss_sp: [*]u8,
    ss_size: usize,
    ss_flags: i32,
};

fn getDefaultAction(signum: i32) SigAction {
    const terminate = SigAction{
        .handler = .{ .sa_handler = @as(SignalHandler, @ptrFromInt(SIG_DFL)) },
        .sa_mask = SigSet.empty(),
        .sa_flags = 0,
    };

    const ignore = SigAction{
        .handler = .{ .sa_handler = @as(SignalHandler, @ptrFromInt(SIG_IGN)) },
        .sa_mask = SigSet.empty(),
        .sa_flags = 0,
    };

    return switch (signum) {
        SIGCHLD, SIGURG, SIGWINCH => ignore,
        SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU => terminate,
        SIGCONT => ignore,
        else => terminate,
    };
}

pub fn kill(pid: i32, signum: i32) !void {
    if (signum < 0 or signum > 64) {
        return error.InvalidSignal;
    }

    const target = process.getProcessByPid(@as(u32, @intCast(pid))) orelse return error.NoSuchProcess;

    if (signum == 0) {
        return;
    }

    sendSignal(target, signum);
}

pub fn sigaction(signum: i32, act: ?*const SigAction, oldact: ?*SigAction) !void {
    if (signum <= 0 or signum > 64 or signum == SIGKILL or signum == SIGSTOP) {
        return error.InvalidSignal;
    }

    const current = process.getCurrentProcess().?;

    if (oldact) |old| {
        old.* = current.signals.handlers[@as(usize, @intCast(signum))];
    }

    if (act) |new| {
        current.signals.handlers[@as(usize, @intCast(signum))] = new.*;
    }
}

pub fn sigprocmask(how: i32, set: ?*const SigSet, oldset: ?*SigSet) !void {
    const current = process.getCurrentProcess().?;

    if (oldset) |old| {
        old.* = current.signals.blocked;
    }

    if (set) |new| {
        switch (how) {
            0 => current.signals.blocked = new.*,
            1 => {
                for (new.sig, 0..) |mask, i| {
                    current.signals.blocked.sig[i] |= mask;
                }
            },
            2 => {
                for (new.sig, 0..) |mask, i| {
                    current.signals.blocked.sig[i] &= ~mask;
                }
            },
            else => return error.InvalidArgument,
        }

        current.signals.blocked.del(SIGKILL);
        current.signals.blocked.del(SIGSTOP);
    }
}

pub fn sigpending(set: *SigSet) void {
    const current = process.getCurrentProcess().?;
    set.* = current.signals.pending.pending;
}

pub fn sigsuspend(mask: *const SigSet) !void {
    const current = process.getCurrentProcess().?;
    const old_mask = current.signals.blocked;

    current.signals.blocked = mask.*;
    current.signals.blocked.del(SIGKILL);
    current.signals.blocked.del(SIGSTOP);

    process.yield();

    current.signals.blocked = old_mask;

    if (current.signals.pending.pending.sig[0] != 0 or
        current.signals.pending.pending.sig[1] != 0) {
        return error.Interrupted;
    }
}

pub fn sendSignal(target: *process.Process, signum: i32) void {
    if (signum <= 0 or signum > 64) return;
    target.signals.ensureInit();

    const info = SigInfo{
        .si_signo = signum,
        .si_errno = 0,
        .si_code = 0,
        .si_pid = if (process.getCurrentProcess()) |p| @as(i32, @intCast(p.pid)) else 0,
        .si_uid = 0,
        .si_addr = null,
        .si_status = 0,
        .si_value = .{ .sival_int = 0 },
    };

    target.signals.pending.add(signum, &info);

    if (target.state == .Waiting) {
        target.state = .Ready;
    }
}

pub fn handlePendingSignals() void {
    const proc = process.getCurrentProcess() orelse return;
    proc.signals.ensureInit();
    const current = proc;

    while (current.signals.pending.get()) |queued| {
        const signum = queued.signum;

        if (current.signals.blocked.ismember(signum)) {
            current.signals.pending.add(signum, &queued.info);
            continue;
        }

        const action = &current.signals.handlers[@as(usize, @intCast(signum))];

        if (@intFromPtr(action.handler.sa_handler) == SIG_IGN) {
            continue;
        }

        if (@intFromPtr(action.handler.sa_handler) == SIG_DFL) {
            handleDefaultSignal(signum);
            continue;
        }

        const old_blocked = current.signals.blocked;
        if ((action.sa_flags & SA_NODEFER) == 0) {
            current.signals.blocked.add(signum);
        }
        for (action.sa_mask.sig, 0..) |mask, i| {
            current.signals.blocked.sig[i] |= mask;
        }

        if ((action.sa_flags & SA_SIGINFO) != 0) {
            action.handler.sa_sigaction(signum, @as(*SigInfo, @ptrCast(@constCast(&queued.info))), null);
        } else {
            action.handler.sa_handler(signum);
        }

        current.signals.blocked = old_blocked;

        if ((action.sa_flags & SA_RESETHAND) != 0) {
            current.signals.handlers[@as(usize, @intCast(signum))] = getDefaultAction(signum);
        }
    }
}

fn handleDefaultSignal(signum: i32) void {
    const current = process.getCurrentProcess() orelse return;

    switch (signum) {
        SIGCHLD, SIGURG, SIGWINCH => {},
        SIGCONT => {
            if (current.state == .Stopped) {
                current.state = .Ready;
            }
        },
        SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU => {
            current.state = .Stopped;
            process.yield();
        },
        else => {
            vga.print("Process ");
            printNumber(current.pid);
            vga.print(" terminated by signal ");
            printNumber(@as(u32, @intCast(signum)));
            vga.print("\n");

            current.state = .Zombie;
            process.yield();
        },
    }
}

pub fn alarm(seconds: u32) u32 {
    const current = process.getCurrentProcess().?;
    const old_alarm = current.alarm_time;

    if (seconds == 0) {
        current.alarm_time = 0;
    } else {
        current.alarm_time = process.getSystemTime() + seconds * 1000;
    }

    if (old_alarm == 0) return 0;

    const now = process.getSystemTime();
    if (old_alarm > now) {
        return @as(u32, @intCast((old_alarm - now) / 1000));
    }

    return 0;
}

pub fn checkAlarms() void {
    const now = process.getSystemTime();

    for (process.process_table) |*proc| {
        if (proc.state != .Zombie and proc.alarm_time != 0 and proc.alarm_time <= now) {
            proc.alarm_time = 0;
            sendSignal(proc, SIGALRM);
        }
    }
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.printChar('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[count] = @as(u8, @intCast('0' + (n % 10)));
        count += 1;
    }

    var i = count;
    while (i > 0) {
        i -= 1;
        vga.printChar(digits[i]);
    }
}