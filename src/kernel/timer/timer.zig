const vga = @import("../drivers/vga.zig");
const io = @import("../utils/io.zig");

const PIT_CHANNEL0 = 0x40;
const PIT_COMMAND = 0x43;
const PIT_FREQUENCY = 1193180;
const MAX_SLEEPERS = 128;

const SleepEntry = struct {
    pid: u32 = 0,
    wake_tick: u64 = 0,
    active: bool = false,
};

var ticks: u64 = 0;
var sleep_entries: [MAX_SLEEPERS]SleepEntry = [_]SleepEntry{.{}} ** MAX_SLEEPERS;
var sleep_lock: u32 = 0;

pub fn init(frequency_hz: u32) void {
    vga.print("Initializing PIT timer at ");
    print_number(frequency_hz);
    vga.print(" Hz...\n");

    ticks = 0;
    @memset(sleep_entries[0..], .{});
    sleep_lock = 0;

    const divisor = PIT_FREQUENCY / frequency_hz;

    io.outb(PIT_COMMAND, 0x36);

    io.outb(PIT_CHANNEL0, @truncate(divisor & 0xFF));
    io.outb(PIT_CHANNEL0, @truncate((divisor >> 8) & 0xFF));

    vga.print("Timer initialized!\n");
}

pub fn handleInterrupt() void {
    ticks += 1;
    const woke_sleepers = wakeExpiredSleepers();

    const TCP_TICK_INTERVAL = 50;
    if (ticks % TCP_TICK_INTERVAL == 0) {
        const tcp = @import("../net/tcp.zig");
        tcp.tick();
    }

    const PREEMPTION_TICKS = 10;
    if (ticks % PREEMPTION_TICKS == 0 or woke_sleepers) {
        const scheduler = @import("../process/scheduler.zig");
        scheduler.preempt();

        const process = @import("../process/process.zig");
        process.yield();
    }

    const ALARM_CHECK_INTERVAL = 100;
    if (ticks % ALARM_CHECK_INTERVAL == 0) {
        const signal = @import("../process/signal.zig");
        signal.checkAlarms();
    }
}

pub fn getTicks() u64 {
    return ticks;
}

pub fn sleepCurrentTicks(ticks_to_wait: u64) void {
    if (ticks_to_wait == 0) return;

    const process = @import("../process/process.zig");
    const scheduler = @import("../process/scheduler.zig");

    const current = process.getEffectiveCurrent() orelse {
        const start_ticks = ticks;
        while (ticks - start_ticks < ticks_to_wait) {
            asm volatile ("hlt");
        }
        return;
    };

    const flags = disableInterrupts();
    const wake_tick = ticks + ticks_to_wait;

    const inserted = scheduleWake(current.pid, wake_tick);

    if (!inserted) {
        restoreInterrupts(flags);
        const start_ticks = ticks;
        while (ticks - start_ticks < ticks_to_wait) {
            asm volatile ("hlt");
        }
        return;
    }

    current.state = .Blocked;
    scheduler.blockProcess(current);
    restoreInterrupts(flags);
    process.yield();
}

pub fn scheduleWake(pid: u32, wake_tick: u64) bool {
    if (pid == 0) return false;

    lockSleep();
    defer unlockSleep();

    for (&sleep_entries) |*entry| {
        if (entry.active and entry.pid == pid) {
            entry.wake_tick = wake_tick;
            return true;
        }
    }

    for (&sleep_entries) |*entry| {
        if (!entry.active) {
            entry.pid = pid;
            entry.wake_tick = wake_tick;
            entry.active = true;
            return true;
        }
    }

    return false;
}

pub fn cancelWake(pid: u32) void {
    if (pid == 0) return;

    lockSleep();
    defer unlockSleep();

    for (&sleep_entries) |*entry| {
        if (entry.active and entry.pid == pid) {
            entry.active = false;
        }
    }
}

pub fn sleep(milliseconds: u32) void {
    const start_ticks = ticks;
    const ticks_to_wait = milliseconds / 10;
    while (ticks - start_ticks < ticks_to_wait) {
        asm volatile ("hlt");
    }
}

fn print_number(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var digits: [10]u8 = undefined;
    var i: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[i] = @as(u8, @truncate(n % 10)) + '0';
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(digits[i]);
    }
}

fn lockSleep() void {
    while (@cmpxchgWeak(u32, &sleep_lock, 0, 1, .acquire, .monotonic) != null) {
        while (@atomicLoad(u32, &sleep_lock, .monotonic) != 0) {
            asm volatile ("pause");
        }
    }
}

fn unlockSleep() void {
    @atomicStore(u32, &sleep_lock, 0, .release);
}

fn wakeExpiredSleepers() bool {
    const process = @import("../process/process.zig");
    const scheduler = @import("../process/scheduler.zig");

    var ready_pids: [MAX_SLEEPERS]u32 = undefined;
    var ready_count: usize = 0;

    lockSleep();
    for (&sleep_entries) |*entry| {
        if (entry.active and entry.wake_tick <= ticks) {
            ready_pids[ready_count] = entry.pid;
            ready_count += 1;
            entry.active = false;
        }
    }
    unlockSleep();

    for (ready_pids[0..ready_count]) |pid| {
        if (process.getProcessByPid(pid)) |proc| {
            scheduler.unblockProcess(proc);
        }
    }

    return ready_count != 0;
}

fn disableInterrupts() u32 {
    var flags: u32 = undefined;
    asm volatile (
        \\pushfl
        \\popl %[flags]
        \\cli
        : [flags] "=r" (flags),
    );
    return flags;
}

fn restoreInterrupts(flags: u32) void {
    asm volatile (
        \\pushl %[flags]
        \\popfl
        :
        : [flags] "r" (flags),
    );
}
