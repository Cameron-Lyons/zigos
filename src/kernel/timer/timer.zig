const std = @import("std");
const console = @import("../utils/console.zig");
const x2apic = @import("../interrupts/x2apic.zig");
const x86 = @import("../../arch/x86.zig");
const cpu_baseline = @import("../../arch/cpu_baseline.zig");

const IA32_TSC_DEADLINE_MSR: u32 = 0x6E0;
const X2APIC_LVT_TIMER_MSR: u32 = 0x832;
const X2APIC_TIMER_MODE_TSC_DEADLINE: u64 = 1 << 18;

pub const TICKS_PER_SECOND: u64 = 100;
pub const MILLISECONDS_PER_TICK: u64 = 1000 / TICKS_PER_SECOND;
pub const NANOSECONDS_PER_TICK: u64 = 1_000_000_000 / TICKS_PER_SECOND;
pub const INTERRUPT_VECTOR: u8 = 0x40;
pub const SPURIOUS_VECTOR: u8 = 0xFF;
pub const TICKLESS_TSC_DEADLINE = true;

pub const Mode = enum {
    tsc_deadline,
};

var ticks: u64 = 0;
var tsc_ticks_per_tick: u64 = 0;
var tsc_epoch: u64 = 0;
var scheduler_tick_enabled = false;

pub fn init(features: cpu_baseline.Features, mode: Mode) void {
    if (mode != .tsc_deadline) unreachable;
    if (!features.tsc_deadline or !features.invariant_tsc) unreachable;

    console.print("Initializing x2APIC tickless TSC-deadline timer...\n");

    ticks = 0;
    tsc_epoch = 0;
    scheduler_tick_enabled = false;
    tsc_ticks_per_tick = features.tsc_frequency_hz / TICKS_PER_SECOND;
    if (tsc_ticks_per_tick == 0) @panic("invalid TSC frequency for timer");

    x2apic.enable();
    x86.writeMsr(
        X2APIC_LVT_TIMER_MSR,
        X2APIC_TIMER_MODE_TSC_DEADLINE | INTERRUPT_VECTOR,
    );
    tsc_epoch = x86.rdtsc();
}

fn elapsedTicks(epoch: u64, now: u64, tsc_per_tick: u64) u64 {
    return (now -% epoch) / tsc_per_tick;
}

fn nextTickDeadline(epoch: u64, now: u64, tsc_per_tick: u64) u64 {
    const ticks_into_period = (now -% epoch) % tsc_per_tick;
    return now +% (tsc_per_tick - ticks_into_period);
}

fn synchronizeTicks(now: u64) void {
    ticks = elapsedTicks(tsc_epoch, now, tsc_ticks_per_tick);
}

fn scheduleNextTick(now: u64) void {
    const deadline = nextTickDeadline(tsc_epoch, now, tsc_ticks_per_tick);
    x86.writeMsr(IA32_TSC_DEADLINE_MSR, deadline);
}

pub fn synchronize() void {
    synchronizeTicks(x86.rdtsc());
}

pub fn armSchedulerTick() void {
    const now = x86.rdtsc();
    synchronizeTicks(now);
    scheduler_tick_enabled = true;
    scheduleNextTick(now);
}

pub fn disarmSchedulerTick() void {
    synchronizeTicks(x86.rdtsc());
    scheduler_tick_enabled = false;
    x86.writeMsr(IA32_TSC_DEADLINE_MSR, 0);
}

pub fn handleInterrupt() void {
    const now = x86.rdtsc();
    synchronizeTicks(now);
    if (scheduler_tick_enabled) scheduleNextTick(now);
    x2apic.acknowledge();
}

pub fn handleSpuriousInterrupt() void {}

pub fn getTicks() u64 {
    return ticks;
}

pub fn millisecondsToTicksCeil(milliseconds: u64) u64 {
    if (milliseconds == 0) return 0;

    return @max(@as(u64, 1), @divFloor(
        milliseconds + MILLISECONDS_PER_TICK - 1,
        MILLISECONDS_PER_TICK,
    ));
}

pub fn ticksToMilliseconds(tick_count: u64) u64 {
    return tick_count * MILLISECONDS_PER_TICK;
}

pub fn sleepCurrentTicks(ticks_to_wait: u64) void {
    if (ticks_to_wait == 0) return;
    synchronize();
    const start_ticks = getTicks();
    while (true) {
        synchronize();
        if (getTicks() -% start_ticks >= ticks_to_wait) return;
        armSchedulerTick();
        x86.hlt();
    }
}

pub fn sleep(milliseconds: u32) void {
    if (milliseconds == 0) return;

    const ticks_to_wait = millisecondsToTicksCeil(milliseconds);
    sleepCurrentTicks(ticks_to_wait);
}

test "invariant TSC ticks catch up and deadlines stay phase aligned" {
    const epoch: u64 = 1_000;
    const tsc_per_tick: u64 = 100;

    try std.testing.expectEqual(@as(u64, 0), elapsedTicks(epoch, epoch, tsc_per_tick));
    try std.testing.expectEqual(@as(u64, 0), elapsedTicks(epoch, 1_099, tsc_per_tick));
    try std.testing.expectEqual(@as(u64, 1), elapsedTicks(epoch, 1_100, tsc_per_tick));
    try std.testing.expectEqual(@as(u64, 3), elapsedTicks(epoch, 1_351, tsc_per_tick));
    try std.testing.expectEqual(@as(u64, 1_100), nextTickDeadline(epoch, epoch, tsc_per_tick));
    try std.testing.expectEqual(@as(u64, 1_100), nextTickDeadline(epoch, 1_099, tsc_per_tick));
    try std.testing.expectEqual(@as(u64, 1_200), nextTickDeadline(epoch, 1_100, tsc_per_tick));
    try std.testing.expectEqual(@as(u64, 1_400), nextTickDeadline(epoch, 1_351, tsc_per_tick));
}

test "invariant TSC tick math tolerates counter wrap" {
    const epoch = std.math.maxInt(u64) - 49;
    try std.testing.expectEqual(@as(u64, 4), elapsedTicks(epoch, 50, 25));
    try std.testing.expectEqual(@as(u64, 75), nextTickDeadline(epoch, 50, 25));
}
