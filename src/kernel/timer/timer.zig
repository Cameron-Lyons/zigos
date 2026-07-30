const std = @import("std");
const console = @import("../utils/console.zig");
const x86 = @import("../../arch/x86.zig");
const cpu_baseline = @import("../../arch/cpu_baseline.zig");

const IA32_APIC_BASE_MSR: u32 = 0x1B;
const IA32_TSC_DEADLINE_MSR: u32 = 0x6E0;
const X2APIC_EOI_MSR: u32 = 0x80B;
const X2APIC_SPURIOUS_VECTOR_MSR: u32 = 0x80F;
const X2APIC_LVT_TIMER_MSR: u32 = 0x832;
const X2APIC_TIMER_INITIAL_COUNT_MSR: u32 = 0x838;
const X2APIC_TIMER_CURRENT_COUNT_MSR: u32 = 0x839;
const X2APIC_TIMER_DIVIDE_CONFIG_MSR: u32 = 0x83E;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
const X2APIC_ENABLE: u64 = 1 << 10;
const X2APIC_SOFTWARE_ENABLE: u64 = 1 << 8;
const X2APIC_VECTOR_MASK: u64 = 0xFF;
const X2APIC_TIMER_MASKED: u64 = 1 << 16;
const X2APIC_TIMER_MODE_PERIODIC: u64 = 1 << 17;
const X2APIC_TIMER_MODE_TSC_DEADLINE: u64 = 1 << 18;
const X2APIC_TIMER_DIVIDE_BY_16: u64 = 0x3;

pub const TICKS_PER_SECOND: u64 = 100;
pub const MILLISECONDS_PER_TICK: u64 = 1000 / TICKS_PER_SECOND;
pub const NANOSECONDS_PER_TICK: u64 = 1_000_000_000 / TICKS_PER_SECOND;
pub const INTERRUPT_VECTOR: u8 = 0x40;
pub const SPURIOUS_VECTOR: u8 = 0xFF;

pub const Mode = enum {
    tsc_deadline,
    calibrated_countdown,
};

var ticks: u64 = 0;
var active_mode: Mode = .tsc_deadline;
var tsc_ticks_per_tick: u64 = 0;
var tsc_epoch: u64 = 0;
var scheduler_tick_enabled = false;

pub fn init(features: cpu_baseline.Features, mode: Mode) void {
    if (mode == .tsc_deadline and (!features.tsc_deadline or !features.invariant_tsc)) unreachable;

    console.print("Initializing x2APIC timer...\n");

    ticks = 0;
    tsc_epoch = 0;
    scheduler_tick_enabled = false;
    active_mode = mode;
    tsc_ticks_per_tick = features.tsc_frequency_hz / TICKS_PER_SECOND;
    if (tsc_ticks_per_tick == 0) @panic("invalid TSC frequency for timer");

    x86.writeMsr(
        IA32_APIC_BASE_MSR,
        x86.readMsr(IA32_APIC_BASE_MSR) | APIC_GLOBAL_ENABLE | X2APIC_ENABLE,
    );
    const spurious = x86.readMsr(X2APIC_SPURIOUS_VECTOR_MSR);
    x86.writeMsr(
        X2APIC_SPURIOUS_VECTOR_MSR,
        (spurious & ~X2APIC_VECTOR_MASK) | X2APIC_SOFTWARE_ENABLE | SPURIOUS_VECTOR,
    );
    switch (mode) {
        .tsc_deadline => {
            x86.writeMsr(
                X2APIC_LVT_TIMER_MSR,
                X2APIC_TIMER_MODE_TSC_DEADLINE | INTERRUPT_VECTOR,
            );
            tsc_epoch = x86.rdtsc();
            armSchedulerTick();
        },
        .calibrated_countdown => initCalibratedCountdownTimer(),
    }
}

fn initCalibratedCountdownTimer() void {
    x86.writeMsr(
        X2APIC_LVT_TIMER_MSR,
        X2APIC_TIMER_MASKED | INTERRUPT_VECTOR,
    );
    x86.writeMsr(X2APIC_TIMER_DIVIDE_CONFIG_MSR, X2APIC_TIMER_DIVIDE_BY_16);
    x86.writeMsr(X2APIC_TIMER_INITIAL_COUNT_MSR, std.math.maxInt(u32));

    const calibration_start = x86.rdtsc();
    while (x86.rdtsc() -% calibration_start < tsc_ticks_per_tick) {}

    const remaining: u32 = @truncate(x86.readMsr(X2APIC_TIMER_CURRENT_COUNT_MSR));
    const initial_count = std.math.maxInt(u32) - remaining;
    if (initial_count == 0) @panic("x2APIC timer calibration failed");
    x86.writeMsr(
        X2APIC_LVT_TIMER_MSR,
        X2APIC_TIMER_MODE_PERIODIC | INTERRUPT_VECTOR,
    );
    x86.writeMsr(X2APIC_TIMER_INITIAL_COUNT_MSR, initial_count);
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
    if (active_mode == .tsc_deadline) synchronizeTicks(x86.rdtsc());
}

pub fn armSchedulerTick() void {
    if (active_mode != .tsc_deadline) return;
    const now = x86.rdtsc();
    synchronizeTicks(now);
    scheduler_tick_enabled = true;
    scheduleNextTick(now);
}

pub fn disarmSchedulerTick() void {
    if (active_mode != .tsc_deadline) return;
    synchronizeTicks(x86.rdtsc());
    scheduler_tick_enabled = false;
    x86.writeMsr(IA32_TSC_DEADLINE_MSR, 0);
}

pub fn handleInterrupt() void {
    switch (active_mode) {
        .tsc_deadline => {
            const now = x86.rdtsc();
            synchronizeTicks(now);
            if (scheduler_tick_enabled) scheduleNextTick(now);
        },
        .calibrated_countdown => ticks +%= 1,
    }
    x86.writeMsr(X2APIC_EOI_MSR, 0);
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
