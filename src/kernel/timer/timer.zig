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
var next_deadline: u64 = 0;

pub fn init(features: cpu_baseline.Features, mode: Mode) void {
    if (mode == .tsc_deadline and (!features.tsc_deadline or !features.invariant_tsc)) unreachable;

    console.print("Initializing x2APIC timer...\n");

    ticks = 0;
    next_deadline = 0;
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
            scheduleNextDeadline(x86.rdtsc());
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

fn scheduleNextDeadline(now: u64) void {
    var deadline = next_deadline +% tsc_ticks_per_tick;
    if (deadline <= now) deadline = now +% tsc_ticks_per_tick;
    next_deadline = deadline;
    x86.writeMsr(IA32_TSC_DEADLINE_MSR, deadline);
}

pub fn handleInterrupt() void {
    ticks +%= 1;
    if (active_mode == .tsc_deadline) scheduleNextDeadline(x86.rdtsc());
    x86.writeMsr(X2APIC_EOI_MSR, 0);
}

pub fn handleSpuriousInterrupt() void {
    // Intel specifies that spurious local-APIC interrupts do not receive EOI.
}

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
    const start_ticks = ticks;
    while (ticks -% start_ticks < ticks_to_wait) {
        x86.hlt();
    }
}

pub fn sleep(milliseconds: u32) void {
    if (milliseconds == 0) return;

    const ticks_to_wait = millisecondsToTicksCeil(milliseconds);
    sleepCurrentTicks(ticks_to_wait);
}
