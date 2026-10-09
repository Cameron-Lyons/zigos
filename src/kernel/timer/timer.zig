const std = @import("std");
const builtin = @import("builtin");
const units = @import("../../native/core/units.zig");
const console = @import("../utils/console.zig");
const x2apic = @import("../interrupts/x2apic.zig");
const x86 = @import("../../arch/x86.zig");
const cpu_baseline = @import("../../arch/cpu_baseline.zig");
const cpu_identity = @import("../cpu_identity.zig");

const IA32_TSC_DEADLINE_MSR: u32 = 0x6E0;
const X2APIC_LVT_TIMER_MSR: u32 = 0x832;
const X2APIC_TIMER_INITIAL_COUNT_MSR: u32 = 0x838;
const X2APIC_TIMER_CURRENT_COUNT_MSR: u32 = 0x839;
const X2APIC_TIMER_DIVIDE_CONFIG_MSR: u32 = 0x83E;
const X2APIC_TIMER_MASKED: u64 = 1 << 16;
const X2APIC_TIMER_MODE_PERIODIC: u64 = 1 << 17;
const X2APIC_TIMER_MODE_TSC_DEADLINE: u64 = 1 << 18;
const X2APIC_TIMER_DIVIDE_BY_16: u64 = 0x3;

pub const TICKS_PER_SECOND: u64 = units.TIMER_FREQUENCY_HZ;
pub const MILLISECONDS_PER_TICK: u64 = 1000 / TICKS_PER_SECOND;
pub const NANOSECONDS_PER_TICK: u64 = 1_000_000_000 / TICKS_PER_SECOND;
pub const INTERRUPT_VECTOR: u8 = 0x40;
pub const SPURIOUS_VECTOR: u8 = 0xFF;
pub const TICKLESS_TSC_DEADLINE = true;

pub const Mode = enum {
    tsc_deadline,
    calibrated_countdown,
};

const ClockAuthority = struct {
    mode: Mode = .tsc_deadline,
    epoch: u64 = 0,
    frequency_hz: u64 = 0,
    per_tick: u64 = 0,
};

// Published once by the BSP before SMP startup. APs cannot choose a different
// clock or reset its epoch; only their own cached tick and timer state vary.
var clock_authority: ClockAuthority = .{};
var clock_ready: bool = false;

const TimerState = extern struct {
    ticks: u64 = 0,
    initialized: bool = false,
    scheduler_tick_enabled: bool = false,
    lvt_unmasked: bool = false,
    padding: [53]u8 = @splat(0),
};
var cpu_states: [cpu_identity.MAX_CPUS]TimerState align(64) = @splat(.{});
comptime {
    if (@sizeOf(TimerState) != 64) @compileError("timer state must occupy one cache line");
}

inline fn currentState() *TimerState {
    return &cpu_states[cpu_identity.currentIndex()];
}

const Hardware = struct {
    inline fn available() bool {
        return if (builtin.is_test) Testing.active_model != null else builtin.target.os.tag == .freestanding;
    }

    inline fn counter() u64 {
        if (builtin.is_test) {
            const model = Testing.active_model orelse return 0;
            const cpu = &model.cpus[cpu_identity.currentIndex()];
            const now = cpu.now;
            cpu.now +%= cpu.tsc_step;
            return now;
        }
        return if (builtin.target.os.tag == .freestanding) x86.rdtsc() else 0;
    }

    inline fn interruptsEnabled() bool {
        if (builtin.is_test) {
            const model = Testing.active_model orelse return false;
            return model.cpus[cpu_identity.currentIndex()].interrupts_enabled;
        }
        return if (builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
    }

    inline fn disableInterrupts() void {
        if (builtin.is_test) {
            const model = Testing.active_model orelse return;
            model.cpus[cpu_identity.currentIndex()].interrupts_enabled = false;
        } else if (builtin.target.os.tag == .freestanding) x86.cli();
    }

    inline fn restoreInterrupts(enabled: bool) void {
        if (!enabled) return;
        if (builtin.is_test) {
            const model = Testing.active_model orelse return;
            const cpu = &model.cpus[cpu_identity.currentIndex()];
            cpu.interrupts_enabled = true;
            // Deliver a pending modeled interrupt only after the complete
            // production state/MSR transaction, as hardware IF restoration does.
            if (cpu.pending_interrupt) {
                cpu.pending_interrupt = false;
                cpu.interrupts_enabled = false;
                handleInterrupt();
                cpu.interrupts_enabled = true;
            }
        } else if (builtin.target.os.tag == .freestanding) x86.sti();
    }

    inline fn write(msr: u32, value: u64) void {
        if (builtin.is_test) {
            const model = Testing.active_model orelse return;
            const cpu = &model.cpus[cpu_identity.currentIndex()];
            cpu.writes += 1;
            if (cpu.interrupts_enabled) cpu.unmasked_writes += 1;
            switch (msr) {
                IA32_TSC_DEADLINE_MSR => cpu.deadline = value,
                X2APIC_LVT_TIMER_MSR => cpu.lvt = value,
                X2APIC_TIMER_INITIAL_COUNT_MSR => {
                    cpu.initial_count = value;
                    cpu.current_count = value;
                },
                X2APIC_TIMER_DIVIDE_CONFIG_MSR => cpu.divide = value,
                0x80B => cpu.eois += 1,
                else => unreachable,
            }
            if (cpu.inject_after_msr == msr) {
                cpu.inject_after_msr = null;
                cpu.pending_interrupt = true;
            }
        } else if (builtin.target.os.tag == .freestanding) x86.writeMsr(msr, value);
    }

    inline fn readCurrentCount() u64 {
        if (builtin.is_test) {
            const model = Testing.active_model orelse return 0;
            const cpu = &model.cpus[cpu_identity.currentIndex()];
            return cpu.current_count -| cpu.calibration_decrement;
        }
        return if (builtin.target.os.tag == .freestanding) x86.readMsr(X2APIC_TIMER_CURRENT_COUNT_MSR) else 0;
    }

    inline fn enableApic() void {
        if (builtin.is_test) {
            const model = Testing.active_model orelse return;
            model.cpus[cpu_identity.currentIndex()].apic_enables += 1;
        } else if (builtin.target.os.tag == .freestanding) x2apic.enable();
    }

    inline fn acknowledge() void {
        if (builtin.is_test) write(0x80B, 0) else if (builtin.target.os.tag == .freestanding) x2apic.acknowledge();
    }
};

const InterruptGuard = struct {
    enabled: bool,

    inline fn enter() InterruptGuard {
        const enabled = Hardware.interruptsEnabled();
        Hardware.disableInterrupts();
        return .{ .enabled = enabled };
    }

    inline fn leave(self: InterruptGuard) void {
        Hardware.restoreInterrupts(self.enabled);
    }
};

pub fn init(features: cpu_baseline.Features, mode: Mode) void {
    if (!initializeBsp(features, mode)) @panic("invalid BSP timer initialization");
}

fn initializeBsp(features: cpu_baseline.Features, mode: Mode) bool {
    const guard = InterruptGuard.enter();
    defer guard.leave();
    if (cpu_identity.currentIndex() != 0 or !Hardware.available() or
        @atomicLoad(bool, &clock_ready, .acquire) or currentState().initialized or
        features.tsc_frequency_hz / TICKS_PER_SECOND == 0 or
        (mode == .tsc_deadline and (!features.tsc_deadline or !features.invariant_tsc))) return false;

    if (!builtin.is_test) console.print("Initializing x2APIC timer...\n");
    Hardware.enableApic();
    clock_authority = .{
        .mode = mode,
        .epoch = Hardware.counter(),
        .frequency_hz = features.tsc_frequency_hz,
        .per_tick = features.tsc_frequency_hz / TICKS_PER_SECOND,
    };
    switch (mode) {
        .tsc_deadline => {
            Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, 0);
            Hardware.write(IA32_TSC_DEADLINE_MSR, 0);
            Hardware.write(
                X2APIC_LVT_TIMER_MSR,
                X2APIC_TIMER_MODE_TSC_DEADLINE | INTERRUPT_VECTOR,
            );
        },
        .calibrated_countdown => initCalibratedCountdownTimer(),
    }
    currentState().* = .{ .initialized = true, .lvt_unmasked = true };
    @atomicStore(bool, &clock_ready, true, .release);
    return true;
}

// Called after AP identity, native entry/IDT and x2APIC setup, before online
// publication. The explicit model countdown source remains BSP-only.
pub fn initApplicationProcessor(features: cpu_baseline.Features) bool {
    const guard = InterruptGuard.enter();
    defer guard.leave();
    if (cpu_identity.currentIndex() == 0 or !Hardware.available() or
        !@atomicLoad(bool, &clock_ready, .acquire) or currentState().initialized or
        features.tsc_frequency_hz != clock_authority.frequency_hz or
        (clock_authority.mode == .tsc_deadline and (!features.tsc_deadline or !features.invariant_tsc))) return false;

    Hardware.write(X2APIC_LVT_TIMER_MSR, X2APIC_TIMER_MASKED | INTERRUPT_VECTOR |
        (if (clock_authority.mode == .tsc_deadline) X2APIC_TIMER_MODE_TSC_DEADLINE else @as(u64, 0)));
    Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, 0);
    if (features.tsc_deadline) Hardware.write(IA32_TSC_DEADLINE_MSR, 0);
    currentState().* = .{ .initialized = true };
    return true;
}

fn initCalibratedCountdownTimer() void {
    Hardware.write(
        X2APIC_LVT_TIMER_MSR,
        X2APIC_TIMER_MASKED | INTERRUPT_VECTOR,
    );
    Hardware.write(X2APIC_TIMER_DIVIDE_CONFIG_MSR, X2APIC_TIMER_DIVIDE_BY_16);
    Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, std.math.maxInt(u32));

    const calibration_start = Hardware.counter();
    while (Hardware.counter() -% calibration_start < clock_authority.per_tick) {}

    const remaining: u32 = @truncate(Hardware.readCurrentCount());
    const initial_count = std.math.maxInt(u32) - remaining;
    if (initial_count == 0) @panic("x2APIC timer calibration failed");
    Hardware.write(
        X2APIC_LVT_TIMER_MSR,
        X2APIC_TIMER_MODE_PERIODIC | INTERRUPT_VECTOR,
    );
    Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, initial_count);
}

fn elapsedTicks(epoch: u64, now: u64, tsc_per_tick: u64) u64 {
    return (now -% epoch) / tsc_per_tick;
}

fn nextTickDeadline(epoch: u64, now: u64, tsc_per_tick: u64) u64 {
    const ticks_into_period = (now -% epoch) % tsc_per_tick;
    return now +% (tsc_per_tick - ticks_into_period);
}

inline fn synchronizeTicks(state: *TimerState, now: u64) void {
    @atomicStore(u64, &state.ticks, elapsedTicks(clock_authority.epoch, now, clock_authority.per_tick), .monotonic);
}

inline fn unmaskDeadlineTimer(state: *TimerState) void {
    if (state.lvt_unmasked) return;
    Hardware.write(X2APIC_LVT_TIMER_MSR, X2APIC_TIMER_MODE_TSC_DEADLINE | INTERRUPT_VECTOR);
    state.lvt_unmasked = true;
}

inline fn scheduleNextTick(now: u64) void {
    Hardware.write(IA32_TSC_DEADLINE_MSR, nextTickDeadline(clock_authority.epoch, now, clock_authority.per_tick));
}

pub fn synchronize() void {
    // The calibrated QEMU wake source uses the same elapsed-time clock. Counting
    // interrupts would freeze leases during boot proofs or masked interrupts.
    const guard = InterruptGuard.enter();
    defer guard.leave();
    const state = currentState();
    if (state.initialized) synchronizeTicks(state, Hardware.counter());
}

pub fn armSchedulerTick() void {
    const guard = InterruptGuard.enter();
    defer guard.leave();
    const state = currentState();
    if (!state.initialized or clock_authority.mode != .tsc_deadline) return;
    const now = Hardware.counter();
    synchronizeTicks(state, now);
    state.scheduler_tick_enabled = true;
    unmaskDeadlineTimer(state);
    scheduleNextTick(now);
}

pub fn disarmSchedulerTick() void {
    const guard = InterruptGuard.enter();
    defer guard.leave();
    const state = currentState();
    if (!state.initialized or clock_authority.mode != .tsc_deadline) return;
    synchronizeTicks(state, Hardware.counter());
    state.scheduler_tick_enabled = false;
    Hardware.write(IA32_TSC_DEADLINE_MSR, 0);
}

// Service deadlines need one wake, not a periodic scheduler tick while idle.
pub fn armWakeAt(deadline_ticks: u64) void {
    const guard = InterruptGuard.enter();
    defer guard.leave();
    const state = currentState();
    if (!state.initialized or clock_authority.mode != .tsc_deadline) return;
    const now = Hardware.counter();
    synchronizeTicks(state, now);
    state.scheduler_tick_enabled = false;
    unmaskDeadlineTimer(state);
    Hardware.write(IA32_TSC_DEADLINE_MSR, wakeDeadline(clock_authority.epoch, now, clock_authority.per_tick, deadline_ticks));
}

fn wakeDeadline(epoch: u64, now: u64, per_tick: u64, deadline: u64) u64 {
    const current = elapsedTicks(epoch, now, per_tick);
    const periods = if (deadline > current) deadline - current - 1 else 0;
    const cycles = std.math.mul(u64, periods, per_tick) catch std.math.maxInt(u64) / 2;
    return nextTickDeadline(epoch, now, per_tick) +% @min(cycles, std.math.maxInt(u64) / 2);
}

pub fn handleInterrupt() void {
    const guard = InterruptGuard.enter();
    defer guard.leave();
    const state = currentState();
    if (state.initialized) {
        const now = Hardware.counter();
        synchronizeTicks(state, now);
        if (clock_authority.mode == .tsc_deadline and state.scheduler_tick_enabled) scheduleNextTick(now);
    }
    Hardware.acknowledge();
}

pub fn handleSpuriousInterrupt() void {}

pub fn getTicks() u64 {
    // A single aligned cache snapshot needs no IRQ masking. All writers are
    // this CPU, inside the state/register transaction's interrupt guard.
    return @atomicLoad(u64, &currentState().ticks, .monotonic);
}

pub fn millisecondsToTicksCeil(milliseconds: u64) u64 {
    return units.millisecondsToTimerTicksCeil(milliseconds);
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

// This register bank exists only in hosted tests. The public timer wrappers
// execute unchanged against it; no production backend or state override exists.
pub const Testing = if (builtin.is_test) struct {
    var active_model: ?*Model = null;

    pub const CpuRegisters = struct {
        now: u64 = 1_000,
        tsc_step: u64 = 0,
        interrupts_enabled: bool = true,
        lvt: u64 = 0,
        deadline: u64 = 0,
        initial_count: u64 = 0,
        current_count: u64 = 0,
        divide: u64 = 0,
        calibration_decrement: u64 = 1_000,
        writes: usize = 0,
        unmasked_writes: usize = 0,
        eois: usize = 0,
        apic_enables: usize = 0,
        pending_interrupt: bool = false,
        inject_after_msr: ?u32 = null,
    };

    pub const Model = struct {
        cpus: [cpu_identity.MAX_CPUS]CpuRegisters = @splat(.{}),
    };

    pub const Snapshot = struct {
        clock: ClockAuthority,
        ready: bool,
        states: [cpu_identity.MAX_CPUS]TimerState,
        model: ?*Model,
        identity: u8,

        pub fn restore(self: Snapshot) void {
            clock_authority = self.clock;
            cpu_states = self.states;
            @atomicStore(bool, &clock_ready, self.ready, .release);
            active_model = self.model;
            cpu_identity.setIndexForTest(self.identity);
        }
    };

    pub fn install(model: *Model) Snapshot {
        const snapshot = Snapshot{
            .clock = clock_authority,
            .ready = @atomicLoad(bool, &clock_ready, .acquire),
            .states = cpu_states,
            .model = active_model,
            .identity = cpu_identity.currentIndex(),
        };
        @atomicStore(bool, &clock_ready, false, .release);
        clock_authority = .{};
        cpu_states = @splat(.{});
        active_model = model;
        cpu_identity.setIndexForTest(0);
        return snapshot;
    }

    pub const deadline_features: cpu_baseline.Features = .{
        .invariant_tsc = true,
        .tsc_deadline = true,
        .tsc_frequency_hz = 100 * TICKS_PER_SECOND,
    };
} else struct {};

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

test "invariant TSC service deadlines stay phase aligned without periodic polling" {
    try std.testing.expectEqual(@as(u64, 1_300), wakeDeadline(1_000, 1_099, 100, 3));
    try std.testing.expectEqual(@as(u64, 1_100), wakeDeadline(1_000, 1_099, 100, 0));
    try std.testing.expectEqual(@as(u64, 1_200), wakeDeadline(1_000, 1_100, 100, 1));
    try std.testing.expectEqual(@as(u64, 100), wakeDeadline(std.math.maxInt(u64) - 49, 50, 25, 6));
    const distant = wakeDeadline(1_000, 1_099, 100, std.math.maxInt(u64));
    try std.testing.expect(distant > 1_099);
}

test "timer admission is immutable and rejects every invalid owner before register writes" {
    var model: Testing.Model = .{};
    const saved = Testing.install(&model);
    defer saved.restore();
    const features = Testing.deadline_features;

    // Hosted driver reads and an unexpected cold IRQ remain harmless.
    cpu_identity.setIndexForTest(15);
    synchronize();
    armSchedulerTick();
    disarmSchedulerTick();
    armWakeAt(1);
    try std.testing.expectEqual(@as(u64, 0), getTicks());
    try std.testing.expectEqual(@as(usize, 0), model.cpus[15].writes);
    handleInterrupt();
    try std.testing.expectEqual(@as(usize, 1), model.cpus[15].eois);
    const cold = model;
    try std.testing.expect(!initApplicationProcessor(features));
    try std.testing.expect(!initializeBsp(features, .tsc_deadline));
    try std.testing.expectEqualDeep(cold, model);

    cpu_identity.setIndexForTest(0);
    for ([_]u64{ 0, TICKS_PER_SECOND - 1 }) |frequency| {
        var invalid = features;
        invalid.tsc_frequency_hz = frequency;
        try std.testing.expect(!initializeBsp(invalid, .tsc_deadline));
    }
    inline for (.{ "invariant_tsc", "tsc_deadline" }) |field| {
        var invalid = features;
        @field(invalid, field) = false;
        try std.testing.expect(!initializeBsp(invalid, .tsc_deadline));
    }
    try std.testing.expectEqualDeep(cold, model);
    init(features, .tsc_deadline);
    const published = clock_authority;
    const bsp_initialized = model;
    try std.testing.expect(!initApplicationProcessor(features));
    try std.testing.expect(!initializeBsp(features, .calibrated_countdown));
    try std.testing.expectEqualDeep(bsp_initialized, model);

    for (1..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        model.cpus[index].interrupts_enabled = index % 2 == 0;
        const before = model;
        // This has the same truncated per-tick value, but a different clock.
        var different_clock = features;
        different_clock.tsc_frequency_hz += 1;
        try std.testing.expect(!initApplicationProcessor(different_clock));
        inline for (.{ "invariant_tsc", "tsc_deadline" }) |field| {
            var invalid = features;
            @field(invalid, field) = false;
            try std.testing.expect(!initApplicationProcessor(invalid));
        }
        try std.testing.expectEqualDeep(before, model);
        try std.testing.expect(initApplicationProcessor(features));
        const initialized = model;
        try std.testing.expect(!initApplicationProcessor(features));
        try std.testing.expect(!initializeBsp(features, .tsc_deadline));
        try std.testing.expectEqualDeep(initialized, model);
        try std.testing.expectEqualDeep(published, clock_authority);
    }
}

test "all sixteen timer owners isolate register transactions cached ticks and interrupt flags" {
    var model: Testing.Model = .{};
    const saved = Testing.install(&model);
    defer saved.restore();
    const features = Testing.deadline_features;
    init(features, .tsc_deadline);
    for (1..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        model.cpus[index].deadline = 0xFEED;
        model.cpus[index].initial_count = 0xBEEF;
        const before_states = cpu_states;
        const before_registers = model;
        try std.testing.expect(initApplicationProcessor(features));
        try std.testing.expectEqual(X2APIC_TIMER_MASKED | X2APIC_TIMER_MODE_TSC_DEADLINE | INTERRUPT_VECTOR, model.cpus[index].lvt);
        try std.testing.expectEqual(@as(u64, 0), model.cpus[index].deadline);
        try std.testing.expectEqual(@as(u64, 0), model.cpus[index].initial_count);
        try std.testing.expectEqual(@as(u64, 0), model.cpus[index].current_count);
        try std.testing.expectEqual(@as(usize, 0), model.cpus[index].apic_enables);
        for (0..cpu_identity.MAX_CPUS) |neighbor| {
            if (neighbor == index) continue;
            try std.testing.expectEqualDeep(before_states[neighbor], cpu_states[neighbor]);
            try std.testing.expectEqualDeep(before_registers.cpus[neighbor], model.cpus[neighbor]);
        }
        try std.testing.expectEqual(@as(usize, 64), @intFromPtr(&cpu_states[index]) - @intFromPtr(&cpu_states[index - 1]));
    }
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        const cpu = &model.cpus[index];
        cpu.interrupts_enabled = index % 2 == 0;
        const enabled = cpu.interrupts_enabled;
        const now = 1_000 + (index + 1) * 100 + 37;
        cpu.now = now;
        const before_states = cpu_states;
        const before_registers = model;
        armSchedulerTick();
        try std.testing.expectEqual(@as(u64, index + 1), getTicks());
        try std.testing.expectEqual(@as(u64, now + 63), cpu.deadline);
        try std.testing.expectEqual(enabled, cpu.interrupts_enabled);
        cpu.now = now + 399;
        handleInterrupt();
        try std.testing.expectEqual(@as(u64, index + 5), getTicks());
        try std.testing.expectEqual(@as(u64, now + 463), cpu.deadline);
        try std.testing.expectEqual(@as(usize, 1), cpu.eois);
        disarmSchedulerTick();
        handleInterrupt();
        try std.testing.expectEqual(@as(u64, 0), cpu.deadline);
        try std.testing.expectEqual(@as(usize, 2), cpu.eois);
        armWakeAt(index + 8);
        const wake = cpu.deadline;
        cpu.now = wake;
        handleInterrupt();
        try std.testing.expectEqual(wake, cpu.deadline);
        try std.testing.expectEqual(@as(usize, 3), cpu.eois);
        try std.testing.expectEqual(enabled, cpu.interrupts_enabled);
        try std.testing.expectEqual(@as(usize, 0), cpu.unmasked_writes);
        for (0..cpu_identity.MAX_CPUS) |neighbor| {
            if (neighbor == index) continue;
            try std.testing.expectEqualDeep(before_states[neighbor], cpu_states[neighbor]);
            try std.testing.expectEqualDeep(before_registers.cpus[neighbor], model.cpus[neighbor]);
        }
    }
}

test "deadline transactions defer late IRQs until disarm and preserve delayed wrap phase" {
    var model: Testing.Model = .{};
    model.cpus[0].now = std.math.maxInt(u64) - 49;
    const saved = Testing.install(&model);
    defer saved.restore();
    var features = Testing.deadline_features;
    features.tsc_frequency_hz = 25 * TICKS_PER_SECOND;
    init(features, .tsc_deadline);
    cpu_identity.setIndexForTest(1);
    try std.testing.expect(initApplicationProcessor(features));
    const cpu = &model.cpus[1];
    cpu.now = 50;
    armSchedulerTick();
    try std.testing.expectEqual(@as(u64, 4), getTicks());
    try std.testing.expectEqual(@as(u64, 75), cpu.deadline);
    cpu.now = 81;
    cpu.inject_after_msr = IA32_TSC_DEADLINE_MSR;
    disarmSchedulerTick();
    try std.testing.expectEqual(@as(u64, 0), cpu.deadline);
    try std.testing.expectEqual(@as(u64, 5), getTicks());
    try std.testing.expectEqual(@as(usize, 1), cpu.eois);
    try std.testing.expect(!currentState().scheduler_tick_enabled);
    try std.testing.expect(cpu.interrupts_enabled);
    cpu.inject_after_msr = IA32_TSC_DEADLINE_MSR;
    armSchedulerTick();
    try std.testing.expectEqual(@as(u64, 100), cpu.deadline);
    try std.testing.expectEqual(@as(usize, 2), cpu.eois);
    cpu.now = 356;
    cpu.interrupts_enabled = false;
    handleInterrupt();
    try std.testing.expectEqual(@as(u64, 16), getTicks());
    try std.testing.expectEqual(@as(u64, 375), cpu.deadline);
    try std.testing.expect(!cpu.interrupts_enabled);
    try std.testing.expectEqual(@as(usize, 3), cpu.eois);
    try std.testing.expectEqual(@as(usize, 0), cpu.unmasked_writes);
}

test "explicit BSP countdown stays periodic while every AP countdown remains disarmed" {
    var model: Testing.Model = .{};
    model.cpus[0].tsc_step = 100;
    const saved = Testing.install(&model);
    defer saved.restore();
    const features: cpu_baseline.Features = .{ .tsc_frequency_hz = 100 * TICKS_PER_SECOND };
    init(features, .calibrated_countdown);
    try std.testing.expectEqual(X2APIC_TIMER_MODE_PERIODIC | INTERRUPT_VECTOR, model.cpus[0].lvt);
    try std.testing.expectEqual(X2APIC_TIMER_DIVIDE_BY_16, model.cpus[0].divide);
    try std.testing.expectEqual(@as(u64, 1_000), model.cpus[0].initial_count);
    const published = clock_authority;
    for (1..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        model.cpus[index].deadline = 0xDEAD;
        try std.testing.expect(initApplicationProcessor(features));
        try std.testing.expectEqual(X2APIC_TIMER_MASKED | INTERRUPT_VECTOR, model.cpus[index].lvt);
        try std.testing.expectEqual(@as(u64, 0), model.cpus[index].initial_count);
        // Unsupported deadline MSRs must never be touched in model mode.
        try std.testing.expectEqual(@as(u64, 0xDEAD), model.cpus[index].deadline);
        const writes = model.cpus[index].writes;
        model.cpus[index].now = 1_000 + index * 100;
        synchronize();
        try std.testing.expectEqual(@as(u64, index), getTicks());
        armSchedulerTick();
        armWakeAt(index + 1);
        disarmSchedulerTick();
        try std.testing.expectEqual(writes, model.cpus[index].writes);
        handleInterrupt();
        try std.testing.expectEqual(writes + 1, model.cpus[index].writes);
        try std.testing.expectEqual(@as(usize, 1), model.cpus[index].eois);
        try std.testing.expectEqualDeep(published, clock_authority);
    }
    cpu_identity.setIndexForTest(0);
    const before = model.cpus[0];
    armSchedulerTick();
    armWakeAt(10);
    disarmSchedulerTick();
    try std.testing.expectEqualDeep(before, model.cpus[0]);
    try std.testing.expectEqual(@as(u64, 1_000), model.cpus[0].initial_count);
}
