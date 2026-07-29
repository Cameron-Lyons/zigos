const console = @import("../utils/console.zig");
const io = @import("../utils/io.zig");
const numfmt = @import("../utils/numfmt.zig");

const PIT_CHANNEL0 = 0x40;
const PIT_COMMAND = 0x43;
const PIT_FREQUENCY = 1193180;
const PIT_COMMAND_RATE_GENERATOR = 0x36;
const LOW_BYTE_MASK: u32 = 0xFF;
const BYTE_BITS: u4 = 8;

pub const TICKS_PER_SECOND: u64 = 100;
pub const DEFAULT_FREQUENCY_HZ: u32 = @intCast(TICKS_PER_SECOND);
pub const MILLISECONDS_PER_TICK: u64 = 1000 / TICKS_PER_SECOND;
pub const NANOSECONDS_PER_TICK: u64 = 1_000_000_000 / TICKS_PER_SECOND;

var ticks: u64 = 0;

pub fn init(frequency_hz: u32) void {
    console.print("Initializing PIT timer at ");
    numfmt.printDec(frequency_hz);
    console.print(" Hz...\n");

    ticks = 0;

    const divisor = PIT_FREQUENCY / frequency_hz;

    io.outb(PIT_COMMAND, PIT_COMMAND_RATE_GENERATOR);

    io.outb(PIT_CHANNEL0, @truncate(divisor & LOW_BYTE_MASK));
    io.outb(PIT_CHANNEL0, @truncate((divisor >> BYTE_BITS) & LOW_BYTE_MASK));

    console.print("Timer initialized!\n");
}

pub fn handleInterrupt() void {
    ticks += 1;
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
    while (ticks - start_ticks < ticks_to_wait) {
        asm volatile ("hlt");
    }
}

pub fn sleep(milliseconds: u32) void {
    if (milliseconds == 0) return;

    const ticks_to_wait = millisecondsToTicksCeil(milliseconds);
    sleepCurrentTicks(ticks_to_wait);
}
