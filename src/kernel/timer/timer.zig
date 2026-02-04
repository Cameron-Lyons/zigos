const vga = @import("../drivers/vga.zig");

const PIT_CHANNEL0 = 0x40;
const PIT_COMMAND = 0x43;
const PIT_FREQUENCY = 1193180;

var ticks: u64 = 0;

fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

pub fn init(frequency_hz: u32) void {
    vga.print("Initializing PIT timer at ");
    print_number(frequency_hz);
    vga.print(" Hz...\n");

    const divisor = PIT_FREQUENCY / frequency_hz;

    outb(PIT_COMMAND, 0x36);

    outb(PIT_CHANNEL0, @truncate(divisor & 0xFF));
    outb(PIT_CHANNEL0, @truncate((divisor >> 8) & 0xFF));

    vga.print("Timer initialized!\n");
}

pub fn handleInterrupt() void {
    ticks += 1;

    const TCP_TICK_INTERVAL = 50;
    if (ticks % TCP_TICK_INTERVAL == 0) {
        const tcp = @import("../net/tcp.zig");
        tcp.tick();
    }

    const PREEMPTION_TICKS = 10;
    if (ticks % PREEMPTION_TICKS == 0) {
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