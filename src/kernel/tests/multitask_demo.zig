const vga = @import("../drivers/vga.zig");
const process = @import("../process/process.zig");
const scheduler = @import("../process/scheduler.zig");

var counter_a: u32 = 0;
var counter_b: u32 = 0;
var counter_c: u32 = 0;

fn high_priority_task() void {
    vga.print("\n[HIGH] Starting high priority task\n");
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        counter_a += 1;
        if (counter_a % 10 == 0) {
            vga.print("H");
        }

        var delay: u32 = 0;
        while (delay < 100000) : (delay += 1) {
            asm volatile ("nop");
        }

        process.yield();
    }
    vga.print("\n[HIGH] Task completed\n");
}

fn normal_priority_task() void {
    vga.print("\n[NORMAL] Starting normal priority task\n");
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        counter_b += 1;
        if (counter_b % 10 == 0) {
            vga.print("N");
        }

        var delay: u32 = 0;
        while (delay < 100000) : (delay += 1) {
            asm volatile ("nop");
        }

        process.yield();
    }
    vga.print("\n[NORMAL] Task completed\n");
}

fn low_priority_task() void {
    vga.print("\n[LOW] Starting low priority task\n");
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        counter_c += 1;
        if (counter_c % 10 == 0) {
            vga.print("L");
        }

        var delay: u32 = 0;
        while (delay < 100000) : (delay += 1) {
            asm volatile ("nop");
        }

        process.yield();
    }
    vga.print("\n[LOW] Task completed\n");
}

pub fn runMultitaskingDemo() void {
    vga.print("\n=== Starting Multitasking Demo ===\n");
    vga.print("Creating processes with different priorities...\n");

    const high_proc = process.create_kernel_process("high_priority", high_priority_task);
    const normal_proc = process.create_kernel_process("normal_priority", normal_priority_task);
    const low_proc = process.create_kernel_process("low_priority", low_priority_task);

    _ = scheduler.setProcessPriority(high_proc.pid, .High);
    _ = scheduler.setProcessPriority(normal_proc.pid, .Normal);
    _ = scheduler.setProcessPriority(low_proc.pid, .Low);

    vga.print("\nProcesses created. Scheduler will manage execution.\n");
    vga.print("H=High Priority, N=Normal Priority, L=Low Priority\n");
    vga.print("\nStarting execution...\n");
}

pub fn showSchedulerStats() void {
    const stats = scheduler.getStatistics();

    vga.print("\n=== Scheduler Statistics ===\n");
    vga.print("Context switches: ");
    print_number(@truncate(stats.context_switches));
    vga.print("\nTotal processes: ");
    print_number(stats.total_processes);
    vga.print("\nReady processes: ");
    print_number(stats.ready_processes);
    vga.print("\nBlocked processes: ");
    print_number(stats.blocked_processes);
    vga.print("\nCPU usage: ");
    print_number(stats.cpu_usage_percent);
    vga.print("%\n");
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
