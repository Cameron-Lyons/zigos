const vga = @import("../drivers/vga.zig");
const smp = @import("../smp/smp.zig");
const process = @import("../process/process.zig");

var pass_count: u32 = 0;
var fail_count: u32 = 0;

pub fn runSMPTests() void {
    pass_count = 0;
    fail_count = 0;

    vga.print("\n=== SMP (Multicore) Tests ===\n\n");

    testAPICDetection();
    testCPUCount();
    testSpinlock();
    testSpinlockContention();
    testPerCPUCurrent();
    testSchedulerLock();
    testCPUIdentification();

    vga.print("\n--- Results: ");
    printDec(pass_count);
    vga.print(" passed, ");
    printDec(fail_count);
    vga.print(" failed ---\n");
    vga.print("=== SMP Tests Complete ===\n");
}

fn testAPICDetection() void {
    vga.print("Test 1: APIC detection\n");
    const num_cpus = smp.getNumCPUs();
    if (num_cpus >= 1) {
        vga.print("  [OK] APIC detected, ");
        printDec(num_cpus);
        vga.print(" CPU(s) found\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] No CPUs detected\n");
        fail_count += 1;
    }
}

fn testCPUCount() void {
    vga.print("Test 2: CPU count sanity\n");
    const num_cpus = smp.getNumCPUs();
    if (num_cpus > 0 and num_cpus <= 16) {
        vga.print("  [OK] CPU count ");
        printDec(num_cpus);
        vga.print(" within valid range (1-16)\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] CPU count out of range: ");
        printDec(num_cpus);
        vga.print("\n");
        fail_count += 1;
    }
}

fn testSpinlock() void {
    vga.print("Test 3: Spinlock acquire/release\n");
    var lock = smp.Spinlock{};

    lock.acquire();
    lock.release();

    lock.acquire();
    lock.release();

    vga.print("  [OK] Spinlock acquire/release cycle completed\n");
    pass_count += 1;
}

fn testSpinlockContention() void {
    vga.print("Test 4: Spinlock state tracking\n");
    var lock = smp.Spinlock{};

    if (lock.locked == 0) {
        vga.print("  [OK] Lock starts unlocked\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Lock not initially unlocked\n");
        fail_count += 1;
    }

    lock.acquire();
    if (lock.locked == 1) {
        vga.print("  [OK] Lock is locked after acquire\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Lock state incorrect after acquire\n");
        fail_count += 1;
    }

    lock.release();
    if (lock.locked == 0) {
        vga.print("  [OK] Lock is unlocked after release\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Lock state incorrect after release\n");
        fail_count += 1;
    }
}

fn testPerCPUCurrent() void {
    vga.print("Test 5: Per-CPU current process tracking\n");
    const current = process.getEffectiveCurrent();
    if (current != null) {
        vga.print("  [OK] BSP has a current process (PID ");
        printDec(current.?.pid);
        vga.print(")\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] BSP has no current process\n");
        fail_count += 1;
    }
}

fn testSchedulerLock() void {
    vga.print("Test 6: Scheduler lock acquire/release\n");

    smp.scheduler_lock.acquire();
    smp.scheduler_lock.release();

    vga.print("  [OK] Scheduler lock cycle completed without deadlock\n");
    pass_count += 1;
}

fn testCPUIdentification() void {
    vga.print("Test 7: Current CPU identification\n");
    const cpu_id = smp.getCurrentCPU();
    if (cpu_id < 16) {
        vga.print("  [OK] Running on CPU ");
        printDec(cpu_id);
        vga.print("\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Invalid CPU ID: ");
        printDec(cpu_id);
        vga.print("\n");
        fail_count += 1;
    }

    if (smp.isSMPEnabled()) {
        vga.print("  [OK] SMP is enabled with multiple CPUs\n");
        pass_count += 1;
    } else {
        vga.print("  [OK] SMP not enabled (single CPU or no APIC)\n");
        pass_count += 1;
    }
}

fn printDec(value: u32) void {
    // SAFETY: filled by the following digit extraction loop
    var buffer: [10]u8 = undefined;
    var i: usize = 0;
    var v = value;

    if (v == 0) {
        vga.put_char('0');
        return;
    }

    while (v > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}
