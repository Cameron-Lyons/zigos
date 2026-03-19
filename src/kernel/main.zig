const std = @import("std");
const vga = @import("drivers/vga.zig");
const x86 = @import("../arch/x86.zig");
const console = @import("utils/console.zig");
const config = @import("config.zig");
const isr = @import("interrupts/isr.zig");
const keyboard = @import("drivers/keyboard.zig");
const paging = @import("memory/paging.zig");
const timer = @import("timer/timer.zig");
const process = @import("process/process.zig");
const scheduler = @import("process/scheduler.zig");
const shell = @import("shell/shell.zig");
const external = @import("shell/external.zig");
const syscall = @import("process/syscall.zig");
const test_syscall = @import("tests/test_syscall.zig");
const memory = @import("memory/memory.zig");
const panic_handler = @import("utils/panic.zig");
const qemu_exit = @import("utils/qemu_exit.zig");
const device = @import("devices/device.zig");
const console_device = @import("devices/console_device.zig");
const vfs = @import("fs/vfs.zig");
const ata = @import("drivers/ata.zig");
const fat32 = @import("fs/fat32.zig");
const pci = @import("drivers/pci.zig");
const rtl8139 = @import("drivers/rtl8139.zig");
const network = @import("net/network.zig");
const usb = @import("drivers/usb.zig");
const acpi = @import("acpi/acpi.zig");
const ac97 = @import("drivers/ac97.zig");
const ext2 = @import("fs/ext2.zig");
const vt = @import("devices/vt.zig");
const mmap = @import("memory/mmap.zig");
const swap = @import("memory/swap.zig");
const credentials = @import("process/credentials.zig");
const tmpfs = @import("fs/tmpfs.zig");
const procfs = @import("fs/procfs.zig");
const sysfs = @import("fs/sysfs.zig");
const uhci = @import("drivers/uhci.zig");
const ipv6 = @import("net/ipv6.zig");
const icmpv6 = @import("net/icmpv6.zig");
const icmp = @import("net/icmp.zig");
const devfs = @import("fs/devfs.zig");
const embedfs = @import("fs/embedfs.zig");
const benchmark_suite = @import("benchmarks/suite.zig");
const smp = @import("smp/smp.zig");

const test_process_log_interval: u32 = 1_000_000;
const smp_stress_task_count: usize = 6;
const smp_stress_rounds: usize = 256;

fn runTestProcess(marker: []const u8) void {
    var i: u32 = 0;
    while (true) : (i += 1) {
        if (i % test_process_log_interval == 0) {
            console.print(marker);
        }
        process.yield();
    }
}

fn test_process1() void {
    runTestProcess("A");
}

fn test_process2() void {
    runTestProcess("B");
}

fn printBootMarker(marker: []const u8) void {
    console.print(marker);
    console.print("\n");
}

fn printBootProfile() void {
    console.print("BOOT:PROFILE:");
    console.print(config.name());
    console.print("\n");
}

fn printCpuCount(count: u32) void {
    var cpu_str: [10]u8 = undefined;
    var cpu_count = count;
    var idx: usize = 0;

    if (cpu_count == 0) {
        cpu_str[0] = '0';
        idx = 1;
    } else {
        while (cpu_count > 0) : (idx += 1) {
            cpu_str[idx] = @as(u8, @intCast('0' + (cpu_count % 10)));
            cpu_count /= 10;
        }
        var i: usize = 0;
        while (i < idx / 2) : (i += 1) {
            const tmp = cpu_str[i];
            cpu_str[i] = cpu_str[idx - 1 - i];
            cpu_str[idx - 1 - i] = tmp;
        }
    }

    console.print(cpu_str[0..idx]);
}

fn initCore() void {
    console.print("Initializing GDT...\n");
    const gdt = @import("interrupts/gdt.zig");
    gdt.init();
    console.print("GDT initialized!\n");

    console.print("Initializing interrupts...\n");
    isr.init();
    console.print("Interrupts enabled!\n");

    console.print("Initializing system calls...\n");
    syscall.init();
    console.print("System calls ready!\n");

    console.print("Initializing paging...\n");
    paging.init();

    console.print("Initializing swap...\n");
    swap.init();

    console.print("Enabling kernel memory protection...\n");
    const protection = @import("memory/protection.zig");
    protection.protectKernelMemory();

    console.print("Initializing memory allocator...\n");
    memory.init();

    console.print("Initializing environment variables...\n");
    const environ = @import("utils/environ.zig");
    environ.init();
}

fn initDevices() void {
    console.print("Initializing device drivers...\n");
    device.init();
    console_device.init() catch |err| {
        panic_handler.panic("Failed to initialize console device: {}", .{err});
    };
    ata.init();
    console.print("Device drivers ready!\n");

    if (config.shouldInitRuntimeExtras() or config.shouldInitAcpi()) {
        console.print("Deferring PCI inventory scan and optional device init...\n");
    } else {
        console.print("Scanning PCI bus...\n");
        pci.scanBus();
    }

    if (config.shouldInitSmp()) {
        console.print("Initializing SMP (multicore) support...\n");
        smp.init();
        if (smp.getNumCPUs() > 1) {
            console.print("SMP discovered ");
            printCpuCount(smp.getNumCPUs());
            console.print(" CPUs; runtime startup deferred\n");
        } else {
            console.print("Single CPU mode\n");
        }
    }
}

fn deferredRuntimeInitTask() void {
    console.print("Deferred runtime initialization starting...\n");

    console.print("Scanning PCI bus...\n");
    pci.scanBus();

    if (config.shouldInitAcpi()) {
        console.print("Initializing ACPI...\n");
        acpi.init();
    }

    if (config.shouldInitRuntimeExtras()) {
        console.print("Initializing USB...\n");
        usb.init();

        console.print("Initializing UHCI...\n");
        uhci.init();

        console.print("Initializing audio...\n");
        ac97.init();

        console.print("Initializing virtual terminals...\n");
        vt.init();
    }

    console.print("Deferred runtime initialization complete\n");
}

fn startDeferredRuntimeInit() void {
    if (!config.shouldInitRuntimeExtras() and !config.shouldInitAcpi()) return;

    console.print("Scheduling deferred runtime initialization...\n");
    const init_proc = process.create_kernel_process_any_cpu("runtime-init", deferredRuntimeInitTask);
    _ = scheduler.setProcessPriority(init_proc.pid, .Low);
}

fn initNetworkStack() void {
    network.init();

    console.print("Initializing ICMP...\n");
    icmp.init();

    console.print("Initializing socket API...\n");
    const socket = @import("net/socket.zig");
    socket.init();

    console.print("Initializing DNS client...\n");
    const dns = @import("net/dns.zig");
    dns.init();

    console.print("Initializing DHCP client...\n");
    const dhcp = @import("net/dhcp.zig");
    dhcp.init();

    console.print("Initializing IPv6...\n");
    ipv6.init();

    console.print("Initializing ICMPv6...\n");
    icmpv6.init();
    icmpv6.sendRouterSolicitation();

    console.print("Initializing routing table...\n");
    const routing = @import("net/routing.zig");
    routing.init();
}

fn initFileSystems() void {
    console.print("Initializing Virtual File System...\n");
    vfs.init();
    console.print("VFS ready!\n");

    console.print("Initializing FAT32 file system...\n");
    fat32.init();
    console.print("FAT32 ready!\n");

    console.print("Initializing ext2 file system...\n");
    ext2.init();

    console.print("Initializing embedded root filesystem...\n");
    embedfs.init();

    console.print("Mounting FAT32 disk as root...\n");
    const disk_root_ready = blk: {
        vfs.mount("ata0", "/", "fat32", 0) catch |err| {
            console.print("Disk root unavailable: ");
            console.print(@errorName(err));
            console.print("\n");
            break :blk false;
        };
        console.print("Disk root mounted at /\n");
        break :blk true;
    };

    if (!disk_root_ready) {
        console.print("Mounting embedded root filesystem fallback...\n");
        vfs.mount("none", "/", "embedfs", 0) catch |err| {
            console.print("Failed to mount embedded root filesystem: ");
            console.print(@errorName(err));
            console.print("\n");
        };
    }

    if (!disk_root_ready) {
        console.print("Mounting FAT32 disk on /mnt...\n");
        vfs.mount("ata0", "/mnt", "fat32", 0) catch |err| {
            console.print("Disk mount unavailable: ");
            console.print(@errorName(err));
            console.print("\n");
        };
    }

    console.print("Initializing tmpfs...\n");
    tmpfs.init();

    console.print("Mounting tmpfs on /tmp...\n");
    vfs.mount("none", "/tmp", "tmpfs", 0) catch |err| {
        console.print("Failed to mount tmpfs: ");
        console.print(@errorName(err));
        console.print("\n");
    };

    console.print("Initializing devfs...\n");
    devfs.init();

    console.print("Mounting devfs on /dev...\n");
    vfs.mount("none", "/dev", "devfs", 0) catch |err| {
        console.print("Failed to mount devfs: ");
        console.print(@errorName(err));
        console.print("\n");
    };

    console.print("Initializing procfs...\n");
    procfs.init();

    console.print("Mounting procfs on /proc...\n");
    vfs.mount("none", "/proc", "procfs", 0) catch |err| {
        console.print("Failed to mount procfs: ");
        console.print(@errorName(err));
        console.print("\n");
    };

    console.print("Initializing sysfs...\n");
    sysfs.init();

    console.print("Mounting sysfs on /sys...\n");
    vfs.mount("none", "/sys", "sysfs", 0) catch |err| {
        console.print("Failed to mount sysfs: ");
        console.print(@errorName(err));
        console.print("\n");
    };

    console.print("Initializing memory mapping...\n");
    mmap.init();
}

fn initRuntime() void {
    console.print("Initializing credentials...\n");
    credentials.init();

    console.print("Initializing process management...\n");
    process.init();

    if (config.shouldInitSmp()) {
        smp.startSecondaryCPUs();
        if (smp.isSMPEnabled()) {
            console.print("SMP enabled with ");
            printCpuCount(smp.getActiveCPUCount());
            console.print(" CPUs\n");
        } else if (smp.getNumCPUs() > 1) {
            console.print("SMP startup unavailable, continuing on BSP only\n");
        }
    }

    if (config.shouldInitRuntimeExtras()) {
        console.print("Starting async IO workers...\n");
        ata.startAsyncWorker();
        network.startWorkers();

        console.print("Initializing process monitoring...\n");
        const procmon = @import("tests/procmon.zig");
        procmon.init();
    }

    console.print("Initializing timer...\n");
    timer.init(timer.DEFAULT_FREQUENCY_HZ);

    console.print("Initializing keyboard...\n");
    keyboard.init();
    console.print("Keyboard ready!\n");

    startDeferredRuntimeInit();
}

fn createDemoProcesses() void {
    console.print("Creating test processes...\n");
    _ = process.create_process("test1", test_process1);
    _ = process.create_process("test2", test_process2);
    _ = process.create_process("syscall_test", test_syscall.test_syscall_process);

    const userspace = @import("process/userspace.zig");
    userspace.createUserTestProcess();

    const ring3 = @import("process/ring3.zig");
    ring3.createRing3TestProcess();
}

fn initializeShell(shell_instance: *shell.Shell) void {
    console.print("Initializing shell...\n");
    shell_instance.* = shell.Shell.init();
    keyboard.setShell(shell_instance);
    printBootMarker("BOOT:SHELL_READY");
}

fn launchInitProcess() ?*process.Process {
    const init_command = [_][*:0]const u8{"/bin/init"};
    const pid = external.launchExternalCommand(init_command[0..], null, null, null) catch |err| {
        console.print("Failed to launch /bin/init: ");
        console.print(@errorName(err));
        console.print("\n");
        return null;
    };

    console.print("Init process launched\n");
    return process.getProcessByPid(pid);
}

fn enterIdleLoop() noreturn {
    asm volatile ("sti");
    while (true) {
        asm volatile ("hlt");
    }
}

fn runDevProfile() noreturn {
    if (launchInitProcess()) |init_proc| {
        console.print("\nZigOS Init Ready!\n");
        process.switchToProcess(init_proc);
    }

    var system_shell: shell.Shell = undefined;
    createDemoProcesses();
    initializeShell(&system_shell);

    console.print("\nFalling back to kernel shell.\n");
    console.print("ZigOS Shell Ready!\n");
    system_shell.printPrompt();

    asm volatile ("sti");

    while (system_shell.running) {
        asm volatile ("hlt");
    }

    enterIdleLoop();
}

fn runVmProfile() noreturn {
    console.print("Running VM tests...\n");

    const vm_test = @import("tests/vm_test.zig");
    if (vm_test.test_virtual_memory()) {
        printBootMarker("TEST:VM:PASS");
        qemu_exit.success();
    }

    printBootMarker("TEST:VM:FAIL");
    qemu_exit.failure();
}

fn runBenchmarkProfile() noreturn {
    console.print("Running kernel benchmarks...\n");
    if (benchmark_suite.run()) {
        qemu_exit.success();
    }
    qemu_exit.failure();
}

fn printSmpStats() void {
    const stats = scheduler.getStatistics();
    var line_buf: [192]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "SMP:STATS:context_switches={d}:ready={d}:blocked={d}:cpu_usage={d}\n",
        .{ stats.context_switches, stats.ready_processes, stats.blocked_processes, stats.cpu_usage_percent },
    ) catch "SMP:STATS\n";
    console.print(line);
}

fn printUserlandStepEvent(marker: []const u8, phase: []const u8) void {
    var line_buf: [96]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "USERLAND:STEP:{s}:{s}\n", .{ phase, marker }) catch "USERLAND:STEP\n";
    console.print(line);
}

fn runUserlandSmokeStep(smoke_shell: *shell.Shell, command: []const u8, marker: []const u8) bool {
    printUserlandStepEvent(marker, "START");
    if (!smoke_shell.runCommandLine(command)) {
        printUserlandStepEvent(marker, "FAIL");
        return false;
    }
    printBootMarker(marker);
    return true;
}

fn runSmpStressProfile() noreturn {
    const task_entries = [_]struct {
        name: []const u8,
        priority: scheduler.Priority,
    }{
        .{ .name = "smp-stress-0", .priority = .High },
        .{ .name = "smp-stress-1", .priority = .Normal },
        .{ .name = "smp-stress-2", .priority = .Low },
        .{ .name = "smp-stress-3", .priority = .High },
        .{ .name = "smp-stress-4", .priority = .Normal },
        .{ .name = "smp-stress-5", .priority = .Low },
    };
    var stress_processes: [smp_stress_task_count]*process.Process = undefined;
    var sink: u32 = 0;

    const runner = process.create_kernel_process("smp_stress_runner", idle_task_placeholder);
    process.adoptAsCurrent(runner);

    console.print("Running SMP scheduler stress...\n");
    printBootMarker("SMP:START");
    console.print("SMP:ACTIVE_CPUS:");
    printCpuCount(smp.getActiveCPUCount());
    console.print("\n");

    scheduler.setSchedulerType(.MultiLevelFeedback);

    for (task_entries, 0..) |task, idx| {
        const proc = process.create_kernel_process_any_cpu(task.name, idle_task_placeholder);
        _ = scheduler.setProcessPriority(proc.pid, task.priority);
        stress_processes[idx] = proc;
    }
    printBootMarker("SMP:TASKS_CREATED");

    for (0..smp_stress_rounds) |round| {
        const proc = stress_processes[round % stress_processes.len];
        const next_priority = task_entries[(round + 1) % task_entries.len].priority;
        _ = scheduler.setProcessPriority(proc.pid, next_priority);
        _ = scheduler.setProcessNice(proc.pid, @intCast(@as(i32, @intCast(round % 3)) - 1));

        if ((round & 1) == 0) {
            scheduler.blockProcess(proc);
            scheduler.unblockProcess(proc);
        }

        if (scheduler.tryScheduleLocalForCPU(0)) |selected| {
            sink +%= selected.pid;
        }
    }

    std.mem.doNotOptimizeAway(&sink);

    printBootMarker("SMP:TASKS_DONE");
    printSmpStats();

    if (scheduler.getStatistics().context_switches < 16) {
        printBootMarker("SMP:FAIL");
        qemu_exit.failure();
    }

    printBootMarker("SMP:PASS");
    qemu_exit.success();
}

fn userlandSmokeRunner() callconv(.c) void {
    var smoke_shell = shell.Shell.init();
    const commands = [_]struct {
        command: []const u8,
        marker: []const u8,
    }{
        .{ .command = "/bin/hello", .marker = "USERLAND:HELLO" },
        .{ .command = "/bin/echo USERLAND:ECHO", .marker = "USERLAND:ECHO" },
        .{ .command = "/bin/echo user:$USER home:${HOME}", .marker = "USERLAND:ENV" },
        .{ .command = "/bin/echo shell-$(/bin/uname)", .marker = "USERLAND:CMDSUB" },
        .{ .command = "/bin/echo \"USERLAND QUOTED\"", .marker = "USERLAND:QUOTED" },
        .{ .command = "/bin/echo USERLAND\\ ESCAPED", .marker = "USERLAND:ESCAPED" },
        .{ .command = "/bin/echo /bin/c* /bin/l?", .marker = "USERLAND:GLOB" },
        .{ .command = "/bin/uname", .marker = "USERLAND:UNAME" },
        .{ .command = "/bin/ls /bin", .marker = "USERLAND:LS" },
        .{ .command = "/bin/cat /etc/motd", .marker = "USERLAND:CAT" },
        .{ .command = "/bin/env", .marker = "USERLAND:ENV_STANDALONE" },
        .{ .command = "/bin/env | /bin/grep PATH=", .marker = "USERLAND:ENV_BIN" },
        .{ .command = "/bin/which ls", .marker = "USERLAND:WHICH" },
        .{ .command = "/bin/head /etc/motd", .marker = "USERLAND:HEAD" },
        .{ .command = "/bin/tail /etc/motd", .marker = "USERLAND:TAIL" },
        .{ .command = "/bin/wc /etc/motd", .marker = "USERLAND:WC" },
        .{ .command = "/bin/sort /etc/motd", .marker = "USERLAND:SORT" },
        .{ .command = "/bin/uniq /etc/motd", .marker = "USERLAND:UNIQ" },
        .{ .command = "/bin/hexdump /etc/motd", .marker = "USERLAND:HEXDUMP" },
        .{ .command = "/bin/test -e /etc/motd", .marker = "USERLAND:TEST" },
        .{ .command = "/bin/true", .marker = "USERLAND:TRUE" },
        .{ .command = "/bin/cp /etc/motd /tmp/motd.copy", .marker = "USERLAND:CP" },
        .{ .command = "/bin/mv /tmp/motd.copy /tmp/motd.moved", .marker = "USERLAND:MV" },
        .{ .command = "/bin/grep ZigOS /tmp/motd.moved", .marker = "USERLAND:GREP" },
        .{ .command = "/bin/chmod 600 /tmp/motd.moved", .marker = "USERLAND:CHMOD" },
        .{ .command = "/bin/chown user /tmp/motd.moved", .marker = "USERLAND:CHOWN" },
        .{ .command = "/bin/ln /etc/motd /motd-caf\xC3\xA9-r\xC3\xA9sum\xC3\xA9-hardlink.txt", .marker = "USERLAND:LN" },
        .{ .command = "/bin/cat /motd-caf\xC3\xA9-r\xC3\xA9sum\xC3\xA9-hardlink.txt", .marker = "USERLAND:CAT_HARD" },
        .{ .command = "/bin/cat /MOTD-CAFE\xCC\x81-RE\xCC\x81SUME\xCC\x81-HARDLINK.TXT", .marker = "USERLAND:CAT_HARD_CI" },
        .{ .command = "/bin/ln -s /etc/motd /motd-caf\xC3\xA9-stra\xC3\x9Fe-symbolic-link.txt", .marker = "USERLAND:LNS" },
        .{ .command = "/bin/cat /motd-caf\xC3\xA9-stra\xC3\x9Fe-symbolic-link.txt", .marker = "USERLAND:CAT_LINK" },
        .{ .command = "/bin/cat /MOTD-CAFE\xCC\x81-STRASSE-SYMBOLIC-LINK.TXT", .marker = "USERLAND:CAT_LINK_CI" },
        .{ .command = "/bin/ps", .marker = "USERLAND:PS" },
        .{ .command = "/bin/ping 1.1.1.1", .marker = "USERLAND:PING" },
        .{ .command = "/bin/whoami", .marker = "USERLAND:WHOAMI" },
        .{ .command = "/bin/id", .marker = "USERLAND:ID" },
        .{ .command = "/bin/date", .marker = "USERLAND:DATE" },
        .{ .command = "/bin/hostname", .marker = "USERLAND:HOSTNAME" },
        .{ .command = "/bin/cat /proc/version", .marker = "USERLAND:PROC_VERSION" },
        .{ .command = "/bin/cat /proc/mounts", .marker = "USERLAND:PROC_MOUNTS" },
        .{ .command = "/bin/cat /sys/kernel/hostname", .marker = "USERLAND:SYS_HOSTNAME" },
        .{ .command = "/bin/echo USERLAND:PIPE | /bin/cat", .marker = "USERLAND:PIPE_OK" },
        .{ .command = "/bin/echo USERLAND:REDIRECT > /tmp/redir.txt", .marker = "USERLAND:REDIRECT_WRITE" },
        .{ .command = "/bin/cat < /tmp/redir.txt", .marker = "USERLAND:REDIRECT_READ" },
    };

    printBootMarker("USERLAND:START");

    for (commands) |step| {
        if (!runUserlandSmokeStep(&smoke_shell, step.command, step.marker)) {
            printBootMarker("USERLAND:FAIL");
            qemu_exit.failure();
        }
    }

    if (!smoke_shell.runCommandLine("/bin/sleep 3 &")) {
        printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    printBootMarker("USERLAND:BG_START");

    if (!smoke_shell.runCommandLine("jobs")) {
        printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    printBootMarker("USERLAND:JOBS_RUNNING");

    const bg_pid = smoke_shell.latestBackgroundPid() orelse {
        printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    };

    if (process.getProcessByPid(bg_pid)) |bg_proc| {
        bg_proc.state = .Stopped;
    } else {
        printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }

    if (!smoke_shell.runCommandLine("jobs")) {
        printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    printBootMarker("USERLAND:JOBS_STOPPED");

    if (!smoke_shell.runCommandLine("bg")) {
        printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    printBootMarker("USERLAND:BG_RESUME");

    if (!smoke_shell.runCommandLine("jobs")) {
        printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    printBootMarker("USERLAND:JOBS_RESUMED");

    printBootMarker("USERLAND:PASS");
    qemu_exit.success();
}

fn runUserlandSmokeProfile() noreturn {
    var shell_instance: shell.Shell = undefined;
    initializeShell(&shell_instance);

    const runner = process.create_kernel_process("userland_smoke_runner", idle_task_placeholder);
    process.adoptAsCurrent(runner);
    userlandSmokeRunner();
    unreachable;
}

fn idle_task_placeholder() void {}

export fn kernel_main() void {
    x86.enableSse();
    vga.init();
    vga.clear();
    console.init();
    printBootMarker("BOOT:START");
    printBootProfile();
    console.print("Welcome to ZigOS!\n");
    console.print("A minimal operating system written in Zig\n");

    initCore();
    initDevices();
    if (config.shouldInitNetworkStack()) {
        initNetworkStack();
    }
    initFileSystems();
    initRuntime();

    printBootMarker("BOOT:CORE_READY");

    switch (config.bootProfile()) {
        .dev => runDevProfile(),
        .ci_smoke => {
            var system_shell: shell.Shell = undefined;

            initializeShell(&system_shell);
            printBootMarker("BOOT:PASS");
            qemu_exit.success();
        },
        .test_vm => runVmProfile(),
        .benchmark => runBenchmarkProfile(),
        .smp_stress => runSmpStressProfile(),
        .userland_smoke => runUserlandSmokeProfile(),
    }
}
