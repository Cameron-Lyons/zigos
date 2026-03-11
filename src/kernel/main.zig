const vga = @import("drivers/vga.zig");
const x86 = @import("../arch/x86.zig");
const console = @import("utils/console.zig");
const config = @import("config.zig");
const isr = @import("interrupts/isr.zig");
const keyboard = @import("drivers/keyboard.zig");
const paging = @import("memory/paging.zig");
const timer = @import("timer/timer.zig");
const process = @import("process/process.zig");
const shell = @import("shell/shell.zig");
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
const e1000 = @import("drivers/e1000.zig");
const virtio = @import("drivers/virtio.zig");
const network = @import("net/network.zig");
const usb = @import("drivers/usb.zig");
const acpi = @import("acpi/acpi.zig");
const ac97 = @import("drivers/ac97.zig");
const ext2 = @import("fs/ext2.zig");
const vt = @import("devices/vt.zig");
const mmap = @import("memory/mmap.zig");
const file_ops = @import("fs/file_ops.zig");
const swap = @import("memory/swap.zig");
const credentials = @import("process/credentials.zig");
const tmpfs = @import("fs/tmpfs.zig");
const uhci = @import("drivers/uhci.zig");
const ipv6 = @import("net/ipv6.zig");
const icmpv6 = @import("net/icmpv6.zig");
const icmp = @import("net/icmp.zig");
const devfs = @import("fs/devfs.zig");
const embedfs = @import("fs/embedfs.zig");

fn test_process1() void {
    var i: u32 = 0;
    while (true) : (i += 1) {
        if (i % 1000000 == 0) {
            console.print("A");
        }
        process.yield();
    }
}

fn test_process2() void {
    var i: u32 = 0;
    while (true) : (i += 1) {
        if (i % 1000000 == 0) {
            console.print("B");
        }
        process.yield();
    }
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

    console.print("Scanning PCI bus...\n");
    pci.scanBus();

    if (config.shouldInitAcpi()) {
        console.print("Initializing ACPI...\n");
        acpi.init();
    }

    if (config.shouldInitSmp()) {
        console.print("Initializing SMP (multicore) support...\n");
        const smp = @import("smp/smp.zig");
        smp.init();
        if (smp.isSMPEnabled()) {
            console.print("SMP enabled with ");
            const num_cpus = smp.getNumCPUs();
            var cpu_str: [10]u8 = undefined;
            var cpu_count = num_cpus;
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
            console.print(" CPUs\n");
        } else {
            console.print("Single CPU mode\n");
        }
    }
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

    console.print("Initializing file operations...\n");
    file_ops.init();

    console.print("Initializing memory mapping...\n");
    mmap.init();
}

fn initRuntime() void {
    console.print("Initializing credentials...\n");
    credentials.init();

    console.print("Initializing process management...\n");
    process.init();

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

    if (config.shouldInitRuntimeExtras()) {
        console.print("Initializing USB...\n");
        usb.init();

        console.print("Initializing UHCI...\n");
        uhci.init();

        console.print("Initializing audio...\n");
        ac97.init();

        console.print("Initializing virtual terminals...\n");
        vt.init();

        console.print("Initializing graphics mode (framebuffer)...\n");
        _ = @import("devices/framebuffer.zig");
        console.print("Framebuffer support ready (requires multiboot framebuffer info)\n");
    }
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

fn userlandSmokeRunner() callconv(.c) void {
    var smoke_shell = shell.Shell.init();
    const commands = [_]struct {
        command: []const u8,
        marker: []const u8,
    }{
        .{ .command = "/bin/hello", .marker = "USERLAND:HELLO" },
        .{ .command = "/bin/echo USERLAND:ECHO", .marker = "USERLAND:ECHO" },
        .{ .command = "/bin/echo \"USERLAND QUOTED\"", .marker = "USERLAND:QUOTED" },
        .{ .command = "/bin/echo USERLAND\\ ESCAPED", .marker = "USERLAND:ESCAPED" },
        .{ .command = "/bin/echo /bin/c* /bin/l?", .marker = "USERLAND:GLOB" },
        .{ .command = "/bin/uname", .marker = "USERLAND:UNAME" },
        .{ .command = "/bin/ls /bin", .marker = "USERLAND:LS" },
        .{ .command = "/bin/cat /etc/motd", .marker = "USERLAND:CAT" },
        .{ .command = "/bin/echo USERLAND:PIPE | /bin/cat", .marker = "USERLAND:PIPE_OK" },
        .{ .command = "/bin/echo USERLAND:REDIRECT > /tmp/redir.txt", .marker = "USERLAND:REDIRECT_WRITE" },
        .{ .command = "/bin/cat < /tmp/redir.txt", .marker = "USERLAND:REDIRECT_READ" },
    };

    printBootMarker("USERLAND:START");

    for (commands) |step| {
        if (!smoke_shell.runCommandLine(step.command)) {
            printBootMarker("USERLAND:FAIL");
            qemu_exit.failure();
        }
        printBootMarker(step.marker);
    }

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
        .dev => {
            var system_shell: shell.Shell = undefined;

            createDemoProcesses();
            initializeShell(&system_shell);

            asm volatile ("sti");

            console.print("\nZigOS Shell Ready!\n");
            system_shell.printPrompt();

            while (system_shell.running) {
                asm volatile ("hlt");
            }
        },
        .ci_smoke => {
            var system_shell: shell.Shell = undefined;

            initializeShell(&system_shell);
            printBootMarker("BOOT:PASS");
            qemu_exit.success();
        },
        .test_vm => runVmProfile(),
        .userland_smoke => runUserlandSmokeProfile(),
    }
}
