const vga = @import("drivers/vga.zig");
const console = @import("utils/console.zig");
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

export fn kernel_main() void {
    vga.init();
    vga.clear();
    console.init(); // Initialize serial port early
    console.print("Welcome to ZigOS!\n");
    console.print("A minimal operating system written in Zig\n");

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

    console.print("Enabling kernel memory protection...\n");
    const protection = @import("memory/protection.zig");
    protection.protectKernelMemory();

    console.print("Initializing memory allocator...\n");
    memory.init();

    console.print("Initializing advanced memory management...\n");
    const memory_pool = @import("memory/memory_pool.zig");
    memory_pool.init();

    console.print("Initializing environment variables...\n");
    const environ = @import("utils/environ.zig");
    environ.init();

    console.print("Initializing device drivers...\n");
    device.init();
    console_device.init() catch |err| {
        panic_handler.panic("Failed to initialize console device: {}", .{err});
    };
    ata.init();
    console.print("Device drivers ready!\n");

    console.print("Scanning PCI bus...\n");
    pci.scanBus();

    console.print("Initializing ACPI...\n");
    acpi.init();

    console.print("Initializing SMP (multicore) support...\n");
    const smp = @import("smp/smp.zig");
    smp.init();
    if (smp.isSMPEnabled()) {
        console.print("SMP enabled with ");
        const num_cpus = smp.getNumCPUs();
        // SAFETY: filled by the following digit extraction loop
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

    console.print("Initializing network...\n");
    e1000.init();
    if (!e1000.isInitialized()) {
        virtio.init();
        if (!virtio.isInitialized()) {
            rtl8139.init();
        }
    }
    network.init();

    console.print("Initializing socket API...\n");
    const socket = @import("net/socket.zig");
    socket.init();

    console.print("Initializing DNS client...\n");
    const dns = @import("net/dns.zig");
    dns.init();

    console.print("Initializing DHCP client...\n");
    const dhcp = @import("net/dhcp.zig");
    dhcp.init();

    console.print("Initializing routing table...\n");
    const routing = @import("net/routing.zig");
    routing.init();

    console.print("Initializing Virtual File System...\n");
    vfs.init();
    console.print("VFS ready!\n");

    console.print("Initializing file operations...\n");
    file_ops.init();

    console.print("Initializing memory mapping...\n");
    mmap.init();

    console.print("Initializing FAT32 file system...\n");
    fat32.init();
    console.print("FAT32 ready!\n");

    console.print("Initializing ext2 file system...\n");
    ext2.init();

    if (ata.getPrimaryMaster()) |_| {
        console.print("Mounting primary master as FAT32...\n");
        vfs.mount("ata0", "/mnt", "fat32", 0) catch |err| {
            console.print("Failed to mount: ");
            console.print(@errorName(err));
            console.print("\n");
        };
    }

    console.print("Running VM tests...\n");
    const vm_test = @import("tests/vm_test.zig");
    vm_test.test_virtual_memory();

    console.print("Initializing process management...\n");
    process.init();

    console.print("Initializing process monitoring...\n");
    const procmon = @import("tests/procmon.zig");
    procmon.init();

    console.print("Initializing timer...\n");
    timer.init(100);

    console.print("Initializing keyboard...\n");
    keyboard.init();
    console.print("Keyboard ready!\n");

    console.print("Initializing USB...\n");
    usb.init();

    console.print("Initializing audio...\n");
    ac97.init();

    console.print("Initializing virtual terminals...\n");
    vt.init();

    console.print("Initializing graphics mode (framebuffer)...\n");
    _ = @import("devices/framebuffer.zig");
    console.print("Framebuffer support ready (requires multiboot framebuffer info)\n");

    console.print("Creating test processes...\n");
    _ = process.create_process("test1", test_process1);
    _ = process.create_process("test2", test_process2);
    _ = process.create_process("syscall_test", test_syscall.test_syscall_process);

    const userspace = @import("process/userspace.zig");
    userspace.createUserTestProcess();

    const ring3 = @import("process/ring3.zig");
    ring3.createRing3TestProcess();

    console.print("Initializing user programs...\n");
    const user_programs = @import("process/user_programs.zig");
    user_programs.init();

    console.print("Initializing shell...\n");
    var system_shell = shell.Shell.init();
    keyboard.setShell(&system_shell);

    asm volatile ("sti");

    console.print("\nZigOS Shell Ready!\n");
    system_shell.printPrompt();

    while (system_shell.running) {
        asm volatile ("hlt");
    }
}
