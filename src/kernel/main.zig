const vga = @import("vga.zig");
const boot = @import("../boot/boot.zig");
const isr = @import("isr.zig");
const keyboard = @import("keyboard.zig");
const paging = @import("paging.zig");
const timer = @import("timer.zig");
const process = @import("process.zig");
const shell = @import("shell.zig");
const syscall = @import("syscall.zig");
const test_syscall = @import("test_syscall.zig");
const memory = @import("memory.zig");
const panic_handler = @import("panic.zig");
const error_handler = @import("error.zig");
const device = @import("device.zig");
const console_device = @import("console_device.zig");
const vfs = @import("vfs.zig");
const ata = @import("ata.zig");
const fat32 = @import("fat32.zig");
const pci = @import("pci.zig");
const rtl8139 = @import("rtl8139.zig");
const e1000 = @import("e1000.zig");
const virtio = @import("virtio.zig");
const network = @import("network.zig");
const usb = @import("usb.zig");
const acpi = @import("acpi.zig");
const ac97 = @import("ac97.zig");
const ext2 = @import("ext2.zig");
const signals = @import("signal.zig");
const vt = @import("vt.zig");
const mmap = @import("mmap.zig");
const file_ops = @import("file_ops.zig");

fn test_process1() void {
    var i: u32 = 0;
    while (true) : (i += 1) {
        if (i % 1000000 == 0) {
            vga.print("A");
        }
        process.yield();
    }
}

fn test_process2() void {
    var i: u32 = 0;
    while (true) : (i += 1) {
        if (i % 1000000 == 0) {
            vga.print("B");
        }
        process.yield();
    }
}

export fn kernel_main() void {
    vga.init();
    vga.clear();
    vga.print("Welcome to ZigOS!\n");
    vga.print("A minimal operating system written in Zig\n");

    vga.print("Initializing GDT...\n");
    const gdt = @import("gdt.zig");
    gdt.init();
    vga.print("GDT initialized!\n");

    vga.print("Initializing interrupts...\n");
    isr.init();
    vga.print("Interrupts enabled!\n");

    vga.print("Initializing system calls...\n");
    syscall.init();
    vga.print("System calls ready!\n");

    vga.print("Initializing paging...\n");
    paging.init();

    vga.print("Enabling kernel memory protection...\n");
    const protection = @import("protection.zig");
    protection.protectKernelMemory();

    vga.print("Initializing memory allocator...\n");
    memory.init();

    vga.print("Initializing advanced memory management...\n");
    const memory_pool = @import("memory_pool.zig");
    memory_pool.init();

    vga.print("Initializing environment variables...\n");
    const environ = @import("environ.zig");
    environ.init();

    vga.print("Initializing device drivers...\n");
    device.init();
    console_device.init() catch |err| {
        panic_handler.panic("Failed to initialize console device: {}", .{err});
    };
    ata.init();
    vga.print("Device drivers ready!\n");

    vga.print("Scanning PCI bus...\n");
    pci.scanBus();

    vga.print("Initializing ACPI...\n");
    acpi.init();

    vga.print("Initializing SMP (multicore) support...\n");
    const smp = @import("smp.zig");
    smp.init();
    if (smp.isSMPEnabled()) {
        vga.print("SMP enabled with ");
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
        vga.print(cpu_str[0..idx]);
        vga.print(" CPUs\n");
    } else {
        vga.print("Single CPU mode\n");
    }

    vga.print("Initializing network...\n");
    e1000.init();
    if (!e1000.isInitialized()) {
        virtio.init();
        if (!virtio.isInitialized()) {
            rtl8139.init();
        }
    }
    network.init();

    vga.print("Initializing socket API...\n");
    const socket = @import("socket.zig");
    socket.init();

    vga.print("Initializing DNS client...\n");
    const dns = @import("dns.zig");
    dns.init();

    vga.print("Initializing DHCP client...\n");
    const dhcp = @import("dhcp.zig");
    dhcp.init();

    vga.print("Initializing routing table...\n");
    const routing = @import("routing.zig");
    routing.init();

    vga.print("Initializing Virtual File System...\n");
    vfs.init();
    vga.print("VFS ready!\n");

    vga.print("Initializing file operations...\n");
    file_ops.init();

    vga.print("Initializing memory mapping...\n");
    mmap.init();

    vga.print("Initializing FAT32 file system...\n");
    fat32.init();
    vga.print("FAT32 ready!\n");

    vga.print("Initializing ext2 file system...\n");
    ext2.init();

    if (ata.getPrimaryMaster()) |_| {
        vga.print("Mounting primary master as FAT32...\n");
        vfs.mount("ata0", "/mnt", "fat32", 0) catch |err| {
            vga.print("Failed to mount: ");
            vga.print(@errorName(err));
            vga.print("\n");
        };
    }

    vga.print("Running VM tests...\n");
    const vm_test = @import("vm_test.zig");
    vm_test.test_virtual_memory();

    vga.print("Initializing process management...\n");
    process.init();

    vga.print("Initializing process monitoring...\n");
    const procmon = @import("procmon.zig");
    procmon.init();

    vga.print("Initializing timer...\n");
    timer.init(100);

    vga.print("Initializing keyboard...\n");
    keyboard.init();
    vga.print("Keyboard ready!\n");

    vga.print("Initializing USB...\n");
    usb.init();

    vga.print("Initializing audio...\n");
    ac97.init();

    vga.print("Initializing virtual terminals...\n");
    vt.init();

    vga.print("Initializing graphics mode (framebuffer)...\n");
    _ = @import("framebuffer.zig");
    vga.print("Framebuffer support ready (requires multiboot framebuffer info)\n");

    vga.print("Creating test processes...\n");
    _ = process.create_process("test1", test_process1);
    _ = process.create_process("test2", test_process2);
    _ = process.create_process("syscall_test", test_syscall.test_syscall_process);

    const userspace = @import("userspace.zig");
    userspace.createUserTestProcess();

    const ring3 = @import("ring3.zig");
    ring3.createRing3TestProcess();

    vga.print("Initializing user programs...\n");
    const user_programs = @import("user_programs.zig");
    user_programs.init();

    vga.print("Initializing shell...\n");
    var system_shell = shell.Shell.init();
    keyboard.setShell(&system_shell);

    asm volatile ("sti");

    vga.print("\nZigOS Shell Ready!\n");
    system_shell.printPrompt();

    while (system_shell.running) {
        asm volatile ("hlt");
    }
}
