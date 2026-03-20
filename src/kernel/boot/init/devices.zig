const console = @import("../../utils/console.zig");
const config = @import("../../config.zig");
const device = @import("../../devices/device.zig");
const console_device = @import("../../devices/console_device.zig");
const ata = @import("../../drivers/ata.zig");
const pci = @import("../../drivers/pci.zig");
const smp = @import("../../smp/smp.zig");
const acpi = @import("../../acpi/acpi.zig");
const usb = @import("../../drivers/usb.zig");
const uhci = @import("../../drivers/uhci.zig");
const ac97 = @import("../../drivers/ac97.zig");
const vt = @import("../../devices/vt.zig");
const process = @import("../../process/process.zig");
const scheduler = @import("../../process/scheduler.zig");
const panic_handler = @import("../../utils/panic.zig");
const common = @import("../common.zig");

pub fn init() void {
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
            common.printCpuCount(smp.getNumCPUs());
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

pub fn startDeferredRuntimeInit() void {
    if (!config.shouldInitRuntimeExtras() and !config.shouldInitAcpi()) return;

    console.print("Scheduling deferred runtime initialization...\n");
    const init_proc = process.create_kernel_process_any_cpu("runtime-init", deferredRuntimeInitTask);
    _ = scheduler.setProcessPriority(init_proc.pid, .Low);
}
