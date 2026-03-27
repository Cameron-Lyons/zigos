const console = @import("../../utils/console.zig");
const config = @import("../../config.zig");
const device = @import("../../devices/device.zig");
const console_device = @import("../../devices/console_device.zig");
const ata = @import("../../drivers/ata.zig");
const pci = @import("../../drivers/pci.zig");
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
}

pub fn startDeferredRuntimeInit() void {
    // Native-only bootstrap no longer schedules legacy kernel process-based init work.
}
