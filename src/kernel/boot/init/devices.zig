const console = @import("../../utils/console.zig");
const config = @import("../../config.zig");
const device = @import("../../devices/device.zig");
const console_device = @import("../../devices/console_device.zig");
const ata = @import("../../drivers/ata.zig");
const pci = @import("../../drivers/pci.zig");
const bootstrap_driver_port = @import("../../../native/drivers/bootstrap_driver_port.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");
const storage_driver_protocol = @import("../../../native/drivers/storage_driver_protocol.zig");
const panic_handler = @import("../../utils/panic.zig");
const common = @import("../common.zig");

pub const kernel_boundary_role = "bootstrap_device_inventory_shim";
pub const publishes_device_data_planes = false;

pub fn init() void {
    console.print("Initializing device drivers...\n");
    bootstrap_driver_port.reset();
    device_inventory.reset();
    device.init();
    console_device.init() catch |err| {
        panic_handler.panic("Failed to initialize console device: {}", .{err});
    };
    ata.init();
    captureAtaBootstrapInventory();
    capturePciInventory();
    console.print("Bootstrap device inventory ready!\n");

    if (config.shouldInitRuntimeExtras()) {
        console.print("Deferring optional device init after PCI inventory capture...\n");
    } else {
        console.print("PCI data planes remain unpublished until userspace driver claims.\n");
    }
}

pub fn startDeferredRuntimeInit() void {
    console.print("Deferred runtime keeps device data planes behind userspace drivers...\n");
    publishDeferredNetworkBootstrap();
}

fn captureAtaBootstrapInventory() void {
    if (ata.firstDetectedDevice()) |drive| {
        device_inventory.registerDetected(.storage_controller, ata.stableDeviceId(drive), .ata_bootstrap, true);
        device_inventory.recordAtaBootstrapGrant(ata.stableDeviceId(drive), ataBrokerGrant(drive));
    }
}

fn capturePciInventory() void {
    if (pci.firstDeviceByClass(0x02)) |dev| {
        device_inventory.registerDetected(.network_adapter, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstDeviceByClass(0x03)) |dev| {
        device_inventory.registerDetected(.graphics_adapter, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstDeviceByClass(0x04)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    } else if (pci.firstDeviceByClass(0x07)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    }
    if (!device_inventory.recordForClass(.storage_controller).detected) {
        if (pci.firstDeviceByClass(0x01)) |dev| {
            device_inventory.registerDetected(.storage_controller, pciDeviceId(dev), .pci_inventory, false);
        }
    }
}

fn publishDeferredNetworkBootstrap() void {
    const network_record = device_inventory.recordForClass(.network_adapter);
    if (!network_record.detected) return;
    // Network adapters are deliberately left as user-space driver claims. Kernel
    // boot records inventory only; it does not publish NIC data-plane transports.
}

fn pciDeviceId(device_info: pci.PCIDevice) u64 {
    return pci.stableDeviceId(device_info);
}

fn ataBrokerGrant(drive: *const ata.ATADevice) storage_driver_protocol.AtaBrokerGrant {
    return .{
        .base_port = drive.base_port,
        .ctrl_port = drive.ctrl_port,
        .is_master = drive.is_master,
        .irq_line = if (drive.base_port == 0x170) 15 else 14,
        .sector_count = drive.sectors,
    };
}
