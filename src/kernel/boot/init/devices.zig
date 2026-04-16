const console = @import("../../utils/console.zig");
const config = @import("../../config.zig");
const device = @import("../../devices/device.zig");
const console_device = @import("../../devices/console_device.zig");
const ata = @import("../../drivers/ata.zig");
const e1000 = @import("../../drivers/e1000.zig");
const pci = @import("../../drivers/pci.zig");
const rtl8139 = @import("../../drivers/rtl8139.zig");
const virtio = @import("../../drivers/virtio.zig");
const bootstrap_driver_port = @import("../../../native/drivers/bootstrap_driver_port.zig");
const device_broker = @import("../../../native/kernel_api/device_broker.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");
const storage_driver_protocol = @import("../../../native/drivers/storage_driver_protocol.zig");
const panic_handler = @import("../../utils/panic.zig");
const common = @import("../common.zig");

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
    publishStorageBootstrapBackend();
    console.print("Device drivers ready!\n");

    if (config.shouldInitRuntimeExtras() or config.shouldInitAcpi()) {
        console.print("Deferring PCI inventory scan and optional device init...\n");
    } else {
        console.print("Scanning PCI bus...\n");
        pci.scanBus();
    }
}

pub fn startDeferredRuntimeInit() void {
    console.print("Publishing deferred native driver transports...\n");
    publishDeferredNetworkBootstrap();
}

fn captureAtaBootstrapInventory() void {
    if (ata.firstDetectedDevice()) |drive| {
        device_inventory.registerDetected(.storage_controller, ata.stableDeviceId(drive), .ata_bootstrap, true);
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

fn publishStorageBootstrapBackend() void {
    const storage_record = device_inventory.recordForClass(.storage_controller);
    if (!storage_record.detected) return;
    if (storage_record.source != .ata_bootstrap) return;
    const drive = ata.findDetectedDeviceByStableId(storage_record.device_id) orelse return;
    _ = device_broker.publishAtaController(storage_record.device_id, ataBrokerGrant(drive));
    _ = bootstrap_driver_port.publishStorageAtaBootstrap(
        storage_record.device_id,
        "ata-bootstrap",
        true,
    );
}

fn publishDeferredNetworkBootstrap() void {
    const network_record = device_inventory.recordForClass(.network_adapter);
    if (!network_record.detected) return;

    if (virtio.publishBootstrapTransport(network_record.device_id)) return;
    if (e1000.publishBootstrapTransport(network_record.device_id)) return;
    if (rtl8139.publishBootstrapTransport(network_record.device_id)) return;
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
