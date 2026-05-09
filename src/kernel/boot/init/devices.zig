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
const data_plane_boundary = @import("data_plane_boundary.zig");

const PCI_CLASS_STORAGE_CONTROLLER: u8 = 0x01;
const PCI_CLASS_NETWORK_ADAPTER: u8 = 0x02;
const PCI_CLASS_GRAPHICS_ADAPTER: u8 = 0x03;
const PCI_CLASS_MULTIMEDIA_CONTROLLER: u8 = 0x04;
const PCI_CLASS_SIMPLE_COMMUNICATIONS_CONTROLLER: u8 = 0x07;
const ATA_SECONDARY_BASE_PORT: u16 = 0x170;
const ATA_PRIMARY_IRQ_LINE: u8 = 14;
const ATA_SECONDARY_IRQ_LINE: u8 = 15;

pub const kernel_boundary_role = data_plane_boundary.kernel_boundary_role;
pub const publishes_device_data_planes = data_plane_boundary.publishes_device_data_planes;
pub const publishes_windowing_data_plane = data_plane_boundary.publishes_windowing_data_plane;
pub const publishes_package_data_plane = data_plane_boundary.publishes_package_data_plane;
pub const publishes_indexing_data_plane = data_plane_boundary.publishes_indexing_data_plane;
pub const publishes_sync_data_plane = data_plane_boundary.publishes_sync_data_plane;
pub const rejectKernelDeviceDataPlane = data_plane_boundary.rejectKernelDeviceDataPlane;
pub const rejectKernelSubsystemDataPlane = data_plane_boundary.rejectKernelSubsystemDataPlane;
pub const PublicationRequest = data_plane_boundary.PublicationRequest;
pub const SubsystemPublicationRequest = data_plane_boundary.SubsystemPublicationRequest;
pub const DataPlaneKind = data_plane_boundary.DataPlaneKind;

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
    if (pci.firstDeviceByClass(PCI_CLASS_NETWORK_ADAPTER)) |dev| {
        device_inventory.registerDetected(.network_adapter, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstDeviceByClass(PCI_CLASS_GRAPHICS_ADAPTER)) |dev| {
        device_inventory.registerDetected(.graphics_adapter, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstDeviceByClass(PCI_CLASS_MULTIMEDIA_CONTROLLER)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    } else if (pci.firstDeviceByClass(PCI_CLASS_SIMPLE_COMMUNICATIONS_CONTROLLER)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    }
    if (!device_inventory.recordForClass(.storage_controller).detected) {
        if (pci.firstDeviceByClass(PCI_CLASS_STORAGE_CONTROLLER)) |dev| {
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
        .irq_line = if (drive.base_port == ATA_SECONDARY_BASE_PORT) ATA_SECONDARY_IRQ_LINE else ATA_PRIMARY_IRQ_LINE,
        .sector_count = drive.sectors,
    };
}
