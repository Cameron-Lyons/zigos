const console = @import("../../utils/console.zig");
const config = @import("../../config.zig");
const ata = @import("../../drivers/ata.zig");
const first_target_telemetry = @import("../../drivers/first_target_telemetry.zig");
const pci = @import("../../drivers/pci.zig");
const nvme_hw = @import("../../drivers/nvme_hw.zig");
const bootstrap_driver_port = @import("../../../native/drivers/bootstrap_driver_port.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");
const storage_driver_protocol = @import("../../../native/drivers/storage_driver_protocol.zig");
const common = @import("../common.zig");
const data_plane_boundary = @import("data_plane_boundary.zig");
const hardware_proof = @import("../../platform/hardware_proof.zig");
const handoff = @import("../handoff.zig");

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
pub const first_target_telemetry_driver_role = first_target_telemetry.kernel_boundary_role;
pub const first_target_telemetry_requires_acpi_fadt_base = first_target_telemetry.requires_acpi_fadt_base;
pub const first_target_telemetry_requires_complete_source_registry = true;
pub const first_target_telemetry_supports_independent_provider_slots = true;
pub const first_target_telemetry_supports_hardware_proof_provider_slots = true;
pub const PublicationRequest = data_plane_boundary.PublicationRequest;
pub const SubsystemPublicationRequest = data_plane_boundary.SubsystemPublicationRequest;
pub const DataPlaneKind = data_plane_boundary.DataPlaneKind;

pub fn init() void {
    console.print("Initializing device drivers...\n");
    bootstrap_driver_port.reset();
    device_inventory.reset();
    // QEMU "modeled" test boots cannot expose the exact first-target Intel
    // devices, so explicit test profiles request a modeled inventory seed.
    // Native QEMU paths that cannot pass `-append` reliably also fall back to
    // modeled inventory only when first-target network hardware is absent.
    // Real freestanding hardware keeps strict detected-inventory binding.
    ata.init();
    captureAtaBootstrapInventory();
    capturePciInventory();
    hardware_proof.capturePciEvidence();
    const model_via_cmdline = if (handoff.capturedInfo()) |info|
        handoff.commandLineContains(info, "model_inventory")
    else
        false;
    device_inventory.setModelDeviceInventory(
        shouldEnableModelDeviceInventory(model_via_cmdline),
    );
    if (!device_inventory.recordForClass(.compositor_policy).detected) {
        device_inventory.registerDetected(.compositor_policy, 0xC0DE_9001, .platform_policy, false);
    }
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

fn shouldEnableModelDeviceInventory(model_via_cmdline: bool) bool {
    if (config.smokeFaultMode() != .none or model_via_cmdline) return true;
    // The direct multiboot QEMU path does not reliably surface `-append`
    // before service bootstrap. The first supported hardware target exposes an
    // Intel I225-LM inventory record, so a native profile without that record is
    // treated as modeled QEMU inventory rather than production hardware proof.
    if (config.bootProfile() == .zigos_native) {
        return !device_inventory.recordForClass(.network_adapter).detected;
    }
    return false;
}

fn captureAtaBootstrapInventory() void {
    if (ata.firstDetectedDevice()) |drive| {
        device_inventory.registerDetected(.storage_controller, ata.stableDeviceId(drive), .ata_bootstrap, true);
        device_inventory.recordAtaBootstrapGrant(ata.stableDeviceId(drive), ataBrokerGrant(drive));
    }
}

fn capturePciInventory() void {
    if (pci.firstIntelI225Lm()) |dev| {
        device_inventory.registerDetected(.network_adapter, pciDeviceId(dev), .intel_i225_lm_inventory, false);
    }
    if (pci.firstDeviceByClass(PCI_CLASS_GRAPHICS_ADAPTER)) |dev| {
        device_inventory.registerDetected(.graphics_adapter, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstXhciController()) |dev| {
        const xhci_device_id = pciDeviceId(dev);
        device_inventory.registerDetected(.usb_controller, xhci_device_id, .xhci_inventory, false);
        device_inventory.registerDetected(.input_device, xhci_device_id, .xhci_inventory, false);
    }
    if (pci.firstDeviceByClass(PCI_CLASS_MULTIMEDIA_CONTROLLER)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    } else if (pci.firstDeviceByClass(PCI_CLASS_SIMPLE_COMMUNICATIONS_CONTROLLER)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    }
    // Always probe NVMe even after an ATA bootstrap record exists: a detected
    // NVMe controller promotes the storage record away from the non-production
    // ATA bootstrap observation. device_inventory.registerDetected keeps the
    // higher-grade NVMe binding and never downgrades back to ATA, so probing
    // unconditionally is the only way the documented promotion path runs on
    // machines that expose both an ATA disk and the target NVMe controller.
    if (pci.firstNvmeController()) |dev| {
        device_inventory.registerDetected(.storage_controller, pciDeviceId(dev), .nvme_pci_inventory, false);
        nvme_hw.probeAndReport(dev);
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
