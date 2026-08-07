const console = @import("../../utils/console.zig");
const config = @import("../../config.zig");
const first_target_telemetry = @import("../../drivers/first_target_telemetry.zig");
const intel_i225_hw = @import("../../drivers/intel_i225_hw.zig");
const pci = @import("../../drivers/pci.zig");
const nvme_hw = @import("../../drivers/nvme_hw.zig");
const xhci_hw = @import("../../drivers/xhci_hw.zig");
const intel_vtd = @import("../../platform/intel_vtd.zig");
const bootstrap_driver_port = @import("../../../native/drivers/bootstrap_driver_port.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");
const common = @import("../common.zig");
const data_plane_boundary = @import("data_plane_boundary.zig");
const hardware_proof = @import("../../platform/hardware_proof.zig");
const handoff = @import("../handoff.zig");

const PCI_CLASS_GRAPHICS_ADAPTER: u8 = 0x03;
const PCI_CLASS_MULTIMEDIA_CONTROLLER: u8 = 0x04;
const PCI_CLASS_SIMPLE_COMMUNICATIONS_CONTROLLER: u8 = 0x07;

var network_prepared = false;
var storage_attached = false;

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
    network_prepared = false;
    storage_attached = false;
    hardware_proof.capturePlatformFirmwareEvidence();
    const ecam_allocation = hardware_proof.pciEcamAllocation() orelse
        @panic("ACPI MCFG is required for PCIe discovery");
    pci.init(ecam_allocation) catch @panic("ACPI MCFG exposed an invalid PCIe ECAM allocation");
    _ = pci.revokeBootBusMasters();
    _ = pci.disableBootMessageSignaledInterrupts() catch
        @panic("PCI capability chain prevented interrupt quiescence");
    if (pci.bootBusMasterCount() != 0) {
        @panic("PCI bus-master revocation failed before device ownership transfer");
    }
    if (pci.bootLegacyInterruptCount() != 0) {
        @panic("PCI INTx quiescence failed before VT-d handoff");
    }
    if ((pci.bootMessageSignaledInterruptCount() catch
        @panic("PCI capability chain prevented interrupt verification")) != 0)
    {
        @panic("PCI message-signaled interrupt quiescence failed before VT-d handoff");
    }

    capturePciInventory();
    hardware_proof.capturePciEvidence();
    const model_via_cmdline = if (handoff.capturedInfo()) |info|
        handoff.commandLineHasFlag(info, "model_inventory")
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
    if (storage_attached) {
        var interrupts_ready = true;
        nvme_hw.activateInterrupts() catch |err| {
            interrupts_ready = false;
            const real_target = hardware_proof.realTargetDetected();
            console.print(if (real_target)
                "ZIGOS:NVME:HW:INTERRUPT_BRINGUP_FAIL "
            else
                "ZIGOS:NVME:HW:INTERRUPT_UNAVAILABLE ");
            console.print(@errorName(err));
            console.print("\n");
            if (real_target) {
                @panic("production NVMe interrupt activation failed closed");
            }
        };
        if (interrupts_ready) console.print("ZIGOS:NVME:HW:REMAP_MSI_OK\n");
    }
    if (network_prepared) {
        if (!storage_attached and hardware_proof.realTargetDetected()) {
            @panic("production I225-LM activation requires the confined storage bootstrap");
        }
        intel_i225_hw.activate() catch |err| {
            console.print("ZIGOS:I225:HW:BRINGUP_FAIL ");
            console.print(@errorName(err));
            console.print("\n");
            if (hardware_proof.realTargetDetected()) {
                @panic("production I225-LM activation failed closed");
            }
            return;
        };
        console.print("ZIGOS:I225:HW:TX_QUEUE_OK\n");
        console.print("ZIGOS:I225:HW:RX_QUEUE_OK\n");
        console.print("ZIGOS:I225:HW:REMAP_MSI_OK\n");
    }
    publishDeferredNetworkBootstrap();
}

fn shouldEnableModelDeviceInventory(model_via_cmdline: bool) bool {
    if (config.smokeFaultMode() != .none or model_via_cmdline) return true;

    if (config.bootProfile() == .zigos_native) {
        return !device_inventory.recordForClass(.network_adapter).detected;
    }
    return false;
}

fn capturePciInventory() void {
    var network_domain: ?intel_vtd.DmaDomain = null;
    if (pci.firstIntelI225Lm()) |dev| {
        device_inventory.registerDetected(.network_adapter, pciDeviceId(dev), .intel_i225_lm_inventory, false);
        intel_i225_hw.prepare(dev) catch |err| {
            console.print("ZIGOS:I225:HW:BRINGUP_FAIL ");
            console.print(@errorName(err));
            console.print("\n");
            if (hardware_proof.realTargetDetected()) {
                @panic("production I225-LM preparation failed closed");
            }
            return;
        };
        network_domain = intel_i225_hw.isolationDomain() orelse
            @panic("I225-LM preparation omitted its DMA isolation domain");
        network_prepared = true;
    }
    if (pci.firstDeviceByClass(PCI_CLASS_GRAPHICS_ADAPTER)) |dev| {
        device_inventory.registerDetected(.graphics_adapter, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstXhciController()) |dev| {
        if (xhci_hw.probe(dev)) |_| {
            const xhci_device_id = pciDeviceId(dev);
            device_inventory.registerDetected(.usb_controller, xhci_device_id, .xhci_inventory, false);
            console.print("ZIGOS:XHCI:HW:CAPABILITY_PROBE_OK\n");
            console.print("ZIGOS:XHCI:HW:OWNERSHIP_OK\n");
            console.print("ZIGOS:XHCI:HW:RESET_OK\n");
        } else |err| {
            console.print("ZIGOS:XHCI:HW:CAPABILITY_PROBE_FAIL ");
            console.print(@errorName(err));
            console.print("\n");
            if (hardware_proof.realTargetDetected()) {
                @panic("production xHCI capability probe failed closed");
            }
        }
    }
    if (pci.firstDeviceByClass(PCI_CLASS_MULTIMEDIA_CONTROLLER)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    } else if (pci.firstDeviceByClass(PCI_CLASS_SIMPLE_COMMUNICATIONS_CONTROLLER)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstNvmeController()) |dev| {
        device_inventory.registerDetected(.storage_controller, pciDeviceId(dev), .nvme_pci_inventory, false);
        var vtd_summary = if (hardware_proof.realTargetDetected())
            hardware_proof.vtdSummary() orelse @panic("validated VT-d firmware is required on the production target")
        else
            null;
        const vtd_summary_ptr = if (vtd_summary) |*summary| summary else null;
        const fault_proof = nvme_hw.probeAndReport(dev, vtd_summary_ptr, network_domain) catch |err| {
            console.print("ZIGOS:NVME:HW:BRINGUP_FAIL ");
            console.print(@errorName(err));
            console.print("\n");
            if (hardware_proof.realTargetDetected()) {
                @panic("production NVMe bring-up failed closed");
            }
            return;
        };
        if (fault_proof) |proof| hardware_proof.recordVtdIsolationProof(proof);
        storage_attached = true;
    }
}

fn publishDeferredNetworkBootstrap() void {
    const network_record = device_inventory.recordForClass(.network_adapter);
    if (!network_record.detected) return;
}

fn pciDeviceId(device_info: pci.PCIDevice) u64 {
    return pci.stableDeviceId(device_info);
}
