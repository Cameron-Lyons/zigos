const std = @import("std");
const console = @import("../../utils/console.zig");
const config = @import("../../config.zig");
const first_target_telemetry = @import("../../drivers/first_target_telemetry.zig");
const intel_i225_hw = @import("../../drivers/intel_i225_hw.zig");
const pci = @import("../../drivers/pci.zig");
const nvme_hw = @import("../../drivers/nvme_hw.zig");
const xhci_hw = @import("../../drivers/xhci_hw.zig");
const intel_vtd = @import("../../platform/intel_vtd.zig");
const bootstrap_driver_port = @import("../../../native/drivers/bootstrap_driver_port.zig");
const device_broker = @import("../../../native/kernel_api/device_broker.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");
const common = @import("../common.zig");
const data_plane_boundary = @import("data_plane_boundary.zig");
const hardware_proof = @import("../../platform/hardware_proof.zig");
const handoff = @import("../handoff.zig");

const PCI_CLASS_GRAPHICS_ADAPTER: u8 = 0x03;
const PCI_CLASS_MULTIMEDIA_CONTROLLER: u8 = 0x04;
const PCI_CLASS_SIMPLE_COMMUNICATIONS_CONTROLLER: u8 = 0x07;

var network_detected = false;
var storage_detected = false;
var xhci_detected = false;
var xhci_prepared = false;
var graphics_started = false;

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
    network_detected = false;
    storage_detected = false;
    xhci_detected = false;
    xhci_prepared = false;
    graphics_started = false;
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
    console.print("Device dataplanes start at userspace driver claim.\n");
}

pub fn startStorageDataplane() bool {
    if (nvme_hw.attached()) return true;
    const dev = pci.firstNvmeController() orelse return true;
    if (!storage_detected) return true;
    var isolation_domains: [2]intel_vtd.DmaDomain = undefined;
    var isolation_domain_count: usize = 0;
    if (intel_i225_hw.isolationDomain()) |domain| {
        isolation_domains[isolation_domain_count] = domain;
        isolation_domain_count += 1;
    }
    if (xhci_hw.isolationDomain()) |domain| {
        isolation_domains[isolation_domain_count] = domain;
        isolation_domain_count += 1;
    }
    var vtd_summary = if (hardware_proof.realTargetDetected())
        hardware_proof.vtdSummary() orelse @panic("validated VT-d firmware is required on the production target")
    else
        null;
    const vtd_summary_ptr = if (vtd_summary) |*summary| summary else null;
    const fault_proof = nvme_hw.probeAndReport(
        dev,
        vtd_summary_ptr,
        isolation_domains[0..isolation_domain_count],
    ) catch |err| {
        reportHardwareFailure(
            "ZIGOS:NVME:HW:BRINGUP_FAIL ",
            err,
            hardware_proof.realTargetDetected(),
            "production NVMe bring-up failed closed",
        );
        return false;
    };
    if (fault_proof) |proof| hardware_proof.recordVtdIsolationProof(proof);
    if (nvme_hw.publishedBar()) |bar| {
        registerDeviceMmio(pciDeviceId(dev), bar.physical_base, bar.length);
    }
    var interrupts_ready = true;
    nvme_hw.activateInterrupts() catch |err| {
        interrupts_ready = false;
        reportHardwareFailure(
            if (hardware_proof.realTargetDetected())
                "ZIGOS:NVME:HW:INTERRUPT_BRINGUP_FAIL "
            else
                "ZIGOS:NVME:HW:INTERRUPT_UNAVAILABLE ",
            err,
            hardware_proof.realTargetDetected(),
            "production NVMe interrupt activation failed closed",
        );
    };
    if (interrupts_ready) console.print("ZIGOS:NVME:HW:REMAP_MSI_OK\n");
    return true;
}

pub fn startNetworkDataplane() bool {
    if (intel_i225_hw.attached()) return true;
    const dev = pci.firstIntelI225Lm() orelse return true;
    if (!network_detected) return true;
    intel_i225_hw.prepare(dev) catch |err| switch (err) {
        error.AlreadyPrepared => {},
        else => {
            reportHardwareFailure(
                "ZIGOS:I225:HW:BRINGUP_FAIL ",
                err,
                hardware_proof.realTargetDetected(),
                "production I225-LM preparation failed closed",
            );
            return false;
        },
    };
    if (intel_i225_hw.publishedBar()) |bar| {
        registerDeviceMmio(pciDeviceId(dev), bar.physical_base, bar.length);
    }
    intel_i225_hw.activate() catch |err| {
        reportHardwareFailure(
            "ZIGOS:I225:HW:BRINGUP_FAIL ",
            err,
            hardware_proof.realTargetDetected(),
            "production I225-LM activation failed closed",
        );
        return false;
    };
    console.print("ZIGOS:I225:HW:TX_QUEUE_OK\n");
    console.print("ZIGOS:I225:HW:RX_QUEUE_OK\n");
    console.print("ZIGOS:I225:HW:REMAP_MSI_OK\n");
    return true;
}

pub fn startInputDataplane() bool {
    if (xhci_prepared) return true;
    const dev = pci.firstXhciController() orelse return true;
    if (!xhci_detected) return true;
    const caps = xhci_hw.probe(dev) catch |err| switch (err) {
        error.AlreadyPrepared => xhci_hw.probedCapabilities() orelse return false,
        else => {
            reportHardwareFailure(
                "ZIGOS:XHCI:HW:CAPABILITY_PROBE_FAIL ",
                err,
                hardware_proof.realTargetDetected(),
                "production xHCI capability probe failed closed",
            );
            return false;
        },
    };
    _ = caps;
    console.print("ZIGOS:XHCI:HW:CAPABILITY_PROBE_OK\n");
    console.print("ZIGOS:XHCI:HW:OWNERSHIP_OK\n");
    console.print("ZIGOS:XHCI:HW:RESET_OK\n");
    console.print("ZIGOS:XHCI:HW:SLOTS_OK\n");
    console.print("ZIGOS:XHCI:HW:DMA_OK\n");
    if (xhci_hw.publishedBar()) |bar| {
        registerDeviceMmio(pciDeviceId(dev), bar.physical_base, bar.length);
    }
    xhci_hw.activate() catch |err| {
        reportHardwareFailure(
            "ZIGOS:XHCI:HW:ACTIVATION_FAIL ",
            err,
            hardware_proof.realTargetDetected(),
            "production xHCI activation failed closed",
        );
        return !hardware_proof.realTargetDetected();
    };
    xhci_prepared = true;
    console.print("ZIGOS:XHCI:HW:REMAP_MSI_OK\n");
    console.print("ZIGOS:XHCI:HW:RUN_OK\n");
    return true;
}

pub fn startGraphicsDataplane() bool {
    if (graphics_started) return true;
    const device_id = if (pci.firstDeviceByClass(PCI_CLASS_GRAPHICS_ADAPTER)) |dev|
        pciDeviceId(dev)
    else
        0xC0DE_9001;
    registerFramebufferWindow(device_id);
    graphics_started = true;
    return true;
}

fn shouldEnableModelDeviceInventory(model_via_cmdline: bool) bool {
    if (config.smokeFaultMode() != .none or model_via_cmdline) return true;

    if (config.bootProfile() == .zigos_native) {
        return !device_inventory.recordForClass(.network_adapter).detected;
    }
    return false;
}

noinline fn reportHardwareFailure(
    prefix: []const u8,
    err: anyerror,
    real_target: bool,
    fatal_message: []const u8,
) void {
    console.print(prefix);
    console.print(@errorName(err));
    console.print("\n");
    if (real_target) @panic(fatal_message);
}

fn capturePciInventory() void {
    if (pci.firstIntelI225Lm()) |dev| {
        device_inventory.registerDetected(.network_adapter, pciDeviceId(dev), .intel_i225_lm_inventory, false);
        if (pci.memoryBar0(dev)) |bar| {
            registerDeviceMmio(pciDeviceId(dev), bar.address, 0x1_0000);
        }
        network_detected = true;
    }
    if (pci.firstDeviceByClass(PCI_CLASS_GRAPHICS_ADAPTER)) |dev| {
        device_inventory.registerDetected(.graphics_adapter, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstXhciController()) |dev| {
        const xhci_device_id = pciDeviceId(dev);
        device_inventory.registerDetected(.usb_controller, xhci_device_id, .xhci_inventory, false);
        if (pci.memoryBar0(dev)) |bar| {
            registerDeviceMmio(xhci_device_id, bar.address, 0x1_0000);
        }
        xhci_detected = true;
    }
    if (pci.firstDeviceByClass(PCI_CLASS_MULTIMEDIA_CONTROLLER)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    } else if (pci.firstDeviceByClass(PCI_CLASS_SIMPLE_COMMUNICATIONS_CONTROLLER)) |dev| {
        device_inventory.registerDetected(.audio_print_io, pciDeviceId(dev), .pci_inventory, false);
    }
    if (pci.firstNvmeController()) |dev| {
        device_inventory.registerDetected(.storage_controller, pciDeviceId(dev), .nvme_pci_inventory, false);
        if (pci.memoryBar0(dev)) |bar| {
            registerDeviceMmio(pciDeviceId(dev), bar.address, 0x4000);
        }
        storage_detected = true;
    }
}

fn publishDeferredNetworkBootstrap() void {
    const network_record = device_inventory.recordForClass(.network_adapter);
    if (!network_record.detected) return;
}

fn pciDeviceId(device_info: pci.PCIDevice) u64 {
    return pci.stableDeviceId(device_info);
}

fn registerFramebufferWindow(device_id: u64) void {
    const info = handoff.capturedInfo() orelse return;
    const framebuffer_info = handoff.framebufferInfo(info) catch return;
    registerDeviceMmio(device_id, framebuffer_info.physical_address, framebuffer_info.buffer_bytes);
}

fn registerDeviceMmio(device_id: u64, physical_base: u64, length: u64) void {
    const page_size: u64 = 4096;
    if (physical_base == 0 or physical_base % page_size != 0 or length == 0) return;
    const mapped_length = std.mem.alignForward(u64, length, page_size);
    device_broker.registerMmioWindows(device_id, &.{.{
        .base = 0,
        .physical_base = physical_base,
        .length = mapped_length,
        .writable = true,
    }}) catch {
        reportHardwareFailure(
            "ZIGOS:DEVICE:MMIO:REGISTER_FAIL ",
            error.InvalidMmioWindow,
            hardware_proof.realTargetDetected(),
            "userspace MMIO window registration failed closed",
        );
    };
}
