//! IOMMU enforcement is one device-independent step. Every requester the
//! kernel drives (NVMe, the selected NIC and xHCI) publishes its DMA windows
//! while its bus mastering is still revoked, then VT-d is enabled once for
//! all of them. Each driver's activation runs this step first, so whichever
//! device class starts first, no requester becomes DMA-capable before its
//! isolation domain is enforced.
const pci = @import("pci.zig");
const nvme_hw = @import("nvme_hw.zig");
const network_hw = @import("network_hw.zig");
const intel_i225_hw = @import("intel_i225_hw.zig");
const virtio_net_hw = @import("virtio_net_hw.zig");
const xhci_hw = @import("xhci_hw.zig");
const intel_vtd = @import("../platform/intel_vtd.zig");
const hardware_proof = @import("../platform/hardware_proof.zig");
const console = @import("../utils/console.zig");

pub const Error = error{
    StorageDmaUnavailable,
    NetworkPrepareFailed,
    UsbPrepareFailed,
    DmaFirmwareMissing,
    DmaEnforcementFailed,
};

const MAX_DOMAINS = 3;

const State = enum { pending, enforced, not_required, failed };
var state: State = .pending;

/// Idempotent. Preparation failures leave every requester with bus mastering
/// revoked and may be retried; a failed enforcement is final because VT-d
/// programming is one-shot.
pub fn ensureEnforced() Error!void {
    switch (state) {
        .enforced, .not_required => return,
        .failed => return error.DmaEnforcementFailed,
        .pending => {},
    }
    var domains: [MAX_DOMAINS]intel_vtd.DmaDomain = undefined;
    var count: usize = 0;
    if (pci.firstNvmeController()) |nvme| {
        domains[count] = nvme_hw.prepareDma(nvme) catch return error.StorageDmaUnavailable;
        count += 1;
    }
    network_hw.prepare() catch |err| {
        console.print("ZIGOS:NETWORK:PREPARE_FAIL ");
        console.print(@errorName(err));
        console.print("\n");
        return error.NetworkPrepareFailed;
    };
    if (intel_i225_hw.isolationDomain() orelse virtio_net_hw.isolationDomain()) |domain| {
        domains[count] = domain;
        count += 1;
    }
    if (pci.firstXhciController()) |usb| {
        if (xhci_hw.isolationDomain() == null) xhci_hw.probe(usb) catch return error.UsbPrepareFailed;
    }
    if (xhci_hw.isolationDomain()) |domain| {
        domains[count] = domain;
        count += 1;
    }

    if (count == 0) {
        state = .not_required;
        return;
    }
    if (hardware_proof.realTargetDetected()) {
        const summary = hardware_proof.vtdSummary() orelse return error.DmaFirmwareMissing;
        intel_vtd.enforceDevices(&summary, domains[0..count]) catch |err| return enforcementFailed(err);
    } else if (hardware_proof.dmaIsolationTable()) |table| {
        intel_vtd.enforceScopedDevices(table, domains[0..count]) catch |err| return enforcementFailed(err);
    } else if (virtio_net_hw.isolationDomain() != null) {
        console.print("ZIGOS:NETWORK:DMA_FIRMWARE_FAIL\n");
        return error.DmaFirmwareMissing;
    } else {
        // A virtual machine without an IOMMU: storage attaches unisolated and
        // every other requester refuses activation.
        state = .not_required;
        return;
    }
    state = .enforced;
}

fn enforcementFailed(err: intel_vtd.Error) Error {
    state = .failed;
    console.print("ZIGOS:VTD:ENFORCEMENT_FAIL ");
    console.print(@errorName(err));
    console.print("\n");
    return error.DmaEnforcementFailed;
}
