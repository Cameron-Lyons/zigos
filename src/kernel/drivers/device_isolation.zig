//! Isolation steps shared by every DMA-capable driver: the IOMMU preconditions
//! for activation, the remapped message-signalled interrupt route, and DMA
//! fault polling. Each driver keeps its own bus-master ordering around them.
const pci = @import("pci.zig");
const intel_vtd = @import("../platform/intel_vtd.zig");
const smp = @import("../smp.zig");

pub const Error = error{
    DmaIsolationBypassed,
    DmaFaultMonitoringUnavailable,
    InterruptIsolationUnavailable,
    InterruptRouteInstallFailed,
    MsiEnableFailed,
};

/// A requester may run only while VT-d translates its DMA, records its
/// faults and remaps its interrupts.
pub fn requireIsolated(device: pci.PCIDevice) Error!void {
    if (!intel_vtd.requesterProtected(device)) return error.DmaIsolationBypassed;
    if (!intel_vtd.faultMonitoringEnabled()) return error.DmaFaultMonitoringUnavailable;
    if (!intel_vtd.interruptIsolationEnabled()) return error.InterruptIsolationUnavailable;
}

pub const MessageTarget = union(enum) {
    msi,
    /// Program and unmask MSI-X entry 0.
    msix: pci.MsixEntry,
    /// Program MSI-X entry 0 but leave the function masked; the caller opens
    /// delivery with `pci.unmaskSingleMsix` once its queues are ready.
    msix_masked: pci.MsixEntry,
};

/// Install the remapped interrupt for `vector` and program the device's
/// message. The capability is probed first so a device that cannot signal
/// this way never holds a route, and any later failure revokes the route.
pub fn routeInterrupt(device: pci.PCIDevice, vector: u8, target: MessageTarget) Error!void {
    const capable = switch (target) {
        .msi => pci.hasMsi(device),
        .msix, .msix_masked => pci.hasMsix(device),
    } catch return error.MsiEnableFailed;
    if (!capable) return error.MsiEnableFailed;
    const remapped = intel_vtd.routeInterrupt(device, vector, smp.irqDestinationId()) catch
        return error.InterruptRouteInstallFailed;
    errdefer intel_vtd.clearInterruptRoute(device) catch {};
    const message = pci.MsiMessage{ .address = remapped.address, .data = remapped.data };
    (switch (target) {
        .msi => pci.enableSingleMsi(device, message),
        .msix => |entry| pci.enableSingleMsix(device, entry, message),
        .msix_masked => |entry| pci.beginSingleMsix(device, entry, message),
    }) catch return error.MsiEnableFailed;
}

/// Stop message signalling and drop the remapped route, so containment leaves
/// no live interrupt path and a later activation can route the device again.
/// Callers revoke bus mastering first. The route is dropped even if the
/// capability writes fail: a cleared entry blocks any further message.
pub fn revokeInterrupt(device: pci.PCIDevice) void {
    pci.disableMessageInterrupts(device) catch {};
    intel_vtd.clearInterruptRoute(device) catch {};
}

pub const FaultState = enum { clear, monitoring_unavailable, fail_closed, fault };

pub fn pollFault(device: pci.PCIDevice) FaultState {
    if (!intel_vtd.faultMonitoringEnabled()) return .monitoring_unavailable;
    const fault = intel_vtd.pollFaultForDevice(device) catch return .fail_closed;
    return if (fault == null) .clear else .fault;
}
