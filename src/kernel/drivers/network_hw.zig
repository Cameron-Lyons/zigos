//! Dispatch only the NIC selected by the boot inventory. Physical-target proof
//! remains in the I225 driver; VirtIO has its own transport and DMA domain.
//! The native network data plane calls this module directly.
const pci = @import("pci.zig");
const intel_nic = @import("intel_i225_hw.zig");
const virtio = @import("virtio_net_hw.zig");
const inventory = @import("../../native/drivers/device_inventory.zig");
const dma_enforcement = @import("dma_enforcement.zig");
const console = @import("../utils/console.zig");

/// The selected NIC owns this one message-signalled vector.
pub const INTERRUPT_VECTOR: u8 = 65;

pub fn prepare() !void {
    const record = inventory.recordForClass(.network_adapter);
    const device = pci.findDeviceByStableId(record.device_id) orelse return;
    switch (record.source) {
        .virtio_net_inventory => try virtio.prepare(device),
        .intel_i225_lm_inventory => intel_nic.prepare(device) catch |err| switch (err) {
            error.AlreadyPrepared => {},
            else => return err,
        },
        else => return error.UnsupportedDevice,
    }
}

pub fn activate() !void {
    try dma_enforcement.ensureEnforced();
    if (virtio.isolationDomain() != null) {
        try virtio.activate();
    } else if (intel_nic.publishedBar() != null and !intel_nic.attached()) {
        try intel_nic.activate();
        console.print("ZIGOS:I225:HW:TX_QUEUE_OK\n");
        console.print("ZIGOS:I225:HW:RX_QUEUE_OK\n");
        console.print("ZIGOS:I225:HW:REMAP_MSI_OK\n");
    } else if (!intel_nic.attached() and
        pci.findDeviceByStableId(inventory.deviceIdForClass(.network_adapter)) != null)
    {
        return error.NetworkDeviceNotPrepared;
    }
}

pub fn handleInterrupt() void {
    if (virtio.isolationDomain() != null) virtio.handleInterrupt() else intel_nic.handleInterrupt();
}

pub fn attached() bool {
    return virtio.attached() or intel_nic.attached();
}

pub fn send(destination: [6]u8, payload: []const u8) bool {
    if (payload.len == 0 or payload.len > intel_nic.MAX_PAYLOAD_BYTES) return false;
    if (virtio.attached()) return virtio.sendPayload(destination, payload);
    return intel_nic.sendPayload(destination, payload);
}

/// Services the attached NIC once and drains one bounded batch of receive
/// completions into `sink`. For each completion the driver copies the payload
/// into `sink.buffer()` (an empty buffer drains it uncopied) and reports a
/// `.frame` or `.dropped` result to `sink.accept`, which ends the batch by
/// returning false. A device failure ends the batch through `sink.fail()`.
pub fn receive(sink: anytype) void {
    if (virtio.attached()) virtio.pollReceiveBatch(sink) else intel_nic.pollReceiveBatch(sink);
}

pub fn workPending() bool {
    return if (virtio.attached()) virtio.workPending() else intel_nic.networkWorkPending();
}

pub fn nextWake() ?u64 {
    return if (virtio.attached()) virtio.nextWake() else intel_nic.nextWake();
}

pub fn macAddress() ?[6]u8 {
    if (virtio.attached()) return virtio.macAddress();
    if (intel_nic.attached()) return intel_nic.macAddress();
    return null;
}
