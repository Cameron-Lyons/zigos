//! Dispatch only the NIC selected by the boot inventory. Physical-target proof
//! remains in the I225 driver; VirtIO has its own transport and DMA domain.
const pci = @import("pci.zig");
const intel_nic = @import("intel_i225_hw.zig");
const virtio = @import("virtio_net_hw.zig");
const inventory = @import("../../native/drivers/device_inventory.zig");

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
    if (virtio.isolationDomain() != null) {
        try virtio.activate();
    } else if (intel_nic.publishedBar() != null and !intel_nic.attached()) {
        try intel_nic.activate();
        const console = @import("../utils/console.zig");
        console.print("ZIGOS:I225:HW:TX_QUEUE_OK\n");
        console.print("ZIGOS:I225:HW:RX_QUEUE_OK\n");
        console.print("ZIGOS:I225:HW:REMAP_MSI_OK\n");
    } else if (!intel_nic.attached() and
        pci.findDeviceByStableId(inventory.deviceIdForClass(.network_adapter)) != null)
    {
        return error.NetworkDeviceNotPrepared;
    }
}

export fn zigosNetworkBootstrapAttached() callconv(.c) bool {
    return virtio.attached() or intel_nic.attached();
}

export fn zigosNetworkBootstrapSend(destination_ptr: [*]const u8, payload_ptr: [*]const u8, payload_len: usize) callconv(.c) bool {
    if (payload_len == 0 or payload_len > intel_nic.MAX_PAYLOAD_BYTES) return false;
    var destination: [6]u8 = undefined;
    @memcpy(&destination, destination_ptr[0..6]);
    if (virtio.attached()) return virtio.sendPayload(destination, payload_ptr[0..payload_len]);
    return intel_nic.sendPayload(destination, payload_ptr[0..payload_len]);
}

export fn zigosNetworkBootstrapReceive(output_ptr: [*]u8, output_capacity: usize, output_len: *usize) callconv(.c) u8 {
    output_len.* = 0;
    const result = if (virtio.attached()) virtio.pollReceive(output_ptr[0..output_capacity]) else intel_nic.pollReceive(output_ptr[0..output_capacity]);
    output_len.* = result.length;
    return @backingInt(result.status);
}

export fn zigosNetworkBootstrapWorkPending() callconv(.c) bool {
    return if (virtio.attached()) virtio.workPending() else intel_nic.networkWorkPending();
}

export fn zigosNetworkBootstrapNextWake(deadline: *u64) callconv(.c) bool {
    deadline.* = 0;
    const wake = (if (virtio.attached()) virtio.nextWake() else intel_nic.nextWake()) orelse return false;
    deadline.* = wake;
    return true;
}

export fn zigosNetworkBootstrapMac(output: [*]u8) callconv(.c) bool {
    if (!zigosNetworkBootstrapAttached()) return false;
    const mac = if (virtio.attached()) virtio.macAddress() else intel_nic.macAddress();
    @memcpy(output[0..mac.len], &mac);
    return true;
}
