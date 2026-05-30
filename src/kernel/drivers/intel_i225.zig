const std = @import("std");

pub const kernel_boundary_role = "bootstrap_i225_lm_inventory_shim";
pub const publishes_full_network_service = false;
pub const network_data_plane_exports_fail_closed = true;

pub const DESCRIPTOR_BYTES: u32 = 16;
pub const MIN_RING_DESCRIPTORS: u32 = 64;
pub const MAX_RING_DESCRIPTORS: u32 = 4096;
pub const RING_ALIGNMENT_BYTES: u64 = 128;

pub const Error = error{
    KernelNetworkDataPlaneDisabled,
    RingTooSmall,
    RingTooLarge,
    RingCountInvalid,
    RingAddressUnaligned,
};

pub const TransmitRequest = struct {
    device_id: u64,
    frame_len: u16,
};

pub const RingPlan = struct {
    rx_descriptors: u32,
    tx_descriptors: u32,
    rx_ring_address: u64,
    tx_ring_address: u64,
};

pub fn validateRingPlan(plan: RingPlan) Error!void {
    try validateDescriptorCount(plan.rx_descriptors);
    try validateDescriptorCount(plan.tx_descriptors);
    if (!aligned(plan.rx_ring_address, RING_ALIGNMENT_BYTES)) return error.RingAddressUnaligned;
    if (!aligned(plan.tx_ring_address, RING_ALIGNMENT_BYTES)) return error.RingAddressUnaligned;
}

pub fn ringBytes(descriptor_count: u32) Error!u32 {
    try validateDescriptorCount(descriptor_count);
    return descriptor_count * DESCRIPTOR_BYTES;
}

pub fn rejectKernelTransmit(_: TransmitRequest) Error!void {
    return error.KernelNetworkDataPlaneDisabled;
}

fn validateDescriptorCount(count: u32) Error!void {
    if (count < MIN_RING_DESCRIPTORS) return error.RingTooSmall;
    if (count > MAX_RING_DESCRIPTORS) return error.RingTooLarge;
    if ((count % 8) != 0) return error.RingCountInvalid;
}

fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

test "Intel I225-LM ring plan validates descriptor geometry" {
    try validateRingPlan(.{
        .rx_descriptors = 256,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    });
    try std.testing.expectEqual(@as(u32, 4096), try ringBytes(256));
}

test "Intel I225-LM ring plan rejects unsafe geometry" {
    try std.testing.expectError(error.RingTooSmall, validateRingPlan(.{
        .rx_descriptors = 32,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    }));

    try std.testing.expectError(error.RingCountInvalid, validateRingPlan(.{
        .rx_descriptors = 66,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    }));

    try std.testing.expectError(error.RingAddressUnaligned, validateRingPlan(.{
        .rx_descriptors = 256,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1001,
        .tx_ring_address = 0x2000,
    }));
}

test "Intel I225-LM kernel shim rejects direct network transmit attempts" {
    try std.testing.expectError(error.KernelNetworkDataPlaneDisabled, rejectKernelTransmit(.{
        .device_id = 0x8086_15F2_0000,
        .frame_len = 64,
    }));
}
