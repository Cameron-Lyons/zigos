const std = @import("std");

pub const kernel_boundary_role = "bootstrap_i225_lm_inventory_shim";
pub const publishes_full_network_service = false;
pub const network_data_plane_exports_fail_closed = true;

pub const DESCRIPTOR_BYTES: u32 = 16;
pub const MIN_RING_DESCRIPTORS: u32 = 64;
pub const MAX_RING_DESCRIPTORS: u32 = 4096;
pub const RING_ALIGNMENT_BYTES: u64 = 128;
pub const MIN_ETHERNET_FRAME_BYTES: usize = 60;
pub const MAX_ETHERNET_FRAME_BYTES: usize = 1518;
const RING_DESCRIPTOR_GRANULARITY: u32 = 8;
const TEST_RING_DESCRIPTORS: u32 = 256;
const TEST_RX_RING_ADDRESS: u64 = 0x1000;
const TEST_TX_RING_ADDRESS: u64 = 0x2000;
const TEST_UNALIGNED_RING_ADDRESS: u64 = TEST_RX_RING_ADDRESS + 1;

pub const Error = error{
    KernelNetworkDataPlaneDisabled,
    RingTooSmall,
    RingTooLarge,
    RingCountInvalid,
    RingAddressUnaligned,
    FrameTooSmall,
    FrameTooLarge,
    RxRingEmpty,
    BufferTooSmall,
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

pub const TxCompletion = struct {
    descriptor_index: u32,
    bytes: u16,
    end_of_packet: bool,
    descriptor_done: bool,
};

pub const RxCompletion = struct {
    descriptor_index: u32,
    bytes: u16,
    checksum_valid: bool,
    descriptor_done: bool,
};

pub const SoftwareAdapter = struct {
    ring_plan: RingPlan,
    mac_address: [6]u8,
    tx_tail: u32 = 0,
    rx_head: u32 = 0,
    last_tx_len: usize = 0,
    last_tx_frame: [MAX_ETHERNET_FRAME_BYTES]u8 = [_]u8{0} ** MAX_ETHERNET_FRAME_BYTES,
    pending_rx_len: usize = 0,
    pending_rx_frame: [MAX_ETHERNET_FRAME_BYTES]u8 = [_]u8{0} ** MAX_ETHERNET_FRAME_BYTES,

    pub fn init(ring_plan: RingPlan, mac_address: [6]u8) Error!SoftwareAdapter {
        try validateRingPlan(ring_plan);
        return .{
            .ring_plan = ring_plan,
            .mac_address = mac_address,
        };
    }

    pub fn transmit(self: *SoftwareAdapter, frame: []const u8) Error!TxCompletion {
        try validateFrameLength(frame.len);
        const descriptor_index = self.tx_tail;
        @memcpy(self.last_tx_frame[0..frame.len], frame);
        self.last_tx_len = frame.len;
        self.tx_tail = nextDescriptorIndex(self.tx_tail, self.ring_plan.tx_descriptors);
        return .{
            .descriptor_index = descriptor_index,
            .bytes = @intCast(frame.len),
            .end_of_packet = true,
            .descriptor_done = true,
        };
    }

    pub fn injectReceivedFrame(self: *SoftwareAdapter, frame: []const u8) Error!void {
        try validateFrameLength(frame.len);
        @memcpy(self.pending_rx_frame[0..frame.len], frame);
        self.pending_rx_len = frame.len;
    }

    pub fn receive(self: *SoftwareAdapter, buffer: []u8) Error!RxCompletion {
        if (self.pending_rx_len == 0) return error.RxRingEmpty;
        if (buffer.len < self.pending_rx_len) return error.BufferTooSmall;
        const descriptor_index = self.rx_head;
        @memcpy(buffer[0..self.pending_rx_len], self.pending_rx_frame[0..self.pending_rx_len]);
        const received_len = self.pending_rx_len;
        self.pending_rx_len = 0;
        self.rx_head = nextDescriptorIndex(self.rx_head, self.ring_plan.rx_descriptors);
        return .{
            .descriptor_index = descriptor_index,
            .bytes = @intCast(received_len),
            .checksum_valid = true,
            .descriptor_done = true,
        };
    }

    pub fn lastTransmitSlice(self: *const SoftwareAdapter) []const u8 {
        return self.last_tx_frame[0..self.last_tx_len];
    }
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
    if ((count % RING_DESCRIPTOR_GRANULARITY) != 0) return error.RingCountInvalid;
}

fn validateFrameLength(frame_len: usize) Error!void {
    if (frame_len < MIN_ETHERNET_FRAME_BYTES) return error.FrameTooSmall;
    if (frame_len > MAX_ETHERNET_FRAME_BYTES) return error.FrameTooLarge;
}

fn nextDescriptorIndex(index: u32, descriptor_count: u32) u32 {
    return (index + 1) % descriptor_count;
}

fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

test "Intel I225-LM ring plan validates descriptor geometry" {
    try validateRingPlan(.{
        .rx_descriptors = TEST_RING_DESCRIPTORS,
        .tx_descriptors = TEST_RING_DESCRIPTORS,
        .rx_ring_address = TEST_RX_RING_ADDRESS,
        .tx_ring_address = TEST_TX_RING_ADDRESS,
    });
    try std.testing.expectEqual(DESCRIPTOR_BYTES * TEST_RING_DESCRIPTORS, try ringBytes(TEST_RING_DESCRIPTORS));
}

test "Intel I225-LM ring plan rejects unsafe geometry" {
    try std.testing.expectError(error.RingTooSmall, validateRingPlan(.{
        .rx_descriptors = 32,
        .tx_descriptors = TEST_RING_DESCRIPTORS,
        .rx_ring_address = TEST_RX_RING_ADDRESS,
        .tx_ring_address = TEST_TX_RING_ADDRESS,
    }));

    try std.testing.expectError(error.RingCountInvalid, validateRingPlan(.{
        .rx_descriptors = 66,
        .tx_descriptors = TEST_RING_DESCRIPTORS,
        .rx_ring_address = TEST_RX_RING_ADDRESS,
        .tx_ring_address = TEST_TX_RING_ADDRESS,
    }));

    try std.testing.expectError(error.RingAddressUnaligned, validateRingPlan(.{
        .rx_descriptors = TEST_RING_DESCRIPTORS,
        .tx_descriptors = TEST_RING_DESCRIPTORS,
        .rx_ring_address = TEST_UNALIGNED_RING_ADDRESS,
        .tx_ring_address = TEST_TX_RING_ADDRESS,
    }));
}

test "Intel I225-LM kernel shim rejects direct network transmit attempts" {
    try std.testing.expectError(error.KernelNetworkDataPlaneDisabled, rejectKernelTransmit(.{
        .device_id = 0x8086_15F2_0000,
        .frame_len = 64,
    }));
}

test "Intel I225-LM software adapter transmits and receives descriptor-backed frames" {
    var adapter = try SoftwareAdapter.init(.{
        .rx_descriptors = TEST_RING_DESCRIPTORS,
        .tx_descriptors = TEST_RING_DESCRIPTORS,
        .rx_ring_address = TEST_RX_RING_ADDRESS,
        .tx_ring_address = TEST_TX_RING_ADDRESS,
    }, .{ 0x02, 0x15, 0xF2, 0, 0, 1 });
    var tx_frame = [_]u8{0xAB} ** MIN_ETHERNET_FRAME_BYTES;
    const broadcast = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    @memcpy(tx_frame[0..6], broadcast[0..]);
    @memcpy(tx_frame[6..12], &adapter.mac_address);
    const tx = try adapter.transmit(tx_frame[0..]);
    try std.testing.expectEqual(@as(u32, 0), tx.descriptor_index);
    try std.testing.expect(tx.end_of_packet);
    try std.testing.expect(tx.descriptor_done);
    try std.testing.expectEqual(@as(u32, 1), adapter.tx_tail);
    try std.testing.expect(std.mem.eql(u8, tx_frame[0..], adapter.lastTransmitSlice()));

    var rx_frame = [_]u8{0xCD} ** MIN_ETHERNET_FRAME_BYTES;
    @memcpy(rx_frame[0..6], &adapter.mac_address);
    try adapter.injectReceivedFrame(rx_frame[0..]);
    var rx_buffer = [_]u8{0} ** MAX_ETHERNET_FRAME_BYTES;
    const rx = try adapter.receive(rx_buffer[0..]);
    try std.testing.expectEqual(@as(u32, 0), rx.descriptor_index);
    try std.testing.expect(rx.checksum_valid);
    try std.testing.expectEqual(@as(u32, 1), adapter.rx_head);
    try std.testing.expect(std.mem.eql(u8, rx_frame[0..], rx_buffer[0..rx.bytes]));
}

test "Intel I225-LM software adapter rejects invalid frame flow" {
    var adapter = try SoftwareAdapter.init(.{
        .rx_descriptors = 64,
        .tx_descriptors = 64,
        .rx_ring_address = TEST_RX_RING_ADDRESS,
        .tx_ring_address = TEST_TX_RING_ADDRESS,
    }, .{ 0x02, 0x15, 0xF2, 0, 0, 2 });
    var too_small = [_]u8{0} ** (MIN_ETHERNET_FRAME_BYTES - 1);
    try std.testing.expectError(error.FrameTooSmall, adapter.transmit(too_small[0..]));
    var frame = [_]u8{0xEE} ** MIN_ETHERNET_FRAME_BYTES;
    try adapter.injectReceivedFrame(frame[0..]);
    var short_buffer = [_]u8{0} ** (MIN_ETHERNET_FRAME_BYTES - 1);
    try std.testing.expectError(error.BufferTooSmall, adapter.receive(short_buffer[0..]));
    var buffer = [_]u8{0} ** MIN_ETHERNET_FRAME_BYTES;
    _ = try adapter.receive(buffer[0..]);
    try std.testing.expectError(error.RxRingEmpty, adapter.receive(buffer[0..]));
}
