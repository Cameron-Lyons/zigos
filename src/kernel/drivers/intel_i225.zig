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
const TEST_TX_BUFFER_ADDRESS: u64 = 0x3000;
const TEST_RX_BUFFER_ADDRESS: u64 = 0x4000;
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
    ProofCycleCountInvalid,
    ProofMismatch,
    MissingPacketBuffer,
    PacketBufferAddressUnaligned,
    LinkDown,
    UnsupportedLinkSpeed,
    HalfDuplexLink,
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

pub const PacketBufferPlan = struct {
    tx_buffer_address: u64,
    rx_buffer_address: u64,
    buffer_bytes: usize,
};

pub const PhyLinkState = struct {
    link_up: bool,
    speed_mbps: u32,
    full_duplex: bool,
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

pub const PacketEvidenceSource = enum(u8) {
    modeled_mmio,
    hardware_descriptor_ring,
};

pub const HardwarePacketEvidence = struct {
    source: PacketEvidenceSource = .modeled_mmio,
    tx_descriptors_owned_by_device: u32 = 0,
    rx_descriptors_owned_by_device: u32 = 0,
    tx_dma_bytes: u64 = 0,
    rx_dma_bytes: u64 = 0,
    asserted_interrupts: u32 = 0,
    phy_packet_observations: u32 = 0,

    pub fn verified(self: HardwarePacketEvidence, expected_cycles: u32, bytes_per_direction: u64) bool {
        return self.source == .hardware_descriptor_ring and
            expected_cycles > 0 and
            bytes_per_direction > 0 and
            self.tx_descriptors_owned_by_device >= expected_cycles and
            self.rx_descriptors_owned_by_device >= expected_cycles and
            self.tx_dma_bytes >= bytes_per_direction and
            self.rx_dma_bytes >= bytes_per_direction and
            self.asserted_interrupts >= expected_cycles and
            self.phy_packet_observations >= expected_cycles;
    }
};

pub const PacketProof = struct {
    ring_plan: RingPlan,
    mac_address: [6]u8,
    frame_bytes: u16,
    tx_rx_cycles: u16,
    transmit_completions: u16,
    receive_completions: u16,
    last_tx_completion: TxCompletion,
    last_rx_completion: RxCompletion,
    mmio: MmioPacketProof,

    pub fn verified(self: PacketProof) bool {
        validateRingPlan(self.ring_plan) catch return false;
        const expected_cycles = @as(u32, self.transmit_completions);
        return macAddressPresent(self.mac_address) and
            self.frame_bytes >= MIN_ETHERNET_FRAME_BYTES and
            self.frame_bytes <= MAX_ETHERNET_FRAME_BYTES and
            self.tx_rx_cycles > 0 and
            self.transmit_completions == self.tx_rx_cycles and
            self.receive_completions == self.tx_rx_cycles and
            self.last_tx_completion.descriptor_index < self.ring_plan.tx_descriptors and
            self.last_rx_completion.descriptor_index < self.ring_plan.rx_descriptors and
            self.last_tx_completion.bytes == self.frame_bytes and
            self.last_rx_completion.bytes == self.frame_bytes and
            self.last_tx_completion.end_of_packet and
            self.last_tx_completion.descriptor_done and
            self.last_rx_completion.checksum_valid and
            self.last_rx_completion.descriptor_done and
            self.mmio.verified(self.ring_plan, expected_cycles);
    }

    pub fn productionHardwareVerified(self: PacketProof) bool {
        const expected_cycles = @as(u32, self.transmit_completions);
        const bytes_per_direction = self.bytesPerDirection() orelse return false;
        return self.verified() and self.mmio.hardwareVerified(self.ring_plan, expected_cycles, bytes_per_direction);
    }

    fn bytesPerDirection(self: PacketProof) ?u64 {
        return std.math.mul(u64, @as(u64, self.tx_rx_cycles), @as(u64, self.frame_bytes)) catch null;
    }
};

pub const MmioPacketProof = struct {
    rx_ring_address: u64,
    tx_ring_address: u64,
    rx_ring_bytes: u32,
    tx_ring_bytes: u32,
    rx_buffer_address: u64,
    tx_buffer_address: u64,
    buffer_bytes: usize,
    link_up: bool,
    link_speed_mbps: u32,
    full_duplex: bool,
    phy_status_reads: u32,
    tx_tail_register_writes: u32,
    rx_tail_register_writes: u32,
    tx_descriptor_write_backs: u32,
    rx_descriptor_write_backs: u32,
    interrupt_cause_reads: u32,
    hardware_packet: HardwarePacketEvidence = .{},

    pub fn verified(self: MmioPacketProof, ring_plan: RingPlan, expected_cycles: u32) bool {
        const expected_rx_ring_bytes = ringBytes(ring_plan.rx_descriptors) catch return false;
        const expected_tx_ring_bytes = ringBytes(ring_plan.tx_descriptors) catch return false;
        const expected_interrupts = expected_cycles * 2;
        return expected_cycles > 0 and
            self.rx_ring_address == ring_plan.rx_ring_address and
            self.tx_ring_address == ring_plan.tx_ring_address and
            self.rx_ring_bytes == expected_rx_ring_bytes and
            self.tx_ring_bytes == expected_tx_ring_bytes and
            aligned(self.rx_buffer_address, RING_ALIGNMENT_BYTES) and
            aligned(self.tx_buffer_address, RING_ALIGNMENT_BYTES) and
            self.rx_buffer_address != self.tx_buffer_address and
            self.buffer_bytes >= MAX_ETHERNET_FRAME_BYTES and
            self.link_up and
            self.full_duplex and
            supportedLinkSpeed(self.link_speed_mbps) and
            self.phy_status_reads > 0 and
            self.tx_tail_register_writes >= expected_cycles and
            self.rx_tail_register_writes >= expected_cycles and
            self.tx_descriptor_write_backs == expected_cycles and
            self.rx_descriptor_write_backs == expected_cycles and
            self.interrupt_cause_reads >= expected_interrupts;
    }

    pub fn hardwareVerified(
        self: MmioPacketProof,
        ring_plan: RingPlan,
        expected_cycles: u32,
        bytes_per_direction: u64,
    ) bool {
        return self.verified(ring_plan, expected_cycles) and
            self.hardware_packet.verified(expected_cycles, bytes_per_direction);
    }
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
    mmio: ?MmioState = null,

    pub fn init(ring_plan: RingPlan, mac_address: [6]u8) Error!SoftwareAdapter {
        try validateRingPlan(ring_plan);
        return .{
            .ring_plan = ring_plan,
            .mac_address = mac_address,
        };
    }

    pub fn initWithMmio(
        ring_plan: RingPlan,
        mac_address: [6]u8,
        phy: PhyLinkState,
        buffers: PacketBufferPlan,
    ) Error!SoftwareAdapter {
        try validatePacketBufferPlan(buffers);
        try validatePhyLink(phy);
        var adapter = try SoftwareAdapter.init(ring_plan, mac_address);
        adapter.mmio = .{
            .phy = phy,
            .buffers = buffers,
        };
        return adapter;
    }

    pub fn transmit(self: *SoftwareAdapter, frame: []const u8) Error!TxCompletion {
        try validateFrameLength(frame.len);
        const descriptor_index = self.tx_tail;
        @memcpy(self.last_tx_frame[0..frame.len], frame);
        self.last_tx_len = frame.len;
        self.tx_tail = nextDescriptorIndex(self.tx_tail, self.ring_plan.tx_descriptors);
        if (self.mmio) |*mmio| {
            mmio.tx_tail_register_writes += 1;
            mmio.tx_descriptor_write_backs += 1;
            mmio.interrupt_cause_reads += 1;
        }
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
        if (self.mmio) |*mmio| {
            mmio.rx_tail_register_writes += 1;
            mmio.rx_descriptor_write_backs += 1;
            mmio.interrupt_cause_reads += 1;
        }
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

    pub fn proveFrameCycles(self: *SoftwareAdapter, cycles: u16) Error!PacketProof {
        if (cycles == 0) return error.ProofCycleCountInvalid;

        var tx_frame: [MIN_ETHERNET_FRAME_BYTES]u8 = undefined;
        var rx_frame: [MIN_ETHERNET_FRAME_BYTES]u8 = undefined;
        var rx_buffer: [MAX_ETHERNET_FRAME_BYTES]u8 = undefined;
        var last_tx_completion: TxCompletion = undefined;
        var last_rx_completion: RxCompletion = undefined;
        const mmio_start = self.mmioCounters();
        try self.observePhyLink();
        var completed: u16 = 0;
        while (completed < cycles) : (completed += 1) {
            fillProofFrame(tx_frame[0..], self.mac_address, completed, .transmit);
            last_tx_completion = try self.transmit(tx_frame[0..]);
            if (!std.mem.eql(u8, tx_frame[0..], self.lastTransmitSlice())) return error.ProofMismatch;

            fillProofFrame(rx_frame[0..], self.mac_address, completed, .receive);
            try self.injectReceivedFrame(rx_frame[0..]);
            @memset(rx_buffer[0..], 0);
            last_rx_completion = try self.receive(rx_buffer[0..]);
            if (!std.mem.eql(u8, rx_frame[0..], rx_buffer[0..@as(usize, last_rx_completion.bytes)])) {
                return error.ProofMismatch;
            }
        }

        return .{
            .ring_plan = self.ring_plan,
            .mac_address = self.mac_address,
            .frame_bytes = MIN_ETHERNET_FRAME_BYTES,
            .tx_rx_cycles = completed,
            .transmit_completions = completed,
            .receive_completions = completed,
            .last_tx_completion = last_tx_completion,
            .last_rx_completion = last_rx_completion,
            .mmio = self.mmioProofSince(mmio_start),
        };
    }

    fn observePhyLink(self: *SoftwareAdapter) Error!void {
        if (self.mmio) |*mmio| {
            mmio.phy_status_reads += 1;
            try validatePhyLink(mmio.phy);
        }
    }

    fn mmioProof(self: *const SoftwareAdapter) MmioPacketProof {
        const mmio = self.mmio orelse return emptyMmioPacketProof();
        return mmio.proof(self.ring_plan);
    }

    fn mmioCounters(self: *const SoftwareAdapter) MmioCounters {
        const mmio = self.mmio orelse return .{};
        return .{
            .phy_status_reads = mmio.phy_status_reads,
            .tx_tail_register_writes = mmio.tx_tail_register_writes,
            .rx_tail_register_writes = mmio.rx_tail_register_writes,
            .tx_descriptor_write_backs = mmio.tx_descriptor_write_backs,
            .rx_descriptor_write_backs = mmio.rx_descriptor_write_backs,
            .interrupt_cause_reads = mmio.interrupt_cause_reads,
        };
    }

    fn mmioProofSince(self: *const SoftwareAdapter, start: MmioCounters) MmioPacketProof {
        var proof = self.mmioProof();
        proof.phy_status_reads = saturatedDelta(proof.phy_status_reads, start.phy_status_reads);
        proof.tx_tail_register_writes = saturatedDelta(proof.tx_tail_register_writes, start.tx_tail_register_writes);
        proof.rx_tail_register_writes = saturatedDelta(proof.rx_tail_register_writes, start.rx_tail_register_writes);
        proof.tx_descriptor_write_backs = saturatedDelta(proof.tx_descriptor_write_backs, start.tx_descriptor_write_backs);
        proof.rx_descriptor_write_backs = saturatedDelta(proof.rx_descriptor_write_backs, start.rx_descriptor_write_backs);
        proof.interrupt_cause_reads = saturatedDelta(proof.interrupt_cause_reads, start.interrupt_cause_reads);
        return proof;
    }
};

const MmioCounters = struct {
    phy_status_reads: u32 = 0,
    tx_tail_register_writes: u32 = 0,
    rx_tail_register_writes: u32 = 0,
    tx_descriptor_write_backs: u32 = 0,
    rx_descriptor_write_backs: u32 = 0,
    interrupt_cause_reads: u32 = 0,
};

const MmioState = struct {
    phy: PhyLinkState,
    buffers: PacketBufferPlan,
    phy_status_reads: u32 = 0,
    tx_tail_register_writes: u32 = 0,
    rx_tail_register_writes: u32 = 0,
    tx_descriptor_write_backs: u32 = 0,
    rx_descriptor_write_backs: u32 = 0,
    interrupt_cause_reads: u32 = 0,

    fn proof(self: MmioState, ring_plan: RingPlan) MmioPacketProof {
        return .{
            .rx_ring_address = ring_plan.rx_ring_address,
            .tx_ring_address = ring_plan.tx_ring_address,
            .rx_ring_bytes = ringBytes(ring_plan.rx_descriptors) catch 0,
            .tx_ring_bytes = ringBytes(ring_plan.tx_descriptors) catch 0,
            .rx_buffer_address = self.buffers.rx_buffer_address,
            .tx_buffer_address = self.buffers.tx_buffer_address,
            .buffer_bytes = self.buffers.buffer_bytes,
            .link_up = self.phy.link_up,
            .link_speed_mbps = self.phy.speed_mbps,
            .full_duplex = self.phy.full_duplex,
            .phy_status_reads = self.phy_status_reads,
            .tx_tail_register_writes = self.tx_tail_register_writes,
            .rx_tail_register_writes = self.rx_tail_register_writes,
            .tx_descriptor_write_backs = self.tx_descriptor_write_backs,
            .rx_descriptor_write_backs = self.rx_descriptor_write_backs,
            .interrupt_cause_reads = self.interrupt_cause_reads,
        };
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

pub fn withHardwarePacketEvidence(proof: PacketProof, evidence: HardwarePacketEvidence) PacketProof {
    var upgraded = proof;
    upgraded.mmio.hardware_packet = evidence;
    return upgraded;
}

pub fn defaultPacketBufferPlan() PacketBufferPlan {
    return .{
        .tx_buffer_address = TEST_TX_BUFFER_ADDRESS,
        .rx_buffer_address = TEST_RX_BUFFER_ADDRESS,
        .buffer_bytes = MAX_ETHERNET_FRAME_BYTES,
    };
}

pub fn defaultPhyLinkState() PhyLinkState {
    return .{
        .link_up = true,
        .speed_mbps = 2500,
        .full_duplex = true,
    };
}

pub fn validatePacketBufferPlan(plan: PacketBufferPlan) Error!void {
    if (plan.buffer_bytes < MAX_ETHERNET_FRAME_BYTES) return error.MissingPacketBuffer;
    if (!aligned(plan.tx_buffer_address, RING_ALIGNMENT_BYTES)) return error.PacketBufferAddressUnaligned;
    if (!aligned(plan.rx_buffer_address, RING_ALIGNMENT_BYTES)) return error.PacketBufferAddressUnaligned;
    if (plan.tx_buffer_address == plan.rx_buffer_address) return error.PacketBufferAddressUnaligned;
}

pub fn validatePhyLink(phy: PhyLinkState) Error!void {
    if (!phy.link_up) return error.LinkDown;
    if (!supportedLinkSpeed(phy.speed_mbps)) return error.UnsupportedLinkSpeed;
    if (!phy.full_duplex) return error.HalfDuplexLink;
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

fn supportedLinkSpeed(speed_mbps: u32) bool {
    return speed_mbps == 1000 or speed_mbps == 2500;
}

fn emptyMmioPacketProof() MmioPacketProof {
    return .{
        .rx_ring_address = 0,
        .tx_ring_address = 0,
        .rx_ring_bytes = 0,
        .tx_ring_bytes = 0,
        .rx_buffer_address = 0,
        .tx_buffer_address = 0,
        .buffer_bytes = 0,
        .link_up = false,
        .link_speed_mbps = 0,
        .full_duplex = false,
        .phy_status_reads = 0,
        .tx_tail_register_writes = 0,
        .rx_tail_register_writes = 0,
        .tx_descriptor_write_backs = 0,
        .rx_descriptor_write_backs = 0,
        .interrupt_cause_reads = 0,
    };
}

fn saturatedDelta(after: u32, before: u32) u32 {
    return if (after >= before) after - before else 0;
}

const ProofFrameDirection = enum {
    transmit,
    receive,
};

fn fillProofFrame(frame: []u8, mac_address: [6]u8, cycle: u16, direction: ProofFrameDirection) void {
    const peer = [_]u8{ 0x02, 0x5A, 0x17, 0x22, @intCast((cycle >> 8) & 0xFF), @intCast(cycle & 0xFF) };
    switch (direction) {
        .transmit => {
            @memcpy(frame[0..6], peer[0..]);
            @memcpy(frame[6..12], &mac_address);
        },
        .receive => {
            @memcpy(frame[0..6], &mac_address);
            @memcpy(frame[6..12], peer[0..]);
        },
    }
    frame[12] = 0x88;
    frame[13] = 0xB5;
    var index: usize = 14;
    while (index < frame.len) : (index += 1) {
        const mixed = @as(u32, @intCast(index)) *% 29 +%
            @as(u32, cycle) *% 13 +%
            @as(u32, mac_address[index % mac_address.len]);
        frame[index] = @intCast(mixed & 0xFF);
    }
}

fn macAddressPresent(mac_address: [6]u8) bool {
    for (mac_address) |byte| {
        if (byte != 0) return true;
    }
    return false;
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
    try std.testing.expectError(error.PacketBufferAddressUnaligned, SoftwareAdapter.initWithMmio(.{
        .rx_descriptors = TEST_RING_DESCRIPTORS,
        .tx_descriptors = TEST_RING_DESCRIPTORS,
        .rx_ring_address = TEST_RX_RING_ADDRESS,
        .tx_ring_address = TEST_TX_RING_ADDRESS,
    }, .{ 0x02, 0x15, 0xF2, 0, 0, 1 }, defaultPhyLinkState(), .{
        .tx_buffer_address = TEST_TX_BUFFER_ADDRESS + 1,
        .rx_buffer_address = TEST_RX_BUFFER_ADDRESS,
        .buffer_bytes = MAX_ETHERNET_FRAME_BYTES,
    }));
    var adapter = try SoftwareAdapter.initWithMmio(.{
        .rx_descriptors = TEST_RING_DESCRIPTORS,
        .tx_descriptors = TEST_RING_DESCRIPTORS,
        .rx_ring_address = TEST_RX_RING_ADDRESS,
        .tx_ring_address = TEST_TX_RING_ADDRESS,
    }, .{ 0x02, 0x15, 0xF2, 0, 0, 1 }, defaultPhyLinkState(), defaultPacketBufferPlan());
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

    const proof = try adapter.proveFrameCycles(3);
    try std.testing.expect(proof.verified());
    try std.testing.expect(!proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u16, 3), proof.tx_rx_cycles);
    try std.testing.expectEqual(@as(u32, 3), proof.last_tx_completion.descriptor_index);
    try std.testing.expectEqual(@as(u32, 3), proof.last_rx_completion.descriptor_index);
    try std.testing.expectEqual(@as(u32, 3), proof.mmio.tx_tail_register_writes);
    try std.testing.expectEqual(@as(u32, 3), proof.mmio.rx_tail_register_writes);
    try std.testing.expectEqual(@as(u32, 3), proof.mmio.tx_descriptor_write_backs);
    try std.testing.expectEqual(@as(u32, 3), proof.mmio.rx_descriptor_write_backs);
    try std.testing.expectEqual(@as(u32, 6), proof.mmio.interrupt_cause_reads);
    try std.testing.expectEqual(@as(u32, 1), proof.mmio.phy_status_reads);
    try std.testing.expectEqual(@as(u32, 2500), proof.mmio.link_speed_mbps);

    var malformed = proof;
    malformed.mmio.interrupt_cause_reads = 0;
    try std.testing.expect(!malformed.verified());

    const hardware_proof = withHardwarePacketEvidence(proof, .{
        .source = .hardware_descriptor_ring,
        .tx_descriptors_owned_by_device = 3,
        .rx_descriptors_owned_by_device = 3,
        .tx_dma_bytes = 3 * MIN_ETHERNET_FRAME_BYTES,
        .rx_dma_bytes = 3 * MIN_ETHERNET_FRAME_BYTES,
        .asserted_interrupts = 3,
        .phy_packet_observations = 3,
    });
    try std.testing.expect(hardware_proof.productionHardwareVerified());

    var missing_descriptor_ownership = hardware_proof;
    missing_descriptor_ownership.mmio.hardware_packet.rx_descriptors_owned_by_device = 0;
    try std.testing.expect(!missing_descriptor_ownership.productionHardwareVerified());
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
    try std.testing.expectError(error.ProofCycleCountInvalid, adapter.proveFrameCycles(0));
}
