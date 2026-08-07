const std = @import("std");
const attestation_service = @import("../platform/attestation_service.zig");
const binary_cursor = @import("binary_cursor");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const device_graph = @import("device_graph.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const hardware_target = @import("../platform/hardware_target.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const intel_i225 = @import("../../kernel/drivers/intel_i225.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const network_driver_task = @import("../drivers/network_driver_task.zig");
const network_policy = @import("network_policy.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sync_state = @import("sync_state_support.zig");

pub const harness = @import("sync_transport_harness.zig");

pub const MAX_PACKET_BYTES = harness.MAX_PACKET_BYTES;
pub const MAX_RELAY_PACKETS = harness.MAX_RELAY_PACKETS;
pub const EncryptedPacket = harness.EncryptedPacket;
pub const SignedEncryptedFrame = harness.SignedEncryptedFrame;
pub const Relay = harness.Relay;
pub const BootedOverlayRelayService = harness.BootedOverlayRelayService;
pub const TransportSession = harness.TransportSession;
pub const VerifiedServiceIdentityOpenRequest = harness.VerifiedServiceIdentityOpenRequest;
pub const Harness = harness.Harness;
pub const EmulatedNativeTransport = harness.EmulatedNativeTransport;
pub const signPacket = harness.signPacket;
pub const verifySignedFrame = harness.verifySignedFrame;
pub const decryptForSession = harness.decryptForSession;
pub const decryptSignedFrame = harness.decryptSignedFrame;

pub const Error = harness.Error || endpoint.Error || network_driver_task.Error || error{
    NativeTransportCongested,
    NativeTransportDisconnected,
    NativeTransportDeviceRevoked,
    NativeTransportFrameMissing,
    NativeTransportHardwareProofMissing,
    NativeTransportMalformedFrame,
    NativeTransportReplayRejected,
    NativeTransportSequenceExhausted,
    PacketCaptureFull,
};

pub const MAX_CAPTURED_PACKETS: usize = 16;
pub const MAX_NATIVE_IN_FLIGHT_FRAMES: usize = 4;
pub const NATIVE_TRANSPORT_ABI_VERSION: u16 = 3;
const NativeFrameWriter = binary_cursor.Writer(Error, error.PacketTooLarge);
const NativeFrameReader = binary_cursor.Reader(Error, error.NativeTransportMalformedFrame);

pub const NativeTransportAbi = struct {
    pub const magic = [_]u8{ 'Z', 'G', 'S', 'T' };
    pub const version: u16 = NATIVE_TRANSPORT_ABI_VERSION;
    pub const flag_encrypted: u8 = 1 << 0;
    pub const flag_egress_allowed: u8 = 1 << 1;
    pub const fixed_header_bytes: usize = 4 + 2 + 2 + (4 * @sizeOf(u64)) + 4 + (4 * @sizeOf(u64)) + 2;
};

pub const NATIVE_FRAME_DIGEST_BYTES: usize = 2 * @sizeOf(crypto_hash.Digest);
pub const MAX_NATIVE_PAYLOAD_BYTES: usize = @min(
    MAX_PACKET_BYTES,
    @min(
        endpoint.MAX_MESSAGE_BYTES,
        network_driver_task.MAX_NATIVE_FRAME_BYTES - NativeTransportAbi.fixed_header_bytes - NATIVE_FRAME_DIGEST_BYTES,
    ),
);

pub const NativeSyncFrameView = struct {
    abi_version: u16,
    header_len: u16,
    session_id: u64,
    sequence: u64,
    source_task_id: u64,
    target_task_id: u64,
    transport: sync_state.TransportMode,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    flags: u8,
    policy_id: u64,
    capability_id: u64,
    ciphertext: []const u8,
    payload_digest: []const u8,
    packet_digest: []const u8,

    pub fn encrypted(self: NativeSyncFrameView) bool {
        return (self.flags & NativeTransportAbi.flag_encrypted) != 0;
    }

    pub fn egressAllowed(self: NativeSyncFrameView) bool {
        return (self.flags & NativeTransportAbi.flag_egress_allowed) != 0;
    }
};

pub const CapturedFrameExpectation = struct {
    session_id: u64,
    sequence: u64,
    source_task_id: u64,
    target_task_id: u64,
    transport: sync_state.TransportMode,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    policy_id: u64,
    capability_id: u64,
    forbidden_plaintext: []const u8 = "",
};

pub const IntelI225TransportProof = struct {
    evidence: hardware_target.EvidenceSummary,
    ring_plan: intel_i225.RingPlan,
    packet_proof: intel_i225.PacketProof,
    kernel_data_plane_disabled: bool = intel_i225.network_data_plane_exports_fail_closed,
    i225_driver_present: bool = true,

    pub fn satisfied(self: IntelI225TransportProof) bool {
        if (!self.kernel_data_plane_disabled or !self.i225_driver_present) return false;
        intel_i225.validateRingPlan(self.ring_plan) catch return false;
        if (!self.packet_proof.verified()) return false;
        if (!sameRingPlan(self.ring_plan, self.packet_proof.ring_plan)) return false;
        if (self.packet_proof.tx_rx_cycles < hardware_target.first_supported_target.proof_minimums.network_frame_cycles) return false;
        return hardware_target.hardwareProofSatisfied(&hardware_target.first_supported_target, self.evidence);
    }
};

fn sameRingPlan(left: intel_i225.RingPlan, right: intel_i225.RingPlan) bool {
    return left.rx_descriptors == right.rx_descriptors and
        left.tx_descriptors == right.tx_descriptors and
        left.rx_ring_address == right.rx_ring_address and
        left.tx_ring_address == right.tx_ring_address;
}

pub const CapturedPacket = struct {
    in_use: bool = false,
    packet_id: u64 = 0,
    len: usize = 0,
    bytes: [network_driver_task.MAX_NATIVE_FRAME_BYTES]u8 = [_]u8{0} ** network_driver_task.MAX_NATIVE_FRAME_BYTES,

    pub fn slice(self: *const CapturedPacket) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn capturedPacketSlotId(slot: *const CapturedPacket) u64 {
    return slot.packet_id;
}

const CapturedPacketArena = indexed_arena.IndexedArenaWithKey(u64, CapturedPacket, MAX_CAPTURED_PACKETS, MAX_CAPTURED_PACKETS * 2, capturedPacketSlotId);

pub const PacketCapture = struct {
    packets: CapturedPacketArena = CapturedPacketArena.init(),
    next_packet_id: u64 = 1,
    last_packet_id: u64 = 0,
    captured_count: usize = 0,
    dropped_count: usize = 0,

    pub fn ensureCapacity(self: *PacketCapture) Error!void {
        if (self.packets.countInUse() < MAX_CAPTURED_PACKETS) return;
        self.dropped_count += 1;
        return error.PacketCaptureFull;
    }

    pub fn record(self: *PacketCapture, frame: []const u8) Error!void {
        if (frame.len > network_driver_task.MAX_NATIVE_FRAME_BYTES) return error.PacketTooLarge;
        const packet_id = self.allocatePacketId();
        const slot_index = self.packets.reserveIndex(packet_id) orelse {
            self.dropped_count += 1;
            return error.PacketCaptureFull;
        };
        const slot = &self.packets.slots[slot_index];
        slot.packet_id = packet_id;
        slot.len = frame.len;
        @memcpy(slot.bytes[0..frame.len], frame);
        self.last_packet_id = packet_id;
        self.captured_count += 1;
    }

    pub fn last(self: *const PacketCapture) ?CapturedPacket {
        const packet = self.lastPtr() orelse return null;
        return packet.*;
    }

    pub fn lastPtr(self: *const PacketCapture) ?*const CapturedPacket {
        if (self.last_packet_id == 0) return null;
        return self.packets.getConst(self.last_packet_id);
    }

    fn allocatePacketId(self: *PacketCapture) u64 {
        const packet_id = self.next_packet_id;
        self.next_packet_id +%= 1;
        if (self.next_packet_id == 0) self.next_packet_id = 1;
        return packet_id;
    }
};

pub const NativeConnection = struct {
    session: TransportSession,
    source_endpoint_id: ids.EndpointId,
    target_endpoint_id: ids.EndpointId,
    source_task_id: u64,
    target_task_id: u64,
    target_mac: ?[6]u8,
    connected: bool = true,
    next_sequence: u64 = 1,
    highest_sent_sequence: u64 = 0,
    highest_delivered_sequence: u64 = 0,
    in_flight_frames: usize = 0,

    pub fn isConnected(self: *const NativeConnection) bool {
        return self.connected;
    }
};

pub const NativeDelivery = struct {
    signed_frame: SignedEncryptedFrame,
    endpoint_delivered: bool,
    network_delivered: bool,
    relay_fallback: bool,
    congested: bool,
    sequence: u64,
    payload_len: usize,
};

pub const ObjectShareEnvelope = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    encrypted: bool,
    payload_len: usize,
    payload: [MAX_PACKET_BYTES]u8 = [_]u8{0} ** MAX_PACKET_BYTES,

    pub fn payloadSlice(self: *const ObjectShareEnvelope) []const u8 {
        return self.payload[0..self.payload_len];
    }
};

pub const NativeTransportService = struct {
    harness: Harness = Harness.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    capture: PacketCapture = .{},
    peer_links: network_driver_task.PeerLinkDirectory = .{},
    opened_connections: usize = 0,
    disconnected_connections: usize = 0,
    reconnect_count: usize = 0,
    endpoint_frame_count: usize = 0,
    network_frame_count: usize = 0,
    relay_fallback_count: usize = 0,
    congestion_drop_count: usize = 0,
    replay_rejection_count: usize = 0,
    revoked_device_rejection_count: usize = 0,
    peer_address_miss_count: usize = 0,
    production_attested_sessions_required: bool = false,
    i225_proof_required: bool = false,
    i225_proof_attached: bool = false,
    i225_proof_cycles: u16 = 0,
    i225_tx_tail_register_writes: u32 = 0,
    i225_rx_tail_register_writes: u32 = 0,
    i225_interrupt_cause_reads: u32 = 0,
    i225_link_speed_mbps: u32 = 0,
    i225_mac_address: [6]u8 = [_]u8{0} ** 6,
    trust_graph: ?*const device_graph.Graph = null,

    pub fn init() NativeTransportService {
        return .{};
    }

    pub fn bindTrustedDeviceGraph(self: *NativeTransportService, graph: *const device_graph.Graph) void {
        self.trust_graph = graph;
    }

    pub fn bindPeerLink(
        self: *NativeTransportService,
        device: principal.PrincipalId,
        mac: [6]u8,
    ) network_driver_task.PeerLinkError!void {
        try self.peer_links.bind(device, mac);
    }

    pub fn requireIntelI225Proof(self: *NativeTransportService) void {
        self.i225_proof_required = true;
    }

    pub fn requireProductionAttestedSessions(self: *NativeTransportService) void {
        self.production_attested_sessions_required = true;
    }

    pub fn intelI225NetworkReady(self: *const NativeTransportService) bool {
        const minimum = hardware_target.first_supported_target.proof_minimums.network_frame_cycles;
        const expected_interrupts = @as(u32, minimum) * 2;
        return self.i225_proof_attached and
            self.i225_proof_cycles >= minimum and
            self.i225_tx_tail_register_writes >= minimum and
            self.i225_rx_tail_register_writes >= minimum and
            self.i225_interrupt_cause_reads >= expected_interrupts and
            self.i225_link_speed_mbps != 0 and
            macAddressPresent(self.i225_mac_address);
    }

    pub fn attachIntelI225Proof(self: *NativeTransportService, proof: IntelI225TransportProof) Error!void {
        if (!proof.satisfied()) return error.NativeTransportHardwareProofMissing;
        self.i225_proof_attached = true;
        self.i225_proof_cycles = proof.packet_proof.tx_rx_cycles;
        self.i225_tx_tail_register_writes = proof.packet_proof.mmio.tx_tail_register_writes;
        self.i225_rx_tail_register_writes = proof.packet_proof.mmio.rx_tail_register_writes;
        self.i225_interrupt_cause_reads = proof.packet_proof.mmio.interrupt_cause_reads;
        self.i225_link_speed_mbps = proof.packet_proof.mmio.link_speed_mbps;
        self.i225_mac_address = proof.packet_proof.mac_address;
    }

    pub fn openDeviceToDevice(
        self: *NativeTransportService,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_task_id: u64,
        target_task_id: u64,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!NativeConnection {
        try self.ensureTrustedTransportDevices(source_device, target_device);
        const session = try self.harness.openDeviceToDevice(
            broker,
            request,
            source_device,
            target_device,
        );
        return self.openEndpointBackedConnection(session, source_task_id, target_task_id, true);
    }

    pub fn openServiceIdentity(
        self: *NativeTransportService,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_task_id: u64,
        target_task_id: u64,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!NativeConnection {
        try self.ensureTrustedTransportDevices(source_device, target_device);
        const session = try self.harness.openServiceIdentity(
            broker,
            request,
            source_device,
            target_device,
        );
        return self.openEndpointBackedConnection(session, source_task_id, target_task_id, false);
    }

    pub fn openVerifiedServiceIdentity(
        self: *NativeTransportService,
        broker: *network_policy.EgressBroker,
        request: VerifiedServiceIdentityOpenRequest,
        source_task_id: u64,
        target_task_id: u64,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!NativeConnection {
        try self.ensureTrustedTransportDevices(source_device, target_device);
        const session = try self.harness.openVerifiedServiceIdentity(
            broker,
            request,
            source_device,
            target_device,
        );
        return self.openEndpointBackedConnection(session, source_task_id, target_task_id, false);
    }

    pub fn openRelay(
        self: *NativeTransportService,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_task_id: u64,
        target_task_id: u64,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
        relay_domain: []const u8,
    ) Error!NativeConnection {
        try self.ensureTrustedTransportDevices(source_device, target_device);
        const session = try self.harness.openRelay(
            broker,
            request,
            source_device,
            target_device,
            relay_domain,
        );
        return self.openEndpointBackedConnection(session, source_task_id, target_task_id, false);
    }

    pub fn disconnect(self: *NativeTransportService, connection: *NativeConnection) void {
        if (!connection.connected) return;
        connection.connected = false;
        self.disconnected_connections += 1;
    }

    pub fn reconnect(self: *NativeTransportService, connection: *NativeConnection) void {
        if (connection.connected) return;
        connection.connected = true;
        self.reconnect_count += 1;
    }

    pub fn acknowledge(self: *NativeTransportService, connection: *NativeConnection, sequence: u64) void {
        _ = self;
        if (sequence == 0 or sequence > connection.highest_sent_sequence) return;
        if (sequence <= connection.highest_delivered_sequence) return;
        const newly_delivered = sequence - connection.highest_delivered_sequence;
        connection.highest_delivered_sequence = sequence;
        const delivered_frames: usize = if (newly_delivered > @as(u64, @intCast(connection.in_flight_frames)))
            connection.in_flight_frames
        else
            @intCast(newly_delivered);
        connection.in_flight_frames -|= delivered_frames;
    }

    pub fn sendSigned(
        self: *NativeTransportService,
        connection: *NativeConnection,
        plaintext: []const u8,
        signer: signing.SignerIdentity,
    ) Error!NativeDelivery {
        if (!connection.connected) return error.NativeTransportDisconnected;
        try self.ensureTrustedTransportDevices(connection.session.source_device, connection.session.target_device);
        try self.ensureProductionSessionReady(&connection.session);
        try self.ensureHardwareBackedNetworkReady();
        if (plaintext.len > MAX_NATIVE_PAYLOAD_BYTES) return error.PacketTooLarge;
        if (connection.in_flight_frames >= MAX_NATIVE_IN_FLIGHT_FRAMES) {
            self.congestion_drop_count += 1;
            return error.NativeTransportCongested;
        }
        const sequence = try self.pendingSequence(connection);
        try self.capture.ensureCapacity();
        const signed_frame = try self.harness.encryptSignedFrame(&connection.session, plaintext, signer);
        var wire_frame: [network_driver_task.MAX_NATIVE_FRAME_BYTES]u8 = undefined;
        const encoded = try encodeNativeSyncFrame(
            wire_frame[0..],
            &connection.session,
            connection.source_task_id,
            connection.target_task_id,
            sequence,
            &signed_frame,
        );
        try self.endpoints.send(
            connection.source_endpoint_id,
            ids.task(connection.source_task_id),
            signed_frame.packet.session_id,
            plaintext,
            null,
            false,
        );
        try self.capture.record(encoded);
        const network_delivered = if (connection.target_mac) |target_mac|
            network_driver_task.sendActiveFrame(target_mac, encoded)
        else blk: {
            self.peer_address_miss_count += 1;
            break :blk false;
        };
        self.endpoint_frame_count += 1;
        connection.in_flight_frames += 1;
        markSequenceSent(connection, sequence);
        if (network_delivered) self.network_frame_count += 1;

        return .{
            .signed_frame = signed_frame,
            .endpoint_delivered = true,
            .network_delivered = network_delivered,
            .relay_fallback = false,
            .congested = false,
            .sequence = sequence,
            .payload_len = plaintext.len,
        };
    }

    pub fn assertLastCapturedFrame(
        self: *const NativeTransportService,
        expectation: CapturedFrameExpectation,
    ) Error!NativeSyncFrameView {
        return assertLastCapturedNativeSyncFrame(&self.capture, expectation);
    }

    pub fn sendWithRelayFallback(
        self: *NativeTransportService,
        connection: *NativeConnection,
        relay_service: *BootedOverlayRelayService,
        plaintext: []const u8,
        signer: signing.SignerIdentity,
    ) Error!NativeDelivery {
        const delivery = self.sendSigned(connection, plaintext, signer) catch |err| switch (err) {
            error.NativeTransportDisconnected, error.NativeTransportCongested => {
                try self.ensureTrustedTransportDevices(connection.session.source_device, connection.session.target_device);
                try self.ensureProductionSessionReady(&connection.session);
                try self.ensureHardwareBackedNetworkReady();
                const sequence = try self.pendingSequence(connection);
                const signed_frame = try self.harness.encryptSignedFrame(&connection.session, plaintext, signer);
                try relay_service.submitSignedFrame(connection.session.task_id, &connection.session, signed_frame);
                markSequenceSent(connection, sequence);
                self.relay_fallback_count += 1;
                return .{
                    .signed_frame = signed_frame,
                    .endpoint_delivered = false,
                    .network_delivered = false,
                    .relay_fallback = true,
                    .congested = err == error.NativeTransportCongested,
                    .sequence = sequence,
                    .payload_len = plaintext.len,
                };
            },
            else => return err,
        };
        if (!delivery.network_delivered) {
            try self.ensureTrustedTransportDevices(connection.session.source_device, connection.session.target_device);
            try relay_service.submitSignedFrame(connection.session.task_id, &connection.session, delivery.signed_frame);
            self.relay_fallback_count += 1;
            return .{
                .signed_frame = delivery.signed_frame,
                .endpoint_delivered = delivery.endpoint_delivered,
                .network_delivered = false,
                .relay_fallback = true,
                .congested = false,
                .sequence = delivery.sequence,
                .payload_len = delivery.payload_len,
            };
        }
        return delivery;
    }

    pub fn encryptObjectShare(
        self: *NativeTransportService,
        connection: *const NativeConnection,
        workspace_id: u64,
        object_id: u64,
        version_id: u64,
        payload: []const u8,
    ) Error!ObjectShareEnvelope {
        try self.ensureTrustedTransportDevices(connection.session.source_device, connection.session.target_device);
        try self.ensureProductionSessionReady(&connection.session);
        const packet = try self.harness.encryptPacket(&connection.session, payload);
        var envelope = ObjectShareEnvelope{
            .workspace_id = workspace_id,
            .object_id = object_id,
            .version_id = version_id,
            .encrypted = packet.encrypted,
            .payload_len = packet.ciphertext_len,
        };
        @memcpy(envelope.payload[0..packet.ciphertext_len], packet.ciphertextSlice());
        return envelope;
    }

    pub fn receive(self: *NativeTransportService, connection: *const NativeConnection) Error!endpoint.Message {
        return (try self.endpoints.recv(connection.target_endpoint_id)) orelse error.NativeTransportFrameMissing;
    }

    fn openEndpointBackedConnection(
        self: *NativeTransportService,
        session: TransportSession,
        source_task_id: u64,
        target_task_id: u64,
        local_only: bool,
    ) Error!NativeConnection {
        if (source_task_id == 0 or target_task_id == 0 or source_task_id == target_task_id) {
            return error.NativeTransportMalformedFrame;
        }
        const source_endpoint = try self.endpoints.create(ids.task(source_task_id), "sync-out", .{
            .local_only = local_only,
        });
        const target_endpoint = try self.endpoints.create(ids.task(target_task_id), "sync-in", .{
            .local_only = local_only,
            .service_port = true,
        });
        try self.endpoints.connect(source_endpoint.id, target_endpoint.id);
        self.opened_connections += 1;
        return .{
            .session = session,
            .source_endpoint_id = source_endpoint.id,
            .target_endpoint_id = target_endpoint.id,
            .source_task_id = source_task_id,
            .target_task_id = target_task_id,
            .target_mac = self.peer_links.resolve(session.target_device),
            .connected = true,
        };
    }

    fn ensureTrustedTransportDevices(
        self: *NativeTransportService,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!void {
        const graph = self.trust_graph orelse return;
        if (!graph.isTrusted(source_device) or !graph.isTrusted(target_device)) {
            self.revoked_device_rejection_count += 1;
            return error.NativeTransportDeviceRevoked;
        }
    }

    fn ensureHardwareBackedNetworkReady(self: *const NativeTransportService) Error!void {
        if (self.i225_proof_required and !self.intelI225NetworkReady()) {
            return error.NativeTransportHardwareProofMissing;
        }
    }

    fn ensureProductionSessionReady(self: *const NativeTransportService, session: *const TransportSession) Error!void {
        if (self.production_attested_sessions_required) {
            try session.requireProductionAttestation();
        }
    }

    fn pendingSequence(self: *NativeTransportService, connection: *const NativeConnection) Error!u64 {
        const sequence = connection.next_sequence;
        if (sequence == 0) return error.NativeTransportSequenceExhausted;
        if (sequence <= connection.highest_sent_sequence or
            (sequence <= connection.highest_delivered_sequence and
                connection.highest_delivered_sequence - sequence >= sync_state.TRANSPORT_REPLAY_WINDOW))
        {
            self.replay_rejection_count += 1;
            return error.NativeTransportReplayRejected;
        }
        return sequence;
    }
};

fn markSequenceSent(connection: *NativeConnection, sequence: u64) void {
    if (sequence > connection.highest_sent_sequence) connection.highest_sent_sequence = sequence;
    if (connection.next_sequence == sequence) {
        connection.next_sequence = if (sequence == std.math.maxInt(u64)) 0 else sequence + 1;
    }
}

pub fn assertLastCapturedNativeSyncFrame(
    capture: *const PacketCapture,
    expectation: CapturedFrameExpectation,
) Error!NativeSyncFrameView {
    const captured = capture.lastPtr() orelse return error.NativeTransportFrameMissing;
    const view = try decodeNativeSyncFrame(captured.slice());
    if (view.abi_version != NativeTransportAbi.version or view.header_len != NativeTransportAbi.fixed_header_bytes) {
        return error.NativeTransportMalformedFrame;
    }
    if (view.session_id != expectation.session_id or
        view.sequence != expectation.sequence or
        view.source_task_id != expectation.source_task_id or
        view.target_task_id != expectation.target_task_id or
        view.transport != expectation.transport or
        !view.source_device.eql(expectation.source_device) or
        !view.target_device.eql(expectation.target_device) or
        view.policy_id != expectation.policy_id or
        view.capability_id != expectation.capability_id or
        !view.encrypted() or
        !view.egressAllowed())
    {
        return error.NativeTransportMalformedFrame;
    }
    if (expectation.forbidden_plaintext.len != 0 and std.mem.indexOf(u8, captured.slice(), expectation.forbidden_plaintext) != null) {
        return error.PacketAuthenticationFailed;
    }
    return view;
}

pub fn decodeNativeSyncFrame(frame: []const u8) Error!NativeSyncFrameView {
    if (frame.len < NativeTransportAbi.fixed_header_bytes + 64) return error.NativeTransportMalformedFrame;

    var reader = NativeFrameReader{ .buffer = frame };
    if (!std.mem.eql(u8, try reader.readSlice(NativeTransportAbi.magic.len), &NativeTransportAbi.magic)) return error.NativeTransportMalformedFrame;

    const abi_version = try reader.readU16();
    if (abi_version != NativeTransportAbi.version) return error.NativeTransportMalformedFrame;
    const header_len = try reader.readU16();
    if (header_len != NativeTransportAbi.fixed_header_bytes) return error.NativeTransportMalformedFrame;

    const session_id = try reader.readU64();
    const sequence = try reader.readU64();
    const source_task_id = try reader.readU64();
    const target_task_id = try reader.readU64();
    if (session_id == 0 or sequence == 0) return error.NativeTransportMalformedFrame;
    if (source_task_id == 0 or target_task_id == 0 or source_task_id == target_task_id) return error.NativeTransportMalformedFrame;
    const transport = try parseTransportMode(try reader.readByte());
    const source_kind = try parsePrincipalKind(try reader.readByte());
    const target_kind = try parsePrincipalKind(try reader.readByte());
    const flags = try reader.readByte();
    const known_flags: u8 = NativeTransportAbi.flag_encrypted | NativeTransportAbi.flag_egress_allowed;
    if ((flags & ~known_flags) != 0) return error.NativeTransportMalformedFrame;
    const encrypted = (flags & NativeTransportAbi.flag_encrypted) != 0;
    const egress_allowed = (flags & NativeTransportAbi.flag_egress_allowed) != 0;
    if (!encrypted or !egress_allowed) return error.NativeTransportMalformedFrame;
    if (source_kind != .device or target_kind != .device) return error.NativeTransportMalformedFrame;
    const policy_id = try reader.readU64();
    const capability_id = try reader.readU64();
    const source_serial = try reader.readU64();
    const target_serial = try reader.readU64();
    if (policy_id == 0 or capability_id == 0) return error.NativeTransportMalformedFrame;
    if (source_serial == 0 or target_serial == 0 or source_serial == target_serial) return error.NativeTransportMalformedFrame;
    const ciphertext_len = try reader.readU16();
    if (ciphertext_len > MAX_PACKET_BYTES) return error.NativeTransportMalformedFrame;
    if (reader.remaining() != ciphertext_len + 64) return error.NativeTransportMalformedFrame;
    const ciphertext = try reader.readSlice(ciphertext_len);
    const payload_digest = try reader.readSlice(32);
    const packet_digest = try reader.readSlice(32);

    var packet = EncryptedPacket{
        .session_id = session_id,
        .transport = transport,
        .policy_id = policy_id,
        .capability_id = capability_id,
        .source_device = .{ .kind = source_kind, .serial = source_serial },
        .target_device = .{ .kind = target_kind, .serial = target_serial },
        .ciphertext_len = ciphertext.len,
        .ciphertext = [_]u8{0} ** MAX_PACKET_BYTES,
        .payload_digest = payload_digest[0..32].*,
        .encrypted = encrypted,
        .egress_allowed = egress_allowed,
    };
    if (ciphertext.len > packet.ciphertext.len) return error.NativeTransportMalformedFrame;
    @memcpy(packet.ciphertext[0..ciphertext.len], ciphertext);
    const expected_digest = harness.packetDigest(packet);
    if (!std.mem.eql(u8, &expected_digest, packet_digest)) return error.PacketAuthenticationFailed;

    return .{
        .abi_version = abi_version,
        .header_len = header_len,
        .session_id = session_id,
        .sequence = sequence,
        .source_task_id = source_task_id,
        .target_task_id = target_task_id,
        .transport = transport,
        .source_device = .{ .kind = source_kind, .serial = source_serial },
        .target_device = .{ .kind = target_kind, .serial = target_serial },
        .flags = flags,
        .policy_id = policy_id,
        .capability_id = capability_id,
        .ciphertext = ciphertext,
        .payload_digest = payload_digest,
        .packet_digest = packet_digest,
    };
}

pub fn encodeNativeSyncFrame(
    buffer: []u8,
    session: *const TransportSession,
    source_task_id: u64,
    target_task_id: u64,
    sequence: u64,
    frame: *const SignedEncryptedFrame,
) Error![]const u8 {
    try validateNativeFrameForSession(session, source_task_id, target_task_id, &frame.packet);
    const ciphertext = frame.packet.ciphertextSlice();
    if (ciphertext.len > std.math.maxInt(u16)) return error.PacketTooLarge;
    const required_len = NativeTransportAbi.fixed_header_bytes + ciphertext.len + frame.packet.payload_digest.len + frame.packet_digest.len;
    if (buffer.len < required_len) return error.PacketTooLarge;

    var writer = NativeFrameWriter{ .buffer = buffer };
    try writer.writeBytes(&NativeTransportAbi.magic);
    try writer.writeU16(NativeTransportAbi.version);
    try writer.writeU16(@intCast(NativeTransportAbi.fixed_header_bytes));
    try writer.writeU64(session.id);
    try writer.writeU64(sequence);
    try writer.writeU64(source_task_id);
    try writer.writeU64(target_task_id);
    try writer.writeByte(@intFromEnum(session.transport));
    try writer.writeByte(@intFromEnum(frame.packet.source_device.kind));
    try writer.writeByte(@intFromEnum(frame.packet.target_device.kind));
    const flags = (if (frame.packet.encrypted) NativeTransportAbi.flag_encrypted else 0) |
        (if (frame.packet.egress_allowed) NativeTransportAbi.flag_egress_allowed else 0);
    try writer.writeByte(flags);
    try writer.writeU64(frame.packet.policy_id);
    try writer.writeU64(frame.packet.capability_id);
    try writer.writeU64(frame.packet.source_device.serial);
    try writer.writeU64(frame.packet.target_device.serial);
    try writer.writeU16(@intCast(ciphertext.len));
    try writer.writeBytes(ciphertext);
    try writer.writeBytes(&frame.packet.payload_digest);
    try writer.writeBytes(&frame.packet_digest);
    return buffer[0..writer.offset];
}

fn validateNativeFrameForSession(
    session: *const TransportSession,
    source_task_id: u64,
    target_task_id: u64,
    packet: *const EncryptedPacket,
) Error!void {
    if (session.id == 0 or session.task_id == 0 or session.policy_id == 0 or session.capability_id == 0) {
        return error.NativeTransportMalformedFrame;
    }
    if (source_task_id == 0 or target_task_id == 0 or source_task_id == target_task_id) return error.NativeTransportMalformedFrame;
    if (session.source_device.kind != .device or session.target_device.kind != .device) return error.NativeTransportMalformedFrame;
    if (session.source_device.serial == 0 or session.target_device.serial == 0) return error.NativeTransportMalformedFrame;
    if (session.source_device.eql(session.target_device)) return error.NativeTransportMalformedFrame;
    if (packet.ciphertext_len > packet.ciphertext.len) return error.PacketTooLarge;
    if (!packet.encrypted or !packet.egress_allowed) return error.NativeTransportMalformedFrame;
    if (packet.session_id != session.id or
        packet.transport != session.transport or
        packet.policy_id != session.policy_id or
        packet.capability_id != session.capability_id or
        !packet.source_device.eql(session.source_device) or
        !packet.target_device.eql(session.target_device))
    {
        return error.NativeTransportMalformedFrame;
    }
}

fn parseTransportMode(raw: u8) Error!sync_state.TransportMode {
    return switch (raw) {
        @intFromEnum(sync_state.TransportMode.device_to_device) => .device_to_device,
        @intFromEnum(sync_state.TransportMode.relay_assisted) => .relay_assisted,
        else => error.NativeTransportMalformedFrame,
    };
}

fn parsePrincipalKind(raw: u8) Error!principal.PrincipalKind {
    return switch (raw) {
        @intFromEnum(principal.PrincipalKind.user) => .user,
        @intFromEnum(principal.PrincipalKind.device) => .device,
        @intFromEnum(principal.PrincipalKind.app) => .app,
        @intFromEnum(principal.PrincipalKind.service) => .service,
        @intFromEnum(principal.PrincipalKind.policy_authority) => .policy_authority,
        @intFromEnum(principal.PrincipalKind.team) => .team,
        else => error.NativeTransportMalformedFrame,
    };
}

fn macAddressPresent(mac_address: [6]u8) bool {
    for (mac_address) |byte| {
        if (byte != 0) return true;
    }
    return false;
}

fn expectNativeEncodeError(
    expected_error: anyerror,
    session: *const TransportSession,
    frame: *const SignedEncryptedFrame,
) !void {
    var wire_frame: [network_driver_task.MAX_NATIVE_FRAME_BYTES]u8 = undefined;
    try std.testing.expectError(expected_error, encodeNativeSyncFrame(wire_frame[0..], session, 1, 2, 1, frame));
}

test "native sync transport uses endpoints and reconnects without the in-process relay queue" {
    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 40 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 41 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 42 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 43 };
    const relay = try policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.native.sync",
    });
    const relay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 44 },
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 45, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 80 },
        .audit = .{},
    });
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var native_transport = NativeTransportService.init();
    try std.testing.expectError(error.NativeTransportMalformedFrame, native_transport.openRelay(&broker, .{
        .task_id = 45,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.native.sync" } },
        .now_ticks = 20,
    }, 0, 46, source, target, "relay.native.sync"));
    try std.testing.expectError(error.NativeTransportMalformedFrame, native_transport.openRelay(&broker, .{
        .task_id = 45,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.native.sync" } },
        .now_ticks = 20,
    }, 45, 45, source, target, "relay.native.sync"));
    try std.testing.expectEqual(@as(usize, 0), native_transport.opened_connections);
    var connection = try native_transport.openRelay(&broker, .{
        .task_id = 45,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.native.sync" } },
        .now_ticks = 20,
    }, 45, 46, source, target, "relay.native.sync");

    const signer = signing.SignerIdentity{ .label = "native-sync-transport", .seed = signing.seedFromByte(0x45) };
    native_transport.disconnect(&connection);
    try std.testing.expectError(error.NativeTransportDisconnected, native_transport.sendSigned(&connection, "queued while offline", signer));
    native_transport.reconnect(&connection);
    try std.testing.expectError(error.PacketEmpty, native_transport.sendSigned(&connection, "", signer));
    try std.testing.expectEqual(@as(usize, 0), native_transport.endpoint_frame_count);
    try std.testing.expectEqual(@as(usize, 0), native_transport.network_frame_count);
    const delivered = try native_transport.sendSigned(&connection, "sync after reconnect", signer);
    try std.testing.expect(delivered.endpoint_delivered);
    try std.testing.expect(verifySignedFrame(&delivered.signed_frame));
    const received = try native_transport.receive(&connection);
    try std.testing.expectEqualStrings("sync after reconnect", received.payload());
    native_transport.acknowledge(&connection, delivered.sequence);

    const max_payload = [_]u8{0xA5} ** MAX_NATIVE_PAYLOAD_BYTES;
    const max_delivery = try native_transport.sendSigned(&connection, &max_payload, signer);
    const max_received = try native_transport.receive(&connection);
    try std.testing.expectEqualSlices(u8, &max_payload, max_received.payload());
    native_transport.acknowledge(&connection, max_delivery.sequence);

    const oversized_payload = [_]u8{0xA5} ** (MAX_NATIVE_PAYLOAD_BYTES + 1);
    const endpoint_frames_before_oversized = native_transport.endpoint_frame_count;
    const captured_frames_before_oversized = native_transport.capture.captured_count;
    try std.testing.expectError(error.PacketTooLarge, native_transport.sendSigned(&connection, &oversized_payload, signer));
    try std.testing.expectEqual(endpoint_frames_before_oversized, native_transport.endpoint_frame_count);
    try std.testing.expectEqual(captured_frames_before_oversized, native_transport.capture.captured_count);
    try std.testing.expectEqual(@as(usize, 1), native_transport.opened_connections);
    try std.testing.expectEqual(@as(usize, 1), native_transport.disconnected_connections);
    try std.testing.expectEqual(@as(usize, 1), native_transport.reconnect_count);
    try std.testing.expectEqual(@as(usize, 2), native_transport.endpoint_frame_count);
}

test "native sync transport captures encrypted driver packets and handles replay and congestion" {
    const Driver = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;
        var last_frame: [network_driver_task.MAX_NATIVE_FRAME_BYTES]u8 = [_]u8{0} ** network_driver_task.MAX_NATIVE_FRAME_BYTES;
        var last_destination: [6]u8 = [_]u8{0} ** 6;

        fn send(destination: [6]u8, frame: []const u8) bool {
            send_count += 1;
            last_frame_len = frame.len;
            last_destination = destination;
            @memcpy(last_frame[0..frame.len], frame);
            return true;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 0x51 };
        }

        fn driverEgressBroker(request: network_driver_task.EgressRequest) network_driver_task.EgressDecision {
            return .{
                .allowed = request.network_policy_id == 91,
                .capability_backed = request.egress_capability_id == 92,
            };
        }
    };

    Driver.send_count = 0;
    Driver.last_frame_len = 0;
    Driver.last_destination = [_]u8{0} ** 6;
    network_driver_task.reset();
    defer network_driver_task.reset();
    const device = network_driver_task.NetworkDevice{
        .send = Driver.send,
        .receive = network_driver_task.noNetworkFrame,
        .getMacAddress = Driver.mac,
    };
    try std.testing.expect(network_driver_task.activateDevice(&device, 90));
    network_driver_task.setEgressBroker(Driver.driverEgressBroker);
    network_driver_task.bindEgressCapability(92, 91);

    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 90 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 91 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 92 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 93 };
    const relay = try policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.capture.sync",
    });
    const relay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 94 },
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 95, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var native_transport = NativeTransportService.init();
    try native_transport.bindPeerLink(target, .{ 0x02, 0, 0, 0, 0, 0x52 });
    var connection = try native_transport.openRelay(&broker, .{
        .task_id = 95,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.capture.sync" } },
        .now_ticks = 20,
    }, 95, 96, source, target, "relay.capture.sync");
    const signer = signing.SignerIdentity{ .label = "native-sync-capture", .seed = signing.seedFromByte(0x52) };

    const delivered = try native_transport.sendSigned(&connection, "object delta", signer);
    try std.testing.expect(delivered.network_delivered);
    try std.testing.expectEqual(@as(u64, 1), delivered.sequence);
    try std.testing.expectEqual(@as(usize, 1), Driver.send_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0, 0, 0, 0, 0x52 }, &Driver.last_destination);
    try std.testing.expectEqual(@as(usize, 1), native_transport.capture.captured_count);
    const captured = native_transport.capture.last().?;
    try std.testing.expect(std.mem.startsWith(u8, captured.slice(), "ZGST"));
    try std.testing.expect(std.mem.indexOf(u8, captured.slice(), "object delta") == null);
    try std.testing.expectEqualSlices(u8, captured.slice(), Driver.last_frame[0..Driver.last_frame_len]);
    const view = try native_transport.assertLastCapturedFrame(.{
        .session_id = connection.session.id,
        .sequence = delivered.sequence,
        .source_task_id = connection.source_task_id,
        .target_task_id = connection.target_task_id,
        .transport = .relay_assisted,
        .source_device = source,
        .target_device = target,
        .policy_id = relay.id,
        .capability_id = relay_capability.id,
        .forbidden_plaintext = "object delta",
    });
    try std.testing.expectEqual(NativeTransportAbi.version, view.abi_version);
    try std.testing.expectEqual(@as(u16, @intCast(NativeTransportAbi.fixed_header_bytes)), view.header_len);
    try std.testing.expect(view.encrypted());
    try std.testing.expect(view.egressAllowed());
    try std.testing.expect(!std.mem.eql(u8, view.ciphertext, "object delta"));
    try std.testing.expectEqualSlices(u8, delivered.signed_frame.packet.payload_digest[0..], view.payload_digest);
    try std.testing.expectEqualSlices(u8, delivered.signed_frame.packet_digest[0..], view.packet_digest);
    const session_id_offset = 4 + 2 + 2;
    const sequence_offset = session_id_offset + @sizeOf(u64);
    const source_task_id_offset = sequence_offset + @sizeOf(u64);
    const target_task_id_offset = source_task_id_offset + @sizeOf(u64);
    const transport_offset = target_task_id_offset + @sizeOf(u64);
    const source_kind_offset = transport_offset + 1;
    const target_kind_offset = source_kind_offset + 1;
    const flags_offset = target_kind_offset + 1;
    const policy_id_offset = flags_offset + 1;
    const capability_id_offset = policy_id_offset + @sizeOf(u64);
    const source_serial_offset = capability_id_offset + @sizeOf(u64);
    const target_serial_offset = source_serial_offset + @sizeOf(u64);
    const ciphertext_len_offset = target_serial_offset + @sizeOf(u64);

    var zero_session_id = captured;
    std.mem.writeInt(u64, zero_session_id.bytes[session_id_offset..][0..@sizeOf(u64)], 0, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(zero_session_id.slice()));
    var zero_sequence = captured;
    std.mem.writeInt(u64, zero_sequence.bytes[sequence_offset..][0..@sizeOf(u64)], 0, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(zero_sequence.slice()));
    var zero_source_task = captured;
    std.mem.writeInt(u64, zero_source_task.bytes[source_task_id_offset..][0..@sizeOf(u64)], 0, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(zero_source_task.slice()));
    var zero_target_task = captured;
    std.mem.writeInt(u64, zero_target_task.bytes[target_task_id_offset..][0..@sizeOf(u64)], 0, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(zero_target_task.slice()));
    var same_task_ids = captured;
    std.mem.writeInt(u64, same_task_ids.bytes[target_task_id_offset..][0..@sizeOf(u64)], connection.source_task_id, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(same_task_ids.slice()));
    var unsupported_transport = captured;
    unsupported_transport.bytes[transport_offset] = 0xff;
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(unsupported_transport.slice()));
    var tampered_flags = captured;
    tampered_flags.bytes[flags_offset] |= 0x80;
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(tampered_flags.slice()));
    var missing_encryption_flag = captured;
    missing_encryption_flag.bytes[flags_offset] &= ~NativeTransportAbi.flag_encrypted;
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(missing_encryption_flag.slice()));
    var missing_egress_flag = captured;
    missing_egress_flag.bytes[flags_offset] &= ~NativeTransportAbi.flag_egress_allowed;
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(missing_egress_flag.slice()));
    var non_device_source = captured;
    non_device_source.bytes[source_kind_offset] = @intFromEnum(principal.PrincipalKind.app);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(non_device_source.slice()));
    var non_device_target = captured;
    non_device_target.bytes[target_kind_offset] = @intFromEnum(principal.PrincipalKind.service);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(non_device_target.slice()));
    var zero_policy = captured;
    std.mem.writeInt(u64, zero_policy.bytes[policy_id_offset..][0..@sizeOf(u64)], 0, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(zero_policy.slice()));
    var zero_capability = captured;
    std.mem.writeInt(u64, zero_capability.bytes[capability_id_offset..][0..@sizeOf(u64)], 0, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(zero_capability.slice()));
    var zero_source_serial = captured;
    std.mem.writeInt(u64, zero_source_serial.bytes[source_serial_offset..][0..@sizeOf(u64)], 0, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(zero_source_serial.slice()));
    var zero_target_serial = captured;
    std.mem.writeInt(u64, zero_target_serial.bytes[target_serial_offset..][0..@sizeOf(u64)], 0, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(zero_target_serial.slice()));
    var same_device_serials = captured;
    std.mem.writeInt(u64, same_device_serials.bytes[target_serial_offset..][0..@sizeOf(u64)], source.serial, .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(same_device_serials.slice()));
    var oversized_ciphertext = captured;
    std.mem.writeInt(u16, oversized_ciphertext.bytes[ciphertext_len_offset..][0..@sizeOf(u16)], @intCast(MAX_PACKET_BYTES + 1), .little);
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(oversized_ciphertext.slice()));
    var tampered_payload_digest = captured;
    tampered_payload_digest.bytes[tampered_payload_digest.len - 64] ^= 0x40;
    try std.testing.expectError(error.PacketAuthenticationFailed, decodeNativeSyncFrame(tampered_payload_digest.slice()));
    var tampered_packet_digest = captured;
    tampered_packet_digest.bytes[tampered_packet_digest.len - 1] ^= 0x20;
    try std.testing.expectError(error.PacketAuthenticationFailed, decodeNativeSyncFrame(tampered_packet_digest.slice()));

    var forged_frame = delivered.signed_frame;
    forged_frame.packet.session_id += 1;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &connection.session, &forged_frame);
    forged_frame = delivered.signed_frame;
    forged_frame.packet.transport = .device_to_device;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &connection.session, &forged_frame);
    forged_frame = delivered.signed_frame;
    forged_frame.packet.policy_id += 1;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &connection.session, &forged_frame);
    forged_frame = delivered.signed_frame;
    forged_frame.packet.capability_id += 1;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &connection.session, &forged_frame);
    forged_frame = delivered.signed_frame;
    forged_frame.packet.source_device = target;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &connection.session, &forged_frame);
    forged_frame = delivered.signed_frame;
    forged_frame.packet.target_device = source;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &connection.session, &forged_frame);
    forged_frame = delivered.signed_frame;
    forged_frame.packet.encrypted = false;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &connection.session, &forged_frame);
    forged_frame = delivered.signed_frame;
    forged_frame.packet.egress_allowed = false;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &connection.session, &forged_frame);
    forged_frame = delivered.signed_frame;
    forged_frame.packet.ciphertext_len = MAX_PACKET_BYTES + 1;
    try expectNativeEncodeError(error.PacketTooLarge, &connection.session, &forged_frame);
    var invalid_session = connection.session;
    invalid_session.id = 0;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &invalid_session, &delivered.signed_frame);
    invalid_session = connection.session;
    invalid_session.target_device = invalid_session.source_device;
    try expectNativeEncodeError(error.NativeTransportMalformedFrame, &invalid_session, &delivered.signed_frame);

    _ = try native_transport.sendSigned(&connection, "two", signer);
    _ = try native_transport.sendSigned(&connection, "three", signer);
    _ = try native_transport.sendSigned(&connection, "four", signer);
    try std.testing.expectEqual(@as(usize, 4), connection.in_flight_frames);
    try std.testing.expectError(error.NativeTransportCongested, native_transport.sendSigned(&connection, "five", signer));
    try std.testing.expectEqual(@as(usize, 1), native_transport.congestion_drop_count);

    native_transport.acknowledge(&connection, 2);
    try std.testing.expectEqual(@as(u64, 2), connection.highest_delivered_sequence);
    try std.testing.expectEqual(@as(usize, 2), connection.in_flight_frames);
    native_transport.acknowledge(&connection, 2);
    try std.testing.expectEqual(@as(usize, 2), connection.in_flight_frames);
    native_transport.acknowledge(&connection, 99);
    try std.testing.expectEqual(@as(usize, 2), connection.in_flight_frames);
    native_transport.acknowledge(&connection, 4);
    try std.testing.expectEqual(@as(usize, 0), connection.in_flight_frames);

    while (native_transport.capture.packets.countInUse() < MAX_CAPTURED_PACKETS) {
        try native_transport.capture.record("capacity-fill");
    }
    const endpoint_frames_before_capture_full = native_transport.endpoint_frame_count;
    const network_frames_before_capture_full = native_transport.network_frame_count;
    const next_sequence_before_capture_full = connection.next_sequence;
    try std.testing.expectError(error.PacketCaptureFull, native_transport.sendSigned(&connection, "audit full", signer));
    try std.testing.expectEqual(endpoint_frames_before_capture_full, native_transport.endpoint_frame_count);
    try std.testing.expectEqual(network_frames_before_capture_full, native_transport.network_frame_count);
    try std.testing.expectEqual(next_sequence_before_capture_full, connection.next_sequence);
    try std.testing.expectEqual(@as(usize, 1), native_transport.capture.dropped_count);
    native_transport.capture = .{};

    connection.next_sequence = 3;
    try std.testing.expectError(error.NativeTransportReplayRejected, native_transport.sendSigned(&connection, "replay", signer));
    try std.testing.expectEqual(@as(usize, 1), native_transport.replay_rejection_count);

    connection.next_sequence = std.math.maxInt(u64);
    connection.highest_sent_sequence = std.math.maxInt(u64) - 1;
    connection.highest_delivered_sequence = std.math.maxInt(u64) - 1;
    connection.in_flight_frames = 0;
    const last_delivery = try native_transport.sendSigned(&connection, "last sequence", signer);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), last_delivery.sequence);
    try std.testing.expectEqual(@as(u64, 0), connection.next_sequence);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), connection.highest_sent_sequence);
    try std.testing.expectEqual(@as(usize, 1), connection.in_flight_frames);
    native_transport.acknowledge(&connection, std.math.maxInt(u64));
    try std.testing.expectEqual(@as(usize, 0), connection.in_flight_frames);

    const endpoint_frames_before_exhaustion = native_transport.endpoint_frame_count;
    const network_frames_before_exhaustion = native_transport.network_frame_count;
    const captured_frames_before_exhaustion = native_transport.capture.captured_count;
    try std.testing.expectError(
        error.NativeTransportSequenceExhausted,
        native_transport.sendSigned(&connection, "exhausted", signer),
    );
    try std.testing.expectEqual(@as(u64, 0), connection.next_sequence);
    try std.testing.expectEqual(endpoint_frames_before_exhaustion, native_transport.endpoint_frame_count);
    try std.testing.expectEqual(network_frames_before_exhaustion, native_transport.network_frame_count);
    try std.testing.expectEqual(captured_frames_before_exhaustion, native_transport.capture.captured_count);
    try std.testing.expectEqual(@as(usize, 1), native_transport.replay_rejection_count);
}

fn verifiedSyncPeerBoot(generation: u64) !measured_boot.BootRecord {
    var recorder = measured_boot.Recorder.init();
    var artifact_manifest = measured_boot.ArtifactManifest.init(generation);
    recorder.begin(generation);
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos-sync", "kernel=v1");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .base_image, "stable-sync", "image=v1");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "compositor", "healthy");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .policy, "production-sync-policy", "strict");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .driver_set, "production-sync-drivers", "i225");
    var boot = recorder.finalize();
    try measured_boot.verifyBootRecordAgainstManifest(&boot, &artifact_manifest, .bootloader_provided);
    return boot;
}

test "native sync transport rejects revoked trusted devices and requires real I225 proof" {
    var graph = device_graph.Graph.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 170 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 171 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 172 };
    const owner = principal.PrincipalId{ .kind = .service, .serial = 173 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 174 };
    const user_signer = signing.SignerIdentity{ .label = "native-revocation-user", .seed = signing.seedFromByte(0x61) };
    const source_signer = signing.SignerIdentity{ .label = "native-revocation-source", .seed = signing.seedFromByte(0x62) };
    const target_signer = signing.SignerIdentity{ .label = "native-revocation-target", .seed = signing.seedFromByte(0x63) };
    const frame_signer = signing.SignerIdentity{ .label = "native-revocation-frame", .seed = signing.seedFromByte(0x64) };

    _ = try graph.ensureUserRoot(user, "owner", user_signer);
    _ = try graph.enrollDevice(user, source, "source", user_signer, source_signer, 1);
    _ = try graph.enrollDevice(user, target, "target", user_signer, target_signer, 2);

    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const relay = try policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.revoked.sync",
    });
    const relay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 175 },
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 176, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var native_transport = NativeTransportService.init();
    native_transport.bindTrustedDeviceGraph(&graph);

    var connection = try native_transport.openRelay(&broker, .{
        .task_id = 176,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.revoked.sync" } },
        .now_ticks = 10,
    }, 176, 177, source, target, "relay.revoked.sync");

    try graph.revokeDevice(user, target, user_signer, 20);
    try std.testing.expectError(error.NativeTransportDeviceRevoked, native_transport.encryptObjectShare(&connection, 1, 2, 3, "blocked object share after revoke"));
    try std.testing.expectError(error.NativeTransportDeviceRevoked, native_transport.sendSigned(&connection, "blocked after revoke", frame_signer));
    native_transport.disconnect(&connection);
    var relay_service = try BootedOverlayRelayService.init(178, 176, "relay.revoked.sync");
    try std.testing.expectError(error.NativeTransportDeviceRevoked, native_transport.sendWithRelayFallback(&connection, &relay_service, "blocked fallback after revoke", frame_signer));
    try std.testing.expectEqual(@as(usize, 0), relay_service.accepted_packets);
    try std.testing.expectError(error.NativeTransportDeviceRevoked, native_transport.openRelay(&broker, .{
        .task_id = 176,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.revoked.sync" } },
        .now_ticks = 21,
    }, 176, 177, source, target, "relay.revoked.sync"));
    try std.testing.expectEqual(@as(usize, 4), native_transport.revoked_device_rejection_count);

    const good_ring_plan = intel_i225.RingPlan{
        .rx_descriptors = 256,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    };
    var i225_adapter = try intel_i225.SoftwareAdapter.initWithMmio(
        good_ring_plan,
        .{ 0x02, 0x15, 0xF2, 0, 0, 8 },
        intel_i225.defaultPhyLinkState(),
        intel_i225.defaultPacketBufferPlan(),
    );
    const packet_proof = try i225_adapter.proveFrameCycles(hardware_target.first_supported_target.proof_minimums.network_frame_cycles);
    const incomplete_proof = IntelI225TransportProof{
        .evidence = .{
            .target_id = hardware_target.first_supported_target.id,
            .source = .qemu,
        },
        .ring_plan = good_ring_plan,
        .packet_proof = packet_proof,
    };
    try std.testing.expectError(error.NativeTransportHardwareProofMissing, native_transport.attachIntelI225Proof(incomplete_proof));

    const complete_proof = IntelI225TransportProof{
        .evidence = .{
            .target_id = hardware_target.first_supported_target.id,
            .source = .real_hardware,
            .hardware_cold_boots = hardware_target.first_supported_target.proof_minimums.cold_boots,
            .hardware_warm_reboots = hardware_target.first_supported_target.proof_minimums.warm_reboots,
            .storage_write_read_cycles = hardware_target.first_supported_target.proof_minimums.storage_write_read_cycles,
            .network_frame_cycles = hardware_target.first_supported_target.proof_minimums.network_frame_cycles,
            .suspend_resume_cycles = hardware_target.first_supported_target.proof_minimums.suspend_resume_cycles,
            .crash_recovery_cycles = hardware_target.first_supported_target.proof_minimums.crash_recovery_cycles,
            .crash_record_persistence_cycles = hardware_target.first_supported_target.proof_minimums.crash_record_persistence_cycles,
            .update_rollback_cycles = hardware_target.first_supported_target.proof_minimums.update_rollback_cycles,
            .proof_manifest_captured = true,
            .serial_log_captured = true,
            .required_markers_captured = true,
            .firmware_settings_captured = true,
            .power_cycle_notes_captured = true,
            .artifact_digests_captured = true,
        },
        .ring_plan = good_ring_plan,
        .packet_proof = packet_proof,
    };
    try native_transport.attachIntelI225Proof(complete_proof);
    try std.testing.expect(native_transport.i225_proof_attached);
    try std.testing.expect(native_transport.intelI225NetworkReady());
    try std.testing.expectEqual(hardware_target.first_supported_target.proof_minimums.network_frame_cycles, native_transport.i225_proof_cycles);
    try std.testing.expectEqual(@as(u32, hardware_target.first_supported_target.proof_minimums.network_frame_cycles), native_transport.i225_tx_tail_register_writes);
    try std.testing.expectEqual(@as(u32, hardware_target.first_supported_target.proof_minimums.network_frame_cycles), native_transport.i225_rx_tail_register_writes);
    try std.testing.expectEqual(@as(u32, hardware_target.first_supported_target.proof_minimums.network_frame_cycles) * 2, native_transport.i225_interrupt_cause_reads);
    try std.testing.expectEqual(@as(u32, 2500), native_transport.i225_link_speed_mbps);

    const ProductionDriver = struct {
        var send_count: usize = 0;
        var authorized_native_frames: usize = 0;
        var allowed_capability_id: u64 = 0;
        var allowed_policy_id: u64 = 0;
        var last_destination: [6]u8 = [_]u8{0} ** 6;

        fn send(destination: [6]u8, _: []const u8) bool {
            send_count += 1;
            last_destination = destination;
            return true;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 8 };
        }

        fn driverEgressBroker(request: network_driver_task.EgressRequest) network_driver_task.EgressDecision {
            const native_sync_frame = std.mem.startsWith(u8, request.frame, &NativeTransportAbi.magic);
            const no_plaintext = std.mem.indexOf(u8, request.frame, "production after i225 proof") == null;
            const allowed = request.egress_capability_id == allowed_capability_id and
                request.network_policy_id == allowed_policy_id and
                native_sync_frame and
                no_plaintext;
            if (allowed) authorized_native_frames += 1;
            return .{
                .allowed = allowed,
                .capability_backed = request.egress_capability_id == allowed_capability_id,
            };
        }
    };
    network_driver_task.reset();
    defer network_driver_task.reset();
    ProductionDriver.send_count = 0;
    ProductionDriver.authorized_native_frames = 0;
    ProductionDriver.last_destination = [_]u8{0} ** 6;
    ProductionDriver.allowed_capability_id = relay_capability.id;
    ProductionDriver.allowed_policy_id = relay.id;
    const production_device = network_driver_task.NetworkDevice{
        .send = ProductionDriver.send,
        .receive = network_driver_task.noNetworkFrame,
        .getMacAddress = ProductionDriver.mac,
    };
    try std.testing.expect(network_driver_task.activateDevice(&production_device, 176));
    network_driver_task.setEgressBroker(ProductionDriver.driverEgressBroker);
    network_driver_task.bindEgressCapability(relay_capability.id, relay.id);

    var production_transport = NativeTransportService.init();
    try production_transport.bindPeerLink(target, .{ 0x02, 0x15, 0xF2, 0, 0, 9 });
    production_transport.requireIntelI225Proof();
    try std.testing.expect(!production_transport.intelI225NetworkReady());
    var production_connection = try production_transport.openRelay(&broker, .{
        .task_id = 176,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.revoked.sync" } },
        .now_ticks = 30,
    }, 176, 177, source, target, "relay.revoked.sync");
    try std.testing.expectError(error.NativeTransportHardwareProofMissing, production_transport.sendSigned(&production_connection, "blocked until i225 proof", frame_signer));
    try std.testing.expectEqual(@as(usize, 0), production_transport.endpoint_frame_count);
    try std.testing.expectEqual(@as(usize, 0), production_transport.network_frame_count);
    try std.testing.expectEqual(@as(usize, 0), production_transport.capture.captured_count);
    try std.testing.expectEqual(@as(usize, 0), production_connection.in_flight_frames);
    try std.testing.expectEqual(@as(usize, 0), network_driver_task.activeDriverTransmitCount());

    try production_transport.attachIntelI225Proof(complete_proof);
    try std.testing.expect(production_transport.intelI225NetworkReady());
    production_transport.requireProductionAttestedSessions();
    try std.testing.expectError(error.ProductionAttestationRequired, production_transport.sendSigned(&production_connection, "blocked lab session after i225 proof", frame_signer));
    try std.testing.expectError(error.ProductionAttestationRequired, production_transport.encryptObjectShare(&production_connection, 1, 2, 3, "blocked lab object share"));
    production_transport.disconnect(&production_connection);
    var production_relay_service = try BootedOverlayRelayService.init(179, 176, "relay.revoked.sync");
    try std.testing.expectError(error.ProductionAttestationRequired, production_transport.sendWithRelayFallback(&production_connection, &production_relay_service, "blocked lab relay fallback", frame_signer));
    try std.testing.expectEqual(@as(usize, 0), production_relay_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 0), production_transport.endpoint_frame_count);
    try std.testing.expectEqual(@as(usize, 0), production_transport.network_frame_count);
    try std.testing.expectEqual(@as(usize, 0), production_transport.capture.captured_count);
    try std.testing.expectEqual(@as(usize, 0), network_driver_task.activeDriverTransmitCount());

    const peer_attestation_signer = signing.SignerIdentity{
        .label = "production-sync-peer-root",
        .seed = signing.seedFromByte(0xD7),
    };
    const peer_attestation_identity = try signing.publicIdentity(peer_attestation_signer);
    const peer_attestation_key = attestation_service.AttestationRootKeyHandle{
        .key_id = "production-sync-peer-root",
        .label = "production-sync-peer-root",
        .public_identity = peer_attestation_identity,
        .generation = 1,
        .origin = .tpm,
        .provider_boundary = .platform_tpm,
        .custody = .tpm,
    };
    const peer_attestation_descriptor = attestation_service.RootProviderDescriptor{
        .name = "production-sync-tpm-attestation-root",
        .role = .production,
        .origin = .tpm,
        .key_id = "production-sync-peer-root",
        .key_generation = 1,
        .provider_boundary = .platform_tpm,
        .custody = .tpm,
        .customer_verifiable = true,
    };
    const PeerAttestationSigner = struct {
        signer: signing.SignerIdentity,

        fn sign(context: *anyopaque, handle: attestation_service.AttestationRootKeyHandle, digest: []const u8) !manifest.Signature {
            const fixture: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, fixture.signer.label, handle.label)) return error.RootIdentityMismatch;
            return signing.signWithDefaultRegistry(.ed25519, fixture.signer, digest);
        }
    };
    var peer_attestation_fixture = PeerAttestationSigner{ .signer = peer_attestation_signer };
    var peer_attestation_provider = try attestation_service.ExternalAttestationRootProvider.init(
        peer_attestation_descriptor,
        peer_attestation_key,
        &peer_attestation_fixture,
        PeerAttestationSigner.sign,
    );
    const peer_attestation_metadata_digest = peer_attestation_provider.verifierMetadataDigest();
    var peer_attestation = attestation_service.Service.init(target);
    try peer_attestation.provisionRootProvider(peer_attestation_provider.provider());
    const peer_boot = try verifiedSyncPeerBoot(32);
    const peer_attestation_request = try attestation_service.RemoteAttestationRequest.init(.{
        .remote_party = "overlay.production.sync",
        .nonce = "native-sync-verified-0001",
        .policy_label = "production-service-identity",
        .expected_key_origin = .tpm,
        .root_key_id = "production-sync-peer-root",
        .minimum_root_generation = 1,
        .attestation_verifier_metadata_digest_required = true,
        .attestation_verifier_metadata_digest = peer_attestation_metadata_digest,
    });
    const peer_attestation_response = try peer_attestation.respondToRemoteAttestationRequest(peer_boot, peer_attestation_request);
    const pinned_peer_root = peer_attestation_response.statement.root_digest;
    const service_identity_policy = try policies.create(.{
        .owner = owner,
        .label = "production-service-identity",
        .mode = .named_service_identity,
        .target = "overlay.production.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_peer_root,
        .pinned_attestation_verifier_metadata_digest = peer_attestation_metadata_digest,
    });
    const service_identity_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 180 },
        .target = .{ .kind = .network_policy, .id = service_identity_policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 176, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    ProductionDriver.allowed_capability_id = service_identity_capability.id;
    ProductionDriver.allowed_policy_id = service_identity_policy.id;
    network_driver_task.bindEgressCapability(service_identity_capability.id, service_identity_policy.id);

    try std.testing.expectError(error.ProductionAttestationRequired, production_transport.openVerifiedServiceIdentity(&broker, .{
        .task_id = 176,
        .principal_id = app,
        .capability_id = service_identity_capability.id,
        .policy_id = service_identity_policy.id,
        .service_identity = "overlay.other.sync",
        .attestation_response = peer_attestation_response,
        .attestation_request = peer_attestation_request,
        .attested_boot = &peer_boot,
        .trusted_root = peer_attestation_identity,
        .now_ticks = 31,
    }, 176, 177, source, target));

    var production_service_connection = try production_transport.openVerifiedServiceIdentity(&broker, .{
        .task_id = 176,
        .principal_id = app,
        .capability_id = service_identity_capability.id,
        .policy_id = service_identity_policy.id,
        .service_identity = "overlay.production.sync",
        .attestation_response = peer_attestation_response,
        .attestation_request = peer_attestation_request,
        .attested_boot = &peer_boot,
        .trusted_root = peer_attestation_identity,
        .now_ticks = 31,
    }, 176, 177, source, target);
    try std.testing.expect(production_service_connection.session.productionAttested());
    try std.testing.expect(production_service_connection.session.attestation_verifier_metadata_digest_present);
    try std.testing.expect(production_service_connection.session.attestation_verifier_metadata_digest_bound);
    try std.testing.expect(std.mem.eql(
        u8,
        &peer_attestation_metadata_digest,
        &production_service_connection.session.attestation_verifier_metadata_digest,
    ));
    const production_delivery = try production_transport.sendSigned(&production_service_connection, "production after i225 proof", frame_signer);
    try std.testing.expect(production_delivery.endpoint_delivered);
    try std.testing.expect(production_delivery.network_delivered);
    try std.testing.expectEqual(@as(usize, 1), production_transport.endpoint_frame_count);
    try std.testing.expectEqual(@as(usize, 1), production_transport.network_frame_count);
    try std.testing.expectEqual(@as(usize, 1), production_transport.capture.captured_count);
    try std.testing.expectEqual(@as(usize, 1), ProductionDriver.authorized_native_frames);
    try std.testing.expectEqual(@as(usize, 1), ProductionDriver.send_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x15, 0xF2, 0, 0, 9 }, &ProductionDriver.last_destination);
    try std.testing.expectEqual(@as(usize, 1), network_driver_task.activeDriverTransmitCount());
}

test "native sync transport falls back through booted relay and encrypts object shares" {
    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 100 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 101 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 102 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 103 };
    const relay = try policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.fallback.sync",
    });
    const relay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 104 },
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 105, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var native_transport = NativeTransportService.init();
    var connection = try native_transport.openRelay(&broker, .{
        .task_id = 105,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.fallback.sync" } },
        .now_ticks = 20,
    }, 105, 106, source, target, "relay.fallback.sync");
    const signer = signing.SignerIdentity{ .label = "native-sync-fallback", .seed = signing.seedFromByte(0x53) };

    const share = try native_transport.encryptObjectShare(&connection, 12, 34, 56, "enc:per-object-secret");
    try std.testing.expectEqual(@as(u64, 12), share.workspace_id);
    try std.testing.expectEqual(@as(u64, 34), share.object_id);
    try std.testing.expectEqual(@as(u64, 56), share.version_id);
    try std.testing.expect(share.encrypted);
    try std.testing.expect(!std.mem.eql(u8, share.payloadSlice(), "enc:per-object-secret"));

    var relay_service = try BootedOverlayRelayService.init(107, 105, "relay.fallback.sync");
    native_transport.disconnect(&connection);
    try std.testing.expectError(error.PacketEmpty, native_transport.sendWithRelayFallback(&connection, &relay_service, "", signer));
    try std.testing.expectEqual(@as(u64, 1), connection.next_sequence);
    try std.testing.expectEqual(@as(usize, 0), relay_service.accepted_packets);
    const fallback = try native_transport.sendWithRelayFallback(&connection, &relay_service, "offline delta", signer);
    try std.testing.expect(fallback.relay_fallback);
    try std.testing.expect(!fallback.endpoint_delivered);
    try std.testing.expect(!fallback.network_delivered);
    try std.testing.expectEqual(@as(u64, 1), fallback.sequence);
    try std.testing.expectEqual(@as(u64, 2), connection.next_sequence);
    try std.testing.expectEqual(@as(u64, 1), connection.highest_sent_sequence);
    try std.testing.expectEqual(@as(usize, 1), native_transport.relay_fallback_count);

    var plaintext_buffer: [MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay_service.deliverNext(105, &connection.session, plaintext_buffer[0..])).?;
    try std.testing.expectEqualStrings("offline delta", delivered);

    native_transport.reconnect(&connection);
    const after_fallback = try native_transport.sendSigned(&connection, "after fallback", signer);
    try std.testing.expectEqual(@as(u64, 2), after_fallback.sequence);

    native_transport.disconnect(&connection);
    connection.next_sequence = std.math.maxInt(u64);
    connection.highest_sent_sequence = std.math.maxInt(u64) - 1;
    connection.highest_delivered_sequence = std.math.maxInt(u64) - 1;
    const last_fallback = try native_transport.sendWithRelayFallback(&connection, &relay_service, "last fallback", signer);
    try std.testing.expect(last_fallback.relay_fallback);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), last_fallback.sequence);
    try std.testing.expectEqual(@as(u64, 0), connection.next_sequence);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), connection.highest_sent_sequence);

    const accepted_before_exhaustion = relay_service.accepted_packets;
    const fallbacks_before_exhaustion = native_transport.relay_fallback_count;
    try std.testing.expectError(
        error.NativeTransportSequenceExhausted,
        native_transport.sendWithRelayFallback(&connection, &relay_service, "exhausted fallback", signer),
    );
    try std.testing.expectEqual(@as(u64, 0), connection.next_sequence);
    try std.testing.expectEqual(accepted_before_exhaustion, relay_service.accepted_packets);
    try std.testing.expectEqual(fallbacks_before_exhaustion, native_transport.relay_fallback_count);
}
