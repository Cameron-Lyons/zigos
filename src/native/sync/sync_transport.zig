const std = @import("std");
const binary_cursor = @import("binary_cursor");
const capability = @import("../kernel_api/capability.zig");
const device_graph = @import("device_graph.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const hardware_target = @import("../platform/hardware_target.zig");
const ids = @import("../core/ids.zig");
const intel_i225 = @import("../../kernel/drivers/intel_i225.zig");
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
    PacketCaptureFull,
};

pub const MAX_CAPTURED_PACKETS: usize = 16;
pub const MAX_NATIVE_IN_FLIGHT_FRAMES: usize = 4;
pub const NATIVE_TRANSPORT_ABI_VERSION: u16 = 1;
const NativeFrameWriter = binary_cursor.Writer(Error, error.PacketTooLarge);
const NativeFrameReader = binary_cursor.Reader(Error, error.NativeTransportMalformedFrame);

pub const NativeTransportAbi = struct {
    pub const magic = [_]u8{ 'Z', 'G', 'S', 'T' };
    pub const version: u16 = NATIVE_TRANSPORT_ABI_VERSION;
    pub const flag_encrypted: u8 = 1 << 0;
    pub const flag_egress_allowed: u8 = 1 << 1;
    pub const fixed_header_bytes: usize = 4 + 2 + 2 + (2 * @sizeOf(u64)) + 4 + (4 * @sizeOf(u64)) + 2;
};

pub const NativeSyncFrameView = struct {
    abi_version: u16,
    header_len: u16,
    session_id: u64,
    sequence: u64,
    transport: sync_state.TransportMode,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    flags: u8,
    policy_id: u64,
    capability_id: u64,
    ciphertext: []const u8,
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
    kernel_data_plane_disabled: bool = intel_i225.network_data_plane_exports_fail_closed,
    i225_driver_present: bool = true,

    pub fn satisfied(self: IntelI225TransportProof) bool {
        if (!self.kernel_data_plane_disabled or !self.i225_driver_present) return false;
        intel_i225.validateRingPlan(self.ring_plan) catch return false;
        return hardware_target.hardwareProofSatisfied(&hardware_target.first_supported_target, self.evidence);
    }
};

pub const CapturedPacket = struct {
    in_use: bool = false,
    len: usize = 0,
    bytes: [network_driver_task.MAX_NATIVE_FRAME_BYTES]u8 = [_]u8{0} ** network_driver_task.MAX_NATIVE_FRAME_BYTES,

    pub fn slice(self: *const CapturedPacket) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const PacketCapture = struct {
    packets: [MAX_CAPTURED_PACKETS]CapturedPacket = [_]CapturedPacket{.{}} ** MAX_CAPTURED_PACKETS,
    captured_count: usize = 0,
    dropped_count: usize = 0,

    pub fn record(self: *PacketCapture, frame: []const u8) Error!void {
        if (frame.len > network_driver_task.MAX_NATIVE_FRAME_BYTES) return error.PacketTooLarge;
        for (&self.packets) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.len = frame.len;
            @memcpy(slot.bytes[0..frame.len], frame);
            self.captured_count += 1;
            return;
        }
        self.dropped_count += 1;
        return error.PacketCaptureFull;
    }

    pub fn last(self: *const PacketCapture) ?CapturedPacket {
        const packet = self.lastPtr() orelse return null;
        return packet.*;
    }

    pub fn lastPtr(self: *const PacketCapture) ?*const CapturedPacket {
        var index = self.packets.len;
        while (index > 0) {
            index -= 1;
            if (self.packets[index].in_use) return &self.packets[index];
        }
        return null;
    }
};

pub const NativeConnection = struct {
    session: TransportSession,
    source_endpoint_id: ids.EndpointId,
    target_endpoint_id: ids.EndpointId,
    source_task_id: u64,
    target_task_id: u64,
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
    opened_connections: usize = 0,
    disconnected_connections: usize = 0,
    reconnect_count: usize = 0,
    endpoint_frame_count: usize = 0,
    network_frame_count: usize = 0,
    relay_fallback_count: usize = 0,
    congestion_drop_count: usize = 0,
    replay_rejection_count: usize = 0,
    revoked_device_rejection_count: usize = 0,
    i225_proof_attached: bool = false,
    trust_graph: ?*const device_graph.Graph = null,

    pub fn init() NativeTransportService {
        return .{};
    }

    pub fn bindTrustedDeviceGraph(self: *NativeTransportService, graph: *const device_graph.Graph) void {
        self.trust_graph = graph;
    }

    pub fn attachIntelI225Proof(self: *NativeTransportService, proof: IntelI225TransportProof) Error!void {
        if (!proof.satisfied()) return error.NativeTransportHardwareProofMissing;
        self.i225_proof_attached = true;
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
        connection.in_flight_frames = saturatingSubUsize(
            connection.in_flight_frames,
            delivered_frames,
        );
    }

    pub fn sendSigned(
        self: *NativeTransportService,
        connection: *NativeConnection,
        plaintext: []const u8,
        signer: signing.SignerIdentity,
    ) Error!NativeDelivery {
        if (!connection.connected) return error.NativeTransportDisconnected;
        try self.ensureTrustedTransportDevices(connection.session.source_device, connection.session.target_device);
        if (connection.in_flight_frames >= MAX_NATIVE_IN_FLIGHT_FRAMES) {
            self.congestion_drop_count += 1;
            return error.NativeTransportCongested;
        }
        const sequence = connection.next_sequence;
        if (sequence <= connection.highest_sent_sequence or sequence + sync_state.TRANSPORT_REPLAY_WINDOW <= connection.highest_delivered_sequence) {
            self.replay_rejection_count += 1;
            return error.NativeTransportReplayRejected;
        }
        const signed_frame = try self.harness.encryptSignedFrame(&connection.session, plaintext, signer);
        try self.endpoints.send(
            connection.source_endpoint_id,
            ids.task(connection.source_task_id),
            signed_frame.packet.session_id,
            plaintext,
            null,
            false,
        );
        self.endpoint_frame_count += 1;
        connection.in_flight_frames += 1;
        connection.next_sequence += 1;
        connection.highest_sent_sequence = sequence;

        var network_delivered = false;
        var wire_frame: [network_driver_task.MAX_NATIVE_FRAME_BYTES]u8 = undefined;
        const encoded = try encodeNativeSyncFrame(wire_frame[0..], &connection.session, sequence, &signed_frame);
        try self.capture.record(encoded);
        network_delivered = network_driver_task.sendActiveFrame(encoded);
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
                const sequence = connection.next_sequence;
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
};

fn markSequenceSent(connection: *NativeConnection, sequence: u64) void {
    if (sequence > connection.highest_sent_sequence) connection.highest_sent_sequence = sequence;
    if (connection.next_sequence == sequence) {
        connection.next_sequence +%= 1;
        if (connection.next_sequence == 0) connection.next_sequence = 1;
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
    if (frame.len < NativeTransportAbi.fixed_header_bytes + 32) return error.NativeTransportMalformedFrame;

    var reader = NativeFrameReader{ .buffer = frame };
    if (!std.mem.eql(u8, try reader.readSlice(NativeTransportAbi.magic.len), &NativeTransportAbi.magic)) return error.NativeTransportMalformedFrame;

    const abi_version = try reader.readU16();
    if (abi_version != NativeTransportAbi.version) return error.NativeTransportMalformedFrame;
    const header_len = try reader.readU16();
    if (header_len != NativeTransportAbi.fixed_header_bytes) return error.NativeTransportMalformedFrame;

    const session_id = try reader.readU64();
    const sequence = try reader.readU64();
    const transport = try parseTransportMode(try reader.readByte());
    const source_kind = try parsePrincipalKind(try reader.readByte());
    const target_kind = try parsePrincipalKind(try reader.readByte());
    const flags = try reader.readByte();
    const known_flags: u8 = NativeTransportAbi.flag_encrypted | NativeTransportAbi.flag_egress_allowed;
    if ((flags & ~known_flags) != 0) return error.NativeTransportMalformedFrame;
    const policy_id = try reader.readU64();
    const capability_id = try reader.readU64();
    const source_serial = try reader.readU64();
    const target_serial = try reader.readU64();
    const ciphertext_len = try reader.readU16();
    if (reader.remaining() != ciphertext_len + 32) return error.NativeTransportMalformedFrame;
    const ciphertext = try reader.readSlice(ciphertext_len);
    const packet_digest = try reader.readSlice(32);

    return .{
        .abi_version = abi_version,
        .header_len = header_len,
        .session_id = session_id,
        .sequence = sequence,
        .transport = transport,
        .source_device = .{ .kind = source_kind, .serial = source_serial },
        .target_device = .{ .kind = target_kind, .serial = target_serial },
        .flags = flags,
        .policy_id = policy_id,
        .capability_id = capability_id,
        .ciphertext = ciphertext,
        .packet_digest = packet_digest,
    };
}

pub fn encodeNativeSyncFrame(
    buffer: []u8,
    session: *const TransportSession,
    sequence: u64,
    frame: *const SignedEncryptedFrame,
) Error![]const u8 {
    const ciphertext = frame.packet.ciphertextSlice();
    if (ciphertext.len > std.math.maxInt(u16)) return error.PacketTooLarge;
    const required_len = NativeTransportAbi.fixed_header_bytes + ciphertext.len + frame.packet_digest.len;
    if (buffer.len < required_len) return error.PacketTooLarge;

    var writer = NativeFrameWriter{ .buffer = buffer };
    try writer.writeBytes(&NativeTransportAbi.magic);
    try writer.writeU16(NativeTransportAbi.version);
    try writer.writeU16(@intCast(NativeTransportAbi.fixed_header_bytes));
    try writer.writeU64(session.id);
    try writer.writeU64(sequence);
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
    try writer.writeBytes(&frame.packet_digest);
    return buffer[0..writer.offset];
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

fn saturatingSubUsize(value: usize, amount: usize) usize {
    if (amount >= value) return 0;
    return value - amount;
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
    const delivered = try native_transport.sendSigned(&connection, "sync after reconnect", signer);
    try std.testing.expect(delivered.endpoint_delivered);
    try std.testing.expect(verifySignedFrame(&delivered.signed_frame));
    const received = try native_transport.receive(&connection);
    try std.testing.expectEqualStrings("sync after reconnect", received.payload());
    try std.testing.expectEqual(@as(usize, 1), native_transport.opened_connections);
    try std.testing.expectEqual(@as(usize, 1), native_transport.disconnected_connections);
    try std.testing.expectEqual(@as(usize, 1), native_transport.reconnect_count);
    try std.testing.expectEqual(@as(usize, 1), native_transport.endpoint_frame_count);
}

test "native sync transport captures encrypted driver packets and handles replay and congestion" {
    const Driver = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;
        var last_frame: [network_driver_task.MAX_NATIVE_FRAME_BYTES]u8 = [_]u8{0} ** network_driver_task.MAX_NATIVE_FRAME_BYTES;

        fn send(frame: []const u8) void {
            send_count += 1;
            last_frame_len = frame.len;
            @memcpy(last_frame[0..frame.len], frame);
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 0x51 };
        }

        fn broker(request: network_driver_task.EgressRequest) network_driver_task.EgressDecision {
            return .{
                .allowed = request.network_policy_id == 91,
                .capability_backed = request.egress_capability_id == 92,
            };
        }
    };

    Driver.send_count = 0;
    Driver.last_frame_len = 0;
    network_driver_task.reset();
    defer network_driver_task.reset();
    const device = network_driver_task.NetworkDevice{
        .send = Driver.send,
        .getMacAddress = Driver.mac,
    };
    try std.testing.expect(network_driver_task.activateDevice(&device, 90));
    network_driver_task.setEgressBroker(Driver.broker);
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
    try std.testing.expectEqual(@as(usize, 1), native_transport.capture.captured_count);
    const captured = native_transport.capture.last().?;
    try std.testing.expect(std.mem.startsWith(u8, captured.slice(), "ZGST"));
    try std.testing.expect(std.mem.indexOf(u8, captured.slice(), "object delta") == null);
    try std.testing.expectEqualSlices(u8, captured.slice(), Driver.last_frame[0..Driver.last_frame_len]);
    const view = try native_transport.assertLastCapturedFrame(.{
        .session_id = connection.session.id,
        .sequence = delivered.sequence,
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
    try std.testing.expectEqualSlices(u8, delivered.signed_frame.packet_digest[0..], view.packet_digest);
    var tampered_flags = captured;
    const flags_offset = 4 + 2 + 2 + @sizeOf(u64) + @sizeOf(u64) + 3;
    tampered_flags.bytes[flags_offset] |= 0x80;
    try std.testing.expectError(error.NativeTransportMalformedFrame, decodeNativeSyncFrame(tampered_flags.slice()));

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
    connection.next_sequence = 3;
    try std.testing.expectError(error.NativeTransportReplayRejected, native_transport.sendSigned(&connection, "replay", signer));
    try std.testing.expectEqual(@as(usize, 1), native_transport.replay_rejection_count);
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
    try std.testing.expectError(error.NativeTransportDeviceRevoked, native_transport.sendSigned(&connection, "blocked after revoke", frame_signer));
    try std.testing.expectError(error.NativeTransportDeviceRevoked, native_transport.openRelay(&broker, .{
        .task_id = 176,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.revoked.sync" } },
        .now_ticks = 21,
    }, 176, 177, source, target, "relay.revoked.sync"));
    try std.testing.expectEqual(@as(usize, 2), native_transport.revoked_device_rejection_count);

    const good_ring_plan = intel_i225.RingPlan{
        .rx_descriptors = 256,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    };
    const incomplete_proof = IntelI225TransportProof{
        .evidence = .{
            .target_id = hardware_target.first_supported_target.id,
            .source = .qemu,
        },
        .ring_plan = good_ring_plan,
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
    };
    try native_transport.attachIntelI225Proof(complete_proof);
    try std.testing.expect(native_transport.i225_proof_attached);
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
}
