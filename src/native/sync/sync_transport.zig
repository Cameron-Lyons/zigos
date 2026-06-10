const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const ids = @import("../core/ids.zig");
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
    NativeTransportFrameMissing,
    NativeTransportReplayRejected,
    PacketCaptureFull,
};

pub const MAX_CAPTURED_PACKETS: usize = 16;
pub const MAX_NATIVE_IN_FLIGHT_FRAMES: usize = 4;

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
        var index = self.packets.len;
        while (index > 0) {
            index -= 1;
            if (self.packets[index].in_use) return self.packets[index];
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

    pub fn init() NativeTransportService {
        return .{};
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
        if (sequence > connection.highest_delivered_sequence) connection.highest_delivered_sequence = sequence;
        if (connection.in_flight_frames != 0) connection.in_flight_frames -= 1;
    }

    pub fn sendSigned(
        self: *NativeTransportService,
        connection: *NativeConnection,
        plaintext: []const u8,
        signer: signing.SignerIdentity,
    ) Error!NativeDelivery {
        if (!connection.connected) return error.NativeTransportDisconnected;
        if (connection.in_flight_frames >= MAX_NATIVE_IN_FLIGHT_FRAMES) {
            self.congestion_drop_count += 1;
            return error.NativeTransportCongested;
        }
        const sequence = connection.next_sequence;
        if (sequence <= connection.highest_delivered_sequence or sequence + sync_state.TRANSPORT_REPLAY_WINDOW <= connection.highest_delivered_sequence) {
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

    pub fn sendWithRelayFallback(
        self: *NativeTransportService,
        connection: *NativeConnection,
        relay_service: *BootedOverlayRelayService,
        plaintext: []const u8,
        signer: signing.SignerIdentity,
    ) Error!NativeDelivery {
        const delivery = self.sendSigned(connection, plaintext, signer) catch |err| switch (err) {
            error.NativeTransportDisconnected, error.NativeTransportCongested => {
                const signed_frame = try self.harness.encryptSignedFrame(&connection.session, plaintext, signer);
                try relay_service.submitSignedFrame(connection.session.task_id, &connection.session, signed_frame);
                self.relay_fallback_count += 1;
                return .{
                    .signed_frame = signed_frame,
                    .endpoint_delivered = false,
                    .network_delivered = false,
                    .relay_fallback = true,
                    .congested = err == error.NativeTransportCongested,
                    .sequence = connection.next_sequence,
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
};

fn encodeNativeSyncFrame(
    buffer: []u8,
    session: *const TransportSession,
    sequence: u64,
    frame: *const SignedEncryptedFrame,
) Error![]const u8 {
    const ciphertext = frame.packet.ciphertextSlice();
    if (ciphertext.len > std.math.maxInt(u16)) return error.PacketTooLarge;
    const required_len = 4 + (6 * @sizeOf(u64)) + 2 + ciphertext.len + frame.packet_digest.len;
    if (buffer.len < required_len) return error.PacketTooLarge;

    var index: usize = 0;
    @memcpy(buffer[index..][0..4], "ZGST");
    index += 4;
    writeU64(buffer, &index, session.id);
    writeU64(buffer, &index, sequence);
    writeU64(buffer, &index, frame.packet.policy_id);
    writeU64(buffer, &index, frame.packet.capability_id);
    writeU64(buffer, &index, frame.packet.source_device.serial);
    writeU64(buffer, &index, frame.packet.target_device.serial);
    std.mem.writeInt(u16, buffer[index..][0..2], @intCast(ciphertext.len), .little);
    index += 2;
    @memcpy(buffer[index..][0..ciphertext.len], ciphertext);
    index += ciphertext.len;
    @memcpy(buffer[index..][0..frame.packet_digest.len], &frame.packet_digest);
    index += frame.packet_digest.len;
    return buffer[0..index];
}

fn writeU64(buffer: []u8, index: *usize, value: u64) void {
    std.mem.writeInt(u64, buffer[index.*..][0..@sizeOf(u64)], value, .little);
    index.* += @sizeOf(u64);
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

    const signer = signing.SignerIdentity{ .label = "native-sync-transport", .seed = [_]u8{0x45} ** 32 };
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
    const signer = signing.SignerIdentity{ .label = "native-sync-capture", .seed = [_]u8{0x52} ** 32 };

    const delivered = try native_transport.sendSigned(&connection, "object delta", signer);
    try std.testing.expect(delivered.network_delivered);
    try std.testing.expectEqual(@as(u64, 1), delivered.sequence);
    try std.testing.expectEqual(@as(usize, 1), Driver.send_count);
    try std.testing.expectEqual(@as(usize, 1), native_transport.capture.captured_count);
    const captured = native_transport.capture.last().?;
    try std.testing.expect(std.mem.startsWith(u8, captured.slice(), "ZGST"));
    try std.testing.expect(std.mem.indexOf(u8, captured.slice(), "object delta") == null);
    try std.testing.expectEqualSlices(u8, captured.slice(), Driver.last_frame[0..Driver.last_frame_len]);

    _ = try native_transport.sendSigned(&connection, "two", signer);
    _ = try native_transport.sendSigned(&connection, "three", signer);
    _ = try native_transport.sendSigned(&connection, "four", signer);
    try std.testing.expectError(error.NativeTransportCongested, native_transport.sendSigned(&connection, "five", signer));
    try std.testing.expectEqual(@as(usize, 1), native_transport.congestion_drop_count);

    native_transport.acknowledge(&connection, 4);
    connection.next_sequence = 3;
    try std.testing.expectError(error.NativeTransportReplayRejected, native_transport.sendSigned(&connection, "replay", signer));
    try std.testing.expectEqual(@as(usize, 1), native_transport.replay_rejection_count);
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
    const signer = signing.SignerIdentity{ .label = "native-sync-fallback", .seed = [_]u8{0x53} ** 32 };

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
    try std.testing.expectEqual(@as(usize, 1), native_transport.relay_fallback_count);

    var plaintext_buffer: [MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay_service.deliverNext(105, &connection.session, plaintext_buffer[0..])).?;
    try std.testing.expectEqualStrings("offline delta", delivered);
}
