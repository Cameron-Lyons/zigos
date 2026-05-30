const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const ids = @import("../core/ids.zig");
const network_driver_task = @import("../drivers/network_driver_task.zig");
const network_policy = @import("network_policy.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

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
    NativeTransportDisconnected,
    NativeTransportFrameMissing,
};

pub const NativeConnection = struct {
    session: TransportSession,
    source_endpoint_id: ids.EndpointId,
    target_endpoint_id: ids.EndpointId,
    source_task_id: u64,
    target_task_id: u64,
    connected: bool = true,

    pub fn isConnected(self: *const NativeConnection) bool {
        return self.connected;
    }
};

pub const NativeDelivery = struct {
    signed_frame: SignedEncryptedFrame,
    endpoint_delivered: bool,
    network_delivered: bool,
    payload_len: usize,
};

pub const NativeTransportService = struct {
    harness: Harness = Harness.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    opened_connections: usize = 0,
    disconnected_connections: usize = 0,
    reconnect_count: usize = 0,
    endpoint_frame_count: usize = 0,
    network_frame_count: usize = 0,

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

    pub fn sendSigned(
        self: *NativeTransportService,
        connection: *const NativeConnection,
        plaintext: []const u8,
        signer: signing.SignerIdentity,
    ) Error!NativeDelivery {
        if (!connection.connected) return error.NativeTransportDisconnected;
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

        var network_delivered = false;
        if (plaintext.len <= network_driver_task.MAX_NATIVE_FRAME_BYTES) {
            network_delivered = network_driver_task.sendActiveFrame(plaintext);
            if (network_delivered) self.network_frame_count += 1;
        }

        return .{
            .signed_frame = signed_frame,
            .endpoint_delivered = true,
            .network_delivered = network_delivered,
            .payload_len = plaintext.len,
        };
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
