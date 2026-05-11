const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const network_policy = @import("../sync/network_policy.zig");

pub const NetworkDevice = struct {
    send: *const fn (data: []const u8) void,
    getMacAddress: *const fn () [6]u8,
};

pub const EgressRequest = struct {
    frame: []const u8,
    source_mac: [6]u8,
    egress_capability_id: u64,
    network_policy_id: u64,
};

pub const EgressDecision = struct {
    allowed: bool,
    capability_backed: bool,
};

pub const EgressBroker = *const fn (request: EgressRequest) EgressDecision;
pub const MAX_NATIVE_PAYLOAD_BYTES: usize = 160;
pub const MAX_NATIVE_FRAME_BYTES: usize = 256;

pub const Error = error{
    EgressDenied,
    PayloadTooLarge,
    ServiceIdentityTooLong,
    DiscoveryClassTooLong,
};

pub const NativeServiceIdentityConnection = struct {
    id: u64,
    policy_id: u64,
    capability_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    source_mac: [6]u8,
    service_identity_len: usize = 0,
    service_identity: [network_policy.MAX_TARGET_BYTES]u8 = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
    peer_root_digest: [32]u8,
    key: [32]u8,
    attested: bool,
    attestation_required: bool,
    identity_pinned: bool,
    egress_decision: network_policy.EgressDecision,

    pub fn serviceIdentitySlice(self: *const NativeServiceIdentityConnection) []const u8 {
        return self.service_identity[0..self.service_identity_len];
    }
};

pub const NativeServiceIdentityFrame = struct {
    connection_id: u64,
    policy_id: u64,
    capability_id: u64,
    payload_len: usize,
    ciphertext: [MAX_NATIVE_PAYLOAD_BYTES]u8,
    payload_digest: [32]u8,
    peer_root_digest: [32]u8,
    encrypted: bool,
    egress_allowed: bool,
    attested: bool,
    identity_pinned: bool,

    pub fn ciphertextSlice(self: *const NativeServiceIdentityFrame) []const u8 {
        return self.ciphertext[0..self.payload_len];
    }
};

pub const NativeLocalDiscoveryConnection = struct {
    id: u64,
    policy_id: u64,
    capability_id: u64,
    source_device: principal.PrincipalId,
    source_mac: [6]u8,
    discovery_class_len: usize = 0,
    discovery_class: [network_policy.MAX_TARGET_BYTES]u8 = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
    key: [32]u8,
    scoped_discovery: bool,
    egress_decision: network_policy.EgressDecision,

    pub fn discoveryClassSlice(self: *const NativeLocalDiscoveryConnection) []const u8 {
        return self.discovery_class[0..self.discovery_class_len];
    }
};

pub const NativeLocalDiscoveryFrame = struct {
    connection_id: u64,
    policy_id: u64,
    capability_id: u64,
    probe_len: usize,
    ciphertext: [MAX_NATIVE_PAYLOAD_BYTES]u8,
    probe_digest: [32]u8,
    discovery_class_len: usize = 0,
    discovery_class: [network_policy.MAX_TARGET_BYTES]u8 = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
    encrypted: bool,
    egress_allowed: bool,
    scoped_discovery: bool,

    pub fn ciphertextSlice(self: *const NativeLocalDiscoveryFrame) []const u8 {
        return self.ciphertext[0..self.probe_len];
    }

    pub fn discoveryClassSlice(self: *const NativeLocalDiscoveryFrame) []const u8 {
        return self.discovery_class[0..self.discovery_class_len];
    }
};

pub const NativeNetworkStack = struct {
    next_connection_id: u64 = 1,
    attempted_connections: usize = 0,
    denied_before_transmit: usize = 0,
    opened_connections: usize = 0,
    transmitted_packets: usize = 0,
    last_denial_reason: network_policy.EgressDecisionReason = .none,

    pub fn init() NativeNetworkStack {
        return .{};
    }

    pub fn openServiceIdentity(
        self: *NativeNetworkStack,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!NativeServiceIdentityConnection {
        self.attempted_connections += 1;
        const device = active_device orelse return self.denyOpen(.policy_denied);
        const service_identity = switch (request.evidence.destination) {
            .service_identity => |identity| identity,
            else => return self.denyOpen(.destination_mismatch),
        };

        const decision = broker.connect(request) catch return self.denyOpen(.policy_denied);
        if (!decision.allowed) return self.denyOpen(decision.reason);

        var connection = NativeServiceIdentityConnection{
            .id = self.nextConnectionId(),
            .policy_id = request.policy_id,
            .capability_id = request.capability_id,
            .source_device = source_device,
            .target_device = target_device,
            .source_mac = device.getMacAddress(),
            .peer_root_digest = request.evidence.peer_root_digest,
            .key = undefined,
            .attested = request.evidence.attested,
            .attestation_required = decision.policy_decision.attestation_required,
            .identity_pinned = decision.policy_decision.identity_pinned,
            .egress_decision = decision,
        };
        connection.service_identity_len = native_util.copyTextExact(&connection.service_identity, service_identity) catch return error.ServiceIdentityTooLong;
        connection.key = nativeConnectionKey(&connection);
        self.opened_connections += 1;
        return connection;
    }

    pub fn openLocalDiscovery(
        self: *NativeNetworkStack,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_device: principal.PrincipalId,
    ) Error!NativeLocalDiscoveryConnection {
        self.attempted_connections += 1;
        const device = active_device orelse return self.denyOpen(.policy_denied);
        const discovery_class = switch (request.evidence.destination) {
            .discovery_class => |class| class,
            else => return self.denyOpen(.destination_mismatch),
        };

        const decision = broker.connect(request) catch return self.denyOpen(.policy_denied);
        if (!decision.allowed) return self.denyOpen(decision.reason);
        if (decision.policy_decision.matched_mode != .local_subnet_discovery) {
            return self.denyOpen(.destination_mismatch);
        }

        var connection = NativeLocalDiscoveryConnection{
            .id = self.nextConnectionId(),
            .policy_id = request.policy_id,
            .capability_id = request.capability_id,
            .source_device = source_device,
            .source_mac = device.getMacAddress(),
            .key = undefined,
            .scoped_discovery = true,
            .egress_decision = decision,
        };
        connection.discovery_class_len = native_util.copyTextExact(&connection.discovery_class, discovery_class) catch return error.DiscoveryClassTooLong;
        connection.key = nativeDiscoveryKey(&connection);
        self.opened_connections += 1;
        return connection;
    }

    pub fn sendServiceIdentityFrame(
        self: *NativeNetworkStack,
        connection: *const NativeServiceIdentityConnection,
        payload: []const u8,
    ) Error!NativeServiceIdentityFrame {
        if (payload.len > MAX_NATIVE_PAYLOAD_BYTES) return error.PayloadTooLarge;
        if (!connection.egress_decision.allowed) return error.EgressDenied;
        const device = active_device orelse return error.EgressDenied;

        var frame = NativeServiceIdentityFrame{
            .connection_id = connection.id,
            .policy_id = connection.policy_id,
            .capability_id = connection.capability_id,
            .payload_len = payload.len,
            .ciphertext = [_]u8{0} ** MAX_NATIVE_PAYLOAD_BYTES,
            .payload_digest = nativePayloadDigest(connection, payload),
            .peer_root_digest = connection.peer_root_digest,
            .encrypted = true,
            .egress_allowed = true,
            .attested = connection.attested,
            .identity_pinned = connection.identity_pinned,
        };
        for (payload, 0..) |byte, index| {
            frame.ciphertext[index] = byte ^ connection.key[index % connection.key.len];
        }

        var wire_frame: [MAX_NATIVE_FRAME_BYTES]u8 = undefined;
        const encoded = try encodeNativeFrame(wire_frame[0..], connection, &frame);
        device.send(encoded);
        self.transmitted_packets += 1;
        return frame;
    }

    pub fn sendLocalDiscoveryProbe(
        self: *NativeNetworkStack,
        connection: *const NativeLocalDiscoveryConnection,
        payload: []const u8,
    ) Error!NativeLocalDiscoveryFrame {
        if (payload.len > MAX_NATIVE_PAYLOAD_BYTES) return error.PayloadTooLarge;
        if (!connection.egress_decision.allowed or !connection.scoped_discovery) return error.EgressDenied;
        const device = active_device orelse return error.EgressDenied;

        var frame = NativeLocalDiscoveryFrame{
            .connection_id = connection.id,
            .policy_id = connection.policy_id,
            .capability_id = connection.capability_id,
            .probe_len = payload.len,
            .ciphertext = [_]u8{0} ** MAX_NATIVE_PAYLOAD_BYTES,
            .probe_digest = nativeDiscoveryDigest(connection, payload),
            .encrypted = true,
            .egress_allowed = true,
            .scoped_discovery = true,
        };
        frame.discovery_class_len = native_util.copyTextExact(&frame.discovery_class, connection.discoveryClassSlice()) catch return error.DiscoveryClassTooLong;
        for (payload, 0..) |byte, index| {
            frame.ciphertext[index] = byte ^ connection.key[index % connection.key.len];
        }

        var wire_frame: [MAX_NATIVE_FRAME_BYTES]u8 = undefined;
        const encoded = try encodeDiscoveryFrame(wire_frame[0..], connection, &frame);
        device.send(encoded);
        self.transmitted_packets += 1;
        return frame;
    }

    fn denyOpen(self: *NativeNetworkStack, reason: network_policy.EgressDecisionReason) Error {
        self.denied_before_transmit += 1;
        self.last_denial_reason = reason;
        return error.EgressDenied;
    }

    fn nextConnectionId(self: *NativeNetworkStack) u64 {
        defer self.next_connection_id += 1;
        return self.next_connection_id;
    }
};

var active_device: ?*const NetworkDevice = null;
var active_service_id: u64 = 0;
var egress_broker: ?EgressBroker = null;
var active_egress_capability_id: u64 = 0;
var active_network_policy_id: u64 = 0;

pub fn reset() void {
    active_device = null;
    active_service_id = 0;
    egress_broker = null;
    active_egress_capability_id = 0;
    active_network_policy_id = 0;
}

pub fn activateDevice(device: *const NetworkDevice, service_id: u64) bool {
    if (service_id == 0) return false;
    active_device = device;
    active_service_id = service_id;
    return true;
}

pub fn deactivateDevice(service_id: u64) bool {
    if (active_service_id != service_id) return false;
    active_device = null;
    active_service_id = 0;
    clearEgressCapability();
    return true;
}

pub fn hasActiveDevice() bool {
    return active_device != null;
}

pub fn setEgressBroker(broker: ?EgressBroker) void {
    egress_broker = broker;
}

pub fn bindEgressCapability(capability_id: u64, policy_id: u64) void {
    active_egress_capability_id = capability_id;
    active_network_policy_id = policy_id;
}

pub fn clearEgressCapability() void {
    active_egress_capability_id = 0;
    active_network_policy_id = 0;
}

pub fn authorizeDriverTx(frame: []const u8) bool {
    const device = active_device orelse return false;
    const broker = egress_broker orelse return false;
    const decision = broker(.{
        .frame = frame,
        .source_mac = device.getMacAddress(),
        .egress_capability_id = active_egress_capability_id,
        .network_policy_id = active_network_policy_id,
    });
    return decision.allowed and decision.capability_backed;
}

pub fn sendActiveFrame(frame: []const u8) bool {
    if (!authorizeDriverTx(frame)) return false;
    const device = active_device orelse return false;
    device.send(frame);
    return true;
}

fn nativeConnectionKey(connection: *const NativeServiceIdentityConnection) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "connection", connection.id);
    crypto_hash.updateInt(&hasher, "policy", connection.policy_id);
    crypto_hash.updateInt(&hasher, "capability", connection.capability_id);
    updatePrincipal(&hasher, "source", connection.source_device);
    updatePrincipal(&hasher, "target", connection.target_device);
    crypto_hash.updateBytes(&hasher, "source-mac", &connection.source_mac);
    crypto_hash.updateBytes(&hasher, "service-identity", connection.serviceIdentitySlice());
    crypto_hash.updateBytes(&hasher, "peer-root", &connection.peer_root_digest);
    return crypto_hash.finalize(&hasher);
}

fn nativePayloadDigest(connection: *const NativeServiceIdentityConnection, payload: []const u8) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "key", &connection.key);
    crypto_hash.updateBytes(&hasher, "payload", payload);
    return crypto_hash.finalize(&hasher);
}

fn nativeDiscoveryKey(connection: *const NativeLocalDiscoveryConnection) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "connection", connection.id);
    crypto_hash.updateInt(&hasher, "policy", connection.policy_id);
    crypto_hash.updateInt(&hasher, "capability", connection.capability_id);
    updatePrincipal(&hasher, "source", connection.source_device);
    crypto_hash.updateBytes(&hasher, "source-mac", &connection.source_mac);
    crypto_hash.updateBytes(&hasher, "discovery-class", connection.discoveryClassSlice());
    return crypto_hash.finalize(&hasher);
}

fn nativeDiscoveryDigest(connection: *const NativeLocalDiscoveryConnection, payload: []const u8) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "key", &connection.key);
    crypto_hash.updateBytes(&hasher, "discovery-class", connection.discoveryClassSlice());
    crypto_hash.updateBytes(&hasher, "payload", payload);
    return crypto_hash.finalize(&hasher);
}

fn encodeNativeFrame(
    buffer: []u8,
    connection: *const NativeServiceIdentityConnection,
    frame: *const NativeServiceIdentityFrame,
) Error![]const u8 {
    const identity = connection.serviceIdentitySlice();
    if (identity.len > std.math.maxInt(u8) or frame.payload_len > std.math.maxInt(u8)) return error.PayloadTooLarge;
    const required_len = 4 + (3 * @sizeOf(u64)) + connection.source_mac.len + 1 + identity.len + 1 + frame.payload_len + frame.payload_digest.len;
    if (buffer.len < required_len) return error.PayloadTooLarge;

    var index: usize = 0;
    @memcpy(buffer[index..][0..4], "ZGNI");
    index += 4;
    writeU64(buffer, &index, frame.connection_id);
    writeU64(buffer, &index, frame.policy_id);
    writeU64(buffer, &index, frame.capability_id);
    @memcpy(buffer[index..][0..connection.source_mac.len], &connection.source_mac);
    index += connection.source_mac.len;
    buffer[index] = @intCast(identity.len);
    index += 1;
    @memcpy(buffer[index..][0..identity.len], identity);
    index += identity.len;
    buffer[index] = @intCast(frame.payload_len);
    index += 1;
    @memcpy(buffer[index..][0..frame.payload_len], frame.ciphertextSlice());
    index += frame.payload_len;
    @memcpy(buffer[index..][0..frame.payload_digest.len], &frame.payload_digest);
    index += frame.payload_digest.len;
    return buffer[0..index];
}

fn encodeDiscoveryFrame(
    buffer: []u8,
    connection: *const NativeLocalDiscoveryConnection,
    frame: *const NativeLocalDiscoveryFrame,
) Error![]const u8 {
    const discovery_class = connection.discoveryClassSlice();
    if (discovery_class.len > std.math.maxInt(u8) or frame.probe_len > std.math.maxInt(u8)) return error.PayloadTooLarge;
    const required_len = 4 + (3 * @sizeOf(u64)) + connection.source_mac.len + 1 + discovery_class.len + 1 + frame.probe_len + frame.probe_digest.len;
    if (buffer.len < required_len) return error.PayloadTooLarge;

    var index: usize = 0;
    @memcpy(buffer[index..][0..4], "ZGND");
    index += 4;
    writeU64(buffer, &index, frame.connection_id);
    writeU64(buffer, &index, frame.policy_id);
    writeU64(buffer, &index, frame.capability_id);
    @memcpy(buffer[index..][0..connection.source_mac.len], &connection.source_mac);
    index += connection.source_mac.len;
    buffer[index] = @intCast(discovery_class.len);
    index += 1;
    @memcpy(buffer[index..][0..discovery_class.len], discovery_class);
    index += discovery_class.len;
    buffer[index] = @intCast(frame.probe_len);
    index += 1;
    @memcpy(buffer[index..][0..frame.probe_len], frame.ciphertextSlice());
    index += frame.probe_len;
    @memcpy(buffer[index..][0..frame.probe_digest.len], &frame.probe_digest);
    index += frame.probe_digest.len;
    return buffer[0..index];
}

fn writeU64(buffer: []u8, index: *usize, value: u64) void {
    std.mem.writeInt(u64, buffer[index.*..][0..@sizeOf(u64)], value, .little);
    index.* += @sizeOf(u64);
}

fn updatePrincipal(hasher: *crypto_hash.Hasher, tag: []const u8, value: principal.PrincipalId) void {
    var bytes: [9]u8 = undefined;
    bytes[0] = @intFromEnum(value.kind);
    std.mem.writeInt(u64, bytes[1..9], value.serial, .little);
    crypto_hash.updateBytes(hasher, tag, &bytes);
}

test "network driver data plane is brokered by explicit egress capability" {
    const Harness = struct {
        var send_count: usize = 0;

        fn send(_: []const u8) void {
            send_count += 1;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 1 };
        }

        fn broker(request: EgressRequest) EgressDecision {
            return .{
                .allowed = request.network_policy_id == 41,
                .capability_backed = request.egress_capability_id == 99,
            };
        }
    };

    reset();
    defer reset();

    const device = NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(activateDevice(&device, 7));
    try std.testing.expect(!sendActiveFrame("frame"));
    setEgressBroker(Harness.broker);
    try std.testing.expect(!sendActiveFrame("frame"));
    bindEgressCapability(99, 41);
    try std.testing.expect(sendActiveFrame("frame"));
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
}

test "native network stack gates service identity packets on attested policy capability" {
    const Harness = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;

        fn send(frame: []const u8) void {
            send_count += 1;
            last_frame_len = frame.len;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 7 };
        }
    };

    Harness.send_count = 0;
    Harness.last_frame_len = 0;
    reset();
    defer reset();

    const device = NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(activateDevice(&device, 70));

    var policies = network_policy.Directory.init();
    var capabilities = @import("../kernel_api/capability.zig").CapabilityTable.init();
    const service_owner = principal.PrincipalId{ .kind = .service, .serial = 70 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 700 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 701 };
    const pinned_digest = [_]u8{0xA1} ** 32;
    const wrong_digest = [_]u8{0xA2} ** 32;

    const policy = try policies.create(.{
        .owner = service_owner,
        .label = "native-service-identity",
        .mode = .named_service_identity,
        .target = "overlay.native.identity",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
    });
    const policy_capability = try capabilities.mintBootRoot(.{
        .holder = service_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 70, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });

    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var stack = NativeNetworkStack.init();

    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = 70,
        .principal_id = service_owner,
        .capability_id = policy_capability.id,
        .policy_id = policy.id,
        .evidence = .{ .destination = .{ .service_identity = "overlay.native.identity" } },
        .now_ticks = 10,
    }, source, target));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.attestation_required, stack.last_denial_reason);

    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = 71,
        .principal_id = service_owner,
        .capability_id = policy_capability.id,
        .policy_id = policy.id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.native.identity" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
        },
        .now_ticks = 10,
    }, source, target));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.scope_violation, stack.last_denial_reason);

    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = 70,
        .principal_id = service_owner,
        .capability_id = policy_capability.id,
        .policy_id = policy.id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.native.identity" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = wrong_digest,
        },
        .now_ticks = 10,
    }, source, target));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.identity_pin_mismatch, stack.last_denial_reason);
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    const connection = try stack.openServiceIdentity(&broker, .{
        .task_id = 70,
        .principal_id = service_owner,
        .capability_id = policy_capability.id,
        .policy_id = policy.id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.native.identity" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
        },
        .now_ticks = 10,
    }, source, target);
    try std.testing.expect(connection.attestation_required);
    try std.testing.expect(connection.identity_pinned);

    const frame = try stack.sendServiceIdentityFrame(&connection, "native payload");
    try std.testing.expect(frame.encrypted);
    try std.testing.expect(frame.egress_allowed);
    try std.testing.expect(frame.attested);
    try std.testing.expect(frame.identity_pinned);
    try std.testing.expect(!std.mem.eql(u8, frame.ciphertextSlice(), "native payload"));
    try std.testing.expectEqual(@as(usize, 4), stack.attempted_connections);
    try std.testing.expectEqual(@as(usize, 3), stack.denied_before_transmit);
    try std.testing.expectEqual(@as(usize, 1), stack.opened_connections);
    try std.testing.expectEqual(@as(usize, 1), stack.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
    try std.testing.expect(Harness.last_frame_len > "native payload".len);
}

test "native network stack requires scoped local discovery before discovery broadcast" {
    const Harness = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;

        fn send(frame: []const u8) void {
            send_count += 1;
            last_frame_len = frame.len;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 8 };
        }
    };

    Harness.send_count = 0;
    Harness.last_frame_len = 0;
    reset();
    defer reset();

    const device = NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(activateDevice(&device, 80));

    var policies = network_policy.Directory.init();
    var capabilities = @import("../kernel_api/capability.zig").CapabilityTable.init();
    const service_owner = principal.PrincipalId{ .kind = .service, .serial = 80 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 800 };

    const discovery_policy = try policies.create(.{
        .owner = service_owner,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const discovery_capability = try capabilities.mintBootRoot(.{
        .holder = service_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = discovery_policy.id },
        .rights = .{ .network_policy = .{ .network_local = true } },
        .scope = .{ .task_id = 80, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });

    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var stack = NativeNetworkStack.init();

    try std.testing.expectError(error.EgressDenied, stack.openLocalDiscovery(&broker, .{
        .task_id = 80,
        .principal_id = service_owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy.id,
        .evidence = .{ .destination = .local_network },
        .now_ticks = 10,
    }, source));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.destination_mismatch, stack.last_denial_reason);

    try std.testing.expectError(error.EgressDenied, stack.openLocalDiscovery(&broker, .{
        .task_id = 80,
        .principal_id = service_owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy.id,
        .evidence = .{ .destination = .{ .discovery_class = "camera" } },
        .now_ticks = 10,
    }, source));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.destination_mismatch, stack.last_denial_reason);

    try std.testing.expectError(error.EgressDenied, stack.openLocalDiscovery(&broker, .{
        .task_id = 81,
        .principal_id = service_owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy.id,
        .evidence = .{ .destination = .{ .discovery_class = "printer" } },
        .now_ticks = 10,
    }, source));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.scope_violation, stack.last_denial_reason);
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    const connection = try stack.openLocalDiscovery(&broker, .{
        .task_id = 80,
        .principal_id = service_owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy.id,
        .evidence = .{ .destination = .{ .discovery_class = "printer" } },
        .now_ticks = 10,
    }, source);
    try std.testing.expect(connection.scoped_discovery);
    try std.testing.expectEqualStrings("printer", connection.discoveryClassSlice());

    const frame = try stack.sendLocalDiscoveryProbe(&connection, "who-has-printer");
    try std.testing.expect(frame.encrypted);
    try std.testing.expect(frame.egress_allowed);
    try std.testing.expect(frame.scoped_discovery);
    try std.testing.expectEqualStrings("printer", frame.discoveryClassSlice());
    try std.testing.expect(!std.mem.eql(u8, frame.ciphertextSlice(), "who-has-printer"));
    try std.testing.expectEqual(@as(usize, 4), stack.attempted_connections);
    try std.testing.expectEqual(@as(usize, 3), stack.denied_before_transmit);
    try std.testing.expectEqual(@as(usize, 1), stack.opened_connections);
    try std.testing.expectEqual(@as(usize, 1), stack.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
    try std.testing.expect(Harness.last_frame_len > "who-has-printer".len);
}
