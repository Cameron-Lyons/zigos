const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const principal = @import("../core/principal.zig");
const network_policy = @import("network_policy.zig");
const sync_state = @import("sync_state_support.zig");

pub const MAX_PACKET_BYTES: usize = 256;

pub const Error = error{
    EgressDenied,
    PacketTooLarge,
};

pub const EncryptedPacket = struct {
    session_id: u64,
    transport: sync_state.TransportMode,
    policy_id: u64,
    capability_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    ciphertext_len: usize,
    ciphertext: [MAX_PACKET_BYTES]u8,
    payload_digest: [32]u8,
    encrypted: bool,
    egress_allowed: bool,

    pub fn ciphertextSlice(self: *const EncryptedPacket) []const u8 {
        return self.ciphertext[0..self.ciphertext_len];
    }
};

pub const TransportSession = struct {
    id: u64,
    transport: sync_state.TransportMode,
    policy_id: u64,
    capability_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    relay_domain_len: usize = 0,
    relay_domain: [network_policy.MAX_TARGET_BYTES]u8 = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
    key: [32]u8,
    egress_decision: network_policy.EgressDecision,

    pub fn relayDomainSlice(self: *const TransportSession) []const u8 {
        return self.relay_domain[0..self.relay_domain_len];
    }
};

pub const Harness = struct {
    next_session_id: u64 = 1,
    created_sessions: usize = 0,
    denied_sessions: usize = 0,
    encrypted_packets: usize = 0,

    pub fn init() Harness {
        return .{};
    }

    pub fn openDeviceToDevice(
        self: *Harness,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!TransportSession {
        if (request.evidence.destination != .local_network) return error.EgressDenied;
        return self.openSession(
            broker,
            request,
            .device_to_device,
            source_device,
            target_device,
            "",
        );
    }

    pub fn openRelay(
        self: *Harness,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
        relay_domain: []const u8,
    ) Error!TransportSession {
        switch (request.evidence.destination) {
            .domain => |domain| {
                if (!std.mem.eql(u8, domain, relay_domain)) return error.EgressDenied;
            },
            else => return error.EgressDenied,
        }
        return self.openSession(
            broker,
            request,
            .relay_assisted,
            source_device,
            target_device,
            relay_domain,
        );
    }

    pub fn encryptPacket(
        self: *Harness,
        session: *const TransportSession,
        plaintext: []const u8,
    ) Error!EncryptedPacket {
        if (plaintext.len > MAX_PACKET_BYTES) return error.PacketTooLarge;

        var packet = EncryptedPacket{
            .session_id = session.id,
            .transport = session.transport,
            .policy_id = session.policy_id,
            .capability_id = session.capability_id,
            .source_device = session.source_device,
            .target_device = session.target_device,
            .ciphertext_len = plaintext.len,
            .ciphertext = [_]u8{0} ** MAX_PACKET_BYTES,
            .payload_digest = digestPayload(session, plaintext),
            .encrypted = true,
            .egress_allowed = session.egress_decision.allowed,
        };
        for (plaintext, 0..) |byte, index| {
            packet.ciphertext[index] = byte ^ session.key[index % session.key.len];
        }
        self.encrypted_packets += 1;
        return packet;
    }

    fn openSession(
        self: *Harness,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        transport: sync_state.TransportMode,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
        relay_domain: []const u8,
    ) Error!TransportSession {
        const decision = broker.connect(request) catch {
            self.denied_sessions += 1;
            return error.EgressDenied;
        };
        if (!decision.allowed) {
            self.denied_sessions += 1;
            return error.EgressDenied;
        }

        var session = TransportSession{
            .id = self.nextSessionId(),
            .transport = transport,
            .policy_id = request.policy_id,
            .capability_id = request.capability_id,
            .source_device = source_device,
            .target_device = target_device,
            .key = deriveSessionKey(transport, request, source_device, target_device, relay_domain),
            .egress_decision = decision,
        };
        session.relay_domain_len = @min(relay_domain.len, session.relay_domain.len);
        @memcpy(session.relay_domain[0..session.relay_domain_len], relay_domain[0..session.relay_domain_len]);
        self.created_sessions += 1;
        return session;
    }

    fn nextSessionId(self: *Harness) u64 {
        defer self.next_session_id += 1;
        return self.next_session_id;
    }
};

fn deriveSessionKey(
    transport: sync_state.TransportMode,
    request: network_policy.EgressConnectionRequest,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    relay_domain: []const u8,
) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "transport", transport);
    crypto_hash.updateInt(&hasher, "policy", request.policy_id);
    crypto_hash.updateInt(&hasher, "capability", request.capability_id);
    crypto_hash.updateInt(&hasher, "source-kind", @intFromEnum(source_device.kind));
    crypto_hash.updateInt(&hasher, "source-serial", source_device.serial);
    crypto_hash.updateInt(&hasher, "target-kind", @intFromEnum(target_device.kind));
    crypto_hash.updateInt(&hasher, "target-serial", target_device.serial);
    crypto_hash.updateBytes(&hasher, "relay-domain", relay_domain);
    crypto_hash.updateInt(&hasher, "task", request.task_id);
    return crypto_hash.finalize(&hasher);
}

fn digestPayload(session: *const TransportSession, plaintext: []const u8) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "session", session.id);
    crypto_hash.updateBytes(&hasher, "key", &session.key);
    crypto_hash.updateBytes(&hasher, "plaintext", plaintext);
    return crypto_hash.finalize(&hasher);
}

test "encrypted transport harness only creates sessions after egress approval" {
    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 1 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 2 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 10 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 11 };
    const relay = try policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.sync.example",
    });
    const relay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 42, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10 },
        .audit = .{},
    });
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var harness = Harness.init();

    const session = try harness.openRelay(&broker, .{
        .task_id = 42,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.sync.example" } },
        .now_ticks = 5,
    }, source, target, "relay.sync.example");
    const packet = try harness.encryptPacket(&session, "sync payload");
    try std.testing.expect(packet.encrypted);
    try std.testing.expect(packet.egress_allowed);
    try std.testing.expect(!std.mem.eql(u8, packet.ciphertextSlice(), "sync payload"));
    try std.testing.expectEqual(@as(usize, 1), harness.created_sessions);

    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, .{
        .task_id = 42,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "other.sync.example" } },
        .now_ticks = 5,
    }, source, target, "other.sync.example"));
    try std.testing.expectEqual(@as(usize, 1), harness.denied_sessions);
    try std.testing.expectEqual(@as(usize, 1), harness.created_sessions);
}
