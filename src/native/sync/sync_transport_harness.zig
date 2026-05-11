const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const network_policy = @import("network_policy.zig");
const sync_state = @import("sync_state_support.zig");

pub const MAX_PACKET_BYTES: usize = 256;
pub const MAX_RELAY_PACKETS: usize = 16;

pub const Error = error{
    EgressDenied,
    PacketTooLarge,
    PacketAuthenticationFailed,
    PacketTargetMismatch,
    FrameSigningFailed,
    RelayDomainTooLong,
    RelayQueueFull,
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

pub const SignedEncryptedFrame = struct {
    packet: EncryptedPacket,
    packet_digest: [32]u8,
    signature: manifest.Signature,
};

const RelayPacketSlot = struct {
    in_use: bool = false,
    packet_id: u64 = 0,
    packet: EncryptedPacket = undefined,
};

const RelayPacketArena = indexed_arena.IndexedArenaWithKey(u64, RelayPacketSlot, MAX_RELAY_PACKETS, MAX_RELAY_PACKETS * 2, relayPacketSlotId);
const RelaySessionIndex = indexed_arena.MultimapIndex(MAX_RELAY_PACKETS, MAX_RELAY_PACKETS, MAX_RELAY_PACKETS * 2);

pub const Relay = struct {
    next_packet_id: u64 = 1,
    packets: RelayPacketArena = RelayPacketArena.init(),
    session_index: RelaySessionIndex = RelaySessionIndex.init(),
    accepted_packets: usize = 0,
    delivered_packets: usize = 0,

    pub fn init() Relay {
        return .{};
    }

    pub fn submit(self: *Relay, packet: EncryptedPacket) Error!void {
        if (!packet.encrypted or !packet.egress_allowed) return error.EgressDenied;
        const packet_id = self.nextPacketId();
        const slot_index = self.packets.reserveIndex(packet_id) orelse return error.RelayQueueFull;
        const slot = &self.packets.slots[slot_index];
        slot.packet_id = packet_id;
        slot.packet = packet;
        if (!self.session_index.append(relayPacketSessionKey(packet), slot_index)) {
            _ = self.packets.removeIndex(slot_index);
            native_util.impossibleByInvariant("relay session index capacity covers relay packet slots");
        }
        self.accepted_packets += 1;
    }

    pub fn deliverNext(
        self: *Relay,
        session: *const TransportSession,
        plaintext_out: []u8,
    ) Error!?[]const u8 {
        const key = relaySessionKey(session.id, session.source_device, session.target_device);
        const slot_index = self.session_index.head(key);
        if (slot_index == indexed_arena.no_index) return null;
        if (slot_index >= MAX_RELAY_PACKETS) native_util.impossibleByInvariant("relay session index points outside packet slots");
        const slot = &self.packets.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("relay session index points at a free packet");
        if (slot.packet.session_id != session.id or
            !slot.packet.target_device.eql(session.target_device) or
            !slot.packet.source_device.eql(session.source_device))
        {
            native_util.impossibleByInvariant("relay session index points at the wrong packet");
        }
        const plaintext = try decryptPacket(session, slot.packet, plaintext_out);
        _ = self.session_index.remove(key, slot_index);
        _ = self.packets.removeIndex(slot_index);
        self.delivered_packets += 1;
        return plaintext;
    }

    fn nextPacketId(self: *Relay) u64 {
        const packet_id = self.next_packet_id;
        self.next_packet_id +%= 1;
        if (self.next_packet_id == 0) self.next_packet_id = 1;
        return packet_id;
    }
};

pub const BootedOverlayRelayService = struct {
    service_id: u64,
    task_id: u64,
    relay_domain_len: usize = 0,
    relay_domain: [network_policy.MAX_TARGET_BYTES]u8 = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
    relay: Relay = Relay.init(),
    accepted_packets: usize = 0,
    delivered_packets: usize = 0,
    rejected_packets: usize = 0,

    pub fn init(service_id: u64, task_id: u64, relay_domain: []const u8) Error!BootedOverlayRelayService {
        if (service_id == 0 or task_id == 0) return error.EgressDenied;
        if (relay_domain.len > network_policy.MAX_TARGET_BYTES) return error.RelayDomainTooLong;

        var service = BootedOverlayRelayService{
            .service_id = service_id,
            .task_id = task_id,
        };
        service.relay_domain_len = relay_domain.len;
        @memcpy(service.relay_domain[0..relay_domain.len], relay_domain);
        return service;
    }

    pub fn relayDomainSlice(self: *const BootedOverlayRelayService) []const u8 {
        return self.relay_domain[0..self.relay_domain_len];
    }

    pub fn submitSignedFrame(
        self: *BootedOverlayRelayService,
        caller_task_id: u64,
        session: *const TransportSession,
        frame: SignedEncryptedFrame,
    ) Error!void {
        try self.authorizeCaller(caller_task_id, session);
        if (!verifySignedFrame(&frame)) return self.reject(error.PacketAuthenticationFailed);
        if (frame.packet.session_id != session.id or
            frame.packet.transport != session.transport or
            frame.packet.policy_id != session.policy_id or
            frame.packet.capability_id != session.capability_id or
            !frame.packet.source_device.eql(session.source_device) or
            !frame.packet.target_device.eql(session.target_device))
        {
            return self.reject(error.PacketTargetMismatch);
        }

        self.relay.submit(frame.packet) catch |err| return self.reject(err);
        self.accepted_packets += 1;
    }

    pub fn deliverNext(
        self: *BootedOverlayRelayService,
        caller_task_id: u64,
        session: *const TransportSession,
        plaintext_out: []u8,
    ) Error!?[]const u8 {
        try self.authorizeCaller(caller_task_id, session);
        const delivered = self.relay.deliverNext(session, plaintext_out) catch |err| return self.reject(err);
        if (delivered != null) self.delivered_packets += 1;
        return delivered;
    }

    fn authorizeCaller(
        self: *BootedOverlayRelayService,
        caller_task_id: u64,
        session: *const TransportSession,
    ) Error!void {
        if (caller_task_id == 0 or caller_task_id != session.task_id) return self.reject(error.EgressDenied);
        if (session.transport != .relay_assisted) return self.reject(error.EgressDenied);
        if (!session.egress_decision.allowed) return self.reject(error.EgressDenied);
        if (!std.mem.eql(u8, session.relayDomainSlice(), self.relayDomainSlice())) {
            return self.reject(error.EgressDenied);
        }
    }

    fn reject(self: *BootedOverlayRelayService, err: Error) Error {
        self.rejected_packets += 1;
        return err;
    }
};

fn relayPacketSlotId(slot: *const RelayPacketSlot) u64 {
    return slot.packet_id;
}

fn relayPacketSessionKey(packet: EncryptedPacket) u64 {
    return relaySessionKey(packet.session_id, packet.source_device, packet.target_device);
}

fn relaySessionKey(session_id: u64, source_device: principal.PrincipalId, target_device: principal.PrincipalId) u64 {
    var bytes: [26]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..8], session_id, .little);
    bytes[8] = @intFromEnum(source_device.kind);
    std.mem.writeInt(u64, bytes[9..17], source_device.serial, .little);
    bytes[17] = @intFromEnum(target_device.kind);
    std.mem.writeInt(u64, bytes[18..26], target_device.serial, .little);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(0x5A47_5245_4C41_59, &bytes));
}

pub const TransportSession = struct {
    id: u64,
    task_id: u64,
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

    pub fn openServiceIdentity(
        self: *Harness,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!TransportSession {
        switch (request.evidence.destination) {
            .service_identity => {},
            else => return error.EgressDenied,
        }
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

    pub fn encryptSignedFrame(
        self: *Harness,
        session: *const TransportSession,
        plaintext: []const u8,
        identity: signing.SignerIdentity,
    ) Error!SignedEncryptedFrame {
        const packet = try self.encryptPacket(session, plaintext);
        return signPacket(packet, identity);
    }

    pub fn sendRelayPacket(
        self: *Harness,
        relay: *Relay,
        session: *const TransportSession,
        plaintext: []const u8,
    ) Error!EncryptedPacket {
        if (session.transport != .relay_assisted) return error.EgressDenied;
        const packet = try self.encryptPacket(session, plaintext);
        try relay.submit(packet);
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
            .task_id = request.task_id,
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

pub const EmulatedNativeTransport = struct {
    harness: Harness = Harness.init(),
    attempted_connections: usize = 0,
    denied_before_transmit: usize = 0,
    transmitted_packets: usize = 0,

    pub fn init() EmulatedNativeTransport {
        return .{};
    }

    pub fn openServiceIdentity(
        self: *EmulatedNativeTransport,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!TransportSession {
        self.attempted_connections += 1;
        return self.harness.openServiceIdentity(
            broker,
            request,
            source_device,
            target_device,
        ) catch |err| {
            self.denied_before_transmit += 1;
            return err;
        };
    }

    pub fn send(
        self: *EmulatedNativeTransport,
        session: *const TransportSession,
        plaintext: []const u8,
    ) Error!EncryptedPacket {
        const packet = try self.harness.encryptPacket(session, plaintext);
        self.transmitted_packets += 1;
        return packet;
    }
};

pub fn signPacket(
    packet: EncryptedPacket,
    identity: signing.SignerIdentity,
) Error!SignedEncryptedFrame {
    const digest = packetDigest(packet);
    return .{
        .packet = packet,
        .packet_digest = digest,
        .signature = signing.sign(identity, &digest) catch return error.FrameSigningFailed,
    };
}

pub fn verifySignedFrame(frame: *const SignedEncryptedFrame) bool {
    const expected_digest = packetDigest(frame.packet);
    if (!std.mem.eql(u8, &expected_digest, &frame.packet_digest)) return false;
    return signing.verify(frame.signature, &frame.packet_digest);
}

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

fn packetDigest(packet: EncryptedPacket) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "session", packet.session_id);
    crypto_hash.updateEnum(&hasher, "transport", packet.transport);
    crypto_hash.updateInt(&hasher, "policy", packet.policy_id);
    crypto_hash.updateInt(&hasher, "capability", packet.capability_id);
    updatePrincipal(&hasher, "source", packet.source_device);
    updatePrincipal(&hasher, "target", packet.target_device);
    crypto_hash.updateBytes(&hasher, "ciphertext", packet.ciphertextSlice());
    crypto_hash.updateBytes(&hasher, "payload-digest", &packet.payload_digest);
    crypto_hash.updateBool(&hasher, "encrypted", packet.encrypted);
    crypto_hash.updateBool(&hasher, "egress-allowed", packet.egress_allowed);
    return crypto_hash.finalize(&hasher);
}

fn updatePrincipal(hasher: *crypto_hash.Hasher, tag: []const u8, value: principal.PrincipalId) void {
    var bytes: [9]u8 = undefined;
    bytes[0] = @intFromEnum(value.kind);
    std.mem.writeInt(u64, bytes[1..9], value.serial, .little);
    crypto_hash.updateBytes(hasher, tag, &bytes);
}

fn decryptPacket(
    session: *const TransportSession,
    packet: EncryptedPacket,
    plaintext_out: []u8,
) Error![]const u8 {
    if (!packet.target_device.eql(session.target_device) or !packet.source_device.eql(session.source_device)) {
        return error.PacketTargetMismatch;
    }
    if (packet.ciphertext_len > plaintext_out.len) return error.PacketTooLarge;
    var index: usize = 0;
    while (index < packet.ciphertext_len) : (index += 1) {
        plaintext_out[index] = packet.ciphertext[index] ^ session.key[index % session.key.len];
    }
    const plaintext = plaintext_out[0..packet.ciphertext_len];
    const expected_digest = digestPayload(session, plaintext);
    if (!std.mem.eql(u8, &expected_digest, &packet.payload_digest)) {
        return error.PacketAuthenticationFailed;
    }
    return plaintext;
}

pub fn decryptForSession(
    session: *const TransportSession,
    packet: EncryptedPacket,
    plaintext_out: []u8,
) Error![]const u8 {
    return decryptPacket(session, packet, plaintext_out);
}

pub fn decryptSignedFrame(
    session: *const TransportSession,
    frame: *const SignedEncryptedFrame,
    plaintext_out: []u8,
) Error![]const u8 {
    if (!verifySignedFrame(frame)) return error.PacketAuthenticationFailed;
    return decryptPacket(session, frame.packet, plaintext_out);
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

    var relay_queue = Relay.init();
    _ = try harness.sendRelayPacket(&relay_queue, &session, "relay op log");
    try std.testing.expectEqual(@as(usize, 1), relay_queue.packets.countInUse());
    var plaintext_buffer: [MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay_queue.deliverNext(&session, plaintext_buffer[0..])).?;
    try std.testing.expectEqualStrings("relay op log", delivered);
    try std.testing.expectEqual(@as(usize, 0), relay_queue.packets.countInUse());
    try std.testing.expectEqual(@as(usize, 1), relay_queue.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), relay_queue.delivered_packets);

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

test "booted overlay relay service rejects unauthorized relay and target changes" {
    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 5 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 6 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 30 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 31 };
    const other_target = principal.PrincipalId{ .kind = .device, .serial = 32 };
    const signer_identity = signing.SignerIdentity{
        .label = "booted-overlay-relay",
        .seed = [_]u8{0x42} ** 32,
    };

    const relay_policy = try policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.sync.example",
    });
    const relay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = relay_policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 77, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10 },
        .audit = .{},
    });
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var harness = Harness.init();
    const session = try harness.openRelay(&broker, .{
        .task_id = 77,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay_policy.id,
        .evidence = .{ .destination = .{ .domain = "relay.sync.example" } },
        .now_ticks = 5,
    }, source, target, "relay.sync.example");

    var relay_service = try BootedOverlayRelayService.init(50, 51, "relay.sync.example");
    const signed_frame = try harness.encryptSignedFrame(&session, "relay service frame", signer_identity);
    try relay_service.submitSignedFrame(77, &session, signed_frame);
    var plaintext_buffer: [MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay_service.deliverNext(77, &session, plaintext_buffer[0..])).?;
    try std.testing.expectEqualStrings("relay service frame", delivered);
    try std.testing.expectEqualStrings("relay.sync.example", relay_service.relayDomainSlice());
    try std.testing.expectEqual(@as(usize, 1), relay_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), relay_service.delivered_packets);
    try std.testing.expectEqual(@as(usize, 0), relay_service.rejected_packets);
    try std.testing.expectEqual(@as(usize, 1), relay_service.relay.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), relay_service.relay.delivered_packets);

    var wrong_domain_service = try BootedOverlayRelayService.init(52, 53, "other.sync.example");
    const blocked_frame = try harness.encryptSignedFrame(&session, "blocked relay", signer_identity);
    try std.testing.expectError(error.EgressDenied, wrong_domain_service.submitSignedFrame(77, &session, blocked_frame));
    try std.testing.expectEqual(@as(usize, 0), wrong_domain_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), wrong_domain_service.rejected_packets);

    try std.testing.expectError(error.EgressDenied, relay_service.submitSignedFrame(78, &session, blocked_frame));
    try std.testing.expectError(error.EgressDenied, relay_service.submitSignedFrame(0, &session, blocked_frame));
    var tampered_packet = try harness.encryptPacket(&session, "target change");
    tampered_packet.target_device = other_target;
    const tampered_frame = try signPacket(tampered_packet, signer_identity);
    try std.testing.expectError(error.PacketTargetMismatch, relay_service.submitSignedFrame(77, &session, tampered_frame));
    try std.testing.expectEqual(@as(usize, 1), relay_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 3), relay_service.rejected_packets);
}

test "encrypted transport harness binds device sessions to attested identity and route" {
    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 3 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 4 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 20 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 21 };
    const other_target = principal.PrincipalId{ .kind = .device, .serial = 22 };
    const pinned_digest = [_]u8{0xA5} ** 32;
    const local = try policies.create(.{
        .owner = owner,
        .label = "local-pinned",
        .mode = .local_network,
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
    });
    const local_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = local.id },
        .rights = .{ .network_policy = .{ .network_local = true } },
        .scope = .{ .task_id = 43, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10 },
        .audit = .{},
    });
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var harness = Harness.init();

    try std.testing.expectError(error.EgressDenied, harness.openDeviceToDevice(&broker, .{
        .task_id = 43,
        .principal_id = app,
        .capability_id = local_capability.id,
        .policy_id = local.id,
        .evidence = .{ .destination = .local_network },
        .now_ticks = 5,
    }, source, target));

    try std.testing.expectError(error.EgressDenied, harness.openDeviceToDevice(&broker, .{
        .task_id = 43,
        .principal_id = app,
        .capability_id = local_capability.id,
        .policy_id = local.id,
        .evidence = .{
            .destination = .{ .domain = "relay.sync.example" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
        },
        .now_ticks = 5,
    }, source, target));

    const session = try harness.openDeviceToDevice(&broker, .{
        .task_id = 43,
        .principal_id = app,
        .capability_id = local_capability.id,
        .policy_id = local.id,
        .evidence = .{
            .destination = .local_network,
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
        },
        .now_ticks = 5,
    }, source, target);
    try std.testing.expectEqual(sync_state.TransportMode.device_to_device, session.transport);
    try std.testing.expect(session.egress_decision.policy_decision.identity_pinned);

    const retargeted = try harness.openDeviceToDevice(&broker, .{
        .task_id = 43,
        .principal_id = app,
        .capability_id = local_capability.id,
        .policy_id = local.id,
        .evidence = .{
            .destination = .local_network,
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
        },
        .now_ticks = 5,
    }, source, other_target);
    try std.testing.expect(!std.mem.eql(u8, &session.key, &retargeted.key));

    const packet = try harness.encryptPacket(&session, "local sync");
    try std.testing.expect(packet.encrypted);
    try std.testing.expectEqual(source, packet.source_device);
    try std.testing.expectEqual(target, packet.target_device);
    try std.testing.expectEqual(@as(usize, 2), harness.created_sessions);
    try std.testing.expectEqual(@as(usize, 1), harness.denied_sessions);
}

test "emulated native transport denies service identity before packet transmission" {
    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 5 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 6 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 30 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 31 };
    const pinned_digest = [_]u8{0xC1} ** 32;
    const wrong_digest = [_]u8{0xC2} ** 32;

    const overlay = try policies.create(.{
        .owner = owner,
        .label = "notes-service",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
    });
    const overlay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = overlay.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 44, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 20 },
        .audit = .{},
    });

    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var transport = EmulatedNativeTransport.init();

    try std.testing.expectError(error.EgressDenied, transport.openServiceIdentity(&broker, .{
        .task_id = 44,
        .principal_id = app,
        .capability_id = overlay_capability.id,
        .policy_id = overlay.id,
        .evidence = .{ .destination = .{ .service_identity = "overlay.notes.sync" } },
        .now_ticks = 5,
    }, source, target));

    try std.testing.expectError(error.EgressDenied, transport.openServiceIdentity(&broker, .{
        .task_id = 44,
        .principal_id = app,
        .capability_id = overlay_capability.id,
        .policy_id = overlay.id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.notes.sync" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = wrong_digest,
        },
        .now_ticks = 5,
    }, source, target));

    try std.testing.expectEqual(@as(usize, 2), transport.attempted_connections);
    try std.testing.expectEqual(@as(usize, 2), transport.denied_before_transmit);
    try std.testing.expectEqual(@as(usize, 0), transport.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 0), transport.harness.created_sessions);

    const session = try transport.openServiceIdentity(&broker, .{
        .task_id = 44,
        .principal_id = app,
        .capability_id = overlay_capability.id,
        .policy_id = overlay.id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.notes.sync" },
            .attested = true,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
        },
        .now_ticks = 5,
    }, source, target);
    try std.testing.expect(session.egress_decision.policy_decision.attestation_required);
    try std.testing.expect(session.egress_decision.policy_decision.identity_pinned);

    const packet = try transport.send(&session, "attested payload");
    try std.testing.expect(packet.encrypted);
    try std.testing.expect(packet.egress_allowed);
    try std.testing.expect(!std.mem.eql(u8, packet.ciphertextSlice(), "attested payload"));
    try std.testing.expectEqual(@as(usize, 3), transport.attempted_connections);
    try std.testing.expectEqual(@as(usize, 2), transport.denied_before_transmit);
    try std.testing.expectEqual(@as(usize, 1), transport.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 1), transport.harness.created_sessions);
}
