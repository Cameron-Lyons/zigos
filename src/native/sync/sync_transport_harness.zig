const builtin = @import("builtin");
const std = @import("std");
const attestation_service = @import("../platform/attestation_service.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const network_policy = @import("network_policy.zig");
const sync_state = @import("sync_state_support.zig");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/memory/memory.zig")
else
    struct {};

pub const MAX_PACKET_BYTES: usize = 256;
pub const MAX_RELAY_PACKETS: usize = 16;
pub const COMPACT_RELAY_METADATA = true;
pub const HEAP_BACKED_RELAY_QUEUE_ON_FREESTANDING = true;
pub const ENCRYPTED_PACKET_SIZE_CEILING_BYTES: usize = 352;
pub const SIGNED_ENCRYPTED_FRAME_SIZE_CEILING_BYTES: usize = 504;
pub const RELAY_PACKET_SLOT_SIZE_CEILING_BYTES: usize = 368;
pub const HOST_RELAY_SIZE_CEILING_BYTES: usize = 7_016;
pub const FREESTANDING_RELAY_SIZE_CEILING_BYTES: usize = 24;
pub const RELAY_SIZE_CEILING_BYTES: usize = if (builtin.target.os.tag == .freestanding)
    FREESTANDING_RELAY_SIZE_CEILING_BYTES
else
    HOST_RELAY_SIZE_CEILING_BYTES;
pub const HOST_BOOTED_RELAY_SERVICE_SIZE_CEILING_BYTES: usize = 7_128;
pub const FREESTANDING_BOOTED_RELAY_SERVICE_SIZE_CEILING_BYTES: usize = 136;
pub const BOOTED_RELAY_SERVICE_SIZE_CEILING_BYTES: usize = if (builtin.target.os.tag == .freestanding)
    FREESTANDING_BOOTED_RELAY_SERVICE_SIZE_CEILING_BYTES
else
    HOST_BOOTED_RELAY_SERVICE_SIZE_CEILING_BYTES;
pub const TRANSPORT_SESSION_SIZE_CEILING_BYTES: usize = 288;

comptime {
    if (MAX_PACKET_BYTES > std.math.maxInt(u16) or network_policy.MAX_TARGET_BYTES > std.math.maxInt(u8)) {
        @compileError("relay transport metadata no longer fits compact lengths");
    }
}

pub const Error = error{
    EgressDenied,
    PacketEmpty,
    PacketTooLarge,
    PacketAuthenticationFailed,
    PacketTargetMismatch,
    FrameSigningFailed,
    ProductionAttestationRequired,
    RelayDomainTooLong,
    RelayPacketIdExhausted,
    RelayQueueFull,
    TransportSessionIdExhausted,
    NoSpaceLeft,
};

pub const EncryptedPacket = struct {
    session_id: u64,
    transport: sync_state.TransportMode,
    policy_id: u64,
    capability_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    ciphertext_len: u16,
    ciphertext: [MAX_PACKET_BYTES]u8,
    payload_digest: crypto_hash.Digest,
    encrypted: bool,
    egress_allowed: bool,

    pub fn ciphertextSlice(self: *const EncryptedPacket) []const u8 {
        return self.ciphertext[0..@as(usize, self.ciphertext_len)];
    }

    comptime {
        if (@sizeOf(@This()) > ENCRYPTED_PACKET_SIZE_CEILING_BYTES) {
            @compileError("encrypted relay packet exceeds its compact size ceiling");
        }
    }
};

pub const SignedEncryptedFrame = struct {
    packet: EncryptedPacket,
    packet_digest: crypto_hash.Digest,
    signature: manifest.Signature,

    comptime {
        if (@sizeOf(@This()) > SIGNED_ENCRYPTED_FRAME_SIZE_CEILING_BYTES) {
            @compileError("signed encrypted relay frame exceeds its compact size ceiling");
        }
    }
};

pub const SessionTrustPosture = enum(u8) {
    local_lab_only,
    production_attested,
};

pub const VerifiedServiceIdentityOpenRequest = struct {
    task_id: u64,
    principal_id: principal.PrincipalId,
    capability_id: u64,
    policy_id: u64,
    service_identity: []const u8,
    attestation_response: attestation_service.RemoteAttestationResponse,
    attestation_request: attestation_service.RemoteAttestationRequest,
    attested_boot: *const measured_boot.BootRecord,
    trusted_root: signing.PublicIdentity,
    now_ticks: u64,
};

const RelayPacketSlot = struct {
    in_use: bool = false,
    packet_id: u64 = 0,
    packet: EncryptedPacket = undefined,

    comptime {
        if (@sizeOf(@This()) > RELAY_PACKET_SLOT_SIZE_CEILING_BYTES) {
            @compileError("relay packet slot exceeds its compact size ceiling");
        }
    }
};

const RelayPacketArena = indexed_arena.IndexedArenaWithKey(u64, RelayPacketSlot, MAX_RELAY_PACKETS, MAX_RELAY_PACKETS * 2, relayPacketSlotId);
const RelaySessionIndex = indexed_arena.MultimapIndex(MAX_RELAY_PACKETS, MAX_RELAY_PACKETS, MAX_RELAY_PACKETS * 2);

const RelayQueueState = struct {
    next_packet_id: u64 = 1,
    packets: RelayPacketArena = RelayPacketArena.init(),
    session_index: RelaySessionIndex = RelaySessionIndex.init(),

    fn initializeAllocated(self: *RelayQueueState) void {
        @memset(std.mem.asBytes(self), 0);
        self.next_packet_id = 1;
        const no_packet_index = indexed_arena.reusableNoIndex(MAX_RELAY_PACKETS);
        @memset(self.packets.free_next[0..], no_packet_index);
        self.packets.free_head = no_packet_index;

        const SessionIndex = @FieldType(RelayQueueState, "session_index");
        const CompactIndex = @FieldType(SessionIndex, "free_bucket_head");
        const no_session_bucket: CompactIndex = @intCast(@max(self.session_index.links.len, self.session_index.buckets.len));
        for (&self.session_index.links) |*link| link.bucket = no_session_bucket;
        self.session_index.free_bucket_head = no_session_bucket;
    }

    fn pendingPacketId(self: *const RelayQueueState) Error!u64 {
        if (self.next_packet_id == 0) return error.RelayPacketIdExhausted;
        return self.next_packet_id;
    }
};

const heap_backed_relay_queue = HEAP_BACKED_RELAY_QUEUE_ON_FREESTANDING and builtin.target.os.tag == .freestanding;
const RelayQueueBacking = if (heap_backed_relay_queue) ?*RelayQueueState else RelayQueueState;

pub const relay_queue_layout = .{
    .heap_backs_queue_on_freestanding = HEAP_BACKED_RELAY_QUEUE_ON_FREESTANDING,
    .freestanding_handle_size_bytes = @sizeOf(?*RelayQueueState),
    .backing_size_bytes = @sizeOf(RelayQueueState),
    .freestanding_resident_savings_bytes = @sizeOf(RelayQueueState) - @sizeOf(?*RelayQueueState),
    .uses_packet_arena = @hasField(RelayQueueState, "packets"),
    .uses_session_index = @hasField(RelayQueueState, "session_index"),
};

pub const Relay = struct {
    queue: RelayQueueBacking = if (heap_backed_relay_queue) null else .{},
    accepted_packets: usize = 0,
    delivered_packets: usize = 0,

    pub fn init() Relay {
        return .{};
    }

    pub fn submit(self: *Relay, packet: EncryptedPacket) Error!void {
        if (!packet.encrypted or !packet.egress_allowed) return error.EgressDenied;
        if (packet.ciphertext_len == 0) return error.PacketEmpty;
        if (packet.ciphertext_len > packet.ciphertext.len) return error.PacketTooLarge;
        const queue = try self.ensureQueue();
        const packet_id = try queue.pendingPacketId();
        const slot_index = queue.packets.reserveIndex(packet_id) orelse return error.RelayQueueFull;
        const slot = &queue.packets.slots[slot_index];
        slot.packet_id = packet_id;
        slot.packet = packet;
        if (!queue.session_index.append(relayPacketSessionKey(packet), slot_index)) {
            _ = queue.packets.removeIndex(slot_index);
            native_util.impossibleByInvariant("relay session index capacity covers relay packet slots");
        }
        queue.next_packet_id = nextMonotonicId(packet_id);
        self.accepted_packets += 1;
    }

    pub fn deliverNext(
        self: *Relay,
        session: *const TransportSession,
        plaintext_out: []u8,
    ) Error!?[]const u8 {
        const queue = self.queueState() orelse return null;
        const key = relaySessionKey(session.id, session.source_device, session.target_device);
        const slot_index = queue.session_index.head(key);
        if (slot_index == indexed_arena.no_index) return null;
        if (slot_index >= MAX_RELAY_PACKETS) native_util.impossibleByInvariant("relay session index points outside packet slots");
        const slot = &queue.packets.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("relay session index points at a free packet");
        if (slot.packet.session_id != session.id or
            !slot.packet.target_device.eql(session.target_device) or
            !slot.packet.source_device.eql(session.source_device))
        {
            native_util.impossibleByInvariant("relay session index points at the wrong packet");
        }
        const plaintext = try decryptPacket(session, slot.packet, plaintext_out);
        _ = queue.session_index.remove(key, slot_index);
        _ = queue.packets.removeIndex(slot_index);
        self.delivered_packets += 1;
        return plaintext;
    }

    pub fn queuedCount(self: *const Relay) usize {
        const queue = self.queueStateConst() orelse return 0;
        return queue.packets.countInUse();
    }

    pub fn nextPacketId(self: *const Relay) u64 {
        const queue = self.queueStateConst() orelse return 1;
        return queue.next_packet_id;
    }

    fn containsPacketId(self: *const Relay, packet_id: u64) bool {
        const queue = self.queueStateConst() orelse return false;
        return queue.packets.getConst(packet_id) != null;
    }

    fn setNextPacketIdForTest(self: *Relay, packet_id: u64) Error!void {
        const queue = try self.ensureQueue();
        queue.next_packet_id = packet_id;
    }

    fn ensureQueue(self: *Relay) error{NoSpaceLeft}!*RelayQueueState {
        if (comptime heap_backed_relay_queue) {
            if (self.queue) |queue| return queue;
            const allocation = kernel_memory.kmalloc(@sizeOf(RelayQueueState)) orelse return error.NoSpaceLeft;
            const queue: *RelayQueueState = @ptrCast(@alignCast(allocation));
            queue.initializeAllocated();
            self.queue = queue;
            return queue;
        }
        return &self.queue;
    }

    fn queueState(self: *Relay) ?*RelayQueueState {
        if (comptime heap_backed_relay_queue) return self.queue;
        return &self.queue;
    }

    fn queueStateConst(self: *const Relay) ?*const RelayQueueState {
        if (comptime heap_backed_relay_queue) return self.queue;
        return &self.queue;
    }

    pub fn deinit(self: *Relay) void {
        if (comptime heap_backed_relay_queue) {
            if (self.queue) |queue| {
                @memset(std.mem.asBytes(queue), 0);
                kernel_memory.kfree(@ptrCast(queue));
                self.queue = null;
            }
        } else {
            self.queue = .{};
        }
        self.accepted_packets = 0;
        self.delivered_packets = 0;
    }

    comptime {
        if (@sizeOf(@This()) > RELAY_SIZE_CEILING_BYTES) {
            @compileError("relay queue exceeds its compact size ceiling");
        }
    }
};

pub const BootedOverlayRelayService = struct {
    service_id: u64,
    task_id: u64,
    relay_domain_len: u8 = 0,
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
        service.relay_domain_len = @intCast(relay_domain.len);
        @memcpy(service.relay_domain[0..relay_domain.len], relay_domain);
        return service;
    }

    pub fn relayDomainSlice(self: *const BootedOverlayRelayService) []const u8 {
        return self.relay_domain[0..@as(usize, self.relay_domain_len)];
    }

    pub fn deinit(self: *BootedOverlayRelayService) void {
        self.relay.deinit();
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

    comptime {
        if (@sizeOf(@This()) > BOOTED_RELAY_SERVICE_SIZE_CEILING_BYTES) {
            @compileError("booted relay service exceeds its compact size ceiling");
        }
    }
};

fn relayPacketSlotId(slot: *const RelayPacketSlot) u64 {
    return slot.packet_id;
}

fn relayPacketSessionKey(packet: EncryptedPacket) u64 {
    return relaySessionKey(packet.session_id, packet.source_device, packet.target_device);
}

fn relaySessionKey(session_id: u64, source_device: principal.PrincipalId, target_device: principal.PrincipalId) u64 {
    const session_id_offset = 0;
    const source_offset = session_id_offset + @sizeOf(u64);
    const target_offset = source_offset + principal.PrincipalId.key_bytes;
    const relay_session_key_bytes = target_offset + principal.PrincipalId.key_bytes;

    const source_bytes = source_device.keyBytes();
    const target_bytes = target_device.keyBytes();
    var bytes: [relay_session_key_bytes]u8 = undefined;
    std.mem.writeInt(u64, bytes[session_id_offset..][0..@sizeOf(u64)], session_id, .little);
    @memcpy(bytes[source_offset..][0..principal.PrincipalId.key_bytes], &source_bytes);
    @memcpy(bytes[target_offset..][0..principal.PrincipalId.key_bytes], &target_bytes);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(hash_seeds.sync_relay_session_key, &bytes));
}

pub const TransportSession = struct {
    id: u64,
    task_id: u64,
    transport: sync_state.TransportMode,
    policy_id: u64,
    capability_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    relay_domain_len: u8 = 0,
    relay_domain: [network_policy.MAX_TARGET_BYTES]u8 = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
    key: crypto_hash.Digest,
    egress_decision: network_policy.EgressDecision,
    trust_posture: SessionTrustPosture = .local_lab_only,
    verified_remote_attestation: bool = false,
    attestation_request_digest_present: bool = false,
    attestation_request_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    peer_root_digest_present: bool = false,
    peer_root_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    attestation_verifier_metadata_digest_present: bool = false,
    attestation_verifier_metadata_digest_bound: bool = false,
    attestation_verifier_metadata_digest: crypto_hash.Digest = crypto_hash.zero_digest,

    pub fn relayDomainSlice(self: *const TransportSession) []const u8 {
        return self.relay_domain[0..@as(usize, self.relay_domain_len)];
    }

    pub fn productionAttested(self: *const TransportSession) bool {
        return self.trust_posture == .production_attested and
            self.egress_decision.policy_decision.attestation_required and
            self.egress_decision.policy_decision.identity_pinned and
            self.verified_remote_attestation and
            self.attestation_request_digest_present and
            !std.mem.allEqual(u8, &self.attestation_request_digest, 0) and
            self.peer_root_digest_present and
            !std.mem.allEqual(u8, &self.peer_root_digest, 0) and
            self.attestation_verifier_metadata_digest_present and
            self.attestation_verifier_metadata_digest_bound and
            !std.mem.allEqual(u8, &self.attestation_verifier_metadata_digest, 0);
    }

    pub fn requireProductionAttestation(self: *const TransportSession) Error!void {
        if (!self.productionAttested()) return error.ProductionAttestationRequired;
    }

    comptime {
        if (@sizeOf(@This()) > TRANSPORT_SESSION_SIZE_CEILING_BYTES) {
            @compileError("transport session exceeds its compact size ceiling");
        }
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

    pub fn openVerifiedServiceIdentity(
        self: *Harness,
        broker: *network_policy.EgressBroker,
        request: VerifiedServiceIdentityOpenRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!TransportSession {
        const evidence = network_policy.ConnectionEvidence.fromVerifiedRemoteAttestation(
            .{ .service_identity = request.service_identity },
            request.attestation_response,
            request.attestation_request,
            request.attested_boot,
            request.trusted_root,
        ) orelse {
            self.denied_sessions += 1;
            return error.ProductionAttestationRequired;
        };
        return self.openServiceIdentity(broker, .{
            .task_id = request.task_id,
            .principal_id = request.principal_id,
            .capability_id = request.capability_id,
            .policy_id = request.policy_id,
            .evidence = evidence,
            .now_ticks = request.now_ticks,
        }, source_device, target_device);
    }

    pub fn openRelay(
        self: *Harness,
        broker: *network_policy.EgressBroker,
        request: network_policy.EgressConnectionRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
        relay_domain: []const u8,
    ) Error!TransportSession {
        if (relay_domain.len > network_policy.MAX_TARGET_BYTES) return error.RelayDomainTooLong;
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
        try validateSessionForCrypto(session);
        if (plaintext.len == 0) return error.PacketEmpty;
        if (plaintext.len > MAX_PACKET_BYTES) return error.PacketTooLarge;

        var packet = EncryptedPacket{
            .session_id = session.id,
            .transport = session.transport,
            .policy_id = session.policy_id,
            .capability_id = session.capability_id,
            .source_device = session.source_device,
            .target_device = session.target_device,
            .ciphertext_len = @intCast(plaintext.len),
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
        validateSessionRequest(request, source_device, target_device, relay_domain) catch |err| {
            if (err == error.EgressDenied) self.denied_sessions += 1;
            return err;
        };
        const decision = broker.connect(request) catch {
            self.denied_sessions += 1;
            return error.EgressDenied;
        };
        if (!decision.allowed) {
            self.denied_sessions += 1;
            return error.EgressDenied;
        }
        const session_id = try self.pendingSessionId();
        const trust_posture = sessionTrustPosture(request.evidence, decision.policy_decision);

        var session = TransportSession{
            .id = session_id,
            .task_id = request.task_id,
            .transport = transport,
            .policy_id = request.policy_id,
            .capability_id = request.capability_id,
            .source_device = source_device,
            .target_device = target_device,
            .key = deriveSessionKey(transport, trust_posture, request, source_device, target_device, relay_domain),
            .egress_decision = decision,
            .trust_posture = trust_posture,
            .verified_remote_attestation = request.evidence.verified_remote_attestation,
            .attestation_request_digest_present = request.evidence.attestation_request_digest_present,
            .attestation_request_digest = request.evidence.attestation_request_digest,
            .peer_root_digest_present = request.evidence.peer_root_digest_present,
            .peer_root_digest = request.evidence.peer_root_digest,
            .attestation_verifier_metadata_digest_present = request.evidence.attestation_verifier_metadata_digest_present,
            .attestation_verifier_metadata_digest_bound = request.evidence.attestation_verifier_metadata_digest_bound,
            .attestation_verifier_metadata_digest = request.evidence.attestation_verifier_metadata_digest,
        };
        const relay_domain_len = @min(relay_domain.len, session.relay_domain.len);
        session.relay_domain_len = @intCast(relay_domain_len);
        @memcpy(session.relay_domain[0..relay_domain_len], relay_domain[0..relay_domain_len]);
        self.next_session_id = nextMonotonicId(session_id);
        self.created_sessions += 1;
        return session;
    }

    fn pendingSessionId(self: *const Harness) Error!u64 {
        if (self.next_session_id == 0) return error.TransportSessionIdExhausted;
        return self.next_session_id;
    }
};

fn nextMonotonicId(id: u64) u64 {
    std.debug.assert(id != 0);
    return if (id == std.math.maxInt(u64)) 0 else id + 1;
}

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

    pub fn openVerifiedServiceIdentity(
        self: *EmulatedNativeTransport,
        broker: *network_policy.EgressBroker,
        request: VerifiedServiceIdentityOpenRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!TransportSession {
        self.attempted_connections += 1;
        return self.harness.openVerifiedServiceIdentity(
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
    trust_posture: SessionTrustPosture,
    request: network_policy.EgressConnectionRequest,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    relay_domain: []const u8,
) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "transport", transport);
    crypto_hash.updateEnum(&hasher, "trust-posture", trust_posture);
    crypto_hash.updateBool(&hasher, "verified-attestation", request.evidence.verified_remote_attestation);
    crypto_hash.updateBool(&hasher, "attestation-request-digest-present", request.evidence.attestation_request_digest_present);
    if (request.evidence.attestation_request_digest_present) {
        crypto_hash.updateBytes(&hasher, "attestation-request-digest", &request.evidence.attestation_request_digest);
    }
    crypto_hash.updateBool(&hasher, "attestation-verifier-metadata-digest-present", request.evidence.attestation_verifier_metadata_digest_present);
    if (request.evidence.attestation_verifier_metadata_digest_present) {
        crypto_hash.updateBool(&hasher, "attestation-verifier-metadata-digest-bound", request.evidence.attestation_verifier_metadata_digest_bound);
        crypto_hash.updateBytes(&hasher, "attestation-verifier-metadata-digest", &request.evidence.attestation_verifier_metadata_digest);
    }
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

fn sessionTrustPosture(
    evidence: network_policy.ConnectionEvidence,
    decision: network_policy.Decision,
) SessionTrustPosture {
    if (decision.attestation_required and
        decision.identity_pinned and
        evidence.hasVerifiedRemoteAttestation() and
        evidence.hasAttestationVerifierMetadataDigest())
    {
        return .production_attested;
    }
    return .local_lab_only;
}

fn digestPayload(session: *const TransportSession, plaintext: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "session", session.id);
    crypto_hash.updateBytes(&hasher, "key", &session.key);
    crypto_hash.updateBytes(&hasher, "plaintext", plaintext);
    return crypto_hash.finalize(&hasher);
}

pub fn packetDigest(packet: EncryptedPacket) crypto_hash.Digest {
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
    const bytes = value.keyBytes();
    crypto_hash.updateBytes(hasher, tag, &bytes);
}

fn validateSessionRequest(
    request: network_policy.EgressConnectionRequest,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    relay_domain: []const u8,
) Error!void {
    if (request.task_id == 0 or request.policy_id == 0 or request.capability_id == 0) {
        return error.EgressDenied;
    }
    if (relay_domain.len > network_policy.MAX_TARGET_BYTES) return error.RelayDomainTooLong;
    try validateDevicePair(source_device, target_device);
}

fn validateSessionForCrypto(session: *const TransportSession) Error!void {
    if (session.id == 0 or session.task_id == 0 or session.policy_id == 0 or session.capability_id == 0) {
        return error.EgressDenied;
    }
    if (!session.egress_decision.allowed) return error.EgressDenied;
    if (@as(usize, session.relay_domain_len) > network_policy.MAX_TARGET_BYTES) return error.RelayDomainTooLong;
    try validateDevicePair(session.source_device, session.target_device);
}

fn validateDevicePair(source_device: principal.PrincipalId, target_device: principal.PrincipalId) Error!void {
    if (source_device.kind != .device or target_device.kind != .device) return error.EgressDenied;
    if (source_device.serial == 0 or target_device.serial == 0) return error.EgressDenied;
    if (source_device.eql(target_device)) return error.EgressDenied;
}

fn decryptPacket(
    session: *const TransportSession,
    packet: EncryptedPacket,
    plaintext_out: []u8,
) Error![]const u8 {
    try validateSessionForCrypto(session);
    if (!packet.encrypted or !packet.egress_allowed) return error.EgressDenied;
    if (packet.session_id != session.id or
        packet.transport != session.transport or
        packet.policy_id != session.policy_id or
        packet.capability_id != session.capability_id or
        !packet.target_device.eql(session.target_device) or
        !packet.source_device.eql(session.source_device))
    {
        return error.PacketTargetMismatch;
    }
    const ciphertext_len: usize = @intCast(packet.ciphertext_len);
    if (ciphertext_len > packet.ciphertext.len) return error.PacketTooLarge;
    if (ciphertext_len > plaintext_out.len) return error.PacketTooLarge;
    var index: usize = 0;
    while (index < ciphertext_len) : (index += 1) {
        plaintext_out[index] = packet.ciphertext[index] ^ session.key[index % session.key.len];
    }
    const plaintext = plaintext_out[0..ciphertext_len];
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

    const relay_request = network_policy.EgressConnectionRequest{
        .task_id = 42,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.sync.example" } },
        .now_ticks = 5,
    };

    const session = try harness.openRelay(&broker, relay_request, source, target, "relay.sync.example");
    const packet = try harness.encryptPacket(&session, "sync payload");
    try std.testing.expect(packet.encrypted);
    try std.testing.expect(packet.egress_allowed);
    try std.testing.expect(!std.mem.eql(u8, packet.ciphertextSlice(), "sync payload"));
    try std.testing.expectEqual(SessionTrustPosture.local_lab_only, session.trust_posture);
    try std.testing.expect(!session.productionAttested());
    try std.testing.expectError(error.ProductionAttestationRequired, session.requireProductionAttestation());
    try std.testing.expectEqual(@as(usize, 1), harness.created_sessions);

    var zero_id_session = session;
    zero_id_session.id = 0;
    try std.testing.expectError(error.EgressDenied, harness.encryptPacket(&zero_id_session, "bad session"));
    var denied_session = session;
    denied_session.egress_decision.allowed = false;
    try std.testing.expectError(error.EgressDenied, harness.encryptPacket(&denied_session, "bad session"));
    var invalid_source_session = session;
    invalid_source_session.source_device = app;
    try std.testing.expectError(error.EgressDenied, harness.encryptPacket(&invalid_source_session, "bad session"));

    var relay_queue = Relay.init();
    defer relay_queue.deinit();
    _ = try harness.sendRelayPacket(&relay_queue, &session, "relay op log");
    try std.testing.expectEqual(@as(usize, 1), relay_queue.queuedCount());
    var plaintext_buffer: [MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay_queue.deliverNext(&session, plaintext_buffer[0..])).?;
    try std.testing.expectEqualStrings("relay op log", delivered);
    try std.testing.expectEqual(@as(usize, 0), relay_queue.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), relay_queue.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), relay_queue.delivered_packets);

    const extra_packets = MAX_RELAY_PACKETS + 2;
    var packet_index: usize = 0;
    while (packet_index < extra_packets) : (packet_index += 1) {
        _ = try harness.sendRelayPacket(&relay_queue, &session, "x");
        const next = (try relay_queue.deliverNext(&session, plaintext_buffer[0..])).?;
        try std.testing.expectEqualStrings("x", next);
        try std.testing.expectEqual(@as(usize, 0), relay_queue.queuedCount());
    }
    try std.testing.expectEqual(@as(usize, 1 + extra_packets), relay_queue.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1 + extra_packets), relay_queue.delivered_packets);

    var exhausted_relay = Relay.init();
    defer exhausted_relay.deinit();
    try exhausted_relay.setNextPacketIdForTest(std.math.maxInt(u64));
    try exhausted_relay.submit(packet);
    try std.testing.expect(exhausted_relay.containsPacketId(std.math.maxInt(u64)));
    try std.testing.expectEqual(@as(u64, 0), exhausted_relay.nextPacketId());
    try std.testing.expectEqual(@as(usize, 1), exhausted_relay.accepted_packets);
    try std.testing.expectError(error.RelayPacketIdExhausted, exhausted_relay.submit(packet));
    try std.testing.expectEqual(@as(u64, 0), exhausted_relay.nextPacketId());
    try std.testing.expectEqual(@as(usize, 1), exhausted_relay.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), exhausted_relay.accepted_packets);

    var full_relay = Relay.init();
    defer full_relay.deinit();
    var full_index: usize = 0;
    while (full_index < MAX_RELAY_PACKETS) : (full_index += 1) {
        try full_relay.submit(packet);
    }
    const packet_id_before_full = full_relay.nextPacketId();
    try std.testing.expectError(error.RelayQueueFull, full_relay.submit(packet));
    try std.testing.expectEqual(packet_id_before_full, full_relay.nextPacketId());
    try std.testing.expectEqual(MAX_RELAY_PACKETS, full_relay.queuedCount());
    try std.testing.expectEqual(MAX_RELAY_PACKETS, full_relay.accepted_packets);

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

    var zero_task_request = relay_request;
    zero_task_request.task_id = 0;
    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, zero_task_request, source, target, "relay.sync.example"));
    var zero_policy_request = relay_request;
    zero_policy_request.policy_id = 0;
    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, zero_policy_request, source, target, "relay.sync.example"));
    var zero_capability_request = relay_request;
    zero_capability_request.capability_id = 0;
    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, zero_capability_request, source, target, "relay.sync.example"));

    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, relay_request, app, target, "relay.sync.example"));
    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, relay_request, source, .{ .kind = .device, .serial = 0 }, "relay.sync.example"));
    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, relay_request, source, source, "relay.sync.example"));
    const long_relay_domain = [_]u8{'r'} ** (network_policy.MAX_TARGET_BYTES + 1);
    try std.testing.expectError(error.RelayDomainTooLong, harness.openRelay(&broker, relay_request, source, target, &long_relay_domain));

    var wrapping_harness = Harness.init();
    wrapping_harness.next_session_id = std.math.maxInt(u64);
    const last_session = try wrapping_harness.openRelay(&broker, relay_request, source, target, "relay.sync.example");
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), last_session.id);
    try std.testing.expectEqual(@as(u64, 0), wrapping_harness.next_session_id);
    try std.testing.expectEqual(@as(usize, 1), wrapping_harness.created_sessions);
    try std.testing.expectError(
        error.TransportSessionIdExhausted,
        wrapping_harness.openRelay(&broker, relay_request, source, target, "relay.sync.example"),
    );
    try std.testing.expectEqual(@as(u64, 0), wrapping_harness.next_session_id);
    try std.testing.expectEqual(@as(usize, 1), wrapping_harness.created_sessions);
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
        .seed = signing.seedFromByte(0x42),
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
    defer relay_service.deinit();
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
    defer wrong_domain_service.deinit();
    const blocked_frame = try harness.encryptSignedFrame(&session, "blocked relay", signer_identity);
    try std.testing.expectError(error.EgressDenied, wrong_domain_service.submitSignedFrame(77, &session, blocked_frame));
    try std.testing.expectEqual(@as(usize, 0), wrong_domain_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), wrong_domain_service.rejected_packets);

    try std.testing.expectError(error.PacketEmpty, harness.encryptSignedFrame(&session, "", signer_identity));
    var empty_packet = signed_frame.packet;
    empty_packet.ciphertext_len = 0;
    try std.testing.expectError(error.PacketEmpty, relay_service.relay.submit(empty_packet));
    try std.testing.expectEqual(@as(usize, 0), relay_service.rejected_packets);

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
    const pinned_digest = crypto_hash.digestFromByte(0xA5);
    const request_digest = crypto_hash.digestFromByte(0xA6);
    const metadata_digest = crypto_hash.digestFromByte(0xA7);
    const local = try policies.create(.{
        .owner = owner,
        .label = "local-pinned",
        .mode = .local_network,
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
        .pinned_attestation_verifier_metadata_digest = metadata_digest,
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
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = metadata_digest,
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
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = metadata_digest,
        },
        .now_ticks = 5,
    }, source, target);
    try std.testing.expectEqual(sync_state.TransportMode.device_to_device, session.transport);
    try std.testing.expect(session.egress_decision.policy_decision.identity_pinned);
    try std.testing.expect(session.productionAttested());
    try session.requireProductionAttestation();
    try std.testing.expectEqual(SessionTrustPosture.production_attested, session.trust_posture);
    try std.testing.expect(session.peer_root_digest_present);
    try std.testing.expect(std.mem.eql(u8, &pinned_digest, &session.peer_root_digest));
    try std.testing.expect(session.attestation_verifier_metadata_digest_present);
    try std.testing.expect(session.attestation_verifier_metadata_digest_bound);
    try std.testing.expect(std.mem.eql(u8, &metadata_digest, &session.attestation_verifier_metadata_digest));

    const lab_relay = try policies.create(.{
        .owner = owner,
        .label = "lab-relay",
        .mode = .named_domain,
        .target = "relay.lab.sync",
    });
    const lab_relay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = lab_relay.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 43, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10 },
        .audit = .{},
    });
    const lab_session = try harness.openRelay(&broker, .{
        .task_id = 43,
        .principal_id = app,
        .capability_id = lab_relay_capability.id,
        .policy_id = lab_relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.lab.sync" } },
        .now_ticks = 5,
    }, source, target, "relay.lab.sync");
    try std.testing.expectEqual(SessionTrustPosture.local_lab_only, lab_session.trust_posture);
    try std.testing.expect(!lab_session.productionAttested());
    try std.testing.expectError(error.ProductionAttestationRequired, lab_session.requireProductionAttestation());
    try std.testing.expect(!std.mem.eql(u8, &session.key, &lab_session.key));

    const root_pinned_without_metadata_policy = try policies.create(.{
        .owner = owner,
        .label = "root-pinned-without-metadata",
        .mode = .local_network,
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
    });
    const root_only_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = root_pinned_without_metadata_policy.id },
        .rights = .{ .network_policy = .{ .network_local = true } },
        .scope = .{ .task_id = 43, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10 },
        .audit = .{},
    });
    const root_pinned_session = try harness.openDeviceToDevice(&broker, .{
        .task_id = 43,
        .principal_id = app,
        .capability_id = root_only_capability.id,
        .policy_id = root_pinned_without_metadata_policy.id,
        .evidence = .{
            .destination = .local_network,
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
        },
        .now_ticks = 5,
    }, source, target);
    try std.testing.expect(root_pinned_session.egress_decision.policy_decision.attestation_required);
    try std.testing.expect(root_pinned_session.egress_decision.policy_decision.identity_pinned);
    try std.testing.expectEqual(SessionTrustPosture.local_lab_only, root_pinned_session.trust_posture);
    try std.testing.expect(!root_pinned_session.productionAttested());
    try std.testing.expectError(error.ProductionAttestationRequired, root_pinned_session.requireProductionAttestation());
    try std.testing.expect(!std.mem.eql(u8, &session.key, &root_pinned_session.key));

    const retargeted = try harness.openDeviceToDevice(&broker, .{
        .task_id = 43,
        .principal_id = app,
        .capability_id = local_capability.id,
        .policy_id = local.id,
        .evidence = .{
            .destination = .local_network,
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = metadata_digest,
        },
        .now_ticks = 5,
    }, source, other_target);
    try std.testing.expect(!std.mem.eql(u8, &session.key, &retargeted.key));

    const packet = try harness.encryptPacket(&session, "local sync");
    try std.testing.expect(packet.encrypted);
    try std.testing.expectEqual(source, packet.source_device);
    try std.testing.expectEqual(target, packet.target_device);

    var plaintext_buffer: [MAX_PACKET_BYTES]u8 = undefined;
    var forged_packet = packet;
    forged_packet.session_id += 1;
    try std.testing.expectError(error.PacketTargetMismatch, decryptForSession(&session, forged_packet, plaintext_buffer[0..]));
    forged_packet = packet;
    forged_packet.transport = .relay_assisted;
    try std.testing.expectError(error.PacketTargetMismatch, decryptForSession(&session, forged_packet, plaintext_buffer[0..]));
    forged_packet = packet;
    forged_packet.policy_id += 1;
    try std.testing.expectError(error.PacketTargetMismatch, decryptForSession(&session, forged_packet, plaintext_buffer[0..]));
    forged_packet = packet;
    forged_packet.capability_id += 1;
    try std.testing.expectError(error.PacketTargetMismatch, decryptForSession(&session, forged_packet, plaintext_buffer[0..]));
    forged_packet = packet;
    forged_packet.source_device = other_target;
    try std.testing.expectError(error.PacketTargetMismatch, decryptForSession(&session, forged_packet, plaintext_buffer[0..]));
    forged_packet = packet;
    forged_packet.encrypted = false;
    try std.testing.expectError(error.EgressDenied, decryptForSession(&session, forged_packet, plaintext_buffer[0..]));
    forged_packet = packet;
    forged_packet.ciphertext_len = MAX_PACKET_BYTES + 1;
    try std.testing.expectError(error.PacketTooLarge, decryptForSession(&session, forged_packet, plaintext_buffer[0..]));

    try std.testing.expectEqual(@as(usize, 4), harness.created_sessions);
    try std.testing.expectEqual(@as(usize, 1), harness.denied_sessions);
}

test "emulated native transport denies service identity before packet transmission" {
    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 5 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 6 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 30 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 31 };
    const pinned_digest = crypto_hash.digestFromByte(0xC1);
    const wrong_digest = crypto_hash.digestFromByte(0xC2);
    const request_digest = crypto_hash.digestFromByte(0xC3);
    const metadata_digest = crypto_hash.digestFromByte(0xC4);

    const overlay = try policies.create(.{
        .owner = owner,
        .label = "notes-service",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
        .pinned_attestation_verifier_metadata_digest = metadata_digest,
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
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = wrong_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = metadata_digest,
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
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = metadata_digest,
        },
        .now_ticks = 5,
    }, source, target);
    try std.testing.expect(session.egress_decision.policy_decision.attestation_required);
    try std.testing.expect(session.egress_decision.policy_decision.identity_pinned);
    try std.testing.expectEqual(SessionTrustPosture.production_attested, session.trust_posture);
    try std.testing.expect(session.productionAttested());
    try session.requireProductionAttestation();
    try std.testing.expect(session.peer_root_digest_present);
    try std.testing.expect(std.mem.eql(u8, &pinned_digest, &session.peer_root_digest));
    try std.testing.expect(session.attestation_verifier_metadata_digest_present);
    try std.testing.expect(session.attestation_verifier_metadata_digest_bound);
    try std.testing.expect(std.mem.eql(u8, &metadata_digest, &session.attestation_verifier_metadata_digest));

    const packet = try transport.send(&session, "attested payload");
    try std.testing.expect(packet.encrypted);
    try std.testing.expect(packet.egress_allowed);
    try std.testing.expect(!std.mem.eql(u8, packet.ciphertextSlice(), "attested payload"));
    try std.testing.expectEqual(@as(usize, 3), transport.attempted_connections);
    try std.testing.expectEqual(@as(usize, 2), transport.denied_before_transmit);
    try std.testing.expectEqual(@as(usize, 1), transport.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 1), transport.harness.created_sessions);
}

test "compact relay metadata preserves exact packet and domain capacities" {
    try std.testing.expect(relay_queue_layout.heap_backs_queue_on_freestanding);
    try std.testing.expectEqual(@sizeOf(?*anyopaque), relay_queue_layout.freestanding_handle_size_bytes);
    try std.testing.expectEqual(@as(usize, 7_000), relay_queue_layout.backing_size_bytes);
    try std.testing.expectEqual(@as(usize, 6_992), relay_queue_layout.freestanding_resident_savings_bytes);
    try std.testing.expect(relay_queue_layout.uses_packet_arena);
    try std.testing.expect(relay_queue_layout.uses_session_index);
    try std.testing.expectEqual(@as(usize, RELAY_SIZE_CEILING_BYTES), @sizeOf(Relay));
    try std.testing.expectEqual(@as(usize, BOOTED_RELAY_SERVICE_SIZE_CEILING_BYTES), @sizeOf(BootedOverlayRelayService));

    const packet_bytes = [_]u8{0xA5} ** MAX_PACKET_BYTES;
    var packet = std.mem.zeroes(EncryptedPacket);
    packet.ciphertext_len = @intCast(packet_bytes.len);
    @memcpy(&packet.ciphertext, &packet_bytes);
    try std.testing.expectEqualSlices(u8, &packet_bytes, packet.ciphertextSlice());

    const relay_domain = [_]u8{'r'} ** network_policy.MAX_TARGET_BYTES;
    const service = try BootedOverlayRelayService.init(1, 2, &relay_domain);
    try std.testing.expectEqual(@as(u8, network_policy.MAX_TARGET_BYTES), service.relay_domain_len);
    try std.testing.expectEqualSlices(u8, &relay_domain, service.relayDomainSlice());

    var session = std.mem.zeroes(TransportSession);
    session.relay_domain_len = @intCast(relay_domain.len);
    @memcpy(&session.relay_domain, &relay_domain);
    try std.testing.expectEqualSlices(u8, &relay_domain, session.relayDomainSlice());
}
