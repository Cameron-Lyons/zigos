const std = @import("std");
const attestation_service = @import("../platform/attestation_service.zig");
const binary_cursor = @import("binary_cursor");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const network_policy = @import("../sync/network_policy.zig");
const signing = @import("../core/signing.zig");

pub const NetworkDevice = struct {
    send: *const fn (data: []const u8) bool,
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
const SERVICE_IDENTITY_FRAME_MAGIC = "ZGNI";
const DISCOVERY_FRAME_MAGIC = "ZGND";
const NativeFrameWriter = binary_cursor.Writer(Error, error.PayloadTooLarge);

pub const Error = error{
    EgressDenied,
    TransmitFailed,
    PayloadTooLarge,
    ServiceIdentityTooLong,
    DiscoveryClassTooLong,
};

pub const NativeServiceIdentityConnection = struct {
    id: u64,
    task_id: u64,
    principal_id: principal.PrincipalId,
    policy_id: u64,
    capability_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    source_mac: [6]u8,
    service_identity_len: usize = 0,
    service_identity: [network_policy.MAX_TARGET_BYTES]u8 = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
    peer_root_digest: crypto_hash.Digest,
    attestation_request_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    attestation_verifier_metadata_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    key: crypto_hash.Digest,
    attested: bool,
    verified_remote_attestation: bool,
    peer_root_digest_present: bool,
    attestation_request_digest_present: bool,
    attestation_verifier_metadata_digest_present: bool,
    attestation_verifier_metadata_digest_bound: bool,
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
    payload_digest: crypto_hash.Digest,
    peer_root_digest: crypto_hash.Digest,
    encrypted: bool,
    egress_allowed: bool,
    attested: bool,
    verified_remote_attestation: bool,
    identity_pinned: bool,
    attestation_request_digest_present: bool,
    attestation_request_digest: crypto_hash.Digest,
    attestation_verifier_metadata_digest_present: bool,
    attestation_verifier_metadata_digest_bound: bool,
    attestation_verifier_metadata_digest: crypto_hash.Digest,

    pub fn ciphertextSlice(self: *const NativeServiceIdentityFrame) []const u8 {
        return self.ciphertext[0..self.payload_len];
    }
};

pub const NativeLocalDiscoveryConnection = struct {
    id: u64,
    task_id: u64,
    principal_id: principal.PrincipalId,
    policy_id: u64,
    capability_id: u64,
    source_device: principal.PrincipalId,
    source_mac: [6]u8,
    discovery_class_len: usize = 0,
    discovery_class: [network_policy.MAX_TARGET_BYTES]u8 = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
    key: crypto_hash.Digest,
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
    probe_digest: crypto_hash.Digest,
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
            .task_id = request.task_id,
            .principal_id = request.principal_id,
            .policy_id = request.policy_id,
            .capability_id = request.capability_id,
            .source_device = source_device,
            .target_device = target_device,
            .source_mac = device.getMacAddress(),
            .peer_root_digest = request.evidence.peer_root_digest,
            .attestation_request_digest = request.evidence.attestation_request_digest,
            .attestation_verifier_metadata_digest = request.evidence.attestation_verifier_metadata_digest,
            .key = undefined,
            .attested = request.evidence.attested,
            .verified_remote_attestation = request.evidence.verified_remote_attestation,
            .peer_root_digest_present = request.evidence.peer_root_digest_present,
            .attestation_request_digest_present = request.evidence.attestation_request_digest_present,
            .attestation_verifier_metadata_digest_present = request.evidence.attestation_verifier_metadata_digest_present,
            .attestation_verifier_metadata_digest_bound = request.evidence.attestation_verifier_metadata_digest_bound,
            .attestation_required = decision.policy_decision.attestation_required,
            .identity_pinned = decision.policy_decision.identity_pinned,
            .egress_decision = decision,
        };
        connection.service_identity_len = native_util.copyTextExact(&connection.service_identity, service_identity) catch return error.ServiceIdentityTooLong;
        connection.key = nativeConnectionKey(&connection);
        self.opened_connections += 1;
        return connection;
    }

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

    pub fn openVerifiedServiceIdentity(
        self: *NativeNetworkStack,
        broker: *network_policy.EgressBroker,
        request: VerifiedServiceIdentityOpenRequest,
        source_device: principal.PrincipalId,
        target_device: principal.PrincipalId,
    ) Error!NativeServiceIdentityConnection {
        const evidence = network_policy.ConnectionEvidence.fromVerifiedRemoteAttestation(
            .{ .service_identity = request.service_identity },
            request.attestation_response,
            request.attestation_request,
            request.attested_boot,
            request.trusted_root,
        ) orelse {
            self.attempted_connections += 1;
            return self.denyOpen(.attestation_required);
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
            .task_id = request.task_id,
            .principal_id = request.principal_id,
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
            .verified_remote_attestation = connection.verified_remote_attestation,
            .identity_pinned = connection.identity_pinned,
            .attestation_request_digest_present = connection.attestation_request_digest_present,
            .attestation_request_digest = connection.attestation_request_digest,
            .attestation_verifier_metadata_digest_present = connection.attestation_verifier_metadata_digest_present,
            .attestation_verifier_metadata_digest_bound = connection.attestation_verifier_metadata_digest_bound,
            .attestation_verifier_metadata_digest = connection.attestation_verifier_metadata_digest,
        };
        applyModeledKeystream(&frame.ciphertext, payload, &connection.key);

        var wire_frame: [MAX_NATIVE_FRAME_BYTES]u8 = undefined;
        const encoded = try encodeNativeFrame(wire_frame[0..], connection, &frame);
        if (!device.send(encoded)) return error.TransmitFailed;
        self.transmitted_packets += 1;
        return frame;
    }

    pub fn sendServiceIdentityFrameBrokered(
        self: *NativeNetworkStack,
        broker: *network_policy.EgressBroker,
        connection: *const NativeServiceIdentityConnection,
        payload: []const u8,
        now_ticks: u64,
    ) Error!NativeServiceIdentityFrame {
        const decision = broker.connect(.{
            .task_id = connection.task_id,
            .principal_id = connection.principal_id,
            .capability_id = connection.capability_id,
            .policy_id = connection.policy_id,
            .evidence = .{
                .destination = .{ .service_identity = connection.serviceIdentitySlice() },
                .attested = connection.attested,
                .verified_remote_attestation = connection.verified_remote_attestation,
                .attestation_request_digest_present = connection.attestation_request_digest_present,
                .attestation_request_digest = connection.attestation_request_digest,
                .peer_root_digest_present = connection.peer_root_digest_present,
                .peer_root_digest = connection.peer_root_digest,
                .attestation_verifier_metadata_digest_present = connection.attestation_verifier_metadata_digest_present,
                .attestation_verifier_metadata_digest_bound = connection.attestation_verifier_metadata_digest_bound,
                .attestation_verifier_metadata_digest = connection.attestation_verifier_metadata_digest,
            },
            .now_ticks = now_ticks,
        }) catch return self.denySend(.policy_denied);
        if (!decision.allowed) return self.denySend(decision.reason);

        return self.sendServiceIdentityFrame(connection, payload);
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
        applyModeledKeystream(&frame.ciphertext, payload, &connection.key);

        var wire_frame: [MAX_NATIVE_FRAME_BYTES]u8 = undefined;
        const encoded = try encodeDiscoveryFrame(wire_frame[0..], connection, &frame);
        if (!device.send(encoded)) return error.TransmitFailed;
        self.transmitted_packets += 1;
        return frame;
    }

    pub fn sendLocalDiscoveryProbeBrokered(
        self: *NativeNetworkStack,
        broker: *network_policy.EgressBroker,
        connection: *const NativeLocalDiscoveryConnection,
        payload: []const u8,
        now_ticks: u64,
    ) Error!NativeLocalDiscoveryFrame {
        const decision = broker.connect(.{
            .task_id = connection.task_id,
            .principal_id = connection.principal_id,
            .capability_id = connection.capability_id,
            .policy_id = connection.policy_id,
            .evidence = .{ .destination = .{ .discovery_class = connection.discoveryClassSlice() } },
            .now_ticks = now_ticks,
        }) catch return self.denySend(.policy_denied);
        if (!decision.allowed) return self.denySend(decision.reason);

        return self.sendLocalDiscoveryProbe(connection, payload);
    }

    fn denyOpen(self: *NativeNetworkStack, reason: network_policy.EgressDecisionReason) Error {
        self.denied_before_transmit += 1;
        self.last_denial_reason = reason;
        return error.EgressDenied;
    }

    fn denySend(self: *NativeNetworkStack, reason: network_policy.EgressDecisionReason) Error {
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
var active_driver_tx_count: usize = 0;
var last_active_driver_frame_len: usize = 0;
var last_active_driver_frame: [MAX_NATIVE_FRAME_BYTES]u8 = [_]u8{0} ** MAX_NATIVE_FRAME_BYTES;

pub fn reset() void {
    active_device = null;
    active_service_id = 0;
    egress_broker = null;
    active_egress_capability_id = 0;
    active_network_policy_id = 0;
    clearTransmitTelemetry();
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

pub fn clearTransmitTelemetry() void {
    active_driver_tx_count = 0;
    last_active_driver_frame_len = 0;
    @memset(last_active_driver_frame[0..], 0);
}

pub fn activeDriverTransmitCount() usize {
    return active_driver_tx_count;
}

pub fn lastActiveDriverFrame() []const u8 {
    return last_active_driver_frame[0..last_active_driver_frame_len];
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
    if (frame.len > last_active_driver_frame.len) return false;
    if (!authorizeDriverTx(frame)) return false;
    const device = active_device orelse return false;
    if (!device.send(frame)) return false;
    active_driver_tx_count += 1;
    last_active_driver_frame_len = frame.len;
    @memcpy(last_active_driver_frame[0..frame.len], frame);
    return true;
}

fn nativeConnectionKey(connection: *const NativeServiceIdentityConnection) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "connection", connection.id);
    crypto_hash.updateInt(&hasher, "policy", connection.policy_id);
    crypto_hash.updateInt(&hasher, "capability", connection.capability_id);
    updatePrincipal(&hasher, "source", connection.source_device);
    updatePrincipal(&hasher, "target", connection.target_device);
    crypto_hash.updateBytes(&hasher, "source-mac", &connection.source_mac);
    crypto_hash.updateBytes(&hasher, "service-identity", connection.serviceIdentitySlice());
    crypto_hash.updateBytes(&hasher, "peer-root", &connection.peer_root_digest);
    crypto_hash.updateBool(&hasher, "verified-attestation", connection.verified_remote_attestation);
    crypto_hash.updateBool(&hasher, "attestation-request-digest-present", connection.attestation_request_digest_present);
    if (connection.attestation_request_digest_present) {
        crypto_hash.updateBytes(&hasher, "attestation-request-digest", &connection.attestation_request_digest);
    }
    crypto_hash.updateBool(&hasher, "attestation-verifier-metadata-digest-present", connection.attestation_verifier_metadata_digest_present);
    if (connection.attestation_verifier_metadata_digest_present) {
        crypto_hash.updateBool(&hasher, "attestation-verifier-metadata-digest-bound", connection.attestation_verifier_metadata_digest_bound);
        crypto_hash.updateBytes(&hasher, "attestation-verifier-metadata-digest", &connection.attestation_verifier_metadata_digest);
    }
    return crypto_hash.finalize(&hasher);
}

fn nativePayloadDigest(connection: *const NativeServiceIdentityConnection, payload: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "key", &connection.key);
    crypto_hash.updateBytes(&hasher, "payload", payload);
    return crypto_hash.finalize(&hasher);
}

fn nativeDiscoveryKey(connection: *const NativeLocalDiscoveryConnection) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "connection", connection.id);
    crypto_hash.updateInt(&hasher, "policy", connection.policy_id);
    crypto_hash.updateInt(&hasher, "capability", connection.capability_id);
    updatePrincipal(&hasher, "source", connection.source_device);
    crypto_hash.updateBytes(&hasher, "source-mac", &connection.source_mac);
    crypto_hash.updateBytes(&hasher, "discovery-class", connection.discoveryClassSlice());
    return crypto_hash.finalize(&hasher);
}

fn nativeDiscoveryDigest(connection: *const NativeLocalDiscoveryConnection, payload: []const u8) crypto_hash.Digest {
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
    return encodeWireFrame(
        buffer,
        SERVICE_IDENTITY_FRAME_MAGIC,
        frame.connection_id,
        frame.policy_id,
        frame.capability_id,
        &connection.source_mac,
        connection.serviceIdentitySlice(),
        frame.ciphertextSlice(),
        &frame.payload_digest,
    );
}

fn encodeDiscoveryFrame(
    buffer: []u8,
    connection: *const NativeLocalDiscoveryConnection,
    frame: *const NativeLocalDiscoveryFrame,
) Error![]const u8 {
    return encodeWireFrame(
        buffer,
        DISCOVERY_FRAME_MAGIC,
        frame.connection_id,
        frame.policy_id,
        frame.capability_id,
        &connection.source_mac,
        connection.discoveryClassSlice(),
        frame.ciphertextSlice(),
        &frame.probe_digest,
    );
}

/// Both native wire frames share one layout: magic, three u64 ids, source
/// MAC, length-prefixed class/identity, length-prefixed ciphertext, digest.
fn encodeWireFrame(
    buffer: []u8,
    magic: []const u8,
    connection_id: u64,
    policy_id: u64,
    capability_id: u64,
    source_mac: []const u8,
    label: []const u8,
    ciphertext: []const u8,
    digest: []const u8,
) Error![]const u8 {
    if (label.len > std.math.maxInt(u8) or ciphertext.len > std.math.maxInt(u8)) return error.PayloadTooLarge;
    const required_len = magic.len + (3 * @sizeOf(u64)) + source_mac.len + 1 + label.len + 1 + ciphertext.len + digest.len;
    if (buffer.len < required_len) return error.PayloadTooLarge;

    var writer = NativeFrameWriter{ .buffer = buffer };
    try writer.writeBytes(magic);
    try writer.writeU64(connection_id);
    try writer.writeU64(policy_id);
    try writer.writeU64(capability_id);
    try writer.writeBytes(source_mac);
    try writer.writeByte(@intCast(label.len));
    try writer.writeBytes(label);
    try writer.writeByte(@intCast(ciphertext.len));
    try writer.writeBytes(ciphertext);
    try writer.writeBytes(digest);
    return buffer[0..writer.offset];
}

/// Modeled confidentiality only: a repeating-key XOR keystream stands in for
/// a real AEAD in the proof environment. It provides no secrecy against a
/// known-plaintext observer and must be replaced before any real network
/// payload depends on the frame's `encrypted` flag.
fn applyModeledKeystream(
    ciphertext: *[MAX_NATIVE_PAYLOAD_BYTES]u8,
    payload: []const u8,
    key: *const crypto_hash.Digest,
) void {
    for (payload, 0..) |byte, index| {
        ciphertext[index] = byte ^ key[index % key.len];
    }
}

fn updatePrincipal(hasher: *crypto_hash.Hasher, tag: []const u8, value: principal.PrincipalId) void {
    const bytes = value.keyBytes();
    crypto_hash.updateBytes(hasher, tag, &bytes);
}

fn verifiedDriverPeerBoot(generation: u64) !measured_boot.BootRecord {
    var recorder = measured_boot.Recorder.init();
    var artifact_manifest = measured_boot.ArtifactManifest.init(generation);
    recorder.begin(generation);
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos-network-driver", "kernel=v1");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .base_image, "stable-network-driver", "image=v1");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "compositor", "healthy");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .policy, "native-network-policy", "strict");
    try measured_boot.addMeasuredArtifact(&recorder, &artifact_manifest, .driver_set, "native-network-driver-set", "i225");
    var boot = recorder.finalize();
    try measured_boot.verifyBootRecordAgainstManifest(&boot, &artifact_manifest, .bootloader_provided);
    return boot;
}

test "network driver data plane is brokered by explicit egress capability" {
    const Harness = struct {
        var send_count: usize = 0;

        fn send(_: []const u8) bool {
            send_count += 1;
            return true;
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
    try std.testing.expectEqual(@as(usize, 1), activeDriverTransmitCount());
    try std.testing.expectEqualStrings("frame", lastActiveDriverFrame());
    clearTransmitTelemetry();
    try std.testing.expectEqual(@as(usize, 0), activeDriverTransmitCount());
    try std.testing.expectEqual(@as(usize, 0), lastActiveDriverFrame().len);
}

test "network transmit failure is reported without advancing ownership telemetry" {
    const Harness = struct {
        fn send(_: []const u8) bool {
            return false;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 2 };
        }

        fn broker(_: EgressRequest) EgressDecision {
            return .{ .allowed = true, .capability_backed = true };
        }
    };

    reset();
    defer reset();
    const device = NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(activateDevice(&device, 8));
    setEgressBroker(Harness.broker);
    bindEgressCapability(100, 42);
    try std.testing.expect(!sendActiveFrame("frame"));
    try std.testing.expectEqual(@as(usize, 0), activeDriverTransmitCount());
    try std.testing.expectEqual(@as(usize, 0), lastActiveDriverFrame().len);
}

test "native network stack gates service identity packets on attested policy capability" {
    const Harness = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;

        fn send(frame: []const u8) bool {
            send_count += 1;
            last_frame_len = frame.len;
            return true;
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
    const peer_attestation_signer = signing.SignerIdentity{
        .label = "native-network-peer-root",
        .seed = signing.seedFromByte(0xA1),
    };
    const peer_attestation_identity = try signing.publicIdentity(peer_attestation_signer);
    const peer_attestation_key = attestation_service.AttestationRootKeyHandle{
        .key_id = "native-network-peer-root",
        .label = "native-network-peer-root",
        .public_identity = peer_attestation_identity,
        .generation = 1,
        .origin = .tpm,
        .provider_boundary = .platform_tpm,
        .custody = .tpm,
    };
    const peer_attestation_descriptor = attestation_service.RootProviderDescriptor{
        .name = "native-network-tpm-attestation-root",
        .role = .production,
        .origin = .tpm,
        .key_id = "native-network-peer-root",
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
    const peer_boot = try verifiedDriverPeerBoot(70);
    const peer_attestation_request = try attestation_service.RemoteAttestationRequest.init(.{
        .remote_party = "overlay.native.identity",
        .nonce = "native-network-verified-0001",
        .policy_label = "native-service-identity",
        .expected_key_origin = .tpm,
        .root_key_id = "native-network-peer-root",
        .minimum_root_generation = 1,
        .attestation_verifier_metadata_digest_required = true,
        .attestation_verifier_metadata_digest = peer_attestation_metadata_digest,
    });
    const peer_attestation_response = try peer_attestation.respondToRemoteAttestationRequest(peer_boot, peer_attestation_request);
    const pinned_digest = peer_attestation_response.statement.root_digest;
    const request_digest = peer_attestation_response.request_digest;
    var wrong_digest = pinned_digest;
    wrong_digest[0] ^= 0xFF;

    const policy = try policies.create(.{
        .owner = service_owner,
        .label = "native-service-identity",
        .mode = .named_service_identity,
        .target = "overlay.native.identity",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
        .pinned_attestation_verifier_metadata_digest = peer_attestation_metadata_digest,
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
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = peer_attestation_metadata_digest,
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
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = wrong_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = peer_attestation_metadata_digest,
        },
        .now_ticks = 10,
    }, source, target));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.identity_pin_mismatch, stack.last_denial_reason);
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    try std.testing.expectError(error.EgressDenied, stack.openVerifiedServiceIdentity(&broker, .{
        .task_id = 70,
        .principal_id = service_owner,
        .capability_id = policy_capability.id,
        .policy_id = policy.id,
        .service_identity = "overlay.other.identity",
        .attestation_response = peer_attestation_response,
        .attestation_request = peer_attestation_request,
        .attested_boot = &peer_boot,
        .trusted_root = peer_attestation_identity,
        .now_ticks = 10,
    }, source, target));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.attestation_required, stack.last_denial_reason);

    const connection = try stack.openVerifiedServiceIdentity(&broker, .{
        .task_id = 70,
        .principal_id = service_owner,
        .capability_id = policy_capability.id,
        .policy_id = policy.id,
        .service_identity = "overlay.native.identity",
        .attestation_response = peer_attestation_response,
        .attestation_request = peer_attestation_request,
        .attested_boot = &peer_boot,
        .trusted_root = peer_attestation_identity,
        .now_ticks = 10,
    }, source, target);
    try std.testing.expect(connection.attestation_required);
    try std.testing.expect(connection.identity_pinned);
    try std.testing.expect(connection.verified_remote_attestation);
    try std.testing.expect(connection.attestation_request_digest_present);
    try std.testing.expect(std.mem.eql(u8, &request_digest, &connection.attestation_request_digest));
    try std.testing.expect(connection.attestation_verifier_metadata_digest_present);
    try std.testing.expect(connection.attestation_verifier_metadata_digest_bound);
    try std.testing.expect(std.mem.eql(u8, &peer_attestation_metadata_digest, &connection.attestation_verifier_metadata_digest));

    const frame = try stack.sendServiceIdentityFrame(&connection, "native payload");
    try std.testing.expect(frame.encrypted);
    try std.testing.expect(frame.egress_allowed);
    try std.testing.expect(frame.attested);
    try std.testing.expect(frame.verified_remote_attestation);
    try std.testing.expect(frame.attestation_request_digest_present);
    try std.testing.expect(std.mem.eql(u8, &request_digest, &frame.attestation_request_digest));
    try std.testing.expect(frame.attestation_verifier_metadata_digest_present);
    try std.testing.expect(frame.attestation_verifier_metadata_digest_bound);
    try std.testing.expect(std.mem.eql(u8, &peer_attestation_metadata_digest, &frame.attestation_verifier_metadata_digest));
    try std.testing.expect(frame.identity_pinned);
    try std.testing.expect(!std.mem.eql(u8, frame.ciphertextSlice(), "native payload"));
    try std.testing.expectEqual(@as(usize, 5), stack.attempted_connections);
    try std.testing.expectEqual(@as(usize, 4), stack.denied_before_transmit);
    try std.testing.expectEqual(@as(usize, 1), stack.opened_connections);
    try std.testing.expectEqual(@as(usize, 1), stack.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
    try std.testing.expect(Harness.last_frame_len > "native payload".len);

    const brokered_frame = try stack.sendServiceIdentityFrameBrokered(&broker, &connection, "native brokered payload", 11);
    try std.testing.expect(brokered_frame.verified_remote_attestation);
    try std.testing.expect(brokered_frame.attestation_request_digest_present);
    try std.testing.expect(std.mem.eql(u8, &request_digest, &brokered_frame.attestation_request_digest));
    try std.testing.expect(brokered_frame.attestation_verifier_metadata_digest_present);
    try std.testing.expect(brokered_frame.attestation_verifier_metadata_digest_bound);
    try std.testing.expect(std.mem.eql(u8, &peer_attestation_metadata_digest, &brokered_frame.attestation_verifier_metadata_digest));
    try std.testing.expectEqual(@as(usize, 2), stack.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 2), Harness.send_count);
}

test "native network stack requires scoped local discovery before discovery broadcast" {
    const Harness = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;

        fn send(frame: []const u8) bool {
            send_count += 1;
            last_frame_len = frame.len;
            return true;
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
