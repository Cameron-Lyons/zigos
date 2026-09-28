//! Bounded authenticated datagrams for an explicitly enrolled device pair.
//! Noise XX carries device-signed certificates for fresh, separate X25519 keys.
//! This authenticates a peer, not an object operation or an attestation claim.
const std = @import("std");
const noise = @import("../core/noise_xx.zig");
const graph_mod = @import("device_graph.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sealed = @import("../services/sealed_signing_key.zig");
const Hash = std.crypto.hash.sha2.Sha256;
const Ed = std.crypto.sign.Ed25519;
pub const MAGIC = "ZGNP";
pub const VERSION: u8 = 1;
pub const MAX_FRAME = 256;
pub const HEADER = 22;
pub const DATA_HEADER = HEADER + 16 + 8;
pub const MAX_PAYLOAD = MAX_FRAME - DATA_HEADER - 16;
pub const Error = noise.Error || graph_mod.Error || sealed.Error || error{ PeerMismatch, IdentityMismatch, MalformedFrame, ReplayRejected, TrustChanged };

const Crypto = union(enum) { closed, handshake: noise.Handshake, transport: noise.Split };

// Borrows a stable, serialized graph. The root pin is supplied independently by
// enrollment; network inputs cannot choose a root, device key or graph record.
pub const Channel = struct {
    graph: *const graph_mod.Graph,
    root_pin: signing.PublicKey,
    context: [32]u8,
    signer: sealed.Key = .{},
    certificate: [64]u8,
    local: u64,
    remote: u64,
    role: noise.Role,
    crypto: Crypto,
    receive_highest: u64 = 0,
    receive_bitmap: u64 = 0,

    pub fn init(graph: *const graph_mod.Graph, root_pin: signing.PublicKey, local: principal.PrincipalId, remote: principal.PrincipalId, signer: sealed.Key, role: noise.Role, now_ticks: u64) Error!Channel {
        try signer.validate(now_ticks);
        const record = try graph.authenticatedDevice(local, root_pin);
        if (!record.owner.eql(signer.authority.?.owner)) return error.DeviceOwnerMismatch;
        return initImpl(graph, root_pin, local, remote, signer, role, now_ticks);
    }

    pub fn initForVerification(graph: *const graph_mod.Graph, root_pin: signing.PublicKey, local: principal.PrincipalId, remote: principal.PrincipalId, signer: signing.SignerIdentity, role: noise.Role) Error!Channel {
        if (comptime @import("builtin").os.tag == .freestanding) {
            if (comptime !@import("../../kernel/config.zig").includesVerificationEvidence()) return error.SealedSigningKeyRequired;
        }
        return initImpl(graph, root_pin, local, remote, signer, role, 0);
    }

    fn initImpl(graph: *const graph_mod.Graph, root_pin: signing.PublicKey, local: principal.PrincipalId, remote: principal.PrincipalId, signer: anytype, role: noise.Role, now_ticks: u64) Error!Channel {
        if (local.kind != .device or remote.kind != .device or local.serial == remote.serial) return error.PeerMismatch;
        const local_record = try graph.authenticatedDevice(local, root_pin);
        const remote_record = try graph.authenticatedDevice(remote, root_pin);
        if (!local_record.owner.eql(remote_record.owner)) return error.DeviceOwnerMismatch;
        const context = try contextFor(graph, root_pin, local.serial, remote.serial, role);
        var handshake = try noise.Handshake.init(role, &context);
        defer handshake.deinit();
        const digest = certificateDigest(context, handshake.local_static.public_key);
        const certificate = if (@TypeOf(signer) == sealed.Key)
            try signer.signMessage(&digest, now_ticks)
        else
            signing.sign(signer, &digest) catch return error.IdentityMismatch;
        if (!std.mem.eql(u8, certificate.publicKeySlice(), &local_record.device_signature.public_key)) return error.IdentityMismatch;
        return .{
            .graph = graph,
            .root_pin = root_pin,
            .local = local.serial,
            .remote = remote.serial,
            .context = context,
            .signer = if (@TypeOf(signer) == sealed.Key) signer else .{},
            .certificate = certificate.value,
            .role = role,
            .crypto = .{ .handshake = handshake },
        };
    }

    pub fn established(self: *const Channel) bool {
        return self.crypto == .transport;
    }

    pub fn validate(self: *Channel, now_ticks: u64) Error!void {
        try self.requireTrust(now_ticks);
    }

    pub fn writeHandshake(self: *Channel, output: []u8, now_ticks: u64) Error![]const u8 {
        errdefer self.close();
        errdefer std.crypto.secureZero(u8, output[0..@min(output.len, MAX_FRAME)]);
        try self.requireTrust(now_ticks);
        if (self.crypto != .handshake) return error.InvalidState;
        const state = &self.crypto.handshake;
        if (output.len < MAX_FRAME) return error.InvalidLength;
        writeHeader(output[0..HEADER], state.step + 1, self.local, self.remote);
        const payload: []const u8 = if (state.step == 0) "" else &self.certificate;
        const message = try state.write(output[HEADER..MAX_FRAME], payload);
        if (state.step == 3) try self.finish();
        return output[0 .. HEADER + message.len];
    }

    pub fn readHandshake(self: *Channel, frame: []const u8, now_ticks: u64) Error!void {
        errdefer self.close();
        try self.requireTrust(now_ticks);
        if (self.crypto != .handshake) return error.InvalidState;
        const state = &self.crypto.handshake;
        try self.validateHeader(frame, state.step + 1);
        var payload: [noise.MAX_PAYLOAD]u8 = undefined;
        defer std.crypto.secureZero(u8, &payload);
        const first = state.step == 0;
        const certificate = try state.read(&payload, frame[HEADER..]);
        if (first) {
            if (certificate.len != 0) return error.MalformedFrame;
        } else {
            if (certificate.len != 64) return error.IdentityMismatch;
            const digest = certificateDigest(self.context, state.remote_static);
            const peer = self.graph.findDeviceConst(.{ .kind = .device, .serial = self.remote }) orelse return error.DeviceNotFound;
            const public = Ed.PublicKey.fromBytes(peer.device_signature.public_key) catch return error.IdentityMismatch;
            Ed.Signature.fromBytes(certificate[0..64].*).verify(&digest, public) catch return error.IdentityMismatch;
        }
        if (state.step == 3) try self.finish();
    }

    pub fn seal(self: *Channel, output: []u8, payload: []const u8, now_ticks: u64) Error![]const u8 {
        errdefer std.crypto.secureZero(u8, output[0..@min(output.len, MAX_FRAME)]);
        try self.requireTrust(now_ticks);
        if (self.crypto != .transport) return error.InvalidState;
        if (payload.len == 0 or payload.len > MAX_PAYLOAD or output.len < DATA_HEADER + payload.len + 16) return error.InvalidLength;
        const state = &self.crypto.transport;
        if (state.send.nonce == std.math.maxInt(u64)) {
            self.close();
            return error.NonceExhausted;
        }
        writeHeader(output[0..HEADER], 4, self.local, self.remote);
        @memcpy(output[HEADER..][0..16], state.hash[0..16]);
        std.mem.writeInt(u64, output[HEADER + 16 ..][0..8], state.send.nonce, .little);
        const ciphertext = try state.send.seal(output[DATA_HEADER..], payload, output[0..DATA_HEADER]);
        return output[0 .. DATA_HEADER + ciphertext.len];
    }

    pub fn open(self: *Channel, output: []u8, frame: []const u8, now_ticks: u64) Error![]const u8 {
        errdefer std.crypto.secureZero(u8, output[0..@min(output.len, MAX_PAYLOAD)]);
        try self.requireTrust(now_ticks);
        if (self.crypto != .transport) return error.InvalidState;
        try self.validateHeader(frame, 4);
        if (frame.len <= DATA_HEADER + 16) return error.MalformedFrame;
        const state = &self.crypto.transport;
        if (!std.crypto.timing_safe.eql([16]u8, state.hash[0..16].*, frame[HEADER..][0..16].*)) return error.PeerMismatch;
        const nonce = std.mem.readInt(u64, frame[HEADER + 16 ..][0..8], .little);
        try self.checkReplay(nonce);
        const payload = try state.receive.openAt(output, frame[DATA_HEADER..], frame[0..DATA_HEADER], nonce);
        self.commitNonce(nonce);
        return payload;
    }

    pub fn close(self: *Channel) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.crypto));
        self.crypto = .closed;
        self.signer = .{};
        self.receive_highest = 0;
        self.receive_bitmap = 0;
    }

    fn finish(self: *Channel) Error!void {
        var split = try self.crypto.handshake.finish();
        defer split.deinit();
        self.crypto = .{ .transport = split };
    }

    fn requireTrust(self: *Channel, now_ticks: u64) Error!void {
        if (self.crypto == .closed) return error.InvalidState;
        if (self.signer.authority != null) self.signer.validate(now_ticks) catch |err| {
            self.close();
            return err;
        };
        const current = contextFor(self.graph, self.root_pin, self.local, self.remote, self.role) catch {
            self.close();
            return error.TrustChanged;
        };
        if (!std.crypto.timing_safe.eql([32]u8, self.context, current)) {
            self.close();
            return error.TrustChanged;
        }
    }

    fn validateHeader(self: *const Channel, frame: []const u8, kind: u8) Error!void {
        if (frame.len < HEADER or frame.len > MAX_FRAME or !std.mem.eql(u8, frame[0..4], MAGIC) or frame[4] != VERSION or frame[5] != kind) return error.MalformedFrame;
        if (std.mem.readInt(u64, frame[6..14], .little) != self.remote or std.mem.readInt(u64, frame[14..22], .little) != self.local) return error.PeerMismatch;
    }

    fn checkReplay(self: *const Channel, nonce: u64) Error!void {
        if (nonce == std.math.maxInt(u64)) return error.NonceExhausted;
        if (self.receive_bitmap == 0 or nonce > self.receive_highest) return;
        const distance = self.receive_highest - nonce;
        if (distance >= 64 or (self.receive_bitmap & (@as(u64, 1) << @as(u6, @intCast(distance)))) != 0) return error.ReplayRejected;
    }

    fn commitNonce(self: *Channel, nonce: u64) void {
        if (self.receive_bitmap == 0) {
            self.receive_highest = nonce;
            self.receive_bitmap = 1;
        } else if (nonce > self.receive_highest) {
            const distance = nonce - self.receive_highest;
            self.receive_bitmap = (if (distance >= 64) @as(u64, 0) else self.receive_bitmap << @as(u6, @intCast(distance))) | 1;
            self.receive_highest = nonce;
        } else {
            self.receive_bitmap |= @as(u64, 1) << @as(u6, @intCast(self.receive_highest - nonce));
        }
    }
};

fn writeHeader(output: []u8, kind: u8, source: u64, target: u64) void {
    @memcpy(output[0..4], MAGIC);
    output[4] = VERSION;
    output[5] = kind;
    std.mem.writeInt(u64, output[6..14], source, .little);
    std.mem.writeInt(u64, output[14..22], target, .little);
}

fn certificateDigest(context: [32]u8, key: [32]u8) [32]u8 {
    var hasher = Hash.init(.{});
    hasher.update("zigos.peer.noise-certificate.v1");
    hasher.update(&context);
    hasher.update(&key);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

fn contextFor(graph: *const graph_mod.Graph, root_pin: signing.PublicKey, local: u64, remote: u64, role: noise.Role) Error![32]u8 {
    var hasher = Hash.init(.{});
    hasher.update("zigos.peer.Noise_XX_25519_ChaChaPoly_SHA256.v1");
    hasher.update(&root_pin);
    const devices = if (role == .initiator) [2]u64{ local, remote } else [2]u64{ remote, local };
    var owner: u64 = 0;
    for (devices) |serial| {
        const record = graph.findDeviceConst(.{ .kind = .device, .serial = serial }) orelse return error.DeviceNotFound;
        if (!record.isTrusted() or record.owner.kind != .user or record.owner.serial == 0) return error.TrustChanged;
        if (owner != 0 and owner != record.owner.serial) return error.DeviceOwnerMismatch;
        owner = record.owner.serial;
        if (record.device_signature.format != .ed25519 or record.device_signature.public_key_len != 32) return error.InvalidDeviceSignature;
        var fields: [24]u8 = undefined;
        std.mem.writeInt(u64, fields[0..8], serial, .little);
        std.mem.writeInt(u64, fields[8..16], owner, .little);
        std.mem.writeInt(u32, fields[16..20], record.key_rotation_generation, .little);
        std.mem.writeInt(u32, fields[20..24], record.trust_generation, .little);
        hasher.update(&fields);
        hasher.update(&record.device_signature.public_key);
    }
    const root = graph.findUserRootConst(.{ .kind = .user, .serial = owner }) orelse return error.RootNotFound;
    if (root.root_signature.format != .ed25519 or root.root_signature.public_key_len != 32 or
        !std.mem.eql(u8, &root.root_signature.public_key, &root_pin)) return error.InvalidRootSignature;
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

comptime {
    if (@sizeOf(Channel) > 544) @compileError("peer channel exceeds bounded state budget");
}

const Fixture = struct {
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const a = principal.PrincipalId{ .kind = .device, .serial = 11 };
    const b = principal.PrincipalId{ .kind = .device, .serial = 22 };
    const root = signing.SignerIdentity{ .label = "root", .seed = @splat(0x81) };
    const alice = signing.SignerIdentity{ .label = "alice", .seed = @splat(0x82) };
    const bob = signing.SignerIdentity{ .label = "bob", .seed = @splat(0x83) };

    fn graph() !graph_mod.Graph {
        var result = graph_mod.Graph.init();
        _ = try result.ensureUserRoot(owner, "owner", root);
        _ = try result.enrollDevice(owner, a, "alice", root, alice, 1);
        _ = try result.enrollDevice(owner, b, "bob", root, bob, 1);
        return result;
    }

    fn initiator(devices: *const graph_mod.Graph) !Channel {
        return Channel.initForVerification(devices, try signing.publicKey(root), a, b, alice, .initiator);
    }

    fn responder(devices: *const graph_mod.Graph) !Channel {
        return Channel.initForVerification(devices, try signing.publicKey(root), b, a, bob, .responder);
    }

    fn connect(a_channel: *Channel, b_channel: *Channel) !void {
        var wire: [MAX_FRAME]u8 = undefined;
        try b_channel.readHandshake(try a_channel.writeHandshake(&wire, 1), 1);
        try a_channel.readHandshake(try b_channel.writeHandshake(&wire, 1), 1);
        try b_channel.readHandshake(try a_channel.writeHandshake(&wire, 1), 1);
        try std.testing.expect(a_channel.established() and b_channel.established());
    }
};

test "peer channel authenticates independent device state and rejects every altered datagram byte" {
    const graph_a = try Fixture.graph();
    const graph_b = try Fixture.graph();
    var alice = try Fixture.initiator(&graph_a);
    defer alice.close();
    var bob = try Fixture.responder(&graph_b);
    defer bob.close();
    var wire: [MAX_FRAME]u8 = undefined;
    try std.testing.expectError(error.InvalidState, alice.seal(&wire, "too early", 1));
    try Fixture.connect(&alice, &bob);
    const frame = try alice.seal(&wire, "authenticated object request", 1);
    try std.testing.expect(std.mem.indexOf(u8, frame, "authenticated object request") == null);
    var output: [MAX_PAYLOAD]u8 = undefined;
    for (0..frame.len) |index| {
        var changed = wire;
        changed[index] ^= 1;
        @memset(&output, 0xa5);
        if (bob.open(&output, changed[0..frame.len], 1)) |_| return error.TamperAccepted else |_| {}
        try std.testing.expect(std.mem.allEqual(u8, &output, 0));
        try std.testing.expectEqual(@as(u64, 0), bob.receive_bitmap);
    }
    try std.testing.expectEqualStrings("authenticated object request", try bob.open(&output, frame, 1));
    try std.testing.expectError(error.ReplayRejected, bob.open(&output, frame, 1));
    try std.testing.expectError(error.PeerMismatch, alice.open(&output, frame, 1));
    const reply = try bob.seal(&wire, "confirmed", 1);
    try std.testing.expectEqualStrings("confirmed", try alice.open(&output, reply, 1));
}

test "peer channel requires pinned graph signatures and rejects Noise certificates from other identities" {
    var graph = try Fixture.graph();
    const pin = try signing.publicKey(Fixture.root);
    try std.testing.expectError(error.InvalidRootSignature, Channel.initForVerification(&graph, @splat(0), Fixture.a, Fixture.b, Fixture.alice, .initiator));
    try std.testing.expectError(error.IdentityMismatch, Channel.initForVerification(&graph, pin, Fixture.a, Fixture.b, Fixture.bob, .initiator));
    graph.findDevice(Fixture.b).?.enrollment_signature.value[0] ^= 1;
    try std.testing.expectError(error.InvalidEnrollmentSignature, Fixture.initiator(&graph));
    graph.findDevice(Fixture.b).?.enrollment_signature.value[0] ^= 1;
    var alice = try Fixture.initiator(&graph);
    defer alice.close();
    var bob = try Fixture.responder(&graph);
    defer bob.close();
    var wire: [MAX_FRAME]u8 = undefined;
    try bob.readHandshake(try alice.writeHandshake(&wire, 1), 1);
    bob.certificate[0] ^= 1;
    try std.testing.expectError(error.IdentityMismatch, alice.readHandshake(try bob.writeHandshake(&wire, 1), 1));
    try std.testing.expect(alice.crypto == .closed);
    _ = try graph.rotateDeviceKey(Fixture.owner, Fixture.b, Fixture.root, Fixture.bob, 2);
    _ = try graph.authenticatedDevice(Fixture.b, pin);
    graph.findDevice(Fixture.b).?.rotation_signature.value[0] ^= 1;
    try std.testing.expectError(error.InvalidRotationSignature, Fixture.responder(&graph));
}

test "peer channel commits replay window only after authentication and expires retired trust" {
    var graph = try Fixture.graph();
    var alice = try Fixture.initiator(&graph);
    defer alice.close();
    var bob = try Fixture.responder(&graph);
    defer bob.close();
    try Fixture.connect(&alice, &bob);
    var packets: [3][MAX_FRAME]u8 = undefined;
    var lengths: [3]usize = undefined;
    for (&packets, &lengths) |*packet, *length| length.* = (try alice.seal(packet, "delta", 1)).len;
    var output: [MAX_PAYLOAD]u8 = undefined;
    for ([_]usize{ 2, 0, 1 }) |index| try std.testing.expectEqualStrings("delta", try bob.open(&output, packets[index][0..lengths[index]], 1));
    var forged = packets[0];
    std.mem.writeInt(u64, forged[HEADER + 16 ..][0..8], 10_000, .little);
    try std.testing.expectError(error.AuthenticationFailed, bob.open(&output, forged[0..lengths[0]], 1));
    try std.testing.expectEqual(@as(u64, 2), bob.receive_highest);
    alice.crypto.transport.send.nonce = 64;
    var wire: [MAX_FRAME]u8 = undefined;
    _ = try bob.open(&output, try alice.seal(&wire, "new window", 1), 1);
    try std.testing.expectError(error.ReplayRejected, bob.open(&output, packets[0][0..lengths[0]], 1));
    const pending = try alice.seal(&wire, "pending revocation", 1);
    try graph.revokeDevice(Fixture.owner, Fixture.a, Fixture.root, 3);
    try std.testing.expectError(error.TrustChanged, bob.open(&output, pending, 1));
    try std.testing.expectError(error.TrustChanged, alice.seal(&wire, "revoked", 1));
    try std.testing.expect(alice.crypto == .closed and bob.crypto == .closed);
}

test "peer channel fresh sessions isolate old ciphertext and nonce exhaustion closes traffic keys" {
    const graph = try Fixture.graph();
    var alice = try Fixture.initiator(&graph);
    defer alice.close();
    var bob = try Fixture.responder(&graph);
    defer bob.close();
    try Fixture.connect(&alice, &bob);
    var wire: [MAX_FRAME]u8 = undefined;
    const old = try alice.seal(&wire, "old session", 1);
    var next_a = try Fixture.initiator(&graph);
    defer next_a.close();
    var next_b = try Fixture.responder(&graph);
    defer next_b.close();
    try Fixture.connect(&next_a, &next_b);
    var output: [MAX_PAYLOAD]u8 = undefined;
    try std.testing.expectError(error.PeerMismatch, next_b.open(&output, old, 1));
    alice.crypto.transport.send.nonce = std.math.maxInt(u64) - 1;
    try std.testing.expectEqualStrings("last nonce", try bob.open(&output, try alice.seal(&wire, "last nonce", 1), 1));
    try std.testing.expectError(error.NonceExhausted, alice.seal(&wire, "exhausted", 1));
    try std.testing.expect(alice.crypto == .closed);
}

test "peer channel rejects altered and truncated handshakes without retaining secret state" {
    const graph = try Fixture.graph();
    var alice = try Fixture.initiator(&graph);
    defer alice.close();
    var bob = try Fixture.responder(&graph);
    defer bob.close();
    var wire: [MAX_FRAME]u8 = undefined;
    try bob.readHandshake(try alice.writeHandshake(&wire, 1), 1);
    const response = try bob.writeHandshake(&wire, 1);
    for (0..response.len) |index| {
        var candidate = alice;
        defer candidate.close();
        var changed = wire;
        changed[index] ^= 1;
        if (candidate.readHandshake(changed[0..response.len], 1)) |_| return error.TamperAccepted else |_| {}
        try std.testing.expect(candidate.crypto == .closed);
    }
    for (0..response.len) |length| {
        var candidate = alice;
        defer candidate.close();
        if (candidate.readHandshake(response[0..length], 1)) |_| return error.TruncationAccepted else |_| {}
        try std.testing.expect(candidate.crypto == .closed);
    }
    try alice.readHandshake(response, 1);
    try bob.readHandshake(try alice.writeHandshake(&wire, 1), 1);
    try std.testing.expect(alice.established() and bob.established());
}

test "peer channel rejects key rotation and root replacement during a live handshake" {
    for (0..2) |variant| {
        var graph = try Fixture.graph();
        var alice = try Fixture.initiator(&graph);
        defer alice.close();
        var bob = try Fixture.responder(&graph);
        defer bob.close();
        var wire: [MAX_FRAME]u8 = undefined;
        const hello = try alice.writeHandshake(&wire, 1);
        if (variant == 0) {
            _ = try graph.rotateDeviceKey(Fixture.owner, Fixture.a, Fixture.root, Fixture.alice, 2);
        } else {
            graph.findUserRoot(Fixture.owner).?.root_signature.public_key[0] ^= 1;
        }
        try std.testing.expectError(error.TrustChanged, bob.readHandshake(hello, 1));
        try std.testing.expect(bob.crypto == .closed);
    }
}
