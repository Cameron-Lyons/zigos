//! TPM Library Part 2/3: restricted ECDSA-P256/SHA-256 quotes of SHA-256 PCR 11.
//! https://trustedcomputinggroup.org/resource/tpm-library-specification/
//! A verifier must independently enroll the public identity and supply a fresh,
//! single-use challenge and approved PCR value. A key carried by the quote is
//! never a trust anchor. This module does not establish EK/manufacturer trust.
const std = @import("std");
const wire = @import("tpm2_wire.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const Digest = [32]u8;
pub const Name = [34]u8;
pub const PUBLIC_PREFIX = [_]u8{
    0, 0x23, 0, 0x0b, 0, 5, 0, 0x72, 0, 0, // ECC, SHA256, fixed TPM/parent, restricted signing, generated sensitive, auth
    0, 0x10, 0, 0x18, 0, 0x0b, 0, 3, 0, 0x10, // NULL symmetric, ECDSA SHA256, P256, NULL KDF
};
pub const PUBLIC_BYTES = PUBLIC_PREFIX.len + 68;
pub const SELECTION = [_]u8{ 0, 0, 0, 1, 0, 0x0b, 3, 0, 8, 0 };
pub const MAX_QUOTE_BYTES = 219;
pub const Error = wire.Error || error{ InvalidAttestationKey, InvalidChallenge, InvalidQuote, QuoteMismatch, InvalidQuoteSignature };

pub const Identity = struct {
    public: [PUBLIC_BYTES]u8,
    qualified_name: Name,

    pub fn fromPublic(public: []const u8, parent: *const Name) Error!Identity {
        if (!validName(parent)) return error.InvalidAttestationKey;
        _ = try publicKey(public);
        // The sealing client's parent is a primary in the storage hierarchy.
        const parent_qualified = qualifiedName(&.{ 0x40, 0, 0, 1 }, parent);
        return .{ .public = public[0..PUBLIC_BYTES].*, .qualified_name = qualifiedName(&parent_qualified, &objectName(public)) };
    }

    pub fn validate(self: *const Identity) Error!void {
        if (!validName(&self.qualified_name)) return error.InvalidAttestationKey;
        _ = try publicKey(&self.public);
    }

    pub fn name(self: *const Identity) Name {
        return objectName(&self.public);
    }
};

pub const Evidence = struct {
    bytes: [MAX_QUOTE_BYTES]u8 = @splat(0),
    len: u16 = 0,

    pub fn slice(self: *const Evidence) []const u8 {
        std.debug.assert(self.len <= self.bytes.len);
        return self.bytes[0..self.len];
    }
};

pub const ClockInfo = struct {
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool,
    // Storage-hierarchy attestations may obfuscate counters and firmware version.
    // These fields are signed observations, not a firmware identity or wall clock.
    firmware_version: u64,
};

// Verifier-owned request state. The clock is the verifier's monotonic clock,
// never a value from the prover. Invalid evidence does not consume a live
// challenge; success, cancellation, expiry and clock rollback are terminal.
pub const Pending = struct {
    identity: Identity,
    pcr: Digest,
    nonce: Digest,
    last_observed_ms: u64,
    expires_at_ms: u64,
    consumed: bool = false,

    pub fn init(entropy: anytype, enrolled: Identity, expected_pcr: Digest, now_ms: u64, lifetime_ms: u32) !Pending {
        try enrolled.validate();
        if (lifetime_ms == 0 or lifetime_ms > 60_000) return error.InvalidQuoteLifetime;
        const end = std.math.add(u64, now_ms, lifetime_ms) catch return error.InvalidQuoteLifetime;
        var nonce: Digest = undefined;
        try entropy.random(&nonce);
        try validateChallenge(&nonce);
        return .{ .identity = enrolled, .pcr = expected_pcr, .nonce = nonce, .last_observed_ms = now_ms, .expires_at_ms = end };
    }

    pub fn accept(self: *Pending, bytes: []const u8, now_ms: u64) !ClockInfo {
        if (self.consumed) return error.QuoteChallengeConsumed;
        if (now_ms < self.last_observed_ms or now_ms >= self.expires_at_ms) {
            self.consumed = true;
            return error.QuoteChallengeExpired;
        }
        self.last_observed_ms = now_ms;
        const result = try verify(bytes, &self.identity, &self.nonce, &self.pcr);
        self.consumed = true;
        return result;
    }

    pub fn cancel(self: *Pending) void {
        self.consumed = true;
    }
};

pub fn validateChallenge(nonce: *const Digest) Error!void {
    if (std.mem.allEqual(u8, nonce, 0)) return error.InvalidChallenge;
}

pub fn verify(bytes: []const u8, enrolled: *const Identity, nonce: *const Digest, expected_pcr: *const Digest) Error!ClockInfo {
    try validateChallenge(nonce);
    try enrolled.validate();
    if (bytes.len > MAX_QUOTE_BYTES) return error.InvalidQuote;
    var r = wire.Reader{ .bytes = bytes };
    const attestation = try r.sized();
    var a = wire.Reader{ .bytes = attestation };
    if (try a.int(u32) != 0xff54_4347 or try a.int(u16) != 0x8018) return error.InvalidQuote;
    if (!std.mem.eql(u8, try a.sized(), &enrolled.qualified_name) or
        !std.mem.eql(u8, try a.sized(), nonce)) return error.QuoteMismatch;
    var info = ClockInfo{
        .clock = try a.int(u64),
        .reset_count = try a.int(u32),
        .restart_count = try a.int(u32),
        .safe = false,
        .firmware_version = 0,
    };
    const safe = try a.int(u8);
    if (safe > 1) return error.InvalidQuote;
    info.safe = safe != 0;
    info.firmware_version = try a.int(u64);
    if (!std.mem.eql(u8, try a.take(SELECTION.len), &SELECTION)) return error.QuoteMismatch;
    var digest: Digest = undefined;
    Sha256.hash(expected_pcr, &digest, .{});
    if (!std.mem.eql(u8, try a.sized(), &digest)) return error.QuoteMismatch;
    try a.end();
    if (try r.int(u16) != 0x18 or try r.int(u16) != 0x0b) return error.InvalidQuote;
    const signature = Ecdsa.Signature{ .r = try scalar(try r.sized()), .s = try scalar(try r.sized()) };
    try r.end();
    signature.verify(attestation, try publicKey(&enrolled.public)) catch return error.InvalidQuoteSignature;
    return info;
}

pub fn objectName(public: []const u8) Name {
    var result: Name = .{ 0, 0x0b } ++ @as(Digest, @splat(0));
    Sha256.hash(public, result[2..], .{});
    return result;
}

fn qualifiedName(parent: []const u8, name: *const Name) Name {
    var hash = Sha256.init(.{});
    hash.update(parent);
    hash.update(name);
    return .{ 0, 0x0b } ++ hash.finalResult();
}

fn validName(name: *const Name) bool {
    return name[0] == 0 and name[1] == 0x0b and !std.mem.allEqual(u8, name[2..], 0);
}

fn publicKey(bytes: []const u8) Error!Ecdsa.PublicKey {
    if (bytes.len != PUBLIC_BYTES or !std.mem.startsWith(u8, bytes, &PUBLIC_PREFIX)) return error.InvalidAttestationKey;
    var r = wire.Reader{ .bytes = bytes[PUBLIC_PREFIX.len..] };
    const x = try r.sized();
    const y = try r.sized();
    if (x.len != 32 or y.len != 32) return error.InvalidAttestationKey;
    try r.end();
    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    @memcpy(sec1[1..33], x);
    @memcpy(sec1[33..65], y);
    return Ecdsa.PublicKey.fromSec1(&sec1) catch error.InvalidAttestationKey;
}

fn scalar(bytes: []const u8) Error!Digest {
    if (bytes.len == 0 or bytes.len > 32) return error.InvalidQuote;
    var result: Digest = @splat(0);
    @memcpy(result[32 - bytes.len ..], bytes);
    return result;
}

const Fixture = struct {
    key: Ecdsa.KeyPair,
    identity: Identity,
    nonce: Digest = @splat(0x37),
    pcr: Digest = @splat(0x4a),
    evidence: Evidence = .{},

    fn init() !Fixture {
        const key = try Ecdsa.KeyPair.generateDeterministic(@splat(0x79));
        const sec1 = key.public_key.toUncompressedSec1();
        var public: [PUBLIC_BYTES]u8 = undefined;
        var w = wire.Writer{ .bytes = &public };
        try w.put(&PUBLIC_PREFIX);
        try w.sized(sec1[1..33]);
        try w.sized(sec1[33..65]);
        var self = Fixture{ .key = key, .identity = try Identity.fromPublic(&public, &objectName("test parent")) };
        w = .{ .bytes = &self.evidence.bytes, .pos = 2 };
        try w.int(u32, 0xff54_4347);
        try w.int(u16, 0x8018);
        try w.sized(&self.identity.qualified_name);
        try w.sized(&self.nonce);
        try w.int(u64, 42);
        try w.int(u32, 3);
        try w.int(u32, 7);
        try w.int(u8, 1);
        try w.int(u64, 19);
        try w.put(&SELECTION);
        var digest: Digest = undefined;
        Sha256.hash(&self.pcr, &digest, .{});
        try w.sized(&digest);
        std.mem.writeInt(u16, self.evidence.bytes[0..2], @intCast(w.pos - 2), .big);
        try self.sign();
        return self;
    }

    fn sign(self: *Fixture) !void {
        const end = 2 + @as(usize, std.mem.readInt(u16, self.evidence.bytes[0..2], .big));
        const signature = try self.key.sign(self.evidence.bytes[2..end], null);
        var w = wire.Writer{ .bytes = &self.evidence.bytes, .pos = end };
        try w.int(u16, 0x18);
        try w.int(u16, 0x0b);
        try w.sized(&signature.r);
        try w.sized(&signature.s);
        self.evidence.len = @intCast(w.pos);
    }
};

test "TPM quote verifies the enrolled key challenge PCR selection and signed metadata" {
    const f = try Fixture.init();
    try std.testing.expectEqual(@as(usize, MAX_QUOTE_BYTES), f.evidence.len);
    const info = try verify(f.evidence.slice(), &f.identity, &f.nonce, &f.pcr);
    try std.testing.expectEqualDeep(ClockInfo{ .clock = 42, .reset_count = 3, .restart_count = 7, .safe = true, .firmware_version = 19 }, info);
    var changed = f;
    changed.nonce[0] ^= 1;
    try std.testing.expectError(error.QuoteMismatch, verify(f.evidence.slice(), &f.identity, &changed.nonce, &f.pcr));
    changed.pcr[0] ^= 1;
    try std.testing.expectError(error.QuoteMismatch, verify(f.evidence.slice(), &f.identity, &f.nonce, &changed.pcr));
    changed.identity.qualified_name[2] ^= 1;
    try std.testing.expectError(error.QuoteMismatch, verify(f.evidence.slice(), &changed.identity, &f.nonce, &f.pcr));
    try std.testing.expectError(error.InvalidChallenge, verify(f.evidence.slice(), &f.identity, &(@as(Digest, @splat(0))), &f.pcr));
    // The enrolled public key, not just its claimed Name, is authoritative.
    const other = (try Ecdsa.KeyPair.generateDeterministic(@splat(0x71))).public_key.toUncompressedSec1();
    changed.identity = f.identity;
    @memcpy(changed.identity.public[22..54], other[1..33]);
    @memcpy(changed.identity.public[56..88], other[33..65]);
    try std.testing.expectError(error.InvalidQuoteSignature, verify(f.evidence.slice(), &changed.identity, &f.nonce, &f.pcr));
}

test "TPM quote rejects every truncated or altered byte and trailing data" {
    const f = try Fixture.init();
    for (0..f.evidence.len) |length| {
        if (verify(f.evidence.bytes[0..length], &f.identity, &f.nonce, &f.pcr)) |_| return error.AcceptedTruncatedQuote else |_| {}
    }
    for (0..f.evidence.len) |offset| {
        var changed = f.evidence;
        changed.bytes[offset] ^= 1;
        if (verify(changed.slice(), &f.identity, &f.nonce, &f.pcr)) |_| return error.AcceptedChangedQuote else |_| {}
    }
    const extra = f.evidence.bytes ++ [_]u8{0};
    try std.testing.expectError(error.InvalidQuote, verify(&extra, &f.identity, &f.nonce, &f.pcr));
}

test "TPM quote rejects correctly signed incompatible claims and weakened key templates" {
    const f = try Fixture.init();
    // Re-sign modified claims: a valid signature cannot excuse a different
    // attestation type, nonce, qualified signer, bank/PCR or expected digest.
    for ([_]usize{ 2, 6, 10, 46, 103, 108, 109, 111, 115 }) |offset| {
        var changed = f;
        changed.evidence.bytes[offset] ^= 1;
        try changed.sign();
        if (verify(changed.evidence.slice(), &f.identity, &f.nonce, &f.pcr)) |_| return error.AcceptedIncompatibleQuote else |_| {}
    }
    var changed = f;
    changed.evidence.bytes[94] = 2;
    try changed.sign();
    try std.testing.expectError(error.InvalidQuote, verify(changed.evidence.slice(), &f.identity, &f.nonce, &f.pcr));
    for (0..PUBLIC_PREFIX.len) |offset| {
        var public = f.identity.public;
        public[offset] ^= 1;
        try std.testing.expectError(error.InvalidAttestationKey, Identity.fromPublic(&public, &objectName("test parent")));
    }
    var invalid = f.identity;
    @memset(invalid.public[22..54], 0);
    @memset(invalid.public[56..88], 0);
    try std.testing.expectError(error.InvalidAttestationKey, invalid.validate());
}

test "TPM quote challenge rejects replay expiry cancellation clock rollback and failed entropy" {
    const Entropy = struct {
        nonce: Digest,
        fail: bool = false,
        pub fn random(self: *@This(), out: []u8) !void {
            if (self.fail) return error.EntropyUnavailable;
            @memcpy(out, &self.nonce);
        }
    };
    const f = try Fixture.init();
    var entropy = Entropy{ .nonce = f.nonce };
    var pending = try Pending.init(&entropy, f.identity, f.pcr, 100, 50);
    const saved = pending;
    var bad = f.evidence;
    bad.bytes[bad.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidQuoteSignature, pending.accept(bad.slice(), 120));
    try std.testing.expect(!pending.consumed);
    _ = try pending.accept(f.evidence.slice(), 149);
    try std.testing.expectError(error.QuoteChallengeConsumed, pending.accept(f.evidence.slice(), 149));
    for ([_]u64{ 99, 150, 151, std.math.maxInt(u64) }) |now| {
        pending = saved;
        try std.testing.expectError(error.QuoteChallengeExpired, pending.accept(f.evidence.slice(), now));
        try std.testing.expectError(error.QuoteChallengeConsumed, pending.accept(f.evidence.slice(), 120));
    }
    pending = saved;
    try std.testing.expectError(error.InvalidQuoteSignature, pending.accept(bad.slice(), 140));
    try std.testing.expectError(error.QuoteChallengeExpired, pending.accept(f.evidence.slice(), 139));
    try std.testing.expectError(error.QuoteChallengeConsumed, pending.accept(f.evidence.slice(), 141));
    pending = saved;
    pending.cancel();
    try std.testing.expectError(error.QuoteChallengeConsumed, pending.accept(f.evidence.slice(), 120));
    entropy.nonce[0] ^= 1;
    pending = try Pending.init(&entropy, f.identity, f.pcr, 100, 50);
    try std.testing.expectError(error.QuoteMismatch, pending.accept(f.evidence.slice(), 120));
    entropy.fail = true;
    try std.testing.expectError(error.EntropyUnavailable, Pending.init(&entropy, f.identity, f.pcr, 100, 50));
    entropy.fail = false;
    entropy.nonce = @splat(0);
    try std.testing.expectError(error.InvalidChallenge, Pending.init(&entropy, f.identity, f.pcr, 100, 50));
    try std.testing.expectError(error.InvalidQuoteLifetime, Pending.init(&entropy, f.identity, f.pcr, 100, 0));
    try std.testing.expectError(error.InvalidQuoteLifetime, Pending.init(&entropy, f.identity, f.pcr, 100, 60_001));
    try std.testing.expectError(error.InvalidQuoteLifetime, Pending.init(&entropy, f.identity, f.pcr, std.math.maxInt(u64), 1));
}
