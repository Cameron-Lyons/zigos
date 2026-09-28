//! Remote TPM evidence. Enrollment and approved PCR values are verifier policy,
//! obtained independently of the response. A quote proves PCR 11 and possession
//! of that enrolled key; it does not authenticate arbitrary runtime records or
//! establish manufacturer/EK trust. ECDSA quotes sign qualifyingData as extraData:
//! https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/Attestation/Attest_spt.c
const std = @import("std");
const attestation = @import("attestation_service.zig");
const hash = @import("../core/crypto_hash.zig");
const principal = @import("../core/principal.zig");
const quote = @import("tpm2_quote.zig");

pub const Enrollment = struct {
    device: principal.PrincipalId,
    identity: quote.Identity,
    generation: u64,
    key_id: [attestation.MAX_ROOT_KEY_ID_BYTES]u8 = @splat(0),
    key_id_len: u8 = 0,

    pub fn init(device: principal.PrincipalId, identity: quote.Identity, generation: u64, key_id: []const u8) !Enrollment {
        if (key_id.len == 0 or key_id.len > attestation.MAX_ROOT_KEY_ID_BYTES) return error.InvalidTpmEnrollment;
        var result = Enrollment{ .device = device, .identity = identity, .generation = generation, .key_id_len = @intCast(key_id.len) };
        @memcpy(result.key_id[0..key_id.len], key_id);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const Enrollment) !void {
        if (self.device.kind != .device or self.device.serial == 0 or self.generation == 0 or
            self.key_id_len == 0 or self.key_id_len > self.key_id.len or
            !std.mem.allEqual(u8, self.key_id[self.key_id_len..], 0)) return error.InvalidTpmEnrollment;
        try self.identity.validate();
    }

    pub fn keyId(self: *const Enrollment) []const u8 {
        return self.key_id[0..self.key_id_len];
    }

    // Call validate before hashing externally loaded enrollment records.
    pub fn digest(self: *const Enrollment) hash.Digest {
        var h = hash.init();
        hash.updateBytes(&h, "schema", "zigos.tpm-enrollment.v1");
        hash.updateEnum(&h, "device-kind", self.device.kind);
        hash.updateInt(&h, "device-serial", self.device.serial);
        hash.updateBytes(&h, "public", &self.identity.public);
        hash.updateBytes(&h, "qualified-name", &self.identity.qualified_name);
        hash.updateBytes(&h, "key-id", self.keyId());
        hash.updateInt(&h, "generation", self.generation);
        return hash.finalize(&h);
    }
};

pub const Policy = struct {
    remote_party: []const u8,
    policy_label: []const u8,
    minimum_generation: u64 = 1,
    revoked_generations: []const u64 = &.{},
};

pub const Challenge = struct {
    request: attestation.RemoteAttestationRequest,
    approved_pcr11: hash.Digest,

    pub fn validate(self: *const Challenge, enrolled: *const Enrollment) !void {
        try enrolled.validate();
        try self.request.validate();
        if (self.request.remote_party_len == 0 or self.request.nonce_len != 32 or
            std.mem.allEqual(u8, &self.request.nonce, 0) or !self.request.user_visible or
            self.request.expected_key_origin != .tpm or !std.mem.eql(u8, self.request.rootKeyIdSlice(), enrolled.keyId()) or
            !self.request.attestation_verifier_metadata_digest_required or
            !std.mem.eql(u8, &self.request.attestation_verifier_metadata_digest, &enrolled.digest()) or
            std.mem.allEqual(u8, &self.approved_pcr11, 0)) return error.InvalidTpmChallenge;
        if (self.request.minimum_root_generation == 0 or enrolled.generation < self.request.minimum_root_generation) return error.StaleRootGeneration;
        for (self.request.revokedRootGenerationsSlice()) |generation| {
            if (generation == enrolled.generation) return error.RootGenerationRevoked;
        }
    }

    // All request restrictions and the exact approved PCR are signed by the TPM.
    // The random verifier nonce remains in request.digest(), with domain separation
    // preventing raw quotes or another application protocol from being repackaged.
    pub fn qualifyingData(self: *const Challenge) hash.Digest {
        var h = hash.init();
        hash.updateBytes(&h, "schema", "zigos.remote-tpm-attestation.v1");
        hash.updateBytes(&h, "request", &self.request.digest());
        hash.updateBytes(&h, "approved-pcr11", &self.approved_pcr11);
        return hash.finalize(&h);
    }
};

// No prover-controlled identity, policy, metadata or runtime measurement claims.
pub const Response = quote.Evidence;

comptime {
    if (@sizeOf(Response) > 224 or @sizeOf(Pending) > 800) @compileError("TPM attestation exceeds bounded state ceilings");
}

pub const Accepted = struct {
    device: principal.PrincipalId,
    request_digest: hash.Digest,
    boot_digest: hash.Digest,
    enrollment_digest: hash.Digest,
    clock: quote.ClockInfo,
};

pub const Pending = struct {
    enrollment: Enrollment,
    challenge: Challenge,
    verifier: quote.Pending,

    pub fn init(entropy: anytype, enrolled: Enrollment, approved_pcr11: hash.Digest, policy: Policy, now_ms: u64, lifetime_ms: u32) !Pending {
        try enrolled.validate();
        var verifier = try quote.Pending.init(entropy, enrolled.identity, approved_pcr11, now_ms, lifetime_ms);
        const challenge = Challenge{
            .request = try attestation.RemoteAttestationRequest.init(.{
                .remote_party = policy.remote_party,
                .nonce = &verifier.nonce,
                .policy_label = policy.policy_label,
                .expected_key_origin = .tpm,
                .root_key_id = enrolled.keyId(),
                .minimum_root_generation = policy.minimum_generation,
                .revoked_root_generations = policy.revoked_generations,
                .attestation_verifier_metadata_digest_required = true,
                .attestation_verifier_metadata_digest = enrolled.digest(),
            }),
            .approved_pcr11 = approved_pcr11,
        };
        try challenge.validate(&enrolled);
        verifier.nonce = challenge.qualifyingData();
        return .{ .enrollment = enrolled, .challenge = challenge, .verifier = verifier };
    }

    pub fn accept(self: *Pending, response: *const Response, now_ms: u64) !Accepted {
        try self.verifier.observe(now_ms);
        try self.challenge.validate(&self.enrollment);
        if (!std.meta.eql(self.enrollment.identity, self.verifier.identity) or
            !std.mem.eql(u8, &self.challenge.approved_pcr11, &self.verifier.pcr) or
            !std.mem.eql(u8, &self.challenge.qualifyingData(), &self.verifier.nonce)) return error.InvalidTpmChallenge;
        // Validate fixed-size containers before slicing. A malformed response must
        // still advance verifier time, so clock rollback cannot revive a challenge.
        const bytes = if (response.len <= response.bytes.len and std.mem.allEqual(u8, response.bytes[response.len..], 0)) response.bytes[0..response.len] else &.{};
        const clock = try self.verifier.accept(bytes, now_ms);
        return .{
            .device = self.enrollment.device,
            .request_digest = self.challenge.request.digest(),
            .boot_digest = bootDigest(&self.challenge.approved_pcr11),
            .enrollment_digest = self.enrollment.digest(),
            .clock = clock,
        };
    }

    pub fn cancel(self: *Pending) void {
        self.verifier.cancel();
    }
};

// Network policy pins this profile-specific digest, never confuses PCR evidence
// with a signed runtime BootRecord root from an external attestation provider.
pub fn bootDigest(pcr11: *const hash.Digest) hash.Digest {
    var h = hash.init();
    hash.updateBytes(&h, "schema", "zigos.tpm-pcr11-boot.v1");
    hash.updateBytes(&h, "sha256-pcr11", pcr11);
    return hash.finalize(&h);
}

const TestEntropy = struct {
    value: u8 = 0x57,
    pub fn random(self: *@This(), out: []u8) !void {
        @memset(out, self.value);
    }
};

fn testEnrollment() !Enrollment {
    const fixture = try quote.testing.QuoteFixture.initFor(@splat(1), @splat(2));
    return Enrollment.init(.{ .kind = .device, .serial = 93 }, fixture.identity, 2, "tpm-attestation-key");
}

test "TPM remote attestation binds verifier policy enrollment PCR and nonce with one use" {
    const enrolled = try testEnrollment();
    var entropy = TestEntropy{};
    const pcr: hash.Digest = @splat(0x31);
    const policy = Policy{ .remote_party = "peer.example", .policy_label = "policy-a", .minimum_generation = 2, .revoked_generations = &.{1} };
    var pending = try Pending.init(&entropy, enrolled, pcr, policy, 100, 1000);
    const fixture = try quote.testing.QuoteFixture.initFor(pending.challenge.qualifyingData(), pcr);
    const saved = pending;
    const accepted = try pending.accept(&fixture.evidence, 101);
    try std.testing.expectEqualDeep(enrolled.device, accepted.device);
    try std.testing.expectEqualSlices(u8, &enrolled.digest(), &accepted.enrollment_digest);
    try std.testing.expectEqualSlices(u8, &bootDigest(&pcr), &accepted.boot_digest);
    try std.testing.expect(!std.mem.eql(u8, &pcr, &accepted.boot_digest));
    try std.testing.expectEqualSlices(u8, &pending.challenge.request.digest(), &accepted.request_digest);
    try std.testing.expectError(error.QuoteChallengeConsumed, pending.accept(&fixture.evidence, 102));
    for (0..7) |variant| {
        var other_policy = policy;
        var other_enrollment = enrolled;
        var other_pcr = pcr;
        switch (variant) {
            0 => other_policy.policy_label = "policy-b",
            1 => other_policy.minimum_generation = 1,
            2 => other_policy.revoked_generations = &.{3},
            3 => other_policy.remote_party = "else.example",
            4 => other_enrollment.device.serial += 1,
            5 => other_enrollment.generation += 1,
            6 => other_pcr[0] ^= 1,
            else => unreachable,
        }
        pending = try Pending.init(&entropy, other_enrollment, other_pcr, other_policy, 100, 1000);
        try std.testing.expectError(error.QuoteMismatch, pending.accept(&fixture.evidence, 101));
        try std.testing.expect(!pending.verifier.consumed);
    }
    entropy.value += 1;
    pending = try Pending.init(&entropy, enrolled, pcr, policy, 100, 1000);
    try std.testing.expectError(error.QuoteMismatch, pending.accept(&fixture.evidence, 101));
    pending = saved;
    const raw_quote = try quote.testing.QuoteFixture.initFor(pending.challenge.request.nonce, pcr);
    try std.testing.expectError(error.QuoteMismatch, pending.accept(&raw_quote.evidence, 101));
    var bad = fixture.evidence;
    bad.bytes[bad.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidQuoteSignature, pending.accept(&bad, 102));
    _ = try pending.accept(&fixture.evidence, 103);
}

test "TPM remote attestation rejects stale revoked malformed and expired verifier state" {
    const enrolled = try testEnrollment();
    var entropy = TestEntropy{};
    const pcr: hash.Digest = @splat(0x31);
    var policy = Policy{ .remote_party = "peer.example", .policy_label = "policy" };
    const saved = try Pending.init(&entropy, enrolled, pcr, policy, 100, 1000);
    const fixture = try quote.testing.QuoteFixture.initFor(saved.challenge.qualifyingData(), pcr);
    for ([_]u64{ 99, 1100, std.math.maxInt(u64) }) |now| {
        var pending = saved;
        try std.testing.expectError(error.QuoteChallengeExpired, pending.accept(&fixture.evidence, now));
        try std.testing.expectError(error.QuoteChallengeConsumed, pending.accept(&fixture.evidence, 101));
    }
    var pending = saved;
    pending.cancel();
    try std.testing.expectError(error.QuoteChallengeConsumed, pending.accept(&fixture.evidence, 101));
    pending = saved;
    var malformed = fixture.evidence;
    malformed.len = std.math.maxInt(u16);
    try std.testing.expectError(error.InvalidResponse, pending.accept(&malformed, 102));
    try std.testing.expectError(error.QuoteChallengeExpired, pending.accept(&fixture.evidence, 101));
    pending = saved;
    pending.challenge.request.remote_party_len = 255;
    try std.testing.expectError(error.InvalidAttestationRequest, pending.accept(&fixture.evidence, 101));
    pending = saved;
    pending.challenge.request.policy_label[0] ^= 1;
    try std.testing.expectError(error.InvalidTpmChallenge, pending.accept(&fixture.evidence, 101));
    policy.minimum_generation = 3;
    try std.testing.expectError(error.StaleRootGeneration, Pending.init(&entropy, enrolled, pcr, policy, 100, 1000));
    policy.minimum_generation = 1;
    policy.revoked_generations = &.{2};
    try std.testing.expectError(error.RootGenerationRevoked, Pending.init(&entropy, enrolled, pcr, policy, 100, 1000));
    var bad_enrollment = enrolled;
    bad_enrollment.key_id_len = 255;
    try std.testing.expectError(error.InvalidTpmEnrollment, Pending.init(&entropy, bad_enrollment, pcr, policy, 100, 1000));
    bad_enrollment = enrolled;
    bad_enrollment.key_id[63] = 1;
    try std.testing.expectError(error.InvalidTpmEnrollment, bad_enrollment.validate());
    policy.revoked_generations = &.{};
    try std.testing.expectError(error.InvalidTpmChallenge, Pending.init(&entropy, enrolled, @splat(0), policy, 100, 1000));
    entropy.value = 0;
    try std.testing.expectError(error.InvalidChallenge, Pending.init(&entropy, enrolled, pcr, policy, 100, 1000));
}

test "TPM remote attestation service rejects invalid requests without TPM commands or state changes" {
    const sealing = @import("tpm2_sealing.zig");
    const enrolled = try testEnrollment();
    var entropy = TestEntropy{};
    const pcr: hash.Digest = @splat(0x31);
    const pending = try Pending.init(&entropy, enrolled, pcr, .{ .remote_party = "peer.example", .policy_label = "policy" }, 100, 1000);
    var service = attestation.Service.init(enrolled.device);
    const before = service;
    var client = sealing.Client{};
    const Io = struct {
        commands: usize = 0,
        pub fn random(_: *@This(), _: []u8) !void {
            return error.UnexpectedHardwareAccess;
        }
        pub fn execute(self: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            self.commands += 1;
            return error.UnexpectedHardwareAccess;
        }
    };
    var io = Io{};
    var out = Response{ .bytes = @splat(0xa5), .len = 19 };
    var challenge = pending.challenge;
    challenge.request.user_visible = false;
    try std.testing.expectError(error.InvalidTpmChallenge, service.respondToTpmAttestationRequest(&client, &io, "", &(@as(hash.Digest, @splat(1))), &enrolled, &challenge, &out));
    try std.testing.expect(std.mem.allEqual(u8, &out.bytes, 0));
    try std.testing.expectEqual(@as(u16, 0), out.len);
    try std.testing.expectEqualDeep(before, service);
    try std.testing.expectEqual(@as(usize, 0), io.commands);
}
