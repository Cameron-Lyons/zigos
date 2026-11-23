//! Remote attestation requests and the device-side TPM quote service. A
//! verifier-owned request carries the policy restrictions that the TPM signs
//! through tpm_attestation.Challenge.qualifyingData.
const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
pub const tpm = @import("tpm_attestation.zig");

pub const MAX_REMOTE_PARTY_BYTES: usize = 64;
pub const MAX_NONCE_BYTES: usize = 32;
pub const MAX_POLICY_LABEL_BYTES: usize = 64;
pub const MAX_ROOT_KEY_ID_BYTES: usize = 64;
pub const MAX_REVOKED_ROOT_GENERATIONS: usize = 8;
pub const MAX_REMOTE_NONCE_HISTORY: usize = 8;
pub const REMOTE_REQUEST_SIZE_CEILING_BYTES: usize = 336;
pub const SERVICE_SIZE_CEILING_BYTES: usize = 352;

comptime {
    if (MAX_REMOTE_PARTY_BYTES > std.math.maxInt(u8) or
        MAX_NONCE_BYTES > std.math.maxInt(u8) or
        MAX_POLICY_LABEL_BYTES > std.math.maxInt(u8) or
        MAX_ROOT_KEY_ID_BYTES > std.math.maxInt(u8) or
        MAX_REVOKED_ROOT_GENERATIONS > std.math.maxInt(u8) or
        MAX_REMOTE_NONCE_HISTORY > std.math.maxInt(u8))
    {
        @compileError("attestation metadata exceeds compact field capacity");
    }
}

pub const RemoteAttestationRequestInit = struct {
    remote_party: []const u8,
    nonce: []const u8,
    policy_label: []const u8,
    root_key_id: []const u8,
    minimum_root_generation: u64,
    revoked_root_generations: []const u64 = &.{},
    attestation_verifier_metadata_digest: crypto_hash.Digest,
};

pub const RemoteAttestationRequest = struct {
    remote_party_len: u8 = 0,
    remote_party: [MAX_REMOTE_PARTY_BYTES]u8 = @as([MAX_REMOTE_PARTY_BYTES]u8, @splat(0)),
    nonce_len: u8 = 0,
    nonce: [MAX_NONCE_BYTES]u8 = @as([MAX_NONCE_BYTES]u8, @splat(0)),
    policy_label_len: u8 = 0,
    policy_label: [MAX_POLICY_LABEL_BYTES]u8 = @as([MAX_POLICY_LABEL_BYTES]u8, @splat(0)),
    root_key_id_len: u8 = 0,
    root_key_id: [MAX_ROOT_KEY_ID_BYTES]u8 = @as([MAX_ROOT_KEY_ID_BYTES]u8, @splat(0)),
    minimum_root_generation: u64 = 0,
    revoked_root_generation_count: u8 = 0,
    revoked_root_generations: [MAX_REVOKED_ROOT_GENERATIONS]u64 = @as([MAX_REVOKED_ROOT_GENERATIONS]u64, @splat(0)),
    attestation_verifier_metadata_digest: crypto_hash.Digest = crypto_hash.zero_digest,

    pub fn init(args: RemoteAttestationRequestInit) Error!RemoteAttestationRequest {
        if (args.revoked_root_generations.len > MAX_REVOKED_ROOT_GENERATIONS) return error.RevocationListFull;
        if (std.mem.allEqual(u8, &args.attestation_verifier_metadata_digest, 0)) return error.AttestationVerifierMetadataMissing;
        var request = RemoteAttestationRequest{
            .minimum_root_generation = args.minimum_root_generation,
            .revoked_root_generation_count = @intCast(args.revoked_root_generations.len),
            .attestation_verifier_metadata_digest = args.attestation_verifier_metadata_digest,
        };
        request.remote_party_len = @intCast(native_util.copyTextExact(&request.remote_party, args.remote_party) catch return error.RemotePartyTooLong);
        request.nonce_len = @intCast(native_util.copyTextExact(&request.nonce, args.nonce) catch return error.NonceTooLong);
        request.policy_label_len = @intCast(native_util.copyTextExact(&request.policy_label, args.policy_label) catch return error.PolicyLabelTooLong);
        request.root_key_id_len = @intCast(native_util.copyTextExact(&request.root_key_id, args.root_key_id) catch return error.RootKeyIdTooLong);
        @memcpy(request.revoked_root_generations[0..args.revoked_root_generations.len], args.revoked_root_generations);
        try request.validate();
        return request;
    }

    pub fn validate(self: *const RemoteAttestationRequest) Error!void {
        if (!canonicalField(&self.remote_party, self.remote_party_len) or
            !canonicalField(&self.nonce, self.nonce_len) or
            !canonicalField(&self.policy_label, self.policy_label_len) or
            !canonicalField(&self.root_key_id, self.root_key_id_len) or
            !canonicalGenerations(&self.revoked_root_generations, self.revoked_root_generation_count) or
            std.mem.allEqual(u8, &self.attestation_verifier_metadata_digest, 0))
            return error.InvalidAttestationRequest;
    }

    pub fn remotePartySlice(self: *const RemoteAttestationRequest) []const u8 {
        return self.remote_party[0..@as(usize, self.remote_party_len)];
    }

    pub fn nonceSlice(self: *const RemoteAttestationRequest) []const u8 {
        return self.nonce[0..@as(usize, self.nonce_len)];
    }

    pub fn policyLabelSlice(self: *const RemoteAttestationRequest) []const u8 {
        return self.policy_label[0..@as(usize, self.policy_label_len)];
    }

    pub fn rootKeyIdSlice(self: *const RemoteAttestationRequest) []const u8 {
        return self.root_key_id[0..@as(usize, self.root_key_id_len)];
    }

    pub fn revokedRootGenerationsSlice(self: *const RemoteAttestationRequest) []const u64 {
        return self.revoked_root_generations[0..@as(usize, self.revoked_root_generation_count)];
    }

    // Call validate before hashing a request received across a trust boundary.
    pub fn digest(self: *const RemoteAttestationRequest) crypto_hash.Digest {
        var hasher = crypto_hash.init();
        crypto_hash.updateBytes(&hasher, "schema", "zigos.remote-attestation-request.v3");
        crypto_hash.updateBytes(&hasher, "remote-party", self.remotePartySlice());
        crypto_hash.updateBytes(&hasher, "nonce", self.nonceSlice());
        crypto_hash.updateBytes(&hasher, "policy-label", self.policyLabelSlice());
        crypto_hash.updateBytes(&hasher, "root-key-id", self.rootKeyIdSlice());
        crypto_hash.updateInt(&hasher, "minimum-root-generation", self.minimum_root_generation);
        crypto_hash.updateInt(&hasher, "revoked-root-generation-count", self.revoked_root_generation_count);
        for (self.revokedRootGenerationsSlice()) |generation| {
            crypto_hash.updateInt(&hasher, "revoked-root-generation", generation);
        }
        crypto_hash.updateBytes(&hasher, "attestation-verifier-metadata-digest", &self.attestation_verifier_metadata_digest);
        return crypto_hash.finalize(&hasher);
    }
};

pub const Error = error{
    InvalidAttestationRequest,
    NonceTooLong,
    RemotePartyTooLong,
    PolicyLabelTooLong,
    RootIdentityMismatch,
    RootKeyIdTooLong,
    RootGenerationRevoked,
    RevocationListFull,
    AttestationVerifierMetadataMissing,
    RemoteNonceReplay,
};

pub const Service = struct {
    device: principal.PrincipalId,
    visible_request_count: usize = 0,
    remote_nonce_history_count: u8 = 0,
    remote_nonce_history: [MAX_REMOTE_NONCE_HISTORY]crypto_hash.Digest = @as([MAX_REMOTE_NONCE_HISTORY]crypto_hash.Digest, @splat(crypto_hash.zero_digest)),
    revoked_root_generation_count: u8 = 0,
    revoked_root_generations: [MAX_REVOKED_ROOT_GENERATIONS]u64 = @as([MAX_REVOKED_ROOT_GENERATIONS]u64, @splat(0)),

    pub fn init(device: principal.PrincipalId) Service {
        return .{ .device = device };
    }

    pub fn revokeRootGeneration(self: *Service, generation: u64) Error!void {
        if (self.isRootGenerationRevoked(generation)) return;
        if (self.revoked_root_generation_count >= self.revoked_root_generations.len) return error.RevocationListFull;
        self.revoked_root_generations[self.revoked_root_generation_count] = generation;
        self.revoked_root_generation_count += 1;
    }

    pub fn isRootGenerationRevoked(self: *const Service, generation: u64) bool {
        return std.mem.findScalar(u64, self.revoked_root_generations[0..self.revoked_root_generation_count], generation) != null;
    }

    // The enrolled key/blob and authorization come from local provisioning.
    // The verifier's PCR expectation is checked against the TPM's live quote;
    // this path makes no claim about software runtime measurement records.
    pub fn respondToTpmAttestationRequest(
        self: *Service,
        client: *@import("tpm2_sealing.zig").Client,
        io: anytype,
        blob: []const u8,
        auth: *const crypto_hash.Digest,
        enrolled: *const tpm.Enrollment,
        challenge: *const tpm.Challenge,
        out: *tpm.Response,
    ) !void {
        out.* = .{};
        errdefer out.* = .{};
        const request = challenge.*;
        const enrollment = enrolled.*;
        try self.validateTpmAttestationRequest(&enrollment, &request);
        const qualifying_data = request.qualifyingData();
        try client.quoteAttestation(io, blob, auth, &enrollment.identity, &qualifying_data, &request.approved_pcr11, out);
        const Publication = struct {
            pub fn publish(_: @This()) !void {}
        };
        try self.finishTpmAttestationRequest(&enrollment, &request, Publication{});
    }

    pub fn validateTpmAttestationRequest(self: *const Service, enrolled: *const tpm.Enrollment, challenge: *const tpm.Challenge) !void {
        try challenge.validate(enrolled);
        if (!self.device.eql(enrolled.device)) return error.RootIdentityMismatch;
        if (self.isRootGenerationRevoked(enrolled.generation)) return error.RootGenerationRevoked;
        const digest = remoteChallengeDigest(challenge.request.remotePartySlice(), challenge.request.nonceSlice());
        for (self.remote_nonce_history[0..self.remote_nonce_history_count]) |*seen| {
            if (std.mem.eql(u8, seen, &digest)) return error.RemoteNonceReplay;
        }
    }

    // Trusted native quote owners call this only after the client verifies the
    // TPM response. Publication must not yield; failed delivery leaves nonce and
    // visibility history untouched. Recheck policy after all hardware waits.
    pub fn finishTpmAttestationRequest(self: *Service, enrolled: *const tpm.Enrollment, challenge: *const tpm.Challenge, publication: anytype) !void {
        try self.validateTpmAttestationRequest(enrolled, challenge);
        try publication.publish();
        self.visible_request_count +|= 1;
        self.rememberRemoteChallenge(challenge.request.remotePartySlice(), challenge.request.nonceSlice());
    }

    fn rememberRemoteChallenge(self: *Service, remote_party: []const u8, nonce: []const u8) void {
        const digest = remoteChallengeDigest(remote_party, nonce);
        if (self.remote_nonce_history_count < self.remote_nonce_history.len) {
            self.remote_nonce_history[self.remote_nonce_history_count] = digest;
            self.remote_nonce_history_count += 1;
            return;
        }
        std.mem.copyForwards(crypto_hash.Digest, self.remote_nonce_history[0 .. self.remote_nonce_history.len - 1], self.remote_nonce_history[1..]);
        self.remote_nonce_history[self.remote_nonce_history.len - 1] = digest;
    }
};

comptime {
    if (@sizeOf(RemoteAttestationRequest) > REMOTE_REQUEST_SIZE_CEILING_BYTES or
        @sizeOf(Service) > SERVICE_SIZE_CEILING_BYTES)
    {
        @compileError("attestation state exceeds compact layout ceilings");
    }
}

fn canonicalField(bytes: []const u8, len: usize) bool {
    return len <= bytes.len and std.mem.allEqual(u8, bytes[len..], 0);
}

fn canonicalGenerations(generations: []const u64, count: usize) bool {
    return count <= generations.len and std.mem.allEqual(u64, generations[count..], 0);
}

fn remoteChallengeDigest(remote_party: []const u8, nonce: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "remote-party", remote_party);
    crypto_hash.updateBytes(&hasher, "nonce", nonce);
    return crypto_hash.finalize(&hasher);
}
