const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const trust_policy_payload_type = "application/vnd.zigos.release-trust-policy.v1+json";
pub const release_payload_type = "application/vnd.zigos.release-manifest.v1+json";

const max_metadata_bytes: usize = 4 * 1024 * 1024;
const max_keys: usize = 128;
const max_signatures: usize = 128;
const max_artifacts: usize = 4096;
pub const sha256_hex_length = Sha256.digest_length * 2;
const sha256_hex_len = sha256_hex_length;

pub const KeyAlgorithm = enum {
    ed25519,
};

pub const RootKey = struct {
    keyId: []const u8,
    algorithm: KeyAlgorithm,
    publicKey: []const u8,
};

pub const RootMetadata = struct {
    schemaVersion: u32,
    namespace: []const u8,
    channel: []const u8,
    version: u64,
    issuedAt: i64,
    expiresAt: i64,
    minimumPolicyVersion: u64,
    threshold: u32,
    keys: []const RootKey,
};

pub const ReleaseKeyStatus = enum {
    active,
    retired,
    revoked,
};

pub const ReleaseRole = struct {
    threshold: u32,
    keyIds: []const []const u8,
};

pub const ReleaseKey = struct {
    keyId: []const u8,
    algorithm: KeyAlgorithm,
    generation: u64,
    status: ReleaseKeyStatus,
    custody: []const u8,
    hardwareBacked: bool,
    notBefore: i64,
    notAfter: i64,
    publicKey: []const u8,
};

pub const Revocation = struct {
    keyId: []const u8,
    generation: u64,
    revokedAt: i64,
    reason: []const u8,
};

pub const ArtifactProfile = struct {
    profileId: []const u8,
    exactTargets: []const []const u8,
    exactEvidence: []const []const u8,
};

pub const PqcMode = enum {
    shadow,
    canary,
    required,
};

pub const PqcPolicy = struct {
    mode: PqcMode,
    requiredAlgorithm: []const u8,
    fipsValidatedRequired: bool,
};

pub const TrustPolicy = struct {
    rootVersion: u64,
    policyVersion: u64,
    minimumReleaseSequence: u64,
    issuedAt: i64,
    expiresAt: i64,
    releaseRole: ReleaseRole,
    releaseKeys: []const ReleaseKey,
    revocations: []const Revocation,
    artifactProfile: ArtifactProfile,
    pqcPolicy: PqcPolicy,
};

pub const SourceIdentity = struct {
    repository: []const u8,
    changeId: []const u8,
    commitId: []const u8,
};

pub const BuildIdentity = struct {
    zigVersion: []const u8,
    target: []const u8,
    optimizeMode: []const u8,
    builderId: []const u8,
};

pub const FileRecord = struct {
    path: []const u8,
    sha256: []const u8,
    sizeBytes: u64,
};

pub const ReleaseManifest = struct {
    policyVersion: u64,
    profileId: []const u8,
    /// Callers compare this authenticated value with their persisted sequence
    /// before accepting the release or updating rollback-protection state.
    releaseSequence: u64,
    issuedAt: i64,
    expiresAt: i64,
    source: SourceIdentity,
    build: BuildIdentity,
    targets: []const FileRecord,
    evidence: []const FileRecord,
};

const DsseSignature = struct {
    keyid: []const u8,
    sig: []const u8,
};

const DsseEnvelope = struct {
    payloadType: []const u8,
    payload: []const u8,
    signatures: []const DsseSignature,
};

pub const VerifiedRoot = struct {
    parsed: std.json.Parsed(RootMetadata),

    pub fn metadata(self: *const VerifiedRoot) *const RootMetadata {
        return &self.parsed.value;
    }

    pub fn deinit(self: *VerifiedRoot) void {
        self.parsed.deinit();
    }
};

pub const VerifiedPolicy = struct {
    parsed: std.json.Parsed(TrustPolicy),
    root_signer_count: usize,

    pub fn policy(self: *const VerifiedPolicy) *const TrustPolicy {
        return &self.parsed.value;
    }

    pub fn deinit(self: *VerifiedPolicy) void {
        self.parsed.deinit();
    }
};

pub const VerifiedManifest = struct {
    parsed: std.json.Parsed(ReleaseManifest),
    release_signer_count: usize,

    pub fn manifest(self: *const VerifiedManifest) *const ReleaseManifest {
        return &self.parsed.value;
    }

    pub fn deinit(self: *VerifiedManifest) void {
        self.parsed.deinit();
    }
};

/// Establishes the initial root of trust. `expected_sha256_hex` must come from
/// outside the release bundle (for example, an installer or independently
/// pinned configuration). The JSON is not parsed or interpreted until its raw
/// bytes match that digest.
pub fn verifyRootMetadata(
    allocator: std.mem.Allocator,
    source: []const u8,
    expected_sha256_hex: []const u8,
    now_unix: i64,
) !VerifiedRoot {
    if (source.len == 0 or source.len > max_metadata_bytes) return error.InvalidMetadataSize;
    const expected = try decodeCanonicalSha256(expected_sha256_hex);
    var actual: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(source, &actual, .{});
    if (!constantTimeEql(&actual, &expected)) return error.RootDigestMismatch;

    var parsed = try parseStrict(RootMetadata, allocator, source);
    errdefer parsed.deinit();
    try validateRoot(&parsed.value, now_unix);
    return .{ .parsed = parsed };
}

/// Authenticates a trust policy with the externally pinned root before parsing
/// the policy payload into its typed representation.
pub fn verifyTrustPolicy(
    allocator: std.mem.Allocator,
    envelope_source: []const u8,
    root: *const VerifiedRoot,
    now_unix: i64,
    expected_targets: []const []const u8,
    expected_evidence: []const []const u8,
) !VerifiedPolicy {
    const authenticated = try authenticateTrustPolicyEnvelope(allocator, envelope_source, root.metadata());
    defer allocator.free(authenticated.payload);

    var parsed = try parseStrict(TrustPolicy, allocator, authenticated.payload);
    errdefer parsed.deinit();
    try validatePolicy(&parsed.value, root.metadata(), now_unix, expected_targets, expected_evidence);
    return .{
        .parsed = parsed,
        .root_signer_count = authenticated.signer_count,
    };
}

/// Authenticates every DSSE signature before parsing the manifest payload.
/// Unknown, duplicate, revoked, unauthorized, expired, or invalid signatures
/// fail the whole envelope, including signatures beyond the threshold.
pub fn verifyReleaseManifest(
    allocator: std.mem.Allocator,
    envelope_source: []const u8,
    policy: *const VerifiedPolicy,
    now_unix: i64,
    expected_targets: []const []const u8,
    expected_evidence: []const []const u8,
) !VerifiedManifest {
    const authenticated = try authenticateReleaseEnvelope(allocator, envelope_source, policy.policy(), now_unix);
    defer allocator.free(authenticated.payload);
    defer allocator.free(authenticated.signer_ids);

    var parsed = try parseStrict(ReleaseManifest, allocator, authenticated.payload);
    errdefer parsed.deinit();
    try validateManifest(
        &parsed.value,
        policy.policy(),
        authenticated.signer_ids,
        now_unix,
        expected_targets,
        expected_evidence,
    );
    return .{
        .parsed = parsed,
        .release_signer_count = authenticated.signer_count,
    };
}

pub fn sha256Hex(bytes: []const u8, output: *[sha256_hex_len]u8) []const u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    encodeHexLower(&digest, output);
    return output;
}

pub fn keyIdForEd25519(public_key: [Ed25519.PublicKey.encoded_length]u8, output: *[sha256_hex_len]u8) []const u8 {
    return sha256Hex(&public_key, output);
}

const AuthenticatedEnvelope = struct {
    payload: []u8,
    signer_count: usize,
    signer_ids: []const []const u8 = &.{},
};

fn authenticateTrustPolicyEnvelope(
    allocator: std.mem.Allocator,
    source: []const u8,
    root: *const RootMetadata,
) !AuthenticatedEnvelope {
    var envelope = try parseEnvelope(allocator, source, trust_policy_payload_type);
    defer envelope.parsed.deinit();
    errdefer allocator.free(envelope.payload);

    if (envelope.parsed.value.signatures.len < root.threshold) return error.SignatureThresholdNotMet;
    const pae = try dssePreauthEncoding(allocator, trust_policy_payload_type, envelope.payload);
    defer allocator.free(pae);
    for (envelope.parsed.value.signatures, 0..) |signature, index| {
        try rejectDuplicateSigner(envelope.parsed.value.signatures, index);
        const key = findRootKey(root, signature.keyid) orelse return error.UnknownSigner;
        try verifyEnvelopeSignature(allocator, key.publicKey, signature.sig, pae);
    }
    return .{
        .payload = envelope.payload,
        .signer_count = envelope.parsed.value.signatures.len,
    };
}

fn authenticateReleaseEnvelope(
    allocator: std.mem.Allocator,
    source: []const u8,
    policy: *const TrustPolicy,
    now_unix: i64,
) !AuthenticatedEnvelope {
    var envelope = try parseEnvelope(allocator, source, release_payload_type);
    defer envelope.parsed.deinit();
    errdefer allocator.free(envelope.payload);

    if (envelope.parsed.value.signatures.len < policy.releaseRole.threshold) return error.SignatureThresholdNotMet;
    const signer_ids = try allocator.alloc([]const u8, envelope.parsed.value.signatures.len);
    defer allocator.free(signer_ids);
    const pae = try dssePreauthEncoding(allocator, release_payload_type, envelope.payload);
    defer allocator.free(pae);

    for (envelope.parsed.value.signatures, 0..) |signature, index| {
        try rejectDuplicateSigner(envelope.parsed.value.signatures, index);
        if (!containsString(policy.releaseRole.keyIds, signature.keyid)) return error.UnknownOrUnauthorizedSigner;
        const key = findReleaseKey(policy, signature.keyid) orelse return error.UnknownOrUnauthorizedSigner;
        if (key.status != .active) return error.ReleaseKeyNotActive;
        if (isRevoked(policy, key)) return error.ReleaseKeyRevoked;
        if (now_unix < key.notBefore or now_unix >= key.notAfter) return error.ReleaseKeyExpired;
        try verifyEnvelopeSignature(allocator, key.publicKey, signature.sig, pae);
        signer_ids[index] = key.keyId;
    }

    // The returned IDs refer to policy-owned strings, not envelope-owned data.
    const stable_signer_ids = try allocator.dupe([]const u8, signer_ids);
    return .{
        .payload = envelope.payload,
        .signer_count = signer_ids.len,
        .signer_ids = stable_signer_ids,
    };
}

const ParsedEnvelope = struct {
    parsed: std.json.Parsed(DsseEnvelope),
    payload: []u8,
};

fn parseEnvelope(allocator: std.mem.Allocator, source: []const u8, expected_payload_type: []const u8) !ParsedEnvelope {
    if (source.len == 0 or source.len > max_metadata_bytes) return error.InvalidMetadataSize;
    var parsed = try parseStrict(DsseEnvelope, allocator, source);
    errdefer parsed.deinit();
    const envelope = &parsed.value;
    if (!std.mem.eql(u8, envelope.payloadType, expected_payload_type)) return error.PayloadTypeMismatch;
    if (envelope.signatures.len == 0 or envelope.signatures.len > max_signatures) return error.InvalidSignatureCount;
    const payload = try decodeBase64(allocator, envelope.payload, max_metadata_bytes);
    return .{ .parsed = parsed, .payload = payload };
}

fn verifyEnvelopeSignature(
    allocator: std.mem.Allocator,
    public_key_hex: []const u8,
    signature_base64: []const u8,
    pae: []const u8,
) !void {
    const public_key_bytes = decodeHexFixed(Ed25519.PublicKey.encoded_length, public_key_hex) catch return error.InvalidPublicKey;
    const signature_bytes = try decodeBase64(allocator, signature_base64, Ed25519.Signature.encoded_length);
    defer allocator.free(signature_bytes);
    if (signature_bytes.len != Ed25519.Signature.encoded_length) return error.InvalidSignatureLength;
    const public_key = Ed25519.PublicKey.fromBytes(public_key_bytes) catch return error.InvalidPublicKey;
    const signature = Ed25519.Signature.fromBytes(signature_bytes[0..Ed25519.Signature.encoded_length].*);
    signature.verify(pae, public_key) catch return error.InvalidSignature;
}

fn validateRoot(root: *const RootMetadata, now_unix: i64) !void {
    if (root.schemaVersion != 1) return error.UnsupportedRootSchema;
    try validateIdentifier(root.namespace);
    try validateIdentifier(root.channel);
    if (root.version == 0) return error.InvalidRootVersion;
    if (root.minimumPolicyVersion == 0) return error.InvalidMinimumPolicyVersion;
    try validateWindow(root.issuedAt, root.expiresAt, now_unix);
    if (root.keys.len == 0 or root.keys.len > max_keys) return error.InvalidRootKeyCount;
    if (root.threshold == 0 or root.threshold > root.keys.len) return error.InvalidRootThreshold;
    for (root.keys, 0..) |key, index| {
        try validateDerivedKeyId(key.keyId, key.publicKey);
        for (root.keys[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.keyId, key.keyId)) return error.DuplicateKeyId;
        }
    }
}

fn validatePolicy(
    policy: *const TrustPolicy,
    root: *const RootMetadata,
    now_unix: i64,
    expected_targets: []const []const u8,
    expected_evidence: []const []const u8,
) !void {
    if (policy.rootVersion != root.version) return error.RootVersionMismatch;
    if (policy.policyVersion == 0) return error.InvalidPolicyVersion;
    if (policy.policyVersion < root.minimumPolicyVersion) return error.PolicyBelowRootCheckpoint;
    if (policy.minimumReleaseSequence == 0) return error.InvalidMinimumReleaseSequence;
    try validateWindow(policy.issuedAt, policy.expiresAt, now_unix);
    if (policy.issuedAt < root.issuedAt or policy.expiresAt > root.expiresAt) return error.PolicyOutsideRootWindow;
    if (policy.releaseKeys.len == 0 or policy.releaseKeys.len > max_keys) return error.InvalidReleaseKeyCount;
    if (policy.releaseRole.threshold == 0 or policy.releaseRole.threshold > policy.releaseRole.keyIds.len) {
        return error.InvalidReleaseThreshold;
    }
    if (policy.releaseRole.keyIds.len > policy.releaseKeys.len) return error.InvalidReleaseRole;

    for (policy.releaseKeys, 0..) |key, index| {
        try validateDerivedKeyId(key.keyId, key.publicKey);
        if (key.generation == 0) return error.InvalidKeyGeneration;
        validateIdentifier(key.custody) catch return error.InvalidKeyCustody;
        if (!key.hardwareBacked) return error.ReleaseKeyNotHardwareBacked;
        if (key.notBefore < 0 or key.notBefore >= key.notAfter) return error.InvalidKeyWindow;
        for (policy.releaseKeys[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.keyId, key.keyId)) return error.DuplicateKeyId;
        }
    }

    for (policy.releaseRole.keyIds, 0..) |key_id, index| {
        try validateSha256Hex(key_id);
        for (policy.releaseRole.keyIds[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier, key_id)) return error.DuplicateRoleKeyId;
        }
        _ = findReleaseKey(policy, key_id) orelse return error.UnknownRoleKey;
    }

    for (policy.revocations, 0..) |revocation, index| {
        if (revocation.reason.len == 0 or revocation.reason.len > 512) return error.InvalidRevocationReason;
        if (revocation.revokedAt < 0) return error.InvalidRevocationTime;
        if (revocation.revokedAt > policy.issuedAt) return error.FutureRevocation;
        const key = findReleaseKey(policy, revocation.keyId) orelse return error.UnknownRevokedKey;
        if (key.generation != revocation.generation) return error.UnknownRevokedGeneration;
        for (policy.revocations[0..index]) |earlier| {
            if (earlier.generation == revocation.generation and std.mem.eql(u8, earlier.keyId, revocation.keyId)) {
                return error.DuplicateRevocation;
            }
        }
    }

    var usable: usize = 0;
    for (policy.releaseRole.keyIds) |key_id| {
        const key = findReleaseKey(policy, key_id).?;
        if (key.status == .active and !isRevoked(policy, key) and
            key.notBefore <= now_unix and now_unix < key.notAfter)
        {
            usable += 1;
        }
    }
    if (usable < policy.releaseRole.threshold) return error.ReleaseThresholdNotUsable;

    try validateIdentifier(policy.artifactProfile.profileId);
    try validateExactPathSet(policy.artifactProfile.exactTargets, expected_targets);
    try validateExactPathSet(policy.artifactProfile.exactEvidence, expected_evidence);
    for (policy.artifactProfile.exactTargets) |target| {
        if (containsString(policy.artifactProfile.exactEvidence, target)) return error.ArtifactRoleOverlap;
    }

    validateIdentifier(policy.pqcPolicy.requiredAlgorithm) catch return error.InvalidPqcAlgorithm;
    if (!std.mem.eql(u8, policy.pqcPolicy.requiredAlgorithm, "ml-dsa-65")) {
        return error.UnsupportedPqcAlgorithm;
    }
    if (!policy.pqcPolicy.fipsValidatedRequired) return error.PqcValidationDowngrade;
    if (policy.pqcPolicy.mode == .required) return error.RequiredPqcVerificationUnsupported;
}

fn validateManifest(
    manifest: *const ReleaseManifest,
    policy: *const TrustPolicy,
    signer_ids: []const []const u8,
    now_unix: i64,
    expected_targets: []const []const u8,
    expected_evidence: []const []const u8,
) !void {
    if (manifest.policyVersion != policy.policyVersion) return error.PolicyVersionMismatch;
    if (!std.mem.eql(u8, manifest.profileId, policy.artifactProfile.profileId)) return error.ArtifactProfileMismatch;
    if (manifest.releaseSequence < policy.minimumReleaseSequence) return error.ReleaseBelowPolicyCheckpoint;
    try validateWindow(manifest.issuedAt, manifest.expiresAt, now_unix);
    if (manifest.issuedAt < policy.issuedAt or manifest.expiresAt > policy.expiresAt) return error.ManifestOutsidePolicyWindow;

    // Checking current time before payload parsing prevents backdating. These
    // checks additionally bind the signed manifest's own interval to every key.
    for (signer_ids) |signer_id| {
        const key = findReleaseKey(policy, signer_id).?;
        if (manifest.issuedAt < key.notBefore or manifest.issuedAt >= key.notAfter or manifest.expiresAt > key.notAfter) {
            return error.ManifestOutsideKeyWindow;
        }
    }

    try validateIdentity(manifest.source.repository);
    try validateIdentity(manifest.source.changeId);
    try validateIdentity(manifest.source.commitId);
    try validateIdentity(manifest.build.zigVersion);
    try validateIdentity(manifest.build.target);
    try validateIdentity(manifest.build.optimizeMode);
    try validateIdentity(manifest.build.builderId);

    try validateFileRecordSet(manifest.targets, expected_targets);
    try validateFileRecordSet(manifest.evidence, expected_evidence);
    try validateFileRecordSet(manifest.targets, policy.artifactProfile.exactTargets);
    try validateFileRecordSet(manifest.evidence, policy.artifactProfile.exactEvidence);
    for (manifest.targets) |target| {
        for (manifest.evidence) |evidence| {
            if (std.mem.eql(u8, target.path, evidence.path)) return error.ArtifactRoleOverlap;
        }
    }
}

fn validateFileRecordSet(records: []const FileRecord, expected: []const []const u8) !void {
    if (records.len > max_artifacts) return error.ArtifactSetMismatch;
    try validateExpectedPaths(expected);
    for (records, 0..) |record, index| {
        try validateSafeRelativePath(record.path);
        try validateSha256Hex(record.sha256);
        if (record.sizeBytes == 0) return error.InvalidArtifactSize;
        for (records[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.path, record.path)) return error.DuplicateArtifactPath;
        }
        if (!containsString(expected, record.path)) return error.ArtifactSetMismatch;
    }
    if (records.len != expected.len) return error.ArtifactSetMismatch;
}

fn validateExactPathSet(actual: []const []const u8, expected: []const []const u8) !void {
    if (actual.len > max_artifacts) return error.ArtifactSetMismatch;
    try validateExpectedPaths(expected);
    for (actual, 0..) |path, index| {
        try validateSafeRelativePath(path);
        for (actual[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier, path)) return error.DuplicateArtifactPath;
        }
        if (!containsString(expected, path)) return error.ArtifactSetMismatch;
    }
    if (actual.len != expected.len) return error.ArtifactSetMismatch;
}

fn validateExpectedPaths(expected: []const []const u8) !void {
    if (expected.len == 0 or expected.len > max_artifacts) return error.InvalidExpectedArtifactSet;
    for (expected, 0..) |path, index| {
        try validateSafeRelativePath(path);
        for (expected[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier, path)) return error.DuplicateExpectedArtifactPath;
        }
    }
}

fn validateSafeRelativePath(path: []const u8) !void {
    if (path.len == 0 or path.len > 1024 or path[0] == '/' or path[0] == '\\') return error.UnsafeArtifactPath;
    if (std.mem.indexOfScalar(u8, path, '\\') != null or std.mem.indexOfScalar(u8, path, ':') != null) {
        return error.UnsafeArtifactPath;
    }
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) {
            return error.UnsafeArtifactPath;
        }
        for (component) |byte| {
            if (byte < 0x21 or byte > 0x7e) return error.UnsafeArtifactPath;
        }
    }
}

fn validateWindow(issued: i64, expires: i64, now_unix: i64) !void {
    if (issued < 0 or expires <= issued) return error.InvalidTimeWindow;
    if (issued > now_unix) return error.MetadataNotYetValid;
    if (now_unix >= expires) return error.MetadataExpired;
}

fn validateIdentity(value: []const u8) !void {
    if (value.len == 0 or value.len > 512) return error.InvalidIdentity;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f) return error.InvalidIdentity;
    }
}

fn validateIdentifier(value: []const u8) !void {
    if (value.len == 0 or value.len > 128) return error.InvalidIdentifier;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and byte != '-') {
            return error.InvalidIdentifier;
        }
    }
}

fn validateDerivedKeyId(key_id: []const u8, public_key_hex: []const u8) !void {
    const public_key = decodeCanonicalPublicKey(public_key_hex) catch return error.InvalidPublicKey;
    _ = Ed25519.PublicKey.fromBytes(public_key) catch return error.InvalidPublicKey;
    var derived_buffer: [sha256_hex_len]u8 = undefined;
    const derived = keyIdForEd25519(public_key, &derived_buffer);
    if (!std.mem.eql(u8, key_id, derived)) return error.KeyIdMismatch;
}

fn decodeCanonicalPublicKey(value: []const u8) ![Ed25519.PublicKey.encoded_length]u8 {
    if (value.len != Ed25519.PublicKey.encoded_length * 2) return error.InvalidPublicKey;
    for (value) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) {
            return error.InvalidPublicKey;
        }
    }
    return decodeHexFixed(Ed25519.PublicKey.encoded_length, value) catch return error.InvalidPublicKey;
}

fn validateSha256Hex(value: []const u8) !void {
    _ = try decodeCanonicalSha256(value);
}

fn decodeCanonicalSha256(value: []const u8) ![Sha256.digest_length]u8 {
    if (value.len != sha256_hex_len) return error.InvalidSha256;
    for (value) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return error.InvalidSha256;
    }
    return decodeHexFixed(Sha256.digest_length, value) catch return error.InvalidSha256;
}

fn findRootKey(root: *const RootMetadata, key_id: []const u8) ?*const RootKey {
    for (root.keys) |*key| {
        if (std.mem.eql(u8, key.keyId, key_id)) return key;
    }
    return null;
}

fn findReleaseKey(policy: *const TrustPolicy, key_id: []const u8) ?*const ReleaseKey {
    for (policy.releaseKeys) |*key| {
        if (std.mem.eql(u8, key.keyId, key_id)) return key;
    }
    return null;
}

fn isRevoked(policy: *const TrustPolicy, key: *const ReleaseKey) bool {
    for (policy.revocations) |revocation| {
        if (revocation.generation == key.generation and std.mem.eql(u8, revocation.keyId, key.keyId)) return true;
    }
    return false;
}

fn rejectDuplicateSigner(signatures: []const DsseSignature, index: usize) !void {
    for (signatures[0..index]) |earlier| {
        if (std.mem.eql(u8, earlier.keyid, signatures[index].keyid)) return error.DuplicateSigner;
    }
}

fn containsString(values: []const []const u8, needle: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, needle)) return true;
    }
    return false;
}

fn parseStrict(comptime T: type, allocator: std.mem.Allocator, source: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, source, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });
}

fn decodeBase64(allocator: std.mem.Allocator, text: []const u8, maximum: usize) ![]u8 {
    const size = std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
    if (size > maximum) return error.DecodedValueTooLarge;
    const decoded = try allocator.alloc(u8, size);
    errdefer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, text) catch return error.InvalidBase64;
    return decoded;
}

fn dssePreauthEncoding(allocator: std.mem.Allocator, payload_type: []const u8, payload: []const u8) ![]u8 {
    const prefix = try std.fmt.allocPrint(allocator, "DSSEv1 {d} {s} {d} ", .{
        payload_type.len,
        payload_type,
        payload.len,
    });
    defer allocator.free(prefix);
    return std.mem.concat(allocator, u8, &.{ prefix, payload });
}

fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

fn encodeHexLower(bytes: []const u8, output: []u8) void {
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = digits[byte >> 4];
        output[index * 2 + 1] = digits[byte & 0x0f];
    }
}

fn decodeHexFixed(comptime len: usize, text: []const u8) ![len]u8 {
    if (text.len != len * 2) return error.InvalidHexLength;
    var result: [len]u8 = undefined;
    for (&result, 0..) |*byte, index| {
        const high = hexValue(text[index * 2]) orelse return error.InvalidHexDigit;
        const low = hexValue(text[index * 2 + 1]) orelse return error.InvalidHexDigit;
        byte.* = (high << 4) | low;
    }
    return result;
}

fn hexValue(byte: u8) ?u8 {
    if (byte >= '0' and byte <= '9') return byte - '0';
    if (byte >= 'a' and byte <= 'f') return byte - 'a' + 10;
    if (byte >= 'A' and byte <= 'F') return byte - 'A' + 10;
    return null;
}

const test_now: i64 = 1_000;
const test_targets = [_][]const u8{
    "bin/zigos-native-kernel.elf",
    "iso/zigos-native.iso",
};
const test_evidence = [_][]const u8{
    "release/artifact-digests.sha256",
    "release/provenance.dsse.json",
};
const test_digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const TestKey = struct {
    key_pair: Ed25519.KeyPair,
    public_key_hex: [Ed25519.PublicKey.encoded_length * 2]u8,
    key_id: [sha256_hex_len]u8,

    fn init(seed_byte: u8) !TestKey {
        const key_pair = try Ed25519.KeyPair.generateDeterministic([_]u8{seed_byte} ** Ed25519.KeyPair.seed_length);
        const public_key = key_pair.public_key.toBytes();
        var public_key_hex: [Ed25519.PublicKey.encoded_length * 2]u8 = undefined;
        encodeHexLower(&public_key, &public_key_hex);
        var key_id: [sha256_hex_len]u8 = undefined;
        _ = keyIdForEd25519(public_key, &key_id);
        return .{
            .key_pair = key_pair,
            .public_key_hex = public_key_hex,
            .key_id = key_id,
        };
    }
};

const TestSigner = struct {
    key_id: []const u8,
    key_pair: *const Ed25519.KeyPair,
    corrupt: bool = false,
};

const PolicyFixtureOptions = struct {
    policy_version: u64 = 7,
    minimum_release_sequence: u64 = 1,
    release_threshold: u32 = 1,
    first_status: []const u8 = "active",
    first_not_after: i64 = 4_500,
    revoke_first: bool = false,
    pqc_mode: []const u8 = "shadow",
};

fn testRootJson(
    allocator: std.mem.Allocator,
    first: *const TestKey,
    second: *const TestKey,
    threshold: u32,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":1,\"namespace\":\"zigos\",\"channel\":\"stable\",\"version\":3,\"issuedAt\":100,\"expiresAt\":5000,\"minimumPolicyVersion\":7,\"threshold\":{d},\"keys\":[{{\"keyId\":\"{s}\",\"algorithm\":\"ed25519\",\"publicKey\":\"{s}\"}},{{\"keyId\":\"{s}\",\"algorithm\":\"ed25519\",\"publicKey\":\"{s}\"}}]}}",
        .{ threshold, first.key_id, first.public_key_hex, second.key_id, second.public_key_hex },
    );
}

fn testVerifiedRoot(
    allocator: std.mem.Allocator,
    first: *const TestKey,
    second: *const TestKey,
    threshold: u32,
) !VerifiedRoot {
    const source = try testRootJson(allocator, first, second, threshold);
    var digest: [sha256_hex_len]u8 = undefined;
    _ = sha256Hex(source, &digest);
    return verifyRootMetadata(allocator, source, &digest, test_now);
}

fn testPolicyJson(
    allocator: std.mem.Allocator,
    first: *const TestKey,
    second: *const TestKey,
    options: PolicyFixtureOptions,
) ![]u8 {
    const revocations = if (options.revoke_first)
        try std.fmt.allocPrint(
            allocator,
            "[{{\"keyId\":\"{s}\",\"generation\":1,\"revokedAt\":200,\"reason\":\"compromised test key\"}}]",
            .{first.key_id},
        )
    else
        "[]";
    return std.fmt.allocPrint(
        allocator,
        "{{\"rootVersion\":3,\"policyVersion\":{d},\"minimumReleaseSequence\":{d},\"issuedAt\":200,\"expiresAt\":4000,\"releaseRole\":{{\"threshold\":{d},\"keyIds\":[\"{s}\",\"{s}\"]}},\"releaseKeys\":[{{\"keyId\":\"{s}\",\"algorithm\":\"ed25519\",\"generation\":1,\"status\":\"{s}\",\"custody\":\"hardware_test_hsm\",\"hardwareBacked\":true,\"notBefore\":100,\"notAfter\":{d},\"publicKey\":\"{s}\"}},{{\"keyId\":\"{s}\",\"algorithm\":\"ed25519\",\"generation\":2,\"status\":\"active\",\"custody\":\"hardware_test_hsm\",\"hardwareBacked\":true,\"notBefore\":100,\"notAfter\":4500,\"publicKey\":\"{s}\"}}],\"revocations\":{s},\"artifactProfile\":{{\"profileId\":\"native-release-v1\",\"exactTargets\":[\"bin/zigos-native-kernel.elf\",\"iso/zigos-native.iso\"],\"exactEvidence\":[\"release/artifact-digests.sha256\",\"release/provenance.dsse.json\"]}},\"pqcPolicy\":{{\"mode\":\"{s}\",\"requiredAlgorithm\":\"ml-dsa-65\",\"fipsValidatedRequired\":true}}}}",
        .{
            options.policy_version,
            options.minimum_release_sequence,
            options.release_threshold,
            first.key_id,
            second.key_id,
            first.key_id,
            options.first_status,
            options.first_not_after,
            first.public_key_hex,
            second.key_id,
            second.public_key_hex,
            revocations,
            options.pqc_mode,
        },
    );
}

fn testEnvelope(
    allocator: std.mem.Allocator,
    payload_type: []const u8,
    embedded_payload: []const u8,
    signed_payload: ?[]const u8,
    signers: []const TestSigner,
) ![]u8 {
    const encoded_size = std.base64.standard.Encoder.calcSize(embedded_payload.len);
    const encoded_payload = try allocator.alloc(u8, encoded_size);
    _ = std.base64.standard.Encoder.encode(encoded_payload, embedded_payload);

    const signing_payload = signed_payload orelse embedded_payload;
    const pae = try dssePreauthEncoding(allocator, payload_type, signing_payload);
    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    try output.writer.print("{{\"payloadType\":\"{s}\",\"payload\":\"{s}\",\"signatures\":[", .{
        payload_type,
        encoded_payload,
    });
    for (signers, 0..) |signer, index| {
        var signature = (try signer.key_pair.sign(pae, null)).toBytes();
        if (signer.corrupt) signature[0] ^= 0x80;
        const signature_size = std.base64.standard.Encoder.calcSize(signature.len);
        const encoded_signature = try allocator.alloc(u8, signature_size);
        _ = std.base64.standard.Encoder.encode(encoded_signature, &signature);
        if (index != 0) try output.writer.writeAll(",");
        try output.writer.print("{{\"keyid\":\"{s}\",\"sig\":\"{s}\"}}", .{ signer.key_id, encoded_signature });
    }
    try output.writer.writeAll("]}");
    return output.toOwnedSlice();
}

fn testVerifiedPolicy(
    allocator: std.mem.Allocator,
    root: *const VerifiedRoot,
    root_signer: *const TestKey,
    first_release: *const TestKey,
    second_release: *const TestKey,
    options: PolicyFixtureOptions,
) !VerifiedPolicy {
    const payload = try testPolicyJson(allocator, first_release, second_release, options);
    const envelope = try testEnvelope(allocator, trust_policy_payload_type, payload, null, &.{.{
        .key_id = &root_signer.key_id,
        .key_pair = &root_signer.key_pair,
    }});
    return verifyTrustPolicy(allocator, envelope, root, test_now, &test_targets, &test_evidence);
}

fn testManifestJson(
    allocator: std.mem.Allocator,
    target_records: []const u8,
    evidence_records: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"policyVersion\":7,\"profileId\":\"native-release-v1\",\"releaseSequence\":42,\"issuedAt\":300,\"expiresAt\":2000,\"source\":{{\"repository\":\"https://example.invalid/zigos\",\"changeId\":\"change-1\",\"commitId\":\"0123456789abcdef\"}},\"build\":{{\"zigVersion\":\"0.16.0\",\"target\":\"x86_64-freestanding\",\"optimizeMode\":\"ReleaseFast\",\"builderId\":\"release-builder\"}},\"targets\":{s},\"evidence\":{s}}}",
        .{ target_records, evidence_records },
    );
}

fn validTargetRecords() []const u8 {
    return "[{\"path\":\"bin/zigos-native-kernel.elf\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":123},{\"path\":\"iso/zigos-native.iso\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":456}]";
}

fn validEvidenceRecords() []const u8 {
    return "[{\"path\":\"release/artifact-digests.sha256\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":12},{\"path\":\"release/provenance.dsse.json\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":34}]";
}

test "threshold one-of-two root and release roles authenticate" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(1);
    const root_second = try TestKey.init(2);
    const release_first = try TestKey.init(3);
    const release_second = try TestKey.init(4);

    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    var policy = try testVerifiedPolicy(allocator, &root, &root_second, &release_first, &release_second, .{});
    defer policy.deinit();
    const manifest_payload = try testManifestJson(allocator, validTargetRecords(), validEvidenceRecords());
    const manifest_envelope = try testEnvelope(allocator, release_payload_type, manifest_payload, null, &.{.{
        .key_id = &release_second.key_id,
        .key_pair = &release_second.key_pair,
    }});
    var manifest = try verifyReleaseManifest(allocator, manifest_envelope, &policy, test_now, &test_targets, &test_evidence);
    defer manifest.deinit();
    try std.testing.expectEqual(@as(usize, 1), policy.root_signer_count);
    try std.testing.expectEqual(@as(usize, 1), manifest.release_signer_count);
    try std.testing.expectEqual(@as(u64, 42), manifest.manifest().releaseSequence);
}

test "duplicate signer cannot inflate a root threshold" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(10);
    const root_second = try TestKey.init(11);
    const release_first = try TestKey.init(12);
    const release_second = try TestKey.init(13);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 2);
    defer root.deinit();
    const payload = try testPolicyJson(allocator, &release_first, &release_second, .{});
    const envelope = try testEnvelope(allocator, trust_policy_payload_type, payload, null, &.{
        .{ .key_id = &root_first.key_id, .key_pair = &root_first.key_pair },
        .{ .key_id = &root_first.key_id, .key_pair = &root_first.key_pair },
    });
    try std.testing.expectError(
        error.DuplicateSigner,
        verifyTrustPolicy(allocator, envelope, &root, test_now, &test_targets, &test_evidence),
    );
}

test "unknown and invalid extra policy signers fail closed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(20);
    const root_second = try TestKey.init(21);
    const unknown = try TestKey.init(22);
    const release_first = try TestKey.init(23);
    const release_second = try TestKey.init(24);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    const payload = try testPolicyJson(allocator, &release_first, &release_second, .{});

    const unknown_envelope = try testEnvelope(allocator, trust_policy_payload_type, payload, null, &.{
        .{ .key_id = &root_first.key_id, .key_pair = &root_first.key_pair },
        .{ .key_id = &unknown.key_id, .key_pair = &unknown.key_pair },
    });
    try std.testing.expectError(
        error.UnknownSigner,
        verifyTrustPolicy(allocator, unknown_envelope, &root, test_now, &test_targets, &test_evidence),
    );

    const invalid_envelope = try testEnvelope(allocator, trust_policy_payload_type, payload, null, &.{
        .{ .key_id = &root_first.key_id, .key_pair = &root_first.key_pair },
        .{ .key_id = &root_second.key_id, .key_pair = &root_second.key_pair, .corrupt = true },
    });
    try std.testing.expectError(
        error.InvalidSignature,
        verifyTrustPolicy(allocator, invalid_envelope, &root, test_now, &test_targets, &test_evidence),
    );
}

test "payload type confusion and signed policy tampering are rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(30);
    const root_second = try TestKey.init(31);
    const release_first = try TestKey.init(32);
    const release_second = try TestKey.init(33);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    const original = try testPolicyJson(allocator, &release_first, &release_second, .{});

    const confused = try testEnvelope(allocator, release_payload_type, original, null, &.{.{
        .key_id = &root_first.key_id,
        .key_pair = &root_first.key_pair,
    }});
    try std.testing.expectError(
        error.PayloadTypeMismatch,
        verifyTrustPolicy(allocator, confused, &root, test_now, &test_targets, &test_evidence),
    );

    const tampered = try testPolicyJson(allocator, &release_first, &release_second, .{ .release_threshold = 2 });
    const tampered_envelope = try testEnvelope(allocator, trust_policy_payload_type, tampered, original, &.{.{
        .key_id = &root_first.key_id,
        .key_pair = &root_first.key_pair,
    }});
    try std.testing.expectError(
        error.InvalidSignature,
        verifyTrustPolicy(allocator, tampered_envelope, &root, test_now, &test_targets, &test_evidence),
    );
}

test "required PQC mode fails closed without a validated provider" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(34);
    const root_second = try TestKey.init(35);
    const release_first = try TestKey.init(36);
    const release_second = try TestKey.init(37);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    const payload = try testPolicyJson(allocator, &release_first, &release_second, .{ .pqc_mode = "required" });
    const envelope = try testEnvelope(allocator, trust_policy_payload_type, payload, null, &.{.{
        .key_id = &root_first.key_id,
        .key_pair = &root_first.key_pair,
    }});
    try std.testing.expectError(
        error.RequiredPqcVerificationUnsupported,
        verifyTrustPolicy(allocator, envelope, &root, test_now, &test_targets, &test_evidence),
    );
}

test "revoked and expired release signers are rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(40);
    const root_second = try TestKey.init(41);
    const release_first = try TestKey.init(42);
    const release_second = try TestKey.init(43);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    const manifest_payload = try testManifestJson(allocator, validTargetRecords(), validEvidenceRecords());

    var revoked_policy = try testVerifiedPolicy(
        allocator,
        &root,
        &root_first,
        &release_first,
        &release_second,
        .{ .revoke_first = true },
    );
    defer revoked_policy.deinit();
    const revoked_envelope = try testEnvelope(allocator, release_payload_type, manifest_payload, null, &.{.{
        .key_id = &release_first.key_id,
        .key_pair = &release_first.key_pair,
    }});
    try std.testing.expectError(
        error.ReleaseKeyRevoked,
        verifyReleaseManifest(allocator, revoked_envelope, &revoked_policy, test_now, &test_targets, &test_evidence),
    );

    var expired_policy = try testVerifiedPolicy(
        allocator,
        &root,
        &root_first,
        &release_first,
        &release_second,
        .{ .first_not_after = 900 },
    );
    defer expired_policy.deinit();
    const expired_envelope = try testEnvelope(allocator, release_payload_type, manifest_payload, null, &.{.{
        .key_id = &release_first.key_id,
        .key_pair = &release_first.key_pair,
    }});
    try std.testing.expectError(
        error.ReleaseKeyExpired,
        verifyReleaseManifest(allocator, expired_envelope, &expired_policy, test_now, &test_targets, &test_evidence),
    );
}

test "duplicate release signer cannot inflate a release threshold" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(44);
    const root_second = try TestKey.init(45);
    const release_first = try TestKey.init(46);
    const release_second = try TestKey.init(47);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    var policy = try testVerifiedPolicy(
        allocator,
        &root,
        &root_first,
        &release_first,
        &release_second,
        .{ .release_threshold = 2 },
    );
    defer policy.deinit();
    const payload = try testManifestJson(allocator, validTargetRecords(), validEvidenceRecords());
    const envelope = try testEnvelope(allocator, release_payload_type, payload, null, &.{
        .{ .key_id = &release_first.key_id, .key_pair = &release_first.key_pair },
        .{ .key_id = &release_first.key_id, .key_pair = &release_first.key_pair },
    });
    try std.testing.expectError(
        error.DuplicateSigner,
        verifyReleaseManifest(allocator, envelope, &policy, test_now, &test_targets, &test_evidence),
    );
}

test "unknown and invalid extra release signers fail closed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(48);
    const root_second = try TestKey.init(49);
    const release_first = try TestKey.init(54);
    const release_second = try TestKey.init(55);
    const unknown = try TestKey.init(56);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    var policy = try testVerifiedPolicy(allocator, &root, &root_first, &release_first, &release_second, .{});
    defer policy.deinit();
    const payload = try testManifestJson(allocator, validTargetRecords(), validEvidenceRecords());

    const unknown_envelope = try testEnvelope(allocator, release_payload_type, payload, null, &.{
        .{ .key_id = &release_first.key_id, .key_pair = &release_first.key_pair },
        .{ .key_id = &unknown.key_id, .key_pair = &unknown.key_pair },
    });
    try std.testing.expectError(
        error.UnknownOrUnauthorizedSigner,
        verifyReleaseManifest(allocator, unknown_envelope, &policy, test_now, &test_targets, &test_evidence),
    );

    const invalid_envelope = try testEnvelope(allocator, release_payload_type, payload, null, &.{
        .{ .key_id = &release_first.key_id, .key_pair = &release_first.key_pair },
        .{ .key_id = &release_second.key_id, .key_pair = &release_second.key_pair, .corrupt = true },
    });
    try std.testing.expectError(
        error.InvalidSignature,
        verifyReleaseManifest(allocator, invalid_envelope, &policy, test_now, &test_targets, &test_evidence),
    );
}

test "manifest requires the exact target and evidence sets" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(50);
    const root_second = try TestKey.init(51);
    const release_first = try TestKey.init(52);
    const release_second = try TestKey.init(53);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    var policy = try testVerifiedPolicy(allocator, &root, &root_first, &release_first, &release_second, .{});
    defer policy.deinit();

    const missing_payload = try testManifestJson(
        allocator,
        "[{\"path\":\"bin/zigos-native-kernel.elf\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":123}]",
        validEvidenceRecords(),
    );
    const missing_envelope = try testEnvelope(allocator, release_payload_type, missing_payload, null, &.{.{
        .key_id = &release_first.key_id,
        .key_pair = &release_first.key_pair,
    }});
    try std.testing.expectError(
        error.ArtifactSetMismatch,
        verifyReleaseManifest(allocator, missing_envelope, &policy, test_now, &test_targets, &test_evidence),
    );

    const extra_payload = try testManifestJson(
        allocator,
        "[{\"path\":\"bin/zigos-native-kernel.elf\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":123},{\"path\":\"iso/zigos-native.iso\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":456},{\"path\":\"bin/extra\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":1}]",
        validEvidenceRecords(),
    );
    const extra_envelope = try testEnvelope(allocator, release_payload_type, extra_payload, null, &.{.{
        .key_id = &release_first.key_id,
        .key_pair = &release_first.key_pair,
    }});
    try std.testing.expectError(
        error.ArtifactSetMismatch,
        verifyReleaseManifest(allocator, extra_envelope, &policy, test_now, &test_targets, &test_evidence),
    );

    const duplicate_payload = try testManifestJson(
        allocator,
        "[{\"path\":\"bin/zigos-native-kernel.elf\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":123},{\"path\":\"bin/zigos-native-kernel.elf\",\"sha256\":\"" ++ test_digest ++ "\",\"sizeBytes\":456}]",
        validEvidenceRecords(),
    );
    const duplicate_envelope = try testEnvelope(allocator, release_payload_type, duplicate_payload, null, &.{.{
        .key_id = &release_first.key_id,
        .key_pair = &release_first.key_pair,
    }});
    try std.testing.expectError(
        error.DuplicateArtifactPath,
        verifyReleaseManifest(allocator, duplicate_envelope, &policy, test_now, &test_targets, &test_evidence),
    );
}

test "release signature verification precedes manifest payload parsing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(60);
    const root_second = try TestKey.init(61);
    const release_first = try TestKey.init(62);
    const release_second = try TestKey.init(63);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();
    var policy = try testVerifiedPolicy(allocator, &root, &root_first, &release_first, &release_second, .{});
    defer policy.deinit();
    const envelope = try testEnvelope(allocator, release_payload_type, "{not-json", null, &.{.{
        .key_id = &release_first.key_id,
        .key_pair = &release_first.key_pair,
        .corrupt = true,
    }});
    try std.testing.expectError(
        error.InvalidSignature,
        verifyReleaseManifest(allocator, envelope, &policy, test_now, &test_targets, &test_evidence),
    );
}

test "root digest is checked before strict JSON parsing" {
    const allocator = std.testing.allocator;
    var incorrect_digest = [_]u8{'0'} ** sha256_hex_len;
    try std.testing.expectError(
        error.RootDigestMismatch,
        verifyRootMetadata(allocator, "{not-json", &incorrect_digest, test_now),
    );
}

test "root JSON rejects unknown and duplicate fields" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(70);
    const root_second = try TestKey.init(71);
    const valid = try testRootJson(allocator, &root_first, &root_second, 1);

    const unknown = try std.fmt.allocPrint(allocator, "{s},\"unexpected\":true}}", .{valid[0 .. valid.len - 1]});
    var unknown_digest: [sha256_hex_len]u8 = undefined;
    _ = sha256Hex(unknown, &unknown_digest);
    try std.testing.expectError(
        error.UnknownField,
        verifyRootMetadata(allocator, unknown, &unknown_digest, test_now),
    );

    const duplicate = try std.fmt.allocPrint(allocator, "{s},\"version\":4}}", .{valid[0 .. valid.len - 1]});
    var duplicate_digest: [sha256_hex_len]u8 = undefined;
    _ = sha256Hex(duplicate, &duplicate_digest);
    try std.testing.expectError(
        error.DuplicateField,
        verifyRootMetadata(allocator, duplicate, &duplicate_digest, test_now),
    );
}

test "root public keys require canonical lowercase hex" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(72);
    const root_second = try TestKey.init(73);
    const valid = try testRootJson(allocator, &root_first, &root_second, 1);
    const noncanonical = try allocator.dupe(u8, valid);
    const marker = "\"publicKey\":\"";
    const key_start = std.mem.indexOf(u8, noncanonical, marker).? + marker.len;
    var changed = false;
    for (noncanonical[key_start .. key_start + Ed25519.PublicKey.encoded_length * 2]) |*byte| {
        if (byte.* >= 'a' and byte.* <= 'f') {
            byte.* -= 'a' - 'A';
            changed = true;
            break;
        }
    }
    try std.testing.expect(changed);

    var digest: [sha256_hex_len]u8 = undefined;
    _ = sha256Hex(noncanonical, &digest);
    try std.testing.expectError(
        error.InvalidPublicKey,
        verifyRootMetadata(allocator, noncanonical, &digest, test_now),
    );
}

test "out-of-band and policy checkpoints reject first-use rollback" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_first = try TestKey.init(74);
    const root_second = try TestKey.init(75);
    const release_first = try TestKey.init(76);
    const release_second = try TestKey.init(77);
    var root = try testVerifiedRoot(allocator, &root_first, &root_second, 1);
    defer root.deinit();

    const stale_policy_payload = try testPolicyJson(
        allocator,
        &release_first,
        &release_second,
        .{ .policy_version = 6 },
    );
    const stale_policy_envelope = try testEnvelope(
        allocator,
        trust_policy_payload_type,
        stale_policy_payload,
        null,
        &.{.{ .key_id = &root_first.key_id, .key_pair = &root_first.key_pair }},
    );
    try std.testing.expectError(
        error.PolicyBelowRootCheckpoint,
        verifyTrustPolicy(allocator, stale_policy_envelope, &root, test_now, &test_targets, &test_evidence),
    );

    var policy = try testVerifiedPolicy(
        allocator,
        &root,
        &root_first,
        &release_first,
        &release_second,
        .{ .minimum_release_sequence = 43 },
    );
    defer policy.deinit();
    const manifest_payload = try testManifestJson(allocator, validTargetRecords(), validEvidenceRecords());
    const manifest_envelope = try testEnvelope(
        allocator,
        release_payload_type,
        manifest_payload,
        null,
        &.{.{ .key_id = &release_first.key_id, .key_pair = &release_first.key_pair }},
    );
    try std.testing.expectError(
        error.ReleaseBelowPolicyCheckpoint,
        verifyReleaseManifest(allocator, manifest_envelope, &policy, test_now, &test_targets, &test_evidence),
    );
}
