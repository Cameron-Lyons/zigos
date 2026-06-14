const std = @import("std");
const ascii = @import("../kernel/utils/ascii.zig");
const hex = @import("../native/core/hex.zig");
const manifest = @import("../native/policy/manifest.zig");
const units = @import("../native/core/units.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const containsAsciiIgnoreCase = ascii.containsIgnoreCase;

const max_release_metadata_bytes: usize = units.mebibytes(16);
const max_artifact_bytes: usize = units.gibibytes(1);
const stdout_buffer_bytes: usize = units.kibibytes(1);
const revoked_generation_key_buffer_bytes: usize = 128;
const sha256_hex_len: usize = hex.encodedLen(Sha256.digest_length);
const ed25519_public_key_hex_len: usize = hex.encodedLen(Ed25519.PublicKey.encoded_length);
const ml_dsa65_public_key_hex_len: usize = hex.encodedLen(manifest.ML_DSA65_PUBLIC_KEY_BYTES);
const release_key_algorithm_ed25519 = "ed25519";
const release_key_algorithm_ml_dsa65 = "ml-dsa-65";
const release_key_algorithm_ml_dsa65_fips204 = "ml-dsa-65-fips204";
const release_key_encoding_ed25519 = "hex-ed25519-raw";
const release_key_encoding_ml_dsa65 = "hex-ml-dsa-65-raw";
const fips_204_standard = "FIPS 204";
const fips_validation_text = "validated";

pub const VerifyOptions = struct {
    require_public_release: bool = true,
};

pub const VerificationSummary = struct {
    artifacts: usize = 0,
    dsse_envelopes: usize = 0,
    dsse_signatures: usize = 0,
    pqc_signatures: usize = 0,
    slsa_subjects: usize = 0,
    measurements: usize = 0,
    reproducible_digests: usize = 0,
};

const PqcRolloutMode = enum {
    shadow,
    canary,
    required,
};

const PostQuantumPolicy = struct {
    mode: PqcRolloutMode,
};

const ActualArtifact = struct {
    digest_hex: []const u8,
    size_bytes: u64,
};

const ReleaseKey = struct {
    key_id: []const u8,
    algorithm: []const u8,
    public_key: [Ed25519.PublicKey.encoded_length]u8 = [_]u8{0} ** Ed25519.PublicKey.encoded_length,
    generation: u64,
    status: []const u8,
    custody: []const u8,
    hardware_backed: bool,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const io = init.io;

    if (args.len == 2 and (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "help"))) {
        try printUsage(io);
        return;
    }

    if (args.len < 2 or args.len > 3) {
        try printUsage(io);
        return error.InvalidArguments;
    }

    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const release_dir = args[1];
    const artifact_root = if (args.len == 3) args[2] else ".";
    const summary = verifyReleaseBundle(allocator, io, release_dir, artifact_root, .{}) catch |err| {
        std.debug.print("release verification failed: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    var stdout_buffer: [stdout_buffer_bytes]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    try stdout_writer.interface.print(
        "Release verification OK: {d} artifacts, {d} DSSE envelopes, {d} signatures, {d} PQC signatures, {d} SLSA subjects, {d} measurements, {d} reproducible digests\n",
        .{
            summary.artifacts,
            summary.dsse_envelopes,
            summary.dsse_signatures,
            summary.pqc_signatures,
            summary.slsa_subjects,
            summary.measurements,
            summary.reproducible_digests,
        },
    );
    try stdout_writer.interface.flush();
}

fn printUsage(io: std.Io) !void {
    var stdout_buffer: [stdout_buffer_bytes]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    try stdout_writer.interface.print(
        \\usage:
        \\  zigos-verify-release <release-security-dir> [artifact-root]
        \\
        \\Verifies artifact digests, DSSE in-toto/SLSA provenance, release key
        \\revocation metadata, artifact measurements, and reproducible-build
        \\digests for a downloaded Zigos release bundle. Post-quantum keyring
        \\policy is enforced fail-closed: required ML-DSA rollout needs a
        \\validated verifier provider.
        \\
    , .{});
    try stdout_writer.interface.flush();
}

pub fn verifyReleaseBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
    release_dir: []const u8,
    artifact_root: []const u8,
    options: VerifyOptions,
) !VerificationSummary {
    var summary = VerificationSummary{};

    var expected_digests = std.StringHashMap([]const u8).init(allocator);
    try loadDigestManifest(allocator, io, try joinPath(allocator, release_dir, "artifact-digests.sha256"), &expected_digests);
    if (expected_digests.count() == 0) return error.ReleaseDigestManifestEmpty;

    var actual_artifacts = std.StringHashMap(ActualArtifact).init(allocator);
    try verifyArtifactFiles(allocator, io, artifact_root, &expected_digests, &actual_artifacts, &summary);

    const keyring = try parseJsonFile(allocator, io, try joinPath(allocator, release_dir, "release-keyring.json"));
    const pqc_policy = try validateKeyringPolicy(keyring, options);
    const revoked = try parseJsonFile(allocator, io, try joinPath(allocator, release_dir, "revoked-release-keys.json"));

    try verifyDsseProvenance(
        allocator,
        io,
        try joinPath(allocator, release_dir, "provenance.dsse.intoto.jsonl"),
        keyring,
        revoked,
        pqc_policy,
        &expected_digests,
        &summary,
    );
    if (summary.dsse_envelopes == 0 or summary.slsa_subjects != expected_digests.count()) {
        return error.SlsaSubjectCoverageMismatch;
    }

    try verifyArtifactMeasurements(
        allocator,
        io,
        try joinPath(allocator, release_dir, "artifact-measurements.json"),
        &expected_digests,
        &actual_artifacts,
        &summary,
    );
    if (summary.measurements != expected_digests.count()) return error.ArtifactMeasurementCoverageMismatch;

    try verifyReproducibleBuildDigests(
        allocator,
        io,
        release_dir,
        &expected_digests,
        &summary,
    );
    try verifySpdxSbom(allocator, io, try joinPath(allocator, release_dir, "sbom.spdx.json"));

    return summary;
}

fn loadDigestManifest(
    allocator: std.mem.Allocator,
    io: std.Io,
    manifest_path: []const u8,
    out: *std.StringHashMap([]const u8),
) !void {
    const source = try readFileAlloc(io, manifest_path, allocator, max_release_metadata_bytes);
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        const separator = std.mem.indexOf(u8, line, "  ") orelse return error.InvalidDigestManifestLine;
        const digest = line[0..separator];
        const path = std.mem.trimStart(u8, line[separator + 2 ..], " ");
        if (!isSha256Hex(digest)) return error.InvalidDigestHex;
        try validateRelativeArtifactPath(path);
        const gop = try out.getOrPut(try allocator.dupe(u8, path));
        if (gop.found_existing) return error.DuplicateDigestEntry;
        gop.value_ptr.* = try allocator.dupe(u8, digest);
    }
}

fn verifyArtifactFiles(
    allocator: std.mem.Allocator,
    io: std.Io,
    artifact_root: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    actual_artifacts: *std.StringHashMap(ActualArtifact),
    summary: *VerificationSummary,
) !void {
    var it = expected_digests.iterator();
    while (it.next()) |entry| {
        const artifact_path = try joinPath(allocator, artifact_root, entry.key_ptr.*);
        const data = try readFileAlloc(io, artifact_path, allocator, max_artifact_bytes);
        const actual_digest = try sha256HexAlloc(allocator, data);
        if (!std.mem.eql(u8, actual_digest, entry.value_ptr.*)) return error.ArtifactDigestMismatch;
        try actual_artifacts.put(entry.key_ptr.*, .{
            .digest_hex = actual_digest,
            .size_bytes = data.len,
        });
        summary.artifacts += 1;
    }
}

fn validateKeyringPolicy(keyring: std.json.Value, options: VerifyOptions) !PostQuantumPolicy {
    if (try boolField(keyring, "public_release_allowed")) |allowed| {
        if (options.require_public_release and !allowed) return error.PublicReleaseNotAllowedByKeyring;
    } else return error.KeyringMissingPublicReleasePolicy;

    const boundary = try stringField(keyring, "required_provider_boundary");
    if (!containsTrustBoundary(boundary)) return error.KeyringMissingHardwareProviderBoundary;

    const keys = try arrayField(keyring, "keys");
    if (keys.len == 0) return error.KeyringHasNoKeys;

    return validatePostQuantumPolicy(keyring);
}

fn validatePostQuantumPolicy(keyring: std.json.Value) !PostQuantumPolicy {
    const policy = try objectField(keyring, "post_quantum_policy");
    const mode_text = try stringField(policy, "mode");
    const mode = parsePqcRolloutMode(mode_text) orelse return error.InvalidPqcRolloutMode;

    if (!((try boolField(policy, "fips_validated_required")) orelse false)) return error.PqcPolicyMustRequireFipsValidation;
    if (!((try boolField(policy, "fips_140_validation_required")) orelse false)) return error.PqcPolicyMustRequireValidatedModule;
    if (!containsAsciiIgnoreCase(try stringField(policy, "production_signature_algorithm"), "ml-dsa")) {
        return error.PqcPolicyMissingMlDsaSignaturePath;
    }
    if (!containsAsciiIgnoreCase(try stringField(policy, "key_establishment_algorithm"), "ml-kem")) {
        return error.PqcPolicyMissingMlKemPath;
    }
    if (!containsAsciiIgnoreCase(try stringField(policy, "backup_signature_algorithm"), "slh-dsa")) {
        return error.PqcPolicyMissingSlhDsaPath;
    }
    const hybrid_transition = try stringField(policy, "hybrid_transition");
    if (!containsAsciiIgnoreCase(hybrid_transition, "ed25519+ml-dsa65") or
        !containsAsciiIgnoreCase(hybrid_transition, "preview"))
    {
        return error.PqcPolicyMissingHybridPreviewBoundary;
    }

    const standards = try arrayField(policy, "standards");
    var has_fips_203 = false;
    var has_fips_204 = false;
    var has_fips_205 = false;
    for (standards) |standard| {
        const fips = try stringField(standard, "fips");
        const algorithm = try stringField(standard, "algorithm");
        if (std.mem.eql(u8, fips, "FIPS 203") and containsAsciiIgnoreCase(algorithm, "ML-KEM")) has_fips_203 = true;
        if (std.mem.eql(u8, fips, "FIPS 204") and containsAsciiIgnoreCase(algorithm, "ML-DSA")) has_fips_204 = true;
        if (std.mem.eql(u8, fips, "FIPS 205") and containsAsciiIgnoreCase(algorithm, "SLH-DSA")) has_fips_205 = true;
    }
    if (!has_fips_203 or !has_fips_204 or !has_fips_205) return error.PqcPolicyMissingNistStandards;

    const rollout = try arrayField(policy, "rollout");
    if (rollout.len < 3) return error.PqcPolicyMissingMeasuredRollout;
    if (!stringValueArrayContainsSubstring(rollout, "shadow") or
        !stringValueArrayContainsSubstring(rollout, "canary") or
        !stringValueArrayContainsSubstring(rollout, "required"))
    {
        return error.PqcPolicyMissingMeasuredRollout;
    }

    return .{ .mode = mode };
}

fn parsePqcRolloutMode(value: []const u8) ?PqcRolloutMode {
    if (std.mem.eql(u8, value, "shadow")) return .shadow;
    if (std.mem.eql(u8, value, "canary")) return .canary;
    if (std.mem.eql(u8, value, "required")) return .required;
    return null;
}

fn verifyDsseProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    dsse_path: []const u8,
    keyring: std.json.Value,
    revoked: std.json.Value,
    pqc_policy: PostQuantumPolicy,
    expected_digests: *const std.StringHashMap([]const u8),
    summary: *VerificationSummary,
) !void {
    const source = try readFileAlloc(io, dsse_path, allocator, max_release_metadata_bytes);
    var seen_subjects = std.StringHashMap(void).init(allocator);
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
        const envelope = parsed.value;
        const payload_type = try stringField(envelope, "payloadType");
        if (!std.mem.eql(u8, payload_type, "application/vnd.in-toto+json")) return error.InvalidDssePayloadType;
        const payload = try decodeBase64Alloc(allocator, try stringField(envelope, "payload"));
        const pae = try dssePreauthEncoding(allocator, payload_type, payload);
        const signatures = try arrayField(envelope, "signatures");
        if (signatures.len == 0) return error.DsseEnvelopeMissingSignatures;

        var envelope_pqc_signatures: usize = 0;
        for (signatures) |signature_value| {
            const key_id = try stringField(signature_value, "keyid");
            const key = try releaseKeyForId(allocator, keyring, key_id);
            try rejectRevokedKey(revoked, key);
            const signature_bytes = try decodeBase64Alloc(allocator, try stringField(signature_value, "sig"));
            try verifyReleaseSignature(key, signature_bytes, pae);
            summary.dsse_signatures += 1;
            if (isMlDsa65Algorithm(key.algorithm)) {
                summary.pqc_signatures += 1;
                envelope_pqc_signatures += 1;
            }
        }
        if (pqc_policy.mode == .required and envelope_pqc_signatures == 0) return error.PqcSignatureRequired;

        try verifySlsaStatement(allocator, payload, expected_digests, &seen_subjects, summary);
        summary.dsse_envelopes += 1;
    }
}

fn verifySlsaStatement(
    allocator: std.mem.Allocator,
    payload: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    seen_subjects: *std.StringHashMap(void),
    summary: *VerificationSummary,
) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    const statement = parsed.value;
    if (!std.mem.eql(u8, try stringField(statement, "_type"), "https://in-toto.io/Statement/v1")) {
        return error.InvalidInTotoStatementType;
    }
    if (!std.mem.eql(u8, try stringField(statement, "predicateType"), "https://slsa.dev/provenance/v1")) {
        return error.InvalidSlsaPredicateType;
    }
    const subjects = try arrayField(statement, "subject");
    if (subjects.len == 0) return error.SlsaStatementMissingSubjects;
    for (subjects) |subject| {
        const name = try stringField(subject, "name");
        const digest_object = try objectField(subject, "digest");
        const digest = try stringField(digest_object, "sha256");
        const expected_digest = expected_digests.get(name) orelse return error.SlsaSubjectUnknownArtifact;
        if (!std.mem.eql(u8, digest, expected_digest)) return error.SlsaSubjectDigestMismatch;
        const gop = try seen_subjects.getOrPut(name);
        if (gop.found_existing) return error.DuplicateSlsaSubject;
        summary.slsa_subjects += 1;
    }
}

fn verifyArtifactMeasurements(
    allocator: std.mem.Allocator,
    io: std.Io,
    measurements_path: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    actual_artifacts: *const std.StringHashMap(ActualArtifact),
    summary: *VerificationSummary,
) !void {
    const root = try parseJsonFile(allocator, io, measurements_path);
    if (!std.mem.eql(u8, try stringField(root, "measurement_algorithm"), "sha256")) {
        return error.InvalidMeasurementAlgorithm;
    }
    const artifacts = try arrayField(root, "artifacts");
    for (artifacts) |artifact| {
        const path = try stringField(artifact, "path");
        try validateRelativeArtifactPath(path);
        const sha256 = try stringField(artifact, "sha256");
        if (!std.mem.eql(u8, expected_digests.get(path) orelse return error.MeasurementUnknownArtifact, sha256)) {
            return error.MeasurementDigestMismatch;
        }
        const actual = actual_artifacts.get(path) orelse return error.MeasurementMissingDownloadedArtifact;
        if (!std.mem.eql(u8, actual.digest_hex, sha256)) return error.MeasurementDigestMismatch;
        const size_bytes = try integerField(artifact, "size_bytes");
        if (size_bytes < 0 or @as(u64, @intCast(size_bytes)) != actual.size_bytes) return error.MeasurementSizeMismatch;
        summary.measurements += 1;
    }
}

fn verifyReproducibleBuildDigests(
    allocator: std.mem.Allocator,
    io: std.Io,
    release_dir: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    summary: *VerificationSummary,
) !void {
    const root = try parseJsonFile(allocator, io, try joinPath(allocator, release_dir, "reproducible-build.json"));
    if (!std.mem.eql(u8, try stringField(root, "status"), "passed")) return error.ReproducibleBuildNotPassed;
    const manifest_field = try stringField(root, "digest_manifest");
    const manifest_name = std.fs.path.basename(manifest_field);
    var reproducible_digests = std.StringHashMap([]const u8).init(allocator);
    try loadDigestManifest(allocator, io, try joinPath(allocator, release_dir, manifest_name), &reproducible_digests);
    var it = reproducible_digests.iterator();
    while (it.next()) |entry| {
        const expected_digest = expected_digests.get(entry.key_ptr.*) orelse return error.ReproducibleDigestUnknownArtifact;
        if (!std.mem.eql(u8, expected_digest, entry.value_ptr.*)) return error.ReproducibleDigestMismatch;
        summary.reproducible_digests += 1;
    }
    if (summary.reproducible_digests == 0) return error.ReproducibleDigestManifestEmpty;
}

fn verifySpdxSbom(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    const root = try parseJsonFile(allocator, io, path);
    if (!std.mem.eql(u8, try stringField(root, "spdxVersion"), "SPDX-2.3")) return error.InvalidSpdxVersion;
}

fn releaseKeyForId(allocator: std.mem.Allocator, keyring: std.json.Value, key_id: []const u8) !ReleaseKey {
    const keys = try arrayField(keyring, "keys");
    for (keys) |key_value| {
        const candidate_id = try stringField(key_value, "key_id");
        if (!std.mem.eql(u8, candidate_id, key_id)) continue;
        const status = try stringField(key_value, "status");
        if (!std.mem.eql(u8, status, "active")) return error.ReleaseKeyNotActive;
        const algorithm = try stringField(key_value, "algorithm");
        const custody = try stringField(key_value, "custody");
        const hardware_backed = (try boolField(key_value, "hardware_backed")) orelse return error.ReleaseKeyMissingHardwareFlag;
        if (!hardware_backed) return error.ReleaseKeyNotHardwareBacked;
        if (!containsTrustBoundary(custody)) return error.ReleaseKeyCustodyNotHardwareBacked;

        const encoding = try stringField(key_value, "public_key_encoding");
        const public_key_hex = try stringField(key_value, "public_key");
        var public_key: [Ed25519.PublicKey.encoded_length]u8 = [_]u8{0} ** Ed25519.PublicKey.encoded_length;
        if (std.mem.eql(u8, algorithm, release_key_algorithm_ed25519)) {
            if (!std.mem.eql(u8, encoding, release_key_encoding_ed25519)) return error.UnsupportedReleaseKeyEncoding;
            public_key = try hex.decodeFixed(Ed25519.PublicKey.encoded_length, public_key_hex);
        } else if (isMlDsa65Algorithm(algorithm)) {
            if (!std.mem.eql(u8, encoding, release_key_encoding_ml_dsa65)) return error.UnsupportedReleaseKeyEncoding;
            if (public_key_hex.len != ml_dsa65_public_key_hex_len) return error.InvalidMlDsaPublicKeyLength;
            if (!hex.isText(public_key_hex)) return error.InvalidHexDigit;
            if (!std.mem.eql(u8, try stringField(key_value, "fips_standard"), fips_204_standard)) {
                return error.ReleaseKeyMissingFipsValidation;
            }
            if (!containsAsciiIgnoreCase(try stringField(key_value, "fips_validation"), fips_validation_text)) {
                return error.ReleaseKeyMissingFipsValidation;
            }
            if (!((try boolField(key_value, "fips_140_validated_module")) orelse false)) {
                return error.ReleaseKeyMissingFipsValidation;
            }
            const validation_certificate = try stringField(key_value, "validation_certificate");
            if (validation_certificate.len == 0 or std.mem.eql(u8, validation_certificate, "TBD")) {
                return error.ReleaseKeyMissingFipsValidation;
            }
        } else return error.UnsupportedReleaseKeyAlgorithm;

        return .{
            .key_id = try allocator.dupe(u8, key_id),
            .algorithm = algorithm,
            .public_key = public_key,
            .generation = @intCast(try integerField(key_value, "generation")),
            .status = status,
            .custody = custody,
            .hardware_backed = hardware_backed,
        };
    }
    return error.ReleaseKeyNotFound;
}

fn verifyReleaseSignature(key: ReleaseKey, signature_bytes: []const u8, message: []const u8) !void {
    if (std.mem.eql(u8, key.algorithm, release_key_algorithm_ed25519)) {
        if (signature_bytes.len != Ed25519.Signature.encoded_length) return error.InvalidEd25519SignatureLength;
        try verifyEd25519(key.public_key, signature_bytes[0..Ed25519.Signature.encoded_length].*, message);
        return;
    }
    if (isMlDsa65Algorithm(key.algorithm)) {
        if (signature_bytes.len != 3309) return error.InvalidMlDsaSignatureLength;
        return error.PqcVerifierUnavailable;
    }
    return error.UnsupportedReleaseKeyAlgorithm;
}

fn rejectRevokedKey(revoked: std.json.Value, key: ReleaseKey) !void {
    if (try revokedKeyIdContains(revoked, key.key_id)) return error.ReleaseKeyRevoked;
    if (try revokedGenerationContains(revoked, key.key_id, key.generation)) return error.ReleaseKeyGenerationRevoked;
}

fn revokedKeyIdContains(root: std.json.Value, key_id: []const u8) !bool {
    const revoked_keys = try arrayField(root, "revoked_keys");
    for (revoked_keys) |entry| switch (entry) {
        .string => |text| if (std.mem.eql(u8, text, key_id)) return true,
        .object => {
            const revoked_key_id = try stringField(entry, "key_id");
            if (std.mem.eql(u8, revoked_key_id, key_id)) return true;
        },
        else => return error.InvalidRevokedKeyEntry,
    };
    return false;
}

fn revokedGenerationContains(root: std.json.Value, key_id: []const u8, generation: u64) !bool {
    const revoked_generations = try arrayField(root, "revoked_generations");
    for (revoked_generations) |entry| switch (entry) {
        .string => |text| {
            var buffer: [revoked_generation_key_buffer_bytes]u8 = undefined;
            const expected = try std.fmt.bufPrint(&buffer, "{s}:{d}", .{ key_id, generation });
            if (std.mem.eql(u8, text, expected)) return true;
        },
        .object => {
            const revoked_key_id = try stringField(entry, "key_id");
            const revoked_generation = try integerField(entry, "generation");
            if (std.mem.eql(u8, revoked_key_id, key_id) and revoked_generation >= 0 and @as(u64, @intCast(revoked_generation)) == generation) {
                return true;
            }
        },
        else => return error.InvalidRevokedGenerationEntry,
    };
    return false;
}

fn parseJsonFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !std.json.Value {
    const source = try readFileAlloc(io, path, allocator, max_release_metadata_bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, source, .{});
    return parsed.value;
}

fn readFileAlloc(
    io: std.Io,
    path: []const u8,
    allocator: std.mem.Allocator,
    limit: usize,
) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(limit));
}

fn joinPath(allocator: std.mem.Allocator, base: []const u8, path: []const u8) ![]const u8 {
    return std.fs.path.join(allocator, &.{ base, path });
}

fn dssePreauthEncoding(allocator: std.mem.Allocator, payload_type: []const u8, payload: []const u8) ![]const u8 {
    const prefix = try std.fmt.allocPrint(
        allocator,
        "DSSEv1 {d} {s} {d} ",
        .{ payload_type.len, payload_type, payload.len },
    );
    return std.mem.concat(allocator, u8, &.{ prefix, payload });
}

fn verifyEd25519(public_key_bytes: [Ed25519.PublicKey.encoded_length]u8, signature_bytes: [Ed25519.Signature.encoded_length]u8, message: []const u8) !void {
    const public_key = try Ed25519.PublicKey.fromBytes(public_key_bytes);
    const signature = Ed25519.Signature.fromBytes(signature_bytes);
    try signature.verify(message, public_key);
}

fn sha256HexAlloc(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return hexAlloc(allocator, &digest);
}

fn hexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const output = try allocator.alloc(u8, hex.encodedLen(bytes.len));
    _ = try hex.encodeLower(bytes, output);
    return output;
}

fn decodeBase64Alloc(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(text);
    const output = try allocator.alloc(u8, size);
    try std.base64.standard.Decoder.decode(output, text);
    return output;
}

fn encodeBase64Alloc(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const size = std.base64.standard.Encoder.calcSize(bytes.len);
    const output = try allocator.alloc(u8, size);
    return std.base64.standard.Encoder.encode(output, bytes);
}

fn isSha256Hex(value: []const u8) bool {
    if (value.len != sha256_hex_len) return false;
    return hex.isText(value);
}

fn validateRelativeArtifactPath(path: []const u8) !void {
    if (path.len == 0) return error.EmptyArtifactPath;
    if (std.fs.path.isAbsolute(path)) return error.AbsoluteArtifactPathRejected;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return error.ParentArtifactPathRejected;
    }
}

fn containsTrustBoundary(value: []const u8) bool {
    return containsAsciiIgnoreCase(value, "tpm") or
        containsAsciiIgnoreCase(value, "secure enclave") or
        containsAsciiIgnoreCase(value, "hsm") or
        containsAsciiIgnoreCase(value, "kms");
}

fn isMlDsa65Algorithm(value: []const u8) bool {
    return std.mem.eql(u8, value, release_key_algorithm_ml_dsa65) or
        std.mem.eql(u8, value, release_key_algorithm_ml_dsa65_fips204);
}

fn stringValueArrayContainsSubstring(values: []std.json.Value, needle: []const u8) bool {
    for (values) |value| switch (value) {
        .string => |text| if (containsAsciiIgnoreCase(text, needle)) return true,
        else => {},
    };
    return false;
}

fn objectField(value: std.json.Value, name: []const u8) !std.json.Value {
    const field_value = field(value, name) orelse return error.JsonMissingField;
    return switch (field_value) {
        .object => field_value,
        else => error.JsonExpectedObject,
    };
}

fn arrayField(value: std.json.Value, name: []const u8) ![]std.json.Value {
    const field_value = field(value, name) orelse return error.JsonMissingField;
    return switch (field_value) {
        .array => |array| array.items,
        else => error.JsonExpectedArray,
    };
}

fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    const field_value = field(value, name) orelse return error.JsonMissingField;
    return switch (field_value) {
        .string => |text| text,
        else => error.JsonExpectedString,
    };
}

fn boolField(value: std.json.Value, name: []const u8) !?bool {
    const field_value = field(value, name) orelse return null;
    return switch (field_value) {
        .bool => |flag| flag,
        else => error.JsonExpectedBool,
    };
}

fn integerField(value: std.json.Value, name: []const u8) !i64 {
    const field_value = field(value, name) orelse return error.JsonMissingField;
    return switch (field_value) {
        .integer => |number| number,
        else => error.JsonExpectedInteger,
    };
}

fn field(value: std.json.Value, name: []const u8) ?std.json.Value {
    return switch (value) {
        .object => |object| object.get(name),
        else => null,
    };
}

test "customer release verifier accepts DSSE SLSA provenance measurements and reproducible digests" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const summary = try verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{});
    try std.testing.expectEqual(@as(usize, 1), summary.artifacts);
    try std.testing.expectEqual(@as(usize, 1), summary.dsse_envelopes);
    try std.testing.expectEqual(@as(usize, 1), summary.dsse_signatures);
    try std.testing.expectEqual(@as(usize, 1), summary.slsa_subjects);
    try std.testing.expectEqual(@as(usize, 1), summary.measurements);
    try std.testing.expectEqual(@as(usize, 1), summary.reproducible_digests);
}

test "customer release verifier rejects revoked DSSE keys" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", true, "shadow");

    try std.testing.expectError(
        error.ReleaseKeyRevoked,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier requires ML-DSA signatures when PQC rollout is required" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "required");

    try std.testing.expectError(
        error.PqcSignatureRequired,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

fn writeValidFixture(
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
    artifact_path: []const u8,
    revoked: bool,
    pqc_mode: []const u8,
) !void {
    const artifact_bytes = "bootable release bytes";
    try dir.writeFile(std.testing.io, .{ .sub_path = artifact_path, .data = artifact_bytes });
    const artifact_digest = try sha256HexAlloc(allocator, artifact_bytes);
    const measurement_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"measurement_algorithm\":\"sha256\",\"artifacts\":[{{\"path\":\"{s}\",\"sha256\":\"{s}\",\"size_bytes\":{d}}}]}}\n",
        .{ artifact_path, artifact_digest, artifact_bytes.len },
    );
    try dir.writeFile(std.testing.io, .{ .sub_path = "artifact-measurements.json", .data = measurement_json });

    const digest_manifest = try std.fmt.allocPrint(allocator, "{s}  {s}\n", .{ artifact_digest, artifact_path });
    try dir.writeFile(std.testing.io, .{ .sub_path = "artifact-digests.sha256", .data = digest_manifest });
    try dir.writeFile(std.testing.io, .{ .sub_path = "reproducible-artifact-digests.sha256", .data = digest_manifest });
    try dir.writeFile(std.testing.io, .{
        .sub_path = "reproducible-build.json",
        .data = "{\"schema_version\":1,\"status\":\"passed\",\"digest_manifest\":\"build/release-security/reproducible-artifact-digests.sha256\"}\n",
    });
    try dir.writeFile(std.testing.io, .{ .sub_path = "sbom.spdx.json", .data = "{\"spdxVersion\":\"SPDX-2.3\"}\n" });

    const key_pair = try Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** Ed25519.KeyPair.seed_length);
    const public_key = key_pair.public_key.toBytes();
    const public_key_hex = try hexAlloc(allocator, &public_key);
    const keyring_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"public_release_allowed\":true,\"required_provider_boundary\":\"cloud KMS release signing provider\",\"post_quantum_policy\":{{\"mode\":\"{s}\",\"fips_validated_required\":true,\"fips_140_validation_required\":true,\"production_signature_algorithm\":\"ml-dsa-65\",\"key_establishment_algorithm\":\"ml-kem-768\",\"backup_signature_algorithm\":\"slh-dsa-sha2-128s\",\"hybrid_transition\":\"ed25519 remains required; ed25519+ml-dsa65 is preview-only and never satisfies production FIPS 204 ML-DSA\",\"standards\":[{{\"fips\":\"FIPS 203\",\"algorithm\":\"ML-KEM\",\"scope\":\"key establishment\"}},{{\"fips\":\"FIPS 204\",\"algorithm\":\"ML-DSA\",\"scope\":\"digital signatures\"}},{{\"fips\":\"FIPS 205\",\"algorithm\":\"SLH-DSA\",\"scope\":\"hash-based signature fallback\"}}],\"rollout\":[\"shadow verifier measurement\",\"canary dual-signature release\",\"required public-release ML-DSA verification\"]}},\"keys\":[{{\"key_id\":\"fixture-key\",\"status\":\"active\",\"algorithm\":\"ed25519\",\"custody\":\"cloud_kms\",\"hardware_backed\":true,\"generation\":7,\"public_key_encoding\":\"hex-ed25519-raw\",\"public_key\":\"{s}\"}}]}}\n",
        .{ pqc_mode, public_key_hex },
    );
    try dir.writeFile(std.testing.io, .{ .sub_path = "release-keyring.json", .data = keyring_json });

    const revoked_json = if (revoked)
        "{\"schema_version\":1,\"revoked_keys\":[{\"key_id\":\"fixture-key\",\"reason\":\"test\"}],\"revoked_generations\":[]}\n"
    else
        "{\"schema_version\":1,\"revoked_keys\":[],\"revoked_generations\":[]}\n";
    try dir.writeFile(std.testing.io, .{ .sub_path = "revoked-release-keys.json", .data = revoked_json });

    const statement = try std.fmt.allocPrint(
        allocator,
        "{{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{{\"name\":\"{s}\",\"digest\":{{\"sha256\":\"{s}\"}}}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{{\"buildDefinition\":{{\"buildType\":\"fixture\"}}}}}}\n",
        .{ artifact_path, artifact_digest },
    );
    const payload_b64 = try encodeBase64Alloc(allocator, statement);
    const pae = try dssePreauthEncoding(allocator, "application/vnd.in-toto+json", statement);
    const signature = (try key_pair.sign(pae, null)).toBytes();
    const signature_b64 = try encodeBase64Alloc(allocator, &signature);
    const envelope_json = try std.fmt.allocPrint(
        allocator,
        "{{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"{s}\",\"signatures\":[{{\"keyid\":\"fixture-key\",\"sig\":\"{s}\"}}]}}\n",
        .{ payload_b64, signature_b64 },
    );
    try dir.writeFile(std.testing.io, .{ .sub_path = "provenance.dsse.intoto.jsonl", .data = envelope_json });
}
