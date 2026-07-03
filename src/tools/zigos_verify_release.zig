const std = @import("std");
const ascii = @import("../kernel/utils/ascii.zig");
const hex = @import("../native/core/hex.zig");
const manifest = @import("../native/policy/manifest.zig");
const signing = @import("../native/core/signing.zig");
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
const release_source_control_jj = "jj";
const release_slsa_build_type = "https://github.com/Cameron-Lyons/zigos/release-security-gate";
const release_slsa_builder_id = "zigos-local-release-security-gate";
const jj_change_id_len: usize = 32;
const git_commit_id_hex_len: usize = 40;

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

const SourceIdentity = struct {
    repository: []const u8,
    change_id: []const u8,
    commit_id: []const u8,
    zig_version: []const u8,
};

const ReleaseKey = struct {
    key_id: []const u8,
    algorithm: []const u8,
    public_key: [Ed25519.PublicKey.encoded_length]u8 = [_]u8{0} ** Ed25519.PublicKey.encoded_length,
    generation: u64,
    status: []const u8,
    custody: []const u8,
    hardware_backed: bool,
    not_before: []const u8,
    not_after: []const u8,
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

    var slsa_source_identity: ?SourceIdentity = null;
    try verifyDsseProvenance(
        allocator,
        io,
        try joinPath(allocator, release_dir, "provenance.dsse.intoto.jsonl"),
        keyring,
        revoked,
        pqc_policy,
        &expected_digests,
        &slsa_source_identity,
        &summary,
    );
    if (summary.dsse_envelopes == 0 or summary.slsa_subjects != expected_digests.count()) {
        return error.SlsaSubjectCoverageMismatch;
    }
    const expected_source_identity = slsa_source_identity orelse return error.SlsaSourceIdentityMissing;

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
        expected_source_identity,
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
    const classical_baseline = try stringField(policy, "classical_baseline");
    if (!containsAsciiIgnoreCase(classical_baseline, "ed25519") or
        !containsAsciiIgnoreCase(classical_baseline, "validated"))
    {
        return error.PqcPolicyMissingClassicalBaselineBoundary;
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
    slsa_source_identity: *?SourceIdentity,
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
        var signing_keys = std.ArrayList(ReleaseKey).empty;
        for (signatures) |signature_value| {
            const key_id = try stringField(signature_value, "keyid");
            const key = try releaseKeyForId(allocator, keyring, key_id);
            try rejectRevokedKey(revoked, key);
            const signature_bytes = try decodeBase64Alloc(allocator, try stringField(signature_value, "sig"));
            try verifyReleaseSignature(key, signature_bytes, pae);
            try signing_keys.append(allocator, key);
            summary.dsse_signatures += 1;
            if (isMlDsa65Algorithm(key.algorithm)) {
                summary.pqc_signatures += 1;
                envelope_pqc_signatures += 1;
            }
        }
        if (pqc_policy.mode == .required and envelope_pqc_signatures == 0) return error.PqcSignatureRequired;

        const slsa_signing_date = try verifySlsaStatement(allocator, payload, expected_digests, &seen_subjects, slsa_source_identity, summary);
        for (signing_keys.items) |key| {
            try validateReleaseKeyCoversSigningDate(key, slsa_signing_date);
        }
        summary.dsse_envelopes += 1;
    }
}

fn verifySlsaStatement(
    allocator: std.mem.Allocator,
    payload: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    seen_subjects: *std.StringHashMap(void),
    slsa_source_identity: *?SourceIdentity,
    summary: *VerificationSummary,
) ![]const u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    const statement = parsed.value;
    if (!std.mem.eql(u8, try stringField(statement, "_type"), "https://in-toto.io/Statement/v1")) {
        return error.InvalidInTotoStatementType;
    }
    if (!std.mem.eql(u8, try stringField(statement, "predicateType"), "https://slsa.dev/provenance/v1")) {
        return error.InvalidSlsaPredicateType;
    }
    try recordSlsaSourceIdentity(slsa_source_identity, try verifySlsaSourceParameters(statement));
    const signing_date = try verifySlsaRunMetadata(statement);
    const subjects = try arrayField(statement, "subject");
    if (subjects.len == 0) return error.SlsaStatementMissingSubjects;
    if (subjects.len != 1) return error.SlsaStatementSubjectCardinalityInvalid;
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
    return signing_date;
}

fn verifySlsaSourceParameters(statement: std.json.Value) !SourceIdentity {
    const predicate = try objectField(statement, "predicate");
    const build_definition = try objectField(predicate, "buildDefinition");
    if (!std.mem.eql(u8, try stringField(build_definition, "buildType"), release_slsa_build_type)) {
        return error.InvalidSlsaBuildType;
    }
    const external_parameters = try objectField(build_definition, "externalParameters");
    if (!std.mem.eql(u8, try stringField(external_parameters, "sourceControl"), release_source_control_jj)) {
        return error.InvalidSlsaSourceControl;
    }
    const change_id = try stringField(external_parameters, "changeId");
    if (!looksLikeJjChangeId(change_id)) {
        return error.InvalidSlsaChangeId;
    }
    const commit_id = try stringField(external_parameters, "commit");
    if (!looksLikeGitCommitId(commit_id)) {
        return error.InvalidSlsaCommitId;
    }
    const repository = try stringField(external_parameters, "repository");
    if (!validSourceRepository(repository)) {
        return error.InvalidSlsaRepository;
    }
    const zig_version = try stringField(external_parameters, "zigVersion");
    if (!validZigVersion(zig_version)) {
        return error.InvalidSlsaZigVersion;
    }
    return .{
        .repository = repository,
        .change_id = change_id,
        .commit_id = commit_id,
        .zig_version = zig_version,
    };
}

fn verifySlsaRunMetadata(statement: std.json.Value) ![]const u8 {
    const predicate = try objectField(statement, "predicate");
    const run_details = try objectField(predicate, "runDetails");
    const builder = try objectField(run_details, "builder");
    if (!std.mem.eql(u8, try stringField(builder, "id"), release_slsa_builder_id)) {
        return error.InvalidSlsaBuilderId;
    }
    const metadata = try objectField(run_details, "metadata");
    const started_on = try stringField(metadata, "startedOn");
    if (!looksLikeUtcSecond(started_on)) return error.InvalidSlsaStartedOn;
    const invocation_id = try stringField(metadata, "invocationId");
    if (!looksLikeUtcSecond(invocation_id)) return error.InvalidSlsaInvocationId;
    const dirty_workspace_file_count = try integerField(metadata, "dirtyWorkspaceFileCount");
    if (dirty_workspace_file_count != 0) return error.SlsaDirtyWorkspaceEvidence;
    return started_on[0.."YYYY-MM-DD".len];
}

fn recordSlsaSourceIdentity(target: *?SourceIdentity, candidate: SourceIdentity) !void {
    if (target.*) |existing| {
        if (!sourceIdentitiesEqual(existing, candidate)) return error.SlsaSourceIdentityMismatch;
        return;
    }
    target.* = candidate;
}

fn sourceIdentitiesEqual(a: SourceIdentity, b: SourceIdentity) bool {
    return std.mem.eql(u8, a.repository, b.repository) and
        std.mem.eql(u8, a.change_id, b.change_id) and
        std.mem.eql(u8, a.commit_id, b.commit_id) and
        std.mem.eql(u8, a.zig_version, b.zig_version);
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
    var seen_measurements = std.StringHashMap(void).init(allocator);
    for (artifacts) |artifact| {
        const path = try stringField(artifact, "path");
        try validateRelativeArtifactPath(path);
        const gop = try seen_measurements.getOrPut(path);
        if (gop.found_existing) return error.DuplicateArtifactMeasurement;
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
    if (seen_measurements.count() != expected_digests.count()) return error.ArtifactMeasurementCoverageMismatch;
}

fn verifyReproducibleBuildDigests(
    allocator: std.mem.Allocator,
    io: std.Io,
    release_dir: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    expected_source_identity: SourceIdentity,
    summary: *VerificationSummary,
) !void {
    const root = try parseJsonFile(allocator, io, try joinPath(allocator, release_dir, "reproducible-build.json"));
    if (!std.mem.eql(u8, try stringField(root, "status"), "passed")) return error.ReproducibleBuildNotPassed;
    if (!std.mem.eql(u8, try stringField(root, "repo_vcs"), release_source_control_jj)) {
        return error.ReproducibleBuildSourceControlMismatch;
    }
    const repository = try stringField(root, "repository");
    if (!validSourceRepository(repository)) {
        return error.ReproducibleBuildRepositoryInvalid;
    }
    const change_id = try stringField(root, "repo_change_id");
    if (!looksLikeJjChangeId(change_id)) {
        return error.ReproducibleBuildChangeIdInvalid;
    }
    const commit_id = try stringField(root, "commit");
    if (!looksLikeGitCommitId(commit_id)) {
        return error.ReproducibleBuildCommitInvalid;
    }
    const dirty_workspace_file_count = try integerField(root, "dirty_workspace_file_count");
    if (dirty_workspace_file_count < 0) return error.ReproducibleBuildDirtyCountInvalid;
    if (dirty_workspace_file_count != 0) return error.ReproducibleBuildDirtyWorkspace;
    const zig_version = try stringField(root, "zig_version");
    if (!validZigVersion(zig_version)) {
        return error.ReproducibleBuildZigVersionInvalid;
    }
    if (!sourceIdentitiesEqual(expected_source_identity, .{
        .repository = repository,
        .change_id = change_id,
        .commit_id = commit_id,
        .zig_version = zig_version,
    })) {
        return error.ReproducibleBuildSourceIdentityMismatch;
    }
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
    if (reproducible_digests.count() != expected_digests.count()) return error.ReproducibleDigestCoverageMismatch;
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
        const generation = try releaseKeyGeneration(key_value);
        const hardware_backed = (try boolField(key_value, "hardware_backed")) orelse return error.ReleaseKeyMissingHardwareFlag;
        if (!hardware_backed) return error.ReleaseKeyNotHardwareBacked;
        if (!containsTrustBoundary(custody)) return error.ReleaseKeyCustodyNotHardwareBacked;
        try validateActiveReleaseKeyLifecycle(key_value);
        const not_before = try stringField(key_value, "not_before");
        const not_after = try stringField(key_value, "not_after");

        const encoding = try stringField(key_value, "public_key_encoding");
        const public_key_hex = try stringField(key_value, "public_key");
        var public_key: [Ed25519.PublicKey.encoded_length]u8 = [_]u8{0} ** Ed25519.PublicKey.encoded_length;
        var verifier_public_key: [signing.ML_DSA65_PUBLIC_KEY_BYTES]u8 = [_]u8{0} ** signing.ML_DSA65_PUBLIC_KEY_BYTES;
        var verifier_public_key_len: usize = 0;
        var verifier_profile = signing.SignatureProfile.ed25519;
        var verifier_signature_format: []const u8 = signing.SIGNATURE_FORMAT_ED25519;
        var verifier_fips_standard = signing.FipsStandard.not_applicable;
        var verifier_post_quantum_algorithm = signing.PostQuantumAlgorithm.not_applicable;
        var verifier_fips_204 = signing.Fips204Implementation.not_applicable;
        var verifier_fips_validated = false;
        var verifier_fips_140_validated_module = false;
        var verifier_validation_certificate: []const u8 = "";
        if (std.mem.eql(u8, algorithm, release_key_algorithm_ed25519)) {
            if (!std.mem.eql(u8, encoding, release_key_encoding_ed25519)) return error.UnsupportedReleaseKeyEncoding;
            public_key = try hex.decodeFixed(Ed25519.PublicKey.encoded_length, public_key_hex);
            @memcpy(verifier_public_key[0..public_key.len], public_key[0..]);
            verifier_public_key_len = public_key.len;
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
            const ml_public_key = try hex.decodeFixed(signing.ML_DSA65_PUBLIC_KEY_BYTES, public_key_hex);
            @memcpy(verifier_public_key[0..signing.ML_DSA65_PUBLIC_KEY_BYTES], ml_public_key[0..]);
            verifier_public_key_len = signing.ML_DSA65_PUBLIC_KEY_BYTES;
            verifier_profile = .ml_dsa65_fips204;
            verifier_signature_format = signing.SIGNATURE_FORMAT_ML_DSA65;
            verifier_fips_standard = .fips_204;
            verifier_post_quantum_algorithm = .ml_dsa_65;
            verifier_fips_204 = .validated_provider;
            verifier_fips_validated = true;
            verifier_fips_140_validated_module = true;
            verifier_validation_certificate = validation_certificate;
        } else return error.UnsupportedReleaseKeyAlgorithm;
        try verifyReleaseKeyMetadataDigest(key_value, .{
            .provider_name = try stringField(key_value, "provider_name"),
            .key_id = key_id,
            .label = try stringField(key_value, "label"),
            .profile = verifier_profile,
            .signature_format = verifier_signature_format,
            .public_key_len = verifier_public_key_len,
            .public_key = verifier_public_key,
            .generation = @intCast(generation),
            .provider_boundary = try parseProviderBoundary(try stringField(key_value, "provider_boundary")),
            .custody = try parseKeyCustody(custody),
            .hardware_backed = hardware_backed,
            .rotation_supported = try requiredTrueBoolField(key_value, "rotation_supported"),
            .revocation_supported = try requiredTrueBoolField(key_value, "revocation_supported"),
            .customer_verifiable = try requiredTrueBoolField(key_value, "customer_verifiable"),
            .verifier_protocol = try parseVerifierProtocol(try stringField(key_value, "verifier_protocol")),
            .fips_standard = verifier_fips_standard,
            .post_quantum_algorithm = verifier_post_quantum_algorithm,
            .fips_204 = verifier_fips_204,
            .fips_validated = verifier_fips_validated,
            .fips_140_validated_module = verifier_fips_140_validated_module,
            .validation_certificate = verifier_validation_certificate,
        });

        return .{
            .key_id = try allocator.dupe(u8, key_id),
            .algorithm = algorithm,
            .public_key = public_key,
            .generation = generation,
            .status = status,
            .custody = custody,
            .hardware_backed = hardware_backed,
            .not_before = not_before,
            .not_after = not_after,
        };
    }
    return error.ReleaseKeyNotFound;
}

fn releaseKeyGeneration(key_value: std.json.Value) !u64 {
    const raw = try integerField(key_value, "generation");
    if (raw <= 0) return error.ReleaseKeyGenerationInvalid;
    const value: u64 = @intCast(raw);
    if (value > std.math.maxInt(u32)) return error.ReleaseKeyGenerationInvalid;
    return value;
}

fn validateActiveReleaseKeyLifecycle(key_value: std.json.Value) !void {
    const not_before = try stringField(key_value, "not_before");
    const not_after = try stringField(key_value, "not_after");
    if (!looksLikeDate(not_before) or !looksLikeDate(not_after)) return error.ReleaseKeyInvalidValidityWindow;
    if (std.mem.order(u8, not_before, not_after) != .lt) return error.ReleaseKeyInvalidValidityWindow;
}

fn validateReleaseKeyCoversSigningDate(key: ReleaseKey, signing_date: []const u8) !void {
    if (!looksLikeDate(signing_date)) return error.InvalidSlsaStartedOn;
    if (std.mem.order(u8, signing_date, key.not_before) == .lt) return error.ReleaseKeyNotYetValidForSlsaStartedOn;
    if (std.mem.order(u8, signing_date, key.not_after) == .gt) return error.ReleaseKeyExpiredForSlsaStartedOn;
}

fn verifyReleaseKeyMetadataDigest(
    key_value: std.json.Value,
    metadata: signing.ReleaseVerifierMetadata,
) !void {
    if (!std.mem.eql(u8, try stringField(key_value, "verifier_metadata_schema"), "zigos.release-verifier-metadata.v1")) {
        return error.ReleaseKeyVerifierMetadataSchemaMismatch;
    }
    if (!metadata.releaseEligible()) return error.ReleaseKeyVerifierMetadataNotEligible;
    const expected_digest = try stringField(key_value, "verifier_metadata_digest");
    if (!isSha256Hex(expected_digest)) return error.ReleaseKeyVerifierMetadataDigestInvalid;
    const actual_digest = metadata.digest();
    var actual_hex: [sha256_hex_len]u8 = undefined;
    _ = try hex.encodeLower(&actual_digest, actual_hex[0..]);
    if (!std.mem.eql(u8, expected_digest, actual_hex[0..])) return error.ReleaseKeyVerifierMetadataDigestMismatch;
}

fn parseProviderBoundary(value: []const u8) !signing.SignatureProviderBoundary {
    if (std.mem.eql(u8, value, "offline_hsm") or
        std.mem.eql(u8, value, "hardware_security_module") or
        containsAsciiIgnoreCase(value, "hardware security module") or
        containsAsciiIgnoreCase(value, "hsm")) return .offline_hsm;
    if (std.mem.eql(u8, value, "cloud_kms") or containsAsciiIgnoreCase(value, "kms")) return .cloud_kms;
    if (std.mem.eql(u8, value, "platform_tpm") or containsAsciiIgnoreCase(value, "tpm")) return .platform_tpm;
    if (std.mem.eql(u8, value, "secure_enclave") or containsAsciiIgnoreCase(value, "secure enclave")) return .secure_enclave;
    return error.ReleaseKeyProviderBoundaryInvalid;
}

fn parseKeyCustody(value: []const u8) !signing.SignatureKeyCustody {
    if (std.mem.eql(u8, value, "hardware_security_module") or
        containsAsciiIgnoreCase(value, "hardware security module") or
        containsAsciiIgnoreCase(value, "hsm")) return .hardware_security_module;
    if (std.mem.eql(u8, value, "cloud_kms") or containsAsciiIgnoreCase(value, "kms")) return .cloud_kms;
    if (std.mem.eql(u8, value, "tpm") or containsAsciiIgnoreCase(value, "tpm")) return .tpm;
    if (std.mem.eql(u8, value, "secure_enclave") or containsAsciiIgnoreCase(value, "secure enclave")) return .secure_enclave;
    return error.ReleaseKeyCustodyInvalid;
}

fn parseVerifierProtocol(value: []const u8) !signing.SignatureVerifierProtocol {
    if (std.mem.eql(u8, value, "dsse_in_toto_slsa")) return .dsse_in_toto_slsa;
    return error.ReleaseKeyVerifierProtocolInvalid;
}

fn requiredTrueBoolField(value: std.json.Value, name: []const u8) !bool {
    const flag = (try boolField(value, name)) orelse return error.JsonMissingField;
    if (!flag) return error.ReleaseKeyLifecycleControlsMissing;
    return flag;
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

fn looksLikeJjChangeId(value: []const u8) bool {
    if (value.len != jj_change_id_len) return false;
    for (value) |byte| {
        if (byte < 'a' or byte > 'z') return false;
    }
    return true;
}

fn looksLikeGitCommitId(value: []const u8) bool {
    return value.len == git_commit_id_hex_len and hex.isText(value);
}

fn validSourceRepository(value: []const u8) bool {
    return value.len > 0 and !std.mem.eql(u8, value, "NOASSERTION");
}

fn validZigVersion(value: []const u8) bool {
    return value.len > 0 and !std.mem.eql(u8, value, "unknown");
}

fn looksLikeDate(value: []const u8) bool {
    if (value.len != "YYYY-MM-DD".len) return false;
    return std.ascii.isDigit(value[0]) and
        std.ascii.isDigit(value[1]) and
        std.ascii.isDigit(value[2]) and
        std.ascii.isDigit(value[3]) and
        value[4] == '-' and
        std.ascii.isDigit(value[5]) and
        std.ascii.isDigit(value[6]) and
        value[7] == '-' and
        std.ascii.isDigit(value[8]) and
        std.ascii.isDigit(value[9]);
}

fn looksLikeUtcSecond(value: []const u8) bool {
    if (value.len != "YYYY-MM-DDTHH:MM:SSZ".len) return false;
    return std.ascii.isDigit(value[0]) and
        std.ascii.isDigit(value[1]) and
        std.ascii.isDigit(value[2]) and
        std.ascii.isDigit(value[3]) and
        value[4] == '-' and
        std.ascii.isDigit(value[5]) and
        std.ascii.isDigit(value[6]) and
        value[7] == '-' and
        std.ascii.isDigit(value[8]) and
        std.ascii.isDigit(value[9]) and
        value[10] == 'T' and
        std.ascii.isDigit(value[11]) and
        std.ascii.isDigit(value[12]) and
        value[13] == ':' and
        std.ascii.isDigit(value[14]) and
        std.ascii.isDigit(value[15]) and
        value[16] == ':' and
        std.ascii.isDigit(value[17]) and
        std.ascii.isDigit(value[18]) and
        value[19] == 'Z';
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
        containsAsciiIgnoreCase(value, "hardware_security_module") or
        containsAsciiIgnoreCase(value, "hardware security module") or
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

const fixture_artifact_bytes = "bootable release bytes";
const fixture_second_artifact_bytes = "second bootable release bytes";
const fixture_jj_change_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const fixture_commit_id = "1111111111111111111111111111111111111111";
const fixture_repository = "git@example.com:zigos.git";
const fixture_zig_version = "0.16.0";

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

test "customer release verifier rejects signed SLSA provenance without Jujutsu source identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const artifact_digest = try sha256HexAlloc(allocator, fixture_artifact_bytes);
    try writeProvenanceFixture(allocator, tmp.dir, "fixture-artifact", artifact_digest, .{
        .source_control = "git",
    });

    try std.testing.expectError(
        error.InvalidSlsaSourceControl,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier rejects untrusted SLSA builder identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const artifact_digest = try sha256HexAlloc(allocator, fixture_artifact_bytes);
    try writeProvenanceFixture(allocator, tmp.dir, "fixture-artifact", artifact_digest, .{
        .build_type = "https://example.invalid/other-builder",
    });
    try std.testing.expectError(
        error.InvalidSlsaBuildType,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );

    try writeProvenanceFixture(allocator, tmp.dir, "fixture-artifact", artifact_digest, .{
        .builder_id = "untrusted-builder",
    });
    try std.testing.expectError(
        error.InvalidSlsaBuilderId,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier rejects multi-subject SLSA envelopes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const artifact_digest = try sha256HexAlloc(allocator, fixture_artifact_bytes);
    try writeProvenanceFixture(allocator, tmp.dir, "fixture-artifact", artifact_digest, .{
        .extra_subject_path = "fixture-artifact-copy",
        .extra_subject_digest = artifact_digest,
    });

    try std.testing.expectError(
        error.SlsaStatementSubjectCardinalityInvalid,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier rejects reproducible-build evidence without Jujutsu source identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const reproducible_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"repo_vcs\":\"git\",\"repository\":\"{s}\",\"repo_change_id\":\"{s}\",\"commit\":\"{s}\",\"dirty_workspace_file_count\":0,\"zig_version\":\"{s}\",\"status\":\"passed\",\"digest_manifest\":\"build/release-security/reproducible-artifact-digests.sha256\"}}\n",
        .{ fixture_repository, fixture_jj_change_id, fixture_commit_id, fixture_zig_version },
    );
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "reproducible-build.json", .data = reproducible_json });

    try std.testing.expectError(
        error.ReproducibleBuildSourceControlMismatch,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier rejects reproducible-build evidence for a different source identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const reproducible_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"repo_vcs\":\"{s}\",\"repository\":\"{s}\",\"repo_change_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"commit\":\"2222222222222222222222222222222222222222\",\"dirty_workspace_file_count\":0,\"zig_version\":\"{s}\",\"status\":\"passed\",\"digest_manifest\":\"build/release-security/reproducible-artifact-digests.sha256\"}}\n",
        .{ release_source_control_jj, fixture_repository, fixture_zig_version },
    );
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "reproducible-build.json", .data = reproducible_json });

    try std.testing.expectError(
        error.ReproducibleBuildSourceIdentityMismatch,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier rejects dirty SLSA or reproducible-build evidence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const artifact_digest = try sha256HexAlloc(allocator, fixture_artifact_bytes);
    try writeProvenanceFixture(allocator, tmp.dir, "fixture-artifact", artifact_digest, .{
        .dirty_workspace_file_count = 1,
    });
    try std.testing.expectError(
        error.SlsaDirtyWorkspaceEvidence,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );

    try writeProvenanceFixture(allocator, tmp.dir, "fixture-artifact", artifact_digest, .{});
    const dirty_reproducible_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"repo_vcs\":\"{s}\",\"repository\":\"{s}\",\"repo_change_id\":\"{s}\",\"commit\":\"{s}\",\"dirty_workspace_file_count\":1,\"zig_version\":\"{s}\",\"status\":\"passed\",\"digest_manifest\":\"build/release-security/reproducible-artifact-digests.sha256\"}}\n",
        .{ release_source_control_jj, fixture_repository, fixture_jj_change_id, fixture_commit_id, fixture_zig_version },
    );
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "reproducible-build.json", .data = dirty_reproducible_json });
    try std.testing.expectError(
        error.ReproducibleBuildDirtyWorkspace,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier rejects duplicate artifact measurement coverage" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeTwoArtifactFixture(allocator, tmp.dir);

    const artifact_digest = try sha256HexAlloc(allocator, fixture_artifact_bytes);
    const duplicate_measurement_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"measurement_algorithm\":\"sha256\",\"artifacts\":[{{\"path\":\"fixture-artifact\",\"sha256\":\"{s}\",\"size_bytes\":{d}}},{{\"path\":\"fixture-artifact\",\"sha256\":\"{s}\",\"size_bytes\":{d}}}]}}\n",
        .{ artifact_digest, fixture_artifact_bytes.len, artifact_digest, fixture_artifact_bytes.len },
    );
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "artifact-measurements.json", .data = duplicate_measurement_json });

    try std.testing.expectError(
        error.DuplicateArtifactMeasurement,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier rejects incomplete reproducible-build digest coverage" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeTwoArtifactFixture(allocator, tmp.dir);

    const artifact_digest = try sha256HexAlloc(allocator, fixture_artifact_bytes);
    const partial_reproducible_manifest = try std.fmt.allocPrint(allocator, "{s}  fixture-artifact\n", .{artifact_digest});
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "reproducible-artifact-digests.sha256", .data = partial_reproducible_manifest });

    try std.testing.expectError(
        error.ReproducibleDigestCoverageMismatch,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
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

test "customer release verifier rejects stale release key verifier metadata digests" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const keyring = try readFileAlloc(std.testing.io, try std.fs.path.join(allocator, &.{ root_path, "release-keyring.json" }), allocator, max_release_metadata_bytes);
    const tampered = try replaceVerifierMetadataDigestForTest(
        allocator,
        keyring,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "release-keyring.json", .data = tampered });

    try std.testing.expectError(
        error.ReleaseKeyVerifierMetadataDigestMismatch,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

test "customer release verifier rejects DSSE keys outside SLSA signing time" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const root_path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root_path);
    try writeValidFixture(allocator, tmp.dir, "fixture-artifact", false, "shadow");

    const keyring = try readFileAlloc(std.testing.io, try std.fs.path.join(allocator, &.{ root_path, "release-keyring.json" }), allocator, max_release_metadata_bytes);
    const future_keyring = try replaceOnceForTest(
        allocator,
        keyring,
        "\"not_before\":\"2026-01-01\"",
        "\"not_before\":\"2026-02-01\"",
    );
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "release-keyring.json", .data = future_keyring });
    try std.testing.expectError(
        error.ReleaseKeyNotYetValidForSlsaStartedOn,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );

    const expired_keyring = try replaceOnceForTest(
        allocator,
        keyring,
        "\"not_before\":\"2026-01-01\",\"not_after\":\"2027-01-01\"",
        "\"not_before\":\"2025-01-01\",\"not_after\":\"2025-12-31\"",
    );
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "release-keyring.json", .data = expired_keyring });
    try std.testing.expectError(
        error.ReleaseKeyExpiredForSlsaStartedOn,
        verifyReleaseBundle(allocator, std.testing.io, root_path, root_path, .{}),
    );
}

fn replaceVerifierMetadataDigestForTest(
    allocator: std.mem.Allocator,
    source: []const u8,
    replacement: []const u8,
) ![]const u8 {
    if (!isSha256Hex(replacement)) return error.InvalidDigestHex;
    const field_name = "\"verifier_metadata_digest\":\"";
    const field_offset = std.mem.indexOf(u8, source, field_name) orelse return error.MissingFixtureNeedle;
    const digest_offset = field_offset + field_name.len;
    const remaining = source[digest_offset..];
    const digest_len = std.mem.indexOfScalar(u8, remaining, '"') orelse return error.MissingFixtureNeedle;
    if (!isSha256Hex(remaining[0..digest_len])) return error.InvalidDigestHex;

    const output = try allocator.alloc(u8, source.len - digest_len + replacement.len);
    @memcpy(output[0..digest_offset], source[0..digest_offset]);
    @memcpy(output[digest_offset..][0..replacement.len], replacement);
    @memcpy(output[digest_offset + replacement.len ..], source[digest_offset + digest_len ..]);
    return output;
}

fn replaceOnceForTest(
    allocator: std.mem.Allocator,
    source: []const u8,
    needle: []const u8,
    replacement: []const u8,
) ![]const u8 {
    const offset = std.mem.indexOf(u8, source, needle) orelse return error.MissingFixtureNeedle;
    const output = try allocator.alloc(u8, source.len - needle.len + replacement.len);
    @memcpy(output[0..offset], source[0..offset]);
    @memcpy(output[offset..][0..replacement.len], replacement);
    @memcpy(output[offset + replacement.len ..], source[offset + needle.len ..]);
    return output;
}

fn writeValidFixture(
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
    artifact_path: []const u8,
    revoked: bool,
    pqc_mode: []const u8,
) !void {
    const artifact_bytes = fixture_artifact_bytes;
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
    const reproducible_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"generated_at\":\"2026-01-01T00:00:00Z\",\"repo_vcs\":\"{s}\",\"repository\":\"{s}\",\"repo_change_id\":\"{s}\",\"commit\":\"{s}\",\"dirty_workspace_file_count\":0,\"zig_version\":\"{s}\",\"status\":\"passed\",\"digest_manifest\":\"build/release-security/reproducible-artifact-digests.sha256\"}}\n",
        .{ release_source_control_jj, fixture_repository, fixture_jj_change_id, fixture_commit_id, fixture_zig_version },
    );
    try dir.writeFile(std.testing.io, .{ .sub_path = "reproducible-build.json", .data = reproducible_json });
    try dir.writeFile(std.testing.io, .{ .sub_path = "sbom.spdx.json", .data = "{\"spdxVersion\":\"SPDX-2.3\"}\n" });

    const key_pair = try Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** Ed25519.KeyPair.seed_length);
    const public_key = key_pair.public_key.toBytes();
    const public_key_hex = try hexAlloc(allocator, &public_key);
    const key_label = "fixture-release-key";
    const provider_name = "fixture-cloud-kms-release";
    var verifier_public_key: [signing.ML_DSA65_PUBLIC_KEY_BYTES]u8 = [_]u8{0} ** signing.ML_DSA65_PUBLIC_KEY_BYTES;
    @memcpy(verifier_public_key[0..public_key.len], public_key[0..]);
    const verifier_metadata = signing.ReleaseVerifierMetadata{
        .provider_name = provider_name,
        .key_id = "fixture-key",
        .label = key_label,
        .profile = .ed25519,
        .signature_format = signing.SIGNATURE_FORMAT_ED25519,
        .public_key_len = public_key.len,
        .public_key = verifier_public_key,
        .generation = 7,
        .provider_boundary = .cloud_kms,
        .custody = .cloud_kms,
        .hardware_backed = true,
        .rotation_supported = true,
        .revocation_supported = true,
        .customer_verifiable = true,
        .verifier_protocol = .dsse_in_toto_slsa,
    };
    const verifier_digest = verifier_metadata.digest();
    const verifier_metadata_digest = try hexAlloc(allocator, &verifier_digest);
    const keyring_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"public_release_allowed\":true,\"required_provider_boundary\":\"cloud KMS release signing provider\",\"post_quantum_policy\":{{\"mode\":\"{s}\",\"fips_validated_required\":true,\"fips_140_validation_required\":true,\"production_signature_algorithm\":\"ml-dsa-65\",\"key_establishment_algorithm\":\"ml-kem-768\",\"backup_signature_algorithm\":\"slh-dsa-sha2-128s\",\"classical_baseline\":\"ed25519 remains the classical DSSE baseline until releases carry a signature from a separately validated FIPS 204 ML-DSA provider\",\"standards\":[{{\"fips\":\"FIPS 203\",\"algorithm\":\"ML-KEM\",\"scope\":\"key establishment\"}},{{\"fips\":\"FIPS 204\",\"algorithm\":\"ML-DSA\",\"scope\":\"digital signatures\"}},{{\"fips\":\"FIPS 205\",\"algorithm\":\"SLH-DSA\",\"scope\":\"hash-based signature fallback\"}}],\"rollout\":[\"shadow verifier measurement\",\"canary dual-signature release\",\"required public-release ML-DSA verification\"]}},\"keys\":[{{\"key_id\":\"fixture-key\",\"label\":\"{s}\",\"status\":\"active\",\"algorithm\":\"ed25519\",\"custody\":\"cloud_kms\",\"hardware_backed\":true,\"generation\":7,\"not_before\":\"2026-01-01\",\"not_after\":\"2027-01-01\",\"provider_name\":\"{s}\",\"provider_boundary\":\"cloud_kms\",\"rotation_supported\":true,\"revocation_supported\":true,\"customer_verifiable\":true,\"verifier_protocol\":\"dsse_in_toto_slsa\",\"public_key_encoding\":\"hex-ed25519-raw\",\"public_key\":\"{s}\",\"verifier_metadata_schema\":\"zigos.release-verifier-metadata.v1\",\"verifier_metadata_digest\":\"{s}\"}}]}}\n",
        .{ pqc_mode, key_label, provider_name, public_key_hex, verifier_metadata_digest },
    );
    try dir.writeFile(std.testing.io, .{ .sub_path = "release-keyring.json", .data = keyring_json });

    const revoked_json = if (revoked)
        "{\"schema_version\":1,\"revoked_keys\":[{\"key_id\":\"fixture-key\",\"reason\":\"test\"}],\"revoked_generations\":[]}\n"
    else
        "{\"schema_version\":1,\"revoked_keys\":[],\"revoked_generations\":[]}\n";
    try dir.writeFile(std.testing.io, .{ .sub_path = "revoked-release-keys.json", .data = revoked_json });

    try writeProvenanceFixture(allocator, dir, artifact_path, artifact_digest, .{});
}

fn writeTwoArtifactFixture(
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
) !void {
    const first_artifact_path = "fixture-artifact";
    const second_artifact_path = "second-fixture-artifact";
    try writeValidFixture(allocator, dir, first_artifact_path, false, "shadow");
    try dir.writeFile(std.testing.io, .{ .sub_path = second_artifact_path, .data = fixture_second_artifact_bytes });

    const first_digest = try sha256HexAlloc(allocator, fixture_artifact_bytes);
    const second_digest = try sha256HexAlloc(allocator, fixture_second_artifact_bytes);
    const digest_manifest = try std.fmt.allocPrint(
        allocator,
        "{s}  {s}\n{s}  {s}\n",
        .{ first_digest, first_artifact_path, second_digest, second_artifact_path },
    );
    try dir.writeFile(std.testing.io, .{ .sub_path = "artifact-digests.sha256", .data = digest_manifest });
    try dir.writeFile(std.testing.io, .{ .sub_path = "reproducible-artifact-digests.sha256", .data = digest_manifest });

    const measurement_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"measurement_algorithm\":\"sha256\",\"artifacts\":[{{\"path\":\"{s}\",\"sha256\":\"{s}\",\"size_bytes\":{d}}},{{\"path\":\"{s}\",\"sha256\":\"{s}\",\"size_bytes\":{d}}}]}}\n",
        .{
            first_artifact_path,
            first_digest,
            fixture_artifact_bytes.len,
            second_artifact_path,
            second_digest,
            fixture_second_artifact_bytes.len,
        },
    );
    try dir.writeFile(std.testing.io, .{ .sub_path = "artifact-measurements.json", .data = measurement_json });

    const first_envelope = try provenanceEnvelopeFixtureAlloc(allocator, first_artifact_path, first_digest, .{});
    const second_envelope = try provenanceEnvelopeFixtureAlloc(allocator, second_artifact_path, second_digest, .{});
    const provenance_jsonl = try std.mem.concat(allocator, u8, &.{ first_envelope, second_envelope });
    try dir.writeFile(std.testing.io, .{ .sub_path = "provenance.dsse.intoto.jsonl", .data = provenance_jsonl });
}

const FixtureProvenanceOptions = struct {
    build_type: []const u8 = release_slsa_build_type,
    builder_id: []const u8 = release_slsa_builder_id,
    source_control: []const u8 = release_source_control_jj,
    change_id: []const u8 = fixture_jj_change_id,
    commit_id: []const u8 = fixture_commit_id,
    repository: []const u8 = fixture_repository,
    zig_version: []const u8 = fixture_zig_version,
    started_on: []const u8 = "2026-01-01T00:00:00Z",
    dirty_workspace_file_count: u32 = 0,
    extra_subject_path: ?[]const u8 = null,
    extra_subject_digest: ?[]const u8 = null,
};

fn writeProvenanceFixture(
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
    artifact_path: []const u8,
    artifact_digest: []const u8,
    options: FixtureProvenanceOptions,
) !void {
    const envelope_json = try provenanceEnvelopeFixtureAlloc(allocator, artifact_path, artifact_digest, options);
    try dir.writeFile(std.testing.io, .{ .sub_path = "provenance.dsse.intoto.jsonl", .data = envelope_json });
}

fn provenanceEnvelopeFixtureAlloc(
    allocator: std.mem.Allocator,
    artifact_path: []const u8,
    artifact_digest: []const u8,
    options: FixtureProvenanceOptions,
) ![]const u8 {
    const key_pair = try Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** Ed25519.KeyPair.seed_length);
    const subject_entries = if (options.extra_subject_path) |extra_subject_path| blk: {
        const extra_subject_digest = options.extra_subject_digest orelse artifact_digest;
        break :blk try std.fmt.allocPrint(
            allocator,
            "{{\"name\":\"{s}\",\"digest\":{{\"sha256\":\"{s}\"}}}},{{\"name\":\"{s}\",\"digest\":{{\"sha256\":\"{s}\"}}}}",
            .{ artifact_path, artifact_digest, extra_subject_path, extra_subject_digest },
        );
    } else try std.fmt.allocPrint(
        allocator,
        "{{\"name\":\"{s}\",\"digest\":{{\"sha256\":\"{s}\"}}}}",
        .{ artifact_path, artifact_digest },
    );
    const statement = try std.fmt.allocPrint(
        allocator,
        "{{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{s}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{{\"buildDefinition\":{{\"buildType\":\"{s}\",\"externalParameters\":{{\"repository\":\"{s}\",\"sourceControl\":\"{s}\",\"changeId\":\"{s}\",\"commit\":\"{s}\",\"zigVersion\":\"{s}\"}}}},\"runDetails\":{{\"builder\":{{\"id\":\"{s}\"}},\"metadata\":{{\"invocationId\":\"{s}\",\"startedOn\":\"{s}\",\"dirtyWorkspaceFileCount\":{d}}}}}}}}}\n",
        .{
            subject_entries,
            options.build_type,
            options.repository,
            options.source_control,
            options.change_id,
            options.commit_id,
            options.zig_version,
            options.builder_id,
            options.started_on,
            options.started_on,
            options.dirty_workspace_file_count,
        },
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
    return envelope_json;
}
