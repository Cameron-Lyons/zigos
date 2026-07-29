const std = @import("std");
const builtin = @import("builtin");
const catalog = @import("release_catalog.zig");
const trust = @import("release_trust.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

const max_release_metadata_bytes: usize = 16 * 1024 * 1024;
const max_artifact_bytes: usize = 1024 * 1024 * 1024;
const stdout_buffer_bytes: usize = 1024;
const sha256_hex_len: usize = Sha256.digest_length * 2;
const release_manifest_name = "release-manifest.dsse.json";
const trust_policy_name = "release-trust-policy.dsse.json";
const root_metadata_name = "root-metadata.json";
const release_source_control_jj = "jj";
const release_optimize_mode = "ReleaseFast";
const release_build_target = "x86-freestanding-none";
const release_slsa_payload_type = "application/vnd.in-toto+json";
const release_slsa_build_type = "https://github.com/Cameron-Lyons/zigos/release-security-gate";
const release_slsa_builder_id = "zigos-local-release-security-gate";
const jj_change_id_len: usize = 32;
const git_commit_id_hex_len: usize = 40;

const DarwinAcl = if (builtin.os.tag.isDarwin()) struct {
    const type_extended: c_uint = 0x00000100;
    const first_entry: c_int = 0;

    extern "c" fn acl_get_fd_np(fd: c_int, acl_type: c_uint) ?*anyopaque;
    extern "c" fn acl_get_entry(acl: *anyopaque, entry_id: c_int, entry: *?*anyopaque) c_int;
    extern "c" fn acl_free(object: *anyopaque) c_int;

    extern "c" fn acl_from_text(text: [*:0]const u8) ?*anyopaque;
    extern "c" fn acl_set_fd_np(fd: c_int, acl: *anyopaque, acl_type: c_uint) c_int;
} else struct {};

pub const VerifyOptions = struct {
    /// Raw root metadata obtained independently of the release bundle.
    trusted_root: []const u8,
    /// Lowercase SHA-256 pin obtained independently of the release bundle.
    trusted_root_sha256: []const u8,
    /// Persistent state outside both the release bundle and artifact tree.
    trust_state_path: []const u8,
    now_unix: i64,
    /// Candidate verification checks rollback state but does not advance it.
    advance_trust_state: bool = true,
};

pub const VerificationSummary = struct {
    artifacts: usize = 0,
    evidence_files: usize = 0,
    dsse_envelopes: usize = 0,
    dsse_signatures: usize = 0,
    slsa_subjects: usize = 0,
    measurements: usize = 0,
    reproducible_digests: usize = 0,
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
    optimize_mode: []const u8,
    builder_id: []const u8,
};

const TrustState = struct {
    schemaVersion: u32,
    rootSha256: []const u8,
    rootVersion: u64,
    policyVersion: u64,
    /// SHA-256 of the authenticated decoded policy payload, not its DSSE wrapper.
    policyPayloadSha256: []const u8,
    releaseSequence: u64,
    /// SHA-256 of the authenticated decoded manifest payload, not its DSSE wrapper.
    manifestPayloadSha256: []const u8,
    observedAt: i64,
};

const ContainedRoot = struct {
    dir: std.Io.Dir,
    canonical_path: []const u8,

    fn close(self: ContainedRoot, io: std.Io) void {
        self.dir.close(io);
    }
};

const TrustStateTransaction = struct {
    parent: std.Io.Dir,
    basename: []const u8,
    lock_file: std.Io.File,

    fn close(self: TrustStateTransaction, io: std.Io) void {
        self.lock_file.close(io);
        self.parent.close(io);
    }
};

const EvidenceSet = struct {
    bytes: std.StringHashMap([]const u8),
};

const ProvenanceSignature = struct {
    keyid: []const u8,
    sig: []const u8,
};

const ProvenanceEnvelope = struct {
    payloadType: []const u8,
    payload: []const u8,
    signatures: []const ProvenanceSignature,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2 and (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "help"))) {
        try printUsage(init.io);
        return;
    }
    if (args.len < 2) {
        try printUsage(init.io);
        return error.InvalidArguments;
    }

    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const now_unix = std.Io.Clock.real.now(init.io).toSeconds();

    if (std.mem.eql(u8, args[1], "verify") or std.mem.eql(u8, args[1], "verify-candidate")) {
        const advance_trust_state = std.mem.eql(u8, args[1], "verify");
        const cli = parseVerifyCli(args[2..]) catch |err| {
            try printUsage(init.io);
            return err;
        };
        try rejectCliTrustPaths(allocator, init.io, cli.trusted_root_path, cli.bundle, cli.artifacts);
        const root_source = try readExternalFileAlloc(init.io, cli.trusted_root_path, allocator, max_release_metadata_bytes);
        const summary = verifyReleaseBundle(allocator, init.io, cli.bundle, cli.artifacts, .{
            .trusted_root = root_source,
            .trusted_root_sha256 = cli.trusted_root_sha256,
            .trust_state_path = cli.trust_state_path,
            .now_unix = now_unix,
            .advance_trust_state = advance_trust_state,
        }) catch |err| {
            std.debug.print("release verification failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        var buffer: [stdout_buffer_bytes]u8 = undefined;
        var writer = std.Io.File.stdout().writer(init.io, &buffer);
        try writer.interface.print(
            "Release {s} verification OK: {d} artifacts, {d} evidence files, {d} DSSE envelopes, {d} signatures, {d} SLSA subjects, {d} measurements, {d} reproducible digests\n",
            .{
                if (advance_trust_state) "published" else "candidate",
                summary.artifacts,
                summary.evidence_files,
                summary.dsse_envelopes,
                summary.dsse_signatures,
                summary.slsa_subjects,
                summary.measurements,
                summary.reproducible_digests,
            },
        );
        try writer.interface.flush();
        return;
    }

    if (std.mem.eql(u8, args[1], "trust-info")) {
        const cli = parseTrustInfoCli(args[2..]) catch |err| {
            try printUsage(init.io);
            return err;
        };
        const root_source = try readExternalFileAlloc(init.io, cli.trusted_root_path, allocator, max_release_metadata_bytes);
        const policy_source = try readExternalFileAlloc(init.io, cli.policy_path, allocator, max_release_metadata_bytes);
        var verified_root = try trust.verifyRootMetadata(allocator, root_source, cli.trusted_root_sha256, now_unix);
        defer verified_root.deinit();
        var verified_policy = try trust.verifyTrustPolicy(
            allocator,
            policy_source,
            &verified_root,
            now_unix,
            catalog.productionTargetPaths(),
            catalog.releaseEvidenceNames(),
        );
        defer verified_policy.deinit();
        if (verified_policy.policy().releaseRole.threshold != 1) return error.GeneratorRequiresSingleReleaseSigner;
        try requireAuthorizedReleaseKey(verified_policy.policy(), cli.release_key_id, now_unix);
        var buffer: [stdout_buffer_bytes]u8 = undefined;
        var writer = std.Io.File.stdout().writer(init.io, &buffer);
        try writer.interface.print(
            "Trust policy OK: root version {d}, policy version {d}, release key {s}\n",
            .{ verified_root.metadata().version, verified_policy.policy().policyVersion, cli.release_key_id },
        );
        try writer.interface.flush();
        return;
    }

    try printUsage(init.io);
    return error.InvalidArguments;
}

const VerifyCli = struct {
    bundle: []const u8,
    artifacts: []const u8,
    trusted_root_path: []const u8,
    trusted_root_sha256: []const u8,
    trust_state_path: []const u8,
};

const TrustInfoCli = struct {
    trusted_root_path: []const u8,
    trusted_root_sha256: []const u8,
    policy_path: []const u8,
    release_key_id: []const u8,
};

fn parseVerifyCli(args: []const []const u8) !VerifyCli {
    if (args.len != 10) return error.InvalidArguments;
    var result = VerifyCli{ .bundle = "", .artifacts = "", .trusted_root_path = "", .trusted_root_sha256 = "", .trust_state_path = "" };
    var seen: u8 = 0;
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        const flag = args[index];
        const value = args[index + 1];
        if (value.len == 0) return error.InvalidArguments;
        if (std.mem.eql(u8, flag, "--bundle")) {
            if (seen & 1 != 0) return error.DuplicateArgument;
            seen |= 1;
            result.bundle = value;
        } else if (std.mem.eql(u8, flag, "--artifacts")) {
            if (seen & 2 != 0) return error.DuplicateArgument;
            seen |= 2;
            result.artifacts = value;
        } else if (std.mem.eql(u8, flag, "--trusted-root")) {
            if (seen & 4 != 0) return error.DuplicateArgument;
            seen |= 4;
            result.trusted_root_path = value;
        } else if (std.mem.eql(u8, flag, "--trusted-root-sha256")) {
            if (seen & 8 != 0) return error.DuplicateArgument;
            seen |= 8;
            result.trusted_root_sha256 = value;
        } else if (std.mem.eql(u8, flag, "--trust-state")) {
            if (seen & 16 != 0) return error.DuplicateArgument;
            seen |= 16;
            result.trust_state_path = value;
        } else return error.UnknownArgument;
    }
    if (seen != 31) return error.InvalidArguments;
    if (!std.fs.path.isAbsolute(result.trusted_root_path) or !std.fs.path.isAbsolute(result.trust_state_path)) {
        return error.AbsoluteTrustPathRequired;
    }
    return result;
}

fn parseTrustInfoCli(args: []const []const u8) !TrustInfoCli {
    if (args.len != 8) return error.InvalidArguments;
    var result = TrustInfoCli{ .trusted_root_path = "", .trusted_root_sha256 = "", .policy_path = "", .release_key_id = "" };
    var seen: u8 = 0;
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        const flag = args[index];
        const value = args[index + 1];
        if (value.len == 0) return error.InvalidArguments;
        if (std.mem.eql(u8, flag, "--trusted-root")) {
            if (seen & 1 != 0) return error.DuplicateArgument;
            seen |= 1;
            result.trusted_root_path = value;
        } else if (std.mem.eql(u8, flag, "--trusted-root-sha256")) {
            if (seen & 2 != 0) return error.DuplicateArgument;
            seen |= 2;
            result.trusted_root_sha256 = value;
        } else if (std.mem.eql(u8, flag, "--policy")) {
            if (seen & 4 != 0) return error.DuplicateArgument;
            seen |= 4;
            result.policy_path = value;
        } else if (std.mem.eql(u8, flag, "--release-key-id")) {
            if (seen & 8 != 0) return error.DuplicateArgument;
            seen |= 8;
            result.release_key_id = value;
        } else return error.UnknownArgument;
    }
    if (seen != 15) return error.InvalidArguments;
    if (!std.fs.path.isAbsolute(result.trusted_root_path) or !std.fs.path.isAbsolute(result.policy_path)) {
        return error.AbsoluteTrustPathRequired;
    }
    return result;
}

fn printUsage(io: std.Io) !void {
    var buffer: [stdout_buffer_bytes]u8 = undefined;
    var writer = std.Io.File.stdout().writer(io, &buffer);
    try writer.interface.print(
        \\usage:
        \\  zigos-verify-release verify --bundle DIR --artifacts ROOT --trusted-root FILE --trusted-root-sha256 HEX --trust-state FILE
        \\  zigos-verify-release verify-candidate --bundle DIR --artifacts ROOT --trusted-root FILE --trusted-root-sha256 HEX --trust-state FILE
        \\  zigos-verify-release trust-info --trusted-root FILE --trusted-root-sha256 HEX --policy FILE --release-key-id ID
        \\
        \\The root file and its SHA-256 pin must be obtained independently. Trust
        \\state must be persistent and outside both the bundle and artifact tree;
        \\its directory must be user-controlled and not group/world-writable.
        \\verify-candidate checks existing rollback state without advancing it and
        \\is reserved for release-manifest promotion workflows.
        \\
    , .{});
    try writer.interface.flush();
}

pub fn verifyReleaseBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
    release_dir_path: []const u8,
    artifact_root_path: []const u8,
    options: VerifyOptions,
) !VerificationSummary {
    if (options.trust_state_path.len == 0) return error.TrustStateRequired;
    var release_root = try openContainedRoot(allocator, io, release_dir_path);
    defer release_root.close(io);
    var artifact_root = try openContainedRoot(allocator, io, artifact_root_path);
    defer artifact_root.close(io);
    var state_transaction = try openTrustStateTransaction(
        allocator,
        io,
        options.trust_state_path,
        release_root,
        artifact_root,
    );
    defer state_transaction.close(io);
    try requireExactBundleEntries(io, release_root);

    const policy_source = try readContainedFileAlloc(allocator, io, release_root, trust_policy_name, max_release_metadata_bytes);
    var verified_root = try trust.verifyRootMetadata(allocator, options.trusted_root, options.trusted_root_sha256, options.now_unix);
    defer verified_root.deinit();
    var verified_policy = try trust.verifyTrustPolicy(
        allocator,
        policy_source,
        &verified_root,
        options.now_unix,
        catalog.productionTargetPaths(),
        catalog.releaseEvidenceNames(),
    );
    defer verified_policy.deinit();

    const manifest_source = try readContainedFileAlloc(allocator, io, release_root, release_manifest_name, max_release_metadata_bytes);
    var verified_manifest = try trust.verifyReleaseManifest(
        allocator,
        manifest_source,
        &verified_policy,
        options.now_unix,
        catalog.productionTargetPaths(),
        catalog.releaseEvidenceNames(),
    );
    defer verified_manifest.deinit();
    const release_manifest = verified_manifest.manifest();
    try validateManifestBuild(release_manifest);

    var root_digest_buffer: [sha256_hex_len]u8 = undefined;
    const root_digest = trust.sha256Hex(options.trusted_root, &root_digest_buffer);
    if (!std.mem.eql(u8, root_digest, options.trusted_root_sha256)) return error.NonCanonicalRootPin;
    var policy_digest_buffer: [sha256_hex_len]u8 = undefined;
    const policy_digest = try authenticatedPayloadSha256(
        allocator,
        policy_source,
        trust.trust_policy_payload_type,
        &policy_digest_buffer,
    );
    var manifest_digest_buffer: [sha256_hex_len]u8 = undefined;
    const manifest_digest = try authenticatedPayloadSha256(
        allocator,
        manifest_source,
        trust.release_payload_type,
        &manifest_digest_buffer,
    );
    try checkTrustState(
        allocator,
        io,
        &state_transaction,
        .{
            .schemaVersion = 1,
            .rootSha256 = root_digest,
            .rootVersion = verified_root.metadata().version,
            .policyVersion = verified_policy.policy().policyVersion,
            .policyPayloadSha256 = policy_digest,
            .releaseSequence = release_manifest.releaseSequence,
            .manifestPayloadSha256 = manifest_digest,
            .observedAt = options.now_unix,
        },
    );

    var summary = VerificationSummary{
        .dsse_envelopes = 2,
        .dsse_signatures = verified_policy.root_signer_count + verified_manifest.release_signer_count,
    };
    const evidence = try authenticateEvidence(allocator, io, release_root, release_manifest.evidence, &summary);
    if (!std.mem.eql(u8, evidence.bytes.get(root_metadata_name) orelse return error.RootEvidenceMissing, options.trusted_root)) {
        return error.RootEvidenceDoesNotMatchPinnedRoot;
    }
    if (!std.mem.eql(u8, evidence.bytes.get(trust_policy_name) orelse return error.TrustPolicyEvidenceMissing, policy_source)) {
        return error.TrustPolicyEvidenceMismatch;
    }

    var expected_digests = std.StringHashMap([]const u8).init(allocator);
    try loadManifestTargets(allocator, release_manifest.targets, &expected_digests);
    var actual_artifacts = std.StringHashMap(ActualArtifact).init(allocator);
    try verifyArtifactFiles(io, artifact_root, release_manifest.targets, &actual_artifacts, &summary);

    try verifyDigestProjection(allocator, evidence.bytes.get("artifact-digests.sha256").?, &expected_digests);
    try verifyArtifactMeasurementsSource(
        allocator,
        evidence.bytes.get("artifact-measurements.json").?,
        &expected_digests,
        &actual_artifacts,
        &summary,
    );
    const expected_source_identity = sourceIdentityFromManifest(release_manifest);
    try verifyDsseProvenanceSources(
        allocator,
        evidence.bytes.get("provenance.dsse.intoto.jsonl").?,
        evidence.bytes.get("provenance.intoto.jsonl").?,
        verified_policy.policy(),
        release_manifest,
        options.now_unix,
        &expected_digests,
        expected_source_identity,
        &summary,
    );
    try verifyReproducibleBuildSources(
        allocator,
        evidence.bytes.get("reproducible-build.json").?,
        evidence.bytes.get("reproducible-artifact-digests.sha256").?,
        &expected_digests,
        expected_source_identity,
        &summary,
    );
    try verifySpdxSbomSource(allocator, evidence.bytes.get("sbom.spdx.json").?);
    try requireValidJson(allocator, evidence.bytes.get("customer-verification-policy.json").?);

    try requireExactBundleEntries(io, release_root);
    if (options.advance_trust_state) {
        try writeTrustStateAtomic(allocator, io, &state_transaction, .{
            .schemaVersion = 1,
            .rootSha256 = root_digest,
            .rootVersion = verified_root.metadata().version,
            .policyVersion = verified_policy.policy().policyVersion,
            .policyPayloadSha256 = policy_digest,
            .releaseSequence = release_manifest.releaseSequence,
            .manifestPayloadSha256 = manifest_digest,
            .observedAt = options.now_unix,
        });
    }
    return summary;
}

fn requireAuthorizedReleaseKey(policy: *const trust.TrustPolicy, key_id: []const u8, now_unix: i64) !void {
    var authorized = false;
    for (policy.releaseRole.keyIds) |candidate| {
        if (std.mem.eql(u8, candidate, key_id)) {
            authorized = true;
            break;
        }
    }
    if (!authorized) return error.ReleaseKeyNotAuthorized;
    for (policy.releaseKeys) |key| {
        if (!std.mem.eql(u8, key.keyId, key_id)) continue;
        if (key.status != .active) return error.ReleaseKeyNotActive;
        if (!key.hardwareBacked) return error.ReleaseKeyNotHardwareBacked;
        if (now_unix < key.notBefore or now_unix >= key.notAfter) return error.ReleaseKeyExpired;
        for (policy.revocations) |revocation| {
            if (revocation.generation == key.generation and std.mem.eql(u8, revocation.keyId, key_id)) {
                return error.ReleaseKeyRevoked;
            }
        }
        return;
    }
    return error.ReleaseKeyNotFound;
}

fn validateManifestBuild(release_manifest: *const trust.ReleaseManifest) !void {
    if (!std.mem.eql(u8, release_manifest.build.target, release_build_target)) return error.InvalidReleaseBuildTarget;
    if (!std.mem.eql(u8, release_manifest.build.optimizeMode, release_optimize_mode)) return error.InvalidReleaseOptimizeMode;
    if (!std.mem.eql(u8, release_manifest.build.builderId, release_slsa_builder_id)) return error.InvalidReleaseBuilderId;
}

fn requireExactBundleEntries(io: std.Io, release_root: ContainedRoot) !void {
    var iterator = release_root.dir.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) return error.UnexpectedBundleEntry;
        const allowed = std.mem.eql(u8, entry.name, release_manifest_name) or catalog.isReleaseEvidenceName(entry.name);
        if (!allowed) return error.UnexpectedBundleEntry;
        count += 1;
    }
    if (count != catalog.releaseEvidenceNames().len + 1) return error.BundleEntrySetMismatch;
}

fn authenticateEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    release_root: ContainedRoot,
    records: []const trust.FileRecord,
    summary: *VerificationSummary,
) !EvidenceSet {
    var bytes = std.StringHashMap([]const u8).init(allocator);
    for (records) |record| {
        const source = try readContainedFileAlloc(allocator, io, release_root, record.path, max_release_metadata_bytes);
        if (source.len != record.sizeBytes) return error.EvidenceSizeMismatch;
        var digest_buffer: [sha256_hex_len]u8 = undefined;
        if (!std.mem.eql(u8, trust.sha256Hex(source, &digest_buffer), record.sha256)) return error.EvidenceDigestMismatch;
        const gop = try bytes.getOrPut(record.path);
        if (gop.found_existing) return error.DuplicateEvidence;
        gop.value_ptr.* = source;
        summary.evidence_files += 1;
    }
    if (bytes.count() != catalog.releaseEvidenceNames().len) return error.EvidenceCoverageMismatch;
    return .{ .bytes = bytes };
}

fn loadManifestTargets(
    allocator: std.mem.Allocator,
    records: []const trust.FileRecord,
    digests: *std.StringHashMap([]const u8),
) !void {
    for (records) |record| {
        const digest_gop = try digests.getOrPut(try allocator.dupe(u8, record.path));
        if (digest_gop.found_existing) return error.DuplicateManifestTarget;
        digest_gop.value_ptr.* = try allocator.dupe(u8, record.sha256);
    }
}

fn verifyArtifactFiles(
    io: std.Io,
    artifact_root: ContainedRoot,
    records: []const trust.FileRecord,
    actual_artifacts: *std.StringHashMap(ActualArtifact),
    summary: *VerificationSummary,
) !void {
    for (records) |record| {
        const actual = try hashContainedFile(io, artifact_root, record.path, max_artifact_bytes);
        if (actual.size_bytes != record.sizeBytes) return error.ArtifactSizeMismatch;
        if (!std.mem.eql(u8, &actual.digest_hex, record.sha256)) return error.ArtifactDigestMismatch;
        try actual_artifacts.put(record.path, .{ .digest_hex = record.sha256, .size_bytes = actual.size_bytes });
        summary.artifacts += 1;
    }
}

const StreamedArtifact = struct {
    digest_hex: [sha256_hex_len]u8,
    size_bytes: u64,
};

fn hashContainedFile(io: std.Io, root: ContainedRoot, relative_path: []const u8, limit: u64) !StreamedArtifact {
    var file = try openContainedFile(io, root, relative_path);
    defer file.close(io);
    var reader = file.reader(io, &.{});
    var hasher = Sha256.init(.{});
    var total: u64 = 0;
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = reader.interface.readSliceShort(&buffer) catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
        };
        if (count == 0) break;
        total = std.math.add(u64, total, count) catch return error.ArtifactTooLarge;
        if (total > limit) return error.ArtifactTooLarge;
        hasher.update(buffer[0..count]);
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    var digest_hex: [sha256_hex_len]u8 = undefined;
    trust.encodeHexLower(&digest, &digest_hex);
    return .{ .digest_hex = digest_hex, .size_bytes = total };
}

fn loadDigestManifestSource(
    allocator: std.mem.Allocator,
    source: []const u8,
    out: *std.StringHashMap([]const u8),
) !void {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        const separator = std.mem.indexOf(u8, line, "  ") orelse return error.InvalidDigestManifestLine;
        const digest = line[0..separator];
        const path = std.mem.trimStart(u8, line[separator + 2 ..], " ");
        if (!isSha256Hex(digest)) return error.InvalidDigestHex;
        if (!catalog.isSafeRelativePath(path)) return error.UnsafeArtifactPath;
        const gop = try out.getOrPut(try allocator.dupe(u8, path));
        if (gop.found_existing) return error.DuplicateDigestEntry;
        gop.value_ptr.* = try allocator.dupe(u8, digest);
    }
}

fn verifyDigestProjection(
    allocator: std.mem.Allocator,
    source: []const u8,
    expected: *const std.StringHashMap([]const u8),
) !void {
    var projected = std.StringHashMap([]const u8).init(allocator);
    try loadDigestManifestSource(allocator, source, &projected);
    if (projected.count() != expected.count()) return error.DigestProjectionCoverageMismatch;
    var iterator = projected.iterator();
    while (iterator.next()) |entry| {
        const digest = expected.get(entry.key_ptr.*) orelse return error.DigestProjectionUnknownArtifact;
        if (!std.mem.eql(u8, digest, entry.value_ptr.*)) return error.DigestProjectionMismatch;
    }
}

fn verifyArtifactMeasurementsSource(
    allocator: std.mem.Allocator,
    source: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    actual_artifacts: *const std.StringHashMap(ActualArtifact),
    summary: *VerificationSummary,
) !void {
    const parsed = try parseJsonValueStrict(allocator, source);
    const root = parsed.value;
    if (!std.mem.eql(u8, try stringField(root, "measurement_algorithm"), "sha256")) return error.InvalidMeasurementAlgorithm;
    const artifacts = try arrayField(root, "artifacts");
    var seen = std.StringHashMap(void).init(allocator);
    for (artifacts) |artifact| {
        const path = try stringField(artifact, "path");
        if (!catalog.isSafeRelativePath(path)) return error.UnsafeArtifactPath;
        const gop = try seen.getOrPut(path);
        if (gop.found_existing) return error.DuplicateArtifactMeasurement;
        const digest = try stringField(artifact, "sha256");
        if (!std.mem.eql(u8, expected_digests.get(path) orelse return error.MeasurementUnknownArtifact, digest)) return error.MeasurementDigestMismatch;
        const actual = actual_artifacts.get(path) orelse return error.MeasurementMissingDownloadedArtifact;
        const size = try integerField(artifact, "size_bytes");
        if (size < 0 or @as(u64, @intCast(size)) != actual.size_bytes) return error.MeasurementSizeMismatch;
        summary.measurements += 1;
    }
    if (seen.count() != expected_digests.count()) return error.ArtifactMeasurementCoverageMismatch;
}

fn verifyDsseProvenanceSources(
    allocator: std.mem.Allocator,
    dsse_source: []const u8,
    unsigned_source: []const u8,
    policy: *const trust.TrustPolicy,
    release_manifest: *const trust.ReleaseManifest,
    now_unix: i64,
    expected_digests: *const std.StringHashMap([]const u8),
    expected_identity: SourceIdentity,
    summary: *VerificationSummary,
) !void {
    var signed_lines = std.mem.splitScalar(u8, dsse_source, '\n');
    var unsigned_lines = std.mem.splitScalar(u8, unsigned_source, '\n');
    var seen_subjects = std.StringHashMap(void).init(allocator);
    while (nextNonEmptyLine(&signed_lines)) |line| {
        const unsigned_line = nextNonEmptyLine(&unsigned_lines) orelse return error.UnsignedProvenanceCoverageMismatch;
        var envelope = try std.json.parseFromSlice(ProvenanceEnvelope, allocator, line, .{
            .allocate = .alloc_always,
            .duplicate_field_behavior = .@"error",
            .ignore_unknown_fields = false,
        });
        defer envelope.deinit();
        if (!std.mem.eql(u8, envelope.value.payloadType, release_slsa_payload_type)) return error.InvalidDssePayloadType;
        const payload = try decodeBase64Alloc(allocator, envelope.value.payload);
        if (!std.mem.eql(u8, payload, unsigned_line)) return error.UnsignedProvenancePayloadMismatch;
        try verifyProvenanceSignatures(allocator, envelope.value, payload, policy, now_unix, summary);
        const statement = try verifySlsaStatement(allocator, payload, expected_digests, &seen_subjects, summary);
        if (!sourceIdentitiesEqual(statement.identity, expected_identity)) return error.SlsaSourceIdentityMismatch;
        if (statement.started_at < policy.issuedAt or statement.started_at > release_manifest.issuedAt or statement.started_at >= release_manifest.expiresAt) {
            return error.SlsaStartedOnOutsideReleaseWindow;
        }
        for (envelope.value.signatures) |signature| {
            const key = findReleaseKey(policy, signature.keyid) orelse return error.ReleaseKeyNotFound;
            if (statement.started_at < key.notBefore or statement.started_at >= key.notAfter) {
                return error.ReleaseKeyInvalidForSlsaStartedOn;
            }
        }
        summary.dsse_envelopes += 1;
    }
    if (nextNonEmptyLine(&unsigned_lines) != null) return error.UnsignedProvenanceCoverageMismatch;
    if (seen_subjects.count() != expected_digests.count()) return error.SlsaSubjectCoverageMismatch;
}

fn verifyProvenanceSignatures(
    allocator: std.mem.Allocator,
    envelope: ProvenanceEnvelope,
    payload: []const u8,
    policy: *const trust.TrustPolicy,
    now_unix: i64,
    summary: *VerificationSummary,
) !void {
    if (envelope.signatures.len < policy.releaseRole.threshold) return error.SignatureThresholdNotMet;
    const pae = try dssePreauthEncoding(allocator, envelope.payloadType, payload);
    for (envelope.signatures, 0..) |signature, index| {
        for (envelope.signatures[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.keyid, signature.keyid)) return error.DuplicateSigner;
        }
        try requireAuthorizedReleaseKey(policy, signature.keyid, now_unix);
        const key = findReleaseKey(policy, signature.keyid) orelse return error.ReleaseKeyNotFound;
        const public_key_bytes = try decodeHexFixed(Ed25519.PublicKey.encoded_length, key.publicKey);
        const signature_bytes = try decodeBase64Alloc(allocator, signature.sig);
        if (signature_bytes.len != Ed25519.Signature.encoded_length) return error.InvalidSignatureLength;
        const public_key = Ed25519.PublicKey.fromBytes(public_key_bytes) catch return error.InvalidPublicKey;
        const signature_value = Ed25519.Signature.fromBytes(signature_bytes[0..Ed25519.Signature.encoded_length].*);
        signature_value.verify(pae, public_key) catch return error.InvalidSignature;
        summary.dsse_signatures += 1;
    }
}

fn findReleaseKey(policy: *const trust.TrustPolicy, key_id: []const u8) ?*const trust.ReleaseKey {
    for (policy.releaseKeys) |*key| if (std.mem.eql(u8, key.keyId, key_id)) return key;
    return null;
}

fn verifySlsaStatement(
    allocator: std.mem.Allocator,
    payload: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    seen_subjects: *std.StringHashMap(void),
    summary: *VerificationSummary,
) !VerifiedSlsaStatement {
    const parsed = try parseJsonValueStrict(allocator, payload);
    const statement = parsed.value;
    if (!std.mem.eql(u8, try stringField(statement, "_type"), "https://in-toto.io/Statement/v1")) return error.InvalidInTotoStatementType;
    if (!std.mem.eql(u8, try stringField(statement, "predicateType"), "https://slsa.dev/provenance/v1")) return error.InvalidSlsaPredicateType;
    const identity = try verifySlsaSourceParameters(statement);
    const started_at = try verifySlsaRunMetadata(statement, identity.builder_id);
    const subjects = try arrayField(statement, "subject");
    if (subjects.len != 1) return error.SlsaStatementSubjectCardinalityInvalid;
    const name = try stringField(subjects[0], "name");
    const digest = try stringField(try objectField(subjects[0], "digest"), "sha256");
    const expected = expected_digests.get(name) orelse return error.SlsaSubjectUnknownArtifact;
    if (!std.mem.eql(u8, expected, digest)) return error.SlsaSubjectDigestMismatch;
    const gop = try seen_subjects.getOrPut(name);
    if (gop.found_existing) return error.DuplicateSlsaSubject;
    summary.slsa_subjects += 1;
    return .{ .identity = identity, .started_at = started_at };
}

const VerifiedSlsaStatement = struct {
    identity: SourceIdentity,
    started_at: i64,
};

fn verifySlsaSourceParameters(statement: std.json.Value) !SourceIdentity {
    const predicate = try objectField(statement, "predicate");
    const definition = try objectField(predicate, "buildDefinition");
    if (!std.mem.eql(u8, try stringField(definition, "buildType"), release_slsa_build_type)) return error.InvalidSlsaBuildType;
    const parameters = try objectField(definition, "externalParameters");
    if (!std.mem.eql(u8, try stringField(parameters, "sourceControl"), release_source_control_jj)) return error.InvalidSlsaSourceControl;
    const change_id = try stringField(parameters, "changeId");
    const commit_id = try stringField(parameters, "commit");
    const repository = try stringField(parameters, "repository");
    const zig_version = try stringField(parameters, "zigVersion");
    const optimize_mode = try stringField(parameters, "optimizeMode");
    if (!looksLikeJjChangeId(change_id)) return error.InvalidSlsaChangeId;
    if (!looksLikeGitCommitId(commit_id)) return error.InvalidSlsaCommitId;
    if (!validSourceRepository(repository)) return error.InvalidSlsaRepository;
    if (!validZigVersion(zig_version)) return error.InvalidSlsaZigVersion;
    if (!std.mem.eql(u8, optimize_mode, release_optimize_mode)) return error.InvalidSlsaOptimizeMode;
    return .{
        .repository = repository,
        .change_id = change_id,
        .commit_id = commit_id,
        .zig_version = zig_version,
        .optimize_mode = optimize_mode,
        .builder_id = release_slsa_builder_id,
    };
}

fn verifySlsaRunMetadata(statement: std.json.Value, expected_builder: []const u8) !i64 {
    const details = try objectField(try objectField(statement, "predicate"), "runDetails");
    if (!std.mem.eql(u8, try stringField(try objectField(details, "builder"), "id"), expected_builder)) return error.InvalidSlsaBuilderId;
    const metadata = try objectField(details, "metadata");
    const started_on = try stringField(metadata, "startedOn");
    if (!looksLikeUtcSecond(started_on)) return error.InvalidSlsaStartedOn;
    const invocation_id = try stringField(metadata, "invocationId");
    if (!looksLikeUtcSecond(invocation_id)) return error.InvalidSlsaInvocationId;
    if (!std.mem.eql(u8, started_on, invocation_id)) return error.SlsaInvocationTimeMismatch;
    if (try integerField(metadata, "dirtyWorkspaceFileCount") != 0) return error.SlsaDirtyWorkspaceEvidence;
    return parseUtcSecond(started_on);
}

fn verifyReproducibleBuildSources(
    allocator: std.mem.Allocator,
    build_source: []const u8,
    digest_source: []const u8,
    expected_digests: *const std.StringHashMap([]const u8),
    expected_identity: SourceIdentity,
    summary: *VerificationSummary,
) !void {
    const parsed = try parseJsonValueStrict(allocator, build_source);
    const root = parsed.value;
    if (!std.mem.eql(u8, try stringField(root, "status"), "passed")) return error.ReproducibleBuildNotPassed;
    if (!std.mem.eql(u8, try stringField(root, "repo_vcs"), release_source_control_jj)) return error.ReproducibleBuildSourceControlMismatch;
    if (try integerField(root, "dirty_workspace_file_count") != 0) return error.ReproducibleBuildDirtyWorkspace;
    const candidate = SourceIdentity{
        .repository = try stringField(root, "repository"),
        .change_id = try stringField(root, "repo_change_id"),
        .commit_id = try stringField(root, "commit"),
        .zig_version = try stringField(root, "zig_version"),
        .optimize_mode = try stringField(root, "optimize_mode"),
        .builder_id = release_slsa_builder_id,
    };
    if (!sourceIdentitiesEqual(candidate, expected_identity)) return error.ReproducibleBuildSourceIdentityMismatch;
    const manifest_field = try stringField(root, "digest_manifest");
    if (!std.mem.eql(u8, std.fs.path.basename(manifest_field), "reproducible-artifact-digests.sha256")) return error.ReproducibleDigestManifestPathMismatch;
    var reproducible = std.StringHashMap([]const u8).init(allocator);
    try loadDigestManifestSource(allocator, digest_source, &reproducible);
    if (reproducible.count() != expected_digests.count()) return error.ReproducibleDigestCoverageMismatch;
    var iterator = reproducible.iterator();
    while (iterator.next()) |entry| {
        const expected = expected_digests.get(entry.key_ptr.*) orelse return error.ReproducibleDigestUnknownArtifact;
        if (!std.mem.eql(u8, expected, entry.value_ptr.*)) return error.ReproducibleDigestMismatch;
        summary.reproducible_digests += 1;
    }
}

fn verifySpdxSbomSource(allocator: std.mem.Allocator, source: []const u8) !void {
    const parsed = try parseJsonValueStrict(allocator, source);
    if (!std.mem.eql(u8, try stringField(parsed.value, "spdxVersion"), "SPDX-2.3")) return error.InvalidSpdxVersion;
}

fn requireValidJson(allocator: std.mem.Allocator, source: []const u8) !void {
    _ = try parseJsonValueStrict(allocator, source);
}

fn sourceIdentityFromManifest(release_manifest: *const trust.ReleaseManifest) SourceIdentity {
    return .{
        .repository = release_manifest.source.repository,
        .change_id = release_manifest.source.changeId,
        .commit_id = release_manifest.source.commitId,
        .zig_version = release_manifest.build.zigVersion,
        .optimize_mode = release_manifest.build.optimizeMode,
        .builder_id = release_manifest.build.builderId,
    };
}

fn sourceIdentitiesEqual(a: SourceIdentity, b: SourceIdentity) bool {
    return std.mem.eql(u8, a.repository, b.repository) and
        std.mem.eql(u8, a.change_id, b.change_id) and
        std.mem.eql(u8, a.commit_id, b.commit_id) and
        std.mem.eql(u8, a.zig_version, b.zig_version) and
        std.mem.eql(u8, a.optimize_mode, b.optimize_mode) and
        std.mem.eql(u8, a.builder_id, b.builder_id);
}

fn checkTrustState(
    allocator: std.mem.Allocator,
    io: std.Io,
    transaction: *const TrustStateTransaction,
    candidate: TrustState,
) !void {
    try validateTrustStateDirectory(io, transaction.parent);
    var file = transaction.parent.openFile(io, transaction.basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer file.close(io);
    try validateTrustStateFile(io, file);
    var reader = file.reader(io, &.{});
    const source = reader.interface.allocRemaining(allocator, .limited(max_release_metadata_bytes)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => return err,
    };
    var parsed = try std.json.parseFromSlice(TrustState, allocator, source, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    const state = parsed.value;
    if (state.schemaVersion != 1) return error.UnsupportedTrustStateSchema;
    if (!std.mem.eql(u8, state.rootSha256, candidate.rootSha256)) return error.TrustedRootChanged;
    if (state.rootVersion != candidate.rootVersion) return error.TrustedRootVersionChanged;
    if (candidate.observedAt < state.observedAt) return error.TrustClockRollback;
    if (candidate.policyVersion < state.policyVersion) return error.TrustPolicyRollback;
    if (candidate.policyVersion == state.policyVersion and !std.mem.eql(u8, candidate.policyPayloadSha256, state.policyPayloadSha256)) return error.TrustPolicyEquivocation;
    if (candidate.releaseSequence < state.releaseSequence) return error.ReleaseSequenceRollback;
    if (candidate.releaseSequence == state.releaseSequence and !std.mem.eql(u8, candidate.manifestPayloadSha256, state.manifestPayloadSha256)) return error.ReleaseManifestEquivocation;
}

fn writeTrustStateAtomic(
    allocator: std.mem.Allocator,
    io: std.Io,
    transaction: *const TrustStateTransaction,
    state: TrustState,
) !void {
    try validateTrustStateDirectory(io, transaction.parent);
    const temporary_name = try std.fmt.allocPrint(allocator, ".{s}.tmp", .{transaction.basename});
    const serialized = try std.json.Stringify.valueAlloc(allocator, state, .{});
    transaction.parent.deleteFile(io, temporary_name) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    var file = try transaction.parent.createFile(io, temporary_name, .{ .exclusive = true, .permissions = ownerOnlyPermissions() });
    var file_open = true;
    var temporary_exists = true;
    defer {
        if (file_open) file.close(io);
        if (temporary_exists) transaction.parent.deleteFile(io, temporary_name) catch {};
    }
    try validateTrustStateFile(io, file);
    try file.writeStreamingAll(io, serialized);
    try file.sync(io);
    file.close(io);
    file_open = false;
    try std.Io.Dir.rename(transaction.parent, temporary_name, transaction.parent, transaction.basename, io);
    temporary_exists = false;
    var directory_file = try transaction.parent.openFile(io, ".", .{
        .allow_directory = true,
        .follow_symlinks = false,
    });
    defer directory_file.close(io);
    try directory_file.sync(io);
}

fn openTrustStateTransaction(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    release_root: ContainedRoot,
    artifact_root: ContainedRoot,
) !TrustStateTransaction {
    const parent_path = std.fs.path.dirname(state_path) orelse ".";
    const basename = std.fs.path.basename(state_path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, "..")) return error.InvalidTrustStatePath;
    var parent = try std.Io.Dir.cwd().openDir(io, parent_path, .{ .follow_symlinks = false });
    errdefer parent.close(io);
    try validateTrustStateDirectory(io, parent);
    const canonical_parent = try canonicalDirPathAlloc(allocator, io, parent);
    const state_absolute = try std.fs.path.join(allocator, &.{ canonical_parent, basename });
    if (pathIsContained(release_root.canonical_path, state_absolute) or
        pathIsContained(artifact_root.canonical_path, state_absolute))
    {
        return error.TrustStateMustBeExternal;
    }
    const lock_name = try std.fmt.allocPrint(allocator, ".{s}.lock", .{basename});
    var lock_file = parent.createFile(io, lock_name, .{
        .truncate = false,
        .exclusive = true,
        .lock = .exclusive,
        .permissions = ownerOnlyPermissions(),
    }) catch |err| switch (err) {
        error.PathAlreadyExists => try parent.openFile(io, lock_name, .{
            .mode = .read_write,
            .follow_symlinks = false,
            .lock = .exclusive,
        }),
        else => return err,
    };
    errdefer lock_file.close(io);
    try lock_file.setPermissions(io, ownerOnlyPermissions());
    try validateTrustStateFile(io, lock_file);
    try validateTrustStateDirectory(io, parent);
    return .{ .parent = parent, .basename = basename, .lock_file = lock_file };
}

fn ownerOnlyPermissions() std.Io.File.Permissions {
    if (comptime @hasDecl(std.Io.File.Permissions, "fromMode")) {
        return std.Io.File.Permissions.fromMode(0o600);
    }
    return .default_file;
}

fn permissionsAreOwnerControlled(permissions: std.Io.File.Permissions, directory: bool) bool {
    if (comptime @hasDecl(std.Io.File.Permissions, "toMode")) {
        const forbidden: std.posix.mode_t = if (directory) 0o022 else 0o077;
        return permissions.toMode() & forbidden == 0;
    }
    return false;
}

fn validateTrustStateDirectory(io: std.Io, directory: std.Io.Dir) !void {
    const stat = try directory.stat(io);
    const has_extended_acl = try handleHasExtendedAcl(directory.handle);
    if (stat.kind != .directory or !permissionsAreOwnerControlled(stat.permissions, true) or
        !try handleOwnedByEffectiveUser(directory.handle) or has_extended_acl)
    {
        return error.InsecureTrustStateDirectory;
    }
}

fn validateTrustStateFile(io: std.Io, file: std.Io.File) !void {
    const stat = try file.stat(io);
    const has_extended_acl = try handleHasExtendedAcl(file.handle);
    if (stat.kind != .file or !permissionsAreOwnerControlled(stat.permissions, false) or
        !try handleOwnedByEffectiveUser(file.handle) or has_extended_acl)
    {
        return error.InsecureTrustStateFile;
    }
}

fn handleHasExtendedAcl(handle: std.posix.fd_t) !bool {
    if (comptime builtin.os.tag.isDarwin()) {
        const acl = DarwinAcl.acl_get_fd_np(handle, DarwinAcl.type_extended) orelse {
            return switch (std.posix.errno(-1)) {
                .NOENT => false,
                else => error.TrustStateAclCheckFailed,
            };
        };
        var entry: ?*anyopaque = null;
        const entry_result = DarwinAcl.acl_get_entry(acl, DarwinAcl.first_entry, &entry);
        const free_result = DarwinAcl.acl_free(acl);
        if (entry_result != 0 or entry == null or free_result != 0) return error.TrustStateAclCheckFailed;
        return true;
    }
    return false;
}

fn handleOwnedByEffectiveUser(handle: std.posix.fd_t) !bool {
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var statx = std.mem.zeroes(linux.Statx);
        const request: linux.STATX = .{ .UID = true };
        while (true) switch (std.posix.errno(linux.statx(handle, "", linux.AT.EMPTY_PATH, request, &statx))) {
            .SUCCESS => return statx.uid == linux.geteuid(),
            .INTR => continue,
            else => return error.TrustStateOwnershipCheckFailed,
        };
    }
    if (comptime std.posix.Stat != void and @hasDecl(std.posix.system, "fstat") and @hasDecl(std.posix.system, "geteuid")) {
        const fstat_sym = if (std.posix.lfs64_abi) std.posix.system.fstat64 else std.posix.system.fstat;
        var stat = std.mem.zeroes(std.posix.Stat);
        while (true) switch (std.posix.errno(fstat_sym(handle, &stat))) {
            .SUCCESS => return stat.uid == std.posix.system.geteuid(),
            .INTR => continue,
            else => return error.TrustStateOwnershipCheckFailed,
        };
    }
    return error.UnsupportedTrustStatePlatform;
}

fn rejectCliTrustPaths(
    allocator: std.mem.Allocator,
    io: std.Io,
    trusted_root_path: []const u8,
    release_path: []const u8,
    artifact_path: []const u8,
) !void {
    const trusted_root_absolute = try std.Io.Dir.cwd().realPathFileAlloc(io, trusted_root_path, allocator);
    const release_absolute = try std.Io.Dir.cwd().realPathFileAlloc(io, release_path, allocator);
    const artifact_absolute = try std.Io.Dir.cwd().realPathFileAlloc(io, artifact_path, allocator);
    if (pathIsContained(release_absolute, trusted_root_absolute) or pathIsContained(artifact_absolute, trusted_root_absolute)) {
        return error.TrustedRootMustBeExternal;
    }
}

fn openContainedRoot(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !ContainedRoot {
    const dir = try std.Io.Dir.cwd().openDir(io, path, .{ .follow_symlinks = false, .iterate = true });
    errdefer dir.close(io);
    const canonical = try canonicalDirPathAlloc(allocator, io, dir);
    return .{ .dir = dir, .canonical_path = canonical };
}

fn canonicalDirPathAlloc(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) ![]const u8 {
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const length = try dir.realPath(io, &buffer);
    return allocator.dupe(u8, buffer[0..length]);
}

fn readContainedFileAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: ContainedRoot,
    relative_path: []const u8,
    limit: usize,
) ![]u8 {
    var file = try openContainedFile(io, root, relative_path);
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => return err,
    };
}

fn openContainedFile(io: std.Io, root: ContainedRoot, relative_path: []const u8) !std.Io.File {
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (!catalog.isSafeRelativePath(relative_path)) return error.UnsafeArtifactPath;
    const length = try root.dir.realPathFile(io, relative_path, &path_buffer);
    const canonical = path_buffer[0..length];
    if (!pathIsContained(root.canonical_path, canonical) or std.mem.eql(u8, root.canonical_path, canonical)) return error.PathEscapesRoot;
    return root.dir.openFile(io, relative_path, .{ .follow_symlinks = false, .resolve_beneath = true });
}

fn pathIsContained(root: []const u8, candidate: []const u8) bool {
    if (!std.mem.startsWith(u8, candidate, root)) return false;
    if (candidate.len == root.len) return true;
    if (root.len > 0 and std.fs.path.isSep(root[root.len - 1])) return true;
    return std.fs.path.isSep(candidate[root.len]);
}

fn readExternalFileAlloc(io: std.Io, path: []const u8, allocator: std.mem.Allocator, limit: usize) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => return err,
    };
}

fn parseJsonValueStrict(allocator: std.mem.Allocator, source: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, source, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
    });
}

fn nextNonEmptyLine(iterator: *std.mem.SplitIterator(u8, .scalar)) ?[]const u8 {
    while (iterator.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len != 0) return line;
    }
    return null;
}

fn dssePreauthEncoding(allocator: std.mem.Allocator, payload_type: []const u8, payload: []const u8) ![]u8 {
    const prefix = try std.fmt.allocPrint(allocator, "DSSEv1 {d} {s} {d} ", .{ payload_type.len, payload_type, payload.len });
    return std.mem.concat(allocator, u8, &.{ prefix, payload });
}

fn decodeBase64Alloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const size = std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
    const output = try allocator.alloc(u8, size);
    std.base64.standard.Decoder.decode(output, text) catch return error.InvalidBase64;
    return output;
}

/// Call only after the corresponding trust verifier has authenticated the
/// envelope. Rollback identity belongs to the signed payload; JSON whitespace,
/// member order, and other unsigned DSSE wrapper serialization do not.
fn authenticatedPayloadSha256(
    allocator: std.mem.Allocator,
    envelope_source: []const u8,
    expected_payload_type: []const u8,
    output: *[sha256_hex_len]u8,
) ![]const u8 {
    var envelope = try std.json.parseFromSlice(ProvenanceEnvelope, allocator, envelope_source, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });
    defer envelope.deinit();
    if (!std.mem.eql(u8, envelope.value.payloadType, expected_payload_type)) return error.InvalidDssePayloadType;
    const payload = try decodeBase64Alloc(allocator, envelope.value.payload);
    defer allocator.free(payload);
    return trust.sha256Hex(payload, output);
}

fn decodeHexFixed(comptime len: usize, value: []const u8) ![len]u8 {
    if (value.len != len * 2) return error.InvalidHexLength;
    var output: [len]u8 = undefined;
    for (&output, 0..) |*byte, index| {
        const high = hexValue(value[index * 2]) orelse return error.InvalidHexDigit;
        const low = hexValue(value[index * 2 + 1]) orelse return error.InvalidHexDigit;
        byte.* = (high << 4) | low;
    }
    return output;
}

fn hexValue(byte: u8) ?u8 {
    if (byte >= '0' and byte <= '9') return byte - '0';
    if (byte >= 'a' and byte <= 'f') return byte - 'a' + 10;
    return null;
}

fn sha256HexAlloc(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    const output = try allocator.alloc(u8, sha256_hex_len);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    trust.encodeHexLower(&digest, output);
    return output;
}

fn isSha256Hex(value: []const u8) bool {
    if (value.len != sha256_hex_len) return false;
    for (value) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return false;
    return true;
}

fn looksLikeJjChangeId(value: []const u8) bool {
    if (value.len != jj_change_id_len) return false;
    for (value) |byte| if (byte < 'a' or byte > 'z') return false;
    return true;
}

fn looksLikeGitCommitId(value: []const u8) bool {
    return value.len == git_commit_id_hex_len and isLowerHex(value);
}

fn isLowerHex(value: []const u8) bool {
    for (value) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return false;
    return true;
}

fn validSourceRepository(value: []const u8) bool {
    return value.len > 0 and !std.mem.eql(u8, value, "NOASSERTION") and !std.mem.eql(u8, value, "unknown");
}

fn validZigVersion(value: []const u8) bool {
    return value.len > 0 and !std.mem.eql(u8, value, "unknown");
}

fn looksLikeUtcSecond(value: []const u8) bool {
    if (value.len != "YYYY-MM-DDTHH:MM:SSZ".len) return false;
    const separators = [_]struct { index: usize, byte: u8 }{
        .{ .index = 4, .byte = '-' },  .{ .index = 7, .byte = '-' },  .{ .index = 10, .byte = 'T' },
        .{ .index = 13, .byte = ':' }, .{ .index = 16, .byte = ':' }, .{ .index = 19, .byte = 'Z' },
    };
    for (separators) |separator| if (value[separator.index] != separator.byte) return false;
    for (value, 0..) |byte, index| {
        var is_separator = false;
        for (separators) |separator| {
            if (index == separator.index) is_separator = true;
        }
        if (!is_separator and (byte < '0' or byte > '9')) return false;
    }
    return true;
}

fn parseUtcSecond(value: []const u8) !i64 {
    if (!looksLikeUtcSecond(value)) return error.InvalidUtcSecond;
    const year = try parseDecimal(u16, value[0..4]);
    const month_number = try parseDecimal(u8, value[5..7]);
    const day = try parseDecimal(u8, value[8..10]);
    const hour = try parseDecimal(u8, value[11..13]);
    const minute = try parseDecimal(u8, value[14..16]);
    const second = try parseDecimal(u8, value[17..19]);
    if (year < std.time.epoch.epoch_year or month_number < 1 or month_number > 12 or
        hour > 23 or minute > 59 or second > 59)
    {
        return error.InvalidUtcSecond;
    }
    const month: std.time.epoch.Month = @enumFromInt(month_number);
    const days_in_month = std.time.epoch.getDaysInMonth(year, month);
    if (day < 1 or day > days_in_month) return error.InvalidUtcSecond;
    var days: u64 = 0;
    var current_year: std.time.epoch.Year = std.time.epoch.epoch_year;
    while (current_year < year) : (current_year += 1) days += std.time.epoch.getDaysInYear(current_year);
    var current_month: u8 = 1;
    while (current_month < month_number) : (current_month += 1) {
        days += std.time.epoch.getDaysInMonth(year, @enumFromInt(current_month));
    }
    days += day - 1;
    const seconds = days * std.time.s_per_day + @as(u64, hour) * std.time.s_per_hour +
        @as(u64, minute) * std.time.s_per_min + second;
    return @intCast(seconds);
}

fn parseDecimal(comptime T: type, value: []const u8) !T {
    var result: T = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDecimal;
        result = std.math.mul(T, result, 10) catch return error.InvalidDecimal;
        result = std.math.add(T, result, byte - '0') catch return error.InvalidDecimal;
    }
    return result;
}

fn objectField(value: std.json.Value, name: []const u8) !std.json.Value {
    return switch (value) {
        .object => |object| object.get(name) orelse error.MissingJsonField,
        else => error.JsonFieldNotObject,
    };
}

fn arrayField(value: std.json.Value, name: []const u8) ![]std.json.Value {
    return switch (try objectField(value, name)) {
        .array => |array| array.items,
        else => error.JsonFieldNotArray,
    };
}

fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    return switch (try objectField(value, name)) {
        .string => |string| string,
        else => error.JsonFieldNotString,
    };
}

fn integerField(value: std.json.Value, name: []const u8) !i64 {
    return switch (try objectField(value, name)) {
        .integer => |integer| integer,
        else => error.JsonFieldNotInteger,
    };
}

const fixture_now: i64 = 1_780_000_000;
const fixture_jj_change_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const fixture_commit_id = "1111111111111111111111111111111111111111";
const fixture_repository = "ssh://git@example.com/zigos.git";
const fixture_zig_version = "0.16.0";
const fixture_profile_id = "zigos-production-v1";

const Fixture = struct {
    bundle_path: []const u8,
    artifact_path: []const u8,
    state_path: []const u8,
    root_source: []const u8,
    root_digest: []const u8,
    release_key_pair: Ed25519.KeyPair,
    release_key_id: []const u8,
    targets: []const trust.FileRecord,
    evidence: []const trust.FileRecord,
};

const TestEnvelopeSignature = struct {
    keyid: []const u8,
    sig: []const u8,
};

const TestEnvelope = struct {
    payloadType: []const u8,
    payload: []const u8,
    signatures: []const TestEnvelopeSignature,
};

const ReserializedTestEnvelope = struct {
    signatures: []const TestEnvelopeSignature,
    payload: []const u8,
    payloadType: []const u8,
};

test "authenticated exact release bundle verifies and advances external state idempotently" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    const options = fixtureOptions(fixture, fixture_now);

    const first = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options);
    try std.testing.expectEqual(catalog.productionTargetPaths().len, first.artifacts);
    try std.testing.expectEqual(catalog.releaseEvidenceNames().len, first.evidence_files);
    try std.testing.expectEqual(catalog.productionTargetPaths().len, first.slsa_subjects);
    try std.testing.expectEqual(catalog.productionTargetPaths().len, first.measurements);
    try std.testing.expectEqual(catalog.productionTargetPaths().len, first.reproducible_digests);

    const second = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options);
    try std.testing.expectEqual(first.artifacts, second.artifacts);
    const state_stat = try std.Io.Dir.cwd().statFile(std.testing.io, fixture.state_path, .{ .follow_symlinks = false });
    try std.testing.expect(permissionsAreOwnerControlled(state_stat.permissions, false));
    const state_parent = std.fs.path.dirname(fixture.state_path).?;
    const state_lock_path = try std.fs.path.join(allocator, &.{ state_parent, ".state.json.lock" });
    const lock_stat = try std.Io.Dir.cwd().statFile(std.testing.io, state_lock_path, .{ .follow_symlinks = false });
    try std.testing.expect(permissionsAreOwnerControlled(lock_stat.permissions, false));
}

test "trust state transaction stays bound to validated parent after path replacement" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const base = try testingRootPath(allocator, tmp.sub_path[0..]);
    const fixture = try writeExactFixture(allocator, tmp.dir, base, 7);
    var release_root = try openContainedRoot(allocator, std.testing.io, fixture.bundle_path);
    defer release_root.close(std.testing.io);
    var artifact_root = try openContainedRoot(allocator, std.testing.io, fixture.artifact_path);
    defer artifact_root.close(std.testing.io);
    var transaction = try openTrustStateTransaction(
        allocator,
        std.testing.io,
        fixture.state_path,
        release_root,
        artifact_root,
    );
    defer transaction.close(std.testing.io);

    try tmp.dir.createDirPath(std.testing.io, "replacement");
    try std.Io.Dir.rename(tmp.dir, "trust", tmp.dir, "trust-original", std.testing.io);
    try std.Io.Dir.rename(tmp.dir, "replacement", tmp.dir, "trust", std.testing.io);

    const zero_digest = "0000000000000000000000000000000000000000000000000000000000000000";
    const state = TrustState{
        .schemaVersion = 1,
        .rootSha256 = fixture.root_digest,
        .rootVersion = 1,
        .policyVersion = 3,
        .policyPayloadSha256 = zero_digest,
        .releaseSequence = 7,
        .manifestPayloadSha256 = zero_digest,
        .observedAt = fixture_now,
    };
    try checkTrustState(allocator, std.testing.io, &transaction, state);
    try writeTrustStateAtomic(allocator, std.testing.io, &transaction, state);

    const original_state_path = try std.fs.path.join(allocator, &.{ base, "trust-original", "state.json" });
    const stored_source = try readExternalFileAlloc(std.testing.io, original_state_path, allocator, max_release_metadata_bytes);
    var stored = try std.json.parseFromSlice(TrustState, allocator, stored_source, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });
    defer stored.deinit();
    try std.testing.expectEqual(state.releaseSequence, stored.value.releaseSequence);
    try std.testing.expectError(
        error.FileNotFound,
        readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes),
    );
}

test "trust state rejects insecure parent and state file modes" {
    if (builtin.os.tag == .windows or !@hasDecl(std.Io.File.Permissions, "fromMode")) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);

    {
        var trust_dir = try tmp.dir.openDir(std.testing.io, "trust", .{ .iterate = true });
        defer trust_dir.close(std.testing.io);
        try trust_dir.setPermissions(std.testing.io, std.Io.File.Permissions.fromMode(0o777));
        defer trust_dir.setPermissions(std.testing.io, std.Io.File.Permissions.fromMode(0o700)) catch {};
        try std.testing.expectError(
            error.InsecureTrustStateDirectory,
            verifyReleaseBundle(
                allocator,
                std.testing.io,
                fixture.bundle_path,
                fixture.artifact_path,
                fixtureOptions(fixture, fixture_now),
            ),
        );
    }

    _ = try verifyReleaseBundle(
        allocator,
        std.testing.io,
        fixture.bundle_path,
        fixture.artifact_path,
        fixtureOptions(fixture, fixture_now),
    );
    {
        var state_file = try std.Io.Dir.cwd().openFile(std.testing.io, fixture.state_path, .{ .mode = .read_write });
        defer state_file.close(std.testing.io);
        try state_file.setPermissions(std.testing.io, std.Io.File.Permissions.fromMode(0o644));
    }
    try std.testing.expectError(
        error.InsecureTrustStateFile,
        verifyReleaseBundle(
            allocator,
            std.testing.io,
            fixture.bundle_path,
            fixture.artifact_path,
            fixtureOptions(fixture, fixture_now),
        ),
    );
}

test "Darwin trust state rejects extended ACLs on parent state and lock handles" {
    if (comptime !builtin.os.tag.isDarwin()) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    const options = fixtureOptions(fixture, fixture_now);

    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options);
    var trust_dir = try tmp.dir.openDir(std.testing.io, "trust", .{});
    defer trust_dir.close(std.testing.io);

    {
        var state_file = try trust_dir.openFile(std.testing.io, "state.json", .{ .mode = .read_write });
        defer state_file.close(std.testing.io);
        try installDarwinExtendedAcl(state_file.handle);
        try std.testing.expect(permissionsAreOwnerControlled((try state_file.stat(std.testing.io)).permissions, false));
    }
    try std.testing.expectError(
        error.InsecureTrustStateFile,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options),
    );
    try trust_dir.deleteFile(std.testing.io, "state.json");
    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options);

    {
        var lock_file = try trust_dir.openFile(std.testing.io, ".state.json.lock", .{ .mode = .read_write });
        defer lock_file.close(std.testing.io);
        try installDarwinExtendedAcl(lock_file.handle);
        try std.testing.expect(permissionsAreOwnerControlled((try lock_file.stat(std.testing.io)).permissions, false));
    }
    try std.testing.expectError(
        error.InsecureTrustStateFile,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options),
    );
    try trust_dir.deleteFile(std.testing.io, ".state.json.lock");
    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options);

    try installDarwinExtendedAcl(trust_dir.handle);
    try std.testing.expect(permissionsAreOwnerControlled((try trust_dir.stat(std.testing.io)).permissions, true));
    try std.testing.expectError(
        error.InsecureTrustStateDirectory,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options),
    );
}

test "trust state identifies authenticated payloads across DSSE envelope reserialization" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    const options = fixtureOptions(fixture, fixture_now);

    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options);
    const state_before = try readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes);
    const stable_state = try allocator.dupe(u8, state_before);

    {
        var bundle = try std.Io.Dir.cwd().openDir(std.testing.io, fixture.bundle_path, .{});
        defer bundle.close(std.testing.io);
        const manifest_source = try bundle.readFileAlloc(
            std.testing.io,
            release_manifest_name,
            allocator,
            .limited(max_release_metadata_bytes),
        );
        const reserialized_manifest = try reserializeTestEnvelopeAlloc(allocator, manifest_source);
        try bundle.writeFile(std.testing.io, .{ .sub_path = release_manifest_name, .data = reserialized_manifest });
    }

    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, options);
    const state_after = try readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes);
    try std.testing.expectEqualStrings(stable_state, state_after);

    const next_evidence = try allocator.dupe(trust.FileRecord, fixture.evidence);
    {
        var bundle = try std.Io.Dir.cwd().openDir(std.testing.io, fixture.bundle_path, .{});
        defer bundle.close(std.testing.io);
        const policy_source = try bundle.readFileAlloc(
            std.testing.io,
            trust_policy_name,
            allocator,
            .limited(max_release_metadata_bytes),
        );
        const reserialized_policy = try reserializeTestEnvelopeAlloc(allocator, policy_source);
        try bundle.writeFile(std.testing.io, .{ .sub_path = trust_policy_name, .data = reserialized_policy });
        for (next_evidence) |*record| {
            if (!std.mem.eql(u8, record.path, trust_policy_name)) continue;
            record.sha256 = try sha256HexAlloc(allocator, reserialized_policy);
            record.sizeBytes = reserialized_policy.len;
            break;
        }
    }
    try writeFixtureManifestRecords(
        allocator,
        fixture,
        fixture.targets,
        next_evidence,
        8,
        1_779_999_001,
        1_890_000_000,
    );
    _ = try verifyReleaseBundle(
        allocator,
        std.testing.io,
        fixture.bundle_path,
        fixture.artifact_path,
        fixtureOptions(fixture, fixture_now + 1),
    );
}

test "candidate verification checks history without advancing trust state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    var candidate_options = fixtureOptions(fixture, fixture_now);
    candidate_options.advance_trust_state = false;

    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, candidate_options);
    try std.testing.expectError(
        error.FileNotFound,
        readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes),
    );

    _ = try verifyReleaseBundle(
        allocator,
        std.testing.io,
        fixture.bundle_path,
        fixture.artifact_path,
        fixtureOptions(fixture, fixture_now),
    );
    const state_before = try readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes);
    const stable_state = try allocator.dupe(u8, state_before);
    candidate_options.now_unix += 1;
    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, candidate_options);
    const state_after = try readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes);
    try std.testing.expectEqualStrings(stable_state, state_after);

    try writeFixtureManifest(allocator, fixture, 6, 1_779_999_000, 1_890_000_000);
    try std.testing.expectError(
        error.ReleaseSequenceRollback,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, candidate_options),
    );
    try writeFixtureManifest(allocator, fixture, 7, 1_779_999_001, 1_890_000_000);
    try std.testing.expectError(
        error.ReleaseManifestEquivocation,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, candidate_options),
    );
}

test "authenticated release bundle rejects a substituted root pin" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    try std.testing.expectError(error.RootDigestMismatch, verifyReleaseBundle(
        allocator,
        std.testing.io,
        fixture.bundle_path,
        fixture.artifact_path,
        .{
            .trusted_root = fixture.root_source,
            .trusted_root_sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
            .trust_state_path = fixture.state_path,
            .now_unix = fixture_now,
        },
    ));
}

test "authenticated evidence is checked before its contents are parsed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    var bundle = try std.Io.Dir.cwd().openDir(std.testing.io, fixture.bundle_path, .{});
    defer bundle.close(std.testing.io);
    try bundle.writeFile(std.testing.io, .{ .sub_path = "sbom.spdx.json", .data = "{\"spdxVersion\":\"SPDX-2.2\"}\n" });
    try std.testing.expectError(
        error.EvidenceDigestMismatch,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );
    try std.testing.expectError(
        error.FileNotFound,
        readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes),
    );
}

test "bundle directory rejects unexpected entries and does not create state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    var bundle = try std.Io.Dir.cwd().openDir(std.testing.io, fixture.bundle_path, .{});
    defer bundle.close(std.testing.io);
    try bundle.writeFile(std.testing.io, .{ .sub_path = "kernel-verification.elf", .data = "not public" });
    try std.testing.expectError(
        error.UnexpectedBundleEntry,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );
    try std.testing.expectError(
        error.FileNotFound,
        readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes),
    );
}

test "late evidence failure cannot advance existing trust state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now));
    const state_before = try readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes);
    const stable_copy = try allocator.dupe(u8, state_before);
    var bundle = try std.Io.Dir.cwd().openDir(std.testing.io, fixture.bundle_path, .{});
    defer bundle.close(std.testing.io);
    try bundle.writeFile(std.testing.io, .{ .sub_path = "sbom.spdx.json", .data = "{\"spdxVersion\":\"SPDX-2.2\"}\n" });
    try std.testing.expectError(
        error.EvidenceDigestMismatch,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now + 1)),
    );
    const state_after = try readExternalFileAlloc(std.testing.io, fixture.state_path, allocator, max_release_metadata_bytes);
    try std.testing.expectEqualStrings(stable_copy, state_after);
}

test "bundle directory rejects deleted manifest and policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    var bundle = try std.Io.Dir.cwd().openDir(std.testing.io, fixture.bundle_path, .{});
    defer bundle.close(std.testing.io);
    try bundle.deleteFile(std.testing.io, release_manifest_name);
    try std.testing.expectError(
        error.BundleEntrySetMismatch,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );
    try writeFixtureManifest(allocator, fixture, 7, 1_779_999_000, 1_890_000_000);
    try bundle.deleteFile(std.testing.io, trust_policy_name);
    try std.testing.expectError(
        error.BundleEntrySetMismatch,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );
}

test "re-signed manifest cannot reduce the production catalog to 32 targets" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    try writeFixtureManifestRecords(
        allocator,
        fixture,
        fixture.targets[0 .. fixture.targets.len - 1],
        fixture.evidence,
        7,
        1_779_999_000,
        1_890_000_000,
    );
    try std.testing.expectError(
        error.ArtifactSetMismatch,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );
}

test "persisted policy history rejects rollback and same-version equivocation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    const zero_digest = "0000000000000000000000000000000000000000000000000000000000000000";
    try writeTrustStateForTest(allocator, fixture.state_path, .{
        .schemaVersion = 1,
        .rootSha256 = fixture.root_digest,
        .rootVersion = 1,
        .policyVersion = 4,
        .policyPayloadSha256 = zero_digest,
        .releaseSequence = 1,
        .manifestPayloadSha256 = zero_digest,
        .observedAt = fixture_now,
    });
    try std.testing.expectError(
        error.TrustPolicyRollback,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );
    try writeTrustStateForTest(allocator, fixture.state_path, .{
        .schemaVersion = 1,
        .rootSha256 = fixture.root_digest,
        .rootVersion = 1,
        .policyVersion = 3,
        .policyPayloadSha256 = zero_digest,
        .releaseSequence = 1,
        .manifestPayloadSha256 = zero_digest,
        .observedAt = fixture_now,
    });
    try std.testing.expectError(
        error.TrustPolicyEquivocation,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );
}

test "persistent trust state rejects release rollback equivocation and clock rollback" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    _ = try verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now));

    try writeFixtureManifest(allocator, fixture, 6, 1_779_999_000, 1_890_000_000);
    try std.testing.expectError(
        error.ReleaseSequenceRollback,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );

    try writeFixtureManifest(allocator, fixture, 7, 1_779_999_001, 1_890_000_000);
    try std.testing.expectError(
        error.ReleaseManifestEquivocation,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );

    try writeFixtureManifest(allocator, fixture, 7, 1_779_999_000, 1_890_000_000);
    try std.testing.expectError(
        error.TrustClockRollback,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now - 1)),
    );
}

test "artifact symlink escape is rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const fixture = try writeExactFixture(allocator, tmp.dir, try testingRootPath(allocator, tmp.sub_path[0..]), 7);
    var artifacts = try std.Io.Dir.cwd().openDir(std.testing.io, fixture.artifact_path, .{});
    defer artifacts.close(std.testing.io);
    try artifacts.deleteFile(std.testing.io, "build/os.iso");
    try artifacts.symLink(std.testing.io, "../../trust/outside", "build/os.iso", .{});
    var trust_dir = try tmp.dir.openDir(std.testing.io, "trust", .{});
    defer trust_dir.close(std.testing.io);
    try trust_dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "artifact:build/os.iso\n" });
    try std.testing.expectError(
        error.PathEscapesRoot,
        verifyReleaseBundle(allocator, std.testing.io, fixture.bundle_path, fixture.artifact_path, fixtureOptions(fixture, fixture_now)),
    );
}

fn fixtureOptions(fixture: Fixture, now_unix: i64) VerifyOptions {
    return .{
        .trusted_root = fixture.root_source,
        .trusted_root_sha256 = fixture.root_digest,
        .trust_state_path = fixture.state_path,
        .now_unix = now_unix,
    };
}

fn writeExactFixture(
    allocator: std.mem.Allocator,
    root_dir: std.Io.Dir,
    base: []const u8,
    release_sequence: u64,
) !Fixture {
    try root_dir.createDirPath(std.testing.io, "bundle");
    try root_dir.createDirPath(std.testing.io, "artifacts");
    try root_dir.createDirPath(std.testing.io, "trust");
    var bundle = try root_dir.openDir(std.testing.io, "bundle", .{});
    defer bundle.close(std.testing.io);
    var artifacts = try root_dir.openDir(std.testing.io, "artifacts", .{});
    defer artifacts.close(std.testing.io);

    const root_pair_a = try Ed25519.KeyPair.generateDeterministic([_]u8{0x11} ** Ed25519.KeyPair.seed_length);
    const root_pair_b = try Ed25519.KeyPair.generateDeterministic([_]u8{0x22} ** Ed25519.KeyPair.seed_length);
    const release_pair = try Ed25519.KeyPair.generateDeterministic([_]u8{0x33} ** Ed25519.KeyPair.seed_length);
    const root_public_a = root_pair_a.public_key.toBytes();
    const root_public_b = root_pair_b.public_key.toBytes();
    const release_public = release_pair.public_key.toBytes();
    const root_public_hex_a = try hexLowerAlloc(allocator, &root_public_a);
    const root_public_hex_b = try hexLowerAlloc(allocator, &root_public_b);
    const release_public_hex = try hexLowerAlloc(allocator, &release_public);
    var id_buffer_a: [sha256_hex_len]u8 = undefined;
    var id_buffer_b: [sha256_hex_len]u8 = undefined;
    var release_id_buffer: [sha256_hex_len]u8 = undefined;
    const root_id_a = try allocator.dupe(u8, trust.keyIdForEd25519(root_public_a, &id_buffer_a));
    const root_id_b = try allocator.dupe(u8, trust.keyIdForEd25519(root_public_b, &id_buffer_b));
    const release_id = try allocator.dupe(u8, trust.keyIdForEd25519(release_public, &release_id_buffer));

    const root_keys = try allocator.dupe(trust.RootKey, &.{
        .{ .keyId = root_id_a, .algorithm = .ed25519, .publicKey = root_public_hex_a },
        .{ .keyId = root_id_b, .algorithm = .ed25519, .publicKey = root_public_hex_b },
    });
    const root_metadata = trust.RootMetadata{
        .schemaVersion = 1,
        .namespace = "zigos",
        .channel = "production",
        .version = 1,
        .issuedAt = 1_700_000_000,
        .expiresAt = 1_900_000_000,
        .minimumPolicyVersion = 3,
        .threshold = 2,
        .keys = root_keys,
    };
    const root_source = try std.json.Stringify.valueAlloc(allocator, root_metadata, .{});
    const root_digest = try sha256HexAlloc(allocator, root_source);

    const release_keys = try allocator.dupe(trust.ReleaseKey, &.{.{
        .keyId = release_id,
        .algorithm = .ed25519,
        .generation = 1,
        .status = .active,
        .custody = "fixture-hardware-security-module",
        .hardwareBacked = true,
        .notBefore = 1_700_000_000,
        .notAfter = 1_900_000_000,
        .publicKey = release_public_hex,
    }});
    const role_ids = try allocator.dupe([]const u8, &.{release_id});
    const policy = trust.TrustPolicy{
        .rootVersion = 1,
        .policyVersion = 3,
        .minimumReleaseSequence = 1,
        .issuedAt = 1_700_000_010,
        .expiresAt = 1_899_999_999,
        .releaseRole = .{ .threshold = 1, .keyIds = role_ids },
        .releaseKeys = release_keys,
        .revocations = &.{},
        .artifactProfile = .{
            .profileId = fixture_profile_id,
            .exactTargets = catalog.productionTargetPaths(),
            .exactEvidence = catalog.releaseEvidenceNames(),
        },
        .pqcPolicy = .{ .mode = .shadow, .requiredAlgorithm = "ml-dsa-65", .fipsValidatedRequired = true },
    };
    const policy_payload = try std.json.Stringify.valueAlloc(allocator, policy, .{});
    const policy_source = try signedEnvelopeAlloc(
        allocator,
        trust.trust_policy_payload_type,
        policy_payload,
        &.{ root_pair_a, root_pair_b },
        &.{ root_id_a, root_id_b },
    );

    const targets = try allocator.alloc(trust.FileRecord, catalog.productionTargetPaths().len);
    for (catalog.productionTargetPaths(), 0..) |path, index| {
        const parent = std.fs.path.dirname(path);
        if (parent) |directory| try artifacts.createDirPath(std.testing.io, directory);
        const data = try std.fmt.allocPrint(allocator, "artifact:{s}\n", .{path});
        try artifacts.writeFile(std.testing.io, .{ .sub_path = path, .data = data });
        targets[index] = .{ .path = path, .sha256 = try sha256HexAlloc(allocator, data), .sizeBytes = data.len };
    }

    const digest_projection = try digestProjectionAlloc(allocator, targets);
    const measurements = try measurementsAlloc(allocator, targets);
    const provenance = try provenanceSourcesAlloc(allocator, targets, release_pair, release_id);
    const reproducible_build = try reproducibleBuildAlloc(allocator);
    const sbom_source = "{\"spdxVersion\":\"SPDX-2.3\"}\n";
    const customer_policy = "{\"schema_version\":1,\"verification\":\"zigos-verify-release\"}\n";

    try bundle.writeFile(std.testing.io, .{ .sub_path = "artifact-digests.sha256", .data = digest_projection });
    try bundle.writeFile(std.testing.io, .{ .sub_path = "artifact-measurements.json", .data = measurements });
    try bundle.writeFile(std.testing.io, .{ .sub_path = "customer-verification-policy.json", .data = customer_policy });
    try bundle.writeFile(std.testing.io, .{ .sub_path = "provenance.dsse.intoto.jsonl", .data = provenance.dsse });
    try bundle.writeFile(std.testing.io, .{ .sub_path = "provenance.intoto.jsonl", .data = provenance.unsigned });
    try bundle.writeFile(std.testing.io, .{ .sub_path = trust_policy_name, .data = policy_source });
    try bundle.writeFile(std.testing.io, .{ .sub_path = "reproducible-artifact-digests.sha256", .data = digest_projection });
    try bundle.writeFile(std.testing.io, .{ .sub_path = "reproducible-build.json", .data = reproducible_build });
    try bundle.writeFile(std.testing.io, .{ .sub_path = root_metadata_name, .data = root_source });
    try bundle.writeFile(std.testing.io, .{ .sub_path = "sbom.spdx.json", .data = sbom_source });

    const evidence = try allocator.alloc(trust.FileRecord, catalog.releaseEvidenceNames().len);
    for (catalog.releaseEvidenceNames(), 0..) |name, index| {
        const source = try bundle.readFileAlloc(std.testing.io, name, allocator, .limited(max_release_metadata_bytes));
        evidence[index] = .{ .path = name, .sha256 = try sha256HexAlloc(allocator, source), .sizeBytes = source.len };
    }

    const fixture = Fixture{
        .bundle_path = try std.fs.path.join(allocator, &.{ base, "bundle" }),
        .artifact_path = try std.fs.path.join(allocator, &.{ base, "artifacts" }),
        .state_path = try std.fs.path.join(allocator, &.{ base, "trust", "state.json" }),
        .root_source = root_source,
        .root_digest = root_digest,
        .release_key_pair = release_pair,
        .release_key_id = release_id,
        .targets = targets,
        .evidence = evidence,
    };
    try writeFixtureManifest(allocator, fixture, release_sequence, 1_779_999_000, 1_890_000_000);
    return fixture;
}

fn testingRootPath(allocator: std.mem.Allocator, sub_path: []const u8) ![]const u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", sub_path });
}

fn installDarwinExtendedAcl(handle: std.posix.fd_t) !void {
    if (comptime !builtin.os.tag.isDarwin()) return error.UnsupportedTrustStatePlatform;
    const acl = DarwinAcl.acl_from_text(
        "!#acl 1\n" ++
            "group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:read,write,execute,append\n",
    ) orelse return error.TestAclCreateFailed;
    const set_result = DarwinAcl.acl_set_fd_np(handle, acl, DarwinAcl.type_extended);
    const free_result = DarwinAcl.acl_free(acl);
    if (set_result != 0) return error.TestAclSetFailed;
    if (free_result != 0) return error.TestAclFreeFailed;
}

fn writeFixtureManifest(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    release_sequence: u64,
    issued_at: i64,
    expires_at: i64,
) !void {
    return writeFixtureManifestRecords(
        allocator,
        fixture,
        fixture.targets,
        fixture.evidence,
        release_sequence,
        issued_at,
        expires_at,
    );
}

fn writeFixtureManifestRecords(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    targets: []const trust.FileRecord,
    evidence: []const trust.FileRecord,
    release_sequence: u64,
    issued_at: i64,
    expires_at: i64,
) !void {
    const release_manifest = trust.ReleaseManifest{
        .policyVersion = 3,
        .profileId = fixture_profile_id,
        .releaseSequence = release_sequence,
        .issuedAt = issued_at,
        .expiresAt = expires_at,
        .source = .{
            .repository = fixture_repository,
            .changeId = fixture_jj_change_id,
            .commitId = fixture_commit_id,
        },
        .build = .{
            .zigVersion = fixture_zig_version,
            .target = release_build_target,
            .optimizeMode = release_optimize_mode,
            .builderId = release_slsa_builder_id,
        },
        .targets = targets,
        .evidence = evidence,
    };
    const payload = try std.json.Stringify.valueAlloc(allocator, release_manifest, .{});
    const envelope = try signedEnvelopeAlloc(
        allocator,
        trust.release_payload_type,
        payload,
        &.{fixture.release_key_pair},
        &.{fixture.release_key_id},
    );
    var bundle = try std.Io.Dir.cwd().openDir(std.testing.io, fixture.bundle_path, .{});
    defer bundle.close(std.testing.io);
    try bundle.writeFile(std.testing.io, .{ .sub_path = release_manifest_name, .data = envelope });
}

fn writeTrustStateForTest(allocator: std.mem.Allocator, path: []const u8, state: TrustState) !void {
    const source = try std.json.Stringify.valueAlloc(allocator, state, .{});
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = source,
        .flags = .{ .permissions = ownerOnlyPermissions() },
    });
}

fn signedEnvelopeAlloc(
    allocator: std.mem.Allocator,
    payload_type: []const u8,
    payload: []const u8,
    key_pairs: []const Ed25519.KeyPair,
    key_ids: []const []const u8,
) ![]u8 {
    if (key_pairs.len != key_ids.len or key_pairs.len == 0) return error.InvalidFixtureSignerSet;
    const pae = try dssePreauthEncoding(allocator, payload_type, payload);
    const payload_base64 = try encodeBase64Alloc(allocator, payload);
    const signatures = try allocator.alloc(TestEnvelopeSignature, key_pairs.len);
    for (key_pairs, key_ids, 0..) |key_pair, key_id, index| {
        const signature = (try key_pair.sign(pae, null)).toBytes();
        signatures[index] = .{ .keyid = key_id, .sig = try encodeBase64Alloc(allocator, &signature) };
    }
    return std.json.Stringify.valueAlloc(allocator, TestEnvelope{
        .payloadType = payload_type,
        .payload = payload_base64,
        .signatures = signatures,
    }, .{});
}

fn reserializeTestEnvelopeAlloc(allocator: std.mem.Allocator, source: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(TestEnvelope, allocator, source, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    const reordered = try std.json.Stringify.valueAlloc(allocator, ReserializedTestEnvelope{
        .signatures = parsed.value.signatures,
        .payload = parsed.value.payload,
        .payloadType = parsed.value.payloadType,
    }, .{});
    defer allocator.free(reordered);
    return std.mem.concat(allocator, u8, &.{ "\n  ", reordered, "\n" });
}

fn encodeBase64Alloc(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const size = std.base64.standard.Encoder.calcSize(bytes.len);
    const output = try allocator.alloc(u8, size);
    return std.base64.standard.Encoder.encode(output, bytes);
}

fn hexLowerAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const output = try allocator.alloc(u8, bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = digits[byte >> 4];
        output[index * 2 + 1] = digits[byte & 0x0f];
    }
    return output;
}

fn digestProjectionAlloc(allocator: std.mem.Allocator, records: []const trust.FileRecord) ![]u8 {
    const lines = try allocator.alloc([]const u8, records.len);
    for (records, 0..) |record, index| {
        lines[index] = try std.fmt.allocPrint(allocator, "{s}  {s}\n", .{ record.sha256, record.path });
    }
    return std.mem.concat(allocator, u8, lines);
}

const TestMeasurement = struct {
    path: []const u8,
    sha256: []const u8,
    size_bytes: u64,
};

const TestMeasurements = struct {
    schema_version: u32 = 1,
    measurement_algorithm: []const u8 = "sha256",
    artifacts: []const TestMeasurement,
};

fn measurementsAlloc(allocator: std.mem.Allocator, records: []const trust.FileRecord) ![]u8 {
    const measurements = try allocator.alloc(TestMeasurement, records.len);
    for (records, 0..) |record, index| {
        measurements[index] = .{ .path = record.path, .sha256 = record.sha256, .size_bytes = record.sizeBytes };
    }
    return std.json.Stringify.valueAlloc(allocator, TestMeasurements{ .artifacts = measurements }, .{});
}

const ProvenanceSources = struct {
    unsigned: []const u8,
    dsse: []const u8,
};

fn provenanceSourcesAlloc(
    allocator: std.mem.Allocator,
    records: []const trust.FileRecord,
    release_pair: Ed25519.KeyPair,
    release_key_id: []const u8,
) !ProvenanceSources {
    const unsigned_lines = try allocator.alloc([]const u8, records.len);
    const dsse_lines = try allocator.alloc([]const u8, records.len);
    for (records, 0..) |record, index| {
        const statement = try std.fmt.allocPrint(
            allocator,
            "{{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{{\"name\":\"{s}\",\"digest\":{{\"sha256\":\"{s}\"}}}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{{\"buildDefinition\":{{\"buildType\":\"{s}\",\"externalParameters\":{{\"repository\":\"{s}\",\"sourceControl\":\"jj\",\"changeId\":\"{s}\",\"commit\":\"{s}\",\"zigVersion\":\"{s}\",\"optimizeMode\":\"ReleaseFast\"}}}},\"runDetails\":{{\"builder\":{{\"id\":\"{s}\"}},\"metadata\":{{\"invocationId\":\"2026-01-01T00:00:00Z\",\"startedOn\":\"2026-01-01T00:00:00Z\",\"dirtyWorkspaceFileCount\":0}}}}}}}}",
            .{
                record.path,
                record.sha256,
                release_slsa_build_type,
                fixture_repository,
                fixture_jj_change_id,
                fixture_commit_id,
                fixture_zig_version,
                release_slsa_builder_id,
            },
        );
        unsigned_lines[index] = try std.mem.concat(allocator, u8, &.{ statement, "\n" });
        const envelope = try signedEnvelopeAlloc(
            allocator,
            release_slsa_payload_type,
            statement,
            &.{release_pair},
            &.{release_key_id},
        );
        dsse_lines[index] = try std.mem.concat(allocator, u8, &.{ envelope, "\n" });
    }
    return .{
        .unsigned = try std.mem.concat(allocator, u8, unsigned_lines),
        .dsse = try std.mem.concat(allocator, u8, dsse_lines),
    };
}

const TestReproducibleBuild = struct {
    schema_version: u32 = 1,
    generated_at: []const u8 = "2026-01-01T00:00:00Z",
    repo_vcs: []const u8 = release_source_control_jj,
    repository: []const u8 = fixture_repository,
    repo_change_id: []const u8 = fixture_jj_change_id,
    commit: []const u8 = fixture_commit_id,
    dirty_workspace_file_count: u32 = 0,
    zig_version: []const u8 = fixture_zig_version,
    optimize_mode: []const u8 = release_optimize_mode,
    status: []const u8 = "passed",
    digest_manifest: []const u8 = "build/release-security/reproducible-artifact-digests.sha256",
};

fn reproducibleBuildAlloc(allocator: std.mem.Allocator) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, TestReproducibleBuild{}, .{});
}
