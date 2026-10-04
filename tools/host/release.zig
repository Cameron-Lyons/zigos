const std = @import("std");
const common = @import("common.zig");
const catalog = @import("release_catalog");
const support = @import("release/support.zig");

const Context = common.Context;
const provenance_payload_type = "application/vnd.in-toto+json";
const manifest_payload_type = "application/vnd.zigos.release-manifest.v1+json";
const policy_payload_type = "application/vnd.zigos.release-trust-policy.v1+json";
const build_type = "https://github.com/Cameron-Lyons/zigos/release-security-gate";
const builder_id = "zigos-local-release-security-gate";
const optimize_mode = "ReleaseFast";
const generator_evidence_names = [_][]const u8{
    "artifact-digests.sha256",
    "artifact-measurements.json",
    "customer-verification-policy.json",
    "provenance.dsse.intoto.jsonl",
    "provenance.intoto.jsonl",
    "release-trust-policy.dsse.json",
    "root-metadata.json",
    "sbom.spdx.json",
};

pub fn run(ctx: *Context, command: []const u8, args: []const []const u8) !void {
    if (std.mem.eql(u8, command, "generate-release-sbom-provenance")) return generate(ctx, args);
    if (std.mem.eql(u8, command, "finalize-release-manifest")) return finalize(ctx, args);
    if (std.mem.eql(u8, command, "check-reproducible-build")) return reproducible(ctx, args);
    if (std.mem.eql(u8, command, "verify-release-bundle")) return verifyExisting(ctx, args);
    return error.UnknownReleaseCommand;
}

const SigningEnvironment = struct {
    root: []const u8,
    root_pin: []const u8,
    policy: []const u8,
    verifier: []const u8,
    verifier_pin: []const u8,
    key_id: []const u8,
    signer_argv: []const []const u8,
};

/// Signers consume DSSE PAE on stdin and return one standard-base64 signature.
/// Arguments are a JSON string array and are passed literally, without a shell.
fn signerArgv(allocator: std.mem.Allocator, executable: []const u8, args_json: []const u8) ![]const []const u8 {
    try support.absolute(executable);
    const parsed = try std.json.parseFromSlice([]const []const u8, allocator, args_json, .{ .allocate = .alloc_always });
    const argv = try allocator.alloc([]const u8, parsed.value.len + 1);
    argv[0] = executable;
    for (parsed.value, argv[1..]) |arg, *dest| {
        if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidSignerArgument;
        dest.* = arg;
    }
    return argv;
}

fn signingEnvironment(ctx: *Context) !SigningEnvironment {
    try support.same(try support.required(ctx, "ZIGOS_RELEASE_HARDWARE_BACKED"), "true");
    const result = SigningEnvironment{
        .root = try support.required(ctx, "ZIGOS_RELEASE_TRUST_ROOT"),
        .root_pin = try support.required(ctx, "ZIGOS_RELEASE_TRUST_ROOT_SHA256"),
        .policy = try support.required(ctx, "ZIGOS_RELEASE_TRUST_POLICY"),
        .verifier = try support.required(ctx, "ZIGOS_RELEASE_VERIFIER"),
        .verifier_pin = try support.required(ctx, "ZIGOS_RELEASE_VERIFIER_SHA256"),
        .key_id = try support.required(ctx, "ZIGOS_RELEASE_SIGNING_KEY_ID"),
        .signer_argv = try signerArgv(ctx.allocator, try support.required(ctx, "ZIGOS_RELEASE_DSSE_SIGN_EXECUTABLE"), ctx.envDefault("ZIGOS_RELEASE_DSSE_SIGN_ARGS_JSON", "[]")),
    };
    try support.absolute(result.root);
    try support.absolute(result.policy);
    try support.requireHash(result.root_pin);
    try support.requireHash(result.verifier_pin);
    try support.requireHash(result.key_id);
    try support.regular(ctx, result.root, false);
    try support.regular(ctx, result.policy, false);
    try support.regular(ctx, result.signer_argv[0], true);
    return result;
}

fn authenticatePolicy(ctx: *Context, verifier: []const u8, environment: SigningEnvironment, policy: []const u8) !void {
    try ctx.run(&.{ verifier, "trust-info", "--trusted-root", environment.root, "--trusted-root-sha256", environment.root_pin, "--policy", policy, "--release-key-id", environment.key_id });
}

fn preAuthenticationEncoding(ctx: *Context, payload_type: []const u8, payload: []const u8) ![]const u8 {
    return ctx.fmt("DSSEv1 {d} {s} {d} {s}", .{ payload_type.len, payload_type, payload.len, payload });
}

fn signatureText(ctx: *Context, output: []const u8) ![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    for (output) |byte| if (byte != '\n') try text.append(ctx.allocator, byte);
    if (text.items.len == 0) return error.InvalidDsseSignature;
    const decoded = support.decode64(ctx, text.items) catch return error.InvalidDsseSignature;
    if (decoded.len == 0) return error.InvalidDsseSignature;
    // Noncanonical base64 would make evidence signatures ambiguous.
    try support.same(text.items, try support.encode64(ctx, decoded));
    return text.items;
}

fn envelope(ctx: *Context, environment: SigningEnvironment, payload_type: []const u8, payload: []const u8) ![]const u8 {
    const result = try ctx.captureInput(environment.signer_argv, try preAuthenticationEncoding(ctx, payload_type, payload));
    if (!result.term.success()) return error.ReleaseSignerFailed;
    return support.json(ctx, .{
        .payloadType = payload_type,
        .payload = try support.encode64(ctx, payload),
        .signatures = .{.{ .keyid = environment.key_id, .sig = try signatureText(ctx, result.stdout) }},
    });
}

const Source = struct {
    repository: []const u8,
    change_id: []const u8,
    commit: []const u8,
    zig_version: []const u8,
    dirty_count: usize,
};

fn jj(ctx: *Context, root: []const u8, ignore: bool, args: []const []const u8) ![]const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(ctx.allocator, "jj");
    if (ignore) try argv.append(ctx.allocator, "--ignore-working-copy");
    try argv.appendSlice(ctx.allocator, &.{ "-R", root });
    try argv.appendSlice(ctx.allocator, args);
    return support.checkedCapture(ctx, argv.items);
}

fn origin(ctx: *Context, root: []const u8, ignore: bool) ![]const u8 {
    const remotes = jj(ctx, root, ignore, &.{ "git", "remote", "list" }) catch return "NOASSERTION";
    var lines = std.mem.splitScalar(u8, remotes, '\n');
    while (lines.next()) |line| {
        var tokens = std.mem.tokenizeAny(u8, line, " \t\r");
        const name = tokens.next() orelse continue;
        if (std.mem.eql(u8, name, "origin")) return tokens.next() orelse "NOASSERTION";
    }
    return "NOASSERTION";
}

fn compiler(ctx: *Context) ![]const u8 {
    // The build graph supplies its exact compiler through ZIG_BIN.
    const executable = ctx.envDefault("ZIG_BIN", "zig");
    const actual = try support.checkedCapture(ctx, &.{ executable, "version" });
    const tool_versions = try ctx.read(".tool-versions");
    var lines = std.mem.splitScalar(u8, tool_versions, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        if (std.mem.eql(u8, words.next() orelse continue, "zig")) {
            try support.same(actual, words.next() orelse return error.MissingPinnedZigVersion);
            return executable;
        }
    }
    return error.MissingPinnedZigVersion;
}

fn sourceIdentity(ctx: *Context, root: []const u8, frozen: bool) !Source {
    const commit = try jj(ctx, root, false, &.{ "log", "-r", "@", "--no-graph", "-T", "commit_id ++ \"\\n\"" });
    const revision = if (frozen) commit else "@";
    const names = try jj(ctx, root, frozen, &.{ "diff", "-r", revision, "--name-only" });
    var dirty_count: usize = 0;
    var lines = std.mem.splitScalar(u8, names, '\n');
    while (lines.next()) |line| if (line.len != 0) {
        dirty_count += 1;
    };
    return .{
        .repository = try origin(ctx, root, frozen),
        .change_id = try jj(ctx, root, frozen, &.{ "log", "-r", revision, "--no-graph", "-T", "change_id ++ \"\\n\"" }),
        .commit = commit,
        .zig_version = try support.checkedCapture(ctx, &.{ try compiler(ctx), "version" }),
        .dirty_count = dirty_count,
    };
}

fn digestManifest(ctx: *Context, records: []const support.Record) ![]const u8 {
    var result: std.ArrayList(u8) = .empty;
    for (records) |record| try result.appendSlice(ctx.allocator, try ctx.fmt("{s}  {s}\n", .{ record.sha256, record.path }));
    return result.items;
}

fn provenance(ctx: *Context, record: support.Record, source: Source, created: []const u8) ![]const u8 {
    return support.json(ctx, .{
        ._type = "https://in-toto.io/Statement/v1",
        .subject = .{.{ .name = record.path, .digest = .{ .sha256 = record.sha256 } }},
        .predicateType = "https://slsa.dev/provenance/v1",
        .predicate = .{
            .buildDefinition = .{
                .buildType = build_type,
                .externalParameters = .{ .repository = source.repository, .sourceControl = "jj", .changeId = source.change_id, .commit = source.commit, .zigVersion = source.zig_version, .optimizeMode = optimize_mode },
            },
            .runDetails = .{ .builder = .{ .id = builder_id }, .metadata = .{ .invocationId = created, .startedOn = created, .dirtyWorkspaceFileCount = source.dirty_count } },
        },
    });
}

fn generate(ctx: *Context, args: []const []const u8) !void {
    try common.requireArgs(args, 0, 2);
    const output_relative = common.arg(args, 0, "build/release-security");
    try support.same(common.arg(args, 1, optimize_mode), optimize_mode);
    const output = try support.outputPath(ctx, output_relative, true);
    try support.remove(ctx, try ctx.fmt("{s}/release-manifest.dsse.json", .{output}));
    for (generator_evidence_names) |name| try support.remove(ctx, try ctx.fmt("{s}/{s}", .{ output, name }));
    const work = try support.privateTemp(ctx, output, ".generate.");
    defer support.cleanup(ctx, work);
    const environment = try signingEnvironment(ctx);
    const root = try support.rootPath(ctx);
    const verifier = try support.pinVerifier(ctx, environment.verifier, environment.verifier_pin, work, &.{root});
    try authenticatePolicy(ctx, verifier, environment, environment.policy);
    try ctx.copy(environment.root, try ctx.fmt("{s}/root-metadata.json", .{work}));
    try ctx.copy(environment.policy, try ctx.fmt("{s}/release-trust-policy.dsse.json", .{work}));
    try catalog.requireExactProductionTargets(catalog.productionTargetPaths());
    const records = try support.records(ctx, root, catalog.productionTargetPaths());
    const source = try sourceIdentity(ctx, root, false);
    const created = try support.utc(ctx);
    try ctx.write(try ctx.fmt("{s}/artifact-digests.sha256", .{work}), try digestManifest(ctx, records));
    const Measurement = struct { path: []const u8, sha256: []const u8, size_bytes: u64 };
    const measurements = try ctx.allocator.alloc(Measurement, records.len);
    for (records, measurements) |record, *measurement| measurement.* = .{ .path = record.path, .sha256 = record.sha256, .size_bytes = record.sizeBytes };
    try support.writeJson(ctx, try ctx.fmt("{s}/artifact-measurements.json", .{work}), .{ .schema_version = 1, .measurement_algorithm = "sha256", .artifacts = measurements });
    try writeSbom(ctx, work, records, source, created);
    var statements: std.ArrayList(u8) = .empty;
    var envelopes: std.ArrayList(u8) = .empty;
    for (records) |record| {
        const statement = try provenance(ctx, record, source, created);
        try statements.appendSlice(ctx.allocator, try ctx.fmt("{s}\n", .{statement}));
        try envelopes.appendSlice(ctx.allocator, try ctx.fmt("{s}\n", .{try envelope(ctx, environment, provenance_payload_type, statement)}));
    }
    try ctx.write(try ctx.fmt("{s}/provenance.intoto.jsonl", .{work}), statements.items);
    try ctx.write(try ctx.fmt("{s}/provenance.dsse.intoto.jsonl", .{work}), envelopes.items);
    try writeCustomerPolicy(ctx, work, output_relative, created);
    try support.writeJson(ctx, try ctx.fmt("{s}/vulnerability-disclosure-dry-run.json", .{work}), .{
        .schema_version = 1,
        .generated_at = created,
        .primary_private_intake = "https://github.com/Cameron-Lyons/zigos/security/advisories/new",
        .backup_private_intake = "security@zigos.dev",
        .steps = .{ "private-report-created", "maintainer-acknowledged", "severity-triaged", "cwe-recorded", "advisory-drafted", "fix-or-not-exploitable-decision-recorded" },
        .status = "dry-run-recorded",
    });
    const audit = try support.outputPath(ctx, "build/release-audit", true);
    for (generator_evidence_names) |name| try support.rename(ctx, try ctx.fmt("{s}/{s}", .{ work, name }), try ctx.fmt("{s}/{s}", .{ output, name }));
    try support.rename(ctx, try ctx.fmt("{s}/vulnerability-disclosure-dry-run.json", .{work}), try ctx.fmt("{s}/vulnerability-disclosure-dry-run.json", .{audit}));
    try ctx.print("Authenticated release evidence generated under {s}\n", .{output_relative});
}

fn writeSbom(ctx: *Context, work: []const u8, records: []const support.Record, source: Source, created: []const u8) !void {
    const Checksum = struct { algorithm: []const u8 = "SHA256", checksumValue: []const u8 };
    const File = struct { fileName: []const u8, SPDXID: []const u8, checksums: [1]Checksum, licenseConcluded: []const u8 = "NOASSERTION", copyrightText: []const u8 = "NOASSERTION" };
    const files = try ctx.allocator.alloc(File, records.len);
    for (records, files) |record, *file| {
        const name = try ctx.allocator.dupe(u8, record.path);
        for (name) |*byte| if (!std.ascii.isAlphanumeric(byte.*)) {
            byte.* = '-';
        };
        file.* = .{ .fileName = record.path, .SPDXID = try ctx.fmt("SPDXRef-File-{s}", .{name}), .checksums = .{.{ .checksumValue = record.sha256 }} };
    }
    var notices: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "src/native/core/unicode_data/UNICODE-LICENSE.txt", "src/kernel/platform/fonts/README.md", "src/kernel/platform/fonts/UNIFONT-LICENSE.txt" }) |path| try notices.appendSlice(ctx.allocator, try ctx.read(path));
    try support.writeJson(ctx, try ctx.fmt("{s}/sbom.spdx.json", .{work}), .{
        .spdxVersion = "SPDX-2.3",
        .dataLicense = "CC0-1.0",
        .SPDXID = "SPDXRef-DOCUMENT",
        .name = "zigos-release-sbom",
        .documentNamespace = try ctx.fmt("https://github.com/Cameron-Lyons/zigos/release-security/{s}", .{source.commit}),
        .creationInfo = .{ .created = created, .creators = .{ "Tool: zigos-tool generate-release-sbom-provenance", "Organization: Zigos release security gate" } },
        .documentComment = notices.items,
        .packages = .{.{ .name = "zigos", .SPDXID = "SPDXRef-Package-zigos", .downloadLocation = source.repository, .versionInfo = source.commit, .filesAnalyzed = true, .supplier = "Organization: Zigos release security gate" }},
        .files = files,
    });
}

const verification_steps = [_][]const u8{
    "Copy the independently obtained zigos-verify-release executable into private staging, compare that exact copy with its independently distributed SHA-256 pin, and execute only the matched copy.",
    "Obtain root metadata and its SHA-256 digest independently; the bundled root-metadata.json is consistency evidence and never a trust bootstrap.",
    "Before first-use acceptance, require policyVersion to meet root minimumPolicyVersion and releaseSequence to meet the authenticated policy minimumReleaseSequence.",
    "Authenticate release-trust-policy.dsse.json with the pinned root threshold before parsing its payload; reject unknown, invalid, and duplicate signer ids.",
    "Authenticate release-manifest.dsse.json with currently active, unrevoked delegated release keys before parsing its payload.",
    "Require the authenticated policy and manifest to contain exactly 17 production targets and 10 evidence files; the signed manifest is the sole digest authority.",
    "Hash and size-check all targets and hash all evidence before parsing any evidence; treat artifact-digests.sha256 only as a consistency projection.",
    "Verify every DSSE signature in provenance.dsse.intoto.jsonl against the authenticated delegated policy; signatures cover the DSSE v1 pre-authentication encoding.",
    "Verify each decoded in-toto Statement has predicateType https://slsa.dev/provenance/v1, exactly one subject per signed DSSE envelope, and subject digests matching the authenticated release manifest.",
    "Require signed SLSA statements to bind buildDefinition.buildType, runDetails.builder.id, sourceControl=jj, changeId, commit, repository, Zig version, and dirtyWorkspaceFileCount=0.",
    "Require every active release key notBefore/notAfter window to cover the signed SLSA runDetails.metadata.startedOn date.",
    "Compare artifact-measurements.json size and digest measurements against downloaded artifacts, requiring exact one-entry-per-artifact coverage without duplicates.",
    "Compare reproducible-build.json and reproducible-artifact-digests.sha256 against the complete signed release digest manifest and SLSA source identity, requiring a clean ReleaseFast Jujutsu build.",
    "Persist root, authenticated policy payload, release sequence, authenticated manifest payload, and trusted-time state outside the downloaded bundle; reject rollback, equivocation, clock rollback, and implicit root changes.",
    "Run zigos-verify-release verify with explicit --bundle, --artifacts, --trusted-root, --trusted-root-sha256, and --trust-state arguments before trusting a downloaded release.",
    "Reject required post-quantum rollout unless zigos-verify-release supports and verifies the policy-required production algorithm from a validated provider.",
};

fn writeCustomerPolicy(ctx: *Context, work: []const u8, output: []const u8, created: []const u8) !void {
    try support.writeJson(ctx, try ctx.fmt("{s}/customer-verification-policy.json", .{work}), .{
        .schema_version = 1,
        .generated_at = created,
        .release_manifest = try ctx.fmt("{s}/release-manifest.dsse.json", .{output}),
        .trusted_root_evidence = try ctx.fmt("{s}/root-metadata.json", .{output}),
        .signed_trust_policy = try ctx.fmt("{s}/release-trust-policy.dsse.json", .{output}),
        .trusted_root_bootstrap = "supply root metadata and its lowercase SHA-256 digest independently of the release bundle",
        .verifier_bootstrap = "supply zigos-verify-release and its lowercase SHA-256 digest independently of the release bundle and artifact tree",
        .rollback_state = "persist outside both the release bundle and artifact root",
        .automatic_root_rotation_supported = false,
        .artifact_digest_manifest = try ctx.fmt("{s}/artifact-digests.sha256", .{output}),
        .artifact_measurements = try ctx.fmt("{s}/artifact-measurements.json", .{output}),
        .spdx_sbom = try ctx.fmt("{s}/sbom.spdx.json", .{output}),
        .provenance_statements = try ctx.fmt("{s}/provenance.intoto.jsonl", .{output}),
        .dsse_provenance = try ctx.fmt("{s}/provenance.dsse.intoto.jsonl", .{output}),
        .reproducible_build_evidence = try ctx.fmt("{s}/reproducible-build.json", .{output}),
        .reproducible_artifact_digests = try ctx.fmt("{s}/reproducible-artifact-digests.sha256", .{output}),
        .required_predicate_type = "https://slsa.dev/provenance/v1",
        .required_payload_type = provenance_payload_type,
        .required_manifest_payload_type = manifest_payload_type,
        .required_trust_policy_payload_type = policy_payload_type,
        .require_hardware_backed_release_key = true,
        .exact_target_count = catalog.productionTargetPaths().len,
        .exact_evidence_count = catalog.releaseEvidenceNames().len,
        .verification_steps = verification_steps,
    });
}

fn verifierCommand(ctx: *Context, executable: []const u8, command: []const u8, bundle: []const u8, artifacts: []const u8, root: []const u8, pin: []const u8, state: []const u8) !void {
    try ctx.run(&.{ executable, command, "--bundle", bundle, "--artifacts", artifacts, "--trusted-root", root, "--trusted-root-sha256", pin, "--trust-state", state });
}

fn verifyExisting(ctx: *Context, args: []const []const u8) !void {
    try common.requireArgs(args, 7, 7);
    try support.absolute(args[4]);
    try support.absolute(args[6]);
    try support.requireHash(args[5]);
    try support.regular(ctx, args[4], false);
    const bundle = try support.canonical(ctx, args[2]);
    const artifacts = try support.canonical(ctx, args[3]);
    const work = try ctx.tempDir("zigos-pinned-verifier");
    defer support.cleanup(ctx, work);
    const verifier = try support.pinVerifier(ctx, args[0], args[1], work, &.{ bundle, artifacts });
    try verifierCommand(ctx, verifier, "verify", bundle, artifacts, args[4], args[5], args[6]);
}

fn exactEvidence(ctx: *Context, output: []const u8) !void {
    var dir = try std.Io.Dir.cwd().openDir(ctx.io, output, .{ .follow_symlinks = false, .iterate = true });
    defer dir.close(ctx.io);
    var iterator = dir.iterate();
    var names: std.ArrayList([]const u8) = .empty;
    while (try iterator.next(ctx.io)) |entry| {
        if (entry.kind != .file) return error.UnexpectedReleaseEvidenceEntry;
        try names.append(ctx.allocator, try ctx.allocator.dupe(u8, entry.name));
    }
    try catalog.requireExactReleaseEvidenceNames(names.items);
}

const PolicyInfo = struct { version: u64, profile: []const u8, expires_at: u64, key_not_after: u64 };

fn authenticatedPolicyInfo(ctx: *Context, bytes: []const u8, key_id: []const u8) !PolicyInfo {
    const dsse = try support.parse(ctx, bytes);
    try support.same(try support.string(dsse, "payloadType"), policy_payload_type);
    const policy = try support.parse(ctx, try support.decode64(ctx, try support.string(dsse, "payload")));
    const keys = try support.field(policy, "releaseKeys");
    if (keys != .array) return error.InvalidReleaseKeys;
    var key_not_after: ?u64 = null;
    for (keys.array.items) |key| {
        if (std.mem.eql(u8, try support.string(key, "keyId"), key_id) and std.mem.eql(u8, try support.string(key, "status"), "active")) {
            if (key_not_after != null) return error.DuplicateReleaseKey;
            key_not_after = try support.integer(key, "notAfter");
        }
    }
    const version = try support.integer(policy, "policyVersion");
    const expires_at = try support.integer(policy, "expiresAt");
    if (version == 0 or expires_at == 0) return error.InvalidReleasePolicy;
    return .{ .version = version, .profile = try support.string(try support.field(policy, "artifactProfile"), "profileId"), .expires_at = expires_at, .key_not_after = key_not_after orelse return error.MissingActiveReleaseKey };
}

fn cleanReproSource(ctx: *Context, bytes: []const u8) !Source {
    const value = try support.parse(ctx, bytes);
    try support.same(try support.string(value, "status"), "passed");
    try support.same(try support.string(value, "repo_vcs"), "jj");
    try support.same(try support.string(value, "optimize_mode"), optimize_mode);
    if (try support.integer(value, "dirty_workspace_file_count") != 0) return error.DirtyReproducibleBuild;
    return .{ .repository = try support.string(value, "repository"), .change_id = try support.string(value, "repo_change_id"), .commit = try support.string(value, "commit"), .zig_version = try support.string(value, "zig_version"), .dirty_count = 0 };
}

/// Field declarations follow jq -cS ordering recursively. Signed payloads have no
/// trailing newline; the exact serialized bytes are passed to both PAE and base64.
fn manifest(ctx: *Context, policy: PolicyInfo, sequence: u64, issued: i64, expires: u64, source: Source, targets: []const support.Record, evidence: []const support.Record) ![]const u8 {
    return support.json(ctx, .{
        .build = .{ .builderId = builder_id, .optimizeMode = optimize_mode, .target = "x86-freestanding-none", .zigVersion = source.zig_version },
        .evidence = evidence,
        .expiresAt = expires,
        .issuedAt = issued,
        .policyVersion = policy.version,
        .profileId = policy.profile,
        .releaseSequence = sequence,
        .source = .{ .changeId = source.change_id, .commitId = source.commit, .repository = source.repository },
        .targets = targets,
    });
}

fn finalize(ctx: *Context, args: []const []const u8) !void {
    try common.requireArgs(args, 0, 2);
    const output_relative = common.arg(args, 0, "build/release-security");
    const output = try support.outputPath(ctx, output_relative, false);
    const artifacts = try support.canonical(ctx, common.arg(args, 1, "."));
    const lock = try ctx.fmt("{s}.finalize.lock", .{output});
    std.Io.Dir.cwd().createDir(ctx.io, lock, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ReleaseFinalizationAlreadyActive,
        else => return err,
    };
    defer std.Io.Dir.cwd().deleteDir(ctx.io, lock) catch {};
    const work = try support.privateTemp(ctx, try ctx.fmt("{s}/build", .{try support.rootPath(ctx)}), ".release-finalize.");
    defer support.cleanup(ctx, work);
    const environment = try signingEnvironment(ctx);
    const state = try support.required(ctx, "ZIGOS_RELEASE_TRUST_STATE");
    try support.absolute(state);
    const sequence = try support.positive(try support.required(ctx, "ZIGOS_RELEASE_SEQUENCE"));
    const expires = try support.positive(try support.required(ctx, "ZIGOS_RELEASE_EXPIRES_AT"));
    const verifier = try support.pinVerifier(ctx, environment.verifier, environment.verifier_pin, work, &.{artifacts});
    const marker = try ctx.fmt("{s}/release-manifest.dsse.json", .{output});
    try support.remove(ctx, marker);
    try support.same(try ctx.read(environment.root), try support.readContained(ctx, output, "root-metadata.json"));
    try support.same(try ctx.read(environment.policy), try support.readContained(ctx, output, "release-trust-policy.dsse.json"));
    const root_digest = try ctx.sha256File(try ctx.fmt("{s}/root-metadata.json", .{output}));
    try support.same(&root_digest, environment.root_pin);
    const bundled_policy = try ctx.fmt("{s}/release-trust-policy.dsse.json", .{output});
    try authenticatePolicy(ctx, verifier, environment, bundled_policy);
    try exactEvidence(ctx, output);
    const targets = try support.records(ctx, artifacts, catalog.productionTargetPaths());
    const evidence = try support.records(ctx, output, catalog.releaseEvidenceNames());
    const digests = try support.readContained(ctx, output, "artifact-digests.sha256");
    try support.same(digests, try support.readContained(ctx, output, "reproducible-artifact-digests.sha256"));
    try support.same(digests, try digestManifest(ctx, targets));
    const policy = try authenticatedPolicyInfo(ctx, try support.readContained(ctx, output, "release-trust-policy.dsse.json"), environment.key_id);
    if (expires > policy.expires_at or expires > policy.key_not_after) return error.ReleaseExpiryExceedsPolicy;
    const source = try cleanReproSource(ctx, try support.readContained(ctx, output, "reproducible-build.json"));
    const issued = std.Io.Clock.real.now(ctx.io).toSeconds();
    if (issued < 0 or expires <= @as(u64, @intCast(issued))) return error.ReleaseExpiryMustBeInFuture;
    const payload = try manifest(ctx, policy, sequence, issued, expires, source, targets, evidence);
    const staged_marker = try ctx.fmt("{s}/release-manifest.dsse.json", .{work});
    try ctx.write(staged_marker, try ctx.fmt("{s}\n", .{try envelope(ctx, environment, manifest_payload_type, payload)}));
    try support.chmod(ctx, staged_marker, 0o600);
    const candidate = try ctx.fmt("{s}/candidate-bundle", .{work});
    try ctx.mkdir(candidate);
    for (catalog.releaseEvidenceNames()) |name| try ctx.copy(try ctx.fmt("{s}/{s}", .{ output, name }), try ctx.fmt("{s}/{s}", .{ candidate, name }));
    try ctx.copy(staged_marker, try ctx.fmt("{s}/release-manifest.dsse.json", .{candidate}));
    try verifierCommand(ctx, verifier, "verify-candidate", candidate, artifacts, environment.root, environment.root_pin, state);
    try support.rename(ctx, staged_marker, marker);
    verifierCommand(ctx, verifier, "verify", output, artifacts, environment.root, environment.root_pin, state) catch |err| {
        try support.remove(ctx, marker);
        return err;
    };
    try ctx.print("Authenticated exact release manifest finalized at {s}/release-manifest.dsse.json\n", .{output_relative});
}

fn sourceEpoch(value: []const u8) !u64 {
    if (value.len == 0 or value.len > 10) return error.InvalidSourceDateEpoch;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidSourceDateEpoch;
    const epoch = std.fmt.parseInt(u64, value, 10) catch return error.InvalidSourceDateEpoch;
    if (epoch > 4354819199) return error.SourceDateEpochExceedsFatMaximum;
    return epoch;
}

fn exportRevision(ctx: *Context, root: []const u8, revision: []const u8, tree: []const u8) !void {
    try ctx.mkdir(tree);
    const files = try jj(ctx, root, true, &.{ "file", "list", "-r", revision, "-T", "file_type ++ \"\\t\" ++ executable ++ \"\\t\" ++ path ++ \"\\n\"" });
    var lines = std.mem.splitScalar(u8, files, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const kind = fields.next() orelse return error.InvalidTrackedSourceEntry;
        const executable = fields.next() orelse return error.InvalidTrackedSourceEntry;
        const path = fields.next() orelse return error.InvalidTrackedSourceEntry;
        if (fields.next() != null or !catalog.isSafeRelativePath(path)) return error.UnsafeTrackedSourcePath;
        try support.same(kind, "file");
        if (!std.mem.eql(u8, executable, "true") and !std.mem.eql(u8, executable, "false")) return error.InvalidTrackedSourceEntry;
        const result = try ctx.capture(&.{ "jj", "--ignore-working-copy", "-R", root, "file", "show", "-r", revision, path });
        if (!result.term.success()) return error.TrackedSourceExportFailed;
        const destination = try ctx.fmt("{s}/{s}", .{ tree, path });
        try ctx.write(destination, result.stdout);
        try support.chmod(ctx, destination, if (std.mem.eql(u8, executable, "true")) 0o755 else 0o644);
    }
}

fn buildCopy(ctx: *Context, tree: []const u8, zig: []const u8, epoch: u64) !void {
    var environ = std.process.Environ.Map.init(ctx.allocator);
    defer environ.deinit();
    var iterator = ctx.environ.array_hash_map.iterator();
    while (iterator.next()) |entry| try environ.put(entry.key_ptr.*, entry.value_ptr.*);
    const local_cache = try ctx.fmt("{s}/build/zig-cache", .{tree});
    const global_cache = try ctx.fmt("{s}/build/zig-global-cache", .{tree});
    try environ.put("ZIG_LOCAL_CACHE_DIR", local_cache);
    try environ.put("ZIG_GLOBAL_CACHE_DIR", global_cache);
    try environ.put("ZIG_BIN", zig);
    try environ.put("SOURCE_DATE_EPOCH", try ctx.fmt("{d}", .{epoch}));
    var child = try std.process.spawn(ctx.io, .{
        .argv = &.{ zig, "build", "-Doptimize=fast", try ctx.fmt("-Dsource-date-epoch={d}", .{epoch}), "iso" },
        .cwd = .{ .path = tree },
        .environ_map = &environ,
    });
    defer child.kill(ctx.io);
    if (!(try child.wait(ctx.io)).success()) return error.ReproducibleCopyBuildFailed;
}

fn writeReproEvidence(ctx: *Context, work: []const u8, output: []const u8, source: Source, created: []const u8, passed: bool) !void {
    const comparison: ?[]const u8 = if (passed) "two independent tracked-workspace builds produced identical release artifact digests" else null;
    const digest_manifest: ?[]const u8 = if (passed) try ctx.fmt("{s}/reproducible-artifact-digests.sha256", .{output}) else null;
    const serialized = try std.json.Stringify.valueAlloc(ctx.allocator, .{
        .schema_version = 1,
        .generated_at = created,
        .repo_vcs = "jj",
        .repository = source.repository,
        .repo_change_id = source.change_id,
        .commit = source.commit,
        .dirty_workspace_file_count = source.dirty_count,
        .zig_version = source.zig_version,
        .optimize_mode = optimize_mode,
        .status = if (passed) @as([]const u8, "passed") else "failed",
        .comparison = comparison,
        .digest_manifest = digest_manifest,
    }, .{ .emit_null_optional_fields = false });
    try ctx.write(try ctx.fmt("{s}/reproducible-build.json", .{work}), try ctx.fmt("{s}\n", .{serialized}));
}

fn reproducible(ctx: *Context, args: []const []const u8) !void {
    try common.requireArgs(args, 0, 2);
    const epoch = try sourceEpoch(common.arg(args, 1, ctx.envDefault("SOURCE_DATE_EPOCH", "315532800")));
    const output_relative = common.arg(args, 0, "build/release-security");
    const output = try support.outputPath(ctx, output_relative, true);
    for ([_][]const u8{ "release-manifest.dsse.json", "reproducible-artifact-digests.sha256", "reproducible-build.json" }) |name| try support.remove(ctx, try ctx.fmt("{s}/{s}", .{ output, name }));
    const work = try support.canonical(ctx, try ctx.tempDir("zigos-repro"));
    defer support.cleanup(ctx, work);
    const output_work = try support.privateTemp(ctx, output, ".reproducible.");
    defer support.cleanup(ctx, output_work);
    const root = try support.rootPath(ctx);
    const source = try sourceIdentity(ctx, root, true);
    const zig = try compiler(ctx);
    const first = try ctx.fmt("{s}/first", .{work});
    const second = try ctx.fmt("{s}/second", .{work});
    try exportRevision(ctx, root, source.commit, first);
    try exportRevision(ctx, root, source.commit, second);
    try support.same(source.commit, try jj(ctx, root, false, &.{ "log", "-r", "@", "--no-graph", "-T", "commit_id ++ \"\\n\"" }));
    try buildCopy(ctx, first, zig, epoch);
    try buildCopy(ctx, second, zig, epoch);
    const first_manifest = try digestManifest(ctx, try support.records(ctx, first, catalog.productionTargetPaths()));
    const second_manifest = try digestManifest(ctx, try support.records(ctx, second, catalog.productionTargetPaths()));
    const passed = std.mem.eql(u8, first_manifest, second_manifest);
    try writeReproEvidence(ctx, output_work, output_relative, source, try support.utc(ctx), passed);
    if (passed) {
        try ctx.write(try ctx.fmt("{s}/reproducible-artifact-digests.sha256", .{output_work}), first_manifest);
        try support.rename(ctx, try ctx.fmt("{s}/reproducible-artifact-digests.sha256", .{output_work}), try ctx.fmt("{s}/reproducible-artifact-digests.sha256", .{output}));
    }
    try support.rename(ctx, try ctx.fmt("{s}/reproducible-build.json", .{output_work}), try ctx.fmt("{s}/reproducible-build.json", .{output}));
    if (!passed) return error.ReproducibleArtifactDigestMismatch;
    try ctx.print("Reproducible build OK: compared two independent release builds\n", .{});
}

test "signer arguments remain literal and reject shell command syntax as executable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const argv = try signerArgv(arena.allocator(), "/usr/bin/signer", "[\"key with spaces\",\"$(touch /tmp/unsafe)\",\"a;b\"]");
    try std.testing.expectEqualStrings("$(touch /tmp/unsafe)", argv[2]);
    try std.testing.expectError(error.ReleasePathMustBeAbsolute, signerArgv(arena.allocator(), "signer --key release", "[]"));
    try std.testing.expectError(error.InvalidSignerArgument, signerArgv(arena.allocator(), "/signer", "[\"\\u0000\"]"));
}

test "reproducibility timestamps reject negative and FAT overflow epochs" {
    try std.testing.expectEqual(@as(u64, 0), try sourceEpoch("0000000000"));
    try std.testing.expectEqual(@as(u64, 4354819199), try sourceEpoch("4354819199"));
    try std.testing.expectError(error.SourceDateEpochExceedsFatMaximum, sourceEpoch("4354819200"));
    try std.testing.expectError(error.InvalidSourceDateEpoch, sourceEpoch("-1"));
    try std.testing.expectError(error.InvalidSourceDateEpoch, sourceEpoch("1;rm"));
}

test "release command dispatch rejects unknown operations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    try std.testing.expectError(error.UnknownReleaseCommand, run(&ctx, "unknown", &.{}));
}

test "DSSE PAE uses byte lengths and signatures reject malformed or noncanonical base64" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    try std.testing.expectEqualStrings("DSSEv1 4 type 4 é\x00x", try preAuthenticationEncoding(&ctx, "type", "é\x00x"));
    try std.testing.expectEqualStrings("AQ==", try signatureText(&ctx, "AQ==\n"));
    try std.testing.expectError(error.InvalidDsseSignature, signatureText(&ctx, ""));
    try std.testing.expectError(error.InvalidDsseSignature, signatureText(&ctx, "AQ==\r\n"));
    try std.testing.expectError(error.InvalidDsseSignature, signatureText(&ctx, "AB=="));
}

test "reproducible evidence rejects dirty sources and duplicate fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    const clean = "{\"status\":\"passed\",\"repo_vcs\":\"jj\",\"optimize_mode\":\"ReleaseFast\",\"dirty_workspace_file_count\":0,\"repository\":\"repo\",\"repo_change_id\":\"change\",\"commit\":\"commit\",\"zig_version\":\"version\"}";
    _ = try cleanReproSource(&ctx, clean);
    try std.testing.expectError(error.DirtyReproducibleBuild, cleanReproSource(&ctx, "{\"status\":\"passed\",\"repo_vcs\":\"jj\",\"optimize_mode\":\"ReleaseFast\",\"dirty_workspace_file_count\":1}"));
    try std.testing.expectError(error.DuplicateField, support.parse(&ctx, "{\"status\":\"failed\",\"status\":\"passed\"}"));
    try std.testing.expectError(error.ReleaseEvidenceMismatch, cleanReproSource(&ctx, "{\"status\":\"passed\",\"repo_vcs\":\"git\"}"));
}

test "manifest serialization preserves canonical recursively sorted keys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    const result = try manifest(&ctx, .{ .version = 3, .profile = "profile", .expires_at = 200, .key_not_after = 200 }, 7, 100, 200, .{ .repository = "repo", .change_id = "change", .commit = "commit", .zig_version = "version", .dirty_count = 0 }, &.{.{ .path = "artifact", .sha256 = "digest", .sizeBytes = 4 }}, &.{});
    try std.testing.expectEqualStrings("{\"build\":{\"builderId\":\"zigos-local-release-security-gate\",\"optimizeMode\":\"ReleaseFast\",\"target\":\"x86-freestanding-none\",\"zigVersion\":\"version\"},\"evidence\":[],\"expiresAt\":200,\"issuedAt\":100,\"policyVersion\":3,\"profileId\":\"profile\",\"releaseSequence\":7,\"source\":{\"changeId\":\"change\",\"commitId\":\"commit\",\"repository\":\"repo\"},\"targets\":[{\"path\":\"artifact\",\"sha256\":\"digest\",\"sizeBytes\":4}]}", result);
}

test "software custody cannot enable the release signing path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    try environ.put("ZIGOS_RELEASE_HARDWARE_BACKED", "false");
    var ctx: Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    try std.testing.expectError(error.ReleaseEvidenceMismatch, signingEnvironment(&ctx));
}
