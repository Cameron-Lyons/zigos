//! Credential-free release command integration fixture. Deterministic software
//! keys emulate an HSM only in isolated test directories; they are never release
//! providers. The production verifier authenticates every generated test bundle.
const std = @import("std");
const common = @import("common");
const catalog = @import("release_catalog");
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Context = common.Context;
const policy_type = "application/vnd.zigos.release-trust-policy.v1+json";

pub fn main(init: std.process.Init) !void {
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    var ctx: Context = .{ .allocator = init.arena.allocator(), .io = init.io, .environ = init.environ_map };
    const args = try ctx.buildCommandArgs(argv[1..]);
    if (args.len == 1 and (std.mem.eql(u8, args[0], "sign") or std.mem.eql(u8, args[0], "wrong-sign"))) {
        var reader = std.Io.File.stdin().reader(ctx.io, &.{});
        const input = try reader.interface.allocRemaining(ctx.allocator, .limited(16 * 1024 * 1024));
        const pair = try Ed25519.KeyPair.generateDeterministic(@splat(if (std.mem.eql(u8, args[0], "sign")) @as(u8, 0x33) else 0x44));
        try ctx.print("{s}\n", .{try base64(&ctx, &(try pair.sign(input, null)).toBytes())});
        return;
    }
    // A separately pinned synthetic verifier exercises withdrawal after a
    // candidate succeeds but verification of the published marker fails.
    if (args.len >= 1 and (std.mem.eql(u8, args[0], "trust-info") or std.mem.eql(u8, args[0], "verify-candidate"))) return;
    if (args.len >= 1 and std.mem.eql(u8, args[0], "verify")) std.process.exit(1);
    if (args.len != 3 or !std.mem.eql(u8, args[0], "scenario")) return error.InvalidArguments;
    try scenario(&ctx, try std.Io.Dir.cwd().realPathFileAlloc(ctx.io, args[1], ctx.allocator), args[2]);
}

fn json(ctx: *Context, value: anytype) ![]const u8 {
    return std.json.Stringify.valueAlloc(ctx.allocator, value, .{});
}

fn base64(ctx: *Context, bytes: []const u8) ![]const u8 {
    return std.base64.standard.Encoder.encode(try ctx.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len)), bytes);
}

fn digest(ctx: *Context, bytes: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    Sha256.hash(bytes, &hash, .{});
    return ctx.allocator.dupe(u8, &std.fmt.bytesToHex(hash, .lower));
}

fn publicHex(ctx: *Context, pair: Ed25519.KeyPair) ![]const u8 {
    return ctx.allocator.dupe(u8, &std.fmt.bytesToHex(pair.public_key.toBytes(), .lower));
}

const TrustFixture = struct { root_path: []const u8, policy_path: []const u8, root_pin: []const u8, key_id: []const u8, now: i64 };

fn writeTrust(ctx: *Context, directory: []const u8, hardware_backed: bool) !TrustFixture {
    const now = std.Io.Clock.real.now(ctx.io).toSeconds();
    const root_a = try Ed25519.KeyPair.generateDeterministic(@splat(0x11));
    const root_b = try Ed25519.KeyPair.generateDeterministic(@splat(0x22));
    const release = try Ed25519.KeyPair.generateDeterministic(@splat(0x33));
    const root_id_a = try digest(ctx, &root_a.public_key.toBytes());
    const root_id_b = try digest(ctx, &root_b.public_key.toBytes());
    const release_id = try digest(ctx, &release.public_key.toBytes());
    const root = try json(ctx, .{
        .schemaVersion = 1,
        .namespace = "zigos",
        .channel = "production",
        .version = 1,
        .issuedAt = now - 3600,
        .expiresAt = now + 7200,
        .minimumPolicyVersion = 3,
        .threshold = 2,
        .keys = .{
            .{ .keyId = root_id_a, .algorithm = "ed25519", .publicKey = try publicHex(ctx, root_a) },
            .{ .keyId = root_id_b, .algorithm = "ed25519", .publicKey = try publicHex(ctx, root_b) },
        },
    });
    const policy = try json(ctx, .{
        .rootVersion = 1,
        .policyVersion = 3,
        .minimumReleaseSequence = 1,
        .issuedAt = now - 3500,
        .expiresAt = now + 7000,
        .releaseRole = .{ .threshold = 1, .keyIds = .{release_id} },
        .releaseKeys = .{.{ .keyId = release_id, .algorithm = "ed25519", .generation = 1, .status = "active", .custody = "fixture-hardware-security-module", .hardwareBacked = hardware_backed, .notBefore = now - 3600, .notAfter = now + 7200, .publicKey = try publicHex(ctx, release) }},
        .revocations = [0]struct { keyId: []const u8 }{},
        .artifactProfile = .{ .profileId = "native-release-v1", .exactTargets = catalog.productionTargetPaths(), .exactEvidence = catalog.releaseEvidenceNames() },
        .pqcPolicy = .{ .mode = "shadow", .requiredAlgorithm = "ml-dsa-65", .fipsValidatedRequired = true },
    });
    const pae = try ctx.fmt("DSSEv1 {d} {s} {d} {s}", .{ policy_type.len, policy_type, policy.len, policy });
    const envelope = try json(ctx, .{
        .payloadType = policy_type,
        .payload = try base64(ctx, policy),
        .signatures = .{
            .{ .keyid = root_id_a, .sig = try base64(ctx, &(try root_a.sign(pae, null)).toBytes()) },
            .{ .keyid = root_id_b, .sig = try base64(ctx, &(try root_b.sign(pae, null)).toBytes()) },
        },
    });
    const root_path = try ctx.fmt("{s}/root.json", .{directory});
    const policy_path = try ctx.fmt("{s}/policy.json", .{directory});
    try ctx.write(root_path, root);
    try ctx.write(policy_path, envelope);
    return .{ .root_path = root_path, .policy_path = policy_path, .root_pin = try digest(ctx, root), .key_id = release_id, .now = now };
}

fn child(ctx: *Context, root: []const u8, environment: *std.process.Environ.Map, argv: []const []const u8, passed: bool) !std.process.RunResult {
    const result = try std.process.run(ctx.allocator, ctx.io, .{ .argv = argv, .cwd = .{ .path = root }, .environ_map = environment, .stdout_limit = .limited(16 * 1024 * 1024), .stderr_limit = .limited(1024 * 1024) });
    if (result.term.success() != passed) {
        std.debug.print("fixture child {s}: stdout={s}\nstderr={s}\n", .{ argv[0], result.stdout, result.stderr });
        return error.UnexpectedReleaseFixtureResult;
    }
    return result;
}

fn fixtureBuild(ctx: *Context) ![]const u8 {
    var source: std.ArrayList(u8) = .empty;
    try source.appendSlice(ctx.allocator,
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    _ = b.standardOptimizeOption(.{});
        \\    _ = b.option(u64, "source-date-epoch", "fixture timestamp");
        \\    const files = b.addUpdateSourceFiles();
        \\
    );
    for (catalog.productionTargetPaths()) |path| {
        try source.appendSlice(ctx.allocator, try ctx.fmt("    files.addBytesToSource({s}, {s});\n", .{ try json(ctx, try ctx.fmt("fixture artifact: {s}\n", .{path})), try json(ctx, path) }));
    }
    try source.appendSlice(ctx.allocator, "    b.step(\"iso\", \"fixture release artifacts\").dependOn(&files.step);\n}\n");
    return source.items;
}

fn scenario(ctx: *Context, host: []const u8, verifier_source: []const u8) !void {
    const workspace = try ctx.tempDir("zigos-release-integration");
    defer ctx.removeTree(workspace) catch {};
    const tree = try ctx.fmt("{s}/artifacts", .{workspace});
    const trust_dir = try ctx.fmt("{s}/trust", .{workspace});
    try ctx.mkdir(tree);
    try ctx.mkdir(trust_dir);
    const verifier = try ctx.fmt("{s}/independent-verifier", .{trust_dir});
    try ctx.copy(verifier_source, verifier);
    var verifier_file = try std.Io.Dir.cwd().openFile(ctx.io, verifier, .{});
    try verifier_file.setPermissions(ctx.io, .fromMode(0o500));
    verifier_file.close(ctx.io);
    const verifier_pin = try ctx.sha256File(verifier);
    const self = try std.process.executablePathAlloc(ctx.io, ctx.allocator);
    var environment = std.process.Environ.Map.init(ctx.allocator);
    defer environment.deinit();
    var iterator = ctx.environ.array_hash_map.iterator();
    while (iterator.next()) |entry| try environment.put(entry.key_ptr.*, entry.value_ptr.*);
    const zig = ctx.envDefault("ZIG_BIN", "zig");
    const zig_version = try ctx.capture(&.{ zig, "version" });
    try ctx.write(try ctx.fmt("{s}/.tool-versions", .{tree}), try ctx.fmt("zig {s}", .{zig_version.stdout}));
    try ctx.write(try ctx.fmt("{s}/.gitignore", .{tree}), "build/\nzig-out/\n");
    try ctx.write(try ctx.fmt("{s}/build.zig", .{tree}), try fixtureBuild(ctx));
    for (catalog.productionTargetPaths()) |path| try ctx.write(try ctx.fmt("{s}/{s}", .{ tree, path }), try ctx.fmt("fixture artifact: {s}\n", .{path}));
    for ([_][]const u8{ "src/native/core/unicode_data/UNICODE-LICENSE.txt", "src/kernel/platform/fonts/README.md", "src/kernel/platform/fonts/UNIFONT-LICENSE.txt" }) |path| try ctx.write(try ctx.fmt("{s}/{s}", .{ tree, path }), "fixture notice\n");
    _ = try child(ctx, tree, &environment, &.{ "jj", "--config", "user.name=Cameron Lyons", "--config", "user.email=cameron.lyons2@gmail.com", "git", "init", "--colocate", "." }, true);
    _ = try child(ctx, tree, &environment, &.{ "jj", "git", "remote", "add", "origin", "https://github.com/Cameron-Lyons/zigos" }, true);
    _ = try child(ctx, tree, &environment, &.{ "jj", "--config", "user.name=Cameron Lyons", "--config", "user.email=cameron.lyons2@gmail.com", "describe", "-m", "Release fixture source" }, true);
    _ = try child(ctx, tree, &environment, &.{ "jj", "--config", "user.name=Cameron Lyons", "--config", "user.email=cameron.lyons2@gmail.com", "new" }, true);
    var trust = try writeTrust(ctx, trust_dir, false);
    try environment.put("ZIGOS_RELEASE_TRUST_ROOT", trust.root_path);
    try environment.put("ZIGOS_RELEASE_TRUST_ROOT_SHA256", trust.root_pin);
    try environment.put("ZIGOS_RELEASE_TRUST_POLICY", trust.policy_path);
    try environment.put("ZIGOS_RELEASE_VERIFIER", verifier);
    try environment.put("ZIGOS_RELEASE_VERIFIER_SHA256", &verifier_pin);
    try environment.put("ZIGOS_RELEASE_SIGNING_KEY_ID", trust.key_id);
    try environment.put("ZIGOS_RELEASE_HARDWARE_BACKED", "true");
    try environment.put("ZIGOS_RELEASE_DSSE_SIGN_EXECUTABLE", self);
    try environment.put("ZIGOS_RELEASE_DSSE_SIGN_ARGS_JSON", "[\"sign\"]");
    try environment.put("ZIGOS_RELEASE_TRUST_STATE", try ctx.fmt("{s}/state.json", .{trust_dir}));
    try environment.put("ZIGOS_RELEASE_SEQUENCE", "1");
    try environment.put("ZIGOS_RELEASE_EXPIRES_AT", try ctx.fmt("{d}", .{trust.now + 3600}));
    const reproduction = try child(ctx, tree, &environment, &.{ host, "check-reproducible-build" }, true);
    try ctx.print("{s}", .{reproduction.stdout});
    const software = try child(ctx, tree, &environment, &.{ host, "generate-release-sbom-provenance" }, false);
    if (std.mem.indexOf(u8, software.stderr, "ReleaseKeyNotHardwareBacked") == null) {
        std.debug.print("software policy rejection: {s}\n", .{software.stderr});
        return error.SoftwareReleasePolicyAccepted;
    }
    trust = try writeTrust(ctx, trust_dir, true);
    try environment.put("ZIGOS_RELEASE_TRUST_ROOT_SHA256", trust.root_pin);
    _ = try child(ctx, tree, &environment, &.{ host, "generate-release-sbom-provenance" }, true);
    const output = try ctx.fmt("{s}/build/release-security", .{tree});
    const finalization = try child(ctx, tree, &environment, &.{ host, "finalize-release-manifest" }, true);
    try ctx.print("{s}", .{finalization.stdout});
    if (std.mem.indexOf(u8, finalization.stdout, "17 artifacts, 10 evidence files") == null) return error.ReleaseCatalogOutputMismatch;
    const verification = try child(ctx, tree, &environment, &.{ host, "verify-release-bundle", verifier, &verifier_pin, output, tree, trust.root_path, trust.root_pin, environment.get("ZIGOS_RELEASE_TRUST_STATE").? }, true);
    try ctx.print("{s}", .{verification.stdout});
    const state_before = try ctx.read(environment.get("ZIGOS_RELEASE_TRUST_STATE").?);
    try environment.put("ZIGOS_RELEASE_SEQUENCE", "2");
    try environment.put("ZIGOS_RELEASE_DSSE_SIGN_ARGS_JSON", "[\"wrong-sign\"]");
    _ = try child(ctx, tree, &environment, &.{ host, "finalize-release-manifest" }, false);
    const marker = try ctx.fmt("{s}/release-manifest.dsse.json", .{output});
    if (ctx.exists(marker)) return error.InvalidCandidatePublished;
    if (!std.mem.eql(u8, state_before, try ctx.read(environment.get("ZIGOS_RELEASE_TRUST_STATE").?))) return error.InvalidCandidateAdvancedState;
    try environment.put("ZIGOS_RELEASE_DSSE_SIGN_ARGS_JSON", "[\"sign\"]");
    try environment.put("ZIGOS_RELEASE_SEQUENCE", "1");
    try environment.put("ZIGOS_RELEASE_EXPIRES_AT", try ctx.fmt("{d}", .{trust.now + 3601}));
    const rollback = try child(ctx, tree, &environment, &.{ host, "finalize-release-manifest" }, false);
    if (std.mem.indexOf(u8, rollback.stderr, "ReleaseManifestEquivocation") == null) return error.ReleaseEquivocationAccepted;
    if (ctx.exists(marker)) return error.EquivocatedCandidatePublished;
    const synthetic_verifier_pin = try ctx.sha256File(self);
    try environment.put("ZIGOS_RELEASE_VERIFIER", self);
    try environment.put("ZIGOS_RELEASE_VERIFIER_SHA256", &synthetic_verifier_pin);
    _ = try child(ctx, tree, &environment, &.{ host, "finalize-release-manifest" }, false);
    if (ctx.exists(marker)) return error.FailedPublishedVerificationMarkerSurvived;
    if (!std.mem.eql(u8, state_before, try ctx.read(environment.get("ZIGOS_RELEASE_TRUST_STATE").?))) return error.FailedPublishedVerificationAdvancedState;
    try ctx.write(marker, "stale publication marker");
    try environment.put("ZIGOS_RELEASE_HARDWARE_BACKED", "false");
    _ = try child(ctx, tree, &environment, &.{ host, "generate-release-sbom-provenance" }, false);
    if (ctx.exists(marker)) return error.StaleReleaseManifestSurvivedGenerationFailure;
    try std.Io.Dir.cwd().symLink(ctx.io, "../trust/root.json", try ctx.fmt("{s}/tracked-link", .{tree}), .{});
    _ = try child(ctx, tree, &environment, &.{ "jj", "--config", "user.name=Cameron Lyons", "--config", "user.email=cameron.lyons2@gmail.com", "describe", "-m", "Release fixture symlink source" }, true);
    _ = try child(ctx, tree, &environment, &.{ "jj", "--config", "user.name=Cameron Lyons", "--config", "user.email=cameron.lyons2@gmail.com", "new" }, true);
    try ctx.write(marker, "stale publication marker");
    _ = try child(ctx, tree, &environment, &.{ host, "check-reproducible-build" }, false);
    if (ctx.exists(marker)) return error.StaleReleaseManifestSurvivedReproductionFailure;
    try ctx.print("Release command integration OK: two frozen isolated builds, hardware policy, 17-target/10-evidence publication, pinned verification, invalid signer, equivocation, unchanged rollback state, publication withdrawal, stale-marker invalidation, tracked symlink rejection\n", .{});
}
