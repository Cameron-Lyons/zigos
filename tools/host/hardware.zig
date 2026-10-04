const std = @import("std");
const common = @import("common.zig");
const fixtures = @import("hardware/fixtures.zig");
const Ctx = common.Context;
pub const Context = Ctx;
const target = "asus-nuc15crsu7";
const board = "RNUC15CRSU7";
const prefix = "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7";
pub const production_contract = "spec/hardware/nuc15crsu7-production-required-markers.txt";
pub const verification_contract = "spec/hardware/nuc15crsu7-required-markers.txt";
pub const artifacts = @import("release_catalog").production_target_paths;
const inputs = [_][]const u8{ "build/os-verification.iso", "zig-out/bin/kernel-zigos-native-verification.elf", "build/release-security/release-manifest.dsse.json", "build/release-security/release-trust-policy.dsse.json", "build/release-security/root-metadata.json", production_contract, verification_contract };

pub const cycle_types = [_][]const u8{ "cold_boot", "warm_reboot", "storage_write_read", "network_frame", "suspend_resume", "crash_recovery", "crash_record_persistence", "update_rollback" };
pub const cycle_minimums = [_]usize{ 10, 10, 100, 100, 20, 10, 10, 10 };
pub const sidecar_counters = [_][]const u8{ "cold_boots", "warm_reboots", "storage_write_read_cycles", "network_frame_cycles", "suspend_resume_cycles", "crash_recovery_cycles", "crash_record_persistence_cycles", "update_rollback_cycles" };
pub const serial_counters = [_][]const u8{ "COLD_BOOTS", "WARM_REBOOTS", "STORAGE_WRITE_READ_CYCLES", "NETWORK_FRAME_CYCLES", "SUSPEND_RESUME_CYCLES", "CRASH_RECOVERY_CYCLES", "CRASH_RECORD_PERSISTENCE_CYCLES", "UPDATE_ROLLBACK_CYCLES" };
const metadata = [_][]const u8{ prefix ++ ":EVIDENCE_SOURCE:REAL_HARDWARE", prefix ++ ":BOARD_SKU:RNUC15CRSU7", prefix ++ ":PROOF_MANIFEST:RECORDED", prefix ++ ":FIRMWARE_SETTINGS:RECORDED", prefix ++ ":POWER_CYCLE_NOTES:RECORDED", prefix ++ ":ARTIFACT_DIGESTS:RECORDED" };
const forbidden = [_][]const u8{ "BOOT:ROLE:verification", "ZIGOS:RUNTIME_PROOF:PROCESS_ISOLATION:PASS", "ZIGOS:SERVICE_BOOT:IPC_CONNECT:ALL_OK", "ZIGOS:SERVICE_BOOT:SUPERVISOR:CRASH_RECORDED", "ZIGOS:SERVICE_BOOT:DRIVER:REHOST_OK", "ZIGOS:PLATFORM:ACTIVATION:ROLLBACK_OK", "ZIGOS:PLATFORM:HEALTH_CHECKS:BOOT_ROLLBACK", "ZIGOS:PERMISSION:REVIEW_PORT:READY", "ZIGOS:NOTES_DAILY:COMPLETE", "app.notes.daily", "userspace-notes-daily.elf", "zigos.system.transport-probe", "userspace-transport-probe.elf", "zigos.system.termination-probe", "userspace-termination-probe.elf", "zigos.system.service-client", "userspace-service-client.elf", "zigos.proof.mmu-isolation", "userspace-mmu-isolation-proof.elf" };

pub fn run(ctx: *Ctx, command: []const u8, args: []const []const u8) !void {
    if (eq(command, "prepare-nuc15crsu7-hardware-proof")) return prepare(ctx, args);
    if (eq(command, "write-nuc15crsu7-capture-statement")) {
        if (args.len != 1) return error.BundleDirectoryRequired;
        const root = try directory(ctx, ctx.envDefault("ZIGOS_ARTIFACT_ROOT", "."));
        const bundle = try directory(ctx, args[0]);
        try writeStatement(ctx, bundle, root);
        return ctx.print("RNUC15CRSU7 canonical capture statement written: {s}/capture-statement.txt\n", .{bundle});
    }
    if (eq(command, "check-nuc15crsu7-hardware-proof")) {
        if (args.len != 1) return error.BundleDirectoryRequired;
        try check(ctx, args[0], try Options.fromEnv(ctx));
        return ctx.print("RNUC15CRSU7 authenticated hardware proof bundle OK: {s}\n", .{args[0]});
    }
    if (eq(command, "test-nuc15crsu7-hardware-proof-checker")) return fixtures.selfTest(ctx);
    if (eq(command, "hardware-fixture-verifier")) return fixtures.hardwareVerifier(ctx, args);
    if (eq(command, "hardware-fixture-release-verifier")) return fixtures.releaseVerifier(ctx, args);
    if (eq(command, "hardware-fixture-compiler")) return fixtures.compiler(ctx, args);
    return error.UnknownHardwareCommand;
}

pub fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
pub fn digest(data: []const u8) [64]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}
pub fn join(ctx: *Ctx, root: []const u8, child: []const u8) ![]const u8 {
    return ctx.fmt("{s}/{s}", .{ root, child });
}
fn contained(root: []const u8, path: []const u8) bool {
    return eq(root, path) or (std.mem.startsWith(u8, path, root) and path.len > root.len and path[root.len] == '/');
}
fn hex(s: []const u8, len: usize) bool {
    if (s.len != len) return false;
    for (s) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return false;
    return true;
}
fn decimal(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}
fn timestamp(s: []const u8) bool {
    if (s.len != 20) return false;
    for (s, 0..) |c, i| {
        const want: ?u8 = switch (i) {
            4, 7 => '-',
            10 => 'T',
            13, 16 => ':',
            19 => 'Z',
            else => null,
        };
        if (want) |w| {
            if (c != w) return false;
        } else if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}
fn uuid(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (c != '-') return false;
        } else if (!std.ascii.isHex(c)) return false;
    }
    return true;
}
fn deviceId(s: []const u8) bool {
    if (s.len < 8 or s.len > 128 or !std.ascii.isAlphanumeric(s[0])) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "._:-", c) == null) return false;
    return true;
}
pub fn key(text: []const u8, name: []const u8) ![]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var result: ?[]const u8 = null;
    while (lines.next()) |line| {
        const i = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!eq(line[0..i], name)) continue;
        if (result != null) return error.DuplicateKey;
        result = line[i + 1 ..];
    }
    return result orelse error.MissingKey;
}
fn kv(text: []const u8, name: []const u8, expected: []const u8) !void {
    if (!eq(try key(text, name), expected)) return error.KeyValueMismatch;
}
fn present(text: []const u8, name: []const u8) !void {
    if ((try key(text, name)).len == 0) return error.EmptyKey;
}
fn requireHex(text: []const u8, name: []const u8, n: usize) !void {
    if (!hex(try key(text, name), n)) return error.InvalidDigest;
}
fn requireTimestamp(text: []const u8, name: []const u8) !void {
    if (!timestamp(try key(text, name))) return error.InvalidTimestamp;
}
fn orderedTimes(text: []const u8, earlier: []const u8, later: []const u8) !void {
    if (std.mem.order(u8, try key(text, earlier), try key(text, later)) == .gt) return error.TimestampOrder;
}
fn insideWindow(t: []const u8, start: []const u8, end: []const u8) !void {
    if (std.mem.order(u8, t, start) == .lt or std.mem.order(u8, t, end) == .gt) return error.TimestampOutsideCaptureWindow;
}
fn containsInsensitive(text: []const u8, needle: []const u8) bool {
    if (needle.len > text.len) return false;
    for (0..text.len - needle.len + 1) |i| if (std.ascii.eqlIgnoreCase(text[i .. i + needle.len], needle)) return true;
    return false;
}
fn completed(text: []const u8) !void {
    for ([_][]const u8{ "TODO", "TBD", "PLACEHOLDER", "FILL_ME", "synthetic", "simulated", "mock", "fake", "fixture", "test-only", "test_only", "test only", "emulated" }) |bad| if (containsInsensitive(text, bad)) return error.IncompleteOrNonRealEvidence;
    if (std.mem.indexOfScalar(u8, text, '<')) |i| {
        if (std.mem.indexOfScalar(u8, text[i + 1 ..], '>') != null) return error.PlaceholderEvidence;
    }
}
fn cleanLog(text: []const u8) !void {
    try completed(text);
    for ([_][]const u8{ "panic", "System Halted", "QEMU", "SeaBIOS", "OVMF", "TCG accelerator", "KVM accelerator", "Bochs", "BHYVE", "VMware", "VirtualBox", "Hypervisor" }) |bad| if (containsInsensitive(text, bad)) return error.FailedOrEmulatedBoot;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var parts = std.mem.splitScalar(u8, line, ':');
        while (parts.next()) |p| if (std.ascii.eqlIgnoreCase(p, "FAIL")) return error.FailedBoot;
        if (std.ascii.startsWithIgnoreCase(line, "ZIGOS:") and containsInsensitive(line, ":FAIL")) return error.FailedBoot;
    }
}
fn markerCount(text: []const u8, marker: []const u8) usize {
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (eq(line, marker)) count += 1;
    }
    return count;
}
fn prefixCount(text: []const u8, marker: []const u8) usize {
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, marker)) count += 1;
    }
    return count;
}
fn exact(text: []const u8, marker: []const u8) !void {
    if (markerCount(text, marker) != 1) return error.MissingOrDuplicateMarker;
}
fn before(text: []const u8, a: []const u8, b: []const u8) !void {
    var it = std.mem.splitScalar(u8, text, '\n');
    var ai: ?usize = null;
    var bi: ?usize = null;
    var i: usize = 0;
    while (it.next()) |line| : (i += 1) {
        if (eq(line, a) and ai == null) ai = i;
        if (eq(line, b) and bi == null) bi = i;
    }
    if (ai == null or bi == null or ai.? >= bi.?) return error.MarkerOrder;
}
pub fn activeMarkers(ctx: *Ctx, text: []const u8) ![]const []const u8 {
    try completed(text);
    var out = std.ArrayList([]const u8).empty;
    var seen = std.StringHashMap(void).init(ctx.allocator);
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        if (!eq(trimmed, line)) return error.NonCanonicalMarker;
        const gop = try seen.getOrPut(line);
        if (gop.found_existing) return error.DuplicateMarkerContract;
        try out.append(ctx.allocator, line);
    }
    if (out.items.len == 0) return error.EmptyMarkerContract;
    return out.toOwnedSlice(ctx.allocator);
}

// Resolve only the caller's root. Every evidence path below it is opened one
// component at a time with O_NOFOLLOW and retained directory handles.
pub fn directory(ctx: *Ctx, path: []const u8) ![]const u8 {
    const stat = try std.Io.Dir.cwd().statFile(ctx.io, path, .{ .follow_symlinks = false });
    if (stat.kind != .directory) return error.NotRegularDirectory;
    return std.Io.Dir.cwd().realPathFileAlloc(ctx.io, path, ctx.allocator);
}
fn secureParent(ctx: *Ctx, root: []const u8, relative: []const u8) !std.Io.Dir {
    if (std.fs.path.isAbsolute(relative)) return error.UnsafeEvidencePath;
    var dir = try std.Io.Dir.cwd().openDir(ctx.io, root, .{ .follow_symlinks = false });
    errdefer dir.close(ctx.io);
    var it = std.mem.splitScalar(u8, std.fs.path.dirname(relative) orelse "", '/');
    while (it.next()) |component| {
        if (component.len == 0) continue;
        if (eq(component, ".") or eq(component, "..")) return error.UnsafeEvidencePath;
        const next = try dir.openDir(ctx.io, component, .{ .follow_symlinks = false });
        dir.close(ctx.io);
        dir = next;
    }
    return dir;
}
fn openEvidence(ctx: *Ctx, root: []const u8, relative: []const u8) !std.Io.File {
    var dir = try secureParent(ctx, root, relative);
    defer dir.close(ctx.io);
    const name = std.fs.path.basename(relative);
    if (eq(name, ".") or eq(name, "..")) return error.UnsafeEvidencePath;
    const file = try dir.openFile(ctx.io, name, .{ .follow_symlinks = false, .allow_directory = false });
    errdefer file.close(ctx.io);
    const stat = try file.stat(ctx.io);
    if (stat.kind != .file or stat.size == 0) return error.EmptyOrNonRegularEvidence;
    return file;
}
pub fn readEvidence(ctx: *Ctx, root: []const u8, relative: []const u8) ![]const u8 {
    const file = try openEvidence(ctx, root, relative);
    defer file.close(ctx.io);
    var buffer: [8192]u8 = undefined;
    var reader = file.reader(ctx.io, &buffer);
    return reader.interface.allocRemaining(ctx.allocator, .limited(128 * 1024 * 1024));
}
pub fn evidenceDigest(ctx: *Ctx, root: []const u8, path: []const u8) ![64]u8 {
    const file = try openEvidence(ctx, root, path);
    defer file.close(ctx.io);
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    while (true) {
        const amount = try file.readPositionalAll(ctx.io, &buffer, offset);
        if (amount == 0) break;
        hash.update(buffer[0..amount]);
        offset += amount;
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return std.fmt.bytesToHex(result, .lower);
}

pub fn atomicWrite(ctx: *Ctx, root: []const u8, name: []const u8, data: []const u8, replace: bool) !void {
    var dir = try secureParent(ctx, root, name);
    defer dir.close(ctx.io);
    var af = try dir.createFileAtomic(ctx.io, std.fs.path.basename(name), .{ .replace = replace, .permissions = .fromMode(0o600) });
    defer af.deinit(ctx.io);
    try af.file.writeStreamingAll(ctx.io, data);
    try af.file.sync(ctx.io);
    if (replace) try af.replace(ctx.io) else try af.link(ctx.io);
}
pub fn statement(ctx: *Ctx, bundle: []const u8, root: []const u8) ![]const u8 {
    const manifest = try readEvidence(ctx, bundle, "proof-manifest.txt");
    try kv(manifest, "format", "zigos-nuc15crsu7-proof-v2");
    try kv(manifest, "target_id", target);
    try kv(manifest, "board_sku", board);
    try kv(manifest, "repo_vcs", "jj");
    try requireHex(manifest, "capture_nonce", 64);
    var out = std.ArrayList(u8).empty;
    try out.appendSlice(ctx.allocator, "format=zigos-nuc15crsu7-capture-statement-v1\n");
    for ([_][]const u8{ "capture_nonce", "target_id", "board_sku", "device_id", "repo_vcs", "repo_change_id", "repo_commit" }) |k| try out.appendSlice(ctx.allocator, try ctx.fmt("{s}={s}\n", .{ k, try key(manifest, k) }));
    const bindings = [_][2][]const u8{
        .{ "proof_manifest", "proof-manifest.txt" },                       .{ "device_identity", "device-identity.txt" },                   .{ "production_serial", "production-serial.log" },         .{ "verification_serial", "verification-serial.log" },                          .{ "cycle_manifest", "cycle-manifest.txt" },
        .{ "production_iso", "build/os.iso" },                             .{ "production_kernel", "zig-out/bin/kernel-zigos-native.elf" }, .{ "verification_iso", "build/os-verification.iso" },      .{ "verification_kernel", "zig-out/bin/kernel-zigos-native-verification.elf" }, .{ "production_marker_contract", production_contract },
        .{ "verification_marker_contract", verification_contract },        .{ "firmware_settings", "firmware-settings.txt" },               .{ "power_cycle_notes", "power-cycle-notes.txt" },         .{ "attestation_lifecycle", "attestation-lifecycle.txt" },                      .{ "artifact_digests", "artifact-digests.sha256" },
        .{ "operator_metadata_markers", "operator-metadata-markers.txt" }, .{ "production_quote", "production-attestation.quote" },         .{ "production_signature", "production-attestation.sig" }, .{ "verification_quote", "verification-attestation.quote" },                    .{ "verification_signature", "verification-attestation.sig" },
    };
    for (bindings, 0..) |b, i| try out.appendSlice(ctx.allocator, try ctx.fmt("{s}_sha256={s}\n", .{ b[0], try evidenceDigest(ctx, if (i >= 5 and i <= 10) root else bundle, b[1]) }));
    return out.toOwnedSlice(ctx.allocator);
}
fn ceremonyLock(ctx: *Ctx, bundle: []const u8) !std.Io.File {
    const file = try std.Io.Dir.cwd().openFile(ctx.io, try join(ctx, bundle, "proof-manifest.txt"), .{ .follow_symlinks = false, .allow_directory = false, .lock = .exclusive, .lock_nonblocking = true });
    errdefer file.close(ctx.io);
    if ((try file.stat(ctx.io)).kind != .file) return error.NonRegularProofManifest;
    return file;
}
pub fn writeStatement(ctx: *Ctx, bundle: []const u8, root: []const u8) !void {
    const lock = try ceremonyLock(ctx, bundle);
    defer lock.close(ctx.io);
    try atomicWrite(ctx, bundle, "capture-statement.txt", try statement(ctx, bundle, root), true);
}

pub const Options = struct {
    artifact_root: []const u8,
    verifier: []const u8,
    verifier_digest: []const u8,
    nonce: []const u8,
    release_verifier: []const u8,
    release_verifier_digest: []const u8,
    trust_root: []const u8,
    trust_root_digest: []const u8,
    trust_state: []const u8,
    expected_change: ?[]const u8 = null,
    expected_commit: ?[]const u8 = null,
    pub fn fromEnv(ctx: *Ctx) !Options {
        return .{
            .artifact_root = ctx.envDefault("ZIGOS_ARTIFACT_ROOT", "."),
            .verifier = ctx.envDefault("ZIGOS_HARDWARE_PROOF_VERIFIER", ""),
            .verifier_digest = ctx.envDefault("ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256", ""),
            .nonce = ctx.envDefault("ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE", ""),
            .release_verifier = ctx.envDefault("ZIGOS_RELEASE_VERIFIER", ""),
            .release_verifier_digest = ctx.envDefault("ZIGOS_RELEASE_VERIFIER_SHA256", ""),
            .trust_root = ctx.envDefault("ZIGOS_RELEASE_TRUST_ROOT", ""),
            .trust_root_digest = ctx.envDefault("ZIGOS_RELEASE_TRUST_ROOT_SHA256", ""),
            .trust_state = ctx.envDefault("ZIGOS_RELEASE_TRUST_STATE", ""),
            .expected_change = ctx.env("ZIGOS_EXPECTED_REPO_CHANGE_ID"),
            .expected_commit = ctx.env("ZIGOS_EXPECTED_REPO_COMMIT"),
        };
    }
};
fn external(ctx: *Ctx, path: []const u8, bundle: []const u8, root: []const u8, executable: bool) ![]const u8 {
    if (!std.fs.path.isAbsolute(path)) return error.ExternalAbsolutePathRequired;
    const s = try std.Io.Dir.cwd().statFile(ctx.io, path, .{ .follow_symlinks = false });
    if (s.kind != .file or s.size == 0) return error.ExternalRegularFileRequired;
    if (executable) try std.Io.Dir.cwd().access(ctx.io, path, .{ .execute = true });
    const real = try std.Io.Dir.cwd().realPathFileAlloc(ctx.io, path, ctx.allocator);
    if (contained(bundle, real) or contained(root, real)) return error.IndependentTrustRequired;
    return real;
}
fn jjId(ctx: *Ctx, which: []const u8) ![]const u8 {
    const r = try ctx.capture(&.{ "jj", "log", "-r", "@", "--no-graph", "-T", try ctx.fmt("{s} ++ \"\\n\"", .{which}) });
    if (r.term != .exited or r.term.exited != 0) return error.JujutsuIdentityUnavailable;
    return std.mem.trim(u8, r.stdout, "\r\n");
}
fn tempDir(ctx: *Ctx) ![]const u8 {
    const base = try directory(ctx, ctx.envDefault("TMPDIR", "/tmp"));
    var bytes: [16]u8 = undefined;
    std.Io.random(ctx.io, &bytes);
    const p = try join(ctx, base, try ctx.fmt("zigos-hardware-{s}", .{std.fmt.bytesToHex(bytes, .lower)}));
    try std.Io.Dir.cwd().createDir(ctx.io, p, .fromMode(0o700));
    return p;
}
fn pin(ctx: *Ctx, original: []const u8, tmp: []const u8, name: []const u8, expected: []const u8) ![]const u8 {
    const data = try readEvidence(ctx, std.fs.path.dirname(original).?, std.fs.path.basename(original));
    if (!eq(&digest(data), expected)) return error.PinnedVerifierDigestMismatch;
    try atomicWrite(ctx, tmp, name, data, false);
    const path = try join(ctx, tmp, name);
    try std.Io.Dir.cwd().setFilePermissions(ctx.io, path, .fromMode(0o500), .{ .follow_symlinks = false });
    return path;
}
pub fn check(parent_ctx: *Ctx, path: []const u8, options: Options) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var ctx = parent_ctx.*;
    ctx.allocator = arena.allocator();
    return checkImpl(&ctx, path, options);
}
fn checkImpl(ctx: *Ctx, path: []const u8, options: Options) !void {
    const bundle = try directory(ctx, path);
    const lock = try ceremonyLock(ctx, bundle);
    defer lock.close(ctx.io);
    const root = try directory(ctx, options.artifact_root);
    if (!hex(options.nonce, 64)) return error.FreshNonceRequired;
    if (!hex(options.verifier_digest, 64) or !hex(options.release_verifier_digest, 64) or !hex(options.trust_root_digest, 64)) return error.PinnedTrustDigestRequired;
    const verifier = try external(ctx, options.verifier, bundle, root, true);
    const release_verifier = try external(ctx, options.release_verifier, bundle, root, true);
    const trust_root = try external(ctx, options.trust_root, bundle, root, false);
    if (!std.fs.path.isAbsolute(options.trust_state)) return error.ExternalTrustStateRequired;
    const state_parent = try directory(ctx, std.fs.path.dirname(options.trust_state).?);
    const state = try join(ctx, state_parent, std.fs.path.basename(options.trust_state));
    if (contained(bundle, state) or contained(root, state)) return error.ExternalTrustStateRequired;
    if (std.Io.Dir.cwd().statFile(ctx.io, state, .{ .follow_symlinks = false })) |s| {
        if (s.kind != .file) return error.NonRegularTrustState;
    } else |err| {
        if (err != error.FileNotFound) return err;
    }
    const tmp = try tempDir(ctx);
    defer std.Io.Dir.cwd().deleteTree(ctx.io, tmp) catch {};
    const pinned_hw = try pin(ctx, verifier, tmp, if (eq(std.fs.path.basename(verifier), "hardware-fixture-verifier")) "hardware-fixture-verifier" else "trusted-hardware-verifier", options.verifier_digest);
    const pinned_release = try pin(ctx, release_verifier, tmp, if (eq(std.fs.path.basename(release_verifier), "hardware-fixture-release-verifier")) "hardware-fixture-release-verifier" else "trusted-release-verifier", options.release_verifier_digest);
    const root_data = try readEvidence(ctx, std.fs.path.dirname(trust_root).?, std.fs.path.basename(trust_root));
    if (!eq(&digest(root_data), options.trust_root_digest)) return error.PinnedRootDigestMismatch;
    const release_bundle = try join(ctx, root, "build/release-security");
    if (!eq(root_data, try readEvidence(ctx, root, "build/release-security/root-metadata.json"))) return error.BundledRootMismatch;
    _ = try readEvidence(ctx, root, "build/release-security/release-manifest.dsse.json");
    _ = try readEvidence(ctx, root, "build/release-security/release-trust-policy.dsse.json");
    const rr = try ctx.capture(&.{ pinned_release, "verify", "--bundle", release_bundle, "--artifacts", root, "--trusted-root", trust_root, "--trusted-root-sha256", options.trust_root_digest, "--trust-state", state });
    if (rr.term != .exited or rr.term.exited != 0) return error.ReleaseVerifierRejected;
    const manifest = try readEvidence(ctx, bundle, "proof-manifest.txt");
    try completed(manifest);
    try kv(manifest, "format", "zigos-nuc15crsu7-proof-v2");
    try kv(manifest, "target_id", target);
    try kv(manifest, "board_sku", board);
    try kv(manifest, "evidence_source", "real_hardware");
    try kv(manifest, "capture_nonce", options.nonce);
    const device = try key(manifest, "device_id");
    if (!deviceId(device)) return error.InvalidDeviceId;
    const paths = [_][2][]const u8{ .{ "device_identity", "device-identity.txt" }, .{ "production_serial_log", "production-serial.log" }, .{ "verification_serial_log", "verification-serial.log" }, .{ "cycle_manifest", "cycle-manifest.txt" }, .{ "production_boot_medium", "build/os.iso" }, .{ "production_boot_kernel", "zig-out/bin/kernel-zigos-native.elf" }, .{ "production_required_markers", production_contract }, .{ "verification_boot_medium", "build/os-verification.iso" }, .{ "verification_boot_kernel", "zig-out/bin/kernel-zigos-native-verification.elf" }, .{ "verification_required_markers", verification_contract }, .{ "firmware_settings", "firmware-settings.txt" }, .{ "power_cycle_notes", "power-cycle-notes.txt" }, .{ "attestation_lifecycle", "attestation-lifecycle.txt" }, .{ "artifact_digests", "artifact-digests.sha256" }, .{ "release_bundle", "build/release-security" }, .{ "release_manifest", "build/release-security/release-manifest.dsse.json" }, .{ "release_root_metadata", "build/release-security/root-metadata.json" }, .{ "release_trust_policy", "build/release-security/release-trust-policy.dsse.json" }, .{ "operator_metadata_markers", "operator-metadata-markers.txt" }, .{ "production_quote", "production-attestation.quote" }, .{ "production_signature", "production-attestation.sig" }, .{ "verification_quote", "verification-attestation.quote" }, .{ "verification_signature", "verification-attestation.sig" }, .{ "capture_statement", "capture-statement.txt" } };
    for (paths) |p| try kv(manifest, p[0], p[1]);
    for ([_][2][]const u8{ .{ "release_manifest_sha256", "build/release-security/release-manifest.dsse.json" }, .{ "release_root_metadata_sha256", "build/release-security/root-metadata.json" }, .{ "release_trust_policy_sha256", "build/release-security/release-trust-policy.dsse.json" } }) |p| try kv(manifest, p[0], &(try evidenceDigest(ctx, root, p[1])));
    try requireTimestamp(manifest, "prepared_at_utc");
    try requireTimestamp(manifest, "captured_at_utc");
    try orderedTimes(manifest, "prepared_at_utc", "captured_at_utc");
    const start = try key(manifest, "prepared_at_utc");
    const end = try key(manifest, "captured_at_utc");
    try present(manifest, "operator");
    try kv(manifest, "repo_vcs", "jj");
    const change = try key(manifest, "repo_change_id");
    if (change.len != 32) return error.InvalidChangeId;
    for (change) |c| if (c < 'a' or c > 'z') return error.InvalidChangeId;
    try requireHex(manifest, "repo_commit", 40);
    try kv(manifest, "repo_change_id", options.expected_change orelse try jjId(ctx, "change_id"));
    try kv(manifest, "repo_commit", options.expected_commit orelse try jjId(ctx, "commit_id"));
    try kv(manifest, "repo_dirty_files", "0");
    const identity = try readEvidence(ctx, bundle, "device-identity.txt");
    try completed(identity);
    try kv(identity, "format", "zigos-nuc15crsu7-device-identity-v1");
    try kv(identity, "target_id", target);
    try kv(identity, "board_sku", board);
    try kv(identity, "device_id", device);
    if (!uuid(try key(identity, "smbios_system_uuid"))) return error.InvalidUuid;
    try present(identity, "baseboard_serial");
    try requireHex(identity, "tpm_ek_public_sha256", 64);
    const canonical = try statement(ctx, bundle, root);
    const bound_statement = try readEvidence(ctx, bundle, "capture-statement.txt");
    try completed(bound_statement);
    if (!eq(canonical, bound_statement)) return error.NonCanonicalCaptureStatement;
    const production = try readEvidence(ctx, bundle, "production-serial.log");
    const verification = try readEvidence(ctx, bundle, "verification-serial.log");
    try validateLogs(ctx, production, verification, root);
    const firmware = try readEvidence(ctx, bundle, "firmware-settings.txt");
    try completed(firmware);
    for ([_][2][]const u8{ .{ "target_id", target }, .{ "board_sku", board }, .{ "boot_mode", "UEFI" }, .{ "secure_boot", "enabled" }, .{ "storage_mode", "nvme" } }) |p| try kv(firmware, p[0], p[1]);
    for ([_][]const u8{ "bios_version", "wake_suspend", "changed_options" }) |k| try present(firmware, k);
    const power = try readEvidence(ctx, bundle, "power-cycle-notes.txt");
    try completed(power);
    try kv(power, "target_id", target);
    try present(power, "operator");
    try present(power, "notes");
    try requireTimestamp(power, "started_at_utc");
    try requireTimestamp(power, "completed_at_utc");
    try orderedTimes(power, "started_at_utc", "completed_at_utc");
    try insideWindow(try key(power, "started_at_utc"), start, end);
    try insideWindow(try key(power, "completed_at_utc"), start, end);
    const lifecycle = try readEvidence(ctx, bundle, "attestation-lifecycle.txt");
    try completed(lifecycle);
    try kv(lifecycle, "target_id", target);
    try kv(lifecycle, "evidence_source", "real_hardware");
    for ([_][]const u8{ "operator", "provider", "root_key_id", "notes" }) |k| try present(lifecycle, k);
    try requireTimestamp(lifecycle, "captured_at_utc");
    try insideWindow(try key(lifecycle, "captured_at_utc"), start, end);
    var gens: [3]u64 = undefined;
    for ([_][]const u8{ "initial_generation", "active_generation", "revoked_generation_count" }, 0..) |k, i| {
        const v = try key(lifecycle, k);
        if (!decimal(v) or v[0] == '0') return error.InvalidGeneration;
        gens[i] = try std.fmt.parseInt(u64, v, 10);
    }
    if (gens[1] <= gens[0]) return error.AttestationGenerationNotAdvanced;
    for ([_][]const u8{ "stale_generation_rejected", "revoked_generation_rejected", "verifier_rejected_stale_attestation", "verifier_metadata_digest_bound" }) |k| try kv(lifecycle, k, "true");
    try requireHex(lifecycle, "verifier_metadata_digest", 64);
    try requireHex(lifecycle, "attestation_request_digest", 64);
    const operator = try readEvidence(ctx, bundle, "operator-metadata-markers.txt");
    try completed(operator);
    for (metadata) |m| try exact(operator, m);
    try validateCycles(ctx, bundle, options.nonce, device, power, verification);
    try validateArtifacts(ctx, bundle, root);
    // Contract inputs under a foreign artifact root must match this checkout.
    const current = try directory(ctx, ".");
    for ([_][]const u8{ production_contract, verification_contract }) |p| if (!eq(&(try evidenceDigest(ctx, root, p)), &(try evidenceDigest(ctx, current, p)))) return error.MarkerContractMismatch;
    const pq = try readEvidence(ctx, bundle, "production-attestation.quote");
    const vq = try readEvidence(ctx, bundle, "verification-attestation.quote");
    const ps = try readEvidence(ctx, bundle, "production-attestation.sig");
    const vs = try readEvidence(ctx, bundle, "verification-attestation.sig");
    if (eq(&digest(pq), &digest(vq)) or eq(&digest(ps), &digest(vs))) return error.RolesMustBeDistinct;
    const sh = digest(bound_statement);
    const response = try ctx.capture(&.{ pinned_hw, "--statement", try join(ctx, bundle, "capture-statement.txt"), "--statement-sha256", &sh, "--nonce", options.nonce, "--target-id", target, "--device-id", device, "--production-quote", try join(ctx, bundle, "production-attestation.quote"), "--production-signature", try join(ctx, bundle, "production-attestation.sig"), "--verification-quote", try join(ctx, bundle, "verification-attestation.quote"), "--verification-signature", try join(ctx, bundle, "verification-attestation.sig") });
    if (response.term != .exited or response.term.exited != 0) return error.HardwareVerifierRejected;
    const expected = try ctx.fmt("format=zigos-trusted-hardware-verifier-response-v1\nresult=verified\nassertion=signed-response\nstatement_sha256={s}\nnonce={s}\ntarget_id={s}\ndevice_id={s}\nproduction_role=verified\nverification_role=verified\n", .{ &sh, options.nonce, target, device });
    if (!eq(response.stdout, expected)) return error.ExactVerifierResponseRequired;
}

fn validateLogs(ctx: *Ctx, production: []const u8, verification: []const u8, root: []const u8) !void {
    try cleanLog(production);
    try cleanLog(verification);
    if (prefixCount(production, "BOOT:ROLE:") != 1 or prefixCount(verification, "BOOT:ROLE:") != 1) return error.MultipleBootRoles;
    try exact(production, "BOOT:ROLE:production");
    try exact(verification, "BOOT:ROLE:verification");
    try exact(production, "ZIGOS:NATIVE:READY");
    try exact(verification, "ZIGOS:NATIVE:READY");
    for (forbidden) |m| if (std.mem.indexOf(u8, production, m) != null) return error.VerificationEvidenceInProduction;
    for (serial_counters) |name| if (prefixCount(production, try ctx.fmt("{s}:{s}:", .{ prefix, name })) != 0) return error.CycleSummaryInProduction;
    for (try activeMarkers(ctx, try readEvidence(ctx, root, production_contract))) |m| {
        if (eq(m, "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false")) continue;
        try exact(production, m);
    }
    for (try activeMarkers(ctx, try readEvidence(ctx, root, verification_contract))) |m| try exact(verification, m);
    var it = std.mem.splitScalar(u8, production, '\n');
    var checkpoint: ?[]const u8 = null;
    while (it.next()) |line| {
        const ck = "ZIGOS:STORAGE:CHECKPOINT:FINAL";
        if (!std.mem.startsWith(u8, line, ck) or (line.len > ck.len and !std.ascii.isWhitespace(line[ck.len]))) continue;
        if (checkpoint != null) return error.DuplicateCheckpoint;
        checkpoint = line;
        var fields = std.mem.tokenizeAny(u8, line, " \t\r\x0b\x0c");
        if (!eq(fields.next() orelse "", ck) or !eq(fields.next() orelse "", "enabled=true") or !eq(fields.next() orelse "", "dirty=false")) return error.InvalidCheckpoint;
        const generation = fields.next() orelse return error.InvalidCheckpoint;
        if (!std.mem.startsWith(u8, generation, "generation=") or !decimal(generation[11..])) return error.InvalidCheckpoint;
        if (!eq(fields.next() orelse "", "error=none") or fields.next() != null) return error.InvalidCheckpoint;
    }
    const ck = checkpoint orelse return error.MissingCheckpoint;
    for ([_][2][]const u8{ .{ "BOOT:START", "BOOT:PROFILE:zigos_native" }, .{ "BOOT:PROFILE:zigos_native", "BOOT:ROLE:production" }, .{ "BOOT:ROLE:production", "BOOT:CORE_READY" }, .{ "ZIGOS:PLATFORM:MEASURED_BOOT:VERIFIED_ROOT", ck }, .{ ck, "ZIGOS:TASK:SESSION_READY" }, .{ "ZIGOS:TASK:SESSION_READY", "ZIGOS:NATIVE:READY" } }) |p| try before(production, p[0], p[1]);
    try before(verification, "BOOT:ROLE:verification", "ZIGOS:NATIVE:READY");
    for (metadata) |m| try exact(verification, m);
    for ([_][2][]const u8{ .{ "SMBIOS_SKU", "UEFI_BOOT" }, .{ "MULTIBOOT_MEMORY_MAP", "UEFI_BOOT" }, .{ "APIC_TIMER_INTERRUPT", "APIC_TIMER" }, .{ "FRAMEBUFFER_GOP_SCANOUT", "FRAMEBUFFER_GOP" }, .{ "XHCI_BOOT_KEYBOARD_REPORT", "USB_INPUT_XHCI" }, .{ "NVME_WRITE_READ_COMPLETION", "NVME_BLOCK" }, .{ "I225_LM_FRAME_INTERRUPT", "NETWORK_I225_LM" }, .{ "SUSPEND_RESUME_POWER", "SUSPEND_RESUME" }, .{ "CRASH_RECORD_REBOOT_PERSISTENCE", "CRASH_RECOVERY" } }) |p| try before(verification, try ctx.fmt("{s}:{s}:OBSERVED", .{ prefix, p[0] }), try ctx.fmt("{s}:{s}:PASS", .{ prefix, p[1] }));
}
fn validateCycles(ctx: *Ctx, bundle: []const u8, nonce: []const u8, device: []const u8, power: []const u8, verification: []const u8) !void {
    const manifest = try readEvidence(ctx, bundle, "cycle-manifest.txt");
    try completed(manifest);
    var lines = std.mem.splitScalar(u8, if (std.mem.endsWith(u8, manifest, "\n")) manifest[0 .. manifest.len - 1] else manifest, '\n');
    if (!eq(lines.next() orelse "", "format=zigos-nuc15crsu7-cycle-manifest-v1")) return error.InvalidCycleManifest;
    var counts: [cycle_types.len]usize = @splat(0);
    var last_rank: usize = 0;
    var paths = std.StringHashMap(void).init(ctx.allocator);
    var hashes = std.StringHashMap(void).init(ctx.allocator);
    while (lines.next()) |line| {
        var columns = std.mem.splitScalar(u8, line, '|');
        const type_col = columns.next() orelse return error.InvalidCycleManifest;
        const index = columns.next() orelse return error.InvalidCycleManifest;
        const hash = columns.next() orelse return error.InvalidCycleManifest;
        const path = columns.next() orelse return error.InvalidCycleManifest;
        if (columns.next() != null or !std.mem.startsWith(u8, type_col, "cycle=")) return error.InvalidCycleManifest;
        const name = type_col[6..];
        var rank: ?usize = null;
        for (cycle_types, 0..) |t, i| if (eq(t, name)) {
            rank = i;
            break;
        };
        const r = rank orelse return error.InvalidCycleType;
        if (r < last_rank or index.len != 6 or !decimal(index) or (try std.fmt.parseInt(usize, index, 10)) != counts[r] + 1 or !hex(hash, 64)) return error.NonCanonicalCycleManifest;
        if (!eq(path, try ctx.fmt("cycles/{s}-{s}.log", .{ name, index }))) return error.NonCanonicalCyclePath;
        if ((try paths.getOrPut(path)).found_existing or (try hashes.getOrPut(hash)).found_existing) return error.DuplicateCycleEvidence;
        const log = try readEvidence(ctx, bundle, path);
        try completed(log);
        if (!eq(&digest(log), hash)) return error.CycleDigestMismatch;
        for ([_][]const u8{ "QEMU", "SeaBIOS", "OVMF", "VMware", "VirtualBox", "Hypervisor" }) |bad| if (containsInsensitive(log, bad)) return error.EmulatedCycle;
        for ([_][2][]const u8{ .{ "format", "zigos-nuc15crsu7-cycle-log-v1" }, .{ "capture_nonce", nonce }, .{ "target_id", target }, .{ "device_id", device }, .{ "cycle_type", name }, .{ "cycle_index", index }, .{ "result", "pass" } }) |p| try kv(log, p[0], p[1]);
        counts[r] += 1;
        last_rank = r;
    }
    const cycle_dir_path = try join(ctx, bundle, "cycles");
    var dir = try std.Io.Dir.cwd().openDir(ctx.io, cycle_dir_path, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(ctx.io);
    var entries = dir.iterate();
    var actual_count: usize = 0;
    while (try entries.next(ctx.io)) |entry| {
        if (entry.kind != .file) return error.NonRegularCycleEntry;
        // Reject unlisted files as well as directories and links: no hidden evidence.
        const relative = try ctx.fmt("cycles/{s}", .{entry.name});
        if (!paths.contains(relative)) return error.UnlistedCycleEvidence;
        actual_count += 1;
    }
    if (actual_count != paths.count()) return error.MissingCycleEvidence;
    for (cycle_types, 0..) |_, i| {
        if (counts[i] < cycle_minimums[i]) return error.InsufficientHardwareCycles;
        const side = try key(power, sidecar_counters[i]);
        if (!decimal(side) or (try std.fmt.parseInt(usize, side, 10)) != counts[i]) return error.SpoofedCycleSummary;
        const counter_prefix = try ctx.fmt("{s}:{s}:", .{ prefix, serial_counters[i] });
        if (prefixCount(verification, counter_prefix) != 1) return error.MissingOrDuplicateCycleSummary;
        var log_lines = std.mem.splitScalar(u8, verification, '\n');
        while (log_lines.next()) |l| {
            if (!std.mem.startsWith(u8, l, counter_prefix)) continue;
            const value = l[counter_prefix.len..];
            if (!decimal(value) or (try std.fmt.parseInt(usize, value, 10)) != counts[i]) return error.SpoofedCycleSummary;
        }
    }
}
fn validateArtifacts(ctx: *Ctx, bundle: []const u8, root: []const u8) !void {
    const text = try readEvidence(ctx, bundle, "artifact-digests.sha256");
    try completed(text);
    var paths = std.StringHashMap(void).init(ctx.allocator);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r\x0b\x0c");
        const hash = fields.next() orelse continue;
        const path = fields.next() orelse return error.InvalidArtifactDigestManifest;
        if (fields.next() != null or !hex(hash, 64)) return error.InvalidArtifactDigestManifest;
        var required = false;
        for (artifacts) |a| if (eq(a, path)) {
            required = true;
            break;
        };
        if (!required or (try paths.getOrPut(path)).found_existing) return error.ExactProductionArtifactSetRequired;
        if (!eq(hash, &(try evidenceDigest(ctx, root, path)))) return error.ArtifactDigestMismatch;
    }
    if (paths.count() != artifacts.len) return error.ExactProductionArtifactSetRequired;
}

fn utcNow(ctx: *Ctx) ![]const u8 {
    const ns = std.Io.Clock.real.now(ctx.io).nanoseconds;
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(@divFloor(ns, std.time.ns_per_s)) };
    const yd = epoch.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = epoch.getDaySeconds();
    return ctx.fmt("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{ yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() });
}
// SOURCE_DATE_EPOCH must be an explicit configuration argument in nested builds,
// because ambient environment does not invalidate
// Zig's configure cache or override shared.addEfiIsoEpochArg's default.
pub fn releaseBuildArgv(ctx: *Ctx) ![]const []const u8 {
    const envs = [_][]const u8{ "ZIGOS_RELEASE_TRUST_ROOT", "ZIGOS_RELEASE_TRUST_ROOT_SHA256", "ZIGOS_RELEASE_TRUST_POLICY", "ZIGOS_RELEASE_TRUST_STATE", "ZIGOS_RELEASE_VERIFIER", "ZIGOS_RELEASE_VERIFIER_SHA256", "ZIGOS_RELEASE_DSSE_SIGN_EXECUTABLE", "ZIGOS_RELEASE_SIGNING_KEY_ID", "ZIGOS_RELEASE_HARDWARE_BACKED", "ZIGOS_RELEASE_SEQUENCE", "ZIGOS_RELEASE_EXPIRES_AT" };
    for (envs) |e| if (ctx.envDefault(e, "").len == 0) return error.ReleaseBuildTrustEnvironmentRequired;
    var argv = std.ArrayList([]const u8).empty;
    try argv.appendSlice(ctx.allocator, &.{ ctx.envDefault("ZIG_BIN", "zig"), "build", "-Doptimize=fast" });
    if (ctx.env("SOURCE_DATE_EPOCH")) |epoch| {
        if (epoch.len != 0) try argv.append(ctx.allocator, try ctx.fmt("-Dsource-date-epoch={s}", .{epoch}));
    }
    for ([_][2][]const u8{ .{ "release-trust-root", "ZIGOS_RELEASE_TRUST_ROOT" }, .{ "release-trust-root-sha256", "ZIGOS_RELEASE_TRUST_ROOT_SHA256" }, .{ "release-trust-policy", "ZIGOS_RELEASE_TRUST_POLICY" }, .{ "release-trust-state", "ZIGOS_RELEASE_TRUST_STATE" }, .{ "release-verifier", "ZIGOS_RELEASE_VERIFIER" }, .{ "release-verifier-sha256", "ZIGOS_RELEASE_VERIFIER_SHA256" } }) |p| try argv.append(ctx.allocator, try ctx.fmt("-D{s}={s}", .{ p[0], ctx.env(p[1]).? }));
    try argv.append(ctx.allocator, "release-bundle-check");
    return argv.toOwnedSlice(ctx.allocator);
}

fn prepare(ctx: *Ctx, args: []const []const u8) !void {
    var output: []const u8 = "build/hardware-proofs/nuc15crsu7";
    var nonce = ctx.envDefault("ZIGOS_HARDWARE_PROOF_NONCE", "");
    var build = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (eq(arg, "--build")) {
            build = true;
            continue;
        }
        if (eq(arg, "--help") or eq(arg, "-h")) return ctx.print("Usage: zig build tool -- prepare-nuc15crsu7-hardware-proof --nonce HEX [--build] [--output build/hardware-proofs/NAME]\n", .{});
        if (eq(arg, "--nonce") or eq(arg, "--output")) {
            i += 1;
            if (i == args.len) return error.MissingOptionValue;
            if (eq(arg, "--nonce")) nonce = args[i] else output = args[i];
            continue;
        }
        return error.UnknownArgument;
    }
    if (!hex(nonce, 64)) return error.FreshNonceRequired;
    const base = "build/hardware-proofs/";
    if (!std.mem.startsWith(u8, output, base)) return error.UnsafeProofOutput;
    const name = output[base.len..];
    if (name.len == 0 or eq(name, ".") or eq(name, "..")) return error.UnsafeProofOutput;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "._-", c) == null) return error.UnsafeProofOutput;
    const root = try directory(ctx, ".");
    for ([_][]const u8{ "build", "build/hardware-proofs" }) |p| {
        if (std.Io.Dir.cwd().statFile(ctx.io, p, .{ .follow_symlinks = false })) |s| {
            if (s.kind != .directory) return error.SymlinkProofOutput;
        } else |err| {
            if (err != error.FileNotFound) return err;
            try ctx.mkdir(p);
        }
    }
    if (ctx.exists(output)) {
        const p = try directory(ctx, output);
        var d = try std.Io.Dir.cwd().openDir(ctx.io, p, .{ .iterate = true, .follow_symlinks = false });
        defer d.close(ctx.io);
        var it = d.iterate();
        if (try it.next(ctx.io) != null) return error.ProofOutputNotEmpty;
    } else try std.Io.Dir.cwd().createDir(ctx.io, output, .default_dir);
    const bundle = try directory(ctx, output);
    if (build) try ctx.run(try releaseBuildArgv(ctx));
    for (artifacts ++ inputs) |p| _ = try evidenceDigest(ctx, root, p);
    const change = try jjId(ctx, "change_id");
    const commit = try jjId(ctx, "commit_id");
    const dirty = try ctx.capture(&.{ "jj", "diff", "-r", "@", "--name-only" });
    if (dirty.term != .exited or dirty.term.exited != 0) return error.JujutsuIdentityUnavailable;
    var dirty_count: usize = 0;
    var dirty_lines = std.mem.splitScalar(u8, dirty.stdout, '\n');
    while (dirty_lines.next()) |line| if (line.len != 0) {
        dirty_count += 1;
    };
    var manifest = std.ArrayList(u8).empty;
    try manifest.appendSlice(ctx.allocator, try ctx.fmt(@embedFile("hardware/proof-manifest.template"), .{ nonce, try evidenceDigest(ctx, root, "build/release-security/release-manifest.dsse.json"), try evidenceDigest(ctx, root, "build/release-security/root-metadata.json"), try evidenceDigest(ctx, root, "build/release-security/release-trust-policy.dsse.json"), try utcNow(ctx), change, commit, dirty_count }));
    try atomicWrite(ctx, bundle, "proof-manifest.txt", manifest.items, false);
    const lock = try ceremonyLock(ctx, bundle);
    defer lock.close(ctx.io);
    for ([_][2][]const u8{ .{ "device-identity.txt", @embedFile("hardware/device-identity.template") }, .{ "firmware-settings.txt", @embedFile("hardware/firmware-settings.template") }, .{ "power-cycle-notes.txt", @embedFile("hardware/power-cycle-notes.template") }, .{ "attestation-lifecycle.txt", @embedFile("hardware/attestation-lifecycle.template") } }) |p| try atomicWrite(ctx, bundle, p[0], p[1], false);
    var operator = std.ArrayList(u8).empty;
    for (metadata) |m| try operator.appendSlice(ctx.allocator, try ctx.fmt("{s}\n", .{m}));
    try atomicWrite(ctx, bundle, "operator-metadata-markers.txt", operator.items, false);
    try atomicWrite(ctx, bundle, "cycle-manifest.txt", "format=zigos-nuc15crsu7-cycle-manifest-v1\n", false);
    for ([_][]const u8{ "production-attestation.quote", "production-attestation.sig", "verification-attestation.quote", "verification-attestation.sig" }) |p| try atomicWrite(ctx, bundle, p, "TODO-replace-with-role-specific-hardware-quote-or-signature\n", false);
    try ctx.mkdir(try join(ctx, bundle, "cycles"));
    var hashes = std.ArrayList(u8).empty;
    for (artifacts) |p| try hashes.appendSlice(ctx.allocator, try ctx.fmt("{s}  {s}\n", .{ try evidenceDigest(ctx, root, p), p }));
    try atomicWrite(ctx, bundle, "artifact-digests.sha256", hashes.items, false);
    try ctx.print("RNUC15CRSU7 authenticated proof bundle skeleton prepared under {s}\nBound to verifier-issued nonce {s}. Capture separate production and verification boots, record individually hashed cycle logs, complete sidecars and role-specific quotes, then run write-nuc15crsu7-capture-statement and check-nuc15crsu7-hardware-proof with independently pinned hardware/release verifiers and external trust state.\n", .{ output, nonce });
}
