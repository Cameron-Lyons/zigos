const std = @import("std");
const common = @import("../common.zig");
const hw = @import("../hardware.zig");
const Ctx = common.Context;
const nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const device = "nuc15crsu7-system-00112233";
const commit = "1111111111111111111111111111111111111111";
const change = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const prefix = "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7";
fn arg(args: []const []const u8, name: []const u8) ![]const u8 {
    var result: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 2) {
        if (i + 1 >= args.len) return error.InvalidFixtureArguments;
        if (hw.eq(args[i], name)) {
            if (result != null) return error.DuplicateFixtureArgument;
            result = args[i + 1];
        }
    }
    return result orelse error.MissingFixtureArgument;
}
fn kv(text: []const u8, name: []const u8, value: []const u8) !void {
    if (!hw.eq(try hw.key(text, name), value)) return error.FixtureVerifierRejected;
}
// A native child executable records exactly the compiler's literal arguments.
pub fn compiler(ctx: *Ctx, args: []const []const u8) !void {
    try ctx.print("{s}", .{try std.json.Stringify.valueAlloc(ctx.allocator, args, .{})});
}
fn compilerArgvFixtures(ctx: *Ctx, temporary: []const u8, executable: []const u8) !void {
    const compiler_path = try hw.join(ctx, temporary, "hardware-fixture-compiler");
    try ctx.copy(executable, compiler_path);
    try std.Io.Dir.cwd().setFilePermissions(ctx.io, compiler_path, .fromMode(0o700), .{ .follow_symlinks = false });
    var environ = try ctx.environ.clone(ctx.allocator);
    defer environ.deinit();
    var child_ctx = ctx.*;
    child_ctx.environ = &environ;
    try environ.put("ZIG_BIN", compiler_path);
    const literal_root = "/independent/root with spaces/[literal]$unchanged.json";
    const literal_policy = "/independent/policy 'quote' $(unchanged).json";
    const literal_verifier = "/independent/verifier;literal";
    for ([_][2][]const u8{
        .{ "ZIGOS_RELEASE_TRUST_ROOT", literal_root },
        .{ "ZIGOS_RELEASE_TRUST_ROOT_SHA256", "root-pin" },
        .{ "ZIGOS_RELEASE_TRUST_POLICY", literal_policy },
        .{ "ZIGOS_RELEASE_TRUST_STATE", "/independent/state.json" },
        .{ "ZIGOS_RELEASE_VERIFIER", literal_verifier },
        .{ "ZIGOS_RELEASE_VERIFIER_SHA256", "verifier-pin" },
        .{ "ZIGOS_RELEASE_DSSE_SIGN_EXECUTABLE", "/independent/signer" },
        .{ "ZIGOS_RELEASE_SIGNING_KEY_ID", "signing-key" },
        .{ "ZIGOS_RELEASE_HARDWARE_BACKED", "true" },
        .{ "ZIGOS_RELEASE_SEQUENCE", "7" },
        .{ "ZIGOS_RELEASE_EXPIRES_AT", "2000000000" },
    }) |entry| try environ.put(entry[0], entry[1]);
    for ([_][]const u8{ "946684800", "" }) |epoch| {
        try environ.put("SOURCE_DATE_EPOCH", epoch);
        var expected = std.ArrayList([]const u8).empty;
        try expected.appendSlice(ctx.allocator, &.{ "build", "-Doptimize=fast" });
        if (epoch.len != 0) try expected.append(ctx.allocator, "-Dsource-date-epoch=946684800");
        try expected.appendSlice(ctx.allocator, &.{
            "-Drelease-trust-root=" ++ literal_root,
            "-Drelease-trust-root-sha256=root-pin",
            "-Drelease-trust-policy=" ++ literal_policy,
            "-Drelease-trust-state=/independent/state.json",
            "-Drelease-verifier=" ++ literal_verifier,
            "-Drelease-verifier-sha256=verifier-pin",
            "release-bundle-check",
        });
        const result = try child_ctx.capture(try hw.releaseBuildArgv(&child_ctx));
        if (!result.term.success()) return error.NativeCompilerFixtureFailed;
        const expected_json = try std.json.Stringify.valueAlloc(ctx.allocator, expected.items, .{});
        if (!hw.eq(result.stdout, expected_json)) return error.NestedReleaseBuildArgumentMismatch;
    }
}

pub fn hardwareVerifier(ctx: *Ctx, args: []const []const u8) !void {
    const statement_path = try arg(args, "--statement");
    // Native spoof mode exits zero without the required signed response.
    if (ctx.exists(try ctx.fmt("{s}/spoof-mode", .{std.fs.path.dirname(statement_path).?}))) return;
    const statement = try ctx.read(statement_path);
    const statement_hash = try arg(args, "--statement-sha256");
    if (!hw.eq(&hw.digest(statement), statement_hash)) return error.FixtureStatementDigestMismatch;
    const n = try arg(args, "--nonce");
    const d = try arg(args, "--device-id");
    const t = try arg(args, "--target-id");
    if (!hw.eq(t, "asus-nuc15crsu7")) return error.FixtureTargetMismatch;
    for ([_][]const u8{ "production", "verification" }) |role| {
        const quote = try ctx.read(try arg(args, try ctx.fmt("--{s}-quote", .{role})));
        const sig = try ctx.read(try arg(args, try ctx.fmt("--{s}-signature", .{role})));
        try kv(quote, "format", "zigos-fixture-hardware-quote-v1");
        try kv(quote, "role", role);
        try kv(quote, "nonce", n);
        try kv(quote, "device_id", d);
        try kv(sig, "format", "zigos-fixture-hardware-signature-v1");
        try kv(sig, "role", role);
        try kv(sig, "nonce", n);
        try kv(sig, "quote_sha256", &hw.digest(quote));
    }
    try ctx.print("format=zigos-trusted-hardware-verifier-response-v1\nresult=verified\nassertion=signed-response\nstatement_sha256={s}\nnonce={s}\ntarget_id={s}\ndevice_id={s}\nproduction_role=verified\nverification_role=verified\n", .{ statement_hash, n, t, d });
}
pub fn releaseVerifier(ctx: *Ctx, args: []const []const u8) !void {
    if (args.len == 0 or !hw.eq(args[0], "verify")) return error.InvalidFixtureArguments;
    const rest = args[1..];
    const bundle = try arg(rest, "--bundle");
    const artifacts = try arg(rest, "--artifacts");
    const root = try ctx.read(try arg(rest, "--trusted-root"));
    if (!hw.eq(bundle, try ctx.fmt("{s}/build/release-security", .{artifacts})) or !hw.eq(&hw.digest(root), try arg(rest, "--trusted-root-sha256")) or !hw.eq(root, try ctx.read(try ctx.fmt("{s}/root-metadata.json", .{bundle})))) return error.FixtureReleaseRejected;
    if ((try ctx.read(try ctx.fmt("{s}/release-trust-policy.dsse.json", .{bundle}))).len == 0 or (try ctx.read(try ctx.fmt("{s}/release-manifest.dsse.json", .{bundle}))).len == 0) return error.FixtureReleaseRejected;
    try ctx.write(try arg(rest, "--trust-state"), "{\"fixture\":\"authenticated-release-state\"}\n");
    try ctx.print("release bundle verified\n", .{});
}
fn write(ctx: *Ctx, root: []const u8, path: []const u8, data: []const u8) !void {
    try ctx.write(try hw.join(ctx, root, path), data);
}
fn writeRole(ctx: *Ctx, bundle: []const u8, role: []const u8) !void {
    const quote = try ctx.fmt("format=zigos-fixture-hardware-quote-v1\nrole={s}\nnonce={s}\ndevice_id={s}\nmeasurement={s}-hardware-capture\n", .{ role, nonce, device, role });
    try write(ctx, bundle, try ctx.fmt("{s}-attestation.quote", .{role}), quote);
    try rewriteSignature(ctx, bundle, role);
}
fn rewriteSignature(ctx: *Ctx, bundle: []const u8, role: []const u8) !void {
    const quote = try ctx.read(try hw.join(ctx, bundle, try ctx.fmt("{s}-attestation.quote", .{role})));
    try write(ctx, bundle, try ctx.fmt("{s}-attestation.sig", .{role}), try ctx.fmt("format=zigos-fixture-hardware-signature-v1\nrole={s}\nnonce={s}\nquote_sha256={s}\n", .{ role, nonce, hw.digest(quote) }));
}
fn replace(ctx: *Ctx, root: []const u8, path: []const u8, from: []const u8, to: []const u8) !void {
    const full = try hw.join(ctx, root, path);
    const text = try ctx.read(full);
    const next = try std.mem.replaceOwned(u8, ctx.allocator, text, from, to);
    if (hw.eq(next, text)) return error.FixtureMutationDidNotApply;
    try ctx.write(full, next);
}
fn append(ctx: *Ctx, root: []const u8, path: []const u8, text: []const u8) !void {
    const p = try hw.join(ctx, root, path);
    try ctx.write(p, try ctx.fmt("{s}{s}", .{ try ctx.read(p), text }));
}
fn makeBundle(ctx: *Ctx, bundle: []const u8, root: []const u8) !void {
    try ctx.mkdir(bundle);
    var manifest = try ctx.fmt(@embedFile("proof-manifest.template"), .{ nonce, try hw.evidenceDigest(ctx, root, "build/release-security/release-manifest.dsse.json"), try hw.evidenceDigest(ctx, root, "build/release-security/root-metadata.json"), try hw.evidenceDigest(ctx, root, "build/release-security/release-trust-policy.dsse.json"), "2026-06-10T00:00:00Z", change, commit, @as(usize, 0) });
    manifest = try std.mem.replaceOwned(u8, ctx.allocator, manifest, "device_id=TODO-fill-stable-device-id", "device_id=" ++ device);
    manifest = try std.mem.replaceOwned(u8, ctx.allocator, manifest, "captured_at_utc=TODO-fill-after-run", "captured_at_utc=2026-06-10T01:00:00Z");
    manifest = try std.mem.replaceOwned(u8, ctx.allocator, manifest, "operator=TODO-fill-operator", "operator=hardware-operator");
    try write(ctx, bundle, "proof-manifest.txt", manifest);
    try write(ctx, bundle, "device-identity.txt", "format=zigos-nuc15crsu7-device-identity-v1\ntarget_id=asus-nuc15crsu7\nboard_sku=RNUC15CRSU7\ndevice_id=" ++ device ++ "\nsmbios_system_uuid=00112233-4455-6677-8899-aabbccddeeff\nbaseboard_serial=BTNUC11SERIAL001\ntpm_ek_public_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    try write(ctx, bundle, "firmware-settings.txt", "target_id=asus-nuc15crsu7\nboard_sku=RNUC15CRSU7\nbios_version=TNTGL357.0071.2025.0123.1200\nboot_mode=UEFI\nsecure_boot=enabled\nstorage_mode=nvme\nwake_suspend=S3 wake by keyboard and power button enabled\nchanged_options=boot order set to USB first\n");
    try write(ctx, bundle, "power-cycle-notes.txt", "target_id=asus-nuc15crsu7\noperator=hardware-operator\nstarted_at_utc=2026-06-10T00:00:00Z\ncompleted_at_utc=2026-06-10T01:00:00Z\ncold_boots=10\nwarm_reboots=10\nstorage_write_read_cycles=100\nnetwork_frame_cycles=100\nsuspend_resume_cycles=20\ncrash_recovery_cycles=10\ncrash_record_persistence_cycles=10\nupdate_rollback_cycles=10\nnotes=operator observed all required physical power and device cycles\n");
    try write(ctx, bundle, "attestation-lifecycle.txt", "target_id=asus-nuc15crsu7\nevidence_source=real_hardware\noperator=hardware-operator\ncaptured_at_utc=2026-06-10T00:30:00Z\nprovider=hardware-tpm-root\nroot_key_id=hardware-root-key\ninitial_generation=7\nactive_generation=9\nrevoked_generation_count=1\nstale_generation_rejected=true\nrevoked_generation_rejected=true\nverifier_rejected_stale_attestation=true\nverifier_metadata_digest_bound=true\nverifier_metadata_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nattestation_request_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nnotes=operator captured root lifecycle rejection and request binding\n");
    const metadata = prefix ++ ":EVIDENCE_SOURCE:REAL_HARDWARE\n" ++ prefix ++ ":BOARD_SKU:RNUC15CRSU7\n" ++ prefix ++ ":PROOF_MANIFEST:RECORDED\n" ++ prefix ++ ":FIRMWARE_SETTINGS:RECORDED\n" ++ prefix ++ ":POWER_CYCLE_NOTES:RECORDED\n" ++ prefix ++ ":ARTIFACT_DIGESTS:RECORDED\n";
    try write(ctx, bundle, "operator-metadata-markers.txt", metadata);
    var production = std.ArrayList(u8).empty;
    for (try hw.activeMarkers(ctx, try hw.readEvidence(ctx, root, hw.production_contract))) |m| try production.appendSlice(ctx.allocator, try ctx.fmt("{s}{s}\n", .{ m, if (hw.eq(m, "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false")) " generation=42 error=none" else "" }));
    try write(ctx, bundle, "production-serial.log", production.items);
    var verification = std.ArrayList(u8).empty;
    try verification.appendSlice(ctx.allocator, metadata);
    const markers = try hw.activeMarkers(ctx, try hw.readEvidence(ctx, root, hw.verification_contract));
    for (0..3) |pass| for (markers) |m| {
        const hardware = std.mem.startsWith(u8, m, prefix ++ ":");
        const observed = std.mem.endsWith(u8, m, ":OBSERVED");
        if ((pass == 0 and hardware and observed) or (pass == 1 and hardware and !observed) or (pass == 2 and !hardware)) try verification.appendSlice(ctx.allocator, try ctx.fmt("{s}\n", .{m}));
    };
    for (hw.serial_counters, hw.cycle_minimums) |counter, count| try verification.appendSlice(ctx.allocator, try ctx.fmt("{s}:{s}:{d}\n", .{ prefix, counter, count }));
    try write(ctx, bundle, "verification-serial.log", verification.items);
    var cycles = std.ArrayList(u8).empty;
    try cycles.appendSlice(ctx.allocator, "format=zigos-nuc15crsu7-cycle-manifest-v1\n");
    for (hw.cycle_types, hw.cycle_minimums) |kind, count| for (1..count + 1) |i| {
        const index = try ctx.fmt("{d:0>6}", .{i});
        const path = try ctx.fmt("cycles/{s}-{s}.log", .{ kind, index });
        const log = try ctx.fmt("format=zigos-nuc15crsu7-cycle-log-v1\ncapture_nonce={s}\ntarget_id=asus-nuc15crsu7\ndevice_id={s}\ncycle_type={s}\ncycle_index={s}\nresult=pass\nobservation=physical target cycle completed\n", .{ nonce, device, kind, index });
        try write(ctx, bundle, path, log);
        try cycles.appendSlice(ctx.allocator, try ctx.fmt("cycle={s}|{s}|{s}|{s}\n", .{ kind, index, hw.digest(log), path }));
    };
    try write(ctx, bundle, "cycle-manifest.txt", cycles.items);
    try writeRole(ctx, bundle, "production");
    try writeRole(ctx, bundle, "verification");
    var hashes = std.ArrayList(u8).empty;
    for (hw.artifacts) |p| try hashes.appendSlice(ctx.allocator, try ctx.fmt("{s}  {s}\n", .{ try hw.evidenceDigest(ctx, root, p), p }));
    try write(ctx, bundle, "artifact-digests.sha256", hashes.items);
    try hw.writeStatement(ctx, bundle, root);
}
fn expectFail(ctx: *Ctx, bundle: []const u8, options: hw.Options, name: []const u8) !void {
    hw.check(ctx, bundle, options) catch return;
    std.debug.print("Expected hardware checker rejection: {s}\n", .{name});
    return error.ExpectedHardwareProofRejection;
}
pub fn selfTest(ctx: *Ctx) !void {
    const tmp = try ctx.tempDir("zigos-nuc-proof-checker");
    defer ctx.removeTree(tmp) catch {};
    const absolute = try hw.directory(ctx, tmp);
    const root = try hw.join(ctx, absolute, "artifacts");
    try ctx.mkdir(root);
    for (hw.artifacts) |p| try write(ctx, root, p, try ctx.fmt("hardware checker artifact {s}\n", .{p}));
    for ([_][]const u8{ "build/os-verification.iso", "zig-out/bin/kernel-zigos-native-verification.elf" }) |p| try write(ctx, root, p, try ctx.fmt("hardware checker artifact {s}\n", .{p}));
    for ([_][]const u8{ hw.production_contract, hw.verification_contract }) |p| try write(ctx, root, p, try ctx.read(p));
    const trusted_root = try hw.join(ctx, absolute, "trusted-root-metadata.json");
    const root_data = "{\"schemaVersion\":1,\"fixture\":\"trusted-root\"}\n";
    try ctx.write(trusted_root, root_data);
    try write(ctx, root, "build/release-security/root-metadata.json", root_data);
    try write(ctx, root, "build/release-security/release-manifest.dsse.json", "authenticated exact release manifest fixture\n");
    try write(ctx, root, "build/release-security/release-trust-policy.dsse.json", "authenticated release policy fixture\n");
    const executable = try std.process.executablePathAlloc(ctx.io, ctx.allocator);
    try compilerArgvFixtures(ctx, absolute, executable);
    const verifier = try hw.join(ctx, absolute, "hardware-fixture-verifier");
    const release_verifier = try hw.join(ctx, absolute, "hardware-fixture-release-verifier");
    try ctx.copy(executable, verifier);
    try ctx.copy(executable, release_verifier);
    for ([_][]const u8{ verifier, release_verifier }) |p| try std.Io.Dir.cwd().setFilePermissions(ctx.io, p, .fromMode(0o700), .{ .follow_symlinks = false });
    const vd = try ctx.sha256File(verifier);
    const rd = try ctx.sha256File(release_verifier);
    const td = hw.digest(root_data);
    const options: hw.Options = .{ .artifact_root = root, .verifier = verifier, .verifier_digest = &vd, .nonce = nonce, .release_verifier = release_verifier, .release_verifier_digest = &rd, .trust_root = trusted_root, .trust_root_digest = &td, .trust_state = try hw.join(ctx, absolute, "persistent-release-trust-state.json"), .expected_change = change, .expected_commit = commit };
    const valid = try hw.join(ctx, absolute, "valid");
    try makeBundle(ctx, valid, root);
    try hw.check(ctx, valid, options);
    {
        const lock = try std.Io.Dir.cwd().openFile(ctx.io, try hw.join(ctx, valid, "proof-manifest.txt"), .{ .follow_symlinks = false, .lock = .exclusive, .lock_nonblocking = true });
        defer lock.close(ctx.io);
        try expectFail(ctx, valid, options, "ceremony-busy-checker");
        // Confirm a held ceremony lock prevents statement publication as well.
        if (hw.writeStatement(ctx, valid, root)) |_| return error.ExpectedHardwareWriterLockRejection else |_| {}
    }
    const cases = [_][]const u8{ "missing-verifier", "spoof-verifier", "wrong-verifier-digest", "stale-nonce", "stale-production-log", "stale-verification-log", "production-notes-fixture", "tampered-statement", "spoofed-scalar-counts", "stale-cycle-log", "missing-cycle-log", "duplicate-cycle", "stale-quote", "invalid-quote", "invalid-signature", "missing-quote", "checkpoint-error", "checkpoint-after-ready", "disabled-secure-boot", "unverified-boot-image", "missing-verification-ready", "device-mismatch", "legacy-digest-entry", "tampered-release-manifest", "tampered-root-evidence", "artifact-hash", "symlink-evidence", "symlink-cycle-directory", "unlisted-cycle", "duplicate-key", "noncanonical-contract", "duplicate-contract", "insufficient-cycle", "duplicate-cycle-digest", "untrusted-verifier-location", "untrusted-root-location", "internal-trust-state", "wrong-release-verifier-digest", "wrong-root-digest" };
    for (cases) |name| {
        const bundle = try hw.join(ctx, absolute, name);
        try makeBundle(ctx, bundle, root);
        var opts = options;
        var rebind = true;
        if (hw.eq(name, "missing-verifier")) opts.verifier = "" else if (hw.eq(name, "spoof-verifier")) try write(ctx, bundle, "spoof-mode", "true\n") else if (hw.eq(name, "wrong-verifier-digest")) opts.verifier_digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" else if (hw.eq(name, "stale-nonce")) opts.nonce = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" else if (hw.eq(name, "stale-production-log")) {
            try append(ctx, bundle, "production-serial.log", "late unbound production bytes\n");
            rebind = false;
        } else if (hw.eq(name, "stale-verification-log")) {
            try append(ctx, bundle, "verification-serial.log", "late unbound verification bytes\n");
            rebind = false;
        } else if (hw.eq(name, "production-notes-fixture")) try append(ctx, bundle, "production-serial.log", "app.notes.daily\nuserspace-notes-daily.elf\n") else if (hw.eq(name, "tampered-statement")) {
            try replace(ctx, bundle, "capture-statement.txt", "production_iso_sha256=", "production_iso_sha256=f");
            rebind = false;
        } else if (hw.eq(name, "spoofed-scalar-counts")) {
            try replace(ctx, bundle, "power-cycle-notes.txt", "cold_boots=10", "cold_boots=11");
            try replace(ctx, bundle, "verification-serial.log", ":COLD_BOOTS:10", ":COLD_BOOTS:11");
        } else if (hw.eq(name, "stale-cycle-log")) try append(ctx, bundle, "cycles/cold_boot-000001.log", "late unbound cycle bytes\n") else if (hw.eq(name, "missing-cycle-log")) try ctx.removeFile(try hw.join(ctx, bundle, "cycles/warm_reboot-000010.log")) else if (hw.eq(name, "duplicate-cycle")) {
            const text = try ctx.read(try hw.join(ctx, bundle, "cycle-manifest.txt"));
            const trimmed = std.mem.trimEnd(u8, text, "\n");
            const last = std.mem.lastIndexOfScalar(u8, trimmed, '\n').?;
            try append(ctx, bundle, "cycle-manifest.txt", try ctx.fmt("{s}\n", .{trimmed[last + 1 ..]}));
        } else if (hw.eq(name, "stale-quote")) {
            try append(ctx, bundle, "production-attestation.quote", "unbound quote bytes\n");
            rebind = false;
        } else if (hw.eq(name, "invalid-quote")) {
            try replace(ctx, bundle, "production-attestation.quote", "role=production", "role=verification");
            try rewriteSignature(ctx, bundle, "production");
        } else if (hw.eq(name, "invalid-signature")) try replace(ctx, bundle, "verification-attestation.sig", "quote_sha256=", "quote_sha256=f") else if (hw.eq(name, "missing-quote")) {
            try ctx.removeFile(try hw.join(ctx, bundle, "verification-attestation.quote"));
            rebind = false;
        } else if (hw.eq(name, "checkpoint-error")) try replace(ctx, bundle, "production-serial.log", "error=none", "error=write_failed") else if (hw.eq(name, "checkpoint-after-ready")) {
            const path = try hw.join(ctx, bundle, "production-serial.log");
            const text = try ctx.read(path);
            var next = std.ArrayList(u8).empty;
            var ck: []const u8 = "";
            var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, text, "\n"), '\n');
            while (lines.next()) |l| if (std.mem.startsWith(u8, l, "ZIGOS:STORAGE:CHECKPOINT:FINAL")) {
                ck = l;
            } else try next.appendSlice(ctx.allocator, try ctx.fmt("{s}\n", .{l}));
            try next.appendSlice(ctx.allocator, try ctx.fmt("{s}\n", .{ck}));
            try ctx.write(path, next.items);
        } else if (hw.eq(name, "disabled-secure-boot")) try replace(ctx, bundle, "firmware-settings.txt", "secure_boot=enabled", "secure_boot=disabled") else if (hw.eq(name, "unverified-boot-image")) try replace(ctx, bundle, "production-serial.log", "BOOT_IMAGE:FIRMWARE_AUTHENTICATED", "BOOT_IMAGE:UNVERIFIED") else if (hw.eq(name, "missing-verification-ready")) try replace(ctx, bundle, "verification-serial.log", "ZIGOS:NATIVE:READY\n", "") else if (hw.eq(name, "device-mismatch")) try replace(ctx, bundle, "device-identity.txt", "device_id=" ++ device, "device_id=nuc15crsu7-different-device") else if (hw.eq(name, "legacy-digest-entry")) try append(ctx, bundle, "artifact-digests.sha256", "0000000000000000000000000000000000000000000000000000000000000000  spec/release_security/release_keyring.json\n") else if (hw.eq(name, "tampered-release-manifest")) {
            try append(ctx, root, "build/release-security/release-manifest.dsse.json", "unbound replacement release bytes\n");
            rebind = false;
        } else if (hw.eq(name, "tampered-root-evidence")) {
            try append(ctx, root, "build/release-security/root-metadata.json", "untrusted bundled root bytes\n");
            rebind = false;
        } else if (hw.eq(name, "artifact-hash")) {
            try append(ctx, root, "build/os.iso", "changed production ISO\n");
            rebind = false;
        } else if (hw.eq(name, "symlink-evidence")) {
            const path = try hw.join(ctx, bundle, "firmware-settings.txt");
            const copy = try hw.join(ctx, absolute, "linked-firmware");
            try ctx.copy(path, copy);
            try ctx.removeFile(path);
            try std.Io.Dir.cwd().symLink(ctx.io, copy, path, .{});
            rebind = false;
        } else if (hw.eq(name, "symlink-cycle-directory")) {
            const original = try hw.join(ctx, bundle, "cycles");
            const renamed = try hw.join(ctx, absolute, "linked-cycles");
            try std.Io.Dir.cwd().rename(original, std.Io.Dir.cwd(), renamed, ctx.io);
            try std.Io.Dir.cwd().symLink(ctx.io, renamed, original, .{ .is_directory = true });
        } else if (hw.eq(name, "unlisted-cycle")) try write(ctx, bundle, "cycles/extra.log", "unlisted physical evidence\n") else if (hw.eq(name, "duplicate-key")) try append(ctx, bundle, "proof-manifest.txt", "device_id=" ++ device ++ "\n") else if (hw.eq(name, "noncanonical-contract")) {
            try append(ctx, root, hw.production_contract, " noncanonical marker\n");
        } else if (hw.eq(name, "duplicate-contract")) {
            try append(ctx, root, hw.production_contract, "BOOT:START\n");
        } else if (hw.eq(name, "insufficient-cycle")) {
            const path = try hw.join(ctx, bundle, "cycle-manifest.txt");
            const text = try ctx.read(path);
            const end = std.mem.indexOf(u8, text, "cycle=warm_reboot").?;
            const last = std.mem.lastIndexOfScalar(u8, text[0 .. end - 1], '\n').?;
            try ctx.write(path, try ctx.fmt("{s}{s}", .{ text[0 .. last + 1], text[end..] }));
            try ctx.removeFile(try hw.join(ctx, bundle, "cycles/cold_boot-000010.log"));
        } else if (hw.eq(name, "duplicate-cycle-digest")) {
            const path = try hw.join(ctx, bundle, "cycle-manifest.txt");
            const text = try ctx.read(path);
            const h1 = std.mem.indexOfScalar(u8, text, '|').? + 8;
            const h2 = std.mem.indexOfScalarPos(u8, text, h1 + 64, '|').?;
            _ = h2;
            const second = std.mem.indexOf(u8, text, "cycle=cold_boot|000002|").? + "cycle=cold_boot|000002|".len;
            try ctx.write(path, try ctx.fmt("{s}{s}{s}", .{ text[0..second], text[h1 .. h1 + 64], text[second + 64 ..] }));
        } else if (hw.eq(name, "untrusted-verifier-location")) {
            const p = try hw.join(ctx, bundle, "internal-verifier");
            try ctx.copy(verifier, p);
            try std.Io.Dir.cwd().setFilePermissions(ctx.io, p, .fromMode(0o700), .{});
            opts.verifier = p;
        } else if (hw.eq(name, "untrusted-root-location")) opts.trust_root = try hw.join(ctx, root, "build/release-security/root-metadata.json") else if (hw.eq(name, "internal-trust-state")) opts.trust_state = try hw.join(ctx, bundle, "trust-state.json") else if (hw.eq(name, "wrong-release-verifier-digest")) opts.release_verifier_digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" else if (hw.eq(name, "wrong-root-digest")) opts.trust_root_digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        if (rebind) hw.writeStatement(ctx, bundle, root) catch |err| {
            if (!hw.eq(name, "duplicate-key")) return err;
        };
        try expectFail(ctx, bundle, opts, name);
        if (hw.eq(name, "tampered-release-manifest")) try write(ctx, root, "build/release-security/release-manifest.dsse.json", "authenticated exact release manifest fixture\n");
        if (hw.eq(name, "tampered-root-evidence")) try write(ctx, root, "build/release-security/root-metadata.json", root_data);
        if (hw.eq(name, "artifact-hash")) try write(ctx, root, "build/os.iso", "hardware checker artifact build/os.iso\n");
        if (hw.eq(name, "noncanonical-contract") or hw.eq(name, "duplicate-contract")) try write(ctx, root, hw.production_contract, try ctx.read(hw.production_contract));
    }
    try ctx.print("RNUC15CRSU7 hardware proof checker self-test: PASS ({d} negative cases; compiler argv/epoch fixtures)\n", .{cases.len + 2});
}
