const std = @import("std");
const tpm = @import("../../platform/tpm2_sealing.zig");
const pin_mod = @import("../../platform/tpm2_pin.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const objects = @import("../../storage/object_store.zig");
const console = @import("../../../kernel/utils/console.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

// Verification-only recovery authority and independent enrollment signer.
// Production must obtain these through trusted provisioning, never this fixture.
const pin = "73019428";
const admin_keys = [_]tpm.Key{ @splat(0xb3), @splat(0xb4) };
const owner = principal.PrincipalId{ .kind = .user, .serial = 0x704 };
const device = principal.PrincipalId{ .kind = .device, .serial = 0x705 };
const signer = signing.SignerIdentity{ .label = "pin-enrollment-proof", .seed = @splat(0xa5) };
const content_type = "application/x-zigos-tpm-pin-proof";

pub fn run(manager: anytype, io: anytype) !void {
    var client = tpm.Client{};
    defer client.close(io) catch {};
    try client.initialize(io);
    io.known_pin = pin;
    io.protected_authorizations = &admin_keys;
    defer io.known_pin = null;
    defer io.protected_authorizations = &.{};
    defer io.known_key = null;
    const storage = manager.storageServicePtr();
    var matches: [2]objects.ObjectQueryResult = undefined;
    const found = storage.queryObjects(.{ .object_type = .secret, .content_type = content_type }, &matches);
    if (found.len > 1) return error.DuplicatePinEnrollment;
    var key: tpm.Key = @splat(0);
    defer std.crypto.secureZero(u8, &key);
    var capsule: pin_mod.Capsule = undefined;
    var payload: [64 + pin_mod.MAX_BYTES]u8 = undefined;
    var trusted_digest: tpm.Key = undefined;
    var expected_key: tpm.Key = undefined;
    if (found.len == 0) {
        try io.random(&key);
        io.known_key = &key;
        capsule = try pin_mod.Capsule.enroll(&client, io, owner, device, pin, &key);
        trusted_digest = try capsule.digest();
        Sha256.hash(&key, &expected_key, .{});
        @memcpy(payload[0..32], &expected_key);
        @memcpy(payload[32..64], &trusted_digest);
        var bytes: [pin_mod.MAX_BYTES]u8 = undefined;
        const encoded = try capsule.encode(&bytes);
        @memcpy(payload[64..][0..encoded.len], encoded);
        _ = try storage.putLocallySignedVersion(.{ .object_type = .secret, .payload = payload[0 .. 64 + encoded.len], .signer = signer, .label = "TPM PIN enrollment proof", .content_type = content_type, .created_at_ticks = 1 });
        _ = try storage.checkpointDurable();
        // A lost response must not cause an empty-authorization retry. Use the
        // durably retained next secret, then rotate with authenticated old/new
        // request and response values before configuring guessing limits.
        io.corrupt_lockout_change = true;
        if (client.changeLockoutAuthorization(io, null, &admin_keys[0])) |_| return error.AcceptedTamperedLockoutReply else |err| {
            if (err != error.IntegrityFailure or !client.failed) return error.BadLockoutReplyFailure;
        }
        io.corrupt_lockout_change = false;
        client.close(io) catch {};
        client = .{};
        try client.initialize(io);
        try client.changeLockoutAuthorization(io, &admin_keys[0], &admin_keys[1]);
        try client.configureDictionaryAttack(io, &admin_keys[1], .{ .max_tries = 3, .recovery_seconds = 3600, .lockout_recovery_seconds = 86400 });
        var recovered: tpm.Key = @splat(0);
        defer std.crypto.secureZero(u8, &recovered);
        try capsule.unlock(&client, io, &trusted_digest, pin, &recovered);
        if (!std.crypto.timing_safe.eql(tpm.Key, key, recovered)) return error.RecoveredWrongPinKey;
        try @import("identity_session_proof.zig").provision(manager, io, &client, &capsule, &key);
        for (0..3) |_| {
            try @import("identity_session_proof.zig").run(manager, io, &capsule, &trusted_digest, "73019429", error.PinRejected);
        }
        try @import("identity_session_proof.zig").run(manager, io, &capsule, &trusted_digest, pin, error.PinLockedOut);
        const x86 = @import("../../../arch/x86.zig");
        x86.cli();
        console.print("ZIGOS:TPM2:PIN:LOCKED\n");
        while (true) x86.hlt();
    }
    const version = storage.latestVersion(found[0].object_id) orelse return error.MissingPinEnrollment;
    const bytes = try storage.versionPayloadInto(version, &payload);
    if (!version.metadata.verifyFor(.secret, bytes) or !std.mem.eql(u8, version.metadata.signature.publicKeySlice(), &(try signing.publicKey(signer))) or bytes.len < 64)
        return error.UntrustedPinEnrollment;
    expected_key = bytes[0..32].*;
    trusted_digest = bytes[32..64].*;
    capsule = try pin_mod.Capsule.decode(bytes[64..], &trusted_digest);
    if (!capsule.owner.eql(owner) or !capsule.device.eql(device)) return error.WrongPinIdentity;
    var lockout_persisted = false;
    capsule.unlock(&client, io, &trusted_digest, pin, &key) catch |err| {
        if (!std.mem.allEqual(u8, &key, 0)) return error.PinFailureLeakedKey;
        if (err == error.WrongDevice) {
            console.print("ZIGOS:TPM2:PIN:WRONG_DEVICE\n");
            return;
        }
        if (err != error.PinLockedOut) return err;
        lockout_persisted = true;
        // This recovery is an explicit fixture administrator action. Ordinary
        // capsule.unlock never resets guessing counters or lockout settings.
        try client.resetDictionaryAttack(io, &admin_keys[1]);
        try capsule.unlock(&client, io, &trusted_digest, pin, &key);
    };
    io.known_key = &key;
    var actual: tpm.Key = undefined;
    Sha256.hash(&key, &actual, .{});
    if (!std.crypto.timing_safe.eql(tpm.Key, expected_key, actual)) return error.RecoveredWrongPinKey;
    try @import("identity_session_proof.zig").run(manager, io, &capsule, &trusted_digest, pin, null);
    console.print(if (lockout_persisted) "ZIGOS:TPM2:PIN:RECOVERED\n" else "ZIGOS:TPM2:PIN:VERIFIED\n");
}
