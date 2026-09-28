//! Disposable verification-only ownership enrollment. These public administrator
//! fixtures are never linked into production or used by production provisioning.
const std = @import("std");
const tpm = @import("../../platform/tpm2_sealing.zig");
const pin_mod = @import("../../platform/tpm2_pin.zig");
const wire = @import("../../platform/tpm2_wire.zig");
const ids = @import("../../core/ids.zig");
const signing = @import("../../core/signing.zig");
const objects = @import("../../storage/object_store.zig");
const identity_proof = @import("identity_session_proof.zig");
const enrollment = @import("../../services/identity_enrollment.zig");
const recovery = @import("../../services/identity_recovery.zig");
const console = @import("../../../kernel/utils/console.zig");
const x86 = @import("../../../arch/x86.zig");
// These two public fixtures model separately retained transition/recovery keys.
// Final owner, lockout and vault authorizations are random and disk-encrypted.
const transition_owner: tpm.Key = @splat(0xb5);
const recovery_key: tpm.Key = @splat(0xb8);
const pin = "93058271";
const object_id = 0x706_0001;
const parent_handle = 0x8100_7060;
const content_type = "application/x-zigos-tpm-owner-proof";
const label = "TPM owner enrollment proof";
const signer = signing.SignerIdentity{ .label = "owner-proof-enrollment", .seed = @splat(0xa6) };
const MAX_BYTES = 8 + 1 + 32 + 2 + enrollment.MAX_BYTES + recovery.PACKAGE_BYTES;
const Record = struct {
    enrolled: bool = false,
    identity: enrollment.Record,
    package: recovery.Package,

    fn encode(self: *const Record, out: *[MAX_BYTES]u8) ![]const u8 {
        var w = wire.Writer{ .bytes = out };
        try w.put("ZGOwner2");
        try w.int(u8, @intFromBool(self.enrolled));
        try w.put(&(try self.identity.digest()));
        var bytes: [enrollment.MAX_BYTES]u8 = undefined;
        try w.sized(try self.identity.encode(&bytes));
        try w.put(&self.package.bytes);
        return out[0..w.pos];
    }

    fn decode(bytes: []const u8) !Record {
        var r = wire.Reader{ .bytes = bytes };
        if (!std.mem.eql(u8, try r.take(8), "ZGOwner2")) return error.InvalidOwnerProof;
        const enrolled = try r.int(u8);
        if (enrolled > 1) return error.InvalidOwnerProof;
        const digest = (try r.take(32))[0..32].*;
        // The caller has authenticated this whole record with its independent
        // fixture signer before accepting the embedded enrollment digest.
        const identity = try enrollment.Record.decode(try r.sized(), &digest);
        const package = (try r.take(recovery.PACKAGE_BYTES))[0..recovery.PACKAGE_BYTES].*;
        try r.end();
        if (identity.enrollment.parent.handle != parent_handle or identity.capsule.owner.serial != 0x706 or identity.capsule.device.serial != 0x707) return error.InvalidOwnerProof;
        return .{ .enrolled = enrolled != 0, .identity = identity, .package = .{ .bytes = package } };
    }
};

fn save(storage: anytype, record: *const Record) !void {
    var bytes: [MAX_BYTES]u8 = undefined;
    const payload = try record.encode(&bytes);
    const previous = if (storage.latestVersion(object_id)) |version| version.id else null;
    _ = try storage.putVersion(.{ .preferred_object_id = ids.object(object_id), .object_type = .secret, .payload = payload, .metadata = try objects.signMetadata(signer, label, content_type, .secret, payload, 1), .parent_version_id = previous });
    _ = try storage.checkpointDurable();
}

fn halt(marker: []const u8) noreturn {
    x86.cli();
    console.print(marker);
    while (true) x86.hlt();
}

fn requireAuthorizationRejection(client: *const tpm.Client, err: anyerror) !void {
    if (err != error.TpmError or (client.last_tpm_error != 0x98e and client.last_tpm_error != 0x9a2)) return err;
}

pub fn run(manager: anytype, io: anytype) !void {
    io.known_pin = pin;
    defer io.protected_authorizations = &.{};
    defer io.known_pin = null;
    defer io.known_key = null;
    var client = tpm.Client{};
    defer client.close(io) catch {};
    const storage = manager.storageServicePtr();
    var key: tpm.Key = @splat(0);
    defer std.crypto.secureZero(u8, &key);
    var secrets = recovery.Secrets{};
    defer secrets.wipe();
    var admin: [4]tpm.Key = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&admin));
    var record: Record = undefined;
    if (storage.latestVersion(object_id)) |version| {
        var bytes: [MAX_BYTES]u8 = undefined;
        const payload = try storage.versionPayloadInto(version, &bytes);
        if (version.object_type != .secret or !std.mem.eql(u8, version.metadata.contentTypeSlice(), content_type) or
            !version.metadata.verifyFor(.secret, payload) or !std.mem.eql(u8, version.metadata.signature.publicKeySlice(), &(try signing.publicKey(signer)))) return error.UntrustedOwnerProof;
        record = try Record.decode(payload);
        try recovery.Package.open(&record.package.bytes, &(try record.identity.digest()), &recovery_key, &secrets);
        admin = .{ transition_owner, secrets.owner, secrets.lockout, recovery_key };
        io.protected_authorizations = &admin;
    } else {
        try client.createEnrollmentParent(io);
        try recovery.Secrets.generate(io, &secrets);
        admin = .{ transition_owner, secrets.owner, secrets.lockout, recovery_key };
        io.protected_authorizations = &admin;
        key = secrets.vault;
        io.known_key = &key;
        const capsule = try pin_mod.Capsule.enroll(&client, io, .{ .kind = .user, .serial = 0x706 }, .{ .kind = .device, .serial = 0x707 }, pin, &key);
        record = .{ .identity = .{ .capsule = capsule, .enrollment = identity_proof.enrollmentFor(&capsule, try capsule.digest(), .{ .handle = parent_handle, .name = client.parent_name }) }, .package = .{} };
        try recovery.Package.seal(&record.identity, &secrets, &recovery_key, io, &record.package);
        // The independent fixture enrollment record reaches disk before the
        // permanent object does. Simulate losing an accepted persistence reply.
        try save(storage, &record);
        io.corrupt_persistence = true;
        if (client.persistParent(io, record.identity.enrollment.parent, null)) |_| return error.AcceptedCorruptPersistenceReply else |err| {
            if (err != error.IntegrityFailure or !client.failed or io.persist_commands != 1) return error.BadPersistenceFailure;
        }
        io.corrupt_persistence = false;
        try client.close(io);
        halt("ZIGOS:TPM2:OWNER:INTERRUPTED\n");
    }

    client.openPersistent(io, record.identity.enrollment.parent) catch |err| {
        if (err != error.PersistentParentMissing) return err;
        if (io.owner_commands != 0 or !std.mem.allEqual(u8, &key, 0)) return error.ReprovisionedMissingParent;
        console.print("ZIGOS:TPM2:OWNER:REPLACEMENT_REJECTED\n");
        return;
    };
    // Reject a response with a valid public Name but invalid possession HMAC.
    var tampered = tpm.Client{};
    defer tampered.close(io) catch {};
    io.corrupt_parent_public = true;
    if (tampered.openPersistent(io, record.identity.enrollment.parent)) |_| return error.AcceptedUnauthenticatedParent else |err| {
        if (err != error.IntegrityFailure or tampered.parent != 0) return error.BadParentAuthenticationFailure;
    }
    io.corrupt_parent_public = false;
    try record.identity.capsule.unlock(&client, io, &record.identity.enrollment.capsule_digest, pin, &key);
    if (!std.crypto.timing_safe.eql(tpm.Key, key, secrets.vault)) return error.RecoveredWrongVaultAuthorization;
    io.known_key = &key;

    if (!record.enrolled) {
        // Reconcile the accepted persistence without another EvictControl.
        var bootstrap = tpm.Client{};
        defer bootstrap.close(io) catch {};
        try bootstrap.createEnrollmentParent(io);
        try bootstrap.persistParent(io, record.identity.enrollment.parent, null);
        if (io.persist_commands != 0) return error.RepeatedParentPersistence;
        try bootstrap.close(io);

        // Retained administrator fixtures model external recovery custody.
        // A damaged change-auth reply is reconciled with the NEW authorization.
        io.corrupt_lockout_change = true;
        if (client.changeOwnerAuthorization(io, null, &admin[0])) |_| return error.AcceptedCorruptOwnerReply else |err| {
            if (err != error.IntegrityFailure or !client.failed) return error.BadOwnerChangeFailure;
        }
        io.corrupt_lockout_change = false;
        try client.close(io);
        client = .{};
        try client.openPersistent(io, record.identity.enrollment.parent);
        try client.changeOwnerAuthorization(io, &admin[0], &admin[1]);
        try client.changeLockoutAuthorization(io, null, &admin[2]);
        try client.configureDictionaryAttack(io, &admin[2], pin_mod.DEFAULT_POLICY);
        const space = tpm.NvSpace{ .index = 0x0180_7060, .size = 32 };
        if (client.nvDefine(io, space, &key, null)) |_| return error.EmptyOwnerDefinedIndex else |err| try requireAuthorizationRejection(&client, err);
        try client.nvDefine(io, space, &key, &admin[1]);
        const value: [32]u8 = @splat(0x47);
        try client.nvWrite(io, space, &key, &value);
        var actual: [32]u8 = undefined;
        try client.nvRead(io, space, &key, &actual);
        if (!std.mem.eql(u8, &value, &actual)) return error.OwnerProtectedNvMismatch;
        var empty_owner = tpm.Client{};
        defer empty_owner.close(io) catch {};
        if (empty_owner.createEnrollmentParent(io)) |_| return error.EmptyOwnerCreatedParent else |err| try requireAuthorizationRejection(&empty_owner, err);
        try identity_proof.provision(manager, io, &client, &record.identity.capsule, &key, &admin[1]);
        try identity_proof.run(manager, io, &record.identity.capsule, &record.identity.enrollment.capsule_digest, pin, null, record.identity.enrollment.parent);
        record.enrolled = true;
        try save(storage, &record);
        try client.close(io);
        halt("ZIGOS:TPM2:OWNER:ENROLLED\n");
    }

    const before = io.owner_commands;
    try identity_proof.run(manager, io, &record.identity.capsule, &record.identity.enrollment.capsule_digest, pin, null, record.identity.enrollment.parent);
    if (before != 0 or io.owner_commands != 0) return error.IdentityRequestedOwnerAuthorization;
    // Exhaust the real TPM policy, then recover with the encrypted package
    // loaded from the previous boot, without knowing the PIN in that path.
    var denied: tpm.Key = @splat(0);
    defer std.crypto.secureZero(u8, &denied);
    for (0..pin_mod.DEFAULT_POLICY.max_tries) |_| {
        if (record.identity.capsule.unlock(&client, io, &record.identity.enrollment.capsule_digest, "93058279", &denied)) |_| return error.AcceptedWrongPin else |err| {
            if (err != error.PinRejected or !std.mem.allEqual(u8, &denied, 0)) return error.InvalidRecoveryLockout;
        }
    }
    if (record.identity.capsule.unlock(&client, io, &record.identity.enrollment.capsule_digest, pin, &denied)) |_| return error.MissingRecoveryLockout else |err| {
        if (err != error.PinLockedOut or !std.mem.allEqual(u8, &denied, 0)) return error.InvalidRecoveryLockout;
    }
    try identity_proof.runRecovery(manager, io, &record.identity, &record.package, &recovery_key);
    try record.identity.capsule.unlock(&client, io, &record.identity.enrollment.capsule_digest, pin, &denied);
    if (!std.crypto.timing_safe.eql(tpm.Key, denied, secrets.vault)) return error.RecoveryDidNotRestorePin;
    try client.close(io);
    client = .{};
    try client.openPersistent(io, record.identity.enrollment.parent);
    console.print("ZIGOS:TPM2:OWNER:VERIFIED\n");
}
