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
const console = @import("../../../kernel/utils/console.zig");
const x86 = @import("../../../arch/x86.zig");
const admin = [_]tpm.Key{ @splat(0xb5), @splat(0xb6), @splat(0xb7) };
const pin = "93058271";
const object_id = 0x706_0001;
const parent_handle = 0x8100_7060;
const content_type = "application/x-zigos-tpm-owner-proof";
const label = "TPM owner enrollment proof";
const signer = signing.SignerIdentity{ .label = "owner-proof-enrollment", .seed = @splat(0xa6) };
const MAX_BYTES = 8 + 1 + 4 + 34 + 32 + 2 + pin_mod.MAX_BYTES;
const Record = struct {
    enrolled: bool = false,
    parent: tpm.PersistentParent,
    digest: tpm.Key,
    capsule: pin_mod.Capsule,

    fn encode(self: *const Record, out: *[MAX_BYTES]u8) ![]const u8 {
        var w = wire.Writer{ .bytes = out };
        try w.put("ZGOwner1");
        try w.int(u8, @intFromBool(self.enrolled));
        try w.int(u32, self.parent.handle);
        try w.put(&self.parent.name);
        try w.put(&self.digest);
        var capsule: [pin_mod.MAX_BYTES]u8 = undefined;
        try w.sized(try self.capsule.encode(&capsule));
        return out[0..w.pos];
    }

    fn decode(bytes: []const u8) !Record {
        var r = wire.Reader{ .bytes = bytes };
        if (!std.mem.eql(u8, try r.take(8), "ZGOwner1")) return error.InvalidOwnerProof;
        const enrolled = try r.int(u8);
        if (enrolled > 1) return error.InvalidOwnerProof;
        const handle = try r.int(u32);
        const name = (try r.take(34))[0..34].*;
        const digest = (try r.take(32))[0..32].*;
        const capsule = try pin_mod.Capsule.decode(try r.sized(), &digest);
        try r.end();
        const record = Record{ .enrolled = enrolled != 0, .parent = .{ .handle = handle, .name = name }, .digest = digest, .capsule = capsule };
        try record.parent.validate();
        if (handle != parent_handle or capsule.owner.serial != 0x706 or capsule.device.serial != 0x707) return error.InvalidOwnerProof;
        return record;
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
    io.protected_authorizations = &admin;
    io.known_pin = pin;
    defer io.protected_authorizations = &.{};
    defer io.known_pin = null;
    defer io.known_key = null;
    var client = tpm.Client{};
    defer client.close(io) catch {};
    const storage = manager.storageServicePtr();
    var key: tpm.Key = @splat(0);
    defer std.crypto.secureZero(u8, &key);
    var record: Record = undefined;
    if (storage.latestVersion(object_id)) |version| {
        var bytes: [MAX_BYTES]u8 = undefined;
        const payload = try storage.versionPayloadInto(version, &bytes);
        if (version.object_type != .secret or !std.mem.eql(u8, version.metadata.contentTypeSlice(), content_type) or
            !version.metadata.verifyFor(.secret, payload) or !std.mem.eql(u8, version.metadata.signature.publicKeySlice(), &(try signing.publicKey(signer)))) return error.UntrustedOwnerProof;
        record = try Record.decode(payload);
    } else {
        try client.createEnrollmentParent(io);
        try io.random(&key);
        io.known_key = &key;
        record = .{
            .parent = .{ .handle = parent_handle, .name = client.parent_name },
            .digest = undefined,
            .capsule = try pin_mod.Capsule.enroll(&client, io, .{ .kind = .user, .serial = 0x706 }, .{ .kind = .device, .serial = 0x707 }, pin, &key),
        };
        record.digest = try record.capsule.digest();
        // The independent fixture enrollment record reaches disk before the
        // permanent object does. Simulate losing an accepted persistence reply.
        try save(storage, &record);
        io.corrupt_persistence = true;
        if (client.persistParent(io, record.parent, null)) |_| return error.AcceptedCorruptPersistenceReply else |err| {
            if (err != error.IntegrityFailure or !client.failed or io.persist_commands != 1) return error.BadPersistenceFailure;
        }
        io.corrupt_persistence = false;
        try client.close(io);
        halt("ZIGOS:TPM2:OWNER:INTERRUPTED\n");
    }

    client.openPersistent(io, record.parent) catch |err| {
        if (err != error.PersistentParentMissing) return err;
        if (io.owner_commands != 0 or !std.mem.allEqual(u8, &key, 0)) return error.ReprovisionedMissingParent;
        console.print("ZIGOS:TPM2:OWNER:REPLACEMENT_REJECTED\n");
        return;
    };
    // Reject a response with a valid public Name but invalid possession HMAC.
    var tampered = tpm.Client{};
    defer tampered.close(io) catch {};
    io.corrupt_parent_public = true;
    if (tampered.openPersistent(io, record.parent)) |_| return error.AcceptedUnauthenticatedParent else |err| {
        if (err != error.IntegrityFailure or tampered.parent != 0) return error.BadParentAuthenticationFailure;
    }
    io.corrupt_parent_public = false;
    try record.capsule.unlock(&client, io, &record.digest, pin, &key);
    io.known_key = &key;

    if (!record.enrolled) {
        // Reconcile the accepted persistence without another EvictControl.
        var bootstrap = tpm.Client{};
        defer bootstrap.close(io) catch {};
        try bootstrap.createEnrollmentParent(io);
        try bootstrap.persistParent(io, record.parent, null);
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
        try client.openPersistent(io, record.parent);
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
        try identity_proof.provision(manager, io, &client, &record.capsule, &key, &admin[1]);
        try identity_proof.run(manager, io, &record.capsule, &record.digest, pin, null, record.parent);
        record.enrolled = true;
        try save(storage, &record);
        try client.close(io);
        halt("ZIGOS:TPM2:OWNER:ENROLLED\n");
    }

    const before = io.owner_commands;
    try identity_proof.run(manager, io, &record.capsule, &record.digest, pin, null, record.parent);
    if (before != 0 or io.owner_commands != 0) return error.IdentityRequestedOwnerAuthorization;
    try client.close(io);
    client = .{};
    try client.openPersistent(io, record.parent);
    console.print("ZIGOS:TPM2:OWNER:VERIFIED\n");
}
