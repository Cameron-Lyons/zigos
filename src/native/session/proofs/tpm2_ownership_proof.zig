//! Verification-only custody of a provisioning pin and random-key recovery.
//! The fixed signer and recovery key below model an independent trusted channel;
//! production provisioning generates every owner, lockout and identity secret.
const std = @import("std");
const tpm = @import("../../platform/tpm2_sealing.zig");
const pin_mod = @import("../../platform/tpm2_pin.zig");
const wire = @import("../../platform/tpm2_wire.zig");
const ids = @import("../../core/ids.zig");
const signing = @import("../../core/signing.zig");
const objects = @import("../../storage/object_store.zig");
const catalog = @import("../../storage/vault_catalog.zig");
const provisioning = @import("../../services/identity_provisioning.zig");
const setup_proof = @import("identity_setup_proof.zig");
const recovery_record = @import("../../services/identity_recovery_record.zig");
const identity_proof = @import("identity_session_proof.zig");
const recovery = @import("../../services/identity_recovery.zig");
const console = @import("../../../kernel/utils/console.zig");
const x86 = @import("../../../arch/x86.zig");
const custody_key: tpm.Key = @splat(0xb8);
const pin = "93058271";
const object_id = 0x706_0001;
const parent_handle = 0x8100_7060;
const content_type = "application/x-zigos-tpm-owner-proof";
const signer = signing.SignerIdentity{ .label = "owner-proof-enrollment", .seed = @splat(0xa6) };
const Stage = enum(u8) { persistence, owner, lockout, parameters, definition, write, boot_definition, boot_write, boot_lock, finish, enrolled };
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const request = provisioning.Request{ .owner = .{ .kind = .user, .serial = 0x706 }, .device = .{ .kind = .device, .serial = 0x707 }, .record_object_id = object_id + 1, .catalog_object_id = 0x704_0001, .parent_handle = parent_handle, .anchor_index = 0x0180_7041, .boot_index = 0x0180_7042, .max_session_ticks = 1000 };
const Record = struct {
    stage: Stage = .persistence,
    ciphertext: [recovery_record.CODE_BYTES]u8,
    nonce: [Aead.nonce_length]u8,
    tag: [Aead.tag_length]u8,
    const BYTES = 8 + 1 + recovery_record.CODE_BYTES + Aead.nonce_length + Aead.tag_length;

    fn encode(self: Record) ![BYTES]u8 {
        var bytes: [BYTES]u8 = undefined;
        var w = wire.Writer{ .bytes = &bytes };
        try w.put("ZGOwner4");
        try w.int(u8, @intFromEnum(self.stage));
        try w.put(&self.nonce);
        try w.put(&self.ciphertext);
        try w.put(&self.tag);
        return bytes;
    }

    fn decode(bytes: []const u8) !Record {
        var r = wire.Reader{ .bytes = bytes };
        if (!std.mem.eql(u8, try r.take(8), "ZGOwner4")) return error.InvalidOwnerProof;
        const stage = std.enums.fromInt(Stage, try r.int(u8)) orelse return error.InvalidOwnerProof;
        const nonce = (try r.take(Aead.nonce_length))[0..Aead.nonce_length].*;
        const ciphertext = (try r.take(recovery_record.CODE_BYTES))[0..recovery_record.CODE_BYTES].*;
        const tag = (try r.take(Aead.tag_length))[0..Aead.tag_length].*;
        try r.end();
        return .{ .stage = stage, .nonce = nonce, .ciphertext = ciphertext, .tag = tag };
    }

    fn open(self: *const Record, out: *recovery_record.Record) !void {
        out.erase();
        var code: [recovery_record.CODE_BYTES]u8 = undefined;
        defer std.crypto.secureZero(u8, &code);
        try Aead.decrypt(&code, &self.ciphertext, self.tag, "ZGOwner4", self.nonce, custody_key);
        try recovery_record.Record.decode(&code, out);
    }
};

fn Exporter(comptime Io: type) type {
    return struct {
        io: *Io,
        storage: *@import("../../storage/storage_service.zig").Service,
        record: *Record,
        pub fn capture(self: @This(), retained: *const recovery_record.Record) !void {
            var code: [recovery_record.CODE_BYTES]u8 = undefined;
            defer std.crypto.secureZero(u8, &code);
            try retained.encode(&code);
            self.record.* = .{ .ciphertext = undefined, .nonce = undefined, .tag = undefined };
            try self.io.random(&self.record.nonce);
            Aead.encrypt(&self.record.ciphertext, &self.record.tag, &code, "ZGOwner4", self.record.nonce, custody_key);
            try save(self.storage, self.record.*);
        }
    };
}

fn save(storage: anytype, record: Record) !void {
    const payload = try record.encode();
    const previous = if (storage.latestVersion(object_id)) |version| version.id else null;
    _ = try storage.putVersion(.{ .preferred_object_id = ids.object(object_id), .object_type = .secret, .payload = &payload, .metadata = try objects.signMetadata(signer, "TPM provisioning proof pin", content_type, .secret, &payload, 1), .parent_version_id = previous });
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
    const storage = manager.storageServicePtr();
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var record: Record = undefined;
    if (storage.latestVersion(object_id)) |version| {
        var bytes: [Record.BYTES]u8 = undefined;
        const payload = try storage.versionPayloadInto(version, &bytes);
        if (!version.metadata.verifyFor(.secret, payload) or !std.mem.eql(u8, version.metadata.signature.publicKeySlice(), &(try signing.publicKey(signer)))) return error.UntrustedOwnerProof;
        record = try Record.decode(payload);
    } else {
        io.corrupt_persistence = true;
        _ = try setup_proof.run(manager, io, request, pin, null, Exporter(@TypeOf(io.*)){ .io = io, .storage = storage, .record = &record }, &scratch, error.IntegrityFailure);
        if (io.persist_commands != 1 or io.da_resets != 0) return error.InvalidSetupPersistence;
        record.stage = .owner;
        try save(storage, record);
        halt("ZIGOS:TPM2:OWNER:INTERRUPTED\n");
    }
    var retained = recovery_record.Record{};
    defer retained.erase();
    try record.open(&retained);
    var bundle = try provisioning.load(storage, retained.trusted);
    const identity = &bundle.identity;
    var secrets = recovery.Secrets{};
    defer secrets.wipe();
    try recovery.Package.open(&bundle.package.bytes, &(try identity.digest()), &retained.key, &secrets);
    var admin = [_]tpm.Key{ secrets.owner, secrets.lockout, secrets.vault, retained.key };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&admin));
    io.protected_authorizations = &admin;
    var client = tpm.Client{};
    defer client.close(io) catch {};
    if (record.stage != .persistence) {
        client.openPersistent(io, identity.enrollment.parent) catch |err| {
            if (err != error.PersistentParentMissing or io.owner_commands != 0) return err;
            if (provisioning.loadBoot(io, storage, request.boot_index)) |_| return error.ReplacedBootEnrollment else |failure| {
                if (failure != error.NvIndexMissing or io.owner_commands != 0) return error.UnsafeBootEnrollmentReplacement;
            }
            if (record.stage == .enrolled) {
                console.print("ZIGOS:TPM2:OWNER:REPLACEMENT_REJECTED\n");
            } else {
                if (provisioning.commit(io, storage, retained.trusted, &retained.key, &scratch)) |_| return error.ReprovisionedReplacementTpm else |failure| {
                    if (failure != error.PersistentParentChanged or io.persist_commands != 0 or io.owner_commands != 1) return failure;
                }
                console.print("ZIGOS:TPM2:OWNER:SETUP_REPLACEMENT_REJECTED\n");
            }
            return;
        };
        try client.close(io);
    }

    if (record.stage != .enrolled) {
        if (record.stage != .finish) {
            if (provisioning.loadBoot(io, storage, request.boot_index)) |_| return error.PublishedIncompleteBootEnrollment else |err| {
                const expected = if (record.stage == .boot_write or record.stage == .boot_lock) error.BootPinIncomplete else error.NvIndexMissing;
                if (err != expected) return err;
            }
        }
        // Reject a forged hierarchy state before an administrator command.
        if (record.stage == .owner) {
            const before = io.owner_commands;
            io.corrupt_hierarchy_state = true;
            if (provisioning.commit(io, storage, retained.trusted, &retained.key, &scratch)) |_| return error.AcceptedForgedHierarchyState else |err| {
                if (err != error.IntegrityFailure or io.owner_commands != before) return error.UnsafeHierarchyFailure;
            }
            io.corrupt_hierarchy_state = false;
        }
        switch (record.stage) {
            .persistence => io.corrupt_persistence = true,
            .owner => io.corrupt_hierarchy_auth = 0x4000_0001,
            .lockout => io.corrupt_hierarchy_auth = 0x4000_000a,
            .parameters => io.corrupt_da_parameters = true,
            .definition => io.corrupt_nv_define = true,
            .write, .boot_write => io.corrupt_nv_write = true,
            .boot_definition => io.corrupt_nv_define = true,
            .boot_lock => io.corrupt_nv_write_lock = true,
            .finish => {},
            .enrolled => unreachable,
        }
        if (record.stage != .finish) {
            _ = try setup_proof.run(manager, io, request, pin, &retained, setup_proof.NoExport{}, &scratch, error.IntegrityFailure);
            if (io.da_resets != 0 or (record.stage != .persistence and io.persist_commands != 0)) return error.RepeatedProvisioningMutation;
            const expected_writes: usize = if (record.stage == .write or record.stage == .boot_write) 1 else 0;
            const expected_locks: usize = if (record.stage == .boot_lock) 1 else 0;
            if (io.nv_writes != expected_writes or io.nv_write_locks != expected_locks) return error.RepeatedEnrollmentNvMutation;
            const marker = switch (record.stage) {
                .persistence => "ZIGOS:TPM2:OWNER:INTERRUPTED\n",
                .owner => "ZIGOS:TPM2:OWNER:OWNER_INTERRUPTED\n",
                .lockout => "ZIGOS:TPM2:OWNER:LOCKOUT_INTERRUPTED\n",
                .parameters => "ZIGOS:TPM2:OWNER:POLICY_INTERRUPTED\n",
                .definition => "ZIGOS:TPM2:OWNER:DEFINE_INTERRUPTED\n",
                .write => "ZIGOS:TPM2:OWNER:WRITE_INTERRUPTED\n",
                .boot_definition => "ZIGOS:TPM2:OWNER:BOOT_DEFINE_INTERRUPTED\n",
                .boot_write => "ZIGOS:TPM2:OWNER:BOOT_WRITE_INTERRUPTED\n",
                .boot_lock => "ZIGOS:TPM2:OWNER:BOOT_LOCK_INTERRUPTED\n",
                else => unreachable,
            };
            record.stage = @enumFromInt(@intFromEnum(record.stage) + 1);
            try save(storage, record);
            halt(marker);
        }
        const completed = (try setup_proof.run(manager, io, request, pin, &retained, setup_proof.NoExport{}, &scratch, null)) orelse return error.MissingSetupIdentity;
        if (!std.mem.eql(u8, &(try completed.digest()), &(try identity.digest())) or io.persist_commands != 0 or io.nv_writes != 0 or io.nv_write_locks != 0 or io.da_resets != 0) return error.RepeatedCompletedEnrollment;
        const boot_enrollment = try provisioning.loadBoot(io, storage, request.boot_index);
        if (!std.meta.eql(boot_enrollment.trusted, retained.trusted)) return error.BootEnrollmentChanged;
        try client.openPersistent(io, identity.enrollment.parent);
        var changed_pin = retained.trusted;
        changed_pin.digest[0] ^= 1;
        if (client.checkBootPinEnrollment(io, request.boot_index, changed_pin)) |_| return error.AcceptedBootPinConflict else |err| {
            if (err != error.BootPinChanged) return err;
        }
        if (client.enrollBootPin(io, request.boot_index, changed_pin, &secrets.owner)) |_| return error.ReplacedBootPin else |err| {
            if (err != error.BootPinChanged or io.nv_writes != 0 or io.nv_write_locks != 0) return error.UnsafeBootPinReplacement;
        }
        const hierarchy = try client.hierarchyState(io);
        if (!hierarchy.owner_auth_set or !hierarchy.lockout_auth_set or hierarchy.in_lockout) return error.UnprotectedEnrolledHierarchy;
        const space = tpm.NvSpace{ .index = 0x0180_7060, .size = 32 };
        if (client.nvDefine(io, space, &secrets.vault, null)) |_| return error.EmptyOwnerDefinedIndex else |err| try requireAuthorizationRejection(&client, err);
        try client.nvDefine(io, space, &secrets.vault, &secrets.owner);
        var empty_owner = tpm.Client{};
        defer empty_owner.close(io) catch {};
        if (empty_owner.createEnrollmentParent(io)) |_| return error.EmptyOwnerCreatedParent else |err| try requireAuthorizationRejection(&empty_owner, err);
        try identity_proof.addProofCredential(manager, io, identity, pin);
        try identity_proof.run(manager, io, &identity.capsule, &identity.enrollment.capsule_digest, pin, null, identity.enrollment.parent);
        record.stage = .enrolled;
        try save(storage, record);
        try client.close(io);
        halt("ZIGOS:TPM2:OWNER:ENROLLED\n");
    }

    // Ordinary boot obtains its authority from locked TPM state, independently
    // of the fixture's externally retained recovery record.
    io.corrupt_boot_pin_read = true;
    if (provisioning.loadBoot(io, storage, request.boot_index)) |_| return error.AcceptedUnauthenticatedBootPin else |err| {
        if (err != error.IntegrityFailure) return err;
    }
    io.corrupt_boot_pin_read = false;
    io.spoof_unwritten_once = true;
    if (provisioning.loadBoot(io, storage, request.boot_index)) |_| return error.AcceptedUnwrittenBootPin else |err| {
        if (err != error.BootPinIncomplete or io.spoof_unwritten_once) return error.InvalidBootPinStateFailure;
    }
    const disk_record = storage.store.latestVersion(retained.trusted.object_id).?;
    disk_record.metadata.signature.value[0] ^= 1;
    const damaged = provisioning.loadBoot(io, storage, request.boot_index);
    disk_record.metadata.signature.value[0] ^= 1;
    if (damaged) |_| return error.AcceptedUntrustedBootBundle else |err| {
        if (err != error.UntrustedProvisioningBundle) return err;
    }
    const boot_enrollment = try provisioning.loadBoot(io, storage, request.boot_index);
    if (!std.meta.eql(boot_enrollment.trusted, retained.trusted)) return error.BootEnrollmentChanged;
    bundle = boot_enrollment.bundle;
    if (io.owner_commands != 0 or io.nv_writes != 0 or io.nv_write_locks != 0 or io.da_resets != 0) return error.BootEnrollmentRequestedAdministration;
    console.print("ZIGOS:TPM2:BOOT_ENROLLMENT:VERIFIED\n");
    try setup_proof.runBoot(manager, io, request, pin, retained.trusted);
    try client.openPersistent(io, identity.enrollment.parent);
    var tampered = tpm.Client{};
    defer tampered.close(io) catch {};
    io.corrupt_parent_public = true;
    if (tampered.openPersistent(io, identity.enrollment.parent)) |_| return error.AcceptedUnauthenticatedParent else |err| {
        if (err != error.IntegrityFailure or tampered.parent != 0) return error.BadParentAuthenticationFailure;
    }
    io.corrupt_parent_public = false;
    try identity_proof.run(manager, io, &identity.capsule, &identity.enrollment.capsule_digest, pin, null, identity.enrollment.parent);
    if (io.owner_commands != 0) return error.IdentityRequestedOwnerAuthorization;
    var denied: tpm.Key = @splat(0);
    defer std.crypto.secureZero(u8, &denied);
    for (0..pin_mod.DEFAULT_POLICY.max_tries) |_| {
        if (identity.capsule.unlock(&client, io, &identity.enrollment.capsule_digest, "93058279", &denied)) |_| return error.AcceptedWrongPin else |err| {
            if (err != error.PinRejected or !std.mem.allEqual(u8, &denied, 0)) return error.InvalidRecoveryLockout;
        }
    }
    if (identity.capsule.unlock(&client, io, &identity.enrollment.capsule_digest, pin, &denied)) |_| return error.MissingRecoveryLockout else |err| {
        if (err != error.PinLockedOut or !std.mem.allEqual(u8, &denied, 0)) return error.InvalidRecoveryLockout;
    }
    const locked_boot = try provisioning.loadBoot(io, storage, request.boot_index);
    if (!std.meta.eql(locked_boot.trusted, retained.trusted) or io.da_resets != 0 or io.owner_commands != 0)
        return error.BootEnrollmentBypassedLockout;
    try identity_proof.runRecovery(manager, io, identity, &bundle.package, &retained);
    try identity.capsule.unlock(&client, io, &identity.enrollment.capsule_digest, pin, &denied);
    if (!std.crypto.timing_safe.eql(tpm.Key, denied, secrets.vault)) return error.RecoveryDidNotRestorePin;
    try client.close(io);
    console.print("ZIGOS:TPM2:OWNER:VERIFIED\n");
}
