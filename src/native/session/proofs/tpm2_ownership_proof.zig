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
const identity_proof = @import("identity_session_proof.zig");
const recovery = @import("../../services/identity_recovery.zig");
const console = @import("../../../kernel/utils/console.zig");
const x86 = @import("../../../arch/x86.zig");
const recovery_key: tpm.Key = @splat(0xb8);
const pin = "93058271";
const object_id = 0x706_0001;
const parent_handle = 0x8100_7060;
const content_type = "application/x-zigos-tpm-owner-proof";
const signer = signing.SignerIdentity{ .label = "owner-proof-enrollment", .seed = @splat(0xa6) };
const Stage = enum(u8) { persistence, owner, lockout, parameters, definition, write, finish, enrolled };
const Record = struct {
    stage: Stage = .persistence,
    trusted: provisioning.Pin,
    const BYTES = 8 + 1 + 8 + 32;

    fn encode(self: Record) ![BYTES]u8 {
        var bytes: [BYTES]u8 = undefined;
        var w = wire.Writer{ .bytes = &bytes };
        try w.put("ZGOwner3");
        try w.int(u8, @intFromEnum(self.stage));
        try w.int(u64, self.trusted.object_id);
        try w.put(&self.trusted.digest);
        return bytes;
    }

    fn decode(bytes: []const u8) !Record {
        var r = wire.Reader{ .bytes = bytes };
        if (!std.mem.eql(u8, try r.take(8), "ZGOwner3")) return error.InvalidOwnerProof;
        const stage = std.enums.fromInt(Stage, try r.int(u8)) orelse return error.InvalidOwnerProof;
        const trusted = provisioning.Pin{ .object_id = try r.int(u64), .digest = (try r.take(32))[0..32].* };
        try r.end();
        return .{ .stage = stage, .trusted = trusted };
    }
};

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

fn prepare(manager: anytype, io: anytype, scratch: *[catalog.MAX_BYTES]u8) !provisioning.Pin {
    var vault = @import("../../services/secret_vault_service.zig").Service.init();
    var identities = @import("../../platform/os_identity.zig").Store.init();
    var graph = @import("../../sync/device_graph.zig").Graph.init();
    var policies = @import("../../policy/policy_object.zig").Directory.init();
    const owner = @import("../../core/principal.zig").PrincipalId{ .kind = .user, .serial = 0x706 };
    try identity_proof.makePolicy(&policies, owner);
    const storage = manager.storageServicePtr();
    const before = storage.checkpoint_store.last_checkpoint_generation;
    const trusted = try provisioning.prepare(io, storage, .{ .vault = &vault, .identities = &identities, .devices = &graph }, &policies, .{
        .owner = owner,
        .device = .{ .kind = .device, .serial = 0x707 },
        .record_object_id = object_id + 1,
        .catalog_object_id = 0x704_0001,
        .parent_handle = parent_handle,
        .anchor_index = 0x0180_7041,
    }, pin, &recovery_key, 1, scratch);
    if (io.persist_commands != 0 or storage.checkpoint_store.last_checkpoint_generation != before or
        !vault.store.empty() or vault.activeHandleCount() != 0 or vault.store.hardware_provider.operations != null or
        identities.credential_count != 0 or !@import("../../sync/device_graph_snapshot.zig").empty(&graph)) return error.PreparationPublishedAuthority;
    return trusted;
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
        record = .{ .trusted = try prepare(manager, io, &scratch) };
        try save(storage, record);
    }
    const bundle = try provisioning.load(storage, record.trusted);
    const identity = &bundle.identity;
    var secrets = recovery.Secrets{};
    defer secrets.wipe();
    try recovery.Package.open(&bundle.package.bytes, &(try identity.digest()), &recovery_key, &secrets);
    var admin = [_]tpm.Key{ secrets.owner, secrets.lockout, secrets.vault };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&admin));
    io.protected_authorizations = &admin;
    var client = tpm.Client{};
    defer client.close(io) catch {};
    if (record.stage != .persistence) {
        client.openPersistent(io, identity.enrollment.parent) catch |err| {
            if (err != error.PersistentParentMissing or io.owner_commands != 0) return err;
            if (record.stage == .enrolled) {
                console.print("ZIGOS:TPM2:OWNER:REPLACEMENT_REJECTED\n");
            } else {
                if (provisioning.commit(io, storage, record.trusted, &recovery_key, &scratch)) |_| return error.ReprovisionedReplacementTpm else |failure| {
                    if (failure != error.PersistentParentChanged or io.persist_commands != 0 or io.owner_commands != 1) return failure;
                }
                console.print("ZIGOS:TPM2:OWNER:SETUP_REPLACEMENT_REJECTED\n");
            }
            return;
        };
        try client.close(io);
    }

    if (record.stage != .enrolled) {
        // Reject a forged hierarchy state before an administrator command.
        if (record.stage == .owner) {
            const before = io.owner_commands;
            io.corrupt_hierarchy_state = true;
            if (provisioning.commit(io, storage, record.trusted, &recovery_key, &scratch)) |_| return error.AcceptedForgedHierarchyState else |err| {
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
            .write => io.corrupt_nv_write = true,
            .finish => {},
            .enrolled => unreachable,
        }
        if (record.stage != .finish) {
            if (provisioning.commit(io, storage, record.trusted, &recovery_key, &scratch)) |_| return error.AcceptedCorruptProvisioningReply else |err| {
                if (err != error.IntegrityFailure) return err;
            }
            if (io.da_resets != 0 or (record.stage != .persistence and io.persist_commands != 0)) return error.RepeatedProvisioningMutation;
            const marker = switch (record.stage) {
                .persistence => "ZIGOS:TPM2:OWNER:INTERRUPTED\n",
                .owner => "ZIGOS:TPM2:OWNER:OWNER_INTERRUPTED\n",
                .lockout => "ZIGOS:TPM2:OWNER:LOCKOUT_INTERRUPTED\n",
                .parameters => "ZIGOS:TPM2:OWNER:POLICY_INTERRUPTED\n",
                .definition => "ZIGOS:TPM2:OWNER:DEFINE_INTERRUPTED\n",
                .write => "ZIGOS:TPM2:OWNER:WRITE_INTERRUPTED\n",
                else => unreachable,
            };
            record.stage = @enumFromInt(@intFromEnum(record.stage) + 1);
            try save(storage, record);
            halt(marker);
        }
        const completed = try provisioning.commit(io, storage, record.trusted, &recovery_key, &scratch);
        if (!std.mem.eql(u8, &(try completed.digest()), &(try identity.digest())) or io.persist_commands != 0 or io.nv_writes != 0 or io.da_resets != 0) return error.RepeatedCompletedEnrollment;
        try client.openPersistent(io, identity.enrollment.parent);
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
    try identity_proof.runRecovery(manager, io, identity, &bundle.package, &recovery_key);
    try identity.capsule.unlock(&client, io, &identity.enrollment.capsule_digest, pin, &denied);
    if (!std.crypto.timing_safe.eql(tpm.Key, denied, secrets.vault)) return error.RecoveryDidNotRestorePin;
    try client.close(io);
    console.print("ZIGOS:TPM2:OWNER:VERIFIED\n");
}
