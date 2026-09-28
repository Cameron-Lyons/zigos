const std = @import("std");
const session_mod = @import("../../services/identity_session.zig");
const sealed = @import("../../services/sealed_signing_key.zig");
const vault = @import("../../services/secret_vault_service.zig");
const policy = @import("../../policy/policy_object.zig");
const identity = @import("../../platform/os_identity.zig");
const tpm = @import("../../platform/tpm2_sealing.zig");
const pin_mod = @import("../../platform/tpm2_pin.zig");
const provider = @import("../../platform/tpm2_secret_provider.zig");
const nv = @import("../../platform/tpm2_vault_anchor.zig");
const catalog = @import("../../storage/vault_catalog.zig");
const graph_mod = @import("../../sync/device_graph.zig");
const graph_snapshot = @import("../../sync/device_graph_snapshot.zig");
const console = @import("../../../kernel/utils/console.zig");

// Verification-only enrollment, persisted before the PIN lockout/reboot proof.
const object_id = 0x704_0001;
const anchor_index = 0x0180_7041;

fn makePolicy(policies: *policy.Directory, owner: @import("../../core/principal.zig").PrincipalId) !void {
    _ = try policies.create(.{ .scope = .user, .subject_id = owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 1 }, .label = "session proof", .secret_vault_allowed = true, .require_hardware_backed_secrets = true, .deny_secret_raw_export = true, .max_secret_handle_lease_ticks = 1000, .credential_assertions_allowed = true }, .{ .label = "session policy fixture", .seed = @splat(0x72) });
}

pub fn provision(manager: anytype, io: anytype, client: *tpm.Client, capsule: *const pin_mod.Capsule, authorization: *const tpm.Key) !void {
    var service = vault.Service.init();
    defer service.unload();
    var identities = identity.Store.init();
    var graph = graph_mod.Graph.init();
    const storage = manager.storageServicePtr();
    var backend = provider.Backend(@TypeOf(io.*)){ .client = client, .io = io, .authorization = authorization };
    service.attachHardwareProvider(backend.provider());
    var policies = policy.Directory.init();
    try makePolicy(&policies, capsule.owner);
    const subjects = policy.SubjectSet{ .user_id = capsule.owner.serial };
    var authority = sealed.Authority{ .service = &service, .policies = &policies, .subjects = subjects, .owner = capsule.owner, .holder = storage.owner, .task_id = storage.task_id };
    var keys: [4]sealed.Key = undefined;
    const labels = [_][]const u8{ "session catalog", "session root", "session device", "session credential" };
    for (&keys, labels, 0..) |*key, label, i| {
        const secret = try service.generateSigningKey(&policies, subjects, .{ .owner = capsule.owner, .task_id = storage.task_id, .label = label, .now_ticks = 1 }, null);
        if (secret.id != i + 1) return error.InvalidSessionKeyIds;
        const handle = try service.lendHandle(&policies, subjects, .{ .owner = capsule.owner, .holder = storage.owner, .task_id = storage.task_id, .secret_id = secret.id, .now_ticks = 1, .expires_at_ticks = 1000 }, null);
        key.* = try sealed.Key.bind(&authority, handle.id, 1);
    }
    _ = try graph.ensureSealedUserRoot(capsule.owner, "session owner", keys[1], 1);
    _ = try graph.enrollSealedDevice(capsule.owner, capsule.device, "session device", keys[1], keys[2], 1);
    // Enrollment requires key possession, not an already active user session.
    const replay = identity.unlock_context.Session{};
    _ = try identities.registerCredential(&graph, .{ .vault = &service, .policies = &policies, .subjects = subjects, .holder = storage.owner, .task_id = storage.task_id, .now_ticks = 1, .unlock_session = &replay }, .{ .owner = capsule.owner, .device = capsule.device, .relying_party_id = "session.example", .label = "session account", .key_handle_id = keys[3].handle_id });
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var checkpoint = catalog.Session{};
    _ = try checkpoint.save(storage, .{ .vault = &service, .identities = &identities, .devices = &graph }, .{ .key = keys[0] }, object_id, 0, 2, &scratch);
    var anchor = nv.Backend(@TypeOf(io.*)){ .client = client, .io = io, .authorization = authorization, .index = anchor_index, .current = .{
        .checkpoint = try catalog.inspect(storage, .{ .object_id = object_id, .owner = capsule.owner, .public_key = try keys[0].publicKey(2) }, &scratch),
        .device_root_pin = try keys[1].publicKey(2),
    } };
    try anchor.provision(storage, &scratch);
}

fn SessionIo(comptime Inner: type) type {
    return struct {
        inner: *Inner,
        fail_replay_entropy: bool = false,
        pub fn random(self: *@This(), out: []u8) !void {
            // TPM nonces use 32 bytes. The session replay domain uses 16.
            if (self.fail_replay_entropy and out.len == 16) return error.SessionEntropyUnavailable;
            try self.inner.random(out);
        }
        pub fn execute(self: *@This(), command: []const u8, response: []u8, timeout_ms: u32) ![]u8 {
            return self.inner.execute(command, response, timeout_ms);
        }
    };
}

fn requireLocked(session: anytype) !void {
    if (session.replay.active or session.coordinator != null or !std.mem.allEqual(u8, &session.authorization, 0) or
        !session.state.vault.store.empty() or session.state.vault.activeHandleCount() != 0 or session.state.vault.store.handles.countInUse() != 0 or
        session.state.vault.store.hardware_provider.operations != null or session.state.identities.credential_count != 0 or !graph_snapshot.empty(session.state.devices.?)) return error.RetainedLockedAuthority;
}

pub fn run(manager: anytype, io: anytype, capsule: *const pin_mod.Capsule, digest: *const tpm.Key, pin: []const u8, expected_rejection: ?anyerror) !void {
    var service = vault.Service.init();
    var identities = identity.Store.init();
    var graph = graph_mod.Graph.init();
    var policies = policy.Directory.init();
    try makePolicy(&policies, capsule.owner);
    var session_io = SessionIo(@TypeOf(io.*)){ .inner = io };
    var session = session_mod.Session(@TypeOf(session_io)){
        .io = &session_io,
        .enrollment = .{ .owner = capsule.owner, .device = capsule.device, .capsule_digest = digest.*, .catalog_object_id = object_id, .anchor_index = anchor_index, .catalog_secret_id = 1, .device_secret_id = 3 },
        .state = .{ .vault = &service, .identities = &identities, .devices = &graph },
        .storage = manager.storageServicePtr(),
        .policies = &policies,
        .subjects = .{ .user_id = capsule.owner.serial },
    };
    defer session.close() catch {};
    const boot = @import("../../../kernel/platform/secure_random.zig").bootInstanceId();
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    if (expected_rejection) |expected| {
        if (session.unlock(capsule, pin, boot, 1, 100, &scratch)) |_| return error.ActivatedRejectedPinSession else |err| {
            if (err != expected) return err;
        }
        try requireLocked(&session);
        return;
    }
    // Reject failures before restore, after restore/key binding, and at the
    // final activation point. None may leave keys or a usable replay domain.
    io.corrupt_nv_read = true;
    if (session.unlock(capsule, pin, boot, 1, 100, &scratch)) |_| return error.AcceptedCorruptSessionAnchor else |err| {
        if (err != error.IntegrityFailure) return err;
    }
    io.corrupt_nv_read = false;
    try requireLocked(&session);
    session.enrollment.device_secret_id = 2;
    if (session.unlock(capsule, pin, boot, 1, 100, &scratch)) |_| return error.AcceptedWrongSessionDeviceKey else |err| {
        if (err != error.SigningKeyChanged) return err;
    }
    try requireLocked(&session);
    session.enrollment.device_secret_id = 3;
    session_io.fail_replay_entropy = true;
    if (session.unlock(capsule, pin, boot, 1, 100, &scratch)) |_| return error.ActivatedWithoutSessionEntropy else |err| {
        if (err != error.SessionEntropyUnavailable) return err;
    }
    session_io.fail_replay_entropy = false;
    try requireLocked(&session);
    try session.unlock(capsule, pin, boot, 10, 100, &scratch);
    const old_binding = try session.replay.binding();
    const old_key = session.device_key;
    const old_handle = service.findHandleConst(old_key.handle_id).?.*;
    const old_proof = try session.issueUnlockProof("session.example", "challenge", 12, 90);
    if (old_proof.issued_at_ticks != 10) return error.RefreshedPinVerification;
    if (session.unlock(capsule, pin, boot, 13, 100, &scratch)) |_| return error.ReplacedLiveSession else |err| {
        if (err != error.IdentitySessionAlreadyActive) return err;
    }
    try session.replay.require(old_binding);
    const credential = identities.findCredentialConst(1) orelse return error.MissingSessionCredential;
    const public_key = credential.credential_public_key;
    const first = credential.assertion_count == 0;
    if (first) {
        const assertion = try session.assertCredential(.{ .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example", .challenge = "challenge", .local_unlock = old_proof }, 14, &scratch);
        if (assertion.assertion_counter != 1 or assertion.unlock_age_ticks != 4 or !identity.verifyAssertion(&assertion, &public_key)) return error.InvalidSessionAssertion;
    } else if (credential.assertion_count != 2) return error.InvalidSessionCounter;
    session.lock();
    try requireLocked(&session);
    if (old_key.validate(15)) |_| return error.RetainedLockedKey else |err| {
        if (err != error.VaultHandleNotFound) return err;
    }
    if (session.issueUnlockProof("session.example", "challenge", 15, 90)) |_| return error.IssuedLockedProof else |err| {
        if (err != error.UnlockContextUnavailable) return err;
    }
    try session.unlock(capsule, pin, boot, 20, 100, &scratch);
    if (service.store.describeHandle(old_handle.store_handle_id) != null or service.findHandleConst(old_handle.id) != null) return error.RevivedSessionLease;
    if (old_key.validate(21)) |_| return error.RevivedSessionKey else |err| {
        if (err != error.VaultHandleNotFound) return err;
    }
    if (session.assertCredential(.{ .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example", .challenge = "challenge", .local_unlock = old_proof }, 21, &scratch)) |_| return error.ReplayedLockedProof else |err| {
        if (err != error.UnlockContextMismatch) return err;
    }
    if (identities.findCredentialConst(1).?.assertion_count != (if (first) @as(u64, 1) else 2)) return error.LostSessionCounter;
    const proof = try session.issueUnlockProof("session.example", "fresh", 22, 90);
    if (proof.issued_at_ticks != 20) return error.InvalidSessionVerificationTime;
    if (first) {
        // Lose a successful NV write response after disk durability. No signed
        // assertion escapes. Lock discards pending RAM state; unlock recovers
        // the durable counter with a fresh authenticated client.
        io.corrupt_nv_write = true;
        if (session.assertCredential(.{ .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example", .challenge = "fresh", .local_unlock = proof }, 23, &scratch)) |_| return error.PublishedUnacknowledgedSessionAssertion else |err| {
            if (err != error.IntegrityFailure) return err;
        }
        io.corrupt_nv_write = false;
        if (!session.coordinator.?.dirty or session.coordinator.?.checkpoint.pending == null) return error.LostSessionPendingCheckpoint;
        session.lock();
        try requireLocked(&session);
        try session.unlock(capsule, pin, boot, 30, 100, &scratch);
        if (identities.findCredentialConst(1).?.assertion_count != 2) return error.LostSessionCounter;
    }
    const deadline = session.expires_at_ticks;
    if (session.requireActive(deadline)) |_| return error.AcceptedExpiredSession else |err| {
        if (err != error.IdentitySessionExpired) return err;
    }
    try requireLocked(&session);
    try session.close();
    console.print("ZIGOS:TPM2:SESSION:VERIFIED\n");
}
