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

pub fn enrollmentFor(capsule: *const pin_mod.Capsule, digest: tpm.Key, parent: tpm.PersistentParent) session_mod.Enrollment {
    return .{ .owner = capsule.owner, .device = capsule.device, .capsule_digest = digest, .parent = parent, .catalog_object_id = object_id, .anchor_index = anchor_index, .catalog_secret_id = 1, .device_secret_id = 3 };
}

pub fn makePolicy(policies: *policy.Directory, owner: @import("../../core/principal.zig").PrincipalId) !void {
    _ = try policies.create(.{ .scope = .user, .subject_id = owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 1 }, .label = "session proof", .secret_vault_allowed = true, .require_hardware_backed_secrets = true, .deny_secret_raw_export = true, .max_secret_handle_lease_ticks = 1000, .credential_assertions_allowed = true }, .{ .label = "session policy fixture", .seed = @splat(0x72) });
}

// Extend a completed production enrollment with the verification credential
// used by the ordinary PIN/recovery proofs. Setup itself creates no fixture key.
pub fn addProofCredential(manager: anytype, io: anytype, record: *const @import("../../services/identity_enrollment.zig").Record, pin: []const u8) !void {
    var service = vault.Service.init();
    var identities = identity.Store.init();
    var graph = graph_mod.Graph.init();
    var policies = policy.Directory.init();
    try makePolicy(&policies, record.enrollment.owner);
    const storage = manager.storageServicePtr();
    var session = session_mod.Session(@TypeOf(io.*)){
        .io = io,
        .enrollment = record.enrollment,
        .state = .{ .vault = &service, .identities = &identities, .devices = &graph },
        .storage = storage,
        .policies = &policies,
        .subjects = .{ .user_id = record.enrollment.owner.serial },
    };
    defer session.close() catch {};
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    try session.unlock(&record.capsule, pin, @import("../../../kernel/platform/secure_random.zig").bootInstanceId(), 1, 100, &scratch);
    if (service.store.secret_count != 3 or identities.credential_count != 0) return error.UnexpectedProvisionedKeys;
    const secret = try service.generateSigningKey(&policies, session.subjects, .{ .owner = record.enrollment.owner, .task_id = storage.task_id, .label = "session credential", .now_ticks = 2 }, null);
    const handle = try service.lendHandle(&policies, session.subjects, .{ .owner = record.enrollment.owner, .holder = storage.owner, .task_id = storage.task_id, .secret_id = secret.id, .now_ticks = 2, .expires_at_ticks = 100 }, null);
    _ = try session.coordinator.?.registerCredential(&graph, .{ .vault = &service, .policies = &policies, .subjects = session.subjects, .holder = storage.owner, .task_id = storage.task_id, .now_ticks = 2, .unlock_session = &session.replay }, .{ .owner = record.enrollment.owner, .device = record.enrollment.device, .relying_party_id = "session.example", .label = "session account", .key_handle_id = handle.id }, &scratch);
    session.lock();
    try requireLocked(&session);
}

pub fn provision(manager: anytype, io: anytype, client: *tpm.Client, capsule: *const pin_mod.Capsule, authorization: *const tpm.Key, owner_auth: ?*const tpm.Key) !void {
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
    try anchor.provision(storage, &scratch, owner_auth);
}

fn SessionIo(comptime Inner: type) type {
    return struct {
        inner: *Inner,
        fail_replay_entropy: bool = false,
        interrupt_rejection_proved: bool = false,
        pub fn random(self: *@This(), out: []u8) !void {
            // TPM nonces use 32 bytes. The session replay domain uses 16.
            if (self.fail_replay_entropy and out.len == 16) return error.SessionEntropyUnavailable;
            try self.inner.random(out);
        }
        pub fn execute(self: *@This(), command: []const u8, response: []u8, timeout_ms: u32) ![]u8 {
            if (!self.interrupt_rejection_proved and @import("../../task/cooperative_worker.zig").current() != null) {
                try rejectInterrupt(command, response, timeout_ms);
                self.interrupt_rejection_proved = true;
            }
            return self.inner.execute(command, response, timeout_ms);
        }

        fn rejectInterrupt(command: []const u8, response: []u8, timeout_ms: u32) !void {
            // Model interrupt nesting on the active worker: execute must reject
            // entry before yielding or touching the worker's borrowed packet.
            const context = @import("../../../kernel/interrupts/context.zig");
            context.enter();
            defer context.leave();
            if (@import("../../../kernel/platform/tpm2_hw.zig").execute(command, response, timeout_ms)) |_| {
                return error.InterruptEnteredAuthentication;
            } else |err| if (err != error.InterruptContext) return err;
        }
    };
}

fn requireLocked(session: anytype) !void {
    if (session.replay.active or session.coordinator != null or session.unlock_method != null or !std.mem.allEqual(u8, &session.authorization, 0) or
        !session.state.vault.store.empty() or session.state.vault.activeHandleCount() != 0 or session.state.vault.store.handles.countInUse() != 0 or
        session.state.vault.store.hardware_provider.operations != null or session.state.identities.credential_count != 0 or !graph_snapshot.empty(session.state.devices.?)) return error.RetainedLockedAuthority;
}

pub fn run(manager: anytype, io: anytype, capsule: *const pin_mod.Capsule, digest: *const tpm.Key, pin: []const u8, expected_rejection: ?anyerror, parent: tpm.PersistentParent, expected_count: u64) !void {
    var service = vault.Service.init();
    var identities = identity.Store.init();
    var graph = graph_mod.Graph.init();
    var policies = policy.Directory.init();
    try makePolicy(&policies, capsule.owner);
    var session_io = SessionIo(@TypeOf(io.*)){ .inner = io };
    var session = session_mod.Session(@TypeOf(session_io)){
        .io = &session_io,
        .enrollment = enrollmentFor(capsule, digest.*, parent),
        .state = .{ .vault = &service, .identities = &identities, .devices = &graph },
        .storage = manager.storageServicePtr(),
        .policies = &policies,
        .subjects = .{ .user_id = capsule.owner.serial },
    };
    defer session.close() catch {};
    const boot = @import("../../../kernel/platform/secure_random.zig").bootInstanceId();
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    if (expected_rejection) |expected| {
        try proveTrustedInput(manager, &session, capsule, pin, boot, &scratch, null, null, expected);
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
    if (old_proof.issued_at_ticks != 10 or old_proof.method != .device_pin) return error.RefreshedPinVerification;
    if (session.unlock(capsule, pin, boot, 13, 100, &scratch)) |_| return error.ReplacedLiveSession else |err| {
        if (err != error.IdentitySessionAlreadyActive) return err;
    }
    try session.replay.require(old_binding);
    const credential = identities.findCredentialConst(1) orelse return error.MissingSessionCredential;
    const public_key = credential.credential_public_key;
    if (credential.assertion_count != expected_count) return error.InvalidSessionCounter;
    const first = expected_count == 0;
    if (first) {
        const assertion = try session.assertCredential(.{ .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example", .challenge = "challenge", .local_unlock = old_proof }, 14, &scratch);
        if (assertion.assertion_counter != 1 or assertion.unlock_age_ticks != 4 or !identity.verifyAssertion(&assertion, &public_key)) return error.InvalidSessionAssertion;
    }
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
    if (identities.findCredentialConst(1).?.assertion_count != (if (first) @as(u64, 1) else expected_count)) return error.LostSessionCounter;
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
    try proveTrustedInput(manager, &session, capsule, pin, boot, &scratch, null, null, null);
    console.print("ZIGOS:TPM2:SESSION:VERIFIED\n");
}

pub fn runRecovery(manager: anytype, io: anytype, record: *const @import("../../services/identity_enrollment.zig").Record, package: *const @import("../../services/identity_recovery.zig").Package, retained: *const @import("../../services/identity_recovery_record.zig").Record) !void {
    const recovery_key = &retained.key;
    var service = vault.Service.init();
    var identities = identity.Store.init();
    var graph = graph_mod.Graph.init();
    var policies = policy.Directory.init();
    try makePolicy(&policies, record.enrollment.owner);
    var session_io = SessionIo(@TypeOf(io.*)){ .inner = io };
    var session = session_mod.Session(@TypeOf(session_io)){
        .io = &session_io,
        .enrollment = record.enrollment,
        .state = .{ .vault = &service, .identities = &identities, .devices = &graph },
        .storage = manager.storageServicePtr(),
        .policies = &policies,
        .subjects = .{ .user_id = record.enrollment.owner.serial },
    };
    defer session.close() catch {};
    const boot = @import("../../../kernel/platform/secure_random.zig").bootInstanceId();
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    const commands = io.commands;
    const resets = io.da_resets;
    var wrong_key = recovery_key.*;
    defer std.crypto.secureZero(u8, &wrong_key);
    wrong_key[0] ^= 1;
    if (session.unlockRecovery(&record.capsule, &package.bytes, &wrong_key, boot, 1, 100, &scratch)) |_| return error.AcceptedWrongRecoveryKey else |err| {
        if (err != error.RecoveryAuthenticationFailed) return err;
    }
    try requireLocked(&session);
    var damaged = package.*;
    damaged.bytes[damaged.bytes.len - 1] ^= 1;
    if (session.unlockRecovery(&record.capsule, &damaged.bytes, recovery_key, boot, 1, 100, &scratch)) |_| return error.AcceptedDamagedRecoveryPackage else |err| {
        if (err != error.RecoveryAuthenticationFailed) return err;
    }
    try requireLocked(&session);
    session.enrollment.catalog_object_id += 1;
    if (session.unlockRecovery(&record.capsule, &package.bytes, recovery_key, boot, 1, 100, &scratch)) |_| return error.AcceptedForeignRecoveryEnrollment else |err| {
        if (err != error.RecoveryEnrollmentChanged) return err;
    }
    try requireLocked(&session);
    session.enrollment = record.enrollment;
    if (io.commands != commands or io.da_resets != resets) return error.UntrustedRecoveryReachedTpm;
    const codec = @import("../../services/identity_recovery_record.zig");
    var code: [codec.DISPLAY_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &code);
    try retained.format(&code);
    code[0] = if (code[0] == '0') '1' else '0';
    try proveTrustedInput(manager, &session, &record.capsule, &code, boot, &scratch, package, retained.trusted, error.InvalidRecoveryCode);
    var wrong = retained.*;
    defer wrong.erase();
    wrong.key = wrong_key;
    try wrong.format(&code);
    try proveTrustedInput(manager, &session, &record.capsule, &code, boot, &scratch, package, retained.trusted, error.RecoveryAuthenticationFailed);
    if (io.commands != commands or io.da_resets != resets) return error.UntrustedRecoveryInputReachedTpm;
    try retained.format(&code);
    try proveTrustedInput(manager, &session, &record.capsule, &code, boot, &scratch, package, retained.trusted, null);
    try session.close();
    const successful_resets = io.da_resets;
    io.corrupt_nv_read = true;
    if (session.unlockRecovery(&record.capsule, &package.bytes, recovery_key, boot, 1, 100, &scratch)) |_| return error.AcceptedCorruptRecoveryAnchor else |err| {
        if (err != error.IntegrityFailure) return err;
    }
    io.corrupt_nv_read = false;
    try requireLocked(&session);
    session_io.fail_replay_entropy = true;
    if (session.unlockRecovery(&record.capsule, &package.bytes, recovery_key, boot, 1, 100, &scratch)) |_| return error.ActivatedRecoveryWithoutEntropy else |err| {
        if (err != error.SessionEntropyUnavailable) return err;
    }
    session_io.fail_replay_entropy = false;
    try requireLocked(&session);
    try session.unlockRecovery(&record.capsule, &package.bytes, recovery_key, boot, 10, 100, &scratch);
    const proof = try session.issueUnlockProof("session.example", "recover", 11, 90);
    if (proof.method != .recovery_key or proof.issued_at_ticks != 10 or io.da_resets != successful_resets + 3) return error.InvalidRecoveryAuthority;
    const credential = identities.findCredentialConst(1) orelse return error.MissingSessionCredential;
    const public_key = credential.credential_public_key;
    const previous_count = credential.assertion_count;
    const assertion = try session.assertCredential(.{ .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example", .challenge = "recover", .local_unlock = proof }, 12, &scratch);
    if (assertion.assertion_counter != previous_count + 1 or !identity.verifyAssertion(&assertion, &public_key)) return error.InvalidRecoveryAssertion;
    session.lock();
    try requireLocked(&session);
    try session.unlockRecovery(&record.capsule, &package.bytes, recovery_key, boot, 20, 100, &scratch);
    if (identities.findCredentialConst(1).?.assertion_count != previous_count + 1) return error.LostRecoveryCounter;
    if (session.assertCredential(.{ .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example", .challenge = "recover", .local_unlock = proof }, 21, &scratch)) |_| return error.ReplayedRecoveryProof else |err| {
        if (err != error.UnlockContextMismatch) return err;
    }
    if (session.requireActive(session.expires_at_ticks)) |_| return error.AcceptedExpiredRecovery else |err| {
        if (err != error.IdentitySessionExpired) return err;
    }
    try requireLocked(&session);
    console.print("ZIGOS:TPM2:RECOVERY:VERIFIED\n");
}

// Verification-only modeled HID reports enter through the same native router,
// renderer, deadline dispatch and TPM authenticator used by the desktop owner.
const xhci = @import("../../../kernel/drivers/xhci.zig");
var input_report: ?xhci.HardwareBootKeyboardReport = null;
var input_sequence: u64 = 0;

pub fn pollInputReport() ?xhci.HardwareBootKeyboardReport {
    const report = input_report orelse return null;
    std.crypto.secureZero(u8, &input_report.?.bytes);
    input_report = null;
    return report;
}

pub fn noInputProof() ?xhci.InputProof {
    return null;
}

pub fn sendInput(manager: anytype, usage: u8, modifiers: u8, now_ticks: u64) void {
    input_sequence += 1;
    input_report = .{ .sequence = input_sequence, .port_id = 1, .slot_id = 1, .endpoint_id = 3 };
    input_report.?.bytes[0] = modifiers;
    input_report.?.bytes[2] = usage;
    _ = manager.servicePendingInputWork(now_ticks);
    _ = @import("../../platform/desktop_display.zig").present(manager.compositorSessionPtr());
}

// Use elapsed invariant-clock ticks while exercising the real scheduler-facing
// entry points. Synthetic epochs keep this proof independent of earlier boots.
pub const ProofClock = struct {
    start: u64,
    per_tick: u64,
    epoch: u64 = 200,
    native_time: bool = false,
    pub fn init() ProofClock {
        const interval = @import("../../../kernel/timer/tsc_clock.zig").afterMilliseconds(timer.MILLISECONDS_PER_TICK).value;
        return .{ .start = interval.start_ticks, .per_tick = interval.interval_ticks };
    }
    pub fn native() ProofClock {
        timer.synchronize();
        var clock = init();
        clock.epoch = timer.getTicks();
        clock.native_time = true;
        return clock;
    }
    pub fn now(self: ProofClock) u64 {
        if (self.native_time) {
            timer.synchronize();
            return timer.getTicks();
        }
        return self.epoch + (@import("../../../arch/x86.zig").rdtsc() -% self.start) / self.per_tick;
    }
};
const timer = @import("../../../kernel/timer/timer.zig");

pub fn typeAuthentication(manager: anytype, value: []const u8, recovering: bool, clock: ProofClock) !void {
    const router = manager.inputRouterPtr();
    sendInput(manager, 0, 0, clock.now());
    if (recovering) {
        sendInput(manager, 0x15, 1, clock.now()); // Ctrl+R selects recovery in the trusted prompt.
        sendInput(manager, 0, 0, clock.now());
    }
    var characters: usize = 0;
    for (value) |byte| {
        const usage: u8 = switch (byte) {
            '0' => 0x27,
            '1'...'9' => byte - '1' + 0x1e,
            'A'...'Z' => byte - 'A' + 0x04, // Lowercase input exercises normalization.
            '-' => 0x2d,
            ' ' => 0x2c,
            else => return error.InvalidProofInput,
        };
        sendInput(manager, usage, 0, clock.now());
        sendInput(manager, 0, 0, clock.now());
        if (byte != '-' and byte != ' ') characters += 1;
        if (router.queued_event_count != 0 or router.pollWakeTarget() != null) return error.LeakedAuthenticationInput;
    }
    const frame = @import("../../../kernel/platform/framebuffer_hw.zig").frame() orelse return error.MissingAuthenticationFrame;
    for (0..characters) |i| if (frame.cells[(6 + i / frame.columns) * frame.columns + i % frame.columns].character != '*') return error.UnmaskedAuthenticationInput;
    sendInput(manager, 0x28, 0, clock.now());
}

fn serviceAttempt(manager: anytype, entry: anytype, clock: ProofClock) !void {
    if (clock.now() - clock.epoch > 3000) return error.AuthenticationWorkerTimeout;
    manager.serviceAuthenticationClock(clock.now());
    // Input and scanout keep working between TPM polls, without forwarding keys
    // to apps or retaining the submitted secret in the entry or public view.
    sendInput(manager, 0, 0, clock.now());
    if (!std.mem.allEqual(u8, &entry.value, 0) or entry.view.characters != 0 or manager.inputRouterPtr().queued_event_count != 0) return error.RetainedSubmittedSecret;
    @import("../../../kernel/utils/spin.zig").hint();
}

fn proveTrustedInput(manager: anytype, session: anytype, capsule: *const pin_mod.Capsule, value: []const u8, boot: [16]u8, scratch: *[catalog.MAX_BYTES]u8, package: ?*const @import("../../services/identity_recovery.zig").Package, recovery_pin: ?@import("../../services/identity_provisioning.zig").Pin, rejection: ?anyerror) !void {
    const entry_mod = @import("../../platform/trusted_auth_entry.zig");
    const Adapter = @import("../../services/identity_authenticator.zig").Adapter(@TypeOf(session.io.*));
    const recovering = package != null;
    var adapter = Adapter{ .session = session, .capsule = capsule, .recovery_package = package, .recovery_pin = recovery_pin, .boot_instance = boot, .lifetime_ticks = 1000, .scratch = scratch };
    defer adapter.deinit() catch @panic("authentication proof released a live worker");
    var entry = entry_mod.Entry{ .authenticator = adapter.authenticator(), .input_timeout_ticks = 50 };
    const clock = ProofClock.init();
    const router = manager.inputRouterPtr();
    const previous_source = router.source;
    const previous_compositor = router.compositor;
    const previous_task_id = router.compositor_task_id;
    router.bindHardwareSource(.{ .poll_report = pollInputReport, .input_proof = noInputProof });
    router.bindCompositor(manager.compositorSessionPtr(), manager.storageServicePtr().task_id);
    manager.bindTrustedAuthentication(&entry, clock.now());
    defer {
        router.clearTrustedEntry(); // Drains cancellation before borrowed stores disappear.
        sendInput(manager, 0, 0, clock.now());
        if (previous_compositor) |compositor| router.bindCompositor(compositor, previous_task_id) else router.clearCompositor();
        if (previous_source) |source| router.bindHardwareSource(source) else router.clearHardwareSource();
        input_report = null;
    }
    try typeAuthentication(manager, value, recovering, clock);
    if (rejection != null and (rejection.? == error.InvalidRecoveryCode or rejection.? == error.RecoveryAuthenticationFailed)) {
        if (entry.busy() or entry.view.status != (if (rejection.? == error.InvalidRecoveryCode) entry_mod.Status.invalid_code else .rejected)) return error.BadTrustedRecoveryRejection;
        try requireLocked(session);
        if (!std.mem.allEqual(u8, &entry.value, 0) or !std.mem.allEqual(u8, &adapter.value, 0)) return error.RetainedAuthenticationSecrets;
        if (adapter.stack) |stack| if (!std.mem.allEqual(u8, stack.bytes, 0)) return error.RetainedAuthenticationSecrets;
        return;
    }
    if (!entry.busy() or entry.view.status != .verifying) return error.AuthenticationDidNotYield;
    if (!session.io.interrupt_rejection_proved) return error.MissingInterruptRejection;
    if (!adapter.stack.?.guardsPresent()) return error.UnprotectedAuthenticationStack;
    const scheduler = manager.userspaceSchedulerPtr();
    const before = (scheduler.taskDispatchStats(previous_task_id) orelse return error.MissingAuthenticationPeerTask).dispatch_count;
    _ = manager.wakeUserspaceTask(previous_task_id, clock.now());
    for (0..manager.runtimePtr().taskSlotCapacity() * 8) |_| {
        _ = manager.runUserspaceScheduler(clock.now());
        if (scheduler.taskDispatchStats(previous_task_id).?.dispatch_count > before) break;
    }
    if (scheduler.taskDispatchStats(previous_task_id).?.dispatch_count == before or !entry.busy() or
        !adapter.stack.?.guardsPresent()) return error.AuthenticationBlockedUserspace;
    while (entry.busy()) try serviceAttempt(manager, &entry, clock);
    if (!std.mem.allEqual(u8, adapter.stack.?.bytes, 0) or !std.mem.allEqual(u8, &adapter.value, 0)) return error.RetainedAuthenticationSecrets;
    if (rejection) |expected| {
        if (entry.view.status != (if (expected == error.PinLockedOut) entry_mod.Status.locked_out else .rejected)) return error.BadTrustedPinRejection;
        try requireLocked(session);
        return;
    }
    if (entry.capturing() or !session.replay.active) return error.TrustedPinDidNotUnlock;
    const old_key = session.device_key;
    const proof = try session.issueUnlockProof("session.example", "trusted entry", clock.now(), session.expires_at_ticks);
    if (proof.method != (if (recovering) identity.UnlockMethod.recovery_key else .device_pin)) return error.WrongTrustedAuthenticationMethod;
    if (proof.issued_at_ticks != adapter.started_at) return error.WrongTrustedPinTime;
    sendInput(manager, 0, 0, clock.now());
    sendInput(manager, 0x4c, 5, clock.now()); // Ctrl+Alt+Delete revokes locally.
    try requireLocked(session);
    if (!entry.capturing() or entry.view.method != .pin) return error.TrustedAttentionDidNotLock;
    if (old_key.validate(clock.now())) |_| return error.RetainedTrustedInputKey else |err| {
        if (err != error.VaultHandleNotFound) return err;
    }
    // Cancel once after opening the TPM parent and again after restoring keys.
    // Both paths must unwind resource cleanup before allowing another attempt.
    try session.close();
    for (0..2) |stage| {
        try typeAuthentication(manager, value, recovering, clock);
        while (entry.busy() and (if (stage == 0) session.client.parent == 0 else session.state.vault.store.empty())) try serviceAttempt(manager, &entry, clock);
        if (!entry.busy() or session.replay.active) return error.MissedCancellationBoundary;
        sendInput(manager, 0x29, 0, clock.now()); // Escape cancels without blocking input.
        if (!entry.busy() or entry.view.status != .cancelling or session.replay.active) return error.BlockingAuthenticationCancel;
        while (entry.busy()) try serviceAttempt(manager, &entry, clock);
        try requireLocked(session);
        if (session.client.parent != 0 or !std.mem.allEqual(u8, adapter.stack.?.bytes, 0) or !std.mem.allEqual(u8, &adapter.value, 0)) return error.RetainedCancelledWorker;
    }
    try typeAuthentication(manager, value, recovering, clock);
    while (entry.busy()) try serviceAttempt(manager, &entry, clock);
    if (entry.capturing() or !session.replay.active) return error.TrustedPinDidNotUnlock;
    const deadline = session.expires_at_ticks;
    if (manager.nextServiceWake() == null or manager.nextServiceWake().? > deadline) return error.MissingAuthenticationDeadline;
    manager.serviceAuthenticationClock(deadline);
    try requireLocked(session);
    if (!entry.capturing() or router.queued_event_count != 0) return error.MissedAuthenticationDeadline;
    if (recovering) {
        console.print("ZIGOS:TPM2:RECOVERY_WORKER:VERIFIED\n");
        console.print("ZIGOS:TPM2:RECOVERY_INPUT:VERIFIED\n");
    } else {
        console.print("ZIGOS:TPM2:PIN_WORKER:VERIFIED\n");
        console.print("ZIGOS:TPM2:PIN_INPUT:VERIFIED\n");
    }
}
