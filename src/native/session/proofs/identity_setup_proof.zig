//! Verification-only physical-input model for the production setup owner.
const std = @import("std");
const setup = @import("../../platform/trusted_setup_entry.zig");
const provisioning = @import("../../services/identity_provisioning.zig");
const recovery = @import("../../services/identity_recovery_record.zig");
const enrollment = @import("../../services/identity_enrollment.zig");
const catalog = @import("../../storage/vault_catalog.zig");
const identity_proof = @import("identity_session_proof.zig");
const display = @import("../../platform/desktop_display.zig");
const framebuffer = @import("../../../kernel/platform/framebuffer_hw.zig");
const console = @import("../../../kernel/utils/console.zig");

pub fn run(manager: anytype, io: anytype, request: provisioning.Request, pin: []const u8, retained: ?*const recovery.Record, exporter: anytype, scratch: *[catalog.MAX_BYTES]u8, expected_failure: ?anyerror) !?enrollment.Record {
    _ = scratch;
    const clock = identity_proof.ProofClock.init();
    const owner = try manager.attachIdentityOwner(io, .{ .owner = request.owner, .parent_handle = request.parent_handle, .anchor_index = request.anchor_index, .boot_index = request.boot_index, .boot_instance = @import("../../../kernel/platform/secure_random.zig").bootInstanceId(), .input_timeout_ticks = 3000, .operation_timeout_ticks = 3000, .lifetime_ticks = 1000 }, clock.now());
    const entry = &owner.setup;
    const worker = &owner.setup_worker;
    // Reserve the catalog IDs shared by the existing credential/assertion proof.
    // Production chooses fresh IDs from storage when allocating the same owner.
    worker.request.catalog_object_id = request.catalog_object_id;
    worker.request.record_object_id = request.record_object_id;
    const vault = &owner.vault;
    const router = manager.inputRouterPtr();
    const previous_source = router.source;
    const previous_compositor = router.compositor;
    const previous_task_id = router.compositor_task_id;
    router.bindHardwareSource(.{ .poll_report = identity_proof.pollInputReport, .input_proof = identity_proof.noInputProof });
    router.bindCompositor(manager.compositorSessionPtr(), manager.storageServicePtr().task_id);
    entry.discover(clock.now());
    defer {
        manager.clearIdentityOwner();
        identity_proof.sendInput(manager, 0, 0, clock.now());
        if (previous_compositor) |compositor| router.bindCompositor(compositor, previous_task_id) else router.clearCompositor();
        if (previous_source) |source| router.bindHardwareSource(source) else router.clearHardwareSource();
        _ = display.present(manager.compositorSessionPtr());
    }
    var saved = recovery.Record{};
    defer saved.erase();
    var code: [recovery.DISPLAY_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &code);
    if (retained) |record| {
        saved = record.*;
        // Explicit recovery can resume a completed commit whose acknowledgement
        // was lost, even before ordinary boot discovery starts.
        entry.inputInterrupted(clock.now());
        identity_proof.sendInput(manager, 0, 0, clock.now());
        identity_proof.sendInput(manager, 0x15, 1, clock.now());
        identity_proof.sendInput(manager, 0, 0, clock.now());
        if (entry.view.status != .resume_setup) return error.SetupDidNotResume;
    } else {
        _ = manager.servicePendingInputWork(clock.now());
        while (entry.busy() or entry.pending != null) try service(manager, entry, clock);
        if (entry.view.status != .choose_pin) return error.SetupDiscoveryFailed;
        const commands = io.commands;
        try identity_proof.typeAuthentication(manager, pin, false, clock);
        try identity_proof.typeAuthentication(manager, "93058279", false, clock);
        if (entry.view.status != .choose_pin or entry.view.notice != .mismatch or io.commands != commands) return error.UnconfirmedSetupPin;
        // Cancel a submitted preparation while protocol buffers are borrowed.
        try identity_proof.typeAuthentication(manager, pin, false, clock);
        try identity_proof.typeAuthentication(manager, pin, false, clock);
        if (!entry.busy() or !worker.stack.?.guardsPresent()) return error.SetupDidNotYield;
        identity_proof.sendInput(manager, 0, 0, clock.now());
        identity_proof.sendInput(manager, 0x29, 0, clock.now());
        while (entry.busy()) try service(manager, entry, clock);
        try erased(entry, worker);
        if (entry.view.status != .choose_pin or io.persist_commands != 0 or !vault.store.empty()) return error.UnsafeSetupCancellation;
        try identity_proof.typeAuthentication(manager, pin, false, clock);
        try identity_proof.typeAuthentication(manager, pin, false, clock);
        if (!entry.busy() or !worker.stack.?.guardsPresent()) return error.SetupDidNotYield;
        try proveDispatch(manager, previous_task_id, entry, clock);
        while (entry.busy()) try service(manager, entry, clock);
        if (entry.view.status != .record_recovery or io.persist_commands != 0 or io.da_resets != 0 or
            !vault.store.empty() or vault.activeHandleCount() != 0 or vault.store.hardware_provider.operations != null) return error.SetupCommittedBeforeRecovery;
        if (!std.mem.allEqual(u8, worker.stack.?.bytes, 0) or !std.mem.allEqual(u8, &worker.value, 0)) return error.SetupRetainedWorkerSecret;
        // Copy what the native display actually showed into independent fixture
        // custody. No key or pin is learned from an untrusted disk candidate.
        const frame = framebuffer.frame() orelse return error.MissingSetupFrame;
        var compact: [recovery.CODE_BYTES]u8 = undefined;
        defer std.crypto.secureZero(u8, &compact);
        var n: usize = 0;
        for (0..4) |line| for (0..39) |column| {
            const character = frame.cells[(6 + line) * frame.columns + column].character;
            if (character == '-') continue;
            if (character > 127 or n == compact.len) return error.InvalidRecoveryDisplay;
            compact[n] = @intCast(character);
            n += 1;
        };
        if (n != compact.len) return error.InvalidRecoveryDisplay;
        try recovery.Record.decode(&compact, &saved);
        _ = try provisioning.load(manager.storageServicePtr(), saved.trusted);
        try exporter.capture(&saved);
        identity_proof.sendInput(manager, 0, 0, clock.now());
        identity_proof.sendInput(manager, 0x28, 0, clock.now());
        if (entry.view.status != .confirm_recovery or !std.mem.allEqual(u8, &entry.view.recovery_code, 0)) return error.UnhiddenRecoveryConfirmation;
        identity_proof.sendInput(manager, 0, 0, clock.now());
        identity_proof.sendInput(manager, 0x28, 0, clock.now());
        if (entry.view.notice != .invalid_record or io.persist_commands != 0) return error.UnconfirmedRecoveryRecord;
    }
    try saved.format(&code);
    if (expected_failure == null) {
        const commands = io.commands;
        worker.request.boot_index ^= 1;
        try identity_proof.typeAuthentication(manager, &code, false, clock);
        while (entry.busy()) try service(manager, entry, clock);
        if (worker.failure == null or worker.failure.? != error.RecoveryEnrollmentChanged or io.commands != commands or owner.authentication_ready)
            return error.ResumedForeignEnrollment;
        worker.request.boot_index = request.boot_index;
    }
    try identity_proof.typeAuthentication(manager, &code, false, clock);
    if (!entry.busy() or entry.view.status != .committing) return error.SetupCommitDidNotYield;
    try proveDispatch(manager, previous_task_id, entry, clock);
    while (entry.busy()) try service(manager, entry, clock);
    try erased(entry, worker);
    if (expected_failure) |expected| {
        if (worker.failure == null or worker.failure.? != expected or entry.view.status != .resume_setup or entry.identity != null) return error.InvalidSetupFailure;
        console.print("ZIGOS:TPM2:SETUP:INTERRUPTED\n");
        return null;
    }
    if (!owner.authentication_ready or manager.inputRouterPtr().trusted_entry.? != .authentication or
        owner.authentication.view.status != .entering or owner.session.replay.active or worker.stack != null) return error.SetupDidNotHandOff;
    // The final recovery-record report cannot become sign-in input.
    if (owner.authentication.view.characters != 0 or manager.inputRouterPtr().queued_event_count != 0) return error.SetupLeakedAcrossHandoff;
    console.print("ZIGOS:TPM2:SETUP:VERIFIED\n");
    return owner.bundle.identity;
}

pub fn runBoot(manager: anytype, io: anytype, request: provisioning.Request, pin: []const u8, trusted: provisioning.Pin) !void {
    const clock = identity_proof.ProofClock.init();
    const router = manager.inputRouterPtr();
    const previous_source = router.source;
    const previous_compositor = router.compositor;
    const previous_task_id = router.compositor_task_id;
    router.bindHardwareSource(.{ .poll_report = identity_proof.pollInputReport, .input_proof = identity_proof.noInputProof });
    router.bindCompositor(manager.compositorSessionPtr(), manager.storageServicePtr().task_id);
    const owner = try manager.attachIdentityOwner(io, .{ .owner = request.owner, .parent_handle = request.parent_handle, .anchor_index = request.anchor_index, .boot_index = request.boot_index, .boot_instance = @import("../../../kernel/platform/secure_random.zig").bootInstanceId(), .input_timeout_ticks = 3000, .operation_timeout_ticks = 3000, .lifetime_ticks = 2000 }, clock.now());
    defer {
        manager.clearIdentityOwner();
        identity_proof.sendInput(manager, 0, 0, clock.now());
        if (previous_compositor) |compositor| router.bindCompositor(compositor, previous_task_id) else router.clearCompositor();
        if (previous_source) |source| router.bindHardwareSource(source) else router.clearHardwareSource();
        _ = display.present(manager.compositorSessionPtr());
    }
    _ = manager.servicePendingInputWork(clock.now());
    while (owner.setup.busy() or owner.setup.pending != null) try service(manager, &owner.setup, clock);
    if (!owner.authentication_ready or owner.authentication.view.status != .entering or owner.session.replay.active or
        !std.meta.eql(owner.adapter.recovery_pin.?, trusted) or owner.setup_worker.stack != null) return error.BootOwnerDidNotAuthenticateEnrollment;
    if (owner.policies.policies.countInUse() != 1 or !owner.policies.verify(1) or
        owner.adapter.lifetime_ticks != request.max_session_ticks) return error.BootOwnerMissingPolicy;
    const policy_object = owner.policies.activeForScope(.user, request.owner.serial) orelse return error.BootOwnerMissingPolicy;
    const before = io.commands;
    if (owner.session.unlock(&owner.bundle.identity.capsule, pin, owner.config.boot_instance, clock.now(), request.max_session_ticks + 1, &owner.scratch)) |_|
        return error.AcceptedExcessiveSession
    else |err| if (err != error.IdentityPolicyDenied) return err;
    policy_object.max_session_unlock_age_ticks += 1;
    if (owner.session.unlock(&owner.bundle.identity.capsule, pin, owner.config.boot_instance, clock.now(), 1, &owner.scratch)) |_|
        return error.AcceptedChangedPolicy
    else |err| if (err != error.IdentityPolicyDenied) return err;
    policy_object.max_session_unlock_age_ticks -= 1;
    if (io.commands != before or owner.session.replay.active or !owner.vault.store.empty()) return error.PolicyRejectionTouchedHardware;
    for (0..2) |_| {
        try identity_proof.typeAuthentication(manager, pin, false, clock);
        while (owner.adapter.worker.state == .suspended) {
            if (clock.now() - clock.epoch > 3000) return error.OwnerSignInTimeout;
            manager.serviceAuthenticationClock(clock.now());
            @import("../../../kernel/utils/spin.zig").hint();
        }
        if (owner.authentication.view.status != .hidden or !owner.session.replay.active or
            !std.mem.allEqual(u8, owner.adapter.stack.?.bytes, 0)) return error.OwnerSignInFailed;
        owner.authentication.lock(clock.now());
        router.synchronizeTrustedInput();
        if (owner.session.replay.active or !owner.vault.store.empty() or owner.identities.credential_count != 0)
            return error.OwnerLockRetainedAuthority;
    }
    // Teardown must finish an in-flight PIN command before releasing the owner.
    try identity_proof.typeAuthentication(manager, pin, false, clock);
    if (owner.adapter.worker.state != .suspended) return error.OwnerSignInDidNotYield;
    manager.clearIdentityOwner();
    if (router.trusted_entry != null or manager.identity_owner != null or router.queued_event_count != 0 or
        io.owner_commands != 0 or io.nv_writes != 0 or io.nv_write_locks != 0 or io.da_resets != 0) return error.OwnerBootRequestedAdministration;
    console.print("ZIGOS:TPM2:IDENTITY_POLICY:VERIFIED\n");
    console.print("ZIGOS:TPM2:IDENTITY_OWNER:VERIFIED\n");
}

fn erased(entry: *const setup.Entry, worker: anytype) !void {
    if (!std.mem.allEqual(u8, &entry.value, 0) or !std.mem.allEqual(u8, &entry.first_pin, 0) or
        !std.mem.allEqual(u8, &entry.view.recovery_code, 0) or !std.mem.allEqual(u8, std.mem.asBytes(&entry.recovery_record), 0) or
        (if (worker.stack) |stack| !std.mem.allEqual(u8, stack.bytes, 0) else false) or !std.mem.allEqual(u8, &worker.value, 0) or
        !std.mem.allEqual(u8, std.mem.asBytes(&worker.recovery_record), 0)) return error.RetainedSetupSecrets;
}

fn service(manager: anytype, entry: *const setup.Entry, clock: identity_proof.ProofClock) !void {
    if (clock.now() - clock.epoch > 3000) return error.SetupWorkerTimeout;
    manager.serviceAuthenticationClock(clock.now());
    identity_proof.sendInput(manager, 0, 0, clock.now());
    if (!std.mem.allEqual(u8, &entry.value, 0) or entry.view.characters != 0 or manager.inputRouterPtr().queued_event_count != 0) return error.RetainedSetupInput;
    @import("../../../kernel/utils/spin.zig").hint();
}

fn proveDispatch(manager: anytype, task_id: u64, entry: *const setup.Entry, clock: identity_proof.ProofClock) !void {
    const scheduler = manager.userspaceSchedulerPtr();
    const before = (scheduler.taskDispatchStats(task_id) orelse return error.MissingSetupPeerTask).dispatch_count;
    _ = scheduler.wakeTask(task_id, .external_event, 0, clock.now());
    for (0..manager.runtimePtr().taskSlotCapacity() * 8) |_| {
        _ = manager.runUserspaceScheduler(clock.now());
        if (scheduler.taskDispatchStats(task_id).?.dispatch_count > before) break;
    }
    if (scheduler.taskDispatchStats(task_id).?.dispatch_count == before or !entry.busy()) return error.SetupBlockedUserspace;
}

pub const NoExport = struct {
    pub fn capture(_: @This(), _: *const recovery.Record) !void {
        return error.UnexpectedRecoveryExport;
    }
};
