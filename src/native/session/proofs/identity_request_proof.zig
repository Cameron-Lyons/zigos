//! Verification-only native consent fixture and real Ring3 assertion exchange.
const std = @import("std");
const wire = @import("../../services/identity_assertion_wire.zig");
const identity = @import("../../platform/os_identity.zig");
const probe = @import("../../../userspace/identity_client_proof.zig");

pub fn run(manager: anytype, owner: anytype, io: anytype, clock: anytype) !void {
    const task = manager.runtimePtr().findByInitialComponentLabel("service-client") orelse return error.MissingIdentityClient;
    const task_id = task.id;
    const credential = owner.identities.findCredentialConst(1) orelse return error.MissingIdentityCredential;
    const public_key = credential.credential_public_key;
    const previous_count = credential.assertion_count;
    const previous_writes = io.nv_writes;
    const binding = try manager.grantIdentityCredential(.{ .task_id = task_id, .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example" }, clock.now());
    const challenge = probe.challenge(binding);
    var result: [wire.wire.MAX_BYTES]u8 = undefined;
    var result_len: usize = 0;
    var dispatched_while_pending = false;
    while (true) {
        try deadline(clock);
        const pending = owner.adapter.worker.state == .suspended;
        if (pending and !dispatched_while_pending) _ = manager.userspaceSchedulerPtr().wakeTask(task_id, .external_event, 0, clock.now());
        const before = manager.userspaceSchedulerPtr().taskDispatchStats(task_id).?.dispatch_count;
        _ = manager.runUserspaceScheduler(clock.now());
        if (pending and owner.adapter.worker.state == .suspended and manager.userspaceSchedulerPtr().taskDispatchStats(task_id).?.dispatch_count > before)
            dispatched_while_pending = true;
        manager.serviceAuthenticationClock(clock.now());
        var open = false;
        for (&owner.channels) |*channel| if (channel.kernel != null and channel.task_id == task_id) {
            open = true;
            if (channel.complete) {
                result_len = channel.result_len;
                @memcpy(result[0..result_len], channel.result[0..result_len]);
            }
        };
        const mailbox = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), task_id) orelse return error.MissingIdentityMailbox;
        const acknowledged = std.mem.readInt(u64, mailbox.ui_text_digest[0..8], .little) == binding.endpoint_capability_id;
        if (acknowledged and mailbox.ui_commit_count == 2) {
            if (owner.adapter.failure) |err| return err;
            return switch (mailbox.ui_interaction_hash) {
                1 => error.IdentityClientSendFailed,
                2 => error.IdentityClientReceiveFailed,
                3 => error.IdentityClientPeerMismatch,
                4 => error.IdentityClientMalformedFrame,
                5 => error.IdentityClientOutOfOrder,
                6 => error.IdentityClientMalformedAssertion,
                7 => error.IdentityClientChallengeMismatch,
                else => error.IdentityClientFailed,
            };
        }
        if (acknowledged and mailbox.ui_commit_count == 1 and !open) {
            if (result_len == 0 or mailbox.ui_interaction_hash != probe.receipt(result[0..result_len])) return error.InvalidIdentityReceipt;
            break;
        }
        @import("../../../kernel/utils/spin.zig").hint();
    }
    const assertion = try wire.decode(result[0..result_len]);
    if (!identity.verifyAssertion(&assertion, &public_key) or assertion.assertion_counter != previous_count + 1 or
        !std.mem.eql(u8, assertion.challengeSlice(), &challenge) or !assertion.owner.eql(owner.config.owner) or
        !assertion.device.eql(owner.bundle.identity.enrollment.device) or io.nv_writes != previous_writes + 1 or
        !dispatched_while_pending or !std.mem.allEqual(u8, owner.adapter.stack.?.bytes, 0)) return error.InvalidIdentityRequestAssertion;

    // Reuse the real application after retiring the first endpoint. Lock while
    // its next command is suspended; no result or partial reply may escape.
    _ = try manager.grantIdentityCredential(.{ .task_id = task_id, .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example" }, clock.now());
    const commands = io.commands;
    while (owner.adapter.worker.state != .suspended or io.commands == commands) {
        try deadline(clock);
        _ = manager.runUserspaceScheduler(clock.now());
    }
    owner.authentication.lock(clock.now());
    manager.inputRouterPtr().synchronizeTrustedInput();
    if (owner.session.replay.active or std.mem.allEqual(u8, owner.adapter.stack.?.bytes, 0)) return error.UnsafeIdentityCancellation;
    while (owner.authentication.busy()) {
        try deadline(clock);
        manager.serviceAuthenticationClock(clock.now());
    }
    _ = manager.runUserspaceScheduler(clock.now());
    for (&owner.channels) |*channel| if (channel.kernel != null) return error.RetainedIdentityGrant;
    if (!std.mem.allEqual(u8, owner.adapter.stack.?.bytes, 0) or owner.adapter.assertion_result != null or
        !owner.vault.store.empty() or io.nv_writes != previous_writes + 1) return error.RetainedIdentityRequestAuthority;
    const mailbox = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), task_id) orelse return error.MissingIdentityMailbox;
    if (mailbox.ui_commit_count == 1) return error.PublishedCancelledIdentityRequest;
    @import("../../../kernel/utils/console.zig").print("ZIGOS:TPM2:IDENTITY_REQUEST:VERIFIED\n");
}

fn deadline(clock: anytype) !void {
    if (clock.now() - clock.epoch > 3000) return error.IdentityRequestTimeout;
}
