//! Verification-only origin fixture, trusted HID consent and real Ring3 exchange.
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
    const binding = try approve(manager, owner, task_id, clock);
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
    _ = try approve(manager, owner, task_id, clock);
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

fn approve(manager: anytype, owner: anytype, task_id: u64, clock: anytype) !@import("../../../userspace/identity_protocol.zig").Binding {
    const input = @import("identity_session_proof.zig");
    const request = @import("../../services/identity_owner.zig").CredentialRequest{ .task_id = task_id, .credential_id = 1, .relying_party_id = "session.example", .origin = "https://session.example" };
    // First reject using the default action. No endpoint may exist before the
    // user sees and explicitly changes the native decision to Allow once.
    try manager.requestIdentityCredential(request, clock.now());
    for (&owner.channels) |*channel| if (channel.kernel != null) return error.PrematureIdentityGrant;
    if (!owner.authentication.view.review.presented) return error.UnpresentedIdentityReview;
    const frame = @import("../../../kernel/platform/framebuffer_hw.zig").frame() orelse return error.MissingIdentityReviewFrame;
    for ("https://session.example", 0..) |byte, index| {
        if (frame.cells[11 * frame.columns + index].character != byte) return error.IncorrectIdentityReviewOrigin;
    }
    input.sendInput(manager, 0, 0, clock.now());
    input.sendInput(manager, 0x28, 0, clock.now());
    if (owner.consent.kernel != null or owner.authentication.capturing()) return error.UncancelledIdentityReview;
    for (&owner.channels) |*channel| if (channel.kernel != null) return error.DeniedIdentityGrant;
    try manager.requestIdentityCredential(request, clock.now());
    input.sendInput(manager, 0, 0, clock.now());
    input.sendInput(manager, 0x2b, 0, clock.now());
    input.sendInput(manager, 0, 0, clock.now());
    if (!owner.authentication.view.review.allow_selected or !owner.authentication.view.review.presented) return error.UnselectedIdentityConsent;
    input.sendInput(manager, 0x28, 0, clock.now());
    if (owner.consent.kernel != null or owner.authentication.capturing() or manager.inputRouterPtr().queued_event_count != 0) return error.UnconsumedIdentityConsent;
    const mailbox = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), task_id) orelse return error.MissingIdentityMailbox;
    const binding = mailbox.identityBinding();
    if (!binding.isValid()) return error.MissingApprovedIdentityBinding;
    return .{ .endpoint_capability_id = binding.endpoint_capability_id, .service_endpoint_id = binding.service_endpoint_id, .credential_id = binding.credential_id };
}

fn deadline(clock: anytype) !void {
    if (clock.now() - clock.epoch > 3000) return error.IdentityRequestTimeout;
}
