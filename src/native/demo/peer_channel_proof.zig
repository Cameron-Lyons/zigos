//! Separate-guest verification with fixture enrollment keys. The channel itself
//! uses fresh independent key pairs; no traffic key is installed by the harness.
const std = @import("std");
const channel_mod = @import("../sync/peer_channel.zig");
const sync_service = @import("../sync/sync_service.zig");
const handshake_mod = @import("../sync/peer_handshake.zig");
const timer = @import("../../kernel/timer/timer.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const support = @import("scenario_support.zig");
const markers = @import("../../kernel/boot/markers.zig");

pub fn run(context: *support.Context, service: *sync_service.Service, local_mac: [6]u8, peer_mac: [6]u8, laptop: principal.PrincipalId, tablet: principal.PrincipalId) bool {
    if (@import("builtin").target.os.tag != .freestanding) return false;
    const clock = @import("../../kernel/timer/tsc_clock.zig");
    const x86 = @import("../../arch/x86.zig");
    const was_enabled = x86.interruptsEnabled();
    x86.sti();
    defer if (!was_enabled) x86.cli();
    const initiator = local_mac[5] == 1;
    const signer = if (initiator)
        signing.SignerIdentity{ .label = "local-device", .seed = signing.seedFromByte(0x92) }
    else
        signing.SignerIdentity{ .label = "tablet-device-v2", .seed = signing.seedFromByte(0x94) };
    var key_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const device_key = key_fixture.init(context.session_user, service.owner, service.task_id, signer) catch return false;
    var channel = channel_mod.Channel.init(service.deviceGraph(), signing.publicKey(support.user_root_signer) catch return false, if (initiator) laptop else tablet, if (initiator) tablet else laptop, device_key.key, if (initiator) .initiator else .responder, 311) catch |err| {
        support.common.printBootMarker(@errorName(err));
        return false;
    };
    defer channel.close();
    var handshake = handshake_mod.Handshake.init(&channel, service, context.capability_table, support.mintSyncAuthority(context, 311), peer_mac, 311 + handshake_mod.MAX_LIFETIME_TICKS) catch return false;
    const manager = @import("../session/session_manager.zig").system();
    manager.attachPeerHandshake(&handshake, 311) catch return false;
    defer manager.detachPeerHandshake(&handshake);
    // Queue one establishment operation, then stop its owning task. No
    // handshake state or reserved receive ownership may survive suspension.
    _ = manager.servicePeerWork(311);
    if (!(context.runtime.suspendTask(service.task_id, 311) catch return false)) return false;
    _ = manager.servicePeerWork(311);
    const retired = !handshake.active() and channel.crypto == .closed and !manager.peer_handshakes.hasSessions();
    const resumed = context.runtime.resumeTask(service.task_id, 311) catch false;
    if (!retired or !resumed) return false;
    support.common.printBootMarker(markers.sync_peer_handshake_retired);
    channel = channel_mod.Channel.init(service.deviceGraph(), signing.publicKey(support.user_root_signer) catch return false, if (initiator) laptop else tablet, if (initiator) tablet else laptop, device_key.key, if (initiator) .initiator else .responder, 311) catch return false;
    handshake = handshake_mod.Handshake.init(&channel, service, context.capability_table, support.mintSyncAuthority(context, 311), peer_mac, 311 + handshake_mod.MAX_LIFETIME_TICKS) catch return false;
    manager.attachPeerHandshake(&handshake, 311) catch return false;
    support.common.printBootMarker(markers.sync_peer_handshake_admitted);
    timer.synchronize();
    const start_tick = timer.getTicks();
    const deadline = clock.afterMilliseconds(10_000);
    while (!deadline.expired()) {
        timer.synchronize();
        const now = 311 + (timer.getTicks() - start_tick);
        _ = manager.servicePendingNetworkWork(now);
        _ = manager.servicePeerWork(now);
        if (!handshake.active()) {
            support.common.printBootMarker("ZIGOS:SYNC:PEER_CHANNEL:RETIRED");
            return false;
        }
        if (!handshake.complete()) {
            std.atomic.spinLoopHint();
            continue;
        }
        if (!rejectInvalidConfirmation(&channel, handshake.last_received[0..handshake.last_received_len], now)) return false;
        var outgoing: [channel_mod.MAX_FRAME]u8 = undefined;
        const confirmation = manager.takePeerHandshake(&handshake, &outgoing, now) catch return false;
        if (manager.peer_handshakes.hasSessions() or !channel.established()) return false;
        support.common.printBootMarker(markers.sync_peer_handshake_completed);
        if (!@import("peer_object_proof.zig").run(context, service, &channel, peer_mac, initiator, confirmation)) return false;
        if (@import("../../kernel/drivers/virtio_net_hw.zig").interruptCount() == 0) return false;
        support.common.printBootMarker(markers.sync_peer_authenticated);
        support.common.printBootMarker(markers.sync_peer_ciphertext_rejected);
        support.common.printBootMarker(markers.sync_peer_replay_rejected);
        support.common.printBootMarker(markers.sync_native_driver_peer_frame_received);
        return true;
    }
    support.common.printBootMarker("ZIGOS:SYNC:PEER_CHANNEL:TIMEOUT");
    return false;
}

fn rejectInvalidConfirmation(channel: *channel_mod.Channel, received: []const u8, now: u64) bool {
    if (received.len <= channel_mod.DATA_HEADER or received[5] != 4) return false;
    var tampered: [channel_mod.MAX_FRAME]u8 = undefined;
    @memcpy(tampered[0..received.len], received);
    // Use an unseen nonce so authentication, rather than the replay window,
    // rejects this mutation of an actual remotely generated confirmation.
    std.mem.writeInt(u64, tampered[channel_mod.HEADER + 16 ..][0..8], channel.receive_highest + 1, .little);
    tampered[received.len - 1] ^= 1;
    var plaintext: [channel_mod.MAX_PAYLOAD]u8 = @splat(0xa5);
    defer std.crypto.secureZero(u8, &plaintext);
    if (channel.open(&plaintext, tampered[0..received.len], now)) |_| return false else |err| {
        if (err != error.AuthenticationFailed or !std.mem.allEqual(u8, &plaintext, 0)) return false;
    }
    if (channel.open(&plaintext, received, now)) |_| return false else |err| {
        if (err != error.ReplayRejected) return false;
    }
    return true;
}
