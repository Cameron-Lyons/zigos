//! Separate-guest verification with fixture enrollment keys. The channel itself
//! uses fresh independent key pairs; no traffic key is installed by the harness.
const std = @import("std");
const channel_mod = @import("../sync/peer_channel.zig");
const sync_service = @import("../sync/sync_service.zig");
const network = @import("../drivers/network_driver_task.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const support = @import("scenario_support.zig");
const markers = @import("../../kernel/boot/markers.zig");
const confirmation = "zigos peer channel confirmed";

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
    var channel = channel_mod.Channel.init(service.deviceGraph(), signing.publicKey(support.user_root_signer) catch return false, if (initiator) laptop else tablet, if (initiator) tablet else laptop, signer, if (initiator) .initiator else .responder) catch |err| {
        support.common.printBootMarker(@errorName(err));
        return false;
    };
    defer channel.close();
    var outgoing: [channel_mod.MAX_FRAME]u8 = undefined;
    var outgoing_len: usize = 0;
    var last_handshake: [channel_mod.MAX_FRAME]u8 = undefined;
    var last_handshake_len: usize = 0;
    if (initiator) {
        outgoing_len = (channel.writeHandshake(&outgoing) catch return false).len;
        _ = network.sendActiveFrame(peer_mac, outgoing[0..outgoing_len]);
    }
    var received: [1500]u8 = undefined;
    var plaintext: [channel_mod.MAX_PAYLOAD]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext);
    var confirmed = false;
    const deadline = clock.afterMilliseconds(30_000);
    var resend = clock.afterMilliseconds(20);
    while (!deadline.expired()) {
        if (confirmed) {
            if (!@import("peer_object_proof.zig").run(context, service, &channel, peer_mac, initiator, outgoing[0..outgoing_len])) return false;
            if (@import("../../kernel/drivers/virtio_net_hw.zig").interruptCount() == 0) return false;
            support.common.printBootMarker(markers.sync_peer_authenticated);
            support.common.printBootMarker(markers.sync_peer_ciphertext_rejected);
            support.common.printBootMarker(markers.sync_peer_replay_rejected);
            support.common.printBootMarker(markers.sync_native_driver_peer_frame_received);
            return true;
        }
        if (resend.expired()) {
            if (outgoing_len != 0) _ = network.sendActiveFrame(peer_mac, outgoing[0..outgoing_len]);
            resend = clock.afterMilliseconds(20);
        }
        const result = network.receiveActiveFrame(&received);
        if (result.status == .failed) return false;
        if (result.status != .frame) {
            std.atomic.spinLoopHint();
            continue;
        }
        const frame = received[0..result.length];
        if (frame.len < channel_mod.HEADER or frame.len > channel_mod.MAX_FRAME or !std.mem.startsWith(u8, frame, channel_mod.MAGIC)) continue;
        if (frame[5] != 4) {
            // Retransmission repeats the exact encrypted bytes. It never runs
            // the handshake again with a reused ephemeral key or AEAD nonce.
            if (last_handshake_len == frame.len and std.mem.eql(u8, last_handshake[0..last_handshake_len], frame)) {
                // A peer may have queued many retries while this guest was
                // booting. Let the bounded timer resend our cached reply;
                // answering each duplicate would amplify that burst.
                continue;
            }
            channel.readHandshake(frame) catch |err| {
                support.common.printBootMarker(@errorName(err));
                return false;
            };
            @memcpy(last_handshake[0..frame.len], frame);
            last_handshake_len = frame.len;
            outgoing_len = if (channel.established())
                (channel.seal(&outgoing, confirmation) catch return false).len
            else
                (channel.writeHandshake(&outgoing) catch return false).len;
            _ = network.sendActiveFrame(peer_mac, outgoing[0..outgoing_len]);
            continue;
        }
        if (!channel.established()) continue;
        if (!confirmed) {
            var tampered: [channel_mod.MAX_FRAME]u8 = undefined;
            @memcpy(tampered[0..frame.len], frame);
            tampered[frame.len - 1] ^= 1;
            @memset(&plaintext, 0xa5);
            if (channel.open(&plaintext, tampered[0..frame.len])) |_| return false else |err| {
                if (err != error.AuthenticationFailed or !std.mem.allEqual(u8, &plaintext, 0)) return false;
            }
        }
        const payload = channel.open(&plaintext, frame) catch |err| {
            if (err != error.ReplayRejected) return false;
            continue;
        };
        if (!std.mem.eql(u8, payload, confirmation)) return false;
        if (channel.open(&plaintext, frame)) |_| return false else |err| {
            if (err != error.ReplayRejected) return false;
        }
        if (!confirmed) {
            confirmed = true;
            if (initiator) outgoing_len = (channel.seal(&outgoing, confirmation) catch return false).len;
        }
        _ = network.sendActiveFrame(peer_mac, outgoing[0..outgoing_len]);
    }
    support.common.printBootMarker("ZIGOS:SYNC:PEER_CHANNEL:TIMEOUT");
    return false;
}
