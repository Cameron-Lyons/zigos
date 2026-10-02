const std = @import("std");
const exchange = @import("peer_attestation.zig");
const peer = @import("peer_channel.zig");
const attest = @import("../platform/tpm_attestation.zig");
const quote = @import("../platform/tpm2_quote.zig");
const Base = @import("object_transfer_test.zig").Fixture;
const Entropy = struct {
    pub fn random(_: *@This(), out: []u8) !void {
        @memset(out, 0x45);
    }
};

fn pending(lifetime: u32) !attest.Pending {
    const evidence = try quote.testing.QuoteFixture.initFor(@splat(1), @splat(2));
    const label: [64]u8 = @splat('p');
    const enrollment = try attest.Enrollment.init(.{ .kind = .device, .serial = 22 }, evidence.identity, 9, &label);
    var entropy = Entropy{};
    return attest.Pending.init(&entropy, enrollment, @splat(2), .{ .remote_party = &label, .policy_label = &label, .revoked_generations = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } }, 200, lifetime);
}

fn rejectSend(_: [6]u8, _: []const u8) bool {
    return false;
}
fn deliver(to: *exchange.Exchange, packet: []const u8, now: u64) !void {
    try std.testing.expect(to.admit(packet, now));
    try std.testing.expect(to.service(now, @splat(0), rejectSend));
}

test "peer attestation reassembles reordered ciphertext exactly once and survives corrupted and duplicate packets" {
    const base = try Base.init();
    defer base.deinit();
    var verifier = try pending(7000);
    var a = try exchange.Exchange.init(&base.sender, .{ .verify = &verifier }, "", 20, 1000);
    defer a.close();
    var b = try exchange.Exchange.init(&base.recipient, .{ .prove = &verifier.enrollment }, "", 20, 1000);
    defer b.close();
    try std.testing.expectEqual(@as(u8, 3), a.outgoing_count);
    // Each corrupted ciphertext is ignored without committing a replay bit or
    // invoking the owner's quote work. Use separate ticks to respect ingress limits.
    for (0..a.outgoing_lens[2]) |index| {
        var damaged = a.outgoing[2];
        damaged[index] ^= 1;
        if (b.admit(damaged[0..a.outgoing_lens[2]], 20 + index)) _ = b.service(20 + index, @splat(0), rejectSend);
        try std.testing.expect(b.quoteChallenge(20 + index) == null and b.active());
    }
    for ([_]usize{ 2, 2, 1, 0 }) |index| try deliver(&b, a.outgoing[index][0..a.outgoing_lens[index]], 300);
    const challenge = b.quoteChallenge(300) orelse return error.MissingQuoteChallenge;
    try std.testing.expectEqualDeep(verifier.challenge, challenge);
    const evidence = try quote.testing.QuoteFixture.initFor(challenge.qualifyingData(), challenge.approved_pcr11);
    try b.completeQuote(&evidence.evidence, 300);
    try std.testing.expectError(error.InvalidState, b.completeQuote(&evidence.evidence, 300));
    try std.testing.expect(!b.ready());
    const nonce_before = base.recipient.crypto.transport.send.nonce;
    try std.testing.expect(b.service(300, @splat(0), rejectSend));
    try std.testing.expectEqual(nonce_before, base.recipient.crypto.transport.send.nonce);
    for ([_]usize{ 1, 1, 0 }) |index| try deliver(&a, b.outgoing[index][0..b.outgoing_lens[index]], 301);
    try std.testing.expect(a.ready() and verifier.verifier.consumed);
    try std.testing.expectEqualDeep(verifier.enrollment.device, a.accepted.?.device);
    try deliver(&b, a.outgoing[0][0..a.outgoing_lens[0]], 302);
    try std.testing.expect(b.ready() and b.quoteChallenge(302) == null);
    // Repeat the completing quote ciphertext after acceptance: reuse the cached
    // authenticated ACK without spending a new nonce or verifying a consumed quote.
    a.ack_needed = false;
    try deliver(&a, b.outgoing[0][0..b.outgoing_lens[0]], 303);
    try std.testing.expect(a.ack_needed and a.ready());
    try std.testing.expectEqual(@as(u64, 4), base.sender.crypto.transport.send.nonce);
}

test "peer attestation rejects authenticated malformed fragments before quote work" {
    for (0..7) |variant| {
        const base = try Base.init();
        defer base.deinit();
        var verifier = try pending(1000);
        var a = try exchange.Exchange.init(&base.sender, .{ .verify = &verifier }, "", 20, 200);
        defer a.close();
        var b = try exchange.Exchange.init(&base.recipient, .{ .prove = &verifier.enrollment }, "", 20, 200);
        defer b.close();
        var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
        // Decode using a temporary receiver copy to leave its replay window intact.
        var decoder = base.recipient;
        defer decoder.close();
        const data = try decoder.openAttestation(&plaintext, a.outgoing[0][0..a.outgoing_lens[0]], 20);
        switch (variant) {
            0 => plaintext[0] ^= 1,
            1 => plaintext[5] = 2,
            2 => @memset(plaintext[6..8], 0),
            3 => @memset(plaintext[6..8], 0xff),
            4 => plaintext[8] = 3,
            5 => plaintext[9] = 4,
            6 => plaintext[9] = 0,
            else => unreachable,
        }
        var packet: [peer.MAX_FRAME]u8 = undefined;
        try deliver(&b, try base.sender.sealAttestation(&packet, data, 20), 20);
        try std.testing.expect(!b.active() and b.quoteChallenge(20) == null);
        try std.testing.expect(std.mem.allEqual(u8, &b.received, 0));
    }
}

test "peer attestation challenge deadlines and rollback terminate idle work" {
    for (0..3) |variant| {
        const base = try Base.init();
        defer base.deinit();
        var verifier = try pending(1000);
        var a = try exchange.Exchange.init(&base.sender, .{ .verify = &verifier }, "", 20, 200);
        defer a.close();
        // No outbound packet remains due; the verifier deadline must still wake it.
        a.outgoing_count = 0;
        try std.testing.expectEqual(@as(?u64, 120), a.nextWake());
        const now: u64 = switch (variant) {
            0 => 120,
            1 => 19,
            else => std.math.maxInt(u64),
        };
        try std.testing.expect(a.service(now, @splat(0), rejectSend));
        try std.testing.expect(!a.active() and !base.sender.established() and verifier.verifier.consumed);
        try std.testing.expect(a.nextWake() == null);
    }
}

test "peer attestation rejects session substitution and mixed fragment contexts" {
    for (0..4) |variant| {
        const base = try Base.init();
        defer base.deinit();
        var verifier = try pending(1000);
        var a = try exchange.Exchange.init(&base.sender, .{ .verify = &verifier }, "", 20, 200);
        defer a.close();
        var b = try exchange.Exchange.init(&base.recipient, .{ .prove = &verifier.enrollment }, "", 20, 200);
        defer b.close();
        var decoder = base.recipient;
        defer decoder.close();
        for (0..a.outgoing_count) |index| {
            var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
            const data = try decoder.openAttestation(&plaintext, a.outgoing[index][0..a.outgoing_lens[index]], 20);
            if (index == 0 and variant < 2) {
                // Canonical record offset 70 is the Noise binding; offset 6 is
                // the verifier nonce. Neither may change under the exchange ID.
                plaintext[26 + (if (variant == 0) @as(usize, 70) else 6)] ^= 1;
            }
            if (index == 1 and variant >= 2) plaintext[if (variant == 2) @as(usize, 6) else 10] ^= 1;
            var packet: [peer.MAX_FRAME]u8 = undefined;
            try deliver(&b, try base.sender.sealAttestation(&packet, data, 20), 20);
            if (!b.active()) break;
        }
        try std.testing.expect(!b.active() and b.quoteChallenge(20) == null);
        try std.testing.expect(std.mem.allEqual(u8, &b.received, 0));
    }
}
