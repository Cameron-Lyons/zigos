const std = @import("std");
const admission = @import("peer_admission.zig");
const peer = @import("peer_channel.zig");
const transfer = @import("object_transfer.zig");
const Fixture = @import("object_transfer_test.zig").Fixture;
const mac = [6]u8{ 2, 0, 0, 0, 0, 1 };

const Sender = struct {
    var accepted = true;
    var calls: usize = 0;
    var bytes: [peer.MAX_FRAME]u8 = undefined;
    var len: usize = 0;

    fn reset() void {
        accepted = true;
        calls = 0;
        len = 0;
    }

    fn send(destination: [6]u8, data: []const u8) bool {
        std.debug.assert(std.mem.eql(u8, &destination, &mac));
        calls += 1;
        @memcpy(bytes[0..data.len], data);
        len = data.len;
        return accepted;
    }
};

fn session(f: *Fixture) !admission.Session {
    return admission.Session.init(&f.recipient, &f.receiver, f.signer, f.authority, mac, 100);
}

fn begin(f: *Fixture, payload: []const u8, out: []u8) ![]const u8 {
    return transfer.encodeBegin(out, .{ .id = 7, .workspace_id = f.receiver.binding.workspace_id, .object_id = f.receiver.binding.object_id, .expected_version = f.disk.original_version_id, .length = @intCast(payload.len), .digest = transfer.digest(payload) });
}

fn admit(pool: *admission.Sessions, f: *Fixture, message: []const u8, now: u64) !void {
    var wire: [peer.MAX_FRAME]u8 = undefined;
    try std.testing.expect(pool.admit(try f.sender.seal(&wire, message, now), now));
    try std.testing.expectEqual(@as(usize, 1), pool.service(now, Sender.send));
}

fn receipt(pool: *admission.Sessions, f: *Fixture, now: u64) !transfer.Progress {
    try std.testing.expectEqual(@as(usize, 1), pool.service(now, Sender.send));
    var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
    return transfer.decodeProgress(try f.sender.open(&plaintext, Sender.bytes[0..Sender.len], now));
}

test "peer admission dispatches encrypted writes and sends receipts only after a durable checkpoint" {
    const f = try Fixture.init();
    defer f.deinit();
    var s = try session(f);
    var pool = admission.Sessions{};
    defer pool.deinit();
    try pool.attach(&s, 20);
    Sender.reset();
    var message: [peer.MAX_PAYLOAD]u8 = undefined;
    try admit(&pool, f, try begin(f, "through admission", &message), 20);
    try std.testing.expectEqual(@as(usize, 0), Sender.calls);
    try std.testing.expect(!(try receipt(&pool, f, 20)).durable());
    try admit(&pool, f, try transfer.encodeChunk(&message, 7, 0, "through admission"), 21);
    try std.testing.expectEqual(@as(u32, 17), (try receipt(&pool, f, 21)).received);
    f.disk.fail_flushes = true;
    try admit(&pool, f, try transfer.encodeCommit(&message, 7), 22);
    try std.testing.expectEqual(@as(u16, 0), s.outgoing_len);
    try std.testing.expectEqual(@as(usize, 0), pool.service(22, Sender.send));
    const versions = f.disk.service.versionCount();
    f.disk.fail_flushes = false;
    try admit(&pool, f, try transfer.encodeCommit(&message, 7), 23);
    const progress = try receipt(&pool, f, 23);
    try std.testing.expect(progress.durable());
    try std.testing.expectEqual(versions, f.disk.service.versionCount());
    f.disk.crash();
    try std.testing.expectEqualStrings("through admission", try f.disk.text());
}

test "peer admission caches backpressured ciphertext and waits for its retry deadline" {
    const f = try Fixture.init();
    defer f.deinit();
    var s = try session(f);
    var pool = admission.Sessions{};
    defer pool.deinit();
    try pool.attach(&s, 20);
    Sender.reset();
    Sender.accepted = false;
    var message: [peer.MAX_PAYLOAD]u8 = undefined;
    try admit(&pool, f, try begin(f, "pending", &message), 20);
    const nonce = f.recipient.crypto.transport.send.nonce;
    try std.testing.expectEqual(@as(usize, 1), pool.service(20, Sender.send));
    const cached = Sender.bytes;
    try std.testing.expect(!pool.hasReadyWork(20));
    try std.testing.expectEqual(@as(u64, 22), pool.nextWake().?);
    for (0..8) |_| try std.testing.expectEqual(@as(usize, 0), pool.service(21, Sender.send));
    try std.testing.expectEqual(@as(usize, 1), Sender.calls);
    Sender.accepted = true;
    _ = try receipt(&pool, f, 22);
    try std.testing.expectEqualSlices(u8, cached[0..Sender.len], Sender.bytes[0..Sender.len]);
    try std.testing.expectEqual(nonce, f.recipient.crypto.transport.send.nonce);
    try std.testing.expect(!pool.hasReadyWork(22));
    try std.testing.expectEqual(@as(u64, 100), pool.nextWake().?);
}

test "peer admission rechecks revoked authority before sending a cached reply and scrubs uploads" {
    for (0..5) |variant| {
        const f = try Fixture.init();
        defer f.deinit();
        var s = try session(f);
        var pool = admission.Sessions{};
        defer pool.deinit();
        try pool.attach(&s, 20);
        Sender.reset();
        var message: [peer.MAX_PAYLOAD]u8 = undefined;
        try admit(&pool, f, try begin(f, "private", &message), 20);
        _ = try receipt(&pool, f, 20);
        try admit(&pool, f, try transfer.encodeChunk(&message, 7, 0, "private"), 21);
        const sent = Sender.calls;
        switch (variant) {
            0 => try f.capabilities.revokeGrant(f.receiver.binding.peer_capability_id),
            1 => try f.capabilities.revokeGrant(f.authority.capability_id),
            2 => f.signing_fixture.service.findHandle(f.signer.key.handle_id).?.revoked = true,
            3 => f.receiver_keys.service.findHandle(f.recipient.signer.handle_id).?.revoked = true,
            else => s.expires_at = 22,
        }
        _ = pool.service(22, Sender.send);
        try std.testing.expectEqual(sent, Sender.calls);
        try std.testing.expect(!s.active and f.recipient.crypto == .closed and !pool.hasSessions());
        try std.testing.expect(f.receiver.transfer == null);
        try std.testing.expect(std.mem.allEqual(u8, f.scratch[0..7], 0));
        try std.testing.expect(std.mem.allEqual(u8, &s.incoming, 0) and std.mem.allEqual(u8, &s.outgoing, 0));
    }
}

test "peer admission rejects unknown routing and bounds known peer floods before cryptographic dispatch" {
    const f = try Fixture.init();
    defer f.deinit();
    var s = try session(f);
    var pool = admission.Sessions{};
    defer pool.deinit();
    try pool.attach(&s, 20);
    try std.testing.expectError(error.PeerAlreadyAdmitted, pool.attach(&s, 20));
    Sender.reset();
    var wire: [peer.MAX_FRAME]u8 = undefined;
    const frame = try f.sender.seal(&wire, "unauthenticated flood", 20);
    wire[6] ^= 1;
    for (0..100) |_| try std.testing.expect(!pool.admit(frame, 20));
    try std.testing.expectEqual(@as(u8, 0), s.admitted_this_tick);
    wire[6] ^= 1;
    wire[frame.len - 1] ^= 1;
    for (0..admission.MAX_FRAMES_PER_TICK) |_| {
        try std.testing.expect(pool.admit(frame, 20));
        try std.testing.expect(!pool.admit(frame, 20));
        try std.testing.expectEqual(@as(usize, 1), pool.service(20, Sender.send));
    }
    try std.testing.expect(!pool.admit(frame, 20));
    try std.testing.expectEqual(@as(usize, 0), Sender.calls);
    try std.testing.expect(f.recipient.established());
    try std.testing.expect(pool.admit(frame, 21));
    pool.detach(&s);
    try std.testing.expect(!s.active and pool.nextWake() == null and !pool.hasReadyWork(21));
}
