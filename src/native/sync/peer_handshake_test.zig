const std = @import("std");
const peer = @import("peer_channel.zig");
const handshake = @import("peer_handshake.zig");
const sync = @import("sync_service.zig");
const capability = @import("../kernel_api/capability.zig");
const authority = @import("../services/service_authority.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const keys = @import("../../tests/fixtures/document_signer.zig");
const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
const holder = principal.PrincipalId{ .kind = .service, .serial = 700 };
const root_key = signing.SignerIdentity{ .label = "root", .seed = @splat(0x31) };
const identities = [2]signing.SignerIdentity{ .{ .label = "alice", .seed = @splat(0x32) }, .{ .label = "bob", .seed = @splat(0x33) } };
const mac = [6]u8{ 2, 0, 0, 0, 0, 1 };

const Fixture = struct {
    var active: *Fixture = undefined;
    services: [2]sync.Service = undefined,
    capabilities: [2]capability.CapabilityTable = .{ .init(), .init() },
    contexts: [2]authority.Context = undefined,
    keys: [2]keys.Fixture = .{ .{}, .{} },
    channels: [2]peer.Channel = undefined,
    handshakes: [2]handshake.Handshake = undefined,
    pools: [2]handshake.Handshakes = .{ .{}, .{} },
    now: u64 = 20,
    drop_leg: ?usize = null,
    dropped: bool = false,
    blocked: bool = false,
    consistent_retries: bool = true,
    calls: [5]usize = @splat(0),
    first: [5][peer.MAX_FRAME]u8 = undefined,
    first_len: [5]usize = @splat(0),

    fn init(offset: u64) !*Fixture {
        const f = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(f);
        f.* = .{};
        const devices = [2]principal.PrincipalId{ .{ .kind = .device, .serial = offset + 11 }, .{ .kind = .device, .serial = offset + 22 } };
        for (0..2) |i| {
            const service = &f.services[i];
            service.* = .init(700, 701, holder);
            _ = try service.ensureUserRoot(owner, "owner", root_key);
            for (0..2) |d| _ = try service.enrollTrustedDevice(owner, devices[d], identities[d].label, root_key, identities[d], 1);
            const cap = try f.capabilities[i].mintBootRoot(.{
                .holder = holder,
                .issuer = .{ .kind = .policy_authority, .serial = 1 },
                .target = .{ .kind = .service, .id = 700 },
                .rights = .{ .service = .{ .endpoint_connect = true } },
                .scope = .{ .task_id = 701, .local_only = true, .broker_only = true },
                .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 1_000 },
                .audit = .{},
            });
            f.contexts[i] = .{ .task_id = 701, .principal = holder, .capability_id = cap.id, .now_ticks = 20 };
            const key = try f.keys[i].init(owner, holder, 701, identities[i]);
            f.channels[i] = try peer.Channel.init(service.deviceGraph(), try signing.publicKey(root_key), devices[i], devices[1 - i], key.key, if (i == 0) .initiator else .responder, 20);
            f.handshakes[i] = try handshake.Handshake.init(&f.channels[i], service, &f.capabilities[i], f.contexts[i], mac, 500);
        }
        return f;
    }

    fn deinit(f: *Fixture) void {
        for (&f.pools) |*pool| pool.deinit();
        for (&f.channels) |*channel| channel.close();
        std.testing.allocator.destroy(f);
    }

    fn attach(f: *Fixture) !void {
        for (0..2) |i| try f.pools[i].attach(&f.handshakes[i], f.now);
    }

    fn sendA(destination: [6]u8, data: []const u8) bool {
        return active.send(0, destination, data);
    }
    fn sendB(destination: [6]u8, data: []const u8) bool {
        return active.send(1, destination, data);
    }
    fn send(f: *Fixture, source: usize, destination: [6]u8, data: []const u8) bool {
        std.debug.assert(std.mem.eql(u8, &mac, &destination));
        const leg: usize = if (data[5] == 4) (if (source == 0) @as(usize, 4) else 3) else data[5] - 1;
        if (f.first_len[leg] == 0) {
            @memcpy(f.first[leg][0..data.len], data);
            f.first_len[leg] = data.len;
        } else if (!std.mem.eql(u8, f.first[leg][0..f.first_len[leg]], data)) f.consistent_retries = false;
        f.calls[leg] += 1;
        if (f.blocked) return false;
        if (f.drop_leg == leg and !f.dropped) {
            f.dropped = true;
            return true;
        }
        _ = f.pools[1 - source].admit(data, f.now);
        // Duplicate bursts cannot queue additional work or immediate replies.
        for (0..12) |_| _ = f.pools[1 - source].admit(data, f.now);
        return true;
    }

    fn tick(f: *Fixture) void {
        active = f;
        _ = f.pools[0].service(f.now, sendA, 2);
        _ = f.pools[1].service(f.now, sendB, 2);
        f.now += 1;
    }

    fn connect(f: *Fixture) !void {
        for (0..200) |_| {
            f.tick();
            if (f.handshakes[0].complete() and f.handshakes[1].complete()) return;
        }
        return error.HandshakeTimeout;
    }
};

test "peer handshake recovers each lost flight with identical bytes despite duplicate bursts" {
    for (0..5) |leg| {
        const f = try Fixture.init(0);
        defer f.deinit();
        try f.attach();
        f.drop_leg = leg;
        try f.connect();
        try std.testing.expect(f.dropped and f.calls[leg] >= 2 and f.consistent_retries);
        for (0..2) |i| {
            var confirmation: [peer.MAX_FRAME]u8 = undefined;
            const cached = try f.pools[i].take(&f.handshakes[i], &confirmation, f.now);
            try std.testing.expect(cached.len > peer.DATA_HEADER and cached[5] == 4);
            try std.testing.expect(f.channels[i].established() and !f.pools[i].hasSessions());
            try std.testing.expect(std.mem.allEqual(u8, &f.handshakes[i].incoming, 0) and std.mem.allEqual(u8, &f.handshakes[i].outgoing, 0));
        }
        var wire: [peer.MAX_FRAME]u8 = undefined;
        var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
        try std.testing.expectEqualStrings("application after admission", try f.channels[1].open(&plaintext, try f.channels[0].seal(&wire, "application after admission", f.now), f.now));
    }
}

test "peer handshake handoff retains the final confirmation for a lost delivery" {
    const f = try Fixture.init(0);
    defer f.deinit();
    try f.attach();
    f.drop_leg = 4;
    for (0..100) |_| {
        f.tick();
        if (f.handshakes[0].complete()) break;
    }
    try std.testing.expect(f.dropped and !f.handshakes[1].complete());
    var confirmation: [peer.MAX_FRAME]u8 = undefined;
    const cached = try f.pools[0].take(&f.handshakes[0], &confirmation, f.now);
    try std.testing.expect(f.pools[1].admit(cached, f.now));
    _ = f.pools[1].service(f.now, Fixture.sendB, 2);
    try std.testing.expect(f.handshakes[1].complete());
    try std.testing.expect(f.consistent_retries);
}

test "peer handshake waits on backpressure and rechecks authority before cached retransmission" {
    for (0..4) |fault| {
        const f = try Fixture.init(0);
        defer f.deinit();
        try f.attach();
        f.blocked = true;
        f.tick(); // Encode the first flight.
        f.tick(); // Driver refuses it; wait until tick 23.
        try std.testing.expectEqual(@as(usize, 1), f.calls[0]);
        try std.testing.expectEqual(@as(u64, 23), f.pools[0].nextWake().?);
        try std.testing.expect(!f.pools[0].hasReadyWork(22));
        f.tick();
        try std.testing.expectEqual(@as(usize, 1), f.calls[0]);
        switch (fault) {
            0 => try f.capabilities[0].revokeGrant(f.contexts[0].capability_id),
            1 => f.keys[0].service.findHandle(f.channels[0].signer.handle_id).?.revoked = true,
            2 => _ = try f.services[0].revokeTrustedDevice(owner, .{ .kind = .device, .serial = 22 }, root_key, f.now),
            else => f.handshakes[0].expires_at = f.now,
        }
        f.tick();
        try std.testing.expectEqual(@as(usize, 1), f.calls[0]);
        try std.testing.expect(!f.handshakes[0].active() and !f.pools[0].hasSessions() and f.channels[0].crypto == .closed);
        try std.testing.expect(std.mem.allEqual(u8, &f.handshakes[0].outgoing, 0));
    }
}

test "peer handshake bounds unknown routes and expected-flight corruption before retirement" {
    const f = try Fixture.init(0);
    defer f.deinit();
    try f.attach();
    f.blocked = true;
    f.tick();
    f.tick();
    var wire = f.first[0];
    const frame = wire[0..f.first_len[0]];
    wire[6] ^= 1;
    for (0..100) |_| try std.testing.expect(!f.pools[1].admit(frame, f.now));
    try std.testing.expectEqual(@as(u8, 0), f.handshakes[1].admitted_this_tick);
    wire[6] ^= 1;
    wire[5] = 3; // An out-of-order flight is ignored, with a strict CPU budget.
    for (0..8) |_| {
        try std.testing.expect(f.pools[1].admit(frame, f.now));
        try std.testing.expect(!f.pools[1].admit(frame, f.now));
        try std.testing.expectEqual(@as(usize, 1), f.pools[1].service(f.now, Fixture.sendB, 2));
    }
    try std.testing.expect(!f.pools[1].admit(frame, f.now));
    try std.testing.expect(f.handshakes[1].active());
    wire[5] = 1;
    f.now += 1;
    try std.testing.expect(f.pools[1].admit(wire[0 .. peer.HEADER + 1], f.now));
    _ = f.pools[1].service(f.now, Fixture.sendB, 2);
    try std.testing.expect(!f.handshakes[1].active() and !f.pools[1].hasSessions());
}

test "peer handshake table rejects overflow and dispatches each registered peer fairly" {
    var fixtures: [5]*Fixture = undefined;
    var initialized: usize = 0;
    defer for (fixtures[0..initialized]) |f| f.deinit();
    var pool = handshake.Handshakes{};
    defer pool.deinit();
    for (&fixtures, 0..) |*f, i| {
        f.* = try Fixture.init(@intCast(i * 100));
        initialized += 1;
        if (i < 4) try pool.attach(&f.*.handshakes[0], 20);
    }
    try std.testing.expectError(error.PeerTableFull, pool.attach(&fixtures[4].handshakes[0], 20));
    try std.testing.expectError(error.PeerAlreadyAdmitted, pool.attach(&fixtures[0].handshakes[0], 20));
    // A caller cannot increase the two-operation runtime budget.
    try std.testing.expectEqual(@as(usize, 2), pool.service(20, Fixture.sendA, 100));
    for (fixtures[0..4], 0..) |f, i| try std.testing.expectEqual(@as(u8, if (i < 2) 1 else 0), f.channels[0].crypto.handshake.step);
    try std.testing.expectEqual(@as(usize, 2), pool.service(20, Fixture.sendA, 100));
    for (fixtures[0..4]) |f| try std.testing.expectEqual(@as(u8, 1), f.channels[0].crypto.handshake.step);
}

test "peer handshake admission and handoff require current local service and sealed key authority" {
    const f = try Fixture.init(0);
    defer f.deinit();
    var wrong = f.contexts[0];
    wrong.task_id += 1;
    try std.testing.expectError(error.PermissionDenied, handshake.Handshake.init(&f.channels[0], &f.services[0], &f.capabilities[0], wrong, mac, 500));
    try std.testing.expectError(error.PermissionDenied, handshake.Handshake.init(&f.channels[0], &f.services[1], &f.capabilities[0], f.contexts[0], mac, 500));
    try std.testing.expectError(error.InvalidPeerLifetime, handshake.Handshake.init(&f.channels[0], &f.services[0], &f.capabilities[0], f.contexts[0], mac, 20));
    try std.testing.expectError(error.InvalidPeerLifetime, handshake.Handshake.init(&f.channels[0], &f.services[0], &f.capabilities[0], f.contexts[0], mac, 20 + handshake.MAX_LIFETIME_TICKS + 1));
    try std.testing.expectError(error.InvalidPeerAddress, handshake.Handshake.init(&f.channels[0], &f.services[0], &f.capabilities[0], f.contexts[0], @splat(0xff), 500));
    const signer = f.channels[0].signer;
    f.channels[0].signer = .{};
    try std.testing.expectError(error.SealedSigningKeyRequired, handshake.Handshake.init(&f.channels[0], &f.services[0], &f.capabilities[0], f.contexts[0], mac, 500));
    f.channels[0].signer = signer;
    try f.attach();
    var confirmation: [peer.MAX_FRAME]u8 = @splat(0xaa);
    try std.testing.expectError(error.PeerNotReady, f.pools[0].take(&f.handshakes[0], &confirmation, f.now));
    try f.connect();
    try std.testing.expectError(error.NoSpaceLeft, f.pools[0].take(&f.handshakes[0], confirmation[0..1], f.now));
    try std.testing.expect(f.handshakes[0].complete() and f.pools[0].hasSessions());
    try f.capabilities[0].revokeGrant(f.contexts[0].capability_id);
    try std.testing.expectError(error.PeerNotReady, f.pools[0].take(&f.handshakes[0], &confirmation, f.now));
    try std.testing.expect(!f.pools[0].hasSessions() and f.channels[0].crypto == .closed);
    try std.testing.expect(std.mem.allEqual(u8, &confirmation, 0xaa));
}
