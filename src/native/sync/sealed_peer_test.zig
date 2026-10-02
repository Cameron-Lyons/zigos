const std = @import("std");
const sealed = @import("../services/sealed_signing_key.zig");
const fixtures = @import("../../tests/fixtures/document_signer.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const graph_mod = @import("device_graph.zig");
const peer = @import("peer_channel.zig");

const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
const holder = principal.PrincipalId{ .kind = .service, .serial = 700 };
const alice = principal.PrincipalId{ .kind = .device, .serial = 11 };
const bob = principal.PrincipalId{ .kind = .device, .serial = 22 };

const Fixture = struct {
    root: fixtures.Fixture = .{},
    a: fixtures.Fixture = .{},
    b: fixtures.Fixture = .{},
    root_key: sealed.Key = undefined,
    a_key: sealed.Key = undefined,
    b_key: sealed.Key = undefined,
    graph: graph_mod.Graph = .init(),
    pin: signing.PublicKey = undefined,

    fn init() !*Fixture {
        const f = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(f);
        f.* = .{};
        f.root_key = (try f.root.init(owner, holder, 701, .{ .label = "root", .seed = @splat(0x21) })).key;
        f.a_key = (try f.a.init(owner, holder, 701, .{ .label = "alice", .seed = @splat(0x22) })).key;
        f.b_key = (try f.b.init(owner, holder, 701, .{ .label = "bob", .seed = @splat(0x23) })).key;
        f.pin = try f.root_key.publicKey(1);
        _ = try f.graph.ensureSealedUserRoot(owner, "owner", f.root_key, 1);
        _ = try f.graph.enrollSealedDevice(owner, alice, "alice", f.root_key, f.a_key, 2);
        _ = try f.graph.enrollSealedDevice(owner, bob, "bob", f.root_key, f.b_key, 2);
        return f;
    }

    fn deinit(f: *Fixture) void {
        std.testing.allocator.destroy(f);
    }

    fn initiator(f: *Fixture) !peer.Channel {
        return peer.Channel.init(&f.graph, f.pin, alice, bob, f.a_key, .initiator, 3);
    }

    fn responder(f: *Fixture) !peer.Channel {
        return peer.Channel.init(&f.graph, f.pin, bob, alice, f.b_key, .responder, 3);
    }

    fn connect(a: *peer.Channel, b: *peer.Channel) !void {
        var wire: [peer.MAX_FRAME]u8 = undefined;
        try b.readHandshake(try a.writeHandshake(&wire, 3), 3);
        try a.readHandshake(try b.writeHandshake(&wire, 3), 3);
        try b.readHandshake(try a.writeHandshake(&wire, 3), 3);
    }
};

test "sealed peer identities enroll and authenticate without exporting device keys" {
    const f = try Fixture.init();
    defer f.deinit();
    var a = try f.initiator();
    defer a.close();
    var b = try f.responder();
    defer b.close();
    try Fixture.connect(&a, &b);
    var wire: [peer.MAX_FRAME]u8 = undefined;
    var output: [peer.MAX_PAYLOAD]u8 = undefined;
    try std.testing.expectEqualStrings("sealed sender", try b.open(&output, try a.seal(&wire, "sealed sender", 4), 4));
    try std.testing.expectEqualStrings("sealed reply", try a.open(&output, try b.seal(&wire, "sealed reply", 4), 4));
    for ([_]*fixtures.Fixture{ &f.root, &f.a, &f.b }) |keys| {
        const record = keys.service.store.describeSecret(1).?;
        try std.testing.expect(record.hardware_backed and record.hardware_provider_used);
        try std.testing.expect(!record.resident_material and !record.exportable);
    }
    try std.testing.expectError(error.IdentityMismatch, peer.Channel.init(&f.graph, f.pin, alice, bob, f.b_key, .initiator, 3));
    var changed = f.a_key;
    changed.sealed_digest[0] ^= 1;
    try std.testing.expectError(error.SigningKeyChanged, peer.Channel.init(&f.graph, f.pin, alice, bob, changed, .initiator, 3));
    try std.testing.expect(@sizeOf(peer.Channel) <= 544);
}

test "sealed peer revocation expiry and policy changes close live traffic keys and erase output" {
    for (0..5) |fault| {
        const f = try Fixture.init();
        defer f.deinit();
        var a = try f.initiator();
        defer a.close();
        var b = try f.responder();
        defer b.close();
        try Fixture.connect(&a, &b);
        var wire: [peer.MAX_FRAME]u8 = undefined;
        const packet = try b.seal(&wire, "pending peer packet", 4);
        var expected: anyerror = undefined;
        switch (fault) {
            0 => {
                f.a.service.findHandle(f.a_key.handle_id).?.revoked = true;
                expected = error.HandleRevoked;
            },
            1 => {
                f.a.service.findHandle(f.a_key.handle_id).?.expires_at_ticks = 4;
                expected = error.HandleExpired;
            },
            2 => {
                f.a.policies = .init();
                _ = try f.a.policies.create(.{ .scope = .user, .subject_id = owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 1 }, .label = "signing denied", .secret_vault_allowed = false }, .{ .label = "policy", .seed = @splat(0x24) });
                expected = error.PolicyDenied;
            },
            3 => {
                f.a.service.store.secrets[0].sealed_digest[0] ^= 1;
                expected = error.SigningKeyChanged;
            },
            4 => {
                f.a.authority.task_id += 1;
                expected = error.HandleHolderMismatch;
            },
            else => unreachable,
        }
        var output: [peer.MAX_PAYLOAD]u8 = @splat(0xaa);
        try std.testing.expectError(expected, a.open(&output, packet, 4));
        try std.testing.expect(std.mem.allEqual(u8, &output, 0));
        try std.testing.expect(a.crypto == .closed and a.signer.authority == null);
        @memset(&wire, 0xaa);
        try std.testing.expectError(error.InvalidState, a.seal(&wire, "after revocation", 4));
        try std.testing.expect(std.mem.allEqual(u8, &wire, 0));
    }
}

test "sealed peer checks leases on handshake reads and writes before publishing certificates" {
    for (0..2) |read| {
        const f = try Fixture.init();
        defer f.deinit();
        var a = try f.initiator();
        defer a.close();
        var b = try f.responder();
        defer b.close();
        var wire: [peer.MAX_FRAME]u8 = undefined;
        if (read == 0) {
            f.a.service.findHandle(f.a_key.handle_id).?.revoked = true;
            @memset(&wire, 0xaa);
            try std.testing.expectError(error.HandleRevoked, a.writeHandshake(&wire, 4));
            try std.testing.expect(std.mem.allEqual(u8, &wire, 0));
            try std.testing.expect(a.crypto == .closed);
        } else {
            const hello = try a.writeHandshake(&wire, 3);
            f.b.service.findHandle(f.b_key.handle_id).?.revoked = true;
            try std.testing.expectError(error.HandleRevoked, b.readHandshake(hello, 4));
            try std.testing.expect(b.crypto == .closed);
        }
    }
}

test "sealed graph mutations require the matching owner root and preserve live channel generations" {
    const f = try Fixture.init();
    defer f.deinit();
    const before = f.graph;
    try std.testing.expectError(error.RootAuthorityMismatch, f.graph.enrollSealedDevice(owner, .{ .kind = .device, .serial = 33 }, "forged", f.a_key, f.b_key, 3));
    try std.testing.expectEqualDeep(before, f.graph);
    var a = try f.initiator();
    defer a.close();
    var b = try f.responder();
    defer b.close();
    try Fixture.connect(&a, &b);
    _ = try f.graph.rotateSealedDeviceKey(owner, alice, f.root_key, f.b_key, 4);
    try std.testing.expectEqual(@as(u32, 2), (try f.graph.authenticatedDevice(alice, f.pin)).key_rotation_generation);
    var wire: [peer.MAX_FRAME]u8 = undefined;
    try std.testing.expectError(error.TrustChanged, a.seal(&wire, "retired key", 4));
    try f.graph.revokeSealedDevice(owner, bob, f.root_key, 5);
    try std.testing.expectError(error.TrustChanged, b.seal(&wire, "revoked device", 5));
    const revoked = f.graph;
    f.root.service.findHandle(f.root_key.handle_id).?.revoked = true;
    try std.testing.expectError(error.HandleRevoked, f.graph.revokeSealedDevice(owner, alice, f.root_key, 6));
    try std.testing.expectEqualDeep(revoked, f.graph);
}
