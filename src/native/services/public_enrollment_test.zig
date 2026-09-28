const std = @import("std");
const durable = @import("durable_identity_service.zig");
const enrollment = @import("../sync/device_enrollment.zig");
const graph = @import("../sync/device_graph.zig");
const peer = @import("../sync/peer_channel.zig");
const catalog = @import("../storage/vault_catalog.zig");
const disk_fixture = @import("../storage/document_save_test.zig");
const key_fixture = @import("../../tests/fixtures/document_signer.zig");
const provider = @import("../../tests/fixtures/secret_provider.zig");
const identity = @import("../platform/os_identity.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sealed = @import("sealed_signing_key.zig");
const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
const alice = principal.PrincipalId{ .kind = .device, .serial = 11 };
const bob = principal.PrincipalId{ .kind = .device, .serial = 22 };

const Node = struct {
    disk: *disk_fixture.Fixture,
    keys: key_fixture.Fixture = .{},
    generator: provider.KeyGenerator = .{},
    identities: identity.Store = .init(),
    devices: graph.Graph = .init(),
    service: durable.Service = undefined,
    local: principal.PrincipalId,
    local_key: sealed.Key = undefined,
    root_key: ?sealed.Key = null,
    pin: signing.PublicKey = @splat(0),
    catalog_pin: signing.PublicKey = undefined,
    scratch: [catalog.MAX_BYTES]u8 = undefined,

    fn init(start: u8, local: principal.PrincipalId, issuer: bool) !*Node {
        const n = try std.testing.allocator.create(Node);
        errdefer std.testing.allocator.destroy(n);
        n.* = .{ .disk = try disk_fixture.Fixture.init(true), .local = local, .generator = .{ .calls = start } };
        errdefer n.disk.deinit();
        const signer = try n.keys.init(owner, n.disk.service.owner, n.disk.service.task_id, .{ .label = "catalog", .seed = @splat(start) });
        n.catalog_pin = try signer.key.publicKey(1);
        n.keys.service.attachHardwareProvider(n.generator.provider());
        n.local_key = try n.generate("local device");
        n.service = .{ .state = .{ .vault = &n.keys.service, .identities = &n.identities, .devices = &n.devices }, .storage = &n.disk.service, .signer = signer, .object_id = 1000 };
        if (issuer) {
            n.root_key = try n.generate("owner root");
            n.pin = try n.root_key.?.publicKey(1);
            try n.service.ensureUserRoot(owner, "owner", n.root_key.?, 1, &n.scratch);
            try n.service.enrollDevice(owner, local, "local device", n.root_key.?, n.local_key, 2, &n.scratch);
        } else _ = try n.service.flush(1, &n.scratch);
        return n;
    }

    fn deinit(n: *Node) void {
        n.disk.activate();
        n.disk.deinit();
        std.testing.allocator.destroy(n);
    }

    fn generate(n: *Node, label: []const u8) !sealed.Key {
        const secret = try n.keys.service.generateSigningKey(&n.keys.policies, n.keys.authority.subjects, .{ .owner = owner, .task_id = n.disk.service.task_id, .label = label, .now_ticks = 1 }, null);
        return n.lease(secret.id);
    }

    fn lease(n: *Node, id: u64) !sealed.Key {
        const handle = try n.keys.service.lendHandle(&n.keys.policies, n.keys.authority.subjects, .{ .owner = owner, .holder = n.disk.service.owner, .task_id = n.disk.service.task_id, .secret_id = id, .expires_at_ticks = 1000, .now_ticks = 1 }, null);
        return sealed.Key.bind(&n.keys.authority, handle.id, 1);
    }

    fn restore(n: *Node) !void {
        n.disk.activate();
        const is_issuer = n.root_key != null;
        n.disk.crash();
        n.keys.service = .init();
        n.keys.service.attachHardwareProvider(n.generator.provider());
        n.identities = .init();
        n.devices = .init();
        _ = try catalog.restore(&n.disk.service, n.service.state, .{ .object_id = 1000, .owner = owner, .public_key = n.catalog_pin, .device_root_pin = n.pin }, &n.scratch);
        try std.testing.expectEqual(@as(usize, 0), n.keys.service.activeHandleCount());
        n.service = .{ .state = n.service.state, .storage = &n.disk.service, .signer = .{ .key = try n.lease(1) }, .object_id = 1000, .version_id = n.disk.service.latestVersion(@as(u64, 1000)).?.id.raw() };
        n.local_key = try n.lease(2);
        n.root_key = if (is_issuer) try n.lease(3) else null;
    }

    fn request(n: *Node, pin: signing.PublicKey) !graph.EnrollmentProposal {
        var wire: [enrollment.MAX_PROPOSAL_BYTES]u8 = undefined;
        const proposal = try graph.EnrollmentProposal.create(owner, n.local, "local device", pin, n.local_key, 3);
        return enrollment.decodeProposal(try enrollment.encodeProposal(&proposal, &wire));
    }

    fn publish(n: *Node, buffer: []u8) ![]const u8 {
        n.disk.activate();
        return n.service.publishEnrollment(owner, n.root_key.?, 4, buffer);
    }

    fn accept(n: *Node, bytes: []const u8) !void {
        n.disk.activate();
        try n.service.acceptEnrollment(owner, n.local, n.local_key, n.pin, bytes, 4, &n.scratch);
    }

    fn approve(n: *Node, proposal: *const graph.EnrollmentProposal) !void {
        n.disk.activate();
        try n.service.approveEnrollment(proposal, n.root_key.?, 3, &n.scratch);
    }

    fn flush(n: *Node) !void {
        n.disk.activate();
        _ = try n.service.flush(5, &n.scratch);
    }

    fn rotate(n: *Node, key: sealed.Key) !void {
        n.disk.activate();
        try n.service.rotateDeviceKey(owner, n.local, n.root_key.?, key, 4, &n.scratch);
    }

    fn revoke(n: *Node, device: principal.PrincipalId) !void {
        n.disk.activate();
        try n.service.revokeDevice(owner, device, n.root_key.?, 5, &n.scratch);
    }

    fn graphView(n: *Node) !*const graph.Graph {
        n.disk.activate();
        return n.service.deviceGraph(5);
    }
};

fn enroll(a: *Node, b: *Node, buffer: []u8) ![]const u8 {
    b.pin = a.pin; // Independent user-approved pin, never read from publication.
    const proposal = try b.request(a.pin);
    try a.approve(&proposal);
    const publication = try a.publish(buffer);
    try b.accept(publication);
    return publication;
}

fn connect(a: *Node, b: *Node) !void {
    var source = try peer.Channel.init(try a.graphView(), a.pin, alice, bob, a.local_key, .initiator, 5);
    defer source.close();
    var target = try peer.Channel.init(try b.graphView(), b.pin, bob, alice, b.local_key, .responder, 5);
    defer target.close();
    var wire: [peer.MAX_FRAME]u8 = undefined;
    var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
    try target.readHandshake(try source.writeHandshake(&wire, 5), 5);
    try source.readHandshake(try target.writeHandshake(&wire, 5), 5);
    try target.readHandshake(try source.writeHandshake(&wire, 5), 5);
    try std.testing.expectEqualStrings("independent enrollment", try target.open(&plaintext, try source.seal(&wire, "independent enrollment", 5), 5));
}

test "public enrollment joins independent vaults and disks without exchanging private keys" {
    const a = try Node.init(10, alice, true);
    defer a.deinit();
    const b = try Node.init(50, bob, false);
    defer b.deinit();
    var publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    const bytes = try enroll(a, b, &publication);
    try std.testing.expectEqual(@as(u8, 3), a.keys.service.store.secret_count);
    try std.testing.expectEqual(@as(u8, 2), b.keys.service.store.secret_count);
    try std.testing.expect(b.root_key == null);
    for ([_]u8{ 11, 12, 51 }) |seed| try std.testing.expect(std.mem.indexOf(u8, bytes, &([_]u8{seed} ** 32)) == null);
    try connect(a, b);
    const av = a.disk.service.versionCount();
    const bv = b.disk.service.versionCount();
    const proposal = try b.request(a.pin);
    try a.approve(&proposal);
    try b.accept(bytes);
    try std.testing.expectEqual(av, a.disk.service.versionCount());
    try std.testing.expectEqual(bv, b.disk.service.versionCount());
    try a.restore();
    try b.restore();
    try connect(a, b);
}

test "public enrollment authenticates every proposal and publication byte and rejects truncation" {
    const a = try Node.init(10, alice, true);
    defer a.deinit();
    const b = try Node.init(50, bob, false);
    defer b.deinit();
    var wire: [enrollment.MAX_PROPOSAL_BYTES]u8 = undefined;
    const proposal = try b.request(a.pin);
    const encoded = try enrollment.encodeProposal(&proposal, &wire);
    var damaged: [enrollment.MAX_PROPOSAL_BYTES]u8 = undefined;
    for (0..encoded.len) |i| {
        @memcpy(damaged[0..encoded.len], encoded);
        damaged[i] ^= 1;
        if (enrollment.decodeProposal(damaged[0..encoded.len])) |_| return error.AcceptedCorruptProposal else |_| {}
        if (enrollment.decodeProposal(encoded[0..i])) |_| return error.AcceptedTruncatedProposal else |_| {}
    }
    var publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    const bytes = try enroll(a, b, &publication);
    var bad_publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    var candidate = graph.Graph.init();
    for (0..bytes.len) |i| {
        @memcpy(bad_publication[0..bytes.len], bytes);
        bad_publication[i] ^= 1;
        if (enrollment.readPublication(&candidate, owner, a.pin, bad_publication[0..bytes.len])) |_| return error.AcceptedCorruptPublication else |_| {}
        if (enrollment.readPublication(&candidate, owner, a.pin, bytes[0..i])) |_| return error.AcceptedTruncatedPublication else |_| {}
        try std.testing.expect(candidate.devices.countInUse() == 0 and candidate.user_roots.countInUse() == 0);
    }
}

test "public enrollment checkpoints a preloaded graph before accepting an unchanged publication" {
    const a = try Node.init(10, alice, true);
    defer a.deinit();
    const b = try Node.init(50, bob, false);
    defer b.deinit();
    const proposal = try b.request(a.pin);
    try a.approve(&proposal);
    b.pin = a.pin;
    b.devices = a.devices;
    b.service = .{ .state = b.service.state, .storage = &b.disk.service, .signer = b.service.signer, .object_id = 2000 };
    var publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    const bytes = try a.publish(&publication);
    try b.accept(bytes);
    const committed = b.disk.service.latestVersion(@as(u64, 2000)) orelse return error.MissingEnrollmentCheckpoint;
    try std.testing.expectEqual(committed.id.raw(), b.service.version_id);
    const versions = b.disk.service.versionCount();
    try b.accept(bytes);
    try std.testing.expectEqual(versions, b.disk.service.versionCount());
}

test "public enrollment binds consent to the owner root and imported local key" {
    const a = try Node.init(10, alice, true);
    defer a.deinit();
    const b = try Node.init(50, bob, false);
    defer b.deinit();
    var wrong_pin = a.pin;
    wrong_pin[0] ^= 1;
    const wrong_consent = try b.request(wrong_pin);
    try std.testing.expectError(error.RootAuthorityMismatch, a.approve(&wrong_consent));
    var redirected = try b.request(a.pin);
    redirected.owner.serial += 1;
    try std.testing.expectError(error.InvalidDeviceSignature, redirected.validate());
    try std.testing.expectEqual(@as(usize, 1), a.devices.trustedDeviceCount());
    const proposal = try b.request(a.pin);
    try a.approve(&proposal);
    var publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    const bytes = try a.publish(&publication);
    b.pin = wrong_pin;
    try std.testing.expectError(error.InvalidEnrollment, b.accept(bytes));
    b.pin = a.pin;
    const other = try b.generate("other local key");
    try std.testing.expectError(error.InvalidIdentityAuthority, b.service.acceptEnrollment(owner, bob, other, a.pin, bytes, 4, &b.scratch));
    try std.testing.expectEqual(@as(usize, 0), b.devices.trustedDeviceCount());
    try b.accept(bytes);
    try std.testing.expectError(error.InvalidIdentityAuthority, b.service.publishEnrollment(owner, a.root_key.?, 4, &publication));
}

test "public enrollment preserves key generations revocations and known membership" {
    const a = try Node.init(10, alice, true);
    defer a.deinit();
    const b = try Node.init(50, bob, false);
    defer b.deinit();
    var old_publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    const old = try enroll(a, b, &old_publication);
    const next_key = try a.generate("replacement local key");
    try a.rotate(next_key);
    var publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    try b.accept(try a.publish(&publication));
    try std.testing.expectError(error.EnrollmentRollback, b.accept(old));
    try std.testing.expectEqual(@as(u32, 2), b.devices.findDeviceConst(alice).?.key_rotation_generation);
    try a.revoke(alice);
    try b.accept(try a.publish(&publication));
    try std.testing.expectError(error.AlreadyRevoked, b.devices.authenticatedDevice(alice, b.pin));
    var reduced = graph.Graph.init();
    _ = reduced.installUserRootRecord(a.devices.findUserRootConst(owner).?.*).?;
    _ = reduced.installDeviceRecord(a.devices.findDeviceConst(bob).?.*).?;
    try std.testing.expectError(error.EnrollmentRollback, b.accept(try enrollment.publish(&reduced, owner, a.root_key.?, 6, &publication)));
    try a.revoke(bob);
    try b.accept(try a.publish(&publication));
    try std.testing.expectError(error.AlreadyRevoked, b.devices.authenticatedDevice(bob, b.pin));
    const proposal = try b.request(a.pin);
    try std.testing.expectError(error.AlreadyRevoked, a.approve(&proposal));
    try b.restore();
    try std.testing.expectError(error.AlreadyRevoked, b.devices.authenticatedDevice(bob, b.pin));
    try std.testing.expectError(error.EnrollmentRollback, b.accept(old));
}

test "public enrollment withholds publication after failed approval and retries one durable version" {
    const a = try Node.init(10, alice, true);
    defer a.deinit();
    const b = try Node.init(50, bob, false);
    defer b.deinit();
    const proposal = try b.request(a.pin);
    a.disk.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, a.approve(&proposal));
    const versions = a.disk.service.versionCount();
    var publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    try std.testing.expectError(error.IdentityCheckpointPending, a.publish(&publication));
    try std.testing.expectError(error.IdentityCheckpointPending, a.approve(&proposal));
    a.disk.fail_flushes = false;
    try a.flush();
    try std.testing.expectEqual(versions, a.disk.service.versionCount());
    b.pin = a.pin;
    try b.accept(try a.publish(&publication));
    try a.restore();
    try b.restore();
    try connect(a, b);
}

test "public enrollment rejects same-generation rewrites mismatched retries and capacity overflow" {
    const a = try Node.init(10, alice, true);
    defer a.deinit();
    const b = try Node.init(50, bob, false);
    defer b.deinit();
    var publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
    _ = try enroll(a, b, &publication);
    const original = a.devices.findDevice(alice).?.last_rotated_at_ticks;
    a.devices.findDevice(alice).?.last_rotated_at_ticks += 1;
    // Even a root-signed publication cannot rewrite an observed generation.
    try std.testing.expectError(error.EnrollmentRollback, b.accept(try a.publish(&publication)));
    a.devices.findDevice(alice).?.last_rotated_at_ticks = original;
    const different = try graph.EnrollmentProposal.create(owner, bob, "changed label", a.pin, b.local_key, 3);
    try std.testing.expectError(error.DeviceEnrollmentMismatch, a.approve(&different));
    for (0..graph.MAX_DEVICES - 2) |i| {
        const proposal = try graph.EnrollmentProposal.create(owner, .{ .kind = .device, .serial = 100 + i }, "extra", a.pin, b.local_key, 3);
        try a.approve(&proposal);
    }
    try b.accept(try a.publish(&publication));
    try std.testing.expectEqual(graph.MAX_DEVICES, b.devices.trustedDeviceCount());
    const versions = a.disk.service.versionCount();
    const overflow = try graph.EnrollmentProposal.create(owner, .{ .kind = .device, .serial = 200 }, "overflow", a.pin, b.local_key, 3);
    try std.testing.expectError(error.DeviceTableFull, a.approve(&overflow));
    try std.testing.expectEqual(versions, a.disk.service.versionCount());
    try connect(a, b);
}

test "public enrollment imports cross both crash barriers with local keys unchanged" {
    for (1..3) |barrier| for (0..2) |retry| {
        const a = try Node.init(10, alice, true);
        defer a.deinit();
        const b = try Node.init(50, bob, false);
        defer b.deinit();
        b.pin = a.pin;
        const proposal = try b.request(a.pin);
        try a.approve(&proposal);
        var publication: [enrollment.MAX_PUBLICATION_BYTES]u8 = undefined;
        const bytes = try a.publish(&publication);
        b.disk.fail_flush_from = b.disk.flushes + barrier;
        try std.testing.expectError(error.DurabilityBarrierFailed, b.accept(bytes));
        const versions = b.disk.service.versionCount();
        try std.testing.expectError(error.IdentityCheckpointPending, b.graphView());
        try std.testing.expectError(error.IdentityCheckpointPending, b.accept(bytes));
        b.disk.fail_flush_from = null;
        if (retry == 1) {
            try b.flush();
            try std.testing.expectEqual(versions, b.disk.service.versionCount());
        }
        try b.restore();
        try std.testing.expectEqual(@as(u8, 2), b.keys.service.store.secret_count);
        try std.testing.expectEqual(if (retry == 1) @as(usize, 2) else 0, b.devices.trustedDeviceCount());
        if (retry == 1) try connect(a, b);
    };
}
