const std = @import("std");
const durable = @import("durable_identity_service.zig");
const catalog = @import("../storage/vault_catalog.zig");
const disk_fixture = @import("../storage/document_save_test.zig");
const key_fixture = @import("../../tests/fixtures/document_signer.zig");
const provider = @import("../../tests/fixtures/secret_provider.zig");
const identity = @import("../platform/os_identity.zig");
const graph = @import("../sync/device_graph.zig");
const snapshot = @import("../sync/device_graph_snapshot.zig");
const peer = @import("../sync/peer_channel.zig");
const sealed = @import("sealed_signing_key.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
const alice = principal.PrincipalId{ .kind = .device, .serial = 11 };
const bob = principal.PrincipalId{ .kind = .device, .serial = 22 };

const Fixture = struct {
    disk: *disk_fixture.Fixture,
    keys: key_fixture.Fixture = .{},
    generator: provider.KeyGenerator = .{},
    identities: identity.Store = .init(),
    devices: graph.Graph = .init(),
    service: durable.Service = undefined,
    root: sealed.Key = undefined,
    a: sealed.Key = undefined,
    b: sealed.Key = undefined,
    pin: signing.PublicKey = undefined,
    scratch: [catalog.MAX_BYTES]u8 = undefined,

    fn init() !*Fixture {
        const f = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(f);
        f.* = .{ .disk = try disk_fixture.Fixture.init(true) };
        errdefer f.disk.deinit();
        const signer = try f.keys.init(owner, f.disk.service.owner, f.disk.service.task_id, disk_fixture.signer);
        f.keys.service.attachHardwareProvider(f.generator.provider());
        f.service = .{ .state = .{ .vault = &f.keys.service, .identities = &f.identities, .devices = &f.devices }, .storage = &f.disk.service, .signer = signer, .object_id = 1000 };
        f.root = try f.generate("owner root");
        f.pin = try f.root.publicKey(1);
        try f.service.ensureUserRoot(owner, "owner", f.root, 1, &f.scratch);
        f.a = try f.generate("alice");
        try f.service.enrollDevice(owner, alice, "alice", f.root, f.a, 2, &f.scratch);
        f.b = try f.generate("bob");
        try f.service.enrollDevice(owner, bob, "bob", f.root, f.b, 2, &f.scratch);
        return f;
    }

    fn deinit(f: *Fixture) void {
        f.disk.deinit();
        std.testing.allocator.destroy(f);
    }

    fn generate(f: *Fixture, label: []const u8) !sealed.Key {
        const secret = try f.keys.service.generateSigningKey(&f.keys.policies, f.keys.authority.subjects, .{ .owner = owner, .task_id = f.disk.service.task_id, .label = label, .now_ticks = 1 }, null);
        return f.lease(secret.id);
    }

    fn lease(f: *Fixture, secret_id: u64) !sealed.Key {
        const handle = try f.keys.service.lendHandle(&f.keys.policies, f.keys.authority.subjects, .{ .owner = owner, .holder = f.disk.service.owner, .task_id = f.disk.service.task_id, .secret_id = secret_id, .expires_at_ticks = 100, .now_ticks = 1 }, null);
        return sealed.Key.bind(&f.keys.authority, handle.id, 1);
    }

    fn trust(f: *Fixture) !catalog.Trust {
        return .{ .object_id = 1000, .owner = owner, .public_key = try signing.publicKey(disk_fixture.signer), .device_root_pin = f.pin };
    }

    fn reset(f: *Fixture) void {
        f.keys.service = .init();
        f.keys.service.attachHardwareProvider(f.generator.provider());
        f.identities = .init();
        f.devices = .init();
    }

    fn restore(f: *Fixture) !void {
        f.disk.crash();
        f.reset();
        _ = try catalog.restore(&f.disk.service, f.service.state, try f.trust(), &f.scratch);
        try std.testing.expectEqual(@as(usize, 0), f.keys.service.activeHandleCount());
        const key = try f.lease(1);
        f.root = try f.lease(2);
        f.a = try f.lease(3);
        f.b = try f.lease(4);
        f.service = .{ .state = f.service.state, .storage = &f.disk.service, .signer = .{ .key = key }, .object_id = 1000, .version_id = f.disk.service.latestVersion(@as(u64, 1000)).?.id.raw() };
    }

    fn connect(f: *Fixture) !void {
        const devices = try f.service.deviceGraph(4);
        var a = try peer.Channel.init(devices, f.pin, alice, bob, f.a, .initiator, 4);
        defer a.close();
        var b = try peer.Channel.init(devices, f.pin, bob, alice, f.b, .responder, 4);
        defer b.close();
        var wire: [peer.MAX_FRAME]u8 = undefined;
        var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
        try b.readHandshake(try a.writeHandshake(&wire, 4), 4);
        try a.readHandshake(try b.writeHandshake(&wire, 4), 4);
        try b.readHandshake(try a.writeHandshake(&wire, 4), 4);
        try std.testing.expectEqualStrings("restored enrollment", try b.open(&plaintext, try a.seal(&wire, "restored enrollment", 4), 4));
    }
};

test "durable enrollment restores generated keys graph rotation and revocation together" {
    const f = try Fixture.init();
    defer f.deinit();
    try f.restore();
    try f.connect();
    const next = try f.generate("alice replacement");
    const next_public = try next.publicKey(3);
    try f.service.rotateDeviceKey(owner, alice, f.root, next, 3, &f.scratch);
    try f.restore();
    f.a = try f.lease(5);
    const record = try f.devices.authenticatedDevice(alice, f.pin);
    try std.testing.expectEqual(@as(u32, 2), record.key_rotation_generation);
    try std.testing.expectEqualSlices(u8, &next_public, record.device_signature.publicKeySlice());
    try f.connect();
    try f.service.revokeDevice(owner, bob, f.root, 5, &f.scratch);
    try f.restore();
    try std.testing.expectError(error.AlreadyRevoked, f.devices.authenticatedDevice(bob, f.pin));
    try std.testing.expectEqual(@as(usize, 1), f.devices.trustedDeviceCount());
}

test "durable enrollment withholds failed checkpoints and preserves keys with graph at both crash barriers" {
    for (1..3) |barrier| for (0..2) |retry| {
        const f = try Fixture.init();
        defer f.deinit();
        const next = try f.generate("replacement");
        f.disk.fail_flush_from = f.disk.flushes + barrier;
        try std.testing.expectError(error.DurabilityBarrierFailed, f.service.rotateDeviceKey(owner, alice, f.root, next, 3, &f.scratch));
        const count = f.disk.service.versionCount();
        try std.testing.expectError(error.IdentityCheckpointPending, f.service.deviceGraph(4));
        try std.testing.expectError(error.IdentityCheckpointPending, f.service.revokeDevice(owner, bob, f.root, 4, &f.scratch));
        f.disk.fail_flush_from = null;
        if (retry == 1) {
            _ = try f.service.flush(4, &f.scratch);
            try std.testing.expectEqual(count, f.disk.service.versionCount());
        }
        try f.restore();
        const committed = retry == 1;
        try std.testing.expectEqual(if (committed) @as(u8, 5) else @as(u8, 4), f.keys.service.store.secret_count);
        try std.testing.expectEqual(if (committed) @as(u32, 2) else @as(u32, 1), f.devices.findDeviceConst(alice).?.key_rotation_generation);
        if (committed) f.a = try f.lease(5);
        try f.connect();
    };
}

test "durable enrollment rejects foreign vault keys and revoked signing leases before mutation" {
    const f = try Fixture.init();
    defer f.deinit();
    const before = f.devices;
    var foreign = key_fixture.Fixture{};
    const foreign_key = try foreign.init(owner, f.disk.service.owner, f.disk.service.task_id, .{ .label = "foreign", .seed = @splat(0x71) });
    try std.testing.expectError(error.InvalidIdentityAuthority, f.service.rotateDeviceKey(owner, alice, f.root, foreign_key.key, 3, &f.scratch));
    f.keys.service.findHandle(f.root.handle_id).?.revoked = true;
    try std.testing.expectError(error.HandleRevoked, f.service.revokeDevice(owner, alice, f.root, 3, &f.scratch));
    try std.testing.expectEqualDeep(before, f.devices);
}

test "durable enrollment requires an independent pin and leaves all destination stores empty on rejection" {
    for (0..3) |variant| {
        const f = try Fixture.init();
        defer f.deinit();
        var trust = try f.trust();
        if (variant == 0) trust.device_root_pin = null;
        if (variant == 1) trust.device_root_pin.?[0] ^= 1;
        if (variant == 2) trust.minimum_generation = 4;
        f.reset();
        const expected: anyerror = switch (variant) {
            0 => error.RootPinRequired,
            1 => error.InvalidRootSignature,
            else => error.VaultCatalogRollback,
        };
        try std.testing.expectError(expected, catalog.restore(&f.disk.service, f.service.state, trust, &f.scratch));
        try std.testing.expectEqual(@as(u8, 0), f.keys.service.store.secret_count);
        try std.testing.expectEqual(@as(u8, 0), f.identities.credential_count);
        try std.testing.expect(snapshot.empty(&f.devices));
    }
}

test "durable enrollment rejects a forged inner graph despite a valid catalog signature" {
    const f = try Fixture.init();
    defer f.deinit();
    const version = f.disk.service.latestVersion(@as(u64, 1000)).?;
    const bytes = try f.disk.service.versionPayloadInto(version, &f.scratch);
    const signature = f.devices.findDeviceConst(bob).?.enrollment_signature.value;
    const offset = std.mem.lastIndexOf(u8, bytes, &signature).?;
    f.scratch[offset] ^= 1;
    const metadata = try f.service.signer.signObjectMetadata("Sealed vault catalog", catalog.CONTENT_TYPE, .secret, bytes, 3);
    _ = try f.disk.service.putVersion(.{ .preferred_object_id = @import("../core/ids.zig").object(1000), .object_type = .secret, .payload = bytes, .metadata = metadata, .parent_version_id = version.id });
    f.reset();
    try std.testing.expectError(error.InvalidEnrollmentSignature, catalog.restore(&f.disk.service, f.service.state, try f.trust(), &f.scratch));
    try std.testing.expectEqual(@as(u8, 0), f.keys.service.store.secret_count);
    try std.testing.expectEqual(@as(u8, 0), f.identities.credential_count);
    try std.testing.expect(snapshot.empty(&f.devices));
}

test "durable enrollment never publishes a validated graph when a later key cannot unseal" {
    const f = try Fixture.init();
    defer f.deinit();
    const version = f.disk.service.latestVersion(@as(u64, 1000)).?;
    const bytes = try f.disk.service.versionPayloadInto(version, &f.scratch);
    const blob = f.keys.service.store.describeSecret(4).?.sealedBlob().?;
    const offset = std.mem.indexOf(u8, bytes, blob).?;
    f.scratch[offset + blob.len - 1] ^= 1;
    const metadata = try f.service.signer.signObjectMetadata("Sealed vault catalog", catalog.CONTENT_TYPE, .secret, bytes, 3);
    _ = try f.disk.service.putVersion(.{ .preferred_object_id = @import("../core/ids.zig").object(1000), .object_type = .secret, .payload = bytes, .metadata = metadata, .parent_version_id = version.id });
    f.reset();
    try std.testing.expectError(error.InvalidSealedSecret, catalog.restore(&f.disk.service, f.service.state, try f.trust(), &f.scratch));
    try std.testing.expectEqual(@as(u8, 0), f.keys.service.store.secret_count);
    try std.testing.expectEqual(@as(u8, 0), f.identities.credential_count);
    try std.testing.expect(snapshot.empty(&f.devices));
}

test "durable enrollment snapshot rejects truncation duplicate devices and forged revocations" {
    const f = try Fixture.init();
    defer f.deinit();
    try f.service.revokeDevice(owner, bob, f.root, 3, &f.scratch);
    var bytes: [snapshot.MAX_BYTES]u8 = undefined;
    const encoded = try snapshot.encode(&f.devices, owner, &bytes);
    var restored = graph.Graph.init();
    for (0..encoded.len) |len| {
        try std.testing.expectError(error.InvalidGraphSnapshot, snapshot.decode(&restored, owner, f.pin, encoded[0..len]));
        try std.testing.expect(snapshot.empty(&restored));
    }
    try snapshot.decode(&restored, owner, f.pin, encoded);
    @memset(&bytes, 0xaa);
    _ = try restored.authenticatedRecord(bob, f.pin);
    // Alter a validly framed inner graph without relying on its outer signer.
    restored.findDevice(bob).?.revocation_signature.value[0] ^= 1;
    try std.testing.expectError(error.InvalidEnrollmentSignature, snapshot.encode(&restored, owner, &bytes));
    const second = &f.devices.devices.slots[1].device;
    second.principal_id = alice;
    try std.testing.expectError(error.InvalidGraphSnapshot, snapshot.encode(&f.devices, owner, &bytes));
}
