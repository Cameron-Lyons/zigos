const std = @import("std");
const transfer = @import("object_transfer.zig");
const channel = @import("peer_channel.zig");
const graph = @import("device_graph.zig");
const sync = @import("sync_service.zig");
const storage = @import("../storage/storage_service.zig");
const durable = @import("../storage/document_save_test.zig");
const document_save = @import("../storage/document_save.zig");
const signing = @import("../core/signing.zig");
const principal = @import("../core/principal.zig");
const capability = @import("../kernel_api/capability.zig");
const signer_fixture = @import("../../tests/fixtures/document_signer.zig");
const sealed = @import("../storage/sealed_object_signer.zig");
const objects = @import("../storage/object_store.zig");

const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
const alice = principal.PrincipalId{ .kind = .device, .serial = 11 };
const bob = principal.PrincipalId{ .kind = .device, .serial = 22 };
const root_key = signing.SignerIdentity{ .label = "root", .seed = @splat(0xa1) };
const alice_key = signing.SignerIdentity{ .label = "alice", .seed = @splat(0xa2) };
const bob_key = signing.SignerIdentity{ .label = "bob", .seed = @splat(0xa3) };

const Fixture = struct {
    disk: *durable.Fixture,
    service: sync.Service,
    capabilities: capability.CapabilityTable = .init(),
    sender_graph: graph.Graph = undefined,
    sender: channel.Channel = undefined,
    recipient: channel.Channel = undefined,
    signing_fixture: signer_fixture.Fixture = .{},
    sender_keys: signer_fixture.Fixture = .{},
    receiver_keys: signer_fixture.Fixture = .{},
    signer: sealed.Signer = undefined,
    authority: sync.AuthorityContext = undefined,
    receiver: transfer.Receiver = undefined,
    scratch: [4096]u8 = @splat(0),

    fn init() !*Fixture {
        const self = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(self);
        const disk = try durable.Fixture.init(true);
        errdefer disk.deinit();
        self.* = .{ .disk = disk, .service = .init(700, 701, .{ .kind = .service, .serial = 700 }) };
        _ = try self.service.ensureUserRoot(owner, "owner", root_key);
        _ = try self.service.enrollTrustedDevice(owner, alice, "alice", root_key, alice_key, 1);
        _ = try self.service.enrollTrustedDevice(owner, bob, "bob", root_key, bob_key, 1);
        const policy = try self.service.createNetworkPolicy(.{ .owner = self.service.owner, .label = "local", .mode = .local_network });
        _ = try self.service.configureWorkspacePolicy(.{ .owner = owner, .workspace_id = disk.workspace_id, .require_shared_access = true, .device_to_device_policy_id = policy.id });
        const service_cap = try self.capabilities.mintBootRoot(.{
            .holder = self.service.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = self.service.service_id },
            .rights = .{ .service = .{ .endpoint_connect = true } },
            .scope = .{ .task_id = self.service.task_id, .local_only = true, .broker_only = true },
            .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100_000 },
            .audit = .{},
        });
        self.authority = .{ .task_id = self.service.task_id, .principal = self.service.owner, .capability_id = service_cap.id, .now_ticks = 20 };
        const workspace_cap = try self.capabilities.mintBootRoot(.{
            .holder = owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .workspace, .id = disk.workspace_id },
            .rights = .{ .workspace = .{ .object_read = true, .object_write = true, .capability_derive = true } },
            .scope = .{ .workspace_id = disk.workspace_id, .broker_only = true },
            .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100_000 },
            .audit = .{},
        });
        var port = storage.StoragePort.init(&disk.service, &self.capabilities);
        const share = try port.grantObjectShare(&self.capabilities, .{ .task_id = 702, .principal = owner, .capability_id = workspace_cap.id, .now_ticks = 10 }, disk.workspace_id, 900, .{
            .principal_id = alice,
            .can_write = true,
            .network_scope = .trusted_overlay,
            .expires_at_ticks = 90_000,
        });
        self.signer = try self.signing_fixture.init(owner, disk.service.owner, disk.service.task_id, durable.signer);
        self.receiver = .{ .store = &disk.service, .sync = &self.service, .capabilities = &self.capabilities, .binding = .{
            .workspace_id = disk.workspace_id,
            .object_id = 900,
            .local_device = bob.serial,
            .peer_device = alice.serial,
            .peer_capability_id = share.capability.id,
        }, .scratch = &self.scratch };
        _ = try disk.service.checkpointDurable();
        try self.connect();
        return self;
    }

    fn connect(self: *Fixture) !void {
        self.sender_graph = self.service.deviceGraph().*;
        const sender_key = try self.sender_keys.init(owner, self.service.owner, self.service.task_id, alice_key);
        const receiver_key = try self.receiver_keys.init(owner, self.service.owner, self.service.task_id, bob_key);
        self.sender = try channel.Channel.init(&self.sender_graph, try signing.publicKey(root_key), alice, bob, sender_key.key, .initiator, 20);
        self.recipient = try channel.Channel.init(self.service.deviceGraph(), try signing.publicKey(root_key), bob, alice, receiver_key.key, .responder, 20);
        var wire: [channel.MAX_FRAME]u8 = undefined;
        try self.recipient.readHandshake(try self.sender.writeHandshake(&wire, 20), 20);
        try self.sender.readHandshake(try self.recipient.writeHandshake(&wire, 20), 20);
        try self.recipient.readHandshake(try self.sender.writeHandshake(&wire, 20), 20);
    }

    fn deinit(self: *Fixture) void {
        self.receiver.reset();
        self.sender.close();
        self.recipient.close();
        self.disk.deinit();
        std.testing.allocator.destroy(self);
    }

    fn request(self: *Fixture, bytes: []const u8) transfer.Begin {
        return .{ .id = 7, .workspace_id = self.disk.workspace_id, .object_id = 900, .expected_version = self.disk.original_version_id, .length = @intCast(bytes.len), .digest = transfer.digest(bytes) };
    }

    fn send(self: *Fixture, bytes: []const u8) !transfer.Progress {
        var wire: [channel.MAX_FRAME]u8 = undefined;
        return self.receiver.receive(&self.recipient, self.authority, self.signer, try self.sender.seal(&wire, bytes, 20));
    }

    fn begin(self: *Fixture, value: transfer.Begin) !transfer.Progress {
        var bytes: [channel.MAX_PAYLOAD]u8 = undefined;
        return self.send(try transfer.encodeBegin(&bytes, value));
    }

    fn chunk(self: *Fixture, offset: u32, payload: []const u8) !transfer.Progress {
        var bytes: [channel.MAX_PAYLOAD]u8 = undefined;
        return self.send(try transfer.encodeChunk(&bytes, 7, offset, payload));
    }

    fn stage(self: *Fixture, payload: []const u8) !void {
        try std.testing.expect(!(try self.begin(self.request(payload))).durable());
        var offset: usize = 0;
        while (offset < payload.len) {
            const next = @min(payload.len, offset + transfer.MAX_CHUNK);
            const progress = try self.chunk(@intCast(offset), payload[offset..next]);
            try std.testing.expectEqual(next, progress.received);
            try std.testing.expect(!progress.durable());
            offset = next;
        }
    }

    fn commit(self: *Fixture) !transfer.Progress {
        var bytes: [channel.MAX_PAYLOAD]u8 = undefined;
        return self.send(try transfer.encodeCommit(&bytes, 7));
    }
};

test "object transfer admits encrypted chunks and acknowledges durable signed bytes after reopening" {
    const f = try Fixture.init();
    defer f.deinit();
    var payload: [2049]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i * 17);
    const generation = f.disk.checkpoint.last_checkpoint_generation;
    try f.stage(&payload);
    try std.testing.expectEqualStrings("original", try f.disk.text());
    const receipt = try f.commit();
    try std.testing.expect(receipt.durable());
    try std.testing.expectEqual(generation + 1, receipt.checkpoint_generation);
    try std.testing.expect(std.mem.allEqual(u8, &f.scratch, 0));
    var response: [channel.MAX_PAYLOAD]u8 = undefined;
    var wire: [channel.MAX_FRAME]u8 = undefined;
    var plaintext: [channel.MAX_PAYLOAD]u8 = undefined;
    const decoded = try transfer.decodeProgress(try f.sender.open(&plaintext, try f.recipient.seal(&wire, try transfer.encodeProgress(&response, receipt), 20), 20));
    try std.testing.expectEqualDeep(receipt, decoded);
    try std.testing.expectEqualDeep(receipt, try f.commit());
    f.disk.crash();
    try std.testing.expect(f.disk.service.loaded_from_volume);
    try std.testing.expectEqualSlices(u8, &payload, try f.disk.text());
    // A fresh process and session recognize the committed content after loss
    // of the final reply, even though the client's base version is now stale.
    f.receiver.reset();
    f.sender.close();
    f.recipient.close();
    try f.connect();
    try f.stage(&payload);
    const retried = try f.commit();
    try std.testing.expectEqual(receipt.version_id, retried.version_id);
    try std.testing.expectEqual(@as(usize, 2), f.disk.service.versionCount());
}

test "object transfer retries failed writes and barriers without allocating another version" {
    for (0..3) |fault| {
        const f = try Fixture.init();
        defer f.deinit();
        try f.stage("durable remote edit");
        if (fault == 0) f.disk.fail_writes = true else f.disk.fail_flush_from = f.disk.flushes + fault;
        for (0..3) |_| {
            const expected = if (fault == 0) error.CorruptImage else error.DurabilityBarrierFailed;
            try std.testing.expectError(expected, f.commit());
            try std.testing.expectEqual(@as(usize, 2), f.disk.service.versionCount());
            try std.testing.expectEqual(@as(u64, 0), f.receiver.transfer.?.checkpoint_generation);
        }
        const pending = f.receiver.transfer.?.applied_version;
        f.disk.fail_writes = false;
        f.disk.fail_flush_from = null;
        const receipt = try f.commit();
        try std.testing.expect(receipt.durable());
        try std.testing.expectEqual(pending, receipt.version_id);
        f.disk.crash();
        try std.testing.expectEqualStrings("durable remote edit", try f.disk.text());
    }
}

test "object transfer never acknowledges volatile data lost at either checkpoint barrier" {
    for (1..3) |barrier| {
        const f = try Fixture.init();
        defer f.deinit();
        try f.stage("volatile remote edit");
        f.disk.fail_flush_from = f.disk.flushes + barrier;
        try std.testing.expectError(error.DurabilityBarrierFailed, f.commit());
        f.disk.crash();
        try std.testing.expectEqualStrings("original", try f.disk.text());
    }
}

test "object transfer rejects tampering and replay before any object allocation" {
    const f = try Fixture.init();
    defer f.deinit();
    var bytes: [channel.MAX_PAYLOAD]u8 = undefined;
    var wire: [channel.MAX_FRAME]u8 = undefined;
    const frame = try f.sender.seal(&wire, try transfer.encodeBegin(&bytes, f.request("new")), 20);
    wire[frame.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, f.receiver.receive(&f.recipient, f.authority, f.signer, frame));
    try std.testing.expect(f.receiver.transfer == null);
    wire[frame.len - 1] ^= 1;
    _ = try f.receiver.receive(&f.recipient, f.authority, f.signer, frame);
    try std.testing.expectError(error.ReplayRejected, f.receiver.receive(&f.recipient, f.authority, f.signer, frame));
    try std.testing.expectEqual(@as(usize, 1), f.disk.service.versionCount());
}

test "object transfer rechecks capability share and device revocation and erases staged bytes" {
    for (0..4) |revocation| {
        const f = try Fixture.init();
        defer f.deinit();
        try f.stage("private pending bytes");
        if (revocation == 0) {
            try f.capabilities.revokeGrant(f.receiver.binding.peer_capability_id);
        } else if (revocation == 1) {
            try f.disk.service.shareWorkspace(f.disk.workspace_id, .{ .principal_id = alice, .can_read = true, .can_write = false, .network_scope = .trusted_overlay });
        } else if (revocation == 2) {
            _ = try f.service.revokeTrustedDevice(owner, alice, root_key, 21);
        } else {
            f.receiver_keys.service.findHandle(f.recipient.signer.handle_id).?.revoked = true;
        }
        if (f.commit()) |_| return error.RevokedWriteAccepted else |_| {}
        try std.testing.expect(f.receiver.transfer == null);
        try std.testing.expect(std.mem.allEqual(u8, &f.scratch, 0));
        try std.testing.expectEqual(@as(usize, 1), f.disk.service.versionCount());
        try std.testing.expectEqualStrings("original", try f.disk.text());
    }
}

test "object transfer bounds chunks rejects conflicting retries and expires incomplete state" {
    const f = try Fixture.init();
    defer f.deinit();
    var request = f.request("abcdef");
    request.object_id += 1;
    try std.testing.expectError(error.MalformedTransfer, f.begin(request));
    request = f.request("abcdef");
    request.length = f.scratch.len + 1;
    try std.testing.expectError(error.TransferTooLarge, f.begin(request));
    _ = try f.begin(f.request("abcdef"));
    try std.testing.expectError(error.TransferIncomplete, f.commit());
    try std.testing.expectError(error.TransferOutOfOrder, f.chunk(3, "def"));
    _ = try f.chunk(0, "abc");
    try std.testing.expectEqual(@as(u32, 3), (try f.chunk(0, "abc")).received);
    try std.testing.expectError(error.TransferMismatch, f.chunk(0, "xxx"));
    _ = try f.chunk(3, "xyz");
    try std.testing.expectError(error.TransferMismatch, f.commit());
    f.receiver.expire(f.authority.now_ticks + transfer.MAX_IDLE_TICKS);
    try std.testing.expect(f.receiver.transfer == null);
    try std.testing.expect(std.mem.allEqual(u8, &f.scratch, 0));
    try std.testing.expectEqual(@as(usize, 1), f.disk.service.versionCount());
}

test "object transfer requires exact local capability bindings and writable network shares" {
    for (0..13) |variant| {
        const f = try Fixture.init();
        defer f.deinit();
        var mint = capability.MintRequest{
            .holder = alice,
            .issuer = owner,
            .target = .{ .kind = .object, .id = 900 },
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .scope = .{ .workspace_id = f.disk.workspace_id, .broker_only = true },
            .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 90_000 },
        };
        switch (variant) {
            0 => mint.holder = bob,
            1 => mint.target.id = 901,
            2 => mint.scope.workspace_id = f.disk.workspace_id + 1,
            3 => mint.scope.workspace_id = null,
            4 => mint.scope.broker_only = false,
            5 => mint.scope.local_only = true,
            6 => mint.scope.task_id = f.service.task_id + 1,
            7 => mint.rights.object.object_write = false,
            8 => mint.lease.expires_at_ticks = 19,
            9, 10, 11 => {
                var grant = f.disk.service.findShareGrant(f.disk.workspace_id, alice).?;
                if (variant == 9) grant.network_scope = .local_only;
                if (variant == 10) grant.expires_at_ticks = 19;
                if (variant == 11) grant = try grant.withObjectScope(@import("../core/ids.zig").object(901), "elsewhere");
                try f.disk.service.shareWorkspace(f.disk.workspace_id, grant);
            },
            12 => {
                const policy_id = f.service.findWorkspacePolicy(f.disk.workspace_id).?.device_to_device_policy_id;
                _ = try f.service.configureWorkspacePolicy(.{ .workspace_id = f.disk.workspace_id, .owner = owner, .device_to_device_policy_id = policy_id, .selective_prefixes = &.{"elsewhere/"} });
            },
            else => unreachable,
        }
        const grant = try f.capabilities.mintBootRoot(mint);
        f.receiver.binding.peer_capability_id = grant.id;
        const count = f.disk.service.versionCount();
        const writes = f.disk.writes;
        if (f.begin(f.request("unauthorized bytes"))) |_| return error.UnauthorizedBeginAccepted else |_| {}
        try std.testing.expect(f.receiver.transfer == null);
        try std.testing.expectEqual(count, f.disk.service.versionCount());
        try std.testing.expectEqual(writes, f.disk.writes);
    }
}

test "object transfer erases staging after local service authority is revoked" {
    const f = try Fixture.init();
    defer f.deinit();
    try f.stage("pending bytes");
    try f.capabilities.revokeGrant(f.authority.capability_id);
    if (f.commit()) |_| return error.RevokedServiceAccepted else |_| {}
    try std.testing.expect(f.receiver.transfer == null);
    try std.testing.expect(std.mem.allEqual(u8, &f.scratch, 0));
    try std.testing.expectEqualStrings("original", try f.disk.text());
}

test "object transfer refuses byte replacement of secrets collections and event streams" {
    for ([_]objects.ObjectType{ .secret, .collection, .event_stream }) |kind| {
        const f = try Fixture.init();
        defer f.deinit();
        const created = try f.disk.service.putVersion(.{ .object_type = kind, .payload = "typed payload", .metadata = try objects.signMetadata(durable.signer, "typed", "application/octet-stream", kind, "typed payload", 21) });
        try f.disk.service.beginTransaction(f.disk.workspace_id);
        try f.disk.service.stagePut(f.disk.workspace_id, durable.path, created.object_id, created.version_id, kind);
        _ = try f.disk.service.commit(f.disk.workspace_id, 21);
        const grant = try f.disk.service.findShareGrant(f.disk.workspace_id, alice).?.withObjectScope(created.object_id, durable.path);
        try f.disk.service.shareWorkspace(f.disk.workspace_id, grant);
        const cap = try f.capabilities.mintBootRoot(.{
            .holder = alice,
            .issuer = owner,
            .target = .{ .kind = .object, .id = created.object_id.raw() },
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .scope = .{ .workspace_id = f.disk.workspace_id, .broker_only = true },
            .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 90_000 },
        });
        f.receiver.binding.object_id = created.object_id.raw();
        f.receiver.binding.peer_capability_id = cap.id;
        var request = f.request("replacement");
        request.object_id = created.object_id.raw();
        request.expected_version = created.version_id.raw();
        const writes = f.disk.writes;
        try std.testing.expectError(error.UnsupportedObjectType, f.begin(request));
        try std.testing.expect(f.receiver.transfer == null);
        try std.testing.expectEqual(writes, f.disk.writes);
        try std.testing.expectEqualStrings("typed payload", try f.disk.text());
    }
}

test "object transfer cannot overwrite concurrent local edits or carry chunks into a new session" {
    const f = try Fixture.init();
    defer f.deinit();
    try f.stage("remote edit");
    f.sender.close();
    f.recipient.close();
    try f.connect();
    try std.testing.expectError(error.TransferMissing, f.commit());
    try std.testing.expect(std.mem.allEqual(u8, &f.scratch, 0));
    try f.stage("remote edit");
    var editor = document_save.Session{};
    _ = try editor.saveForVerification(&f.disk.service, .{ .workspace_id = f.disk.workspace_id, .path = durable.path, .expected_version_id = f.disk.original_version_id, .payload = "local edit", .signer = durable.signer, .tick = 22 });
    try std.testing.expectError(error.ObjectChanged, f.commit());
    try std.testing.expectEqualStrings("local edit", try f.disk.text());
    try std.testing.expectEqual(@as(usize, 2), f.disk.service.versionCount());
}
