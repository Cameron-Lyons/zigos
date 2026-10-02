const std = @import("std");
const sender_mod = @import("object_sender.zig");
const admission = @import("peer_admission.zig");
const transfer = @import("object_transfer.zig");
const peer = @import("peer_channel.zig");
const storage = @import("../storage/storage_service.zig");
const objects = @import("../storage/object_store.zig");
const Base = @import("object_transfer_test.zig").Fixture;
const signer = @import("../storage/document_save_test.zig").signer;
const owner = @import("../core/principal.zig").PrincipalId{ .kind = .user, .serial = 1 };
const mac_a = [6]u8{ 2, 0, 0, 0, 0, 1 };
const mac_b = [6]u8{ 2, 0, 0, 0, 0, 2 };
const source_path = "outbox/source";
const Leg = enum { offer, begin, chunk, commit, progress, receipt };

pub const Fixture = struct {
    var active: *Fixture = undefined;
    base: *Base,
    sender: sender_mod.Sender = undefined,
    sessions: [2]admission.Session = undefined,
    pool: admission.Sessions = .{},
    staging: [5000]u8 = @splat(0),
    now: u64 = 20,
    drop: ?Leg = null,
    drops_left: u8 = 1,
    dropped: usize = 0,
    block_source: bool = false,
    failed_packet: [peer.MAX_FRAME]u8 = undefined,
    failed_len: usize = 0,
    identical_retries: bool = true,
    sent: [2]usize = @splat(0),
    source_cap: u64 = 0,
    source_object: u64 = 0,

    pub fn init(payload: []const u8) !*Fixture {
        const f = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(f);
        const base = try Base.init();
        errdefer base.deinit();
        f.* = .{ .base = base };
        base.sender.graph = base.service.deviceGraph();
        base.receiver.scratch = &f.staging;
        const store = &base.disk.service;
        const created = try store.putVersion(.{ .object_type = .blob, .payload = payload, .metadata = try objects.signMetadata(signer, "outbound", "application/octet-stream", .blob, payload, 10) });
        f.source_object = created.object_id.raw();
        try store.beginTransaction(base.disk.workspace_id);
        try store.stagePut(base.disk.workspace_id, source_path, created.object_id, created.version_id, .blob);
        _ = try store.commit(base.disk.workspace_id, 10);
        const cap = try base.capabilities.mintBootRoot(.{
            .holder = owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .workspace, .id = base.disk.workspace_id },
            .rights = .{ .workspace = .{ .object_read = true, .object_write = true, .capability_derive = true } },
            .scope = .{ .workspace_id = base.disk.workspace_id, .broker_only = true },
            .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100_000 },
            .audit = .{},
        });
        var port = storage.StoragePort.init(store, &base.capabilities);
        const grant = try port.grantObjectShare(&base.capabilities, .{ .task_id = 701, .principal = owner, .capability_id = cap.id, .now_ticks = 10 }, base.disk.workspace_id, created.object_id, .{ .principal_id = .{ .kind = .device, .serial = 22 }, .can_read = true, .can_write = false, .network_scope = .trusted_overlay, .expires_at_ticks = 90_000 });
        f.source_cap = grant.capability.id;
        _ = try store.checkpointDurable();
        f.sender = try sender_mod.Sender.init(store, &base.service, &base.capabilities, .{ .workspace_id = base.disk.workspace_id, .object_id = created.object_id.raw(), .local_device = 11, .peer_device = 22, .peer_capability_id = grant.capability.id }, &base.sender, base.authority);
        f.sessions[0] = try admission.Session.initSender(&base.sender, &f.sender, base.authority, mac_b, 1_000, "");
        f.sessions[1] = try admission.Session.initOffering(&base.recipient, &base.receiver, base.signer, base.authority, mac_a, 1_000);
        return f;
    }

    pub fn deinit(f: *Fixture) void {
        f.pool.deinit();
        f.base.deinit();
        std.testing.allocator.destroy(f);
    }

    fn attach(f: *Fixture) !void {
        for (&f.sessions) |*s| try f.pool.attach(s, f.now);
    }

    fn send(destination: [6]u8, bytes: []const u8) bool {
        const f = active;
        const from: usize = if (std.mem.eql(u8, &destination, &mac_b)) 0 else 1;
        const leg: Leg = if (from == 0)
            (switch (f.sender.phase) {
                .begin => .begin,
                .chunk => .chunk,
                .commit => .commit,
                else => unreachable,
            })
        else if (f.sessions[1].offering) .offer else if (f.base.receiver.currentProgress().?.durable()) .receipt else .progress;
        if (from == 0) {
            if (f.failed_len != 0 and !std.mem.eql(u8, f.failed_packet[0..f.failed_len], bytes)) f.identical_retries = false;
            if (f.block_source) {
                @memcpy(f.failed_packet[0..bytes.len], bytes);
                f.failed_len = bytes.len;
                return false;
            }
            f.failed_len = 0;
        }
        f.sent[from] += 1;
        if (f.drop == leg and f.drops_left != 0) {
            f.drops_left -= 1;
            f.dropped += 1;
            return true;
        }
        _ = f.pool.admit(bytes, f.now);
        return true;
    }

    fn tick(f: *Fixture) void {
        active = f;
        std.debug.assert(f.pool.service(f.now, send) <= admission.DISPATCH_BUDGET);
        f.now += 1;
    }

    fn finish(f: *Fixture) !void {
        for (0..800) |_| {
            f.tick();
            if (f.sender.complete()) return;
            if (!f.sessions[0].active or !f.sessions[1].active) return error.TransferRetired;
        }
        return error.TransferTimeout;
    }

    fn prepareChunk(f: *Fixture) !void {
        for (0..80) |_| {
            f.tick();
            if (f.sender.phase == .chunk and f.sessions[0].outgoing_len != 0) return;
        }
        return error.ChunkNotPrepared;
    }

    fn reply(f: *Fixture, progress: transfer.Progress) !bool {
        var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
        var wire: [peer.MAX_FRAME]u8 = undefined;
        var authority = f.base.authority;
        authority.now_ticks = f.now;
        return f.sender.receive(&f.base.sender, authority, try f.base.recipient.seal(&wire, try transfer.encodeProgress(&plaintext, progress), f.now));
    }
};

test "object sender streams across storage pages and recovers lost requests and durable receipts" {
    var payload: [objects.MAX_CHUNK_BYTES + transfer.MAX_CHUNK + 17]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i * 13);
    for (std.meta.tags(Leg)) |leg| {
        const f = try Fixture.init(&payload);
        defer f.deinit();
        try f.attach();
        f.drop = leg;
        f.drops_left = 2;
        const versions = f.base.disk.service.versionCount();
        try f.finish();
        try std.testing.expectEqual(@as(usize, 2), f.dropped);
        try std.testing.expect(f.sender.receipt.?.durable());
        try std.testing.expectEqual(versions + 1, f.base.disk.service.versionCount());
        f.base.disk.crash();
        const entry = try f.base.disk.service.resolve(f.base.disk.workspace_id, @import("../storage/document_save_test.zig").path);
        var actual: [payload.len]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &payload, try f.base.disk.service.versionPayloadInto(f.base.disk.service.version(entry.version_id).?, &actual));
    }
}

test "object sender backpressure retains ciphertext without advancing a transport nonce" {
    const f = try Fixture.init("pending read-authorized payload");
    defer f.deinit();
    try f.attach();
    try f.prepareChunk();
    f.block_source = true;
    const nonce = f.base.sender.crypto.transport.send.nonce;
    for (0..10) |_| f.tick();
    try std.testing.expect(f.failed_len != 0 and f.identical_retries);
    try std.testing.expectEqual(nonce, f.base.sender.crypto.transport.send.nonce);
    f.block_source = false;
    try f.finish();
    try std.testing.expect(f.identical_retries);
}

test "object sender resumes and retries from a later storage page" {
    var payload: [objects.MAX_CHUNK_BYTES + transfer.MAX_CHUNK * 3 + 17]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i * 19 + i / objects.MAX_CHUNK_BYTES);
    const f = try Fixture.init(&payload);
    defer f.deinit();
    try f.attach();
    for (0..100) |_| {
        f.tick();
        if (f.sender.acknowledged >= objects.MAX_CHUNK_BYTES) break;
    } else return error.LaterPageNotReached;
    f.block_source = true;
    const acknowledged = f.sender.acknowledged;
    f.tick();
    const nonce = f.base.sender.crypto.transport.send.nonce;
    for (0..10) |_| f.tick();
    try std.testing.expect(f.failed_len != 0 and f.identical_retries);
    try std.testing.expectEqual(acknowledged, f.sender.acknowledged);
    try std.testing.expectEqual(nonce, f.base.sender.crypto.transport.send.nonce);
    f.block_source = false;
    try f.finish();
    f.base.disk.crash();
    const entry = try f.base.disk.service.resolve(f.base.disk.workspace_id, @import("../storage/document_save_test.zig").path);
    var actual: [payload.len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &payload, try f.base.disk.service.versionPayloadInto(f.base.disk.service.version(entry.version_id).?, &actual));
}

test "object sender rejects stale speculative and premature durable receipts" {
    const f = try Fixture.init("a payload awaiting its first chunk");
    defer f.deinit();
    try f.attach();
    try f.prepareChunk();
    const id = f.sender.request.id;
    const length = f.sender.request.length;
    try std.testing.expectError(error.InvalidReceipt, f.reply(.{ .id = id + 1, .received = 0 }));
    try std.testing.expectError(error.InvalidReceipt, f.reply(.{ .id = id, .received = length + 1 }));
    try std.testing.expectError(error.InvalidReceipt, f.reply(.{ .id = id, .received = length })); // Not transmitted yet.
    try std.testing.expectError(error.InvalidReceipt, f.reply(.{ .id = id, .received = length, .version_id = 9, .checkpoint_generation = 1 }));
    try std.testing.expect(!try f.reply(.{ .id = id, .received = 0 }));
    const retry = f.sessions[0].retry_at;
    try std.testing.expect(!f.sender.complete() and f.sessions[0].retry_at == retry);
    try f.finish();
}

test "object sender revocation source changes and expiry cancel queued plaintext-derived packets" {
    for (0..6) |fault| {
        const f = try Fixture.init("private outbound data");
        defer f.deinit();
        try f.attach();
        try f.prepareChunk();
        const sent = f.sent[0];
        switch (fault) {
            0 => try f.base.capabilities.revokeGrant(f.source_cap),
            1 => try f.base.disk.service.shareWorkspace(f.base.disk.workspace_id, .{ .principal_id = .{ .kind = .device, .serial = 22 }, .can_read = false, .can_write = false, .network_scope = .trusted_overlay }),
            2 => try f.base.capabilities.revokeGrant(f.base.authority.capability_id),
            3 => f.base.sender_keys.service.findHandle(f.base.sender.signer.handle_id).?.revoked = true,
            4 => f.sessions[0].expires_at = f.now,
            else => {
                const replacement = try f.base.disk.service.putVersion(.{ .preferred_object_id = objects.ids.object(f.source_object), .object_type = .blob, .payload = "changed", .metadata = try objects.signMetadata(signer, "outbound", "application/octet-stream", .blob, "changed", f.now) });
                try f.base.disk.service.beginTransaction(f.base.disk.workspace_id);
                try f.base.disk.service.stagePut(f.base.disk.workspace_id, source_path, replacement.object_id, replacement.version_id, .blob);
                _ = try f.base.disk.service.commit(f.base.disk.workspace_id, f.now);
            },
        }
        f.tick();
        try std.testing.expect(!f.sessions[0].active and f.base.sender.crypto == .closed);
        try std.testing.expectEqual(sent, f.sent[0]);
        try std.testing.expect(std.mem.allEqual(u8, &f.sessions[0].incoming, 0) and std.mem.allEqual(u8, &f.sessions[0].outgoing, 0));
        try std.testing.expect(std.mem.allEqual(u8, &f.sender.request.digest, 0));
    }
}

test "object sender does not claim success before a failed durable barrier is retried" {
    const f = try Fixture.init("");
    defer f.deinit();
    try f.attach();
    f.base.disk.fail_flushes = true;
    for (0..40) |_| f.tick();
    try std.testing.expect(!f.sender.complete());
    const versions = f.base.disk.service.versionCount();
    f.base.disk.fail_flushes = false;
    try f.finish();
    try std.testing.expectEqual(versions, f.base.disk.service.versionCount());
    try std.testing.expectEqual(@as(u32, 0), f.sender.receipt.?.received);
}

test "object sender admission rejects wrong scopes and selective policy denies cached egress" {
    const f = try Fixture.init("locally selected bytes");
    defer f.deinit();
    var binding = f.sender.binding;
    binding.object_id += 1;
    try std.testing.expectError(error.PermissionDenied, sender_mod.Sender.init(f.sender.store, f.sender.sync, f.sender.capabilities, binding, &f.base.sender, f.base.authority));
    binding = f.sender.binding;
    binding.workspace_id += 1;
    try std.testing.expectError(error.PermissionDenied, sender_mod.Sender.init(f.sender.store, f.sender.sync, f.sender.capabilities, binding, &f.base.sender, f.base.authority));
    binding = f.sender.binding;
    binding.peer_device += 1;
    try std.testing.expectError(error.PermissionDenied, sender_mod.Sender.init(f.sender.store, f.sender.sync, f.sender.capabilities, binding, &f.base.sender, f.base.authority));
    try f.attach();
    try f.prepareChunk();
    const existing = f.base.service.findWorkspacePolicy(f.base.disk.workspace_id).?.*;
    _ = try f.base.service.configureWorkspacePolicy(.{ .owner = owner, .workspace_id = f.base.disk.workspace_id, .require_shared_access = true, .device_to_device_policy_id = existing.device_to_device_policy_id, .selective_prefixes = &.{"unshared/"} });
    const sent = f.sent[0];
    f.tick();
    try std.testing.expect(!f.sessions[0].active);
    try std.testing.expectEqual(sent, f.sent[0]);
}

test "object sender pins an offer once and allocates its request ID from the channel nonce" {
    const f = try Fixture.init("private source");
    defer f.deinit();
    var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
    var wire: [peer.MAX_FRAME]u8 = undefined;
    // Earlier traffic consumes a nonce, even if its ciphertext was lost.
    _ = try f.base.sender.seal(&wire, "earlier authenticated traffic", f.now);
    const expected_id = f.base.sender.crypto.transport.send.nonce + 1;
    const offer = transfer.Offer{ .workspace_id = 9, .object_id = 10, .version_id = 11, .limit = 100 };
    try std.testing.expect(try f.sender.receive(&f.base.sender, f.base.authority, try f.base.recipient.seal(&wire, try transfer.encodeOffer(&plaintext, offer), f.now)));
    try std.testing.expectEqual(expected_id, f.sender.request.id);
    const request = f.sender.request;
    const redirect = transfer.Offer{ .workspace_id = 19, .object_id = 20, .version_id = 21, .limit = 100 };
    try std.testing.expect(!try f.sender.receive(&f.base.sender, f.base.authority, try f.base.recipient.seal(&wire, try transfer.encodeOffer(&plaintext, redirect), f.now)));
    try std.testing.expectEqual(request, f.sender.request);
    f.base.capabilities.revokeGrant(f.source_cap) catch unreachable;
    try std.testing.expectError(error.CapabilityNotFound, f.sender.encode(&f.base.sender, f.base.authority, &plaintext));
}
