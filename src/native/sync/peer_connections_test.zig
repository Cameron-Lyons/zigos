const std = @import("std");
const owned = @import("peer_connections.zig");
const peer = @import("peer_channel.zig");
const handshake = @import("peer_handshake.zig");
const admission = @import("peer_admission.zig");
const Base = @import("object_sender_test.zig").Fixture;
const transfer_fixture = @import("object_transfer_test.zig");
const storage = @import("../storage/storage_service.zig");
const sync = @import("sync_service.zig");
const mac_a = [6]u8{ 2, 0, 0, 0, 0, 1 };
const mac_b = [6]u8{ 2, 0, 0, 0, 0, 2 };
const attest = @import("../platform/tpm_attestation.zig");
const quote = @import("../platform/tpm2_quote.zig");
const AttestationDrop = enum { none, challenge, response, acceptance };
const Drop = enum { none, final_confirmation, first_offer, first_request };

const Fixture = struct {
    var active: *Fixture = undefined;
    base: *Base,
    owners: owned.Connections = .{},
    handshakes: handshake.Handshakes = .{},
    sessions: admission.Sessions = .{},
    handles: [2]owned.Handle = undefined,
    now: u64 = 20,
    drop: Drop = .none,
    dropped: usize = 0,
    sends: [2]usize = @splat(0),
    owners_active: bool = true,
    pending: ?attest.Pending = null,
    verifier_source: bool = true,
    attest_drop: AttestationDrop = .none,
    attest_dropped: usize = 0,
    quote_count: usize = 0,
    quote_wakes: usize = 0,
    auto_quote: bool = true,

    fn enableAttestation(f: *Fixture) !void {
        const evidence = try quote.testing.QuoteFixture.initFor(@splat(1), @splat(2));
        const label: [64]u8 = @splat('a');
        const enrollment = try attest.Enrollment.init(.{ .kind = .device, .serial = if (f.verifier_source) 22 else 11 }, evidence.identity, 9, &label);
        var entropy = struct {
            pub fn random(_: *@This(), out: []u8) !void {
                @memset(out, 0x56);
            }
        }{};
        f.pending = try attest.Pending.init(&entropy, enrollment, @splat(2), .{ .remote_party = &label, .policy_label = &label, .revoked_generations = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } }, 200, 7_000);
    }

    fn init(payload: []const u8) !*Fixture {
        const f = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(f);
        f.* = .{ .base = try Base.init(payload) };
        return f;
    }

    fn deinit(f: *Fixture) void {
        f.owners.deinit(&f.handshakes, &f.sessions);
        f.handshakes.deinit();
        f.sessions.deinit();
        f.base.deinit();
        std.testing.allocator.destroy(f);
    }

    fn request(f: *Fixture, source: bool) owned.Request {
        const b = f.base.base;
        return .{
            .store = &b.disk.service,
            .service = &b.service,
            .capabilities = &b.capabilities,
            .authority = b.authority,
            .binding = if (source) f.base.sender.binding else b.receiver.binding,
            .root_pin = b.sender.root_pin,
            .device_key = if (source) b.sender.signer else b.recipient.signer,
            .peer_mac = if (source) mac_b else mac_a,
            .expires_at = 1_000,
            .attestation = if (f.pending) |*pending| (if (source == f.verifier_source) .{ .verify = pending } else .{ .prove = &pending.enrollment }) else null,
            .direction = if (source) .send else .{ .receive = .{ .signer = b.signer, .limit = 5000 } },
        };
    }

    fn open(f: *Fixture) !void {
        f.handles[0] = try f.owners.open(&f.handshakes, &f.sessions, f.request(true));
        f.handles[1] = try f.owners.open(&f.handshakes, &f.sessions, f.request(false));
    }

    fn send(destination: [6]u8, bytes: []const u8) bool {
        const f = active;
        const from: usize = if (std.mem.eql(u8, &destination, &mac_b)) 0 else 1;
        f.sends[from] += 1;
        if (bytes[5] == 4 and f.dropped < 2) {
            const nonce = std.mem.readInt(u64, bytes[peer.HEADER + 16 ..][0..8], .little);
            const drop = switch (f.drop) {
                .none => false,
                .final_confirmation => from == 0 and nonce == 0,
                .first_offer => from == 1 and nonce != 0,
                .first_request => from == 0 and nonce != 0,
            };
            if (drop) {
                f.dropped += 1;
                return true;
            }
        }
        if (bytes[5] == peer.ATTESTATION_KIND and f.attest_dropped < 2) {
            const nonce = std.mem.readInt(u64, bytes[peer.HEADER + 16 ..][0..8], .little);
            const drop = switch (f.attest_drop) {
                .none => false,
                .challenge => from == @intFromBool(!f.verifier_source) and nonce == 1,
                .response => from == @intFromBool(f.verifier_source) and nonce == 1,
                .acceptance => from == @intFromBool(!f.verifier_source) and nonce == 4,
            };
            if (drop) {
                f.attest_dropped += 1;
                return true;
            }
        }
        if (!f.handshakes.admit(bytes, f.now) and !f.owners.admitAttestation(bytes, f.now)) _ = f.sessions.admit(bytes, f.now);
        return true;
    }

    fn isActive(f: *Fixture, _: *sync.Service, _: *storage.Service) bool {
        return f.owners_active;
    }

    fn wake(f: *Fixture, task_id: u64, _: u64) bool {
        std.debug.assert(task_id == f.base.base.service.task_id);
        f.quote_wakes += 1;
        return true;
    }

    fn tick(f: *Fixture) !void {
        active = f;
        f.owners.retireInactive(&f.handshakes, &f.sessions, f, isActive);
        var work = f.owners.advance(&f.handshakes, &f.sessions, f.now, 2);
        for (0..3) |offset| {
            work += switch ((f.now + offset) % 3) {
                0 => f.handshakes.service(f.now, send, 2 - work),
                1 => f.owners.serviceAttestations(f.now, send, 2 - work),
                else => f.sessions.serviceBudget(f.now, send, 2 - work),
            };
        }
        try std.testing.expect(work <= 2);
        f.owners.reap(&f.handshakes, &f.sessions);
        f.owners.wakeAttestationOwners(f, wake, f.now);
        if (f.pending != null) {
            if (f.owners.status(f.handles[@intFromBool(!f.verifier_source)])) |state| {
                if (state.phase == .transferring or state.phase == .complete) try std.testing.expect(f.pending.?.verifier.consumed);
            }
            if (f.auto_quote) if (f.owners.attestationChallenge(f.handles[@intFromBool(f.verifier_source)], f.now)) |challenge| {
                const response = try quote.testing.QuoteFixture.initFor(challenge.qualifyingData(), challenge.approved_pcr11);
                try f.owners.completeAttestation(f.handles[@intFromBool(f.verifier_source)], &response.evidence, f.now);
                f.quote_count += 1;
            };
        }
        f.now += 1;
    }

    fn finish(f: *Fixture) !void {
        for (0..700) |_| {
            try f.tick();
            const status = f.owners.status(f.handles[0]) orelse return error.SourceRetired;
            if (status.phase == .complete) return;
        }
        return error.TransferTimeout;
    }
};

test "peer connections own storage-backed transfers and recover losses across automatic handoff" {
    var payload: [4294]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i * 17);
    for (std.meta.tags(Drop)) |drop| {
        const f = try Fixture.init(&payload);
        defer f.deinit();
        f.drop = drop;
        try f.open();
        try std.testing.expectEqual(@as(usize, 0), f.owners.slots[0].connection.?.buffer.len);
        try std.testing.expectEqual(@as(usize, 5000), f.owners.slots[1].connection.?.buffer.len);
        try f.finish();
        try std.testing.expectEqual(@as(usize, if (drop == .none) 0 else 2), f.dropped);
        try std.testing.expect(!f.handshakes.hasSessions());
        const source = f.owners.status(f.handles[0]).?;
        const target = f.owners.status(f.handles[1]).?;
        try std.testing.expectEqual(source.progress, target.progress);
        try std.testing.expectEqualSlices(u8, &source.digest, &target.digest);
        try std.testing.expect(std.mem.allEqual(u8, f.owners.slots[1].connection.?.buffer, 0));
        const b = f.base.base;
        b.disk.crash();
        const entry = try b.disk.service.resolve(b.disk.workspace_id, @import("../storage/document_save_test.zig").path);
        var actual: [payload.len]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &payload, try b.disk.service.versionPayloadInto(b.disk.service.version(entry.version_id).?, &actual));
    }
}

test "peer connections reject duplicates and stale handles across slot reuse and reset" {
    const f = try Fixture.init("owned transfer");
    defer f.deinit();
    const request = f.request(true);
    const first = try f.owners.open(&f.handshakes, &f.sessions, request);
    try std.testing.expectError(error.PeerAlreadyAdmitted, f.owners.open(&f.handshakes, &f.sessions, request));
    try f.owners.release(&f.handshakes, &f.sessions, first);
    const second = try f.owners.open(&f.handshakes, &f.sessions, request);
    try std.testing.expect(first != second and f.owners.status(first) == null);
    try std.testing.expectError(error.StalePeerConnection, f.owners.release(&f.handshakes, &f.sessions, first));
    try std.testing.expect(f.owners.status(second) != null);
    f.owners.deinit(&f.handshakes, &f.sessions);
    const third = try f.owners.open(&f.handshakes, &f.sessions, request);
    try std.testing.expect(third != second and f.owners.status(second) == null);
    try std.testing.expect(f.owners.status(@fromBackingInt(@intCast(0))) == null);
}

test "peer connections bound all local allocations and retire exhausted generations" {
    const f = try Fixture.init("capacity");
    defer f.deinit();
    const b = f.base.base;
    for (0..owned.MAX_CONNECTIONS + 1) |i| {
        var request = f.request(true);
        request.binding.local_device = 100 + i;
        _ = try b.service.enrollTrustedDevice(.{ .kind = .user, .serial = 1 }, .{ .kind = .device, .serial = 100 + i }, "extra", transfer_fixture.root_key, transfer_fixture.alice_key, 10);
        if (i == owned.MAX_CONNECTIONS) {
            try std.testing.expectError(error.PeerTableFull, f.owners.open(&f.handshakes, &f.sessions, request));
        } else _ = try f.owners.open(&f.handshakes, &f.sessions, request);
    }
    f.owners.deinit(&f.handshakes, &f.sessions);
    for (&f.owners.slots) |*slot| slot.generation = std.math.maxInt(u64) >> 2;
    try std.testing.expectError(error.PeerTableFull, f.owners.open(&f.handshakes, &f.sessions, f.request(true)));
    try std.testing.expect(!f.handshakes.hasSessions() and !f.sessions.hasSessions());
}

test "peer connections deny invalid local admission before allocating a slot" {
    const f = try Fixture.init("admission");
    defer f.deinit();
    var request = f.request(false);
    request.binding.peer_capability_id = f.base.source_cap;
    try std.testing.expectError(error.PermissionDenied, f.owners.open(&f.handshakes, &f.sessions, request));
    request = f.request(false);
    request.direction.receive.limit = @import("../storage/object_store.zig").MAX_PAYLOAD_BYTES + 1;
    try std.testing.expectError(error.TransferTooLarge, f.owners.open(&f.handshakes, &f.sessions, request));
    request = f.request(true);
    request.authority.task_id += 1;
    try std.testing.expectError(error.PermissionDenied, f.owners.open(&f.handshakes, &f.sessions, request));
    for (f.owners.slots) |slot| try std.testing.expect(slot.connection == null and slot.generation == 0);
    try std.testing.expect(!f.handshakes.hasSessions() and !f.sessions.hasSessions());
}

test "peer connections revalidate authority and source version at automatic handoff" {
    for (0..2) |fault| {
        const f = try Fixture.init("source before handshake");
        defer f.deinit();
        try f.open();
        for (0..100) |_| {
            try f.tick();
            if (f.owners.slots[0].connection.?.state.handshake.complete()) break;
        }
        try std.testing.expect(f.owners.hasReadyWork());
        const b = f.base.base;
        if (fault == 0) {
            try b.capabilities.revokeGrant(f.base.source_cap);
        } else {
            const objects = @import("../storage/object_store.zig");
            const signer = @import("../storage/document_save_test.zig").signer;
            const replacement = try b.disk.service.putVersion(.{ .preferred_object_id = objects.ids.object(f.base.source_object), .object_type = .blob, .payload = "changed", .metadata = try objects.signMetadata(signer, "outbound", "application/octet-stream", .blob, "changed", f.now) });
            try b.disk.service.beginTransaction(b.disk.workspace_id);
            try b.disk.service.stagePut(b.disk.workspace_id, "outbox/source", replacement.object_id, replacement.version_id, .blob);
            _ = try b.disk.service.commit(b.disk.workspace_id, f.now);
        }
        const sent = f.sends[0];
        try f.tick();
        try std.testing.expect(f.owners.status(f.handles[0]) == null);
        try std.testing.expectEqual(sent, f.sends[0]);
    }
}

test "peer connections release ownership on task retirement expiry and failed authentication" {
    for (0..3) |fault| {
        const f = try Fixture.init("pending");
        defer f.deinit();
        try f.open();
        if (fault == 0) {
            f.owners_active = false;
        } else if (fault == 1) {
            f.now = 1_000;
        } else {
            try f.tick();
            // Each peer receives a truncated flight of the expected kind, so
            // the protocol parser closes it and the owner reclaims its bytes.
            for (f.owners.slots[0..2]) |slot| {
                const c = slot.connection.?;
                var frame: [peer.HEADER + 1]u8 = @splat(0);
                @memcpy(frame[0..4], peer.MAGIC);
                frame[4] = peer.VERSION;
                frame[5] = c.channel.crypto.handshake.step + 1;
                std.mem.writeInt(u64, frame[6..14], c.channel.remote, .little);
                std.mem.writeInt(u64, frame[14..22], c.channel.local, .little);
                try std.testing.expect(f.handshakes.admit(&frame, f.now));
            }
        }
        try f.tick();
        for (f.handles) |handle| try std.testing.expect(f.owners.status(handle) == null);
        for (f.owners.slots) |slot| try std.testing.expect(slot.connection == null);
        try std.testing.expect(!f.handshakes.hasSessions() and !f.sessions.hasSessions());
    }
}

test "peer connections failed handoff preserves an independently admitted session" {
    const f = try Fixture.init("pending handoff");
    defer f.deinit();
    try f.open();
    for (0..100) |_| {
        try f.tick();
        if (f.owners.slots[0].connection.?.state.handshake.complete()) break;
    }
    try std.testing.expect(f.owners.hasReadyWork());
    const borrowed = &f.base.sessions[0];
    try f.sessions.attach(borrowed, f.now);
    _ = f.owners.advance(&f.handshakes, &f.sessions, f.now, 2);
    try std.testing.expect(f.owners.status(f.handles[0]) == null);
    try std.testing.expect(borrowed.active and borrowed.channel.established());
    try std.testing.expect(f.sessions.slots[0].? == borrowed);
}

test "session manager peer connections keep retired handles invalid across full reset" {
    const f = try Fixture.init("reset lifetime");
    defer f.deinit();
    const manager_mod = @import("../session/session_manager.zig");
    manager_mod.testing.resetState();
    defer manager_mod.testing.resetState();
    const manager = manager_mod.system();
    const first = try manager.peer_connections.open(&manager.peer_handshakes, &manager.peers, f.request(true));
    manager.reset();
    try std.testing.expect(manager.peerConnectionStatus(first) == null);
    try std.testing.expect(!manager.peer_handshakes.hasSessions() and !manager.peers.hasSessions());
    const second = try manager.peer_connections.open(&manager.peer_handshakes, &manager.peers, f.request(true));
    try std.testing.expect(first != second and manager.peerConnectionStatus(first) == null);
    try std.testing.expectError(error.StalePeerConnection, manager.releasePeerConnection(first));
    try std.testing.expect(manager.peerConnectionStatus(second) != null);
}

test "peer connections require attestation before durable transfer and retry lost fragments and acceptance" {
    const payload: [4294]u8 = @splat(0x48);
    for ([_]bool{ true, false }) |source| for (std.meta.tags(AttestationDrop)) |loss| {
        const f = try Fixture.init(&payload);
        defer f.deinit();
        f.verifier_source = source;
        try f.enableAttestation();
        f.attest_drop = loss;
        f.drop = .final_confirmation;
        try f.open();
        try f.finish();
        try std.testing.expectEqual(@as(usize, if (loss == .none) 0 else 2), f.attest_dropped);
        try std.testing.expectEqual(@as(usize, 2), f.dropped);
        try std.testing.expectEqual(@as(usize, 1), f.quote_count);
        try std.testing.expectEqual(@as(usize, 1), f.quote_wakes);
        try std.testing.expect(!f.owners.hasAttestationWork(f.now));
        const target = f.owners.status(f.handles[1]).?;
        try std.testing.expect(target.phase == .complete);
        const b = f.base.base;
        b.disk.crash();
        const entry = try b.disk.service.resolve(b.disk.workspace_id, @import("../storage/document_save_test.zig").path);
        var actual: [payload.len]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &payload, try b.disk.service.versionPayloadInto(b.disk.service.version(entry.version_id).?, &actual));
    };
}

test "peer connections delayed attestation cannot revive released expired revoked or retired transfers" {
    for (0..5) |fault| {
        const f = try Fixture.init("protected object");
        defer f.deinit();
        try f.enableAttestation();
        f.auto_quote = false;
        try f.open();
        var challenge: ?attest.Challenge = null;
        for (0..100) |_| {
            try f.tick();
            challenge = f.owners.attestationChallenge(f.handles[1], f.now);
            if (challenge != null) break;
        }
        const request = challenge orelse return error.MissingQuoteWork;
        try std.testing.expectEqual(f.handles[1], f.owners.nextAttestationQuote(22, std.math.maxInt(usize)).?);
        try std.testing.expect(f.owners.nextAttestationQuote(11, 0) == null);
        const response = try quote.testing.QuoteFixture.initFor(request.qualifyingData(), request.approved_pcr11);
        try std.testing.expect(!f.sessions.hasSessions());
        try std.testing.expectError(error.PeerAlreadyAdmitted, f.owners.open(&f.handshakes, &f.sessions, f.request(false)));
        try std.testing.expectEqual(@as(usize, 0), f.quote_count);
        for (f.owners.slots[0..2]) |slot| try std.testing.expect(slot.connection.?.endpoint == .pending);
        const handle = f.handles[1];
        switch (fault) {
            0 => {
                try f.owners.release(&f.handshakes, &f.sessions, handle);
                const replacement = try f.owners.open(&f.handshakes, &f.sessions, f.request(false));
                try std.testing.expect(replacement != handle);
            },
            1 => f.now = 1_000,
            2 => try f.base.base.capabilities.revokeGrant(f.base.base.authority.capability_id),
            3 => {
                f.owners_active = false;
                try f.tick();
            },
            4 => f.now -= 1,
            else => unreachable,
        }
        if (f.owners.completeAttestation(handle, &response.evidence, f.now)) |_| return error.StaleQuoteCompleted else |_| {}
        f.owners.reap(&f.handshakes, &f.sessions);
        try std.testing.expect(f.owners.status(handle) == null);
        try std.testing.expect(!f.sessions.hasSessions());
    }
}

test "session manager peer connections reject completions before another dispatcher visit after owner loss" {
    const f = try Fixture.init("retired owner");
    defer f.deinit();
    try f.enableAttestation();
    const manager_mod = @import("../session/session_manager.zig");
    manager_mod.testing.resetState();
    defer manager_mod.testing.resetState();
    const manager = manager_mod.system();
    // Direct owner-table setup models a connection left behind by an owner
    // whose runtime is gone; the public completion entry must retire it itself.
    const handle = try manager.peer_connections.open(&manager.peer_handshakes, &manager.peers, f.request(false));
    try std.testing.expect(manager.peerConnectionStatus(handle) != null);
    const response = attest.Response{};
    try std.testing.expectError(error.StalePeerConnection, manager.completePeerAttestation(handle, &response, 20));
    try std.testing.expect(manager.peerConnectionStatus(handle) == null);
    try std.testing.expect(manager.peerAttestationChallenge(handle, 20) == null);
    try std.testing.expect(!manager.peer_handshakes.hasSessions());
}
