//! Service-owned, locally authorized transfers. Handles never expose resident
//! pointers; network input cannot allocate or reopen a connection. The stores,
//! capability table and sealed-key authorities outlive this table's deinit.
const std = @import("std");
const backing = @import("../core/table_backing.zig");
const peer = @import("peer_channel.zig");
const handshake = @import("peer_handshake.zig");
const admission = @import("peer_admission.zig");
const transfer = @import("object_transfer.zig");
const sender_mod = @import("object_sender.zig");
const storage = @import("../storage/storage_service.zig");
const objects = @import("../storage/object_store.zig");
const sync = @import("sync_service.zig");
const capability = @import("../kernel_api/capability.zig");
const authority_mod = @import("../services/service_authority.zig");
const sealed = @import("../services/sealed_signing_key.zig");
const signer_mod = @import("../storage/sealed_object_signer.zig");
const signing = @import("../core/signing.zig");
const attestation = @import("peer_attestation.zig");
const tpm = @import("../platform/tpm_attestation.zig");

pub const MAX_CONNECTIONS = 4;
pub const Handle = enum(u64) { _ };
pub const Request = struct {
    store: *storage.Service,
    service: *sync.Service,
    capabilities: *const capability.CapabilityTable,
    authority: authority_mod.Context,
    binding: transfer.Binding,
    root_pin: signing.PublicKey,
    device_key: sealed.Key,
    peer_mac: [6]u8,
    expires_at: u64,
    // Local policy and enrollment only. The caller retains these until release.
    attestation: ?attestation.Requirement = null,
    direction: union(enum) {
        send,
        receive: struct { signer: signer_mod.Signer, limit: u32 },
    },
};
pub const Status = struct {
    phase: enum { handshaking, attesting, transferring, complete },
    progress: ?transfer.Progress = null,
    digest: [32]u8 = @splat(0),
};

const Connection = struct {
    const Preflight = struct { started: bool = false, quote_notified: bool = false, exchange: attestation.Exchange = undefined };
    request: Request,
    channel: peer.Channel,
    buffer: []u8 = &.{},
    source_version: u64,
    endpoint: union(enum) { pending, sender: sender_mod.Sender, receiver: transfer.Receiver } = .pending,
    state: union(enum) { closed, handshake: handshake.Handshake, attesting, session: admission.Session } = .closed,
    preflight: ?*Preflight = null,

    fn promote(self: *Connection, handshakes: *handshake.Handshakes, sessions: *admission.Sessions, now: u64) !void {
        var confirmation: [peer.MAX_FRAME]u8 = undefined;
        defer std.crypto.secureZero(u8, &confirmation);
        const last = try handshakes.take(&self.state.handshake, &confirmation, now);
        self.state = .closed;
        if (self.preflight) |preflight| {
            preflight.exchange = try attestation.Exchange.init(&self.channel, self.request.attestation.?, last, now, self.request.expires_at);
            preflight.started = true;
            self.state = .attesting;
            return;
        }
        try self.beginTransfer(sessions, last, now);
    }

    fn beginTransfer(self: *Connection, sessions: *admission.Sessions, confirmation: []const u8, now: u64) !void {
        var authority = self.request.authority;
        authority.now_ticks = now;
        const r = self.request;
        switch (r.direction) {
            .send => {
                const entry = try r.store.findEntryForObject(r.binding.workspace_id, r.binding.object_id);
                if (entry.version_id.raw() != self.source_version) return error.ObjectChanged;
                self.endpoint = .{ .sender = try sender_mod.Sender.init(r.store, r.service, r.capabilities, r.binding, &self.channel, authority) };
                self.state = .{ .session = try admission.Session.initSender(&self.channel, &self.endpoint.sender, authority, r.peer_mac, r.expires_at, confirmation) };
            },
            .receive => |receive| {
                self.endpoint = .{ .receiver = .{ .store = r.store, .sync = r.service, .capabilities = r.capabilities, .binding = r.binding, .scratch = self.buffer } };
                self.state = .{ .session = try admission.Session.initOffering(&self.channel, &self.endpoint.receiver, receive.signer, authority, r.peer_mac, r.expires_at) };
            },
        }
        try sessions.attach(&self.state.session, now);
    }

    fn destroy(self: *Connection, handshakes: *handshake.Handshakes, sessions: *admission.Sessions) void {
        switch (self.state) {
            .handshake => |*h| {
                handshakes.detach(h);
                h.close();
            },
            .session => |*s| {
                sessions.detach(s);
                s.close();
            },
            .closed, .attesting => {},
        }
        if (self.preflight) |preflight| {
            if (preflight.started) preflight.exchange.close();
            if (!preflight.started and self.request.attestation.? == .verify) self.request.attestation.?.verify.cancel();
            std.crypto.secureZero(u8, std.mem.asBytes(preflight));
            backing.free(Preflight, preflight);
        }
        // A failed promotion can own an endpoint before it owns a session.
        switch (self.endpoint) {
            .sender => |*sender| sender.reset(),
            .receiver => |*receiver| receiver.reset(),
            .pending => {},
        }
        self.channel.close();
        backing.freeBytes(self.buffer);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        backing.free(Connection, self);
    }

    fn live(self: *const Connection) bool {
        if (self.preflight) |preflight| if (preflight.started and !preflight.exchange.active()) return false;
        return switch (self.state) {
            .handshake => |*h| h.active(),
            .session => |*s| s.active,
            .attesting => true,
            .closed => false,
        };
    }

    fn status(self: *const Connection) Status {
        if (self.state == .handshake) return .{ .phase = .handshaking };
        if (self.state == .attesting) return .{ .phase = .attesting };
        const progress = self.state.session.lastProgress();
        const complete = if (progress) |p| p.durable() else false;
        return .{ .phase = if (complete) .complete else .transferring, .progress = progress, .digest = if (complete) switch (self.endpoint) {
            .sender => |*sender| sender.request.digest,
            .receiver => |*receiver| receiver.transfer.?.request.digest,
            .pending => unreachable,
        } else @splat(0) };
    }
};

pub const Connections = struct {
    const Slot = struct { generation: u64 = 0, connection: ?*Connection = null };
    slots: [MAX_CONNECTIONS]Slot = @splat(.{}),
    cursor: u8 = 0,

    pub fn open(self: *Connections, handshakes: *handshake.Handshakes, sessions: *admission.Sessions, request: Request) !Handle {
        const now = request.authority.now_ticks;
        if (now == 0 or request.authority.task_id != request.service.task_id or !request.authority.principal.eql(request.service.owner)) return error.PermissionDenied;
        _ = try authority_mod.requireServiceAuthority(request.capabilities, request.service.service_id, request.authority, .endpoint_connect);
        try request.device_key.validateService(request.service.owner, request.service.task_id, now);
        if (request.expires_at <= now or request.expires_at - now > admission.MAX_LIFETIME_TICKS) return error.InvalidPeerLifetime;
        if (request.peer_mac[0] & 1 != 0 or std.mem.allEqual(u8, &request.peer_mac, 0)) return error.InvalidPeerAddress;
        if (handshakes.contains(request.binding.local_device, request.binding.peer_device)) return error.PeerAlreadyAdmitted;
        for (sessions.slots) |maybe| if (maybe) |s| {
            if (s.channel.local == request.binding.local_device and s.channel.remote == request.binding.peer_device) return error.PeerAlreadyAdmitted;
        };
        // Attestation owns the pair between the handshake and transfer pools.
        // One verifier challenge cannot be borrowed by two live connections.
        for (self.slots) |slot| if (slot.connection) |existing| {
            if (existing.channel.local == request.binding.local_device and existing.channel.remote == request.binding.peer_device) return error.PeerAlreadyAdmitted;
            if (request.attestation) |required| if (required == .verify) {
                if (existing.request.attestation) |active| if (active == .verify and active.verify == required.verify) return error.PeerAlreadyAdmitted;
            };
        };
        var available: ?usize = null;
        for (self.slots, 0..) |slot, i| if (slot.connection == null and slot.generation < std.math.maxInt(u64) >> 2) {
            available = i;
            break;
        };
        const index = available orelse return error.PeerTableFull;
        var channel = try peer.Channel.init(request.service.deviceGraph(), request.root_pin, .{ .kind = .device, .serial = request.binding.local_device }, .{ .kind = .device, .serial = request.binding.peer_device }, request.device_key, if (request.direction == .send) .initiator else .responder, now);
        defer channel.close();
        const entry = try transfer.authorizeObject(request.store, request.service, request.capabilities, request.binding, &channel, now, request.direction == .receive);
        const limit = switch (request.direction) {
            .send => 0,
            .receive => |receive| blk: {
                if (receive.limit > objects.MAX_PAYLOAD_BYTES) return error.TransferTooLarge;
                try receive.signer.validateService(request.store.owner, request.store.task_id, now);
                const workspace = request.store.findWorkspaceRecordConst(request.binding.workspace_id) orelse return error.WorkspaceNotFound;
                if (!receive.signer.key.authority.?.owner.eql(workspace.owner)) return error.PermissionDenied;
                try request.store.requireDurableBoundary();
                break :blk receive.limit;
            },
        };
        const connection = backing.alloc(Connection) orelse return error.NoSpaceLeft;
        connection.* = .{ .request = request, .channel = channel, .source_version = entry.version_id.raw() };
        errdefer connection.destroy(handshakes, sessions);
        if (request.attestation != null) {
            connection.preflight = backing.alloc(Connection.Preflight) orelse return error.NoSpaceLeft;
            connection.preflight.?.* = .{};
        }
        connection.buffer = backing.allocBytes(limit) orelse return error.NoSpaceLeft;
        connection.state = .{ .handshake = try handshake.Handshake.init(&connection.channel, request.service, request.capabilities, request.authority, request.peer_mac, now + @min(request.expires_at - now, handshake.MAX_LIFETIME_TICKS)) };
        try handshakes.attach(&connection.state.handshake, now);
        const slot = &self.slots[index];
        slot.generation += 1;
        slot.connection = connection;
        return @enumFromInt((slot.generation << 2) | index);
    }

    fn resolve(self: *const Connections, handle: Handle) ?*Connection {
        const value = @intFromEnum(handle);
        const slot = &self.slots[value & 3];
        if (value >> 2 == 0 or slot.generation != value >> 2) return null;
        return slot.connection;
    }

    pub fn status(self: *const Connections, handle: Handle) ?Status {
        const connection = self.resolve(handle) orelse return null;
        return if (connection.live()) connection.status() else null;
    }

    pub fn release(self: *Connections, handshakes: *handshake.Handshakes, sessions: *admission.Sessions, handle: Handle) !void {
        const connection = self.resolve(handle) orelse return error.StalePeerConnection;
        self.slots[@intFromEnum(handle) & 3].connection = null;
        connection.destroy(handshakes, sessions);
    }

    // A handoff counts against the same budget as packet processing. No new
    // allocation happens here: all coordination and receive bytes belong to
    // the authorized local open, before any network packet is accepted.
    pub fn advance(self: *Connections, handshakes: *handshake.Handshakes, sessions: *admission.Sessions, now: u64, budget: usize) usize {
        if (budget == 0) return 0;
        var work: usize = 0;
        for (0..MAX_CONNECTIONS) |_| {
            const slot = &self.slots[self.cursor];
            self.cursor = @intCast((self.cursor + 1) % MAX_CONNECTIONS);
            const connection = slot.connection orelse continue;
            const establishing = connection.state == .handshake and connection.state.handshake.complete();
            const attested = connection.state == .attesting and connection.preflight.?.exchange.ready();
            if (!establishing and !attested) continue;
            if (attested and !validatePreflight(connection, now)) {
                slot.connection = null;
                connection.destroy(handshakes, sessions);
                work += 1;
                if (work == @min(budget, admission.DISPATCH_BUDGET)) break;
                continue;
            }
            (if (establishing) connection.promote(handshakes, sessions, now) else connection.beginTransfer(sessions, "", now)) catch {
                slot.connection = null;
                connection.destroy(handshakes, sessions);
            };
            work += 1;
            if (work == @min(budget, admission.DISPATCH_BUDGET)) break;
        }
        return work;
    }

    pub fn hasReadyWork(self: *const Connections) bool {
        for (self.slots) |slot| if (slot.connection) |c| {
            if (c.state == .handshake and c.state.handshake.complete()) return true;
            if (c.state == .attesting and c.preflight.?.exchange.ready()) return true;
        };
        return false;
    }

    fn validatePreflight(c: *Connection, now: u64) bool {
        return validatePreflightAuthority(c, now) and c.preflight.?.exchange.validate(now);
    }

    fn validatePreflightAuthority(c: *Connection, now: u64) bool {
        const p = c.preflight orelse return false;
        if (!p.started) return false;
        var authority = c.request.authority;
        authority.now_ticks = now;
        _ = authority_mod.requireServiceAuthority(c.request.capabilities, c.request.service.service_id, authority, .endpoint_connect) catch {
            p.exchange.close();
            return false;
        };
        return true;
    }

    // Notify once when packet processing has assembled the owner's quote work.
    // The owner retrieves it by its existing handle and completes it separately.
    pub fn wakeAttestationOwners(self: *Connections, context: anytype, wake: anytype, now: u64) void {
        for (self.slots) |slot| if (slot.connection) |c| if (c.preflight) |p| {
            if (p.started and !p.quote_notified and p.exchange.needsQuote()) {
                p.quote_notified = true;
                _ = wake(context, c.request.service.task_id, now);
            }
        };
    }

    pub fn nextAttestationQuote(self: *const Connections, local_device: u64, start: usize) ?Handle {
        for (0..MAX_CONNECTIONS) |offset| {
            const index = (start % MAX_CONNECTIONS + offset) % MAX_CONNECTIONS;
            const slot = self.slots[index];
            const c = slot.connection orelse continue;
            const p = c.preflight orelse continue;
            if (c.channel.local == local_device and p.started and p.exchange.needsQuote()) return @enumFromInt((slot.generation << 2) | index);
        }
        return null;
    }

    pub fn attestationChallenge(self: *Connections, handle: Handle, now: u64) ?tpm.Challenge {
        const c = self.resolve(handle) orelse return null;
        if (!validatePreflight(c, now)) return null;
        return c.preflight.?.exchange.quoteChallenge(now);
    }

    pub fn completeAttestation(self: *Connections, handle: Handle, response: *const tpm.Response, now: u64) !void {
        const c = self.resolve(handle) orelse return error.StalePeerConnection;
        if (!validatePreflight(c, now)) return error.PeerAdmissionDenied;
        try c.preflight.?.exchange.completeQuote(response, now);
    }

    pub fn hasAttestations(self: *const Connections) bool {
        for (self.slots) |slot| if (slot.connection) |c| if (c.preflight) |p| if (p.started and p.exchange.active()) return true;
        return false;
    }

    pub fn hasAttestationWork(self: *const Connections, now: u64) bool {
        for (self.slots) |slot| if (slot.connection) |c| if (c.preflight) |p| if (p.started and p.exchange.hasWork(now)) return true;
        return false;
    }

    pub fn nextWake(self: *const Connections) ?u64 {
        var result: ?u64 = null;
        for (self.slots) |slot| if (slot.connection) |c| if (c.preflight) |p| if (p.started) {
            if (p.exchange.nextWake()) |deadline| result = if (result) |existing| @min(existing, deadline) else deadline;
        };
        return result;
    }

    pub fn admitAttestation(self: *Connections, bytes: []const u8, now: u64) bool {
        for (self.slots) |slot| if (slot.connection) |c| if (c.preflight) |p| if (p.started and p.exchange.admit(bytes, now)) return true;
        return false;
    }

    pub fn serviceAttestations(self: *Connections, now: u64, send: anytype, budget: usize) usize {
        if (budget == 0) return 0;
        var work: usize = 0;
        for (0..MAX_CONNECTIONS) |_| {
            const slot = self.slots[self.cursor];
            self.cursor = @intCast((self.cursor + 1) % MAX_CONNECTIONS);
            const c = slot.connection orelse continue;
            if (c.preflight == null or !c.preflight.?.started) continue;
            if (!validatePreflightAuthority(c, now)) continue;
            if (c.preflight.?.exchange.service(now, c.request.peer_mac, send)) work += 1;
            if (work == @min(budget, admission.DISPATCH_BUDGET)) break;
        }
        return work;
    }

    pub fn reap(self: *Connections, handshakes: *handshake.Handshakes, sessions: *admission.Sessions) void {
        for (&self.slots) |*slot| if (slot.connection) |c| if (!c.live()) {
            slot.connection = null;
            c.destroy(handshakes, sessions);
        };
    }

    pub fn retireInactive(self: *Connections, handshakes: *handshake.Handshakes, sessions: *admission.Sessions, context: anytype, is_active: anytype) void {
        for (&self.slots) |*slot| if (slot.connection) |c| if (!is_active(context, c.request.service, c.request.store)) {
            slot.connection = null;
            c.destroy(handshakes, sessions);
        };
    }

    pub fn deinit(self: *Connections, handshakes: *handshake.Handshakes, sessions: *admission.Sessions) void {
        for (&self.slots) |*slot| if (slot.connection) |c| {
            slot.connection = null;
            c.destroy(handshakes, sessions);
        };
        // Keep generations: handles issued before reset must remain stale.
        self.cursor = 0;
    }
};

comptime {
    if (@sizeOf(Connections) > 72 or @sizeOf(Connection) > 2048) @compileError("owned peer connections exceed bounded coordination state");
}
