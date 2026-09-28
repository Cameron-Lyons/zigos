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
    direction: union(enum) {
        send,
        receive: struct { signer: signer_mod.Signer, limit: u32 },
    },
};
pub const Status = struct {
    phase: enum { handshaking, transferring, complete },
    progress: ?transfer.Progress = null,
    digest: [32]u8 = @splat(0),
};

const Connection = struct {
    request: Request,
    channel: peer.Channel,
    buffer: []u8 = &.{},
    source_version: u64,
    endpoint: union(enum) { pending, sender: sender_mod.Sender, receiver: transfer.Receiver } = .pending,
    state: union(enum) { closed, handshake: handshake.Handshake, session: admission.Session } = .closed,

    fn promote(self: *Connection, handshakes: *handshake.Handshakes, sessions: *admission.Sessions, now: u64) !void {
        var confirmation: [peer.MAX_FRAME]u8 = undefined;
        defer std.crypto.secureZero(u8, &confirmation);
        const last = try handshakes.take(&self.state.handshake, &confirmation, now);
        self.state = .closed;
        var authority = self.request.authority;
        authority.now_ticks = now;
        const r = self.request;
        switch (r.direction) {
            .send => {
                const entry = try r.store.findEntryForObject(r.binding.workspace_id, r.binding.object_id);
                if (entry.version_id.raw() != self.source_version) return error.ObjectChanged;
                self.endpoint = .{ .sender = try sender_mod.Sender.init(r.store, r.service, r.capabilities, r.binding, &self.channel, authority) };
                self.state = .{ .session = try admission.Session.initSender(&self.channel, &self.endpoint.sender, authority, r.peer_mac, r.expires_at, last) };
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
            .closed => {},
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
        return switch (self.state) {
            .handshake => |*h| h.active(),
            .session => |*s| s.active,
            .closed => false,
        };
    }

    fn status(self: *const Connection) Status {
        if (self.state == .handshake) return .{ .phase = .handshaking };
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
            if (connection.state != .handshake or !connection.state.handshake.complete()) continue;
            connection.promote(handshakes, sessions, now) catch {
                slot.connection = null;
                connection.destroy(handshakes, sessions);
            };
            work += 1;
            if (work == @min(budget, admission.DISPATCH_BUDGET)) break;
        }
        return work;
    }

    pub fn hasReadyWork(self: *const Connections) bool {
        for (self.slots) |slot| if (slot.connection) |c| if (c.state == .handshake and c.state.handshake.complete()) return true;
        return false;
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
