//! Bounded service admission for explicitly authorized, established peers.
//! Enrollment, channel establishment and object selection are local operations.
const std = @import("std");
const peer = @import("peer_channel.zig");
const transfer = @import("object_transfer.zig");
const sender_mod = @import("object_sender.zig");
const storage_mod = @import("../storage/storage_service.zig");
const sync_mod = @import("sync_service.zig");
const capability_mod = @import("../kernel_api/capability.zig");
const signer_mod = @import("../storage/sealed_object_signer.zig");
const authority_mod = @import("../services/service_authority.zig");

pub const MAX_SESSIONS = 4;
pub const DISPATCH_BUDGET = 2;
pub const MAX_FRAMES_PER_TICK = 8;
pub const RETRY_TICKS: u64 = 2;
pub const MAX_LIFETIME_TICKS: u64 = 3_000;

// The caller owns stable channel/endpoint/scratch/authority state until detach.
// A local registration consumes no packet-driven allocation or table growth.
pub const Session = struct {
    channel: *peer.Channel,
    endpoint: union(enum) {
        receiver: struct { receiver: *transfer.Receiver, signer: signer_mod.Signer },
        sender: *sender_mod.Sender,
    },
    capability_id: u64,
    peer_mac: [6]u8,
    expires_at: u64,
    retry_at: u64 = 0,
    budget_tick: u64 = 0,
    admitted_this_tick: u8 = 0,
    active: bool = true,
    incoming_len: u16 = 0,
    outgoing_len: u16 = 0,
    incoming: [peer.MAX_FRAME]u8 = @splat(0),
    outgoing: [peer.MAX_FRAME]u8 = @splat(0),
    offering: bool = false,

    pub fn init(channel: *peer.Channel, receiver: *transfer.Receiver, signer: signer_mod.Signer, authority: authority_mod.Context, peer_mac: [6]u8, expires_at: u64) !Session {
        try validateRegistration(channel, authority, peer_mac, expires_at);
        _ = try receiver.validate(channel, authority, signer);
        return .{ .channel = channel, .endpoint = .{ .receiver = .{ .receiver = receiver, .signer = signer } }, .capability_id = authority.capability_id, .peer_mac = peer_mac, .expires_at = expires_at };
    }

    pub fn initOffering(channel: *peer.Channel, receiver: *transfer.Receiver, signer: signer_mod.Signer, authority: authority_mod.Context, peer_mac: [6]u8, expires_at: u64) !Session {
        var session = try init(channel, receiver, signer, authority, peer_mac, expires_at);
        session.offering = true;
        return session;
    }

    pub fn initSender(channel: *peer.Channel, sender: *sender_mod.Sender, authority: authority_mod.Context, peer_mac: [6]u8, expires_at: u64, confirmation: []const u8) !Session {
        try validateRegistration(channel, authority, peer_mac, expires_at);
        try sender.validate(channel, authority);
        if (!sender.waitingForOffer()) return error.InvalidState;
        var session = Session{ .channel = channel, .endpoint = .{ .sender = sender }, .capability_id = authority.capability_id, .peer_mac = peer_mac, .expires_at = expires_at };
        if (confirmation.len != 0) {
            if (confirmation.len <= peer.DATA_HEADER + 16 or confirmation.len > peer.MAX_FRAME or
                !std.mem.eql(u8, confirmation[0..4], peer.MAGIC) or confirmation[4] != peer.VERSION or confirmation[5] != 4 or
                std.mem.readInt(u64, confirmation[6..14], .little) != channel.local or std.mem.readInt(u64, confirmation[14..22], .little) != channel.remote or
                !std.mem.eql(u8, confirmation[peer.HEADER..][0..16], channel.crypto.transport.hash[0..16]) or
                std.mem.readInt(u64, confirmation[peer.HEADER + 16 ..][0..8], .little) != 0) return error.InvalidConfirmation;
            @memcpy(session.outgoing[0..confirmation.len], confirmation);
            session.outgoing_len = @intCast(confirmation.len);
        }
        return session;
    }

    fn validateRegistration(channel: *peer.Channel, authority: authority_mod.Context, peer_mac: [6]u8, expires_at: u64) !void {
        if (channel.signer.authority == null) return error.SealedSigningKeyRequired;
        if (expires_at <= authority.now_ticks or expires_at - authority.now_ticks > MAX_LIFETIME_TICKS) return error.InvalidPeerLifetime;
        if (peer_mac[0] & 1 != 0 or std.mem.allEqual(u8, &peer_mac, 0)) return error.InvalidPeerAddress;
    }

    pub fn storageService(self: *const Session) *storage_mod.Service {
        return switch (self.endpoint) {
            .receiver => |r| r.receiver.store,
            .sender => |sender| sender.store,
        };
    }

    pub fn syncService(self: *const Session) *sync_mod.Service {
        return switch (self.endpoint) {
            .receiver => |r| r.receiver.sync,
            .sender => |sender| sender.sync,
        };
    }

    pub fn capabilityTable(self: *const Session) *const capability_mod.CapabilityTable {
        return switch (self.endpoint) {
            .receiver => |r| r.receiver.capabilities,
            .sender => |sender| sender.capabilities,
        };
    }

    pub fn lastProgress(self: *const Session) ?transfer.Progress {
        return switch (self.endpoint) {
            .receiver => |r| r.receiver.currentProgress(),
            .sender => |sender| sender.receipt,
        };
    }

    fn currentAuthority(self: *const Session, now: u64) authority_mod.Context {
        const service = self.syncService();
        return .{ .task_id = service.task_id, .principal = service.owner, .capability_id = self.capability_id, .now_ticks = now };
    }

    fn validate(self: *Session, now: u64) bool {
        if (!self.active) return false;
        if (now >= self.expires_at) {
            self.close();
            return false;
        }
        switch (self.endpoint) {
            .receiver => |r| {
                r.receiver.expire(now);
                _ = r.receiver.validate(self.channel, self.currentAuthority(now), r.signer) catch {
                    self.close();
                    return false;
                };
            },
            .sender => |sender| sender.validate(self.channel, self.currentAuthority(now)) catch {
                self.close();
                return false;
            },
        }
        return true;
    }

    fn admit(self: *Session, frame: []const u8, now: u64) bool {
        if (!self.active or now >= self.expires_at or self.incoming_len != 0 or (self.outgoing_len != 0 and !self.offering and !self.waitingForOffer())) return false;
        if (self.budget_tick != now) {
            self.budget_tick = now;
            self.admitted_this_tick = 0;
        }
        if (self.admitted_this_tick == MAX_FRAMES_PER_TICK) return false;
        self.admitted_this_tick += 1;
        @memcpy(self.incoming[0..frame.len], frame);
        self.incoming_len = @intCast(frame.len);
        return true;
    }

    pub fn close(self: *Session) void {
        if (!self.active) return;
        switch (self.endpoint) {
            .receiver => |r| r.receiver.reset(),
            .sender => |sender| sender.reset(),
        }
        self.channel.close();
        std.crypto.secureZero(u8, &self.incoming);
        std.crypto.secureZero(u8, &self.outgoing);
        if (self.endpoint == .receiver) self.endpoint.receiver.signer = .{};
        self.incoming_len = 0;
        self.outgoing_len = 0;
        self.offering = false;
        self.active = false;
    }

    fn waitingForOffer(self: *const Session) bool {
        return self.endpoint == .sender and self.endpoint.sender.waitingForOffer();
    }

    fn needsEncoding(self: *const Session) bool {
        return self.offering or (self.endpoint == .sender and self.endpoint.sender.hasRequest());
    }

    fn ready(self: *const Session, now: u64) bool {
        return self.active and (self.incoming_len != 0 or (now >= self.retry_at and (self.outgoing_len != 0 or self.needsEncoding())));
    }

    fn clearOutgoing(self: *Session) void {
        std.crypto.secureZero(u8, &self.outgoing);
        self.outgoing_len = 0;
    }

    fn runOnce(self: *Session, now: u64, send: anytype) bool {
        if (self.incoming_len != 0) {
            defer {
                std.crypto.secureZero(u8, &self.incoming);
                self.incoming_len = 0;
            }
            switch (self.endpoint) {
                .receiver => |r| {
                    const progress = r.receiver.receive(self.channel, self.currentAuthority(now), r.signer, self.incoming[0..self.incoming_len]) catch {
                        _ = self.validate(now);
                        return true;
                    };
                    self.offering = false;
                    var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
                    defer std.crypto.secureZero(u8, &plaintext);
                    const response = transfer.encodeProgress(&plaintext, progress) catch unreachable;
                    const packet = self.channel.seal(&self.outgoing, response, now) catch {
                        self.close();
                        return true;
                    };
                    self.outgoing_len = @intCast(packet.len);
                    self.retry_at = now;
                },
                .sender => |sender| {
                    const advanced = sender.receive(self.channel, self.currentAuthority(now), self.incoming[0..self.incoming_len]) catch {
                        _ = self.validate(now);
                        return true;
                    };
                    if (advanced) {
                        self.clearOutgoing();
                        self.retry_at = now;
                    }
                },
            }
            return true;
        }
        if (self.outgoing_len == 0 and self.needsEncoding() and now >= self.retry_at) {
            var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
            defer std.crypto.secureZero(u8, &plaintext);
            const response = switch (self.endpoint) {
                .receiver => |r| blk: {
                    const offer = r.receiver.offer(self.channel, self.currentAuthority(now), r.signer) catch {
                        self.close();
                        return true;
                    };
                    break :blk transfer.encodeOffer(&plaintext, offer) catch unreachable;
                },
                .sender => |sender| sender.encode(self.channel, self.currentAuthority(now), &plaintext) catch {
                    self.close();
                    return true;
                },
            };
            const packet = self.channel.seal(&self.outgoing, response, now) catch {
                self.close();
                return true;
            };
            self.outgoing_len = @intCast(packet.len);
            return true;
        }
        if (self.outgoing_len != 0 and now >= self.retry_at) {
            // Driver backpressure repeats ciphertext without advancing nonces.
            // After accepted application sends, a timed retry is newly sealed
            // so the receiver can authenticate and answer the idempotent request.
            if (send(self.peer_mac, self.outgoing[0..self.outgoing_len]) and !self.waitingForOffer()) {
                if (self.endpoint == .sender) self.endpoint.sender.markSent();
                self.clearOutgoing();
            }
            self.retry_at = std.math.add(u64, now, RETRY_TICKS) catch self.expires_at;
            return true;
        }
        return false;
    }
};

pub const Sessions = struct {
    slots: [MAX_SESSIONS]?*Session = @splat(null),
    cursor: u8 = 0,

    pub fn attach(self: *Sessions, session: *Session, now: u64) !void {
        if (!session.validate(now)) return error.PeerAdmissionDenied;
        for (self.slots) |maybe| if (maybe) |other| {
            if (other == session or (other.active and other.channel.local == session.channel.local and other.channel.remote == session.channel.remote)) return error.PeerAlreadyAdmitted;
        };
        for (&self.slots) |*slot| if (slot.* == null) {
            slot.* = session;
            return;
        };
        return error.PeerTableFull;
    }

    pub fn detach(self: *Sessions, session: *Session) void {
        for (&self.slots) |*slot| if (slot.* == session) {
            session.close();
            slot.* = null;
        };
    }

    pub fn deinit(self: *Sessions) void {
        for (&self.slots) |*slot| if (slot.*) |session| {
            session.close();
            slot.* = null;
        };
        self.cursor = 0;
    }

    pub fn hasSessions(self: *const Sessions) bool {
        for (self.slots) |slot| if (slot != null) return true;
        return false;
    }

    pub fn admit(self: *Sessions, frame: []const u8, now: u64) bool {
        if (frame.len <= peer.DATA_HEADER + 16 or frame.len > peer.MAX_FRAME or
            !std.mem.eql(u8, frame[0..4], peer.MAGIC) or frame[4] != peer.VERSION or frame[5] != 4) return false;
        const remote = std.mem.readInt(u64, frame[6..14], .little);
        const local = std.mem.readInt(u64, frame[14..22], .little);
        for (self.slots) |maybe| if (maybe) |session| {
            if (session.channel.local == local and session.channel.remote == remote) return session.admit(frame, now);
        };
        return false;
    }

    pub fn service(self: *Sessions, now: u64, send: anytype) usize {
        return self.serviceBudget(now, send, DISPATCH_BUDGET);
    }

    pub fn serviceBudget(self: *Sessions, now: u64, send: anytype, budget: usize) usize {
        if (budget == 0) return 0;
        var work: usize = 0;
        for (0..MAX_SESSIONS) |_| {
            const index = self.cursor;
            self.cursor = @intCast((self.cursor + 1) % MAX_SESSIONS);
            const session = self.slots[index] orelse continue;
            if (!session.validate(now)) {
                self.slots[index] = null;
                continue;
            }
            if (session.runOnce(now, send)) work += 1;
            if (!session.active) self.slots[index] = null;
            if (work == @min(budget, DISPATCH_BUDGET)) break;
        }
        return work;
    }

    pub fn hasReadyWork(self: *const Sessions, now: u64) bool {
        for (self.slots) |maybe| if (maybe) |session| if (session.ready(now)) return true;
        return false;
    }

    pub fn nextWake(self: *const Sessions) ?u64 {
        var next: ?u64 = null;
        for (self.slots) |maybe| if (maybe) |session| {
            if (!session.active) continue;
            var deadline = session.expires_at;
            if (session.outgoing_len != 0 or session.needsEncoding()) deadline = @min(deadline, session.retry_at);
            if (session.endpoint == .receiver) {
                if (session.endpoint.receiver.receiver.transfer) |active| deadline = @min(deadline, active.deadline);
            }
            next = if (next) |old| @min(old, deadline) else deadline;
        };
        return next;
    }
};

comptime {
    if (@sizeOf(Session) > 672 or @sizeOf(Sessions) > 40) @compileError("peer admission exceeds bounded coordination state");
}
