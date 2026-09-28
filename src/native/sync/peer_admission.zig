//! Bounded service admission for explicitly authorized, established peers.
//! Enrollment, channel establishment and object selection are local operations.
const std = @import("std");
const peer = @import("peer_channel.zig");
const transfer = @import("object_transfer.zig");
const signer_mod = @import("../storage/sealed_object_signer.zig");
const authority_mod = @import("../services/service_authority.zig");

pub const MAX_SESSIONS = 4;
pub const DISPATCH_BUDGET = 2;
pub const MAX_FRAMES_PER_TICK = 8;
pub const RETRY_TICKS: u64 = 2;
pub const MAX_LIFETIME_TICKS: u64 = 3_000;

// The caller owns stable channel/receiver/scratch/authority state until detach.
// A local registration consumes no packet-driven allocation or table growth.
pub const Session = struct {
    channel: *peer.Channel,
    receiver: *transfer.Receiver,
    signer: signer_mod.Signer,
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
    last_progress: ?transfer.Progress = null,

    pub fn init(channel: *peer.Channel, receiver: *transfer.Receiver, signer: signer_mod.Signer, authority: authority_mod.Context, peer_mac: [6]u8, expires_at: u64) !Session {
        if (channel.signer.authority == null) return error.SealedSigningKeyRequired;
        if (expires_at <= authority.now_ticks or expires_at - authority.now_ticks > MAX_LIFETIME_TICKS) return error.InvalidPeerLifetime;
        if (peer_mac[0] & 1 != 0 or std.mem.allEqual(u8, &peer_mac, 0)) return error.InvalidPeerAddress;
        _ = try receiver.validate(channel, authority, signer);
        return .{ .channel = channel, .receiver = receiver, .signer = signer, .capability_id = authority.capability_id, .peer_mac = peer_mac, .expires_at = expires_at };
    }

    fn currentAuthority(self: *const Session, now: u64) authority_mod.Context {
        return .{ .task_id = self.receiver.sync.task_id, .principal = self.receiver.sync.owner, .capability_id = self.capability_id, .now_ticks = now };
    }

    fn validate(self: *Session, now: u64) bool {
        if (!self.active) return false;
        if (now >= self.expires_at) {
            self.close();
            return false;
        }
        self.receiver.expire(now);
        _ = self.receiver.validate(self.channel, self.currentAuthority(now), self.signer) catch {
            self.close();
            return false;
        };
        return true;
    }

    fn admit(self: *Session, frame: []const u8, now: u64) bool {
        if (!self.active or now >= self.expires_at or self.incoming_len != 0 or self.outgoing_len != 0) return false;
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
        self.receiver.reset();
        self.channel.close();
        std.crypto.secureZero(u8, &self.incoming);
        std.crypto.secureZero(u8, &self.outgoing);
        self.signer = .{};
        self.incoming_len = 0;
        self.outgoing_len = 0;
        self.last_progress = null;
        self.active = false;
    }

    fn ready(self: *const Session, now: u64) bool {
        return self.active and (self.incoming_len != 0 or (self.outgoing_len != 0 and now >= self.retry_at));
    }

    fn runOnce(self: *Session, now: u64, send: anytype) bool {
        if (self.incoming_len != 0) {
            defer {
                std.crypto.secureZero(u8, &self.incoming);
                self.incoming_len = 0;
            }
            const progress = self.receiver.receive(self.channel, self.currentAuthority(now), self.signer, self.incoming[0..self.incoming_len]) catch {
                _ = self.validate(now);
                return true;
            };
            var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
            defer std.crypto.secureZero(u8, &plaintext);
            const response = transfer.encodeProgress(&plaintext, progress) catch unreachable;
            const packet = self.channel.seal(&self.outgoing, response, now) catch {
                self.close();
                return true;
            };
            self.last_progress = progress;
            self.outgoing_len = @intCast(packet.len);
            self.retry_at = now;
            return true;
        }
        if (self.outgoing_len != 0 and now >= self.retry_at) {
            // Backpressure repeats cached ciphertext without advancing a nonce.
            // validate() runs before every attempt, including delayed replies.
            if (send(self.peer_mac, self.outgoing[0..self.outgoing_len])) {
                std.crypto.secureZero(u8, &self.outgoing);
                self.outgoing_len = 0;
            } else self.retry_at = std.math.add(u64, now, RETRY_TICKS) catch self.expires_at;
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
            if (session.outgoing_len != 0) deadline = @min(deadline, session.retry_at);
            if (session.receiver.transfer) |active| deadline = @min(deadline, active.deadline);
            next = if (next) |old| @min(old, deadline) else deadline;
        };
        return next;
    }
};

comptime {
    if (@sizeOf(Session) > 672 or @sizeOf(Sessions) > 40) @compileError("peer admission exceeds bounded coordination state");
}
