//! Locally authorized, bounded Noise establishment. Packets cannot allocate a
//! slot or choose an enrollment pin. The caller retains every borrowed object.
const std = @import("std");
const peer = @import("peer_channel.zig");
const sync = @import("sync_service.zig");
const capability = @import("../kernel_api/capability.zig");
const authority_mod = @import("../services/service_authority.zig");
const admission = @import("peer_admission.zig");

pub const MAX_HANDSHAKES = 4;
pub const MAX_LIFETIME_TICKS: u64 = 1_000;
pub const CONFIRMATION = "zigos peer channel confirmed";
const Phase = enum { write_handshake, read_handshake, write_confirmation, read_confirmation, ready, closed, released };

pub const Handshake = struct {
    channel: *peer.Channel,
    service: *sync.Service,
    capabilities: *const capability.CapabilityTable,
    capability_id: u64,
    peer_mac: [6]u8,
    expires_at: u64,
    retry_at: u64 = 0,
    budget_tick: u64 = 0,
    admitted_this_tick: u8 = 0,
    phase: Phase,
    sent: bool = false,
    incoming_len: u16 = 0,
    outgoing_len: u16 = 0,
    last_received_len: u16 = 0,
    incoming: [peer.MAX_FRAME]u8 = @splat(0),
    outgoing: [peer.MAX_FRAME]u8 = @splat(0),
    last_received: [peer.MAX_FRAME]u8 = @splat(0),

    pub fn init(channel: *peer.Channel, service: *sync.Service, capabilities: *const capability.CapabilityTable, authority: authority_mod.Context, peer_mac: [6]u8, expires_at: u64) !Handshake {
        if (channel.crypto != .handshake or channel.crypto.handshake.step != 0) return error.InvalidState;
        if (channel.signer.authority == null) return error.SealedSigningKeyRequired;
        if (expires_at <= authority.now_ticks or expires_at - authority.now_ticks > MAX_LIFETIME_TICKS) return error.InvalidPeerLifetime;
        if (peer_mac[0] & 1 != 0 or std.mem.allEqual(u8, &peer_mac, 0)) return error.InvalidPeerAddress;
        if (authority.now_ticks == 0 or authority.task_id != service.task_id or !authority.principal.eql(service.owner)) return error.PermissionDenied;
        var result = Handshake{ .channel = channel, .service = service, .capabilities = capabilities, .capability_id = authority.capability_id, .peer_mac = peer_mac, .expires_at = expires_at, .phase = if (channel.role == .initiator) .write_handshake else .read_handshake };
        try result.requireAuthority(authority.now_ticks);
        return result;
    }

    fn requireAuthority(self: *Handshake, now: u64) !void {
        if (now == 0 or self.channel.graph != self.service.deviceGraph()) return error.PermissionDenied;
        _ = try authority_mod.requireServiceAuthority(self.capabilities, self.service.service_id, .{ .task_id = self.service.task_id, .principal = self.service.owner, .capability_id = self.capability_id, .now_ticks = now }, .endpoint_connect);
        try self.channel.signer.validateService(self.service.owner, self.service.task_id, now);
        try self.channel.validate(now);
    }

    pub fn active(self: *const Handshake) bool {
        return self.phase != .closed and self.phase != .released;
    }

    pub fn complete(self: *const Handshake) bool {
        return self.phase == .ready and self.sent;
    }

    fn validate(self: *Handshake, now: u64) bool {
        if (!self.active()) return false;
        if (now >= self.expires_at) {
            self.close();
            return false;
        }
        self.requireAuthority(now) catch {
            self.close();
            return false;
        };
        return true;
    }

    fn erasePackets(self: *Handshake) void {
        std.crypto.secureZero(u8, &self.incoming);
        std.crypto.secureZero(u8, &self.outgoing);
        std.crypto.secureZero(u8, &self.last_received);
        self.incoming_len = 0;
        self.outgoing_len = 0;
        self.last_received_len = 0;
        self.sent = false;
    }

    pub fn close(self: *Handshake) void {
        if (!self.active()) return;
        self.channel.close();
        self.erasePackets();
        self.phase = .closed;
    }

    fn admit(self: *Handshake, frame: []const u8, now: u64) bool {
        if (!self.active() or now >= self.expires_at or self.incoming_len != 0) return false;
        if (self.budget_tick != now) {
            self.budget_tick = now;
            self.admitted_this_tick = 0;
        }
        if (self.admitted_this_tick == admission.MAX_FRAMES_PER_TICK) return false;
        self.admitted_this_tick += 1;
        @memcpy(self.incoming[0..frame.len], frame);
        self.incoming_len = @intCast(frame.len);
        return true;
    }

    fn ready(self: *const Handshake, now: u64) bool {
        return self.active() and (self.phase == .write_handshake or self.phase == .write_confirmation or self.incoming_len != 0 or (self.outgoing_len != 0 and now >= self.retry_at));
    }

    fn runOnce(self: *Handshake, now: u64, send: anytype) bool {
        if (self.phase == .write_handshake or self.phase == .write_confirmation) {
            const confirming = self.phase == .write_confirmation;
            const packet = (if (confirming) self.channel.seal(&self.outgoing, CONFIRMATION, now) else self.channel.writeHandshake(&self.outgoing, now)) catch {
                self.close();
                return true;
            };
            self.outgoing_len = @intCast(packet.len);
            self.sent = false;
            self.retry_at = now;
            self.phase = if (confirming)
                (if (self.channel.role == .initiator) .ready else .read_confirmation)
            else if (self.channel.established()) .read_confirmation else .read_handshake;
            return true;
        }
        if (self.incoming_len != 0) {
            defer {
                std.crypto.secureZero(u8, &self.incoming);
                self.incoming_len = 0;
            }
            const frame = self.incoming[0..self.incoming_len];
            // Queued duplicates never regenerate messages, consume nonces, or
            // trigger immediate replies. Only the retry deadline sends again.
            if (std.mem.eql(u8, frame, self.last_received[0..self.last_received_len])) return true;
            if (self.phase == .read_handshake) {
                if (frame[5] != self.channel.crypto.handshake.step + 1) return true;
                self.channel.readHandshake(frame, now) catch {
                    self.close();
                    return true;
                };
                self.phase = if (self.channel.established()) .write_confirmation else .write_handshake;
            } else if (self.phase == .read_confirmation) {
                if (frame[5] != 4) return true;
                var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
                defer std.crypto.secureZero(u8, &plaintext);
                const payload = self.channel.open(&plaintext, frame, now) catch {
                    _ = self.validate(now);
                    return true;
                };
                if (!std.mem.eql(u8, payload, CONFIRMATION)) {
                    self.close();
                    return true;
                }
                self.phase = if (self.channel.role == .initiator) .write_confirmation else .ready;
            } else return true;
            @memcpy(self.last_received[0..frame.len], frame);
            self.last_received_len = @intCast(frame.len);
            return true;
        }
        if (self.outgoing_len != 0 and now >= self.retry_at) {
            if (send(self.peer_mac, self.outgoing[0..self.outgoing_len])) self.sent = true;
            self.retry_at = std.math.add(u64, now, admission.RETRY_TICKS) catch self.expires_at;
            return true;
        }
        return false;
    }
};

pub const Handshakes = struct {
    slots: [MAX_HANDSHAKES]?*Handshake = @splat(null),
    cursor: u8 = 0,

    pub fn hasSessions(self: *const Handshakes) bool {
        for (self.slots) |slot| if (slot != null) return true;
        return false;
    }

    pub fn contains(self: *const Handshakes, local: u64, remote: u64) bool {
        for (self.slots) |maybe| if (maybe) |h| if (h.channel.local == local and h.channel.remote == remote) return true;
        return false;
    }

    pub fn attach(self: *Handshakes, h: *Handshake, now: u64) !void {
        if (!h.validate(now)) return error.PeerAdmissionDenied;
        if (self.contains(h.channel.local, h.channel.remote)) return error.PeerAlreadyAdmitted;
        for (&self.slots) |*slot| if (slot.* == null) {
            slot.* = h;
            return;
        };
        return error.PeerTableFull;
    }

    pub fn detach(self: *Handshakes, h: *Handshake) void {
        for (&self.slots) |*slot| if (slot.* == h) {
            h.close();
            slot.* = null;
        };
    }

    // Transfer the live channel to its application owner. Keep the final
    // ciphertext for retries until that owner observes remote application data:
    // local TX acceptance alone cannot prove delivery of the last confirmation.
    pub fn take(self: *Handshakes, h: *Handshake, confirmation: []u8, now: u64) ![]const u8 {
        for (&self.slots) |*slot| if (slot.* == h) {
            if (!h.validate(now)) {
                slot.* = null;
                return error.PeerNotReady;
            }
            if (!h.complete()) return error.PeerNotReady;
            if (confirmation.len < h.outgoing_len) return error.NoSpaceLeft;
            const len = h.outgoing_len;
            @memcpy(confirmation[0..len], h.outgoing[0..len]);
            h.erasePackets();
            h.phase = .released;
            slot.* = null;
            return confirmation[0..len];
        };
        return error.PeerNotAdmitted;
    }

    pub fn deinit(self: *Handshakes) void {
        for (&self.slots) |*slot| if (slot.*) |h| {
            h.close();
            slot.* = null;
        };
        self.cursor = 0;
    }

    pub fn admit(self: *Handshakes, frame: []const u8, now: u64) bool {
        if (frame.len <= peer.HEADER or frame.len > peer.MAX_FRAME or !std.mem.eql(u8, frame[0..4], peer.MAGIC) or frame[4] != peer.VERSION or frame[5] < 1 or frame[5] > 4) return false;
        const remote = std.mem.readInt(u64, frame[6..14], .little);
        const local = std.mem.readInt(u64, frame[14..22], .little);
        for (self.slots) |maybe| if (maybe) |h| if (h.channel.local == local and h.channel.remote == remote) return h.admit(frame, now);
        return false;
    }

    pub fn service(self: *Handshakes, now: u64, send: anytype, budget: usize) usize {
        if (budget == 0) return 0;
        var work: usize = 0;
        for (0..MAX_HANDSHAKES) |_| {
            const index = self.cursor;
            self.cursor = @intCast((self.cursor + 1) % MAX_HANDSHAKES);
            const h = self.slots[index] orelse continue;
            if (!h.validate(now)) {
                self.slots[index] = null;
                continue;
            }
            if (h.runOnce(now, send)) work += 1;
            if (!h.active()) self.slots[index] = null;
            if (work == @min(budget, admission.DISPATCH_BUDGET)) break;
        }
        return work;
    }

    pub fn hasReadyWork(self: *const Handshakes, now: u64) bool {
        for (self.slots) |maybe| if (maybe) |h| if (h.ready(now)) return true;
        return false;
    }

    pub fn nextWake(self: *const Handshakes) ?u64 {
        var next: ?u64 = null;
        for (self.slots) |maybe| if (maybe) |h| {
            if (!h.active()) continue;
            const deadline = if (h.outgoing_len != 0) @min(h.expires_at, h.retry_at) else h.expires_at;
            next = if (next) |old| @min(old, deadline) else deadline;
        };
        return next;
    }
};

comptime {
    if (@sizeOf(Handshake) > 856 or @sizeOf(Handshakes) > 40) @compileError("peer handshake exceeds bounded coordination state");
}
