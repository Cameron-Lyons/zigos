//! One locally authorized attestation exchange on an established Noise channel.
//! Ciphertext fragments are cached for retries; packets allocate no state and
//! never run a TPM command. The owner supplies hardware evidence asynchronously.
const std = @import("std");
const peer = @import("peer_channel.zig");
const attest = @import("../platform/tpm_attestation.zig");
const wire = @import("../platform/tpm_attestation_wire.zig");
const timer = @import("../../kernel/timer/timer.zig");
const admission = @import("peer_admission.zig");
pub const Requirement = union(enum) {
    verify: *attest.Pending,
    prove: *const attest.Enrollment,
};
const HEADER = 26;
const CHUNK = peer.MAX_PAYLOAD - HEADER;
const PARTS = std.math.divCeil(usize, wire.MAX_BYTES, CHUNK) catch unreachable;
const Phase = enum { receiving_challenge, quoting, responding, proved, receiving_response, verified, closed };

pub const Exchange = struct {
    channel: *peer.Channel,
    requirement: Requirement,
    expires_at: u64,
    last_tick: u64,
    phase: Phase,
    id: [16]u8 = @splat(0),
    accepted: ?attest.Accepted = null,
    received: [wire.MAX_BYTES]u8 = @splat(0),
    received_len: u16 = 0,
    received_mask: u8 = 0,
    incoming: [peer.MAX_FRAME]u8 = @splat(0),
    incoming_len: u16 = 0,
    last_response: [peer.MAX_FRAME]u8 = @splat(0),
    last_response_len: u16 = 0,
    outgoing: [PARTS][peer.MAX_FRAME]u8 = @splat(@splat(0)),
    outgoing_lens: [PARTS]u16 = @splat(0),
    outgoing_count: u8 = 0,
    outgoing_index: u8 = 0,
    retry_at: u64 = 0,
    ack_needed: bool = false,
    budget_tick: u64 = 0,
    admitted: u8 = 0,
    confirmation: [peer.MAX_FRAME]u8 = @splat(0),
    confirmation_len: u16 = 0,
    confirmation_turn: bool = true,
    confirmation_retry_at: u64 = 0,

    pub fn init(channel: *peer.Channel, requirement: Requirement, confirmation: []const u8, now: u64, expires_at: u64) !Exchange {
        if (expires_at <= now) return error.InvalidPeerLifetime;
        if (confirmation.len > peer.MAX_FRAME) return error.InvalidConfirmation;
        const binding = try channel.binding(now);
        var result = Exchange{ .channel = channel, .requirement = requirement, .expires_at = expires_at, .last_tick = now, .phase = if (requirement == .verify) .receiving_response else .receiving_challenge };
        @memcpy(result.confirmation[0..confirmation.len], confirmation);
        result.confirmation_len = @intCast(confirmation.len);
        switch (requirement) {
            .verify => |pending| {
                if (pending.enrollment.device.serial != channel.remote) return error.PeerMismatch;
                try pending.bindChannel(binding, milliseconds(now));
                result.id = pending.challenge.qualifyingData()[0..16].*;
                var bytes: [wire.MAX_BYTES]u8 = undefined;
                try result.encode(1, try wire.encodeChallenge(&bytes, &pending.challenge, &pending.enrollment), now);
            },
            .prove => |enrollment| {
                try enrollment.validate();
                if (enrollment.device.serial != channel.local) return error.PeerMismatch;
            },
        }
        return result;
    }

    pub fn ready(self: *const Exchange) bool {
        return self.phase == .verified or self.phase == .proved;
    }

    pub fn needsQuote(self: *const Exchange) bool {
        return self.phase == .quoting;
    }

    pub fn active(self: *const Exchange) bool {
        return self.phase != .closed;
    }

    pub fn close(self: *Exchange) void {
        if (self.requirement == .verify) self.requirement.verify.cancel();
        self.channel.close();
        self.erase();
    }

    pub fn erase(self: *Exchange) void {
        @memset(&self.received, 0);
        @memset(&self.incoming, 0);
        @memset(&self.last_response, 0);
        @memset(&self.confirmation, 0);
        for (&self.outgoing) |*frame| @memset(frame, 0);
        self.accepted = null;
        self.phase = .closed;
    }

    pub fn validate(self: *Exchange, now: u64) bool {
        if (!self.active()) return false;
        if (now < self.last_tick or now >= self.expires_at) {
            self.close();
            return false;
        }
        self.last_tick = now;
        self.channel.validate(now) catch {
            self.close();
            return false;
        };
        if (self.requirement == .verify and self.phase != .verified) self.requirement.verify.verifier.observe(milliseconds(now)) catch {
            self.close();
            return false;
        };
        return true;
    }

    pub fn quoteChallenge(self: *Exchange, now: u64) ?attest.Challenge {
        if (!self.validate(now) or self.phase != .quoting) return null;
        return wire.decodeChallenge(self.received[0..self.received_len], self.requirement.prove) catch null;
    }

    pub fn completeQuote(self: *Exchange, response: *const attest.Response, now: u64) !void {
        if (!self.validate(now) or self.phase != .quoting) return error.InvalidState;
        var bytes: [wire.MAX_BYTES]u8 = undefined;
        try self.encode(2, try wire.encodeResponse(&bytes, response), now);
        @memset(&self.received, 0);
        self.phase = .responding;
    }

    pub fn admit(self: *Exchange, frame: []const u8, now: u64) bool {
        if (!self.active() or now >= self.expires_at or self.incoming_len != 0 or frame.len <= peer.DATA_HEADER + 16 or frame.len > peer.MAX_FRAME or
            !std.mem.eql(u8, frame[0..4], peer.MAGIC) or frame[4] != peer.VERSION or frame[5] != peer.ATTESTATION_KIND or
            std.mem.readInt(u64, frame[6..14], .little) != self.channel.remote or std.mem.readInt(u64, frame[14..22], .little) != self.channel.local) return false;
        if (self.budget_tick != now) {
            self.budget_tick = now;
            self.admitted = 0;
        }
        if (self.admitted == admission.MAX_FRAMES_PER_TICK) return false;
        self.admitted += 1;
        @memcpy(self.incoming[0..frame.len], frame);
        self.incoming_len = @intCast(frame.len);
        return true;
    }

    pub fn hasWork(self: *const Exchange, now: u64) bool {
        return self.active() and (self.incoming_len != 0 or
            (self.confirmation_len != 0 and now >= self.confirmation_retry_at) or
            (self.outgoing_count != 0 and now >= self.retry_at and (self.phase != .verified or self.ack_needed)));
    }

    pub fn nextWake(self: *const Exchange) ?u64 {
        if (!self.active()) return null;
        var deadline = self.expires_at;
        if (self.confirmation_len != 0) deadline = @min(deadline, self.confirmation_retry_at);
        if (self.requirement == .verify and self.phase != .verified) deadline = @min(deadline, std.math.divCeil(u64, self.requirement.verify.verifier.expires_at_ms, timer.MILLISECONDS_PER_TICK) catch deadline);
        if (self.outgoing_count != 0 and (self.phase != .verified or self.ack_needed)) deadline = @min(deadline, self.retry_at);
        return deadline;
    }

    pub fn service(self: *Exchange, now: u64, destination: [6]u8, send: anytype) bool {
        if (!self.validate(now)) return true;
        if (self.incoming_len != 0) {
            defer {
                @memset(&self.incoming, 0);
                self.incoming_len = 0;
            }
            self.receive(self.incoming[0..self.incoming_len], now) catch self.close();
            return true;
        }
        if (!self.hasWork(now)) return false;
        if (self.confirmation_len != 0 and now >= self.confirmation_retry_at and
            (self.confirmation_turn or self.outgoing_count == 0 or now < self.retry_at))
        {
            self.confirmation_turn = false;
            _ = send(destination, self.confirmation[0..self.confirmation_len]);
            self.confirmation_retry_at = std.math.add(u64, now, admission.RETRY_TICKS) catch self.expires_at;
            return true;
        }
        self.confirmation_turn = true;
        const index = self.outgoing_index;
        if (send(destination, self.outgoing[index][0..self.outgoing_lens[index]])) {
            if (self.phase == .verified) self.ack_needed = false;
        }
        self.outgoing_index += 1;
        if (self.outgoing_index == self.outgoing_count) {
            self.outgoing_index = 0;
            self.retry_at = std.math.add(u64, now, admission.RETRY_TICKS) catch self.expires_at;
        }
        return true;
    }

    fn receive(self: *Exchange, frame: []const u8, now: u64) !void {
        if (self.phase == .verified) {
            if (std.mem.eql(u8, frame, self.last_response[0..self.last_response_len])) self.ack_needed = true;
            return;
        }
        var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
        defer @memset(&plaintext, 0);
        const data = self.channel.openAttestation(&plaintext, frame, now) catch return;
        self.confirmation_len = 0;
        @memset(&self.confirmation, 0);
        if (data.len < HEADER or !std.mem.eql(u8, data[0..5], "ZGAF\x01")) return error.InvalidAttestationWire;
        const kind = data[5];
        const total = std.mem.readInt(u16, data[6..8], .little);
        const index = data[8];
        const count = data[9];
        const id = data[10..26];
        if (kind == 3) {
            if (self.phase != .responding or total != 0 or index != 0 or count != 0 or data.len != HEADER or !std.mem.eql(u8, id, &self.id)) return error.InvalidAttestationWire;
            self.phase = .proved;
            self.outgoing_count = 0;
            return;
        }
        if ((kind != 1 or self.phase != .receiving_challenge) and (kind != 2 or self.phase != .receiving_response)) return error.InvalidAttestationWire;
        if (total == 0 or total > wire.MAX_BYTES or count != (std.math.divCeil(usize, total, CHUNK) catch unreachable) or index >= count) return error.InvalidAttestationWire;
        const start = @as(usize, index) * CHUNK;
        const length = @min(CHUNK, total - start);
        if (data.len != HEADER + length) return error.InvalidAttestationWire;
        if (self.received_mask == 0) {
            if (self.requirement == .verify and !std.mem.eql(u8, id, &self.id)) return error.InvalidAttestationWire;
            self.id = id[0..16].*;
            self.received_len = total;
        } else if (self.received_len != total or !std.mem.eql(u8, id, &self.id)) return error.InvalidAttestationWire;
        const bit = @as(u8, 1) << @intCast(index);
        if (self.received_mask & bit != 0) return error.InvalidAttestationWire;
        @memcpy(self.received[start..][0..length], data[HEADER..]);
        self.received_mask |= bit;
        if (self.received_mask != mask(count)) return;
        if (kind == 1) {
            const challenge = try wire.decodeChallenge(self.received[0..total], self.requirement.prove);
            if (!std.mem.eql(u8, &challenge.channel_binding, &try self.channel.binding(now)) or
                !std.mem.eql(u8, challenge.qualifyingData()[0..16], &self.id)) return error.InvalidTpmChallenge;
            self.phase = .quoting;
        } else {
            const response = try wire.decodeResponse(self.received[0..total]);
            self.accepted = try self.requirement.verify.accept(&response, milliseconds(now));
            @memcpy(self.last_response[0..frame.len], frame);
            self.last_response_len = @intCast(frame.len);
            try self.encode(3, "", now);
            self.ack_needed = true;
            self.phase = .verified;
        }
        if (kind == 2) @memset(&self.received, 0);
    }

    fn encode(self: *Exchange, kind: u8, bytes: []const u8, now: u64) !void {
        const count = if (kind == 3) 1 else try std.math.divCeil(usize, bytes.len, CHUNK);
        if (count == 0 or count > PARTS) return error.InvalidAttestationWire;
        self.outgoing_count = @intCast(count);
        self.outgoing_index = 0;
        self.retry_at = now;
        for (0..count) |index| {
            var payload: [peer.MAX_PAYLOAD]u8 = @splat(0);
            @memcpy(payload[0..5], "ZGAF\x01");
            payload[5] = kind;
            std.mem.writeInt(u16, payload[6..8], @intCast(bytes.len), .little);
            payload[8] = @intCast(index);
            payload[9] = if (kind == 3) 0 else @intCast(count);
            @memcpy(payload[10..26], &self.id);
            const start = index * CHUNK;
            const length = @min(CHUNK, bytes.len - start);
            @memcpy(payload[HEADER..][0..length], bytes[start..][0..length]);
            const encrypted = try self.channel.sealAttestation(&self.outgoing[index], payload[0 .. HEADER + length], now);
            self.outgoing_lens[index] = @intCast(encrypted.len);
        }
    }
};

fn mask(count: u8) u8 {
    return (@as(u8, 1) << @intCast(count)) - 1;
}

fn milliseconds(ticks: u64) u64 {
    return std.math.mul(u64, ticks, timer.MILLISECONDS_PER_TICK) catch std.math.maxInt(u64);
}

comptime {
    if (PARTS > 3 or @sizeOf(Exchange) > 2304) @compileError("peer attestation exceeds bounded exchange state");
}
