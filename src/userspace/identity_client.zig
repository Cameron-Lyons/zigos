const std = @import("std");
pub const protocol = @import("identity_protocol.zig");
pub const assertion_wire = @import("identity_assertion.zig");

pub const SendResult = enum { sent, busy, failed };
pub const ReceiveResult = union(enum) {
    empty,
    failed,
    reply: struct { sender_endpoint_id: u64, correlation_id: u64, length: u32, bytes: [protocol.MAX_FRAME_BYTES]u8 },
};

test "identity client rejects hostile fragmented replies and never exposes partial assertions" {
    const Transport = struct {
        next: ReceiveResult = .empty,
        pub fn send(_: *@This(), _: u64, _: u64, _: []const u8) SendResult {
            return .sent;
        }
        pub fn receive(self: *@This(), _: u64) ReceiveResult {
            const next = self.next;
            self.next = .empty;
            return next;
        }
        fn reply(self: *@This(), total: u16, offset: u16, bytes: []const u8) !void {
            self.next = .{ .reply = .{ .sender_endpoint_id = 2, .correlation_id = 4, .length = 0, .bytes = undefined } };
            const encoded = try protocol.encode(&self.next.reply.bytes, .{ .request_id = 4, .body = .{ .reply = .{ .status = .ok, .total = total, .offset = offset, .bytes = bytes } } });
            self.next.reply.length = @intCast(encoded.len);
        }
    };
    var encoded: [assertion_wire.MAX_BYTES]u8 = undefined;
    const bytes = try assertion_wire.encode(.{ .credential_id = 3, .owner_id = 1, .device_id = 2, .generation = 1, .counter = 1, .device_trust_generation = 1, .unlock_age_ticks = 2, .flags = 7, .public_key = @splat(7), .signature = @splat(8), .relying_party_id = "session.example", .origin = "https://session.example", .challenge = "challenge" }, &encoded);
    for (0..7) |case| {
        var client = Client{};
        var transport = Transport{};
        try client.begin(.{ .endpoint_capability_id = 1, .service_endpoint_id = 2, .credential_id = 3 }, 4, if (case == 6) "different" else "challenge");
        try transport.reply(@intCast(bytes.len), 0, bytes[0..68]);
        if (case == 0) transport.next.reply.sender_endpoint_id = 99;
        if (case == 1) transport.next.reply.correlation_id = 99;
        if (case == 2) transport.next.reply.bytes[4] = 0;
        _ = client.step(&transport);
        try std.testing.expect(client.result() == null);
        if (case >= 3) {
            try transport.reply(@intCast(bytes.len + @intFromBool(case == 3)), if (case == 4) 67 else 68, bytes[68..136]);
            if (case == 5) transport.next.reply.bytes[20] ^= 1; // public key: decoding alone cannot authenticate it
            _ = client.step(&transport);
            if (case >= 5) {
                var offset: usize = 136;
                while (offset < bytes.len) {
                    const end = @min(offset + 68, bytes.len);
                    try transport.reply(@intCast(bytes.len), @intCast(offset), bytes[offset..end]);
                    _ = client.step(&transport);
                    try std.testing.expect(client.result() == null);
                    offset = end;
                }
            }
        }
        if (case == 5) {
            // A complete envelope is not a verified signature. Applications
            // must still authenticate with their independently registered key.
            try std.testing.expect(client.phase == .finish);
        } else {
            try std.testing.expect(client.phase == .failed);
            try std.testing.expect(std.mem.allEqual(u8, &client.bytes, 0));
        }
    }
}

// Transport must reject attached capabilities. The client publishes no partial
// assertion. The relying party still verifies the independently registered key.
pub const Failure = enum(u8) { invalid_request, send, receive, peer, frame, sequence, assertion, challenge };

pub const Client = struct {
    binding: protocol.Binding = .{ .endpoint_capability_id = 0, .service_endpoint_id = 0, .credential_id = 0 },
    request_id: u64 = 0,
    phase: enum { idle, request, read, finish, ready, failed } = .idle,
    awaiting: bool = false,
    failure: ?Failure = null,
    challenge: [protocol.MAX_CHALLENGE_BYTES]u8 = @splat(0),
    challenge_len: u8 = 0,
    bytes: [assertion_wire.MAX_BYTES]u8 = @splat(0),
    total: u16 = 0,
    received: u16 = 0,

    pub fn begin(self: *Client, binding: protocol.Binding, request_id: u64, challenge: []const u8) !void {
        if (self.pending()) return error.IdentityRequestPending;
        if (binding.endpoint_capability_id == 0 or binding.service_endpoint_id == 0 or binding.credential_id == 0 or
            request_id == 0 or challenge.len == 0 or challenge.len > self.challenge.len) return error.InvalidIdentityRequest;
        self.* = .{ .binding = binding, .request_id = request_id, .phase = .request, .challenge_len = @intCast(challenge.len) };
        @memcpy(self.challenge[0..challenge.len], challenge);
    }

    pub fn pending(self: *const Client) bool {
        return self.phase == .request or self.phase == .read or self.phase == .finish;
    }

    pub fn result(self: *const Client) ?assertion_wire.Assertion {
        if (self.phase != .ready) return null;
        return assertion_wire.decode(self.bytes[0..self.total]) catch null;
    }

    fn fail(self: *Client, reason: Failure) void {
        self.failure = reason;
        @memset(&self.bytes, 0);
        @memset(&self.challenge, 0);
        self.received = 0;
        self.total = 0;
        self.phase = .failed;
        self.awaiting = false;
    }

    pub fn step(self: *Client, transport: anytype) bool {
        if (!self.pending()) return false;
        if (!self.awaiting) {
            var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
            const body: protocol.Body = switch (self.phase) {
                .request => .{ .assert = self.challenge[0..self.challenge_len] },
                .read => .{ .read = self.received },
                .finish => .finish,
                else => unreachable,
            };
            const payload = protocol.encode(&bytes, .{ .request_id = self.request_id, .body = body }) catch {
                self.fail(.invalid_request);
                return true;
            };
            switch (transport.send(self.binding.endpoint_capability_id, self.request_id, payload)) {
                .busy => return true,
                .failed => {
                    self.fail(.send);
                    return true;
                },
                .sent => {},
            }
            if (self.phase == .finish) {
                @memset(&self.challenge, 0);
                self.phase = .ready;
                return true;
            }
            self.awaiting = true;
        }
        switch (transport.receive(self.binding.endpoint_capability_id)) {
            .empty => return false,
            .failed => self.fail(.receive),
            .reply => |reply| {
                if (reply.sender_endpoint_id != self.binding.service_endpoint_id or reply.correlation_id != self.request_id or reply.length > reply.bytes.len) {
                    self.fail(.peer);
                    return true;
                }
                const frame = protocol.decode(reply.bytes[0..reply.length]) catch {
                    self.fail(.frame);
                    return true;
                };
                if (frame.request_id != self.request_id or frame.body != .reply) {
                    self.fail(.frame);
                    return true;
                }
                const data = frame.body.reply;
                if (data.status != .ok or data.total > self.bytes.len or data.offset != self.received or
                    (self.total != 0 and self.total != data.total))
                {
                    self.fail(.sequence);
                    return true;
                }
                self.total = data.total;
                @memcpy(self.bytes[self.received..][0..data.bytes.len], data.bytes);
                self.received += @intCast(data.bytes.len);
                self.awaiting = false;
                self.phase = .read;
                if (self.received == self.total) {
                    const value = assertion_wire.decode(self.bytes[0..self.total]) catch {
                        self.fail(.assertion);
                        return true;
                    };
                    if (value.credential_id != self.binding.credential_id or !std.mem.eql(u8, value.challenge, self.challenge[0..self.challenge_len])) {
                        self.fail(.challenge);
                        return true;
                    }
                    self.phase = .finish;
                }
            },
        }
        return true;
    }
};
