const std = @import("std");
const abi = @import("native_abi");
const mailbox = @import("userspace_bootstrap_mailbox");
const protocol = @import("launcher_protocol.zig");
const State = @import("ui_surface_state.zig").State;

// Per-compositor-task state. The backend retains all path and authority data.
pub const Client = struct {
    binding: mailbox.LauncherBinding = .{},
    token: u64 = 0,
    window_id: u64 = 0,
    action: ?enum { open, cancel } = null,
    sent: bool = false,
    finished: bool = true,
    failed: bool = false,

    pub fn acceptsInput(self: *const Client, event: abi.InputEventDescriptor) bool {
        if (!self.binding.isValid()) return true;
        if (self.finished or self.failed) return event.window_id != self.window_id;
        if (self.action != null or event.window_id != self.window_id or event.length == 0) return false;
        return switch (event.bytes[0]) {
            abi.InputByte.focus_next, abi.InputByte.focus_previous, abi.InputByte.activate => true,
            else => false,
        };
    }

    pub fn recordActivation(self: *Client, event: abi.InputEventDescriptor, surface: *const State) void {
        if (!self.binding.isValid() or self.finished or self.failed or !self.acceptsInput(event)) return;
        if (event.bytes[0] == abi.InputByte.activate) self.action = if (surface.focus_index == 0) .open else .cancel;
    }

    pub fn hasUnsentDecision(self: *const Client) bool {
        return self.action != null and !self.sent and !self.failed and !self.finished;
    }

    // At most one send and one receive. Queue pressure keeps the exact action;
    // after publication, endpoint arrival wakes the parked task for its result.
    pub fn step(self: *Client, binding: mailbox.LauncherBinding, surface: *State, transport: anytype) bool {
        if (!std.meta.eql(binding, self.binding)) self.* = .{ .binding = binding };
        if (!binding.isValid() or self.failed) return false;
        var retry = false;
        if (self.action) |action| {
            if (!self.sent) {
                var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
                const encoded = protocol.encode(&bytes, .{ .token = self.token, .body = if (action == .open) .open else .cancel }) catch unreachable;
                switch (transport.send(binding.endpoint_capability_id, self.token, encoded)) {
                    .sent => self.sent = true,
                    .busy => retry = true,
                    .failed => {
                        self.fail(surface);
                        return false;
                    },
                }
            }
        }
        switch (transport.receive(binding.endpoint_capability_id)) {
            .empty => return retry,
            .failed => {
                self.fail(surface);
                return false;
            },
            .reply => |reply| {
                if (reply.sender_endpoint_id != binding.service_endpoint_id or reply.length > reply.bytes.len) return true;
                const frame = protocol.decode(reply.bytes[0..reply.length]) catch return true;
                if (frame.token != reply.correlation_id) return true;
                switch (frame.body) {
                    .offer => |offer| {
                        if (!self.finished or frame.token <= self.token) return true;
                        self.token = frame.token;
                        self.window_id = offer.window_id;
                        self.action = null;
                        self.sent = false;
                        self.finished = false;
                        surface.focus_index = 0;
                        surface.flags.active = true;
                        show(surface, offer.label, "\nOpen    Cancel");
                    },
                    .result => |result| {
                        if (frame.token != self.token or self.finished) return true;
                        // The server may withdraw an offer before a decision.
                        if (!self.sent and result.status != .unavailable) return true;
                        self.finished = true;
                        self.action = null;
                        surface.flags.active = false;
                        show(surface, switch (result.status) {
                            .opened => "Document opened",
                            .cancelled => "Open cancelled",
                            .unavailable => "Document unavailable",
                        }, "");
                    },
                    else => {},
                }
                return true;
            },
        }
    }

    fn fail(self: *Client, surface: *State) void {
        self.failed = true;
        surface.flags.active = false;
        show(surface, "Document unavailable", "");
    }
};

fn show(surface: *State, label: []const u8, suffix: []const u8) void {
    @memset(&surface.text, 0);
    @memcpy(surface.text[0..label.len], label);
    @memcpy(surface.text[label.len..][0..suffix.len], suffix);
    surface.text_length = @intCast(label.len + suffix.len);
    surface.cursor = 0;
    surface.flags.dirty = false;
    surface.revision +|= 1;
}

test "launcher client freezes an ordered decision and authenticates receipts" {
    const transport_types = @import("document_editor.zig");
    const Mock = struct {
        reply: transport_types.ReceiveResult = .empty,
        busy: bool = false,
        sends: usize = 0,
        pub fn send(self: *@This(), _: u64, token: u64, bytes: []const u8) transport_types.SendResult {
            if (self.busy) return .busy;
            const frame = protocol.decode(bytes) catch unreachable;
            std.debug.assert(frame.token == token and frame.body == .cancel);
            self.sends += 1;
            return .sent;
        }
        pub fn receive(self: *@This(), _: u64) transport_types.ReceiveResult {
            const reply = self.reply;
            self.reply = .empty;
            return reply;
        }
        fn enqueue(self: *@This(), sender: u64, frame: protocol.Frame) void {
            var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
            const encoded = protocol.encode(&bytes, frame) catch unreachable;
            self.reply = .{ .reply = .{ .sender_endpoint_id = sender, .correlation_id = frame.token, .length = @intCast(encoded.len), .bytes = bytes } };
        }
    };
    var mock = Mock{};
    var client = Client{};
    var surface = State.init("zigos.system.display");
    const binding = mailbox.LauncherBinding{ .endpoint_capability_id = 4, .service_endpoint_id = 5 };
    const offer = protocol.Frame{ .token = 7, .body = .{ .offer = .{ .window_id = 9, .label = "Notes" } } };
    mock.enqueue(99, offer);
    _ = client.step(binding, &surface, &mock);
    try std.testing.expect(client.finished);
    mock.enqueue(5, offer);
    _ = client.step(binding, &surface, &mock);
    try std.testing.expectEqualStrings("Notes\nOpen    Cancel", surface.textSlice());
    var event = std.mem.zeroes(abi.InputEventDescriptor);
    event.window_id = 9;
    event.sequence = 1;
    event.length = 2;
    event.bytes = abi.inputPacket(abi.InputByte.focus_next, 0);
    try std.testing.expect(client.acceptsInput(event));
    _ = surface.apply(event);
    event.sequence = 2;
    event.bytes = abi.inputPacket(abi.InputByte.activate, 0);
    _ = surface.apply(event);
    client.recordActivation(event, &surface);
    try std.testing.expect(!client.acceptsInput(event));
    mock.busy = true;
    try std.testing.expect(client.step(binding, &surface, &mock));
    mock.busy = false;
    try std.testing.expect(!client.step(binding, &surface, &mock));
    try std.testing.expect(!client.step(binding, &surface, &mock));
    try std.testing.expectEqual(@as(usize, 1), mock.sends);
    mock.enqueue(5, .{ .token = 6, .body = .{ .result = .{ .status = .cancelled } } });
    _ = client.step(binding, &surface, &mock);
    try std.testing.expect(!client.finished);
    mock.enqueue(5, .{ .token = 7, .body = .{ .result = .{ .status = .cancelled } } });
    _ = client.step(binding, &surface, &mock);
    try std.testing.expect(client.finished);
    mock.enqueue(5, offer);
    _ = client.step(binding, &surface, &mock);
    try std.testing.expect(client.finished);
    mock.enqueue(5, .{ .token = 8, .body = offer.body });
    _ = client.step(binding, &surface, &mock);
    try std.testing.expect(!client.finished);
    event.window_id = 10;
    try std.testing.expect(!client.acceptsInput(event));
    event.window_id = 9;
    surface.focus_index = 1;
    client.recordActivation(event, &surface);
    mock.busy = true;
    mock.enqueue(5, .{ .token = 8, .body = .{ .result = .{ .status = .unavailable } } });
    _ = client.step(binding, &surface, &mock);
    try std.testing.expect(client.finished);
    try std.testing.expect(!client.hasUnsentDecision());
    try std.testing.expectEqual(@as(usize, 1), mock.sends);
    event.window_id = 10;
    try std.testing.expect(client.acceptsInput(event));
    client.recordActivation(event, &surface);
    try std.testing.expect(client.action == null);
}
