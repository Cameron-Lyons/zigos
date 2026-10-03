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
    action: ?protocol.Body = null,
    page: ?protocol.Page = null,
    receiving: bool = false,
    received: u16 = 0,
    labels: [protocol.MAX_PAGE_TEXT_BYTES]u8 = @splat(0),
    selected: u8 = 0,
    sent: bool = false,
    finished: bool = true,
    failed: bool = false,

    pub fn acceptsInput(self: *const Client, event: abi.InputEventDescriptor) bool {
        if (!self.binding.isValid()) return true;
        if (self.finished or self.failed) return event.window_id != self.window_id;
        if (self.receiving or self.action != null or event.window_id != self.window_id or event.length == 0) return false;
        return switch (event.bytes[0]) {
            abi.InputByte.focus_next, abi.InputByte.focus_previous, abi.InputByte.activate, abi.InputByte.cursor_up, abi.InputByte.cursor_down, abi.InputByte.page_up, abi.InputByte.page_down, abi.InputByte.dismiss_recovery => true,
            else => false,
        };
    }

    pub fn recordInput(self: *Client, event: abi.InputEventDescriptor, surface: *State) void {
        if (!self.binding.isValid() or self.finished or self.failed or !self.acceptsInput(event)) return;
        const page = self.page orelse return;
        if (page.count == 0 and (event.bytes[0] == abi.InputByte.focus_next or event.bytes[0] == abi.InputByte.focus_previous)) {
            if (surface.focus_index != 1) {
                surface.focus_index = 1;
                surface.revision +|= 1;
                return;
            }
            return;
        }
        switch (event.bytes[0]) {
            abi.InputByte.activate => self.action = if (surface.focus_index == 0 and page.count != 0) .{ .open = self.selected } else .cancel,
            abi.InputByte.dismiss_recovery => self.action = .cancel,
            abi.InputByte.page_up => if (page.previous) {
                self.action = .{ .move = false };
            },
            abi.InputByte.page_down => if (page.next) {
                self.action = .{ .move = true };
            },
            abi.InputByte.cursor_up, abi.InputByte.cursor_down => {
                if (page.count == 0) return;
                const old = self.selected;
                if (event.bytes[0] == abi.InputByte.cursor_up) self.selected -|= 1 else self.selected = @min(self.selected + 1, page.count - 1);
                if (old == self.selected) return;
                var offset: usize = 0;
                for (0..self.selected) |_| offset += (std.mem.indexOfScalar(u8, self.labels[offset..page.text_length], '\n') orelse unreachable) + 1;
                surface.cursor = @intCast(offset);
                surface.selection_anchor = surface.cursor;
                surface.focus_index = 0;
                surface.revision +|= 1;
                return;
            },
            else => {},
        }
        return;
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
                const encoded = protocol.encode(&bytes, .{ .token = self.token, .body = action }) catch unreachable;
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
                    .page => |page| {
                        const navigating = self.sent and self.action != null and self.action.? == .move;
                        if (self.receiving or frame.token <= self.token or (!self.finished and
                            (!navigating or page.window_id != self.window_id or frame.token - self.token != 1))) return true;
                        self.token = frame.token;
                        self.window_id = page.window_id;
                        self.page = page;
                        self.received = 0;
                        self.receiving = true;
                        self.action = null;
                        self.sent = false;
                        self.finished = false;
                        @memset(&self.labels, 0);
                        if (page.text_length == 0) self.publishPage(surface);
                    },
                    .text => |chunk| {
                        if (frame.token != self.token or !self.receiving) return true;
                        const page = self.page.?;
                        if (chunk.offset != self.received or chunk.bytes.len != @min(protocol.CHUNK_BYTES, page.text_length - self.received)) {
                            self.fail(surface);
                            return true;
                        }
                        @memcpy(self.labels[self.received..][0..chunk.bytes.len], chunk.bytes);
                        self.received += @intCast(chunk.bytes.len);
                        if (self.received == page.text_length) {
                            if (!protocol.validPageText(self.labels[0..self.received], page.count)) {
                                self.fail(surface);
                                return true;
                            }
                            self.publishPage(surface);
                        }
                    },
                    .result => |result| {
                        const withdrawn_navigation = self.sent and self.action != null and self.action.? == .move and
                            frame.token > self.token and frame.token - self.token == 1 and result.status == .unavailable;
                        if ((frame.token != self.token and !withdrawn_navigation) or self.finished) return true;
                        self.token = frame.token;
                        // The server may withdraw an offer before a decision.
                        if (!self.sent and result.status != .unavailable) return true;
                        self.finished = true;
                        self.receiving = false;
                        @memset(&self.labels, 0);
                        surface.window_id = 0;
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

    fn publishPage(self: *Client, surface: *State) void {
        const page = self.page.?;
        self.receiving = false;
        self.selected = 0;
        surface.window_id = page.window_id;
        surface.focus_index = if (page.count == 0) 1 else 0;
        surface.flags.active = true;
        show(surface, if (page.count == 0) "No documents available" else self.labels[0..page.text_length], if (page.count == 0) "\nCancel" else "\nOpen    Cancel");
    }

    fn fail(self: *Client, surface: *State) void {
        self.failed = true;
        @memset(&self.labels, 0);
        surface.window_id = 0;
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
    surface.selection_anchor = 0;
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
    const offer = protocol.Frame{ .token = 7, .body = .{ .page = .{ .window_id = 9, .text_length = 5, .count = 1, .previous = false, .next = false } } };
    mock.enqueue(99, offer);
    _ = client.step(binding, &surface, &mock);
    try std.testing.expect(client.finished);
    mock.enqueue(5, offer);
    _ = client.step(binding, &surface, &mock);
    mock.enqueue(5, .{ .token = 7, .body = .{ .text = .{ .offset = 0, .bytes = "Notes" } } });
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
    client.recordInput(event, &surface);
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
    mock.enqueue(5, .{ .token = 8, .body = .{ .text = .{ .offset = 0, .bytes = "Notes" } } });
    _ = client.step(binding, &surface, &mock);
    event.window_id = 10;
    try std.testing.expect(!client.acceptsInput(event));
    event.window_id = 9;
    surface.focus_index = 1;
    client.recordInput(event, &surface);
    mock.busy = true;
    mock.enqueue(5, .{ .token = 8, .body = .{ .result = .{ .status = .unavailable } } });
    _ = client.step(binding, &surface, &mock);
    try std.testing.expect(client.finished);
    try std.testing.expect(!client.hasUnsentDecision());
    try std.testing.expectEqual(@as(usize, 1), mock.sends);
    event.window_id = 10;
    try std.testing.expect(client.acceptsInput(event));
    client.recordInput(event, &surface);
    try std.testing.expect(client.action == null);
}

test "launcher client assembles pages atomically and freezes selection while browsing" {
    const Mock = PickerTestTransport;
    var mock = Mock{};
    var client = Client{};
    var surface = State.init("zigos.system.display");
    const text = &@as([62]u8, @splat('a')) ++ "\n文書\nc.md\nd.md";
    mock.deliver(&client, &surface, .{ .token = 1, .body = .{ .page = .{ .window_id = 9, .count = 4, .text_length = text.len, .previous = false, .next = true } } });
    const revision = surface.revision;
    var offset: usize = 0;
    while (offset < text.len) {
        try std.testing.expectEqual(revision, surface.revision);
        const length = @min(protocol.CHUNK_BYTES, text.len - offset);
        Mock.key(&client, &surface, abi.InputByte.activate);
        try std.testing.expect(client.action == null);
        mock.deliver(&client, &surface, .{ .token = 1, .body = .{ .text = .{ .offset = @intCast(offset), .bytes = text[offset..][0..length] } } });
        offset += length;
    }
    try std.testing.expectEqualStrings(text ++ "\nOpen    Cancel", surface.textSlice());
    Mock.key(&client, &surface, abi.InputByte.cursor_down);
    try std.testing.expectEqual(@as(u16, 63), surface.cursor);
    try std.testing.expectEqual(surface.cursor, surface.selection_anchor);
    try std.testing.expect(surface.presentationText().isCanonical());
    Mock.key(&client, &surface, abi.InputByte.page_down);
    mock.busy = true;
    _ = client.step(client.binding, &surface, &mock);
    Mock.key(&client, &surface, abi.InputByte.activate);
    try std.testing.expect(client.action.? == .move);
    mock.busy = false;
    _ = client.step(client.binding, &surface, &mock);
    try std.testing.expect(mock.sent.? == .move and mock.sent.?.move);
    // Stale headers cannot replace the visible page.
    mock.deliver(&client, &surface, .{ .token = 1, .body = .{ .page = .{ .window_id = 9, .count = 0, .text_length = 0, .previous = true, .next = false } } });
    try std.testing.expectEqualStrings(text ++ "\nOpen    Cancel", surface.textSlice());
    mock.deliver(&client, &surface, .{ .token = 2, .body = .{ .page = .{ .window_id = 9, .count = 1, .text_length = 4, .previous = true, .next = false } } });
    mock.deliver(&client, &surface, .{ .token = 2, .body = .{ .text = .{ .offset = 0, .bytes = "e.md" } } });
    try std.testing.expectEqualStrings("e.md\nOpen    Cancel", surface.textSlice());
    try std.testing.expectEqual(@as(u16, 0), surface.cursor);
    Mock.key(&client, &surface, abi.InputByte.activate);
    _ = client.step(client.binding, &surface, &mock);
    try std.testing.expect(mock.sent.? == .open and mock.sent.?.open == 0);
}

comptime {
    if (protocol.MAX_PAGE_TEXT_BYTES + "\nOpen    Cancel".len > abi.SURFACE_TEXT_BYTES) @compileError("picker page exceeds the owned surface");
    if (@sizeOf(Client) > 512) @compileError("picker client exceeds bounded storage");
}

const PickerTestTransport = struct {
    reply: @import("document_editor.zig").ReceiveResult = .empty,
    sent: ?protocol.Body = null,
    busy: bool = false,
    pub fn send(self: *@This(), _: u64, _: u64, bytes: []const u8) @import("document_editor.zig").SendResult {
        if (self.busy) return .busy;
        self.sent = (protocol.decode(bytes) catch unreachable).body;
        return .sent;
    }
    pub fn receive(self: *@This(), _: u64) @import("document_editor.zig").ReceiveResult {
        const reply = self.reply;
        self.reply = .empty;
        return reply;
    }
    fn deliver(self: *@This(), client: *Client, surface: *State, frame: protocol.Frame) void {
        var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        const encoded = protocol.encode(&bytes, frame) catch unreachable;
        self.reply = .{ .reply = .{ .sender_endpoint_id = 5, .correlation_id = frame.token, .length = @intCast(encoded.len), .bytes = bytes } };
        _ = client.step(.{ .endpoint_capability_id = 4, .service_endpoint_id = 5 }, surface, self);
    }
    fn key(client: *Client, surface: *State, op: u8) void {
        var event = std.mem.zeroes(abi.InputEventDescriptor);
        event.window_id = 9;
        event.sequence = surface.last_sequence + 1;
        event.length = 2;
        event.bytes = abi.inputPacket(op, 0);
        if (client.acceptsInput(event)) {
            _ = surface.apply(event);
            client.recordInput(event, surface);
        }
    }
};

test "launcher client rejects malformed assemblies and supports empty page cancellation" {
    const Mock = PickerTestTransport;
    for ([_]struct { offset: u16, bytes: []const u8 }{
        .{ .offset = 1, .bytes = "ab" },
        .{ .offset = 0, .bytes = "a" },
        .{ .offset = 0, .bytes = "\xffb" },
        .{ .offset = 0, .bytes = "a\n" },
    }) |chunk| {
        var mock = Mock{};
        var client = Client{};
        var surface = State.init("zigos.system.display");
        mock.deliver(&client, &surface, .{ .token = 1, .body = .{ .page = .{ .window_id = 9, .count = 1, .text_length = 2, .previous = false, .next = false } } });
        mock.deliver(&client, &surface, .{ .token = 1, .body = .{ .text = .{ .offset = chunk.offset, .bytes = chunk.bytes } } });
        try std.testing.expect(client.failed);
        try std.testing.expectEqualStrings("Document unavailable", surface.textSlice());
        try std.testing.expect(std.mem.allEqual(u8, &client.labels, 0));
    }
    var mock = Mock{};
    var client = Client{};
    var surface = State.init("zigos.system.display");
    const labels = &@as([96]u8, @splat('a')) ++ "\n" ++ &@as([96]u8, @splat('b')) ++ "\n" ++ &@as([96]u8, @splat('c')) ++ "\n" ++ &@as([96]u8, @splat('d'));
    mock.deliver(&client, &surface, .{ .token = 1, .body = .{ .page = .{ .window_id = 9, .count = 4, .text_length = labels.len, .previous = false, .next = true } } });
    var offset: usize = 0;
    while (offset < labels.len) {
        const length = @min(protocol.CHUNK_BYTES, labels.len - offset);
        mock.deliver(&client, &surface, .{ .token = 1, .body = .{ .text = .{ .offset = @intCast(offset), .bytes = labels[offset..][0..length] } } });
        offset += length;
    }
    try std.testing.expectEqualStrings(labels ++ "\nOpen    Cancel", surface.textSlice());
    for (0..3) |_| Mock.key(&client, &surface, abi.InputByte.cursor_down);
    try std.testing.expectEqual(@as(u16, 291), surface.cursor);
    try std.testing.expect(surface.presentationText().isCanonical());
    Mock.key(&client, &surface, abi.InputByte.page_down);
    mock.deliver(&client, &surface, .{ .token = 2, .body = .{ .page = .{ .window_id = 9, .count = 0, .text_length = 0, .previous = true, .next = false } } });
    try std.testing.expectEqualStrings("No documents available\nCancel", surface.textSlice());
    Mock.key(&client, &surface, abi.InputByte.focus_next);
    try std.testing.expectEqual(@as(u16, 1), surface.focus_index);
    Mock.key(&client, &surface, abi.InputByte.page_up);
    // Permission can be withdrawn after navigation but before its header arrives.
    mock.deliver(&client, &surface, .{ .token = 3, .body = .{ .result = .{ .status = .unavailable } } });
    try std.testing.expect(client.finished);
    mock.deliver(&client, &surface, .{ .token = 4, .body = .{ .page = .{ .window_id = 9, .count = 0, .text_length = 0, .previous = false, .next = false } } });
    Mock.key(&client, &surface, abi.InputByte.activate);
    _ = client.step(client.binding, &surface, &mock);
    try std.testing.expect(mock.sent.? == .cancel);
}
