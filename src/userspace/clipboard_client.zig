const std = @import("std");
const abi = @import("native_abi");
const mailbox = @import("userspace_bootstrap_mailbox");
const protocol = @import("clipboard_protocol.zig");
const State = @import("ui_surface_state.zig").State;

const Phase = enum { idle, begin, chunk, commit, paste, read };
pub const Client = struct {
    bytes: [protocol.MAX_TEXT_BYTES]u8 = @splat(0),
    binding: mailbox.ClipboardBinding = .{},
    gesture: u64 = 0,
    revision: ?u64 = null,
    length: u16 = 0,
    offset: u16 = 0,
    cursor: u16 = 0,
    anchor: u16 = 0,
    phase: Phase = .idle,
    awaiting: bool = false,
    cut: bool = false,

    pub fn pending(self: *const Client) bool {
        return self.phase != .idle;
    }

    pub fn start(self: *Client, binding: mailbox.ClipboardBinding, state: *State, event: abi.InputEventDescriptor) void {
        if (state.model != .notes or event.length != 2 or self.pending()) return;
        const op = event.bytes[0];
        if (op != abi.InputByte.copy and op != abi.InputByte.cut and op != abi.InputByte.paste) return;
        feedback(state, false);
        if (op != abi.InputByte.paste and state.selectionSlice().len == 0) return;
        if (!binding.isValid() or state.contentRevision() == null) {
            feedback(state, true);
            return;
        }
        self.* = .{
            .binding = binding,
            .gesture = event.sequence,
            .revision = state.contentRevision(),
            .cursor = state.cursor,
            .anchor = state.selection_anchor,
            .phase = if (op == abi.InputByte.paste) .paste else .begin,
            .cut = op == abi.InputByte.cut,
        };
        if (op != abi.InputByte.paste) {
            const selected = state.selectionSlice();
            @memcpy(self.bytes[0..selected.len], selected);
            self.length = @intCast(selected.len);
        }
    }

    // At most one send and one receive per dispatch. Input remains parked at
    // this operation until a complete reply can be applied atomically.
    pub fn step(self: *Client, state: *State, transport: anytype) bool {
        if (!self.pending()) return false;
        if (!self.awaiting) {
            var buffer: [protocol.MAX_FRAME_BYTES]u8 = undefined;
            const body: protocol.Body = switch (self.phase) {
                .idle => unreachable,
                .begin => .{ .copy_begin = self.length },
                .chunk => .{ .copy_chunk = .{ .offset = self.offset, .bytes = self.bytes[self.offset..self.nextOffset()] } },
                .commit => .{ .copy_commit = {} },
                .paste => .{ .paste = {} },
                .read => .{ .paste_read = self.offset },
            };
            const bytes = protocol.encode(&buffer, .{ .gesture = self.gesture, .body = body }) catch unreachable;
            switch (transport.send(self.binding.endpoint_capability_id, self.gesture, bytes)) {
                .busy => return true,
                .failed => {
                    self.finish(state, true);
                    return true;
                },
                .sent => self.awaiting = true,
            }
        }
        switch (transport.receive(self.binding.endpoint_capability_id)) {
            .empty => return false,
            .failed => self.finish(state, true),
            .reply => |reply| {
                if (reply.sender_endpoint_id != self.binding.service_endpoint_id or reply.correlation_id != self.gesture) return true;
                if (reply.length > reply.bytes.len) {
                    self.finish(state, true);
                    return true;
                }
                const frame = protocol.decode(reply.bytes[0..reply.length]) catch {
                    self.finish(state, true);
                    return true;
                };
                if (frame.gesture != self.gesture or frame.body != .reply) {
                    self.finish(state, true);
                    return true;
                }
                const result = frame.body.reply;
                if (result.status != .ok) {
                    self.finish(state, result.status != .empty);
                    return true;
                }
                self.awaiting = false;
                switch (self.phase) {
                    .idle => unreachable,
                    .begin, .chunk, .commit => {
                        const expected: u16 = switch (self.phase) {
                            .begin => 0,
                            .chunk => self.nextOffset(),
                            else => self.length,
                        };
                        if (result.total != self.length or result.offset != expected or result.bytes.len != 0) {
                            self.finish(state, true);
                            return true;
                        }
                        if (self.phase == .commit) {
                            const valid = !self.cut or (self.matches(state) and
                                std.mem.eql(u8, state.selectionSlice(), self.bytes[0..self.length]) and state.replaceSelection(""));
                            self.finish(state, !valid);
                        } else {
                            self.offset = expected;
                            self.phase = if (self.offset == self.length) .commit else .chunk;
                        }
                    },
                    .paste, .read => {
                        if (self.phase == .paste) self.length = result.total;
                        if (result.total != self.length or result.offset != self.offset or self.length == 0 or
                            result.bytes.len != @min(protocol.CHUNK_BYTES, self.length - self.offset))
                        {
                            self.finish(state, true);
                            return true;
                        }
                        @memcpy(self.bytes[self.offset..][0..result.bytes.len], result.bytes);
                        self.offset += @intCast(result.bytes.len);
                        if (self.offset == self.length) {
                            const valid = self.matches(state) and state.replaceSelection(self.bytes[0..self.length]);
                            self.finish(state, !valid);
                        } else self.phase = .read;
                    },
                }
            },
        }
        return true;
    }

    fn nextOffset(self: *const Client) u16 {
        return self.offset + @as(u16, @intCast(@min(protocol.CHUNK_BYTES, self.length - self.offset)));
    }
    fn matches(self: *const Client, state: *const State) bool {
        return self.revision == state.contentRevision() and self.cursor == state.cursor and self.anchor == state.selection_anchor;
    }
    fn finish(self: *Client, state: *State, failed: bool) void {
        self.* = .{};
        feedback(state, failed);
    }
};

fn feedback(state: *State, failed: bool) void {
    if (state.flags.clipboard_failed == failed) return;
    state.flags.clipboard_failed = failed;
    state.revision +|= 1;
}

comptime {
    if (@sizeOf(Client) > 608) @compileError("clipboard client exceeds its task-local state bound");
}

const TestTransport = struct {
    const transport = @import("document_editor.zig");
    outgoing: [protocol.MAX_FRAME_BYTES]u8 = undefined,
    length: usize = 0,
    reply: ?transport.Reply = null,
    busy: bool = false,
    failed: bool = false,
    sends: usize = 0,

    pub fn send(self: *@This(), _: u64, _: u64, bytes: []const u8) transport.SendResult {
        self.sends += 1;
        if (self.failed) return .failed;
        if (self.busy) return .busy;
        @memcpy(self.outgoing[0..bytes.len], bytes);
        self.length = bytes.len;
        return .sent;
    }
    pub fn receive(self: *@This(), _: u64) transport.ReceiveResult {
        if (self.failed) return .failed;
        const reply = self.reply orelse return .empty;
        self.reply = null;
        return .{ .reply = reply };
    }
    fn respond(self: *@This(), gesture: u64, response: protocol.Reply) !void {
        var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        const payload = try protocol.encode(&bytes, .{ .gesture = gesture, .body = .{ .reply = response } });
        self.reply = .{ .sender_endpoint_id = 2, .correlation_id = gesture, .length = @intCast(payload.len), .bytes = bytes };
    }
};

const test_binding = mailbox.ClipboardBinding{ .endpoint_capability_id = 1, .service_endpoint_id = 2 };
fn testEvent(state: *State, op: u8) abi.InputEventDescriptor {
    var event = std.mem.zeroes(abi.InputEventDescriptor);
    event.sequence = state.last_sequence + 1;
    event.length = 2;
    event.bytes = abi.inputPacket(op, 0);
    _ = state.apply(event);
    return event;
}

test "clipboard client cuts only after a complete copy receipt and restores selection with undo" {
    var state = State.init("app.notes");
    try std.testing.expect(state.loadDocument("hello world"));
    state.cursor = 5;
    state.selection_anchor = 0;
    var client = Client{};
    var transport = TestTransport{ .busy = true };
    const event = testEvent(&state, abi.InputByte.cut);
    client.start(test_binding, &state, event);
    try std.testing.expect(client.step(&state, &transport));
    try std.testing.expectEqualStrings("hello world", state.textSlice());
    try std.testing.expectEqual(@as(usize, 1), transport.sends);
    transport.busy = false;
    try std.testing.expect(!client.step(&state, &transport));
    try transport.respond(event.sequence, .{ .status = .ok, .total = 5 });
    try std.testing.expect(client.step(&state, &transport));
    try std.testing.expect(!client.step(&state, &transport));
    try std.testing.expectEqualStrings("hello", (try protocol.decode(transport.outgoing[0..transport.length])).body.copy_chunk.bytes);
    try transport.respond(event.sequence, .{ .status = .ok, .total = 5, .offset = 5 });
    _ = client.step(&state, &transport);
    _ = client.step(&state, &transport);
    try std.testing.expectEqualStrings("hello world", state.textSlice());
    try transport.respond(event.sequence, .{ .status = .ok, .total = 5, .offset = 5 });
    try std.testing.expect(client.step(&state, &transport)); // Continue to queued input after completion.
    try std.testing.expect(!client.pending());
    try std.testing.expectEqualStrings(" world", state.textSlice());
    try std.testing.expect(state.flags.dirty);
    _ = testEvent(&state, abi.InputByte.undo);
    try std.testing.expectEqualStrings("hello world", state.textSlice());
    try std.testing.expectEqual(@as(u16, 5), state.cursor);
    try std.testing.expectEqual(@as(u16, 0), state.selection_anchor);
    try std.testing.expect(!state.flags.dirty);
    try std.testing.expectEqualSlices(u8, &@as([protocol.MAX_TEXT_BYTES]u8, @splat(0)), &client.bytes);
}

test "clipboard client stages a full paste and leaves the selection intact on failure or overflow" {
    for ([_]enum { success, denied, short_chunk, disconnected, overflow, changed }{ .success, .denied, .short_chunk, .disconnected, .overflow, .changed }) |case| {
        var state = State.init("app.notes");
        try std.testing.expect(state.loadDocument("draft"));
        state.selection_anchor = if (case == .overflow) 5 else 0;
        var client = Client{};
        var transport = TestTransport{};
        const event = testEvent(&state, abi.InputByte.paste);
        client.start(test_binding, &state, event);
        _ = client.step(&state, &transport);
        const payload: [protocol.MAX_TEXT_BYTES]u8 = @splat('p');
        var offset: usize = 0;
        while (offset < payload.len and client.pending()) {
            const end = @min(offset + protocol.CHUNK_BYTES, payload.len);
            if (offset != 0 and case == .denied) {
                try transport.respond(event.sequence, .{ .status = .denied });
            } else if (offset != 0 and case == .disconnected) {
                transport.failed = true;
            } else {
                const length = if (offset != 0 and case == .short_chunk) end - offset - 1 else end - offset;
                try transport.respond(event.sequence, .{ .status = .ok, .total = payload.len, .offset = @intCast(offset), .bytes = payload[offset..][0..length] });
            }
            if (case == .changed and end == payload.len) state.cursor = 4;
            _ = client.step(&state, &transport);
            if (client.pending()) {
                try std.testing.expectEqualStrings("draft", state.textSlice());
                try std.testing.expect(!state.flags.dirty);
                _ = client.step(&state, &transport);
            }
            offset = end;
        }
        try std.testing.expect(!client.pending());
        if (case == .success) {
            try std.testing.expectEqualStrings(&payload, state.textSlice());
            _ = testEvent(&state, abi.InputByte.undo);
            try std.testing.expectEqualStrings("draft", state.textSlice());
            try std.testing.expect(!state.flags.dirty);
        } else {
            try std.testing.expectEqualStrings("draft", state.textSlice());
            try std.testing.expectEqual(@as(u16, if (case == .changed) 4 else 5), state.cursor);
            try std.testing.expectEqual(@as(u16, if (case == .overflow) 5 else 0), state.selection_anchor);
            try std.testing.expect(!state.flags.dirty);
            try std.testing.expect(state.flags.clipboard_failed);
        }
        try std.testing.expectEqualSlices(u8, &@as([protocol.MAX_TEXT_BYTES]u8, @splat(0)), &client.bytes);
    }
}
