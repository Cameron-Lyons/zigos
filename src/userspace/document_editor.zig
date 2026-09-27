const std = @import("std");
const mailbox = @import("userspace_bootstrap_mailbox");
const protocol = @import("document_protocol.zig");
const Client = @import("document_client.zig").Client;
const State = @import("ui_surface_state.zig").State;

pub const FRAMES_PER_DISPATCH = 2;
pub const SendResult = enum { sent, busy, failed };
pub const Reply = struct {
    sender_endpoint_id: u64,
    correlation_id: u64,
    length: u16,
    bytes: [protocol.MAX_FRAME_BYTES]u8,
};
pub const ReceiveResult = union(enum) { empty, failed, reply: Reply };

// The opener supplies a fresh channel for one document. This state owns
// both the in-flight snapshot and the latest explicitly requested next save.
pub const Editor = struct {
    binding: mailbox.DocumentBinding = .{},
    client: ?Client = null,
    queued: [protocol.MAX_DOCUMENT_BYTES]u8 = undefined,
    queued_length: u16 = 0,
    has_queued: bool = false,
    transport_failed: bool = false,
    opened: bool = false,

    fn bind(self: *Editor, binding: mailbox.DocumentBinding, surface: *State) void {
        if (std.meta.eql(self.binding, binding)) return;
        self.binding = binding;
        self.has_queued = false;
        self.transport_failed = false;
        self.opened = false;
        if (binding.isValid() and surface.flags.dirty) {
            self.client = null;
            self.transport_failed = true;
            surface.failDocumentLoad();
            return;
        }
        self.client = if (binding.isValid()) .{
            .service_endpoint_id = binding.service_endpoint_id,
            .object_id = binding.object_id,
            .version_id = binding.version_id,
        } else null;
        if (self.client) |*client| {
            client.open() catch unreachable;
            surface.beginDocumentLoad();
        } else if (surface.flags.loading or surface.flags.load_failed) {
            surface.flags.loading = false;
            surface.flags.load_failed = false;
            surface.revision +|= 1;
        }
    }

    pub fn canEdit(self: *Editor, binding: mailbox.DocumentBinding, surface: *State) bool {
        if (surface.model != .notes) return true;
        self.bind(binding, surface);
        return !binding.isValid() or self.opened;
    }

    // Called while processing Ctrl+Enter, before later input can change text.
    pub fn requestSave(self: *Editor, binding: mailbox.DocumentBinding, surface: *State) void {
        if (surface.model != .notes) return;
        self.bind(binding, surface);
        if (!self.opened or !surface.flags.dirty or self.transport_failed) return;
        const client = if (self.client) |*value| value else return;
        if (client.phase == .failed) return;
        if (client.phase == .idle) {
            client.start(surface.textSlice()) catch return;
            return;
        }
        // Coalesce explicit saves while keeping subsequent unsaved typing out
        // of the queued snapshot. A repeated save also retries a lost receipt.
        self.has_queued = !std.mem.eql(u8, surface.textSlice(), client.snapshot[0..client.length]);
        if (self.has_queued) {
            self.queued_length = surface.text_length;
            @memcpy(self.queued[0..self.queued_length], surface.textSlice());
        }
        _ = client.retry();
    }

    // The transport owns capability/syscall validation. Return true only when
    // bounded transport work remains; awaiting a receipt is an event wait.
    pub fn step(self: *Editor, binding: mailbox.DocumentBinding, surface: *State, transport: anytype) bool {
        if (surface.model != .notes) return false;
        self.bind(binding, surface);
        if (self.transport_failed) return false;
        const client = if (self.client) |*value| value else return false;
        var received: usize = 0;
        while (received < FRAMES_PER_DISPATCH) : (received += 1) {
            const reply = switch (transport.receive(binding.endpoint_capability_id)) {
                .empty => break,
                .failed => {
                    self.transport_failed = true;
                    if (!self.opened) surface.failDocumentLoad();
                    return false;
                },
                .reply => |reply| reply,
            };
            if (reply.length > reply.bytes.len) continue;
            if (!client.accept(reply.sender_endpoint_id, reply.correlation_id, reply.bytes[0..reply.length])) continue;
            if (client.finishOpen()) |text| {
                if (!surface.loadDocument(text)) {
                    self.transport_failed = true;
                    surface.failDocumentLoad();
                    return false;
                }
                self.opened = true;
                // Input queued during opening must be drained on the next turn.
                return true;
            }
            if (!self.opened and client.phase == .failed) surface.failDocumentLoad();
            if (client.acknowledgedText()) |text| {
                if (self.has_queued) {
                    client.start(self.queued[0..self.queued_length]) catch return false;
                    self.has_queued = false;
                } else {
                    _ = surface.acknowledgeSavedText(text);
                }
            }
        }
        var sent: usize = 0;
        var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        while (sent < FRAMES_PER_DISPATCH) : (sent += 1) {
            const frame = (client.nextFrame(&bytes) catch {
                self.transport_failed = true;
                if (!self.opened) surface.failDocumentLoad();
                return false;
            }) orelse break;
            switch (transport.send(binding.endpoint_capability_id, client.request_id, frame)) {
                .sent => client.sent(),
                .busy => return true,
                .failed => {
                    self.transport_failed = true;
                    if (!self.opened) surface.failDocumentLoad();
                    return false;
                },
            }
        }
        return received == FRAMES_PER_DISPATCH or switch (client.phase) {
            .reading, .begin, .chunks, .commit => true,
            else => false,
        };
    }
};

comptime {
    if (@sizeOf(Editor) > 1280) @compileError("document editor exceeds its bounded state");
}

const test_binding = mailbox.DocumentBinding{ .endpoint_capability_id = 10, .service_endpoint_id = 11, .object_id = 12, .version_id = 13 };

const TestTransport = struct {
    result: SendResult = .sent,
    pending: ?Reply = null,
    failure: bool = false,
    sends: usize = 0,
    receives: usize = 0,
    last_frame: [protocol.MAX_FRAME_BYTES]u8 = undefined,
    last_length: usize = 0,

    pub fn send(self: *@This(), _: u64, _: u64, bytes: []const u8) SendResult {
        self.sends += 1;
        @memcpy(self.last_frame[0..bytes.len], bytes);
        self.last_length = bytes.len;
        return self.result;
    }

    pub fn receive(self: *@This(), _: u64) ReceiveResult {
        self.receives += 1;
        if (self.failure) return .failed;
        const reply = self.pending orelse return .empty;
        self.pending = null;
        return .{ .reply = reply };
    }

    fn acknowledge(self: *@This(), editor: *const Editor) !void {
        const client = editor.client.?;
        try self.respond(editor, .{ .receipt = .{
            .status = .saved,
            .object_id = client.object_id,
            .previous_version_id = client.version_id,
            .version_id = client.version_id + 1,
            .checkpoint_generation = 1,
        } });
    }

    fn respond(self: *@This(), editor: *const Editor, body: protocol.Body) !void {
        const client = editor.client.?;
        var reply = Reply{ .sender_endpoint_id = client.service_endpoint_id, .correlation_id = client.request_id, .length = 0, .bytes = undefined };
        const bytes = try protocol.encode(&reply.bytes, .{ .request_id = client.request_id, .body = body });
        reply.length = @intCast(bytes.len);
        self.pending = reply;
    }
};

fn openTestEditor(editor: *Editor, surface: *State, transport: *TestTransport) !void {
    try std.testing.expect(!editor.canEdit(test_binding, surface));
    try std.testing.expect(!editor.step(test_binding, surface, transport));
    try transport.respond(editor, .{ .read_data = .{ .version_id = test_binding.version_id, .total_length = 0, .offset = 0, .bytes = "" } });
    try std.testing.expect(editor.step(test_binding, surface, transport));
    try std.testing.expect(editor.canEdit(test_binding, surface));
    transport.sends = 0;
    transport.receives = 0;
}

fn setTestText(surface: *State, text: []const u8) void {
    @memcpy(surface.text[0..text.len], text);
    surface.text_length = @intCast(text.len);
    surface.cursor = surface.text_length;
    surface.flags.dirty = true;
    surface.revision += 1;
}

test "document editor bounds dispatches retains backpressured frames and parks awaiting receipts" {
    var editor = Editor{};
    var surface = State.init("app.notes");
    var transport = TestTransport{};
    try openTestEditor(&editor, &surface, &transport);
    const full = [_]u8{'x'} ** protocol.MAX_DOCUMENT_BYTES;
    setTestText(&surface, &full);
    editor.requestSave(test_binding, &surface);
    transport.result = .busy;
    try std.testing.expect(editor.step(test_binding, &surface, &transport));
    try std.testing.expectEqual(.begin, editor.client.?.phase);
    const blocked = transport.last_frame;
    const blocked_length = transport.last_length;
    try std.testing.expect(editor.step(test_binding, &surface, &transport));
    try std.testing.expectEqualSlices(u8, blocked[0..blocked_length], transport.last_frame[0..transport.last_length]);
    transport.result = .sent;
    for (0..8) |_| {
        const before_sends = transport.sends;
        const before_receives = transport.receives;
        const runnable = editor.step(test_binding, &surface, &transport);
        try std.testing.expect(transport.sends - before_sends <= FRAMES_PER_DISPATCH);
        try std.testing.expect(transport.receives - before_receives <= FRAMES_PER_DISPATCH);
        if (!runnable) break;
    }
    try std.testing.expectEqual(.awaiting_receipt, editor.client.?.phase);
    try std.testing.expect(surface.flags.dirty);
    try std.testing.expect(!editor.step(test_binding, &surface, &transport));
    try transport.acknowledge(&editor);
    try std.testing.expect(!editor.step(test_binding, &surface, &transport));
    try std.testing.expectEqual(.idle, editor.client.?.phase);
    try std.testing.expect(!surface.flags.dirty);
}

test "document editor queues only explicit save snapshots and keeps later typing dirty" {
    var editor = Editor{};
    var surface = State.init("app.notes");
    var transport = TestTransport{};
    try openTestEditor(&editor, &surface, &transport);
    setTestText(&surface, "first");
    editor.requestSave(test_binding, &surface);
    _ = editor.step(test_binding, &surface, &transport);
    _ = editor.step(test_binding, &surface, &transport);
    setTestText(&surface, "second");
    editor.requestSave(test_binding, &surface);
    setTestText(&surface, "third");
    editor.requestSave(test_binding, &surface);
    setTestText(&surface, "later unsaved typing");
    try transport.acknowledge(&editor);
    _ = editor.step(test_binding, &surface, &transport);
    try std.testing.expectEqualStrings("third", editor.client.?.snapshot[0..editor.client.?.length]);
    try std.testing.expectEqual(@as(u64, 3), editor.client.?.request_id);
    _ = editor.step(test_binding, &surface, &transport);
    try transport.acknowledge(&editor);
    try std.testing.expect(!editor.step(test_binding, &surface, &transport));
    try std.testing.expectEqual(.idle, editor.client.?.phase);
    try std.testing.expect(surface.flags.dirty);
    try std.testing.expectEqualStrings("later unsaved typing", surface.textSlice());
}

test "document editor does not clear a reverted draft while a different save is queued" {
    var editor = Editor{};
    var surface = State.init("app.notes");
    var transport = TestTransport{};
    try openTestEditor(&editor, &surface, &transport);
    setTestText(&surface, "first");
    editor.requestSave(test_binding, &surface);
    _ = editor.step(test_binding, &surface, &transport);
    _ = editor.step(test_binding, &surface, &transport);
    setTestText(&surface, "second");
    editor.requestSave(test_binding, &surface);
    setTestText(&surface, "first");
    try transport.acknowledge(&editor);
    _ = editor.step(test_binding, &surface, &transport);
    try std.testing.expect(surface.flags.dirty);
    _ = editor.step(test_binding, &surface, &transport);
    try transport.acknowledge(&editor);
    _ = editor.step(test_binding, &surface, &transport);
    try std.testing.expect(surface.flags.dirty);
    try std.testing.expectEqualStrings("first", surface.textSlice());
}

test "document editor parks unavailable channels without consuming unsaved text" {
    var editor = Editor{};
    var surface = State.init("app.notes");
    var transport = TestTransport{};
    editor.requestSave(.{}, &surface);
    try std.testing.expect(!editor.step(.{}, &surface, &transport));
    try std.testing.expectEqual(@as(usize, 0), transport.sends);
    try openTestEditor(&editor, &surface, &transport);
    setTestText(&surface, "draft");
    editor.requestSave(test_binding, &surface);
    transport.result = .failed;
    try std.testing.expect(!editor.step(test_binding, &surface, &transport));
    try std.testing.expect(editor.transport_failed);
    const count = transport.sends;
    try std.testing.expect(!editor.step(test_binding, &surface, &transport));
    try std.testing.expectEqual(count, transport.sends);
    try std.testing.expect(surface.flags.dirty);
    var replacement = test_binding;
    replacement.endpoint_capability_id += 1;
    replacement.service_endpoint_id += 1;
    transport.result = .sent;
    editor.requestSave(replacement, &surface);
    transport.failure = true;
    try std.testing.expect(!editor.step(replacement, &surface, &transport));
    try std.testing.expect(editor.transport_failed);
    try std.testing.expectEqual(count, transport.sends);
    try std.testing.expectEqualStrings("draft", surface.textSlice());
}

test "document editor publishes a complete load before allowing queued input" {
    var editor = Editor{};
    var surface = State.init("app.notes");
    var transport = TestTransport{};
    const text = [_]u8{'x'} ** 80;
    try std.testing.expect(!editor.canEdit(test_binding, &surface));
    try std.testing.expect(surface.flags.loading);
    try std.testing.expect(!editor.step(test_binding, &surface, &transport));
    try transport.respond(&editor, .{ .read_data = .{ .version_id = test_binding.version_id, .total_length = text.len, .offset = 0, .bytes = text[0..protocol.READ_CHUNK_BYTES] } });
    try std.testing.expect(!editor.step(test_binding, &surface, &transport));
    try std.testing.expectEqualStrings("", surface.textSlice());
    try std.testing.expect(!editor.canEdit(test_binding, &surface));
    try transport.respond(&editor, .{ .read_data = .{ .version_id = test_binding.version_id, .total_length = text.len, .offset = protocol.READ_CHUNK_BYTES, .bytes = text[protocol.READ_CHUNK_BYTES..] } });
    try std.testing.expect(editor.step(test_binding, &surface, &transport));
    try std.testing.expect(editor.canEdit(test_binding, &surface));
    try std.testing.expectEqualStrings(&text, surface.textSlice());
    try std.testing.expect(!surface.flags.loading);
    try std.testing.expect(!surface.flags.dirty);
}

test "document editor refuses opening over a draft and reports failed loads" {
    var editor = Editor{};
    var surface = State.init("app.notes");
    var transport = TestTransport{};
    setTestText(&surface, "unsaved draft");
    try std.testing.expect(!editor.canEdit(test_binding, &surface));
    try std.testing.expect(surface.flags.load_failed);
    try std.testing.expect(!editor.step(test_binding, &surface, &transport));
    try std.testing.expectEqualStrings("unsaved draft", surface.textSlice());
    try std.testing.expectEqual(@as(usize, 0), transport.sends);

    for ([_]bool{ false, true }) |unsupported_text| {
        editor = .{};
        surface = State.init("app.notes");
        _ = editor.canEdit(test_binding, &surface);
        _ = editor.step(test_binding, &surface, &transport);
        if (unsupported_text) {
            try transport.respond(&editor, .{ .read_data = .{ .version_id = test_binding.version_id, .total_length = 1, .offset = 0, .bytes = "\xff" } });
        } else {
            try transport.respond(&editor, .{ .receipt = .{ .status = .permission_denied } });
        }
        try std.testing.expect(!editor.step(test_binding, &surface, &transport));
        try std.testing.expect(surface.flags.load_failed);
        try std.testing.expect(!surface.flags.loading);
        try std.testing.expect(!editor.canEdit(test_binding, &surface));
        try std.testing.expectEqualStrings("", surface.textSlice());
    }
}
