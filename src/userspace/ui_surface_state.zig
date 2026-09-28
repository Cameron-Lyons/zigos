const std = @import("std");
const abi = @import("native_abi");
const mailbox = @import("userspace_bootstrap_mailbox");
const edit_history = @import("edit_history.zig");

pub const TEXT_CAPACITY: usize = 512;
const INTERACTION_HASH_SEED: u64 = 0xcbf29ce484222325;
const INTERACTION_HASH_PRIME: u64 = 0x100000001b3;
const NO_VERTICAL_COLUMN = std.math.maxInt(u16);

pub const ApplyResult = enum(u8) {
    rejected,
    observed,
    mutated,
};

pub const State = struct {
    window_id: u64 = 0,
    model: mailbox.UiModelKind = .none,
    flags: mailbox.UiStateFlags = .{},
    focus_index: u16 = 0,
    text: [TEXT_CAPACITY]u8 = [_]u8{0} ** TEXT_CAPACITY,
    text_length: u16 = 0,
    cursor: u16 = 0,
    selection_anchor: u16 = 0,
    vertical_column: u16 = NO_VERTICAL_COLUMN,
    save_state: abi.DocumentSaveState = .none,
    commit_count: u32 = 0,
    activation_count: u32 = 0,
    revision: u64 = 0,
    interaction_hash: u64 = 0,
    last_sequence: u64 = 0,
    history: edit_history.History = .{},

    pub fn init(comptime bundle_id: []const u8) State {
        const model = modelForBundle(bundle_id);
        return .{
            .model = model,
            .revision = 1,
            .interaction_hash = mixByte(INTERACTION_HASH_SEED, @intFromEnum(model)),
        };
    }

    pub fn textSlice(self: *const State) []const u8 {
        return self.text[0..self.text_length];
    }

    pub fn presentation(self: *const State, surface_id: u64) abi.SurfacePresentation {
        var out = std.mem.zeroes(abi.SurfacePresentation);
        out.surface_id = surface_id;
        out.revision = self.revision;
        out.buffer_object_id = surface_id;
        out.buffer_offset = 0;
        out.buffer_bytes = TEXT_CAPACITY;
        return out;
    }

    pub fn presentationText(self: *const State) abi.SurfaceText {
        var out = abi.SurfaceText{
            .window_id = self.window_id,
            .text_length = self.text_length,
            .cursor = self.cursor,
            .state = .{
                .selection_anchor = @intCast(self.selection_anchor),
                .focus_index = @intCast(self.focus_index),
                .model = @intCast(@intFromEnum(self.model)),
                .flags = @bitCast(self.flags),
                .save_state = @intCast(@intFromEnum(self.save_state)),
            },
        };
        @memcpy(out.text[0..self.text_length], self.textSlice());
        return out;
    }

    pub fn apply(self: *State, event: abi.InputEventDescriptor) ApplyResult {
        if (event.sequence == 0 or event.sequence <= self.last_sequence) return .rejected;
        if (event.length < 1 or event.length > event.bytes.len) return .rejected;
        const op = event.bytes[0];
        const data = if (event.length > 1) event.bytes[1] else 0;
        if (op == abi.InputByte.text and (data < 0x20 or data > 0x7e)) return .rejected;
        const navigation = op >= abi.InputByte.cursor_left and op <= abi.InputByte.document_end;
        if (navigation) {
            if (data & ~abi.INPUT_EXTEND_SELECTION != 0) return .rejected;
        } else if (op != abi.InputByte.text and data != 0) return .rejected;
        const extend = navigation and data & abi.INPUT_EXTEND_SELECTION != 0;
        switch (op) {
            abi.InputByte.text,
            abi.InputByte.backspace,
            abi.InputByte.commit_text,
            abi.InputByte.focus_next,
            abi.InputByte.focus_previous,
            abi.InputByte.activate,
            abi.InputByte.show_recovery,
            abi.InputByte.dismiss_recovery,
            abi.InputByte.task_switch_next,
            abi.InputByte.task_switch_previous,
            abi.InputByte.cursor_left,
            abi.InputByte.cursor_right,
            abi.InputByte.cursor_up,
            abi.InputByte.cursor_down,
            abi.InputByte.line_start,
            abi.InputByte.line_end,
            abi.InputByte.document_start,
            abi.InputByte.document_end,
            abi.InputByte.delete_forward,
            abi.InputByte.select_all,
            abi.InputByte.undo,
            abi.InputByte.redo,
            abi.InputByte.copy,
            abi.InputByte.cut,
            abi.InputByte.paste,
            => {},
            else => return .rejected,
        }

        self.last_sequence = event.sequence;
        self.interaction_hash = mixEvent(self.interaction_hash, event);
        if (op != abi.InputByte.text) self.history.breakGroup();
        const mutated = switch (op) {
            abi.InputByte.text => self.insertText(data),
            abi.InputByte.backspace => self.backspace(),
            abi.InputByte.delete_forward => if (self.model == .notes) self.deleteForward() else false,
            abi.InputByte.cursor_left => self.moveCursor(if (!extend and self.hasSelection()) self.selectionStart() else self.cursor -| 1, false, extend),
            abi.InputByte.cursor_right => self.moveCursor(if (!extend and self.hasSelection()) self.selectionEnd() else @min(self.text_length, self.cursor + 1), false, extend),
            abi.InputByte.cursor_up => self.moveVertical(false, extend),
            abi.InputByte.cursor_down => self.moveVertical(true, extend),
            abi.InputByte.line_start => self.moveCursor(self.lineStart(self.cursor), false, extend),
            abi.InputByte.line_end => self.moveCursor(self.lineEnd(self.cursor), false, extend),
            abi.InputByte.document_start => self.moveCursor(0, false, extend),
            abi.InputByte.document_end => self.moveCursor(self.text_length, false, extend),
            abi.InputByte.select_all => self.selectAll(),
            abi.InputByte.undo => self.restoreEdit(false),
            abi.InputByte.redo => self.restoreEdit(true),
            abi.InputByte.copy, abi.InputByte.cut, abi.InputByte.paste => false,
            abi.InputByte.commit_text => self.commit(),
            abi.InputByte.focus_next => self.moveFocus(true),
            abi.InputByte.focus_previous => self.moveFocus(false),
            abi.InputByte.activate => self.activate(),
            abi.InputByte.show_recovery => self.setRecoveryVisible(true),
            abi.InputByte.dismiss_recovery => self.setRecoveryVisible(false),
            abi.InputByte.task_switch_next, abi.InputByte.task_switch_previous => false,
            else => unreachable,
        };
        if (!mutated) return .observed;
        self.revision +|= 1;
        return .mutated;
    }

    fn insertText(self: *State, byte: u8) bool {
        const start = self.selectionStart();
        const end = self.selectionEnd();
        const new_length = self.text_length - (end - start) + 1;
        if (new_length > self.text.len) return self.noteOverflow();
        if (self.model == .notes) {
            self.history.remember(@intCast(start), self.text[start..end], &.{byte}, self.cursor, self.selection_anchor, byte != '\n');
            if (byte == ' ' or byte == '\n') self.history.breakGroup();
        }
        if (end == start) {
            std.mem.copyBackwards(u8, self.text[start + 1 .. new_length], self.text[end..self.text_length]);
        } else {
            std.mem.copyForwards(u8, self.text[start + 1 .. new_length], self.text[end..self.text_length]);
            @memset(self.text[new_length..self.text_length], 0);
        }
        self.text[start] = byte;
        self.text_length = @intCast(new_length);
        self.cursor = @intCast(start + 1);
        self.selection_anchor = self.cursor;
        self.edited();
        return true;
    }

    fn backspace(self: *State) bool {
        if (self.hasSelection()) return self.eraseRange(self.selectionStart(), self.selectionEnd());
        if (self.cursor == 0) return false;
        return self.eraseRange(self.cursor - 1, self.cursor);
    }

    fn deleteForward(self: *State) bool {
        if (self.hasSelection()) return self.eraseRange(self.selectionStart(), self.selectionEnd());
        if (self.cursor == self.text_length) return false;
        return self.eraseRange(self.cursor, self.cursor + 1);
    }

    fn eraseRange(self: *State, start: usize, end: usize) bool {
        if (self.model == .notes) self.history.remember(@intCast(start), self.text[start..end], "", self.cursor, self.selection_anchor, false);
        const new_length = self.text_length - (end - start);
        std.mem.copyForwards(u8, self.text[start..new_length], self.text[end..self.text_length]);
        @memset(self.text[new_length..self.text_length], 0);
        self.text_length = @intCast(new_length);
        self.cursor = @intCast(start);
        self.selection_anchor = self.cursor;
        self.edited();
        return true;
    }

    fn restoreEdit(self: *State, redo: bool) bool {
        if (self.model != .notes) return false;
        const change = (if (redo) self.history.redo() else self.history.undo()) orelse return false;
        const end = change.position + change.remove_length;
        const new_end = change.position + change.insert.len;
        const new_length = self.text_length - change.remove_length + change.insert.len;
        if (new_end > end) {
            std.mem.copyBackwards(u8, self.text[new_end..new_length], self.text[end..self.text_length]);
        } else {
            std.mem.copyForwards(u8, self.text[new_end..new_length], self.text[end..self.text_length]);
            @memset(self.text[new_length..self.text_length], 0);
        }
        @memcpy(self.text[change.position..new_end], change.insert);
        self.text_length = @intCast(new_length);
        self.cursor = change.cursor;
        self.selection_anchor = change.anchor;
        self.vertical_column = NO_VERTICAL_COLUMN;
        self.flags.input_overflow = false;
        self.flags.dirty = !self.history.isSaved() or self.save_state == .saving or self.save_state == .retryable;
        if (!self.flags.dirty) {
            self.save_state = if (self.history.saved_feedback) .saved else .none;
        } else if (self.save_state == .saved) self.save_state = .none;
        return true;
    }

    pub fn contentRevision(self: *const State) ?u64 {
        return self.history.revision();
    }

    pub fn selectionSlice(self: *const State) []const u8 {
        return self.text[self.selectionStart()..self.selectionEnd()];
    }

    // Clipboard bytes are staged outside the document. Publish one edit only
    // after the complete transfer succeeds, retaining the draft on overflow.
    pub fn replaceSelection(self: *State, bytes: []const u8) bool {
        if (self.model != .notes or !@import("clipboard_protocol.zig").validText(bytes)) return false;
        const start = self.selectionStart();
        const end = self.selectionEnd();
        const remaining = self.text_length - (end - start);
        if (bytes.len > self.text.len - remaining) {
            if (self.noteOverflow()) self.revision +|= 1;
            return false;
        }
        if (start == end and bytes.len == 0) return true;
        const new_end = start + bytes.len;
        const new_length = remaining + bytes.len;
        self.history.remember(@intCast(start), self.text[start..end], bytes, self.cursor, self.selection_anchor, false);
        if (new_end > end) {
            std.mem.copyBackwards(u8, self.text[new_end..new_length], self.text[end..self.text_length]);
        } else {
            std.mem.copyForwards(u8, self.text[new_end..new_length], self.text[end..self.text_length]);
            @memset(self.text[new_length..self.text_length], 0);
        }
        @memcpy(self.text[start..new_end], bytes);
        self.text_length = @intCast(new_length);
        self.cursor = @intCast(new_end);
        self.selection_anchor = self.cursor;
        self.edited();
        self.revision +|= 1;
        return true;
    }

    fn edited(self: *State) void {
        self.flags.clipboard_failed = false;
        self.vertical_column = NO_VERTICAL_COLUMN;
        self.flags.dirty = true;
        self.flags.input_overflow = false;
        if (self.save_state == .saved) self.save_state = .none;
    }

    fn lineStart(self: *const State, position: usize) usize {
        var at = position;
        while (at > 0 and self.text[at - 1] != '\n') : (at -= 1) {}
        return at;
    }

    fn lineEnd(self: *const State, position: usize) usize {
        var at = position;
        while (at < self.text_length and self.text[at] != '\n') : (at += 1) {}
        return at;
    }

    fn hasSelection(self: *const State) bool {
        return self.cursor != self.selection_anchor;
    }

    fn selectionStart(self: *const State) usize {
        return @min(self.cursor, self.selection_anchor);
    }

    fn selectionEnd(self: *const State) usize {
        return @max(self.cursor, self.selection_anchor);
    }

    fn selectAll(self: *State) bool {
        if (self.model != .notes) return false;
        const changed = self.selection_anchor != 0 or self.cursor != self.text_length;
        self.selection_anchor = 0;
        self.cursor = self.text_length;
        self.vertical_column = NO_VERTICAL_COLUMN;
        return changed;
    }

    fn moveCursor(self: *State, position: usize, vertical: bool, extend: bool) bool {
        if (self.model != .notes) return false;
        if (!vertical) self.vertical_column = NO_VERTICAL_COLUMN;
        const changed = self.cursor != position or (!extend and self.hasSelection());
        self.cursor = @intCast(position);
        if (!extend) self.selection_anchor = self.cursor;
        return changed;
    }

    fn moveVertical(self: *State, down: bool, extend: bool) bool {
        if (self.model != .notes) return false;
        const start = self.lineStart(self.cursor);
        const end = self.lineEnd(self.cursor);
        if ((down and end == self.text_length) or (!down and start == 0)) return self.moveCursor(self.cursor, true, extend);
        if (self.vertical_column == NO_VERTICAL_COLUMN) self.vertical_column = @intCast(self.cursor - start);
        const target_start = if (down) end + 1 else self.lineStart(start - 1);
        const target_end = if (down) self.lineEnd(target_start) else start - 1;
        return self.moveCursor(@min(target_start + self.vertical_column, target_end), true, extend);
    }

    fn commit(self: *State) bool {
        self.commit_count +|= 1;
        // This requests a save. Only a durable storage acknowledgement may
        // clear dirty state; surface presentation is not a persistence receipt.
        return true;
    }

    pub fn acknowledgeSavedText(self: *State, saved_text: []const u8, saved_revision: ?u64) bool {
        if (self.model != .notes) return false;
        const matches = std.mem.eql(u8, self.textSlice(), saved_text);
        self.history.markSaved(if (matches) self.contentRevision() else saved_revision);
        const save_state: abi.DocumentSaveState = if (matches) .saved else .none;
        if (self.flags.dirty == matches or self.save_state != save_state) self.revision +|= 1;
        self.flags.dirty = !matches;
        self.save_state = save_state;
        return matches;
    }

    pub fn setSaveState(self: *State, state: abi.DocumentSaveState) void {
        if (self.model != .notes) return;
        const pending_clean = state == .saving and !self.flags.dirty;
        if (self.save_state == state and !pending_clean) return;
        if (pending_clean) self.flags.dirty = true;
        self.save_state = state;
        self.revision +|= 1;
    }

    pub fn beginDocumentLoad(self: *State) void {
        self.save_state = .none;
        self.flags.loading = true;
        self.flags.load_failed = false;
        self.revision +|= 1;
    }

    pub fn failDocumentLoad(self: *State) void {
        if (self.flags.load_failed) return;
        self.flags.loading = false;
        self.flags.load_failed = true;
        self.revision +|= 1;
    }

    pub fn loadDocument(self: *State, text: []const u8) bool {
        if (self.model != .notes or self.flags.dirty or text.len > self.text.len) return false;
        // The current text presentation accepts printable ASCII and newlines.
        // Refuse unsupported content without truncating or changing its bytes.
        for (text) |byte| if (byte != '\n' and (byte < 0x20 or byte > 0x7e)) return false;
        @memset(&self.text, 0);
        @memcpy(self.text[0..text.len], text);
        self.text_length = @intCast(text.len);
        self.cursor = self.text_length;
        self.vertical_column = NO_VERTICAL_COLUMN;
        self.selection_anchor = self.cursor;
        self.history = .{};
        self.flags.loading = false;
        self.flags.load_failed = false;
        self.flags.input_overflow = false;
        self.save_state = .none;
        self.revision +|= 1;
        return true;
    }

    fn moveFocus(self: *State, forward: bool) bool {
        const count = focusableControlCount(self.model);
        if (count <= 1) return false;
        self.focus_index = if (forward)
            (self.focus_index + 1) % count
        else if (self.focus_index == 0)
            count - 1
        else
            self.focus_index - 1;
        return true;
    }

    fn activate(self: *State) bool {
        self.activation_count +|= 1;
        switch (self.model) {
            .notes => _ = self.insertText('\n'),
            .capture => self.flags.active = !self.flags.active,
            else => {},
        }
        return true;
    }

    fn setRecoveryVisible(self: *State, visible: bool) bool {
        if (self.flags.recovery_visible == visible) return false;
        self.flags.recovery_visible = visible;
        return true;
    }

    fn noteOverflow(self: *State) bool {
        if (self.flags.input_overflow) return false;
        self.flags.input_overflow = true;
        return true;
    }
};

pub fn modelForBundle(comptime bundle_id: []const u8) mailbox.UiModelKind {
    if (std.mem.startsWith(u8, bundle_id, "app.notes")) return .notes;
    if (std.mem.eql(u8, bundle_id, "app.viewer")) return .viewer;
    if (std.mem.eql(u8, bundle_id, "app.capture")) return .capture;
    if (std.mem.eql(u8, bundle_id, "zigos.system.permission-review")) return .permission_review;
    if (std.mem.eql(u8, bundle_id, "zigos.system.compositor") or
        std.mem.eql(u8, bundle_id, "zigos.system.display") or
        std.mem.eql(u8, bundle_id, "zigos.system.drivers")) return .compositor;
    return .generic;
}

fn focusableControlCount(model: mailbox.UiModelKind) u16 {
    return switch (model) {
        .notes => 3,
        .viewer => 2,
        .capture => 4,
        .permission_review => 3,
        .compositor => 2,
        .none, .generic => 1,
    };
}

fn mixEvent(initial: u64, event: abi.InputEventDescriptor) u64 {
    var hash = mixByte(initial, if (event.length > 0) event.bytes[0] else 0);
    hash = mixByte(hash, if (event.length > 1) event.bytes[1] else 0);
    var sequence = event.sequence;
    for (0..@sizeOf(u64)) |_| {
        hash = mixByte(hash, @truncate(sequence));
        sequence >>= 8;
    }
    return hash;
}

fn mixByte(hash: u64, byte: u8) u64 {
    return (hash ^ byte) *% INTERACTION_HASH_PRIME;
}

fn inputEvent(sequence: u64, op: u8, data: u8) abi.InputEventDescriptor {
    return .{
        .sequence = sequence,
        .tick = sequence,
        .window_id = 1,
        .task_id = 2,
        .surface_id = 3,
        .port_id = 4,
        .slot_id = 5,
        .length = 2,
        .bytes = abi.inputPacket(op, data),
    };
}

test "UI surface state selects application-specific fixed-capacity models" {
    try std.testing.expectEqual(mailbox.UiModelKind.notes, modelForBundle("app.notes"));
    try std.testing.expectEqual(mailbox.UiModelKind.notes, modelForBundle("app.notes.daily"));
    try std.testing.expectEqual(mailbox.UiModelKind.viewer, modelForBundle("app.viewer"));
    try std.testing.expectEqual(mailbox.UiModelKind.capture, modelForBundle("app.capture"));
    try std.testing.expectEqual(mailbox.UiModelKind.permission_review, modelForBundle("zigos.system.permission-review"));
    try std.testing.expectEqual(mailbox.UiModelKind.compositor, modelForBundle("zigos.system.compositor"));
    try std.testing.expectEqual(mailbox.UiModelKind.compositor, modelForBundle("zigos.system.drivers"));
    try std.testing.expectEqual(mailbox.UiModelKind.generic, modelForBundle("app.unknown"));
}

test "Notes edits invalidate saved feedback while preserving in-flight and failed saves" {
    var state = State.init("app.notes");
    _ = state.apply(inputEvent(1, abi.InputByte.text, 'a'));
    try std.testing.expect(state.acknowledgeSavedText("a", state.contentRevision()));
    try std.testing.expectEqual(abi.DocumentSaveState.saved, state.save_state);
    _ = state.apply(inputEvent(2, abi.InputByte.text, 'b'));
    try std.testing.expectEqual(abi.DocumentSaveState.none, state.save_state);
    state.setSaveState(.saving);
    _ = state.apply(inputEvent(3, abi.InputByte.backspace, 0));
    try std.testing.expectEqual(abi.DocumentSaveState.saving, state.save_state);
    state.setSaveState(.permission_denied);
    _ = state.apply(inputEvent(4, abi.InputByte.text, 'c'));
    try std.testing.expectEqual(abi.DocumentSaveState.permission_denied, state.save_state);
    const presentation = state.presentationText();
    try std.testing.expect(presentation.isCanonical());
    try std.testing.expectEqual(@intFromEnum(abi.DocumentSaveState.permission_denied), presentation.state.save_state);
    try std.testing.expect(state.acknowledgeSavedText("ac", state.contentRevision()));
    _ = state.apply(inputEvent(5, abi.InputByte.backspace, 0));
    try std.testing.expectEqual(abi.DocumentSaveState.none, state.save_state);
}

test "Notes accepts durable receipts without clearing edits made during a save" {
    const document_client = @import("document_client.zig");
    const protocol = @import("document_protocol.zig");
    var state = State.init("app.notes");
    _ = state.apply(inputEvent(1, abi.InputByte.text, 'a'));
    var client = document_client.Client{ .service_endpoint_id = 12, .object_id = 20, .version_id = 30 };
    try client.start(state.textSlice());
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const first = (try client.nextFrame(&bytes)).?;
    var retry_bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    try std.testing.expectEqualSlices(u8, first, (try client.nextFrame(&retry_bytes)).?);
    while (try client.nextFrame(&bytes) != null) client.sent();
    _ = state.apply(inputEvent(2, abi.InputByte.text, 'b'));
    const saved = try protocol.encode(&bytes, .{ .request_id = 1, .body = .{ .receipt = .{
        .status = .saved,
        .object_id = 20,
        .previous_version_id = 30,
        .version_id = 31,
        .checkpoint_generation = 7,
    } } });
    try std.testing.expect(!client.accept(99, 1, saved));
    try std.testing.expect(!client.accept(12, 2, saved));
    try std.testing.expect(client.accept(12, 1, saved));
    try std.testing.expect(!state.acknowledgeSavedText(client.acknowledgedText().?, null));
    try std.testing.expect(state.flags.dirty);
    try client.start(state.textSlice());
    try std.testing.expect(!client.accept(12, 1, saved));
    while (try client.nextFrame(&bytes) != null) client.sent();
    const latest = try protocol.encode(&bytes, .{ .request_id = 2, .body = .{ .receipt = .{
        .status = .saved,
        .object_id = 20,
        .previous_version_id = 31,
        .version_id = 32,
        .checkpoint_generation = 8,
    } } });
    try std.testing.expect(client.accept(12, 2, latest));
    try std.testing.expect(state.acknowledgeSavedText(client.acknowledgedText().?, null));
    try std.testing.expect(!state.flags.dirty);
    try std.testing.expectEqualStrings("ab", state.textSlice());
}

test "UI surface state serializes a canonical bounded presentation" {
    var state = State.init("app.notes");
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(1, abi.InputByte.text, 'x')));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(2, abi.InputByte.activate, 0)));

    const presentation = state.presentation(91);
    try std.testing.expect(abi.isCanonicalSurfacePresentation(&presentation));
    try std.testing.expect(presentation.presentsByHandle());
    try std.testing.expectEqual(@as(u64, 91), presentation.surface_id);
    try std.testing.expectEqual(@as(u64, 91), presentation.buffer_object_id);
    try std.testing.expectEqual(state.revision, presentation.revision);
    try std.testing.expectEqual(@as(u32, TEXT_CAPACITY), presentation.buffer_bytes);
    try std.testing.expectEqualStrings("x\n", state.textSlice());
    try std.testing.expectEqual(mailbox.UiModelKind.notes, state.model);
    try std.testing.expect(state.flags.dirty);
}

test "Notes UI state requests a save without claiming durability" {
    var state = State.init("app.notes");
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(1, abi.InputByte.text, 'a')));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(2, abi.InputByte.text, 'b')));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(3, abi.InputByte.backspace, 0)));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(4, abi.InputByte.activate, 0)));
    try std.testing.expectEqualStrings("a\n", state.textSlice());
    try std.testing.expect(state.flags.dirty);
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(5, abi.InputByte.commit_text, 0)));
    try std.testing.expect(state.flags.dirty);
    try std.testing.expectEqual(@as(u32, 1), state.commit_count);
    try std.testing.expectEqual(@as(u32, 1), state.activation_count);
    try std.testing.expectEqual(@as(u64, 6), state.revision);
}

test "Notes cursor edits preserve surrounding text and navigation does not dirty a saved document" {
    var state = State.init("app.notes");
    try std.testing.expect(state.loadDocument("abc\ndef"));
    state.setSaveState(.saved);
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(1, abi.InputByte.document_start, 0)));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(2, abi.InputByte.cursor_right, 0)));
    try std.testing.expect(!state.flags.dirty);
    try std.testing.expectEqual(abi.DocumentSaveState.saved, state.save_state);
    _ = state.apply(inputEvent(3, abi.InputByte.text, 'X'));
    try std.testing.expectEqualStrings("aXbc\ndef", state.textSlice());
    try std.testing.expectEqual(@as(u16, 2), state.cursor);
    _ = state.apply(inputEvent(4, abi.InputByte.delete_forward, 0));
    _ = state.apply(inputEvent(5, abi.InputByte.backspace, 0));
    try std.testing.expectEqualStrings("ac\ndef", state.textSlice());
    _ = state.apply(inputEvent(6, abi.InputByte.line_end, 0));
    _ = state.apply(inputEvent(7, abi.InputByte.delete_forward, 0));
    try std.testing.expectEqualStrings("acdef", state.textSlice());
    _ = state.apply(inputEvent(8, abi.InputByte.activate, 0));
    try std.testing.expectEqualStrings("ac\ndef", state.textSlice());
    try std.testing.expectEqual(@as(u16, 3), state.cursor);
    try std.testing.expect(state.flags.dirty);
    try std.testing.expectEqual(abi.DocumentSaveState.none, state.save_state);
    try std.testing.expect(state.presentationText().isCanonical());
}

test "Notes undo restores replaced selections and redo returns to the saved edit" {
    var state = State.init("app.notes");
    try std.testing.expect(state.loadDocument("abc\ndef"));
    _ = state.apply(inputEvent(1, abi.InputByte.cursor_left, abi.INPUT_EXTEND_SELECTION));
    _ = state.apply(inputEvent(2, abi.InputByte.document_start, abi.INPUT_EXTEND_SELECTION));
    _ = state.apply(inputEvent(3, abi.InputByte.text, 'X'));
    try std.testing.expectEqualStrings("X", state.textSlice());
    try std.testing.expect(state.acknowledgeSavedText("X", state.contentRevision()));
    _ = state.apply(inputEvent(4, abi.InputByte.undo, 0));
    try std.testing.expectEqualStrings("abc\ndef", state.textSlice());
    try std.testing.expectEqual(@as(u16, 0), state.cursor);
    try std.testing.expectEqual(@as(u16, 7), state.selection_anchor);
    try std.testing.expect(state.flags.dirty);
    try std.testing.expectEqual(abi.DocumentSaveState.none, state.save_state);
    _ = state.apply(inputEvent(5, abi.InputByte.redo, 0));
    try std.testing.expectEqualStrings("X", state.textSlice());
    try std.testing.expect(!state.flags.dirty);
    try std.testing.expectEqual(abi.DocumentSaveState.saved, state.save_state);
    try std.testing.expect(state.presentationText().isCanonical());
}

test "Notes edit history roundtrips every short selection and both deletion directions" {
    const original = "ab\ncd";
    for (0..original.len + 1) |cursor| {
        for (0..original.len + 1) |anchor| {
            for ([_]u8{ abi.InputByte.text, abi.InputByte.activate, abi.InputByte.backspace, abi.InputByte.delete_forward }) |op| {
                var state = State.init("app.notes");
                try std.testing.expect(state.loadDocument(original));
                state.cursor = @intCast(cursor);
                state.selection_anchor = @intCast(anchor);
                const result = state.apply(inputEvent(1, op, if (op == abi.InputByte.text) 'X' else 0));
                if (result == .observed) continue;
                const changed = state.presentationText();
                _ = state.apply(inputEvent(2, abi.InputByte.undo, 0));
                try std.testing.expectEqualStrings(original, state.textSlice());
                try std.testing.expectEqual(cursor, state.cursor);
                try std.testing.expectEqual(anchor, state.selection_anchor);
                try std.testing.expect(!state.flags.dirty);
                try std.testing.expect(state.presentationText().isCanonical());
                _ = state.apply(inputEvent(3, abi.InputByte.redo, 0));
                try std.testing.expectEqualDeep(changed, state.presentationText());
            }
        }
    }
}

test "Notes groups typing and separates navigation saves and new branches" {
    var state = State.init("app.notes");
    for ("one two", 1..) |byte, sequence| _ = state.apply(inputEvent(sequence, abi.InputByte.text, byte));
    _ = state.apply(inputEvent(8, abi.InputByte.undo, 0));
    try std.testing.expectEqualStrings("one ", state.textSlice());
    _ = state.apply(inputEvent(9, abi.InputByte.undo, 0));
    try std.testing.expectEqualStrings("", state.textSlice());
    try std.testing.expect(!state.flags.dirty);
    _ = state.apply(inputEvent(10, abi.InputByte.redo, 0));
    _ = state.apply(inputEvent(11, abi.InputByte.text, 'X'));
    try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(12, abi.InputByte.redo, 0)));
    try std.testing.expectEqualStrings("one X", state.textSlice());
    try std.testing.expect(state.acknowledgeSavedText(state.textSlice(), state.contentRevision()));
    _ = state.apply(inputEvent(13, abi.InputByte.text, 'Y'));
    _ = state.apply(inputEvent(14, abi.InputByte.undo, 0));
    try std.testing.expectEqualStrings("one X", state.textSlice());
    try std.testing.expect(!state.flags.dirty);
    _ = state.apply(inputEvent(15, abi.InputByte.cursor_left, 0));
    _ = state.apply(inputEvent(16, abi.InputByte.text, 'Z'));
    _ = state.apply(inputEvent(17, abi.InputByte.undo, 0));
    try std.testing.expectEqualStrings("one X", state.textSlice());
    try std.testing.expectEqual(@as(u16, 4), state.cursor);
    try std.testing.expect(!state.flags.dirty);
}

test "Notes undo and redo preserve full documents and delete history at a new load" {
    const full = [_]u8{'a'} ** TEXT_CAPACITY;
    for ([_]u8{ abi.InputByte.text, abi.InputByte.activate, abi.InputByte.backspace, abi.InputByte.delete_forward }) |op| {
        var state = State.init("app.notes");
        try std.testing.expect(state.loadDocument(&full));
        _ = state.apply(inputEvent(1, abi.InputByte.select_all, 0));
        _ = state.apply(inputEvent(2, op, if (op == abi.InputByte.text) 'x' else 0));
        _ = state.apply(inputEvent(3, abi.InputByte.undo, 0));
        try std.testing.expectEqualStrings(&full, state.textSlice());
        try std.testing.expectEqual(@as(u16, 0), state.selection_anchor);
        try std.testing.expect(!state.flags.dirty);
        try std.testing.expect(state.presentationText().isCanonical());
        _ = state.apply(inputEvent(4, abi.InputByte.redo, 0));
        try std.testing.expectEqualStrings(switch (op) {
            abi.InputByte.text => "x",
            abi.InputByte.activate => "\n",
            else => "",
        }, state.textSlice());
        try std.testing.expect(state.presentationText().isCanonical());
        _ = state.apply(inputEvent(5, abi.InputByte.undo, 0));
        try std.testing.expect(state.loadDocument("next"));
        try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(6, abi.InputByte.redo, 0)));
        try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(7, abi.InputByte.undo, 0)));
        try std.testing.expectEqualStrings("next", state.textSlice());
        try std.testing.expect(std.mem.allEqual(u8, &state.history.bytes, 0));
    }
}

test "Notes replaces selected text without dirtying on selection or consuming surrounding bytes" {
    var state = State.init("app.notes");
    try std.testing.expect(state.loadDocument("first\nsecond"));
    state.setSaveState(.saved);
    _ = state.apply(inputEvent(1, abi.InputByte.document_start, 0));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(2, abi.InputByte.line_end, abi.INPUT_EXTEND_SELECTION)));
    try std.testing.expectEqual(@as(u16, 0), state.selection_anchor);
    try std.testing.expectEqual(@as(u16, 5), state.cursor);
    try std.testing.expect(!state.flags.dirty);
    try std.testing.expectEqual(abi.DocumentSaveState.saved, state.save_state);
    _ = state.apply(inputEvent(3, abi.InputByte.text, 'X'));
    try std.testing.expectEqualStrings("X\nsecond", state.textSlice());
    try std.testing.expectEqual(@as(u16, 1), state.cursor);
    try std.testing.expectEqual(state.cursor, state.selection_anchor);
    try std.testing.expect(state.presentationText().isCanonical());
}

test "Notes reverse selections shrink cross lines and collapse without editing" {
    var state = State.init("app.notes");
    try std.testing.expect(state.loadDocument("abc\nx\nxyz"));
    const extend = abi.INPUT_EXTEND_SELECTION;
    for ([_]u8{ abi.InputByte.cursor_up, abi.InputByte.cursor_up, abi.InputByte.cursor_down }, [_]u16{ 5, 3, 5 }, 1..) |op, position, sequence| {
        _ = state.apply(inputEvent(sequence, op, extend));
        try std.testing.expectEqual(position, state.cursor);
        try std.testing.expectEqual(@as(u16, 9), state.selection_anchor);
        try std.testing.expect(!state.flags.dirty);
    }
    _ = state.apply(inputEvent(4, abi.InputByte.cursor_right, 0));
    try std.testing.expectEqual(@as(u16, 9), state.cursor);
    try std.testing.expectEqual(state.cursor, state.selection_anchor);
    _ = state.apply(inputEvent(5, abi.InputByte.cursor_left, extend));
    _ = state.apply(inputEvent(6, abi.InputByte.cursor_left, 0));
    try std.testing.expectEqual(@as(u16, 8), state.cursor);
    try std.testing.expectEqual(state.cursor, state.selection_anchor);
    _ = state.apply(inputEvent(7, abi.InputByte.document_start, extend));
    _ = state.apply(inputEvent(8, abi.InputByte.delete_forward, 0));
    try std.testing.expectEqualStrings("z", state.textSlice());
    try std.testing.expectEqual(@as(u16, 0), state.cursor);
    try std.testing.expectEqual(state.cursor, state.selection_anchor);
    try std.testing.expect(state.presentationText().isCanonical());
}

test "Notes selection replacement works at capacity and receipts retain selection" {
    const full = [_]u8{'a'} ** TEXT_CAPACITY;
    for ([_]u8{ abi.InputByte.text, abi.InputByte.activate, abi.InputByte.backspace, abi.InputByte.delete_forward }) |op| {
        var state = State.init("app.notes");
        try std.testing.expect(state.loadDocument(&full));
        _ = state.apply(inputEvent(1, abi.InputByte.text, 'x'));
        try std.testing.expect(state.flags.input_overflow);
        _ = state.apply(inputEvent(2, abi.InputByte.select_all, 0));
        try std.testing.expectEqual(@as(u16, TEXT_CAPACITY), state.cursor);
        try std.testing.expectEqual(@as(u16, 0), state.selection_anchor);
        _ = state.apply(inputEvent(3, op, if (op == abi.InputByte.text) 'x' else 0));
        try std.testing.expectEqualStrings(switch (op) {
            abi.InputByte.text => "x",
            abi.InputByte.activate => "\n",
            else => "",
        }, state.textSlice());
        try std.testing.expect(!state.flags.input_overflow);
        try std.testing.expect(state.presentationText().isCanonical());
        _ = state.apply(inputEvent(4, abi.InputByte.select_all, 0));
        const anchor = state.selection_anchor;
        const cursor = state.cursor;
        try std.testing.expect(state.acknowledgeSavedText(state.textSlice(), state.contentRevision()));
        try std.testing.expectEqual(anchor, state.selection_anchor);
        try std.testing.expectEqual(cursor, state.cursor);
        try std.testing.expect(!state.flags.dirty);
    }
}

test "Notes rejects malformed selection modifiers and stale input without changing state" {
    var state = State.init("app.notes");
    try std.testing.expect(state.loadDocument("abc"));
    _ = state.apply(inputEvent(2, abi.InputByte.cursor_left, abi.INPUT_EXTEND_SELECTION));
    const before = state;
    try std.testing.expectEqual(ApplyResult.rejected, state.apply(inputEvent(3, abi.InputByte.cursor_left, 2)));
    try std.testing.expectEqualDeep(before, state);
    try std.testing.expectEqual(ApplyResult.rejected, state.apply(inputEvent(3, abi.InputByte.select_all, 1)));
    try std.testing.expectEqualDeep(before, state);
    try std.testing.expectEqual(ApplyResult.rejected, state.apply(inputEvent(2, abi.InputByte.backspace, 0)));
    try std.testing.expectEqualDeep(before, state);
}

test "Notes vertical movement retains its column across short and empty lines" {
    var state = State.init("app.notes");
    try std.testing.expect(state.loadDocument("abcdef\nx\n\nuvwxyz\n"));
    const operations = [_]u8{
        abi.InputByte.document_start, abi.InputByte.cursor_right, abi.InputByte.cursor_right,
        abi.InputByte.cursor_right,   abi.InputByte.cursor_right, abi.InputByte.cursor_down,
        abi.InputByte.cursor_down,    abi.InputByte.cursor_down,  abi.InputByte.cursor_up,
        abi.InputByte.cursor_up,      abi.InputByte.cursor_up,    abi.InputByte.line_end,
        abi.InputByte.cursor_down,    abi.InputByte.document_end, abi.InputByte.cursor_up,
        abi.InputByte.line_start,     abi.InputByte.backspace,
    };
    const positions = [_]u16{ 0, 1, 2, 3, 4, 8, 9, 14, 9, 8, 4, 6, 8, 17, 10, 10, 9 };
    for (operations, positions, 1..) |op, position, sequence| {
        _ = state.apply(inputEvent(sequence, op, 0));
        try std.testing.expectEqual(position, state.cursor);
        try std.testing.expect(state.presentationText().isCanonical());
    }
    try std.testing.expectEqualStrings("abcdef\nx\nuvwxyz\n", state.textSlice());
}

test "Notes cursor boundaries and full-buffer edits preserve canonical snapshots" {
    var state = State.init("app.notes");
    const full = [_]u8{'a'} ** TEXT_CAPACITY;
    try std.testing.expect(state.loadDocument(&full));
    _ = state.apply(inputEvent(1, abi.InputByte.document_start, 0));
    try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(2, abi.InputByte.backspace, 0)));
    try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(3, abi.InputByte.cursor_left, 0)));
    _ = state.apply(inputEvent(4, abi.InputByte.text, 'z'));
    try std.testing.expect(state.flags.input_overflow);
    try std.testing.expectEqualSlices(u8, &full, state.textSlice());
    try std.testing.expect(!state.flags.dirty);
    var reopened = state;
    try std.testing.expect(reopened.loadDocument("fresh"));
    try std.testing.expect(!reopened.flags.input_overflow);
    try std.testing.expect(reopened.presentationText().isCanonical());
    _ = state.apply(inputEvent(5, abi.InputByte.delete_forward, 0));
    try std.testing.expect(!state.flags.input_overflow);
    _ = state.apply(inputEvent(6, abi.InputByte.text, 'z'));
    try std.testing.expectEqual(@as(u16, TEXT_CAPACITY), state.text_length);
    try std.testing.expectEqual(@as(u16, 1), state.cursor);
    try std.testing.expectEqual(@as(u8, 'z'), state.text[0]);
    _ = state.apply(inputEvent(7, abi.InputByte.document_end, 0));
    try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(8, abi.InputByte.delete_forward, 0)));
    try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(9, abi.InputByte.cursor_down, 0)));
    try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(10, abi.InputByte.cursor_right, 0)));
    try std.testing.expect(state.presentationText().isCanonical());
}

test "Viewer and Capture UI state keep model-specific controls" {
    var viewer = State.init("app.viewer");
    try std.testing.expectEqual(ApplyResult.mutated, viewer.apply(inputEvent(1, abi.InputByte.focus_previous, 0)));
    try std.testing.expectEqual(@as(u16, 1), viewer.focus_index);
    try std.testing.expectEqual(ApplyResult.mutated, viewer.apply(inputEvent(2, abi.InputByte.text, 'q')));
    try std.testing.expectEqualStrings("q", viewer.textSlice());
    try std.testing.expectEqual(ApplyResult.observed, viewer.apply(inputEvent(3, abi.InputByte.select_all, 0)));
    try std.testing.expectEqual(ApplyResult.observed, viewer.apply(inputEvent(4, abi.InputByte.cursor_left, abi.INPUT_EXTEND_SELECTION)));
    try std.testing.expectEqual(viewer.cursor, viewer.selection_anchor);
    try std.testing.expect(viewer.presentationText().isCanonical());

    var capture = State.init("app.capture");
    try std.testing.expectEqual(ApplyResult.mutated, capture.apply(inputEvent(1, abi.InputByte.activate, 0)));
    try std.testing.expect(capture.flags.active);
    try std.testing.expectEqual(ApplyResult.mutated, capture.apply(inputEvent(2, abi.InputByte.activate, 0)));
    try std.testing.expect(!capture.flags.active);
}

test "UI surface state rejects stale events and records bounded overflow once" {
    var state = State.init("app.notes");
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(2, abi.InputByte.text, 'x')));
    const revision = state.revision;
    try std.testing.expectEqual(ApplyResult.rejected, state.apply(inputEvent(2, abi.InputByte.text, 'y')));
    try std.testing.expectEqual(revision, state.revision);

    state.text_length = TEXT_CAPACITY;
    state.cursor = TEXT_CAPACITY;
    state.selection_anchor = state.cursor;
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(3, abi.InputByte.text, 'z')));
    try std.testing.expect(state.flags.input_overflow);
    try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(4, abi.InputByte.text, 'z')));
}
