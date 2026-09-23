const std = @import("std");
const abi = @import("native_abi");
const mailbox = @import("userspace_bootstrap_mailbox");

pub const TEXT_CAPACITY: usize = 512;
const INTERACTION_HASH_SEED: u64 = 0xcbf29ce484222325;
const INTERACTION_HASH_PRIME: u64 = 0x100000001b3;

pub const ApplyResult = enum(u8) {
    rejected,
    observed,
    mutated,
};

pub const State = struct {
    model: mailbox.UiModelKind = .none,
    flags: mailbox.UiStateFlags = .{},
    focus_index: u16 = 0,
    text: [TEXT_CAPACITY]u8 = [_]u8{0} ** TEXT_CAPACITY,
    text_length: u16 = 0,
    cursor: u16 = 0,
    commit_count: u32 = 0,
    activation_count: u32 = 0,
    revision: u64 = 0,
    interaction_hash: u64 = 0,
    last_sequence: u64 = 0,

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

    pub fn apply(self: *State, event: abi.InputEventDescriptor) ApplyResult {
        if (event.sequence == 0 or event.sequence <= self.last_sequence) return .rejected;
        if (event.length < 1 or event.length > event.bytes.len) return .rejected;
        const op = event.bytes[0];
        const data = if (event.length > 1) event.bytes[1] else 0;
        if (op == abi.InputByte.text and (data < 0x20 or data > 0x7e)) return .rejected;
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
            => {},
            else => return .rejected,
        }

        self.last_sequence = event.sequence;
        self.interaction_hash = mixEvent(self.interaction_hash, event);
        const mutated = switch (op) {
            abi.InputByte.text => self.appendText(data),
            abi.InputByte.backspace => self.backspace(),
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

    fn appendText(self: *State, byte: u8) bool {
        if (self.text_length == self.text.len) return self.noteOverflow();
        self.text[self.text_length] = byte;
        self.text_length += 1;
        self.cursor = self.text_length;
        self.flags.dirty = true;
        return true;
    }

    fn backspace(self: *State) bool {
        if (self.text_length == 0) return false;
        self.text_length -= 1;
        self.text[self.text_length] = 0;
        self.cursor = self.text_length;
        self.flags.dirty = true;
        return true;
    }

    fn commit(self: *State) bool {
        self.commit_count +|= 1;
        self.flags.dirty = false;
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
            .notes => _ = self.appendText('\n'),
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

test "Notes UI state edits and commits document text" {
    var state = State.init("app.notes");
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(1, abi.InputByte.text, 'a')));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(2, abi.InputByte.text, 'b')));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(3, abi.InputByte.backspace, 0)));
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(4, abi.InputByte.activate, 0)));
    try std.testing.expectEqualStrings("a\n", state.textSlice());
    try std.testing.expect(state.flags.dirty);
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(5, abi.InputByte.commit_text, 0)));
    try std.testing.expect(!state.flags.dirty);
    try std.testing.expectEqual(@as(u32, 1), state.commit_count);
    try std.testing.expectEqual(@as(u32, 1), state.activation_count);
    try std.testing.expectEqual(@as(u64, 6), state.revision);
}

test "Viewer and Capture UI state keep model-specific controls" {
    var viewer = State.init("app.viewer");
    try std.testing.expectEqual(ApplyResult.mutated, viewer.apply(inputEvent(1, abi.InputByte.focus_previous, 0)));
    try std.testing.expectEqual(@as(u16, 1), viewer.focus_index);
    try std.testing.expectEqual(ApplyResult.mutated, viewer.apply(inputEvent(2, abi.InputByte.text, 'q')));
    try std.testing.expectEqualStrings("q", viewer.textSlice());

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
    try std.testing.expectEqual(ApplyResult.mutated, state.apply(inputEvent(3, abi.InputByte.text, 'z')));
    try std.testing.expect(state.flags.input_overflow);
    try std.testing.expectEqual(ApplyResult.observed, state.apply(inputEvent(4, abi.InputByte.text, 'z')));
}
