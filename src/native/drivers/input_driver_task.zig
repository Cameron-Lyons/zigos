const std = @import("std");
const abi = @import("../core/abi.zig");

pub const BOOT_KEYBOARD_REPORT_BYTES: usize = 8;
pub const BOOT_KEY_SLOTS: usize = 6;
pub const BATCHED_DECODER_OUTPUT = true;
pub const DECODED_EVENTS_SIZE_CEILING_BYTES: usize = 13;
pub const DECODER_SIZE_CEILING_BYTES: usize = 6;

comptime {
    if (BOOT_KEY_SLOTS > std.math.maxInt(u8)) {
        @compileError("decoded boot-keyboard events no longer fit compact batch metadata");
    }
}

const LEFT_CONTROL: u8 = 1 << 0;
const LEFT_SHIFT: u8 = 1 << 1;
const LEFT_ALT: u8 = 1 << 2;
const LEFT_GUI: u8 = 1 << 3;
const CONTROL_MASK: u8 = LEFT_CONTROL | (1 << 4);
const SHIFT_MASK: u8 = LEFT_SHIFT | (1 << 5);
const ALT_MASK: u8 = LEFT_ALT | (1 << 6);
const GUI_MASK: u8 = LEFT_GUI | (1 << 7);

pub const EventKind = enum(u8) {
    text,
    backspace,
    commit_text,
    focus_next,
    focus_previous,
    activate,
    task_switch_next,
    task_switch_previous,
    show_recovery,
    dismiss_recovery,
    cursor_left,
    cursor_right,
    cursor_up,
    cursor_down,
    line_start,
    line_end,
    document_start,
    document_end,
    delete_forward,
    select_all,
    undo,
    redo,
    copy,
    cut,
    paste,
    page_up,
    page_down,
    new_document,
    open_document,
};

pub const KeyboardEvent = struct {
    kind: EventKind,
    data: u8 = 0,
};

pub const Error = error{InvalidBootKeyboardReport};

pub const DecodedEvents = struct {
    events: [BOOT_KEY_SLOTS]KeyboardEvent = @as([BOOT_KEY_SLOTS]KeyboardEvent, @splat(.{ .kind = .activate })),
    count: u8 = 0,

    pub fn slice(self: *const DecodedEvents) []const KeyboardEvent {
        return self.events[0..@as(usize, self.count)];
    }

    comptime {
        if (@sizeOf(@This()) > DECODED_EVENTS_SIZE_CEILING_BYTES) {
            @compileError("decoded input event batch exceeds its compact size ceiling");
        }
    }
};

pub const Decoder = struct {
    previous_keys: [BOOT_KEY_SLOTS]u8 = @as([BOOT_KEY_SLOTS]u8, @splat(0)),

    // Call before decode, and use only after decode validates the report. A
    // chord containing any new command key must never acquire repeat authority.
    pub fn newRepeatUsage(self: *const Decoder, report: [BOOT_KEYBOARD_REPORT_BYTES]u8) ?u8 {
        var candidate: ?u8 = null;
        for (report[2..]) |usage| {
            if (usage == 0 or containsUsage(&self.previous_keys, usage)) continue;
            _ = repeatEvent(usage, report[0]) orelse return null;
            candidate = usage;
        }
        return candidate;
    }

    pub fn decode(
        self: *Decoder,
        report: [BOOT_KEYBOARD_REPORT_BYTES]u8,
    ) Error!DecodedEvents {
        if (report[1] != 0) return error.InvalidBootKeyboardReport;
        const modifiers = report[0];
        const keys = report[2..BOOT_KEYBOARD_REPORT_BYTES];
        try validateKeys(keys);

        var decoded = DecodedEvents{};
        for (keys) |usage| {
            if (usage == 0 or containsUsage(&self.previous_keys, usage)) continue;
            const event = eventForUsage(usage, modifiers) orelse continue;
            decoded.events[decoded.count] = event;
            decoded.count += 1;
        }
        @memcpy(self.previous_keys[0..], keys);
        return decoded;
    }

    comptime {
        if (@sizeOf(@This()) > DECODER_SIZE_CEILING_BYTES) {
            @compileError("input decoder exceeds its compact size ceiling");
        }
    }
};

// Repeat is restricted to ordinary document editing. In particular, neither
// clipboard authorization nor activation/save/recovery can be synthesized.
pub fn repeatEvent(usage: u8, modifiers: u8) ?KeyboardEvent {
    if (modifiers & ~SHIFT_MASK != 0) return null;
    const event = eventForUsage(usage, modifiers) orelse return null;
    return switch (event.kind) {
        .text, .backspace, .delete_forward, .cursor_left, .cursor_right, .cursor_up, .cursor_down, .line_start, .line_end, .page_up, .page_down => event,
        else => null,
    };
}

fn validateKeys(keys: []const u8) Error!void {
    for (keys, 0..) |usage, index| {
        if (usage >= 1 and usage <= 3) return error.InvalidBootKeyboardReport;
        if (usage == 0) continue;
        for (keys[0..index]) |previous| {
            if (previous == usage) return error.InvalidBootKeyboardReport;
        }
    }
}

fn containsUsage(keys: []const u8, usage: u8) bool {
    for (keys) |key| {
        if (key == usage) return true;
    }
    return false;
}

fn eventForUsage(usage: u8, modifiers: u8) ?KeyboardEvent {
    const control = (modifiers & CONTROL_MASK) != 0;
    const shift = (modifiers & SHIFT_MASK) != 0;
    const alt = (modifiers & ALT_MASK) != 0;
    const gui = (modifiers & GUI_MASK) != 0;

    // USB HID Keyboard/Keypad page 0x07, usages 0x4A..0x52.
    // Shift extends the selection; Ctrl+Home/End reaches document boundaries.
    if (usage >= 0x4A and usage <= 0x52) {
        if (alt or gui) return null;
        const kind: EventKind = switch (usage) {
            0x4A => if (control) .document_start else .line_start,
            0x4D => if (control) .document_end else .line_end,
            0x4B => if (control) return null else .page_up,
            0x4E => if (control) return null else .page_down,
            0x4C => if (control or shift) return null else .delete_forward,
            0x4F => if (control) return null else .cursor_right,
            0x50 => if (control) return null else .cursor_left,
            0x51 => if (control) return null else .cursor_down,
            0x52 => if (control) return null else .cursor_up,
            else => return null,
        };
        return .{ .kind = kind, .data = if (shift) abi.INPUT_EXTEND_SELECTION else 0 };
    }

    return switch (usage) {
        0x11, 0x12 => if (control and !shift and !alt and !gui)
            .{ .kind = if (usage == 0x11) .new_document else .open_document }
        else
            textEvent(usage, shift, control or alt or gui),
        0x06, 0x1B, 0x19 => if (control and !shift and !alt and !gui)
            .{ .kind = switch (usage) {
                0x06 => .copy,
                0x1B => .cut,
                else => .paste,
            } }
        else
            textEvent(usage, shift, control or alt or gui),
        0x1D => if (control and !alt and !gui)
            .{ .kind = if (shift) .redo else .undo }
        else
            textEvent(usage, shift, control or alt or gui),
        0x04 => if (control and !shift and !alt and !gui)
            .{ .kind = .select_all }
        else
            textEvent(usage, shift, control or alt or gui),
        0x29 => .{ .kind = .dismiss_recovery },
        0x2A => .{ .kind = .backspace },
        0x2B => if (alt)
            .{ .kind = if (shift) .task_switch_previous else .task_switch_next }
        else
            .{ .kind = if (shift) .focus_previous else .focus_next },
        0x28 => .{ .kind = if (control) .commit_text else .activate },
        0x15 => if (control)
            .{ .kind = .show_recovery }
        else
            textEvent(usage, shift, alt or gui),
        else => textEvent(usage, shift, control or alt or gui),
    };
}

fn textEvent(usage: u8, shift: bool, shortcut_modifier: bool) ?KeyboardEvent {
    if (shortcut_modifier) return null;
    const text = asciiFromUsage(usage, shift) orelse return null;
    return .{ .kind = .text, .data = text };
}

fn asciiFromUsage(usage: u8, shifted: bool) ?u8 {
    return switch (usage) {
        0x04...0x1D => (if (shifted) @as(u8, 'A') else @as(u8, 'a')) + (usage - 0x04),
        0x1E...0x27 => if (shifted)
            "!@#$%^&*()"[usage - 0x1E]
        else if (usage == 0x27)
            '0'
        else
            '1' + (usage - 0x1E),
        0x2C => ' ',
        0x2D => if (shifted) '_' else '-',
        0x2E => if (shifted) '+' else '=',
        0x2F => if (shifted) '{' else '[',
        0x30 => if (shifted) '}' else ']',
        0x31 => if (shifted) '|' else '\\',
        0x33 => if (shifted) ':' else ';',
        0x34 => if (shifted) '"' else '\'',
        0x35 => if (shifted) '~' else '`',
        0x36 => if (shifted) '<' else ',',
        0x37 => if (shifted) '>' else '.',
        0x38 => if (shifted) '?' else '/',
        else => null,
    };
}

fn testReport(modifiers: u8, keys: []const u8) [BOOT_KEYBOARD_REPORT_BYTES]u8 {
    var result = @as([BOOT_KEYBOARD_REPORT_BYTES]u8, @splat(0));
    result[0] = modifiers;
    @memcpy(result[2..][0..keys.len], keys);
    return result;
}

fn expectDecoded(
    decoder: *Decoder,
    report: [BOOT_KEYBOARD_REPORT_BYTES]u8,
    expected: []const KeyboardEvent,
) !void {
    const decoded = try decoder.decode(report);
    try std.testing.expectEqual(expected.len, decoded.slice().len);
    try std.testing.expectEqualSlices(KeyboardEvent, expected, decoded.slice());
}

test "input decoder emits transitions once and accepts a key after release" {
    var decoder = Decoder{};
    try expectDecoded(&decoder, testReport(0, &.{0x04}), &.{.{ .kind = .text, .data = 'a' }});
    try expectDecoded(&decoder, testReport(0, &.{0x04}), &.{});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(0, &.{0x04}), &.{.{ .kind = .text, .data = 'a' }});
}

test "input decoder maps navigation recovery commit and shifted text" {
    var decoder = Decoder{};
    try expectDecoded(&decoder, testReport(0, &.{0x2B}), &.{.{ .kind = .focus_next }});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(SHIFT_MASK, &.{0x2B}), &.{.{ .kind = .focus_previous }});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(ALT_MASK, &.{0x2B}), &.{.{ .kind = .task_switch_next }});
    try expectDecoded(&decoder, testReport(ALT_MASK | SHIFT_MASK, &.{}), &.{});
    try expectDecoded(&decoder, testReport(ALT_MASK | SHIFT_MASK, &.{0x2B}), &.{.{ .kind = .task_switch_previous }});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(CONTROL_MASK, &.{0x15}), &.{.{ .kind = .show_recovery }});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(CONTROL_MASK, &.{0x28}), &.{.{ .kind = .commit_text }});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});

    const expected = [_]KeyboardEvent{
        .{ .kind = .text, .data = 'A' },
        .{ .kind = .text, .data = '!' },
        .{ .kind = .text, .data = '?' },
    };
    try expectDecoded(&decoder, testReport(SHIFT_MASK, &.{ 0x04, 0x1E, 0x38 }), &expected);
}

test "input decoder maps cursor editing keys and isolates unsupported modifiers" {
    const usages = [_]u8{ 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52 };
    const kinds = [_]EventKind{ .line_start, .page_up, .delete_forward, .line_end, .page_down, .cursor_right, .cursor_left, .cursor_down, .cursor_up };
    for (usages, kinds) |usage, kind| {
        var decoder = Decoder{};
        try expectDecoded(&decoder, testReport(0, &.{usage}), &.{.{ .kind = kind }});
        try expectDecoded(&decoder, testReport(0, &.{usage}), &.{});
        for ([_]u8{ ALT_MASK, GUI_MASK }) |modifier| {
            try expectDecoded(&decoder, testReport(0, &.{}), &.{});
            try expectDecoded(&decoder, testReport(modifier, &.{usage}), &.{});
        }
    }
    var decoder = Decoder{};
    try expectDecoded(&decoder, testReport(CONTROL_MASK, &.{ 0x4A, 0x4D }), &.{ .{ .kind = .document_start }, .{ .kind = .document_end } });
    try expectDecoded(&decoder, testReport(CONTROL_MASK, &.{ 0x4C, 0x4F, 0x50, 0x51, 0x52 }), &.{});
    try expectDecoded(&decoder, testReport(CONTROL_MASK, &.{ 0x4B, 0x4E }), &.{});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(SHIFT_MASK, &.{ 0x4B, 0x4E }), &.{
        .{ .kind = .page_up, .data = abi.INPUT_EXTEND_SELECTION },
        .{ .kind = .page_down, .data = abi.INPUT_EXTEND_SELECTION },
    });
}

test "input decoder carries Shift selection and select all without growing event batches" {
    var decoder = Decoder{};
    try expectDecoded(&decoder, testReport(SHIFT_MASK, &.{ 0x4A, 0x4D, 0x4F, 0x50, 0x51, 0x52 }), &.{
        .{ .kind = .line_start, .data = abi.INPUT_EXTEND_SELECTION },
        .{ .kind = .line_end, .data = abi.INPUT_EXTEND_SELECTION },
        .{ .kind = .cursor_right, .data = abi.INPUT_EXTEND_SELECTION },
        .{ .kind = .cursor_left, .data = abi.INPUT_EXTEND_SELECTION },
        .{ .kind = .cursor_down, .data = abi.INPUT_EXTEND_SELECTION },
        .{ .kind = .cursor_up, .data = abi.INPUT_EXTEND_SELECTION },
    });
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(CONTROL_MASK | SHIFT_MASK, &.{ 0x4A, 0x4D }), &.{
        .{ .kind = .document_start, .data = abi.INPUT_EXTEND_SELECTION },
        .{ .kind = .document_end, .data = abi.INPUT_EXTEND_SELECTION },
    });
    try expectDecoded(&decoder, testReport(CONTROL_MASK, &.{0x04}), &.{.{ .kind = .select_all }});
    try expectDecoded(&decoder, testReport(SHIFT_MASK, &.{0x4C}), &.{});
    try expectDecoded(&decoder, testReport(CONTROL_MASK | ALT_MASK, &.{0x04}), &.{});
    try std.testing.expectEqual(@as(usize, 2), @sizeOf(KeyboardEvent));
    try std.testing.expectEqual(@as(usize, 13), @sizeOf(DecodedEvents));
}

test "input decoder maps Ctrl Z and Ctrl Shift Z to distinct history operations" {
    var decoder = Decoder{};
    try expectDecoded(&decoder, testReport(CONTROL_MASK, &.{0x1D}), &.{.{ .kind = .undo }});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(CONTROL_MASK | SHIFT_MASK, &.{0x1D}), &.{.{ .kind = .redo }});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(CONTROL_MASK | ALT_MASK, &.{0x1D}), &.{});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(0, &.{0x1D}), &.{.{ .kind = .text, .data = 'z' }});
}

test "input decoder rejects malformed reports and bounds decoded batches" {
    var decoder = Decoder{};
    var malformed = testReport(0, &.{0x04});
    malformed[1] = 1;
    try std.testing.expectError(error.InvalidBootKeyboardReport, decoder.decode(malformed));
    try std.testing.expectError(
        error.InvalidBootKeyboardReport,
        decoder.decode(testReport(0, &.{ 0x04, 0x04 })),
    );
    try std.testing.expectError(
        error.InvalidBootKeyboardReport,
        decoder.decode(testReport(0, &.{0x01})),
    );

    const expected = [_]KeyboardEvent{
        .{ .kind = .text, .data = 'a' },
        .{ .kind = .text, .data = 'b' },
        .{ .kind = .text, .data = 'c' },
        .{ .kind = .text, .data = 'd' },
        .{ .kind = .text, .data = 'e' },
        .{ .kind = .text, .data = 'f' },
    };
    try expectDecoded(&decoder, testReport(0, &.{ 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 }), &expected);
    try std.testing.expect(BATCHED_DECODER_OUTPUT);
    try std.testing.expectEqual(@as(usize, DECODED_EVENTS_SIZE_CEILING_BYTES), @sizeOf(DecodedEvents));
    try std.testing.expectEqual(@as(usize, DECODER_SIZE_CEILING_BYTES), @sizeOf(Decoder));
}
