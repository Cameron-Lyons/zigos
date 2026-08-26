const std = @import("std");

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
};

pub const KeyboardEvent = struct {
    kind: EventKind,
    text: u8 = 0,
};

pub const Error = error{InvalidBootKeyboardReport};

pub const DecodedEvents = struct {
    events: [BOOT_KEY_SLOTS]KeyboardEvent = [_]KeyboardEvent{.{ .kind = .activate }} ** BOOT_KEY_SLOTS,
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
    previous_keys: [BOOT_KEY_SLOTS]u8 = [_]u8{0} ** BOOT_KEY_SLOTS,

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

    return switch (usage) {
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
    return .{ .kind = .text, .text = text };
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
    var result = [_]u8{0} ** BOOT_KEYBOARD_REPORT_BYTES;
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
    try expectDecoded(&decoder, testReport(0, &.{0x04}), &.{.{ .kind = .text, .text = 'a' }});
    try expectDecoded(&decoder, testReport(0, &.{0x04}), &.{});
    try expectDecoded(&decoder, testReport(0, &.{}), &.{});
    try expectDecoded(&decoder, testReport(0, &.{0x04}), &.{.{ .kind = .text, .text = 'a' }});
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
        .{ .kind = .text, .text = 'A' },
        .{ .kind = .text, .text = '!' },
        .{ .kind = .text, .text = '?' },
    };
    try expectDecoded(&decoder, testReport(SHIFT_MASK, &.{ 0x04, 0x1E, 0x38 }), &expected);
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
        .{ .kind = .text, .text = 'a' },
        .{ .kind = .text, .text = 'b' },
        .{ .kind = .text, .text = 'c' },
        .{ .kind = .text, .text = 'd' },
        .{ .kind = .text, .text = 'e' },
        .{ .kind = .text, .text = 'f' },
    };
    try expectDecoded(&decoder, testReport(0, &.{ 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 }), &expected);
    try std.testing.expect(BATCHED_DECODER_OUTPUT);
    try std.testing.expectEqual(@as(usize, DECODED_EVENTS_SIZE_CEILING_BYTES), @sizeOf(DecodedEvents));
    try std.testing.expectEqual(@as(usize, DECODER_SIZE_CEILING_BYTES), @sizeOf(Decoder));
}
