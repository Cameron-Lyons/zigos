const std = @import("std");

pub const BOOT_KEYBOARD_REPORT_BYTES: usize = 8;
pub const BOOT_KEY_SLOTS: usize = 6;
pub const EVENT_QUEUE_CAPACITY: usize = BOOT_KEY_SLOTS;
pub const COMPACT_EVENT_QUEUE_METADATA = true;
pub const QUEUE_ONLY_DECODER_STATE = true;
pub const SINGLE_REPORT_EVENT_QUEUE = EVENT_QUEUE_CAPACITY == BOOT_KEY_SLOTS;
pub const DECODER_SIZE_CEILING_BYTES: usize = 21;

comptime {
    if (!SINGLE_REPORT_EVENT_QUEUE) {
        @compileError("input decoder queue must hold exactly one maximal boot-keyboard report");
    }
    if (EVENT_QUEUE_CAPACITY > std.math.maxInt(u8)) {
        @compileError("input decoder event queue no longer fits compact metadata");
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

pub const Error = error{
    InvalidBootKeyboardReport,
    EventQueueFull,
};

pub const Decoder = struct {
    previous_keys: [BOOT_KEY_SLOTS]u8 = [_]u8{0} ** BOOT_KEY_SLOTS,
    events: [EVENT_QUEUE_CAPACITY]KeyboardEvent = [_]KeyboardEvent{.{ .kind = .activate }} ** EVENT_QUEUE_CAPACITY,
    head: u8 = 0,
    tail: u8 = 0,
    count: u8 = 0,

    pub fn submit(
        self: *Decoder,
        report: [BOOT_KEYBOARD_REPORT_BYTES]u8,
    ) Error!usize {
        if (report[1] != 0) return error.InvalidBootKeyboardReport;
        const modifiers = report[0];
        const keys = report[2..BOOT_KEYBOARD_REPORT_BYTES];
        try validateKeys(keys);

        var staged: [BOOT_KEY_SLOTS]KeyboardEvent = undefined;
        var staged_count: usize = 0;
        for (keys) |usage| {
            if (usage == 0 or containsUsage(&self.previous_keys, usage)) continue;
            const event = eventForUsage(usage, modifiers) orelse continue;
            staged[staged_count] = event;
            staged_count += 1;
        }
        if (staged_count > self.events.len - @as(usize, self.count)) return error.EventQueueFull;

        for (staged[0..staged_count]) |event| {
            self.events[self.tail] = event;
            self.tail = @intCast((@as(usize, self.tail) + 1) % self.events.len);
            self.count += 1;
        }
        @memcpy(self.previous_keys[0..], keys);
        return staged_count;
    }

    pub fn poll(self: *Decoder) ?KeyboardEvent {
        if (self.count == 0) return null;
        const event = self.events[self.head];
        self.events[self.head] = .{ .kind = .activate };
        self.head = @intCast((@as(usize, self.head) + 1) % self.events.len);
        self.count -= 1;
        return event;
    }

    pub fn pendingCount(self: *const Decoder) usize {
        return @intCast(self.count);
    }

    pub fn reset(self: *Decoder) void {
        self.* = .{};
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

test "input decoder emits transitions once and accepts a key after release" {
    var decoder = Decoder{};
    try std.testing.expectEqual(@as(usize, 1), try decoder.submit(testReport(0, &.{0x04})));
    try std.testing.expectEqual(@as(usize, 0), try decoder.submit(testReport(0, &.{0x04})));
    try std.testing.expectEqual(@as(usize, 0), try decoder.submit(testReport(0, &.{})));
    try std.testing.expectEqual(@as(usize, 1), try decoder.submit(testReport(0, &.{0x04})));
    try std.testing.expectEqual(KeyboardEvent{ .kind = .text, .text = 'a' }, decoder.poll().?);
    try std.testing.expectEqual(KeyboardEvent{ .kind = .text, .text = 'a' }, decoder.poll().?);
    try std.testing.expect(decoder.poll() == null);
}

test "input decoder maps navigation recovery commit and shifted text" {
    var decoder = Decoder{};
    _ = try decoder.submit(testReport(0, &.{0x2B}));
    _ = try decoder.submit(testReport(0, &.{}));
    _ = try decoder.submit(testReport(SHIFT_MASK, &.{0x2B}));
    _ = try decoder.submit(testReport(0, &.{}));
    _ = try decoder.submit(testReport(ALT_MASK, &.{0x2B}));
    _ = try decoder.submit(testReport(ALT_MASK | SHIFT_MASK, &.{}));
    _ = try decoder.submit(testReport(ALT_MASK | SHIFT_MASK, &.{0x2B}));
    _ = try decoder.submit(testReport(0, &.{}));
    _ = try decoder.submit(testReport(CONTROL_MASK, &.{0x15}));
    _ = try decoder.submit(testReport(0, &.{}));
    _ = try decoder.submit(testReport(CONTROL_MASK, &.{0x28}));
    _ = try decoder.submit(testReport(0, &.{}));

    const navigation_events = [_]KeyboardEvent{
        .{ .kind = .focus_next },
        .{ .kind = .focus_previous },
        .{ .kind = .task_switch_next },
        .{ .kind = .task_switch_previous },
        .{ .kind = .show_recovery },
        .{ .kind = .commit_text },
    };
    for (navigation_events) |event| try std.testing.expectEqual(event, decoder.poll().?);
    try std.testing.expect(decoder.poll() == null);

    _ = try decoder.submit(testReport(SHIFT_MASK, &.{ 0x04, 0x1E, 0x38 }));
    const text_events = [_]KeyboardEvent{
        .{ .kind = .text, .text = 'A' },
        .{ .kind = .text, .text = '!' },
        .{ .kind = .text, .text = '?' },
    };
    for (text_events) |event| try std.testing.expectEqual(event, decoder.poll().?);
    try std.testing.expect(decoder.poll() == null);
}

test "input decoder rejects malformed reports and applies queue backpressure atomically" {
    var decoder = Decoder{};
    var malformed = testReport(0, &.{0x04});
    malformed[1] = 1;
    try std.testing.expectError(error.InvalidBootKeyboardReport, decoder.submit(malformed));
    try std.testing.expectError(
        error.InvalidBootKeyboardReport,
        decoder.submit(testReport(0, &.{ 0x04, 0x04 })),
    );
    try std.testing.expectError(
        error.InvalidBootKeyboardReport,
        decoder.submit(testReport(0, &.{0x01})),
    );

    for (0..EVENT_QUEUE_CAPACITY) |_| {
        _ = try decoder.submit(testReport(0, &.{0x04}));
        _ = try decoder.submit(testReport(0, &.{}));
    }
    try std.testing.expectEqual(EVENT_QUEUE_CAPACITY, decoder.pendingCount());
    try std.testing.expectError(error.EventQueueFull, decoder.submit(testReport(0, &.{0x05})));
    try std.testing.expectEqual(EVENT_QUEUE_CAPACITY, decoder.pendingCount());
    try std.testing.expect(QUEUE_ONLY_DECODER_STATE);
    try std.testing.expect(SINGLE_REPORT_EVENT_QUEUE);
    try std.testing.expectEqual(BOOT_KEY_SLOTS, EVENT_QUEUE_CAPACITY);
    try std.testing.expect(@FieldType(Decoder, "head") == u8);
    try std.testing.expect(@FieldType(Decoder, "tail") == u8);
    try std.testing.expect(@FieldType(Decoder, "count") == u8);
    try std.testing.expectEqual(@as(usize, DECODER_SIZE_CEILING_BYTES), @sizeOf(Decoder));
}
