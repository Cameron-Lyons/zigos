const std = @import("std");
const table = @embedFile("unicode_data/properties.bin");
pub const VERSION = "18.0.0";

const Break = enum(u4) { other, cr, lf, control, extend, zwj, ri, prepend, spacing, l, v, t, lv, lvt };
const Indic = enum(u2) { none, consonant, extend, linker };
const Properties = packed struct(u16) {
    kind: Break = .other,
    indic: Indic = .none,
    pictographic: bool = false,
    wide: bool = false,
    emoji: bool = false,
    reserved: u7 = 0,
};
fn properties(point: u21) Properties {
    if (point < 0x80) return .{ .kind = switch (point) {
        '\r' => .cr,
        '\n' => .lf,
        0...8, 9, 11, 12, 14...31, 127 => .control,
        else => .other,
    } };
    var low: usize = 0;
    var high: usize = table.len / 6;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const end = std.mem.readInt(u32, table[middle * 6 ..][0..4], .little);
        if (point > end) low = middle + 1 else high = middle;
    }
    return @bitCast(std.mem.readInt(u16, table[low * 6 + 4 ..][0..2], .little));
}

pub const Scalar = struct { point: u21, end: usize };
pub fn decode(text: []const u8, offset: usize) ?Scalar {
    if (offset >= text.len) return null;
    if (text[offset] < 0x80) return .{ .point = text[offset], .end = offset + 1 };
    const length = std.unicode.utf8ByteSequenceLength(text[offset]) catch return null;
    if (length > text.len - offset) return null;
    return .{ .point = std.unicode.utf8Decode(text[offset..][0..length]) catch return null, .end = offset + length };
}

// Plain UTF-8 documents preserve their original bytes; no normalization or
// replacement on ingress. Tabs and line separators are supported, C0/C1
// device controls are not. Grapheme iteration itself also accepts controls for
// conformance testing and gives malformed display input a replacement glyph.
pub fn validText(text: []const u8) bool {
    var offset: usize = 0;
    while (offset < text.len) {
        const scalar = decode(text, offset) orelse return false;
        if (!validTextPoint(scalar.point)) return false;
        offset = scalar.end;
    }
    return true;
}

// Validate document bytes and both caret/selection offsets in one traversal.
// Once both boundaries are known, validate the remaining bytes without further
// grapheme classification. The start/end offsets need only byte validation.
pub fn validTextAndBoundaries(text: []const u8, first: usize, second: usize) bool {
    if (first > text.len or second > text.len) return false;
    var iterator = Iterator{ .text = text };
    var first_boundary = first == 0 or first == text.len;
    var second_boundary = second == 0 or second == text.len;
    if (first_boundary and second_boundary) return validText(text);
    while (iterator.nextMode(true) catch return false) |cluster| {
        first_boundary = first_boundary or cluster.end == first;
        second_boundary = second_boundary or cluster.end == second;
        if (first_boundary and second_boundary) return validText(text[cluster.end..]);
        if (cluster.end > @max(first, second)) return false;
    }
    return first_boundary and second_boundary;
}

fn validTextPoint(point: u21) bool {
    return !((point < 0x20 and point != '\n' and point != '\r' and point != '\t') or
        (point >= 0x7f and point <= 0x9f));
}

pub const Cluster = struct {
    start: usize,
    end: usize,
    width: u2 = 1,
    newline: bool = false,
    tab: bool = false,

    pub fn columns(self: Cluster, column: usize) usize {
        return if (self.newline) 0 else if (self.tab) 4 - column % 4 else self.width;
    }
};

pub const Iterator = struct {
    text: []const u8,
    offset: usize = 0,

    // UAX #29 revision 49 extended grapheme rules, GB3..GB999. Each scalar
    // is visited once; prefix state covers Indic links, emoji ZWJ and RI pairs.
    pub fn next(self: *Iterator) ?Cluster {
        return self.nextMode(false) catch unreachable;
    }

    fn nextMode(self: *Iterator, comptime strict: bool) error{InvalidText}!?Cluster {
        if (self.offset == self.text.len) return null;
        const start = self.offset;
        const first = decode(self.text, start) orelse if (strict) return error.InvalidText else Scalar{ .point = 0xfffd, .end = start + 1 };
        if (strict and !validTextPoint(first.point)) return error.InvalidText;
        var result = Cluster{
            .start = start,
            .end = first.end,
            .newline = first.point == '\r' or first.point == '\n' or first.point == 0x2028 or first.point == 0x2029,
            .tab = first.point == '\t',
        };
        // The common ASCII pair needs no property lookup or state machine.
        if (first.point < 0x80 and first.point != '\r' and (first.end == self.text.len or self.text[first.end] < 0x80)) {
            self.offset = first.end;
            return result;
        }
        var previous = properties(first.point);
        result.width = if (previous.wide or previous.emoji or previous.kind == .ri) 2 else 1;
        var regional: bool = previous.kind == .ri;
        var linker: bool = previous.indic == .linker;
        var pictographic = previous.pictographic;
        var emoji_run = previous.pictographic;
        var emoji_zwj = false;
        while (result.end < self.text.len) {
            const current = decode(self.text, result.end) orelse if (strict) return error.InvalidText else Scalar{ .point = 0xfffd, .end = result.end + 1 };
            if (strict and !validTextPoint(current.point)) return error.InvalidText;
            const p = properties(current.point);
            const joined = join: {
                if (previous.kind == .cr and p.kind == .lf) break :join true; // GB3
                if (control(previous.kind) or control(p.kind)) break :join false; // GB4/5
                if (previous.kind == .l and (p.kind == .l or p.kind == .v or p.kind == .lv or p.kind == .lvt)) break :join true; // GB6
                if ((previous.kind == .lv or previous.kind == .v) and (p.kind == .v or p.kind == .t)) break :join true; // GB7
                if ((previous.kind == .lvt or previous.kind == .t) and p.kind == .t) break :join true; // GB8
                if (p.kind == .extend or p.kind == .zwj or p.kind == .spacing or previous.kind == .prepend) break :join true; // GB9/9a/9b
                if (linker and p.indic == .consonant) break :join true; // GB9c (Unicode 18)
                if (emoji_zwj and p.pictographic) break :join true; // GB11
                break :join previous.kind == .ri and p.kind == .ri and regional; // GB12/13, GB999
            };
            if (!joined) break;
            result.end = current.end;
            pictographic = pictographic or p.pictographic;
            const emoji_selector = current.point == 0xfe0f and pictographic;
            const keycap = current.point == 0x20e3 and (first.point == '#' or first.point == '*' or (first.point >= '0' and first.point <= '9'));
            if (p.wide or p.emoji or p.kind == .ri or emoji_selector or keycap) result.width = 2;
            regional = p.kind == .ri and !regional;
            linker = p.indic == .linker or (p.indic == .extend and linker);
            emoji_zwj = p.kind == .zwj and emoji_run;
            emoji_run = p.pictographic or (p.kind == .extend and emoji_run);
            previous = p;
        }
        self.offset = result.end;
        return result;
    }
};
fn control(kind: Break) bool {
    return kind == .cr or kind == .lf or kind == .control;
}

pub fn nextBoundary(text: []const u8, offset: usize) usize {
    var it = Iterator{ .text = text };
    while (it.next()) |cluster| if (cluster.end > offset) return cluster.end;
    return text.len;
}
pub fn previousBoundary(text: []const u8, offset: usize) usize {
    var it = Iterator{ .text = text };
    while (it.next()) |cluster| if (cluster.end >= offset) return cluster.start;
    return text.len;
}
pub fn ceilBoundary(text: []const u8, offset: usize) usize {
    if (offset == 0) return 0;
    var it = Iterator{ .text = text };
    while (it.next()) |cluster| if (cluster.end >= offset) return cluster.end;
    return text.len;
}
pub fn isBoundary(text: []const u8, offset: usize) bool {
    return offset <= text.len and ceilBoundary(text, offset) == offset;
}
pub fn followsNewline(text: []const u8, offset: usize) bool {
    if (offset == 0 or offset > text.len) return false;
    if (text[offset - 1] == '\n' or text[offset - 1] == '\r') return true;
    return offset >= 3 and text[offset - 3] == 0xe2 and text[offset - 2] == 0x80 and (text[offset - 1] == 0xa8 or text[offset - 1] == 0xa9);
}

// Marks can be overlaid by the bitmap renderer. Other multi-scalar clusters
// need a shaping engine; they keep one replacement glyph and their full bytes.
pub fn overlayMark(point: u21) bool {
    return properties(point).kind == .extend;
}
pub fn invisible(point: u21) bool {
    return point == 0x200c or point == 0x200d or point == 0xfe0e or point == 0xfe0f or (point >= 0xe0100 and point <= 0xe01ef);
}

test "Unicode 18 extended grapheme boundaries match the official conformance corpus" {
    const corpus = @embedFile("unicode_data/GraphemeBreakTest.txt");
    var lines = std.mem.splitScalar(u8, corpus, '\n');
    var cases: usize = 0;
    while (lines.next()) |line| {
        const content = line[0 .. std.mem.indexOfScalar(u8, line, '#') orelse line.len];
        var tokens = std.mem.tokenizeAny(u8, content, " \t\r");
        var bytes: [2048]u8 = undefined;
        var length: usize = 0;
        var boundaries: [512]usize = undefined;
        var count: usize = 0;
        while (tokens.next()) |token| {
            if (std.mem.eql(u8, token, "÷")) {
                boundaries[count] = length;
                count += 1;
            } else if (!std.mem.eql(u8, token, "×")) {
                const point = try std.fmt.parseInt(u21, token, 16);
                length += try std.unicode.utf8Encode(point, bytes[length..][0..4]);
            }
        }
        if (count == 0) continue;
        cases += 1;
        var iterator = Iterator{ .text = bytes[0..length] };
        for (boundaries[1..count]) |end| {
            const cluster = iterator.next() orelse return error.MissingCluster;
            try std.testing.expectEqual(end, cluster.end);
        }
        try std.testing.expect(iterator.next() == null);
        if (validText(bytes[0..length])) {
            for (0..length + 2) |offset| {
                const expected = std.mem.indexOfScalar(usize, boundaries[0..count], offset) != null;
                try std.testing.expectEqual(expected, validTextAndBoundaries(bytes[0..length], offset, 0));
                try std.testing.expectEqual(expected, validTextAndBoundaries(bytes[0..length], 0, offset));
            }
        }
    }
    try std.testing.expect(cases > 700);
}

test "Unicode rejects malformed UTF-8 and device controls without normalizing text" {
    for ([_][]const u8{ "\x80", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82", "\x1b", "\xc2\x85" }) |text| try std.testing.expect(!validText(text));
    try std.testing.expect(validText("Café e\u{301}\t世界\r\n👩‍💻\u{2028}"));
    const text = "e\u{301}界🇺🇸";
    try std.testing.expectEqual(@as(usize, 3), nextBoundary(text, 0));
    try std.testing.expectEqual(@as(usize, 3), previousBoundary(text, 6));
    try std.testing.expect(!isBoundary(text, 1));
    try std.testing.expectEqual(@as(usize, 3), ceilBoundary(text, 1));
}

test "Unicode strict text validation preserves two boundary checks" {
    for ([_][]const u8{
        "",                         "abc",                       "a\r\nb\n",
        "\t界\t",
        "e\u{301}Café",
        "🇺🇸🇨🇦🇬",
        "👩‍💻x",
        "क्‍ष",
        "\u{1100}\u{1161}\u{11a8}", "\u{600}a\u{2028}b\u{2029}",
    }) |text| {
        for (0..text.len + 2) |first| {
            for (0..text.len + 2) |second| {
                const expected = validText(text) and isBoundary(text, first) and isBoundary(text, second);
                try std.testing.expectEqual(expected, validTextAndBoundaries(text, first, second));
            }
        }
    }
}

test "Unicode strict text validation inspects bytes after both boundaries" {
    for ([_][]const u8{ "a\x80", "a\xc0\xaf", "a\xed\xa0\x80", "a\xf4\x90\x80\x80", "a\xe2\x82", "a\x1b", "a\xc2\x85" }) |text| {
        try std.testing.expect(!validTextAndBoundaries(text, 0, 0));
        try std.testing.expect(!validTextAndBoundaries(text, 1, 1));
    }
    var bytes: [4]u8 = undefined;
    for (0..0xa0) |point| {
        const length = try std.unicode.utf8Encode(@intCast(point), &bytes);
        const expected = switch (point) {
            '\t', '\n', '\r', 0x20...0x7e => true,
            else => false,
        };
        try std.testing.expectEqual(expected, validText(bytes[0..length]));
        try std.testing.expectEqual(expected, validTextAndBoundaries(bytes[0..length], 0, length));
    }
    // Display input still substitutes malformed bytes and accepts controls for
    // conformance rendering; strict ingress must not change that policy.
    var iterator = Iterator{ .text = "\x80e\u{301}\x1b" };
    try std.testing.expectEqual(@as(usize, 1), iterator.next().?.end);
    try std.testing.expectEqual(@as(usize, 4), iterator.next().?.end);
    try std.testing.expectEqual(@as(usize, 5), iterator.next().?.end);
    try std.testing.expect(iterator.next() == null);
}

test "Unicode generated property ranges cover every scalar with valid enum tags" {
    try std.testing.expectEqual(@as(usize, 0), table.len % 6);
    var previous: u32 = 0;
    for (0..table.len / 6) |index| {
        const end = std.mem.readInt(u32, table[index * 6 ..][0..4], .little);
        const bits = std.mem.readInt(u16, table[index * 6 + 4 ..][0..2], .little);
        try std.testing.expect(index == 0 or end > previous);
        try std.testing.expect(end <= 0x10ffff and bits & 15 <= @backingInt(Break.lvt) and bits >> 9 == 0);
        previous = end;
    }
    try std.testing.expectEqual(@as(u32, 0x10ffff), previous);
}

test "Unicode cell widths distinguish emoji presentation from ignored text variation selectors" {
    for ([_]struct { text: []const u8, width: u2 }{
        .{ .text = "e\u{fe0f}", .width = 1 },
        .{ .text = "♥", .width = 1 },
        .{ .text = "♥\u{fe0f}", .width = 2 },
        .{ .text = "1\u{fe0f}\u{20e3}", .width = 2 },
        .{ .text = "🇺🇸", .width = 2 },
        .{ .text = "界", .width = 2 },
    }) |case| {
        var iterator = Iterator{ .text = case.text };
        const cluster = iterator.next().?;
        try std.testing.expectEqual(case.width, cluster.width);
        try std.testing.expectEqual(case.text.len, cluster.end);
    }
}
