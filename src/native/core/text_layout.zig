const std = @import("std");
pub const unicode = @import("unicode.zig");

pub const Viewport = extern struct {
    columns: u8 = 0,
    rows: u8 = 0,

    pub fn valid(self: Viewport) bool {
        return (self.columns == 0) == (self.rows == 0);
    }

    pub fn pageRows(self: Viewport) usize {
        return @max(1, @as(usize, self.rows) -| 1);
    }
};

// At a soft wrap one byte boundary has two visual positions. Upstream places
// the caret after the preceding row; downstream places it before the next row.
pub const Caret = struct { offset: usize, upstream: bool = false };
pub const Row = struct {
    start: usize,
    end: usize,
    next: usize,
    soft: bool,

    width: usize = 0,
    simple: bool = true,

    fn contains(self: Row, caret: Caret) bool {
        return caret.offset <= self.end and (caret.offset < self.end or !self.soft or caret.upstream);
    }

    pub fn atColumn(self: Row, text: []const u8, column: usize) Caret {
        if (self.simple) {
            const offset = self.start + @min(column, self.width);
            return .{ .offset = offset, .upstream = self.soft and offset == self.end };
        }
        if (column >= self.width) return .{ .offset = self.end, .upstream = self.soft };
        var iterator = unicode.Iterator{ .text = text[0..self.end], .offset = self.start };
        var x: usize = 0;
        while (iterator.next()) |cluster| {
            const next = @min(self.width, x + cluster.columns(x));
            if (next > column) return .{ .offset = cluster.start };
            x = next;
        }
        return .{ .offset = self.end, .upstream = self.soft };
    }

    pub fn columnAt(self: Row, text: []const u8, offset: usize) usize {
        if (self.simple) return @min(offset - self.start, self.width);
        var iterator = unicode.Iterator{ .text = text[0..self.end], .offset = self.start };
        var column: usize = 0;
        while (iterator.offset < offset) {
            const cluster = iterator.next() orelse break;
            column += cluster.columns(column);
        }
        return @min(column, self.width);
    }
};
pub const Location = struct { row: Row, index: usize, column: usize };

pub const VisibleWindow = struct {
    storage: []const Row,
    first_slot: usize,
    first_index: usize,
    count: usize,
    location: Location,

    pub fn rowAt(self: VisibleWindow, index: usize) Row {
        std.debug.assert(index < self.count);
        const slot = self.first_slot + index;
        return self.storage[if (slot < self.storage.len) slot else slot - self.storage.len];
    }
};

// Bounded, allocation-free layout shared by editor navigation and scanout.
// Width zero means no soft wrapping when no display geometry is available.
pub const Layout = struct {
    text: []const u8,
    columns: usize,

    pub fn rows(self: Layout) Iterator {
        return .{ .layout = self, .simple = simpleText(self.text) };
    }

    pub fn locate(self: Layout, caret: Caret) Location {
        const offset = @min(caret.offset, self.text.len);
        var iterator = self.rows();
        var index: usize = 0;
        while (iterator.next()) |row| : (index += 1) {
            if (row.contains(.{ .offset = offset, .upstream = caret.upstream }))
                return .{ .row = row, .index = index, .column = row.columnAt(self.text, offset) };
        }
        unreachable;
    }

    pub fn rowAt(self: Layout, index: usize) Row {
        var iterator = self.rows();
        var row = iterator.next().?;
        for (0..index) |_| row = iterator.next() orelse return row;
        return row;
    }

    pub fn vertical(self: Layout, caret: Caret, column: usize, down: bool, count: usize) Caret {
        const index = self.locate(caret).index;
        return self.rowAt(if (down) index +| count else index -| count).atColumn(self.text, column);
    }

    // The caller provides one row slot per visible line. Retain preceding rows
    // while finding the caret, then finish the window without restarting layout.
    // Storage must be nonempty and remain alive while the window is consumed.
    // In-range caret offsets must be grapheme boundaries.
    pub fn visibleWindow(self: Layout, caret: Caret, storage: []Row) VisibleWindow {
        std.debug.assert(storage.len != 0);
        const bounded = Caret{ .offset = @min(caret.offset, self.text.len), .upstream = caret.upstream };
        var iterator = self.rows();
        var position: ?Location = null;
        var slot: usize = 0;
        var count: usize = 0;
        var index: usize = 0;
        while (iterator.next()) |row| : (index += 1) {
            storage[slot] = row;
            slot += 1;
            if (slot == storage.len) slot = 0;
            count = @min(count + 1, storage.len);
            if (position == null and row.contains(bounded))
                position = .{ .row = row, .index = index, .column = row.columnAt(self.text, bounded.offset) };
            if (position) |location| {
                if (index + 1 >= @max(location.index + 1, storage.len)) break;
            }
        }
        const location = position orelse unreachable;
        return .{
            .storage = storage,
            .first_slot = if (count == storage.len) slot else 0,
            .first_index = location.index -| (storage.len - 1),
            .count = count,
            .location = location,
        };
    }
};

pub const Iterator = struct {
    layout: Layout,
    start: usize = 0,
    finished: bool = false,
    simple: bool = false,

    pub fn next(self: *Iterator) ?Row {
        if (self.finished) return null;
        const text = self.layout.text;
        if (self.simple) {
            const width = if (self.layout.columns == 0) text.len + 1 else self.layout.columns;
            const limit = self.start + @min(width, text.len - self.start);
            const end = self.start + newlineOffset(text[self.start..limit]);
            const hard = end < text.len and text[end] == '\n';
            const row = Row{ .start = self.start, .end = end, .next = end + @as(usize, @intFromBool(hard)), .soft = end < text.len and !hard, .width = end - self.start };
            self.finished = end == text.len;
            self.start = row.next;
            return row;
        }
        const width = if (self.layout.columns == 0) std.math.maxInt(usize) else self.layout.columns;
        var end = self.start;
        var following = end;
        var column: usize = 0;
        var hard = false;
        var simple = true;
        while (end < text.len) {
            // Preserve the tight ASCII scan used for ordinary desktop text.
            if (text[end] >= 0x20 and text[end] < 0x7f and (end + 1 == text.len or text[end + 1] < 0x80)) {
                if (column == width) break;
                end += 1;
                following = end;
                column += 1;
                continue;
            }
            var iterator = unicode.Iterator{ .text = text, .offset = end };
            const cluster = iterator.next().?;
            if (cluster.newline) {
                hard = true;
                following = cluster.end;
                break;
            }
            simple = false;
            const cells = cluster.columns(column);
            if (column != 0 and cells > width - column) break;
            column += @min(cells, width - column);
            end = cluster.end;
            following = end;
        }
        const row = Row{ .start = self.start, .end = end, .next = following, .soft = end < text.len and !hard, .width = column, .simple = simple };
        self.finished = end == text.len;
        self.start = row.next;
        return row;
    }
};

// Find a hard break with word loads. The least significant detected zero byte
// is exact even when subtraction borrows into a following byte.
fn newlineOffset(text: []const u8) usize {
    var offset: usize = 0;
    while (text.len - offset >= 8) : (offset += 8) {
        const word = std.mem.readInt(u64, text[offset..][0..8], .little) ^ 0x0a0a0a0a0a0a0a0a;
        const matches = (word -% 0x0101010101010101) & ~word & 0x8080808080808080;
        if (matches != 0) return offset + @ctz(matches) / 8;
    }
    for (text[offset..], offset..) |byte, index| if (byte == '\n') return index;
    return text.len;
}

// Classify once per scan, eight bytes at a time using integer registers. The
// kernel does not need SIMD state to keep its ordinary ASCII layout fast.
fn simpleText(text: []const u8) bool {
    const ones: u64 = 0x0101010101010101;
    const highs: u64 = 0x8080808080808080;
    var offset: usize = 0;
    while (text.len - offset >= 8) : (offset += 8) {
        const word = std.mem.readInt(u64, text[offset..][0..8], .little);
        const tabs = word ^ (ones * '\t');
        const returns = word ^ (ones * '\r');
        if ((word | ((tabs -% ones) & ~tabs) | ((returns -% ones) & ~returns)) & highs != 0) return false;
    }
    for (text[offset..]) |byte| if (byte >= 0x80 or byte == '\t' or byte == '\r') return false;
    return true;
}

test "text layout distinguishes wrap affinity and avoids a phantom row before newline" {
    const layout = Layout{ .text = "abcdefghij\nxy\n", .columns = 5 };
    var iterator = layout.rows();
    try std.testing.expectEqual(Row{ .start = 0, .end = 5, .next = 5, .soft = true, .width = 5 }, iterator.next().?);
    try std.testing.expectEqual(Row{ .start = 5, .end = 10, .next = 11, .soft = false, .width = 5 }, iterator.next().?);
    try std.testing.expectEqual(Row{ .start = 11, .end = 13, .next = 14, .soft = false, .width = 2 }, iterator.next().?);
    try std.testing.expectEqual(Row{ .start = 14, .end = 14, .next = 14, .soft = false }, iterator.next().?);
    try std.testing.expect(iterator.next() == null);
    try std.testing.expectEqual(@as(usize, 0), layout.locate(.{ .offset = 5, .upstream = true }).index);
    try std.testing.expectEqual(@as(usize, 1), layout.locate(.{ .offset = 5 }).index);
    try std.testing.expectEqual(@as(usize, 5), layout.locate(.{ .offset = 10 }).column);
    try std.testing.expectEqual(Caret{ .offset = 13 }, layout.vertical(.{ .offset = 10 }, 5, true, 1));
    try std.testing.expectEqual(Caret{ .offset = 10 }, layout.vertical(.{ .offset = 13 }, 5, false, 1));
}

test "text layout covers every cursor boundary without allocation across narrow and full widths" {
    for ([_][]const u8{ "", "\n", "abc", "abc\n", "\n\n", "ab\ncdef\ngh" }) |text| {
        for (0..9) |width| {
            const layout = Layout{ .text = text, .columns = width };
            for (0..text.len + 1) |offset| {
                for ([_]bool{ false, true }) |upstream| {
                    const position = layout.locate(.{ .offset = offset, .upstream = upstream });
                    try std.testing.expectEqual(offset, position.row.start + position.column);
                    try std.testing.expect(position.row.end >= offset);
                    if (width != 0) try std.testing.expect(position.column <= width);
                }
            }
        }
    }
}

test "text layout wraps graphemes and maps visual columns across wide glyphs tabs and CRLF" {
    const text = "Ae\u{301}界Z\r\n\t猫\u{2028}x";
    const layout = Layout{ .text = text, .columns = 4 };
    var rows = layout.rows();
    const first = rows.next().?;
    try std.testing.expectEqualStrings("Ae\u{301}界", text[first.start..first.end]);
    try std.testing.expectEqual(@as(usize, 4), first.width);
    try std.testing.expectEqual(@as(usize, 4), first.atColumn(text, 3).offset);
    try std.testing.expectEqual(@as(usize, 7), first.atColumn(text, 4).offset);
    try std.testing.expectEqual(@as(usize, 2), layout.locate(.{ .offset = 4 }).column);
    const second = rows.next().?;
    try std.testing.expectEqualStrings("Z", text[second.start..second.end]);
    try std.testing.expectEqual(@as(usize, 2), second.next - second.end);
    const tab = rows.next().?;
    try std.testing.expectEqualStrings("\t", text[tab.start..tab.end]);
    try std.testing.expectEqual(tab.start, tab.atColumn(text, 3).offset);
    try std.testing.expectEqualStrings("猫", text[rows.next().?.start..][0..3]);
    try std.testing.expectEqual(@as(usize, 1), rows.next().?.width);
    try std.testing.expect(rows.next() == null);
    const narrow = Layout{ .text = "界界", .columns = 1 };
    try std.testing.expectEqual(@as(usize, 1), narrow.rowAt(0).width);
    try std.testing.expectEqual(@as(usize, 3), narrow.rowAt(1).start);
}

test "text layout ASCII classification detects special bytes in every word and tail position" {
    var bytes: [19]u8 = @splat('x');
    for (0..bytes.len) |position| {
        for (0..256) |value| {
            bytes[position] = @intCast(value);
            try std.testing.expectEqual(value < 0x80 and value != '\t' and value != '\r', simpleText(&bytes));
        }
        bytes[position] = 'x';
    }
    try std.testing.expect(simpleText(""));
}

test "text layout word scan finds the first newline without reading past the slice" {
    var bytes: [25]u8 = @splat('x');
    for (0..bytes.len + 1) |length| {
        try std.testing.expectEqual(length, newlineOffset(bytes[0..length]));
        for (0..length) |position| {
            bytes[position] = '\n';
            if (position + 1 < length) bytes[position + 1] = 11; // Subtraction-borrow neighbor.
            try std.testing.expectEqual(position, newlineOffset(bytes[0..length]));
            if (position + 1 < length) bytes[position + 1] = 'x';
            bytes[position] = 'x';
        }
    }
}

test "visible text windows match independent caret lookup and row traversal" {
    const guard = Row{ .start = std.math.maxInt(usize), .end = std.math.maxInt(usize), .next = std.math.maxInt(usize), .soft = false };
    for ([_][]const u8{
        "", "\n", "\n\n", "abc", "abc\n", "abcdefghij\nxy\n",
        "Ae\u{301}界Z\r\n\t猫\u{2028}x\u{2029}",
        "👩‍💻🇺🇸☃\u{fe0f}\tक्‍ष\r\nend",
        "abcd\nefgh\nijkl\nmnop\nqrst\nuvwx\nyz\n" ++
            "abcd\nefgh\nijkl\nmnop\nqrst\nuvwx\nyz\n" ++
            "abcd\nefgh\nijkl\nmnop\nqrst\nuvwx\nyz\n",
    }) |text| {
        for ([_]usize{ 0, 1, 2, 4, 5, 20 }) |columns| {
            const layout = Layout{ .text = text, .columns = columns };
            for (0..text.len + 1) |offset| {
                if (!unicode.isBoundary(text, offset)) continue;
                for ([_]bool{ false, true }) |upstream| {
                    const caret = Caret{ .offset = offset, .upstream = upstream };
                    const expected_location = layout.locate(caret);
                    for (1..49) |capacity| {
                        var storage: [50]Row = @splat(guard);
                        const window = layout.visibleWindow(caret, storage[1 .. capacity + 1]);
                        try std.testing.expectEqualDeep(expected_location, window.location);
                        try std.testing.expectEqual(expected_location.index -| (capacity - 1), window.first_index);
                        var expected_rows = layout.rows();
                        var index: usize = 0;
                        var count: usize = 0;
                        while (expected_rows.next()) |row| : (index += 1) {
                            if (index < window.first_index) continue;
                            if (count == capacity) break;
                            try std.testing.expectEqualDeep(row, window.rowAt(count));
                            count += 1;
                        }
                        try std.testing.expectEqual(count, window.count);
                        try std.testing.expectEqualDeep(guard, storage[0]);
                        try std.testing.expectEqualDeep(guard, storage[capacity + 1]);
                    }
                }
            }
        }
    }
}
