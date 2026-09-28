const std = @import("std");

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

    pub fn atColumn(self: Row, column: usize) Caret {
        const offset = self.start + @min(column, self.end - self.start);
        return .{ .offset = offset, .upstream = self.soft and offset == self.end };
    }
};
pub const Location = struct { row: Row, index: usize, column: usize };

// Bounded, allocation-free layout shared by editor navigation and scanout.
// Width zero means no soft wrapping when no display geometry is available.
pub const Layout = struct {
    text: []const u8,
    columns: usize,

    pub fn rows(self: Layout) Iterator {
        return .{ .layout = self };
    }

    pub fn locate(self: Layout, caret: Caret) Location {
        const offset = @min(caret.offset, self.text.len);
        var iterator = self.rows();
        var index: usize = 0;
        while (iterator.next()) |row| : (index += 1) {
            if (offset <= row.end and (offset < row.end or !row.soft or caret.upstream))
                return .{ .row = row, .index = index, .column = offset - row.start };
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
        return self.rowAt(if (down) index +| count else index -| count).atColumn(column);
    }
};

pub const Iterator = struct {
    layout: Layout,
    start: usize = 0,
    finished: bool = false,

    pub fn next(self: *Iterator) ?Row {
        if (self.finished) return null;
        const text = self.layout.text;
        const width = if (self.layout.columns == 0) text.len + 1 else self.layout.columns;
        var end = self.start;
        while (end < text.len and end - self.start < width and text[end] != '\n') : (end += 1) {}
        const hard = end < text.len and text[end] == '\n';
        const row = Row{ .start = self.start, .end = end, .next = end + @as(usize, @intFromBool(hard)), .soft = end < text.len and !hard };
        self.finished = end == text.len;
        self.start = row.next;
        return row;
    }
};

test "text layout distinguishes wrap affinity and avoids a phantom row before newline" {
    const layout = Layout{ .text = "abcdefghij\nxy\n", .columns = 5 };
    var iterator = layout.rows();
    try std.testing.expectEqual(Row{ .start = 0, .end = 5, .next = 5, .soft = true }, iterator.next().?);
    try std.testing.expectEqual(Row{ .start = 5, .end = 10, .next = 11, .soft = false }, iterator.next().?);
    try std.testing.expectEqual(Row{ .start = 11, .end = 13, .next = 14, .soft = false }, iterator.next().?);
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
