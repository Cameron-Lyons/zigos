const std = @import("std");
const unicode = @import("../../native/core/unicode.zig");
const bitmap = @import("bitmap_font.zig");
const data = @embedFile("fonts/zigos-bitmap.bin");
pub const Glyph = struct { rows: [16]u16, width: u5 };
pub const CELL_WIDTH = 12;

// Admission and scanout share this exact source-to-cell projection. A wider
// source glyph may be sampled into one cell, dropping some source columns.
pub const Projection = struct {
    source_width: u5,
    ink_width: u5,
    left: u5,

    pub inline fn init(source_width: u5, columns: u2) Projection {
        std.debug.assert((source_width == 8 or source_width == 16) and (columns == 1 or columns == 2));
        const span: usize = @as(usize, columns) * CELL_WIDTH;
        const ink_width = @min(@as(usize, source_width), span - 2);
        return .{ .source_width = source_width, .ink_width = @intCast(ink_width), .left = @intCast((span - ink_width) / 2) };
    }

    pub inline fn sourceBit(self: Projection, column: usize) u16 {
        if (column < self.left or column >= @as(usize, self.left) + self.ink_width) return 0;
        const source_x = (column - self.left) * self.source_width / self.ink_width;
        return @as(u16, 1) << @intCast(self.source_width - 1 - source_x);
    }

    pub inline fn sourceMask(self: Projection) u16 {
        var mask: u16 = 0;
        for (0..self.ink_width) |x| mask |= self.sourceBit(x + self.left);
        return mask;
    }
};

pub fn glyph(point: u21) Glyph {
    return lookup(point) orelse lookup(0xfffd).?;
}
fn lookup(point: u21) ?Glyph {
    var low: usize = 0;
    var high: usize = data.len / 36;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const tag = std.mem.readInt(u32, data[middle * 36 ..][0..4], .little);
        const cp = tag & 0x1fffff;
        if (cp == point) {
            var result = Glyph{ .rows = undefined, .width = if (tag & (1 << 21) != 0) 16 else 8 };
            for (&result.rows, 0..) |*row, index| row.* = std.mem.readInt(u16, data[middle * 36 + 4 + index * 2 ..][0..2], .little);
            return result;
        }
        if (cp < point) low = middle + 1 else high = middle;
    }
    return null;
}

pub fn cluster(bytes: []const u8) Glyph {
    const first = unicode.decode(bytes, 0) orelse return glyph(0xfffd);
    var result = glyph(first.point);
    var offset = first.end;
    while (offset < bytes.len) {
        const scalar = unicode.decode(bytes, offset) orelse return glyph(0xfffd);
        offset = scalar.end;
        if (unicode.invisible(scalar.point)) continue;
        // Keep a single explicit fallback for clusters requiring shaping;
        // combining accents use the source font's unadorned mark bitmaps.
        if (!unicode.overlayMark(scalar.point) or (scalar.point >= 0x1f3fb and scalar.point <= 0x1f3ff)) return glyph(0xfffd);
        const mark = lookup(scalar.point) orelse return glyph(0xfffd);
        if (mark.width > result.width) {
            for (&result.rows) |*row| row.* <<= @intCast((mark.width - result.width) / 2);
            result.width = mark.width;
        }
        for (&result.rows, mark.rows) |*row, ink| row.* |= ink << @intCast((result.width - mark.width) / 2);
    }
    return result;
}

// Trusted resource labels require source ink for every scalar. General text
// keeps its existing fallback/overlay behavior; admission must not confuse
// that fallback or a discarded scalar with the exact resource being approved.
pub fn supportsCluster(bytes: []const u8) bool {
    const first = unicode.decode(bytes, 0) orelse return false;
    // Scalar ASCII uses the optimized bitmap branch, with all five source
    // columns rendered. ASCII plus marks uses the Unicode branch below.
    if (first.point < 0x80 and first.end == bytes.len) {
        if (first.point < 0x20 or first.point > 0x7e) return false;
        const source = bitmap.glyph(@intCast(first.point));
        return first.point == ' ' or !std.mem.allEqual(u5, &source, 0);
    }
    var iterator = unicode.Iterator{ .text = bytes };
    const geometry = iterator.next() orelse return false;
    if (geometry.end != bytes.len or geometry.newline or geometry.tab) return false;
    if (unicode.invisible(first.point)) return false;
    const base = lookup(first.point) orelse return false;
    var final_width = base.width;
    var offset = first.end;
    while (offset < bytes.len) {
        const scalar = unicode.decode(bytes, offset) orelse return false;
        offset = scalar.end;
        if (!unicode.overlayMark(scalar.point) or
            (scalar.point >= 0x1f3fb and scalar.point <= 0x1f3ff) or
            unicode.invisible(scalar.point)) return false;
        const source = lookup(scalar.point) orelse return false;
        final_width = @max(final_width, source.width);
    }
    const mask = Projection.init(final_width, geometry.width).sourceMask();
    if (!retainedInk(base, final_width, mask)) return false;
    offset = first.end;
    while (offset < bytes.len) {
        const scalar = unicode.decode(bytes, offset).?;
        offset = scalar.end;
        if (!retainedInk(lookup(scalar.point).?, final_width, mask)) return false;
    }
    return true;
}

inline fn retainedInk(source: Glyph, final_width: u5, mask: u16) bool {
    // cluster() centers every source in the final promoted width. Check each
    // scalar there, before OR overlays can conceal a wholly discarded source.
    const shift: u4 = @intCast((final_width - source.width) / 2);
    for (source.rows) |row| if ((row << shift) & mask != 0) return true;
    return false;
}

test "Unicode font exact cluster admission preserves ink and rejects fallback shaping and discarded scalars" {
    for ([_][]const u8{ "a", "é", "界", "e\u{301}", "界\u{301}", "界\u{732}", "\u{1c0}", " " }) |text| try std.testing.expect(supportsCluster(text));
    for (0x20..0x7f) |point| {
        const text = [_]u8{@intCast(point)};
        try std.testing.expect(supportsCluster(&text));
    }
    for ([_][]const u8{
        "",          "\xff",      "\u{10fffc}",     "\u{10fffd}",
        "👩‍💻",
        "👨‍💻",
        "👍🏽",
        "e\u{200c}", "e\u{200d}", "e\u{fe0f}",      "e\u{e0100}",
        "\u{200c}",  "\u{a0}",    "\u{202f}",       " \u{301}",
        "e\u{732}",  "e\u{738}",  "\u{1c0}\u{730}",
    }) |text| try std.testing.expect(!supportsCluster(text));
    // Resource admission does not alter the general text renderer's fallback.
    try std.testing.expectEqualDeep(glyph(0xfffd), cluster("👩‍💻"));
    try std.testing.expectEqualDeep(cluster("e\u{200c}"), cluster("e\u{200d}"));
}

test "Unicode font shared projection rejects sampled marks and center shifted base ink" {
    try std.testing.expectEqual(@as(u16, 0xff), Projection.init(8, 1).sourceMask());
    try std.testing.expectEqual(@as(u16, 0xdada), Projection.init(16, 1).sourceMask());
    try std.testing.expectEqual(@as(u16, 0xffff), Projection.init(16, 2).sourceMask());
    const mark = lookup(0x732).?;
    try std.testing.expect(!std.mem.allEqual(u16, &mark.rows, 0));
    try std.testing.expect(!retainedInk(mark, 16, Projection.init(16, 1).sourceMask()));
    try std.testing.expect(retainedInk(mark, 16, Projection.init(16, 2).sourceMask()));
    const base = lookup(0x1c0).?;
    try std.testing.expect(retainedInk(base, 8, Projection.init(8, 1).sourceMask()));
    try std.testing.expect(!retainedInk(base, 16, Projection.init(16, 1).sourceMask()));
}

test "Unicode bitmap glyphs preserve narrow wide and combining ink" {
    try std.testing.expectEqual(@as(u5, 8), glyph('é').width);
    try std.testing.expectEqual(@as(u5, 16), glyph('界').width);
    try std.testing.expect(!std.meta.eql(glyph('é'), glyph('?')));
    try std.testing.expect(!std.meta.eql(cluster("e\u{301}"), glyph('e')));
    try std.testing.expectEqualDeep(glyph(0xfffd), cluster("👩‍💻"));
}

test "Unicode font records are sorted bounded and retain the replacement glyph" {
    try std.testing.expectEqual(@as(usize, 0), data.len % 36);
    var previous: u32 = 0;
    for (0..data.len / 36) |index| {
        const tag = std.mem.readInt(u32, data[index * 36 ..][0..4], .little);
        const point = tag & 0x1fffff;
        try std.testing.expect((index == 0 or point > previous) and point <= 0x10ffff and tag >> 22 == 0);
        previous = point;
        if (tag & (1 << 21) == 0) {
            for (0..16) |row| try std.testing.expect(std.mem.readInt(u16, data[index * 36 + 4 + row * 2 ..][0..2], .little) <= 0xff);
        }
    }
    try std.testing.expect(lookup(0xfffd) != null);
    try std.testing.expect(lookup(0x20000) != null);
}
