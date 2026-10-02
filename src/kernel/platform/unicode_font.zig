const std = @import("std");
const unicode = @import("../../native/core/unicode.zig");
const data = @embedFile("fonts/zigos-bitmap.bin");
pub const Glyph = struct { rows: [16]u16, width: u5 };

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
