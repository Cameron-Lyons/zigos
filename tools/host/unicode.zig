//! Regenerate pinned Unicode 18 tables and Zigos Bitmap without network access.
const std = @import("std");
const common = @import("common.zig");

const Pin = struct { name: []const u8, sha256: []const u8 };
const pins = [_]Pin{
    .{ .name = "GraphemeBreakProperty.txt", .sha256 = "0839dcb79e4ac639ecd538b1abf7c9d22e3f9dd265b7e182d33627aa4d75b45a" },
    .{ .name = "DerivedCoreProperties.txt", .sha256 = "09c928886a178fcafd93c29e4bd59073a058e5a100b716d425cb563ab50f68c9" },
    .{ .name = "emoji-data.txt", .sha256 = "80d00f8e616a0ef27fd6b8de3b758c06383b5d917e2977709578e68baf733bf1" },
    .{ .name = "EastAsianWidth.txt", .sha256 = "a0cf29eacd00cfcaec4381c6b7c281685f18dbb4e7ff82b4076ccb342ca839aa" },
    .{ .name = "GraphemeBreakTest.txt", .sha256 = "b0cf047ee94485bbdc846de2b902f5f8a815f6b674f9d04223cddadd91c9df31" },
    .{ .name = "UNICODE-LICENSE.txt", .sha256 = "e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96" },
    .{ .name = "unifont-18.0.01.hex.gz", .sha256 = "e66385c79a0b8b24a466f3129930e08a966a935b4bf3b28c6bb17a9df9bf791d" },
    .{ .name = "unifont_upper-18.0.01.hex.gz", .sha256 = "ef531f3675950380a92569beceb3af0a7efea05dbc5755a1d08cbd1dca83210f" },
    .{ .name = "UNIFONT-LICENSE.txt", .sha256 = "1e74cb82bf476843e97c2596297b04219b1a7e51f7238944a8c031cb9401fa87" },
};

const unicode_limit = 0x110000;
const Glyphs = std.AutoHashMap(u32, [36]u8);

pub fn run(ctx: *common.Context, args: []const []const u8) !void {
    try common.requireArgs(args, 1, 1);
    var files: [pins.len][]u8 = undefined;
    var loaded: usize = 0;
    defer for (files[0..loaded]) |data| ctx.allocator.free(data);
    for (pins, 0..) |pin, index| {
        const path = try std.fs.path.join(ctx.allocator, &.{ args[0], pin.name });
        defer ctx.allocator.free(path);
        files[index] = try ctx.read(path);
        loaded += 1;
        verifyDigest(files[index], pin.sha256) catch |err| {
            try ctx.warn("source digest mismatch: {s}\n", .{pin.name});
            return err;
        };
    }

    const properties = try ctx.allocator.alloc(u16, unicode_limit);
    defer ctx.allocator.free(properties);
    @memset(properties, 0);
    for (files[0..4], 0..) |data, index| try applyProperties(properties, data, @fromBackingInt(@intCast(index)));
    const ranges = try encodeProperties(ctx.allocator, properties);
    defer ctx.allocator.free(ranges);

    var glyphs = Glyphs.init(ctx.allocator);
    defer glyphs.deinit();
    for (files[6..8]) |compressed| {
        const data = try decompressGzip(ctx.allocator, compressed);
        defer ctx.allocator.free(data);
        try parseGlyphs(&glyphs, data);
    }
    const font = try encodeGlyphs(ctx.allocator, &glyphs);
    defer ctx.allocator.free(font);

    // Validate every input and prepare both outputs before changing checked-in data.
    try ctx.write("src/native/core/unicode_data/properties.bin", ranges);
    try ctx.write("src/native/core/unicode_data/GraphemeBreakTest.txt", files[4]);
    try ctx.write("src/native/core/unicode_data/UNICODE-LICENSE.txt", files[5]);
    try ctx.write("src/kernel/platform/fonts/zigos-bitmap.bin", font);
    try ctx.write("src/kernel/platform/fonts/UNIFONT-LICENSE.txt", files[8]);
    try ctx.print("{d} Unicode ranges; {d} font glyphs\n", .{ ranges.len / 6, glyphs.count() });
}

fn verifyDigest(data: []const u8, expected: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &hex, expected)) return error.SourceDigestMismatch;
}

const PropertySource = enum { grapheme, conjunct, emoji, width };

fn applyProperties(properties: []u16, data: []const u8, source: PropertySource) !void {
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        const comment = std.mem.indexOfScalar(u8, line, '#') orelse line.len;
        var fields = std.mem.splitScalar(u8, line[0..comment], ';');
        const span = trim(fields.next() orelse continue);
        const property = trim(fields.next() orelse continue);
        const bits: u16 = switch (source) {
            .grapheme => try graphemeBits(property),
            .conjunct => if (std.mem.eql(u8, property, "InCB")) try conjunctBits(trim(fields.next() orelse return error.MissingConjunctProperty)) else continue,
            .emoji => if (std.mem.eql(u8, property, "Extended_Pictographic")) 1 << 6 else if (std.mem.eql(u8, property, "Emoji_Presentation")) 1 << 8 else continue,
            .width => if (std.mem.eql(u8, property, "W") or std.mem.eql(u8, property, "F")) 1 << 7 else continue,
        };
        const delimiter = std.mem.indexOf(u8, span, "..");
        const first = try std.fmt.parseInt(u32, if (delimiter) |index| span[0..index] else span, 16);
        const last = if (delimiter) |index| try std.fmt.parseInt(u32, span[index + 2 ..], 16) else first;
        if (first > last or last >= properties.len) return error.InvalidCodePointRange;
        for (properties[first .. last + 1]) |*value| value.* |= bits;
    }
}

fn trim(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\r");
}

fn graphemeBits(name: []const u8) !u16 {
    const names = [_][]const u8{ "Other", "CR", "LF", "Control", "Extend", "ZWJ", "Regional_Indicator", "Prepend", "SpacingMark", "L", "V", "T", "LV", "LVT" };
    for (names, 0..) |candidate, index| if (std.mem.eql(u8, name, candidate)) return @intCast(index);
    return error.UnknownGraphemeProperty;
}

fn conjunctBits(name: []const u8) !u16 {
    if (std.mem.eql(u8, name, "Consonant")) return 1 << 4;
    if (std.mem.eql(u8, name, "Extend")) return 2 << 4;
    if (std.mem.eql(u8, name, "Linker")) return 3 << 4;
    return error.UnknownConjunctProperty;
}

fn encodeProperties(allocator: std.mem.Allocator, properties: []const u16) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    for (properties, 0..) |bits, code_point| {
        if (code_point + 1 < properties.len and properties[code_point + 1] == bits) continue;
        // Inclusive end and property bits form fixed six-byte little-endian records.
        try output.writer.writeInt(u32, @intCast(code_point), .little);
        try output.writer.writeInt(u16, bits, .little);
    }
    return output.toOwnedSlice();
}

fn decompressGzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var input: std.Io.Reader = .fixed(compressed);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    if (compressed.len == 0) return error.InvalidGzip;
    while (input.buffered().len != 0) {
        const start = output.written().len;
        var decompress: std.compress.flate.Decompress = .init(&input, .gzip, &.{});
        _ = decompress.reader.streamRemaining(&output.writer) catch |err| return decompress.err orelse err;
        const member = output.written()[start..];
        const metadata = decompress.container_metadata.gzip;
        if (metadata.crc != std.hash.Crc32.hash(member) or metadata.count != @as(u32, @truncate(member.len))) return error.InvalidGzipChecksum;
        // Like gzip.decompress, accept concatenated members and zero padding.
        while (input.buffered().len != 0 and input.buffered()[0] == 0) input.toss(1);
    }
    return output.toOwnedSlice();
}

fn parseGlyphs(glyphs: *Glyphs, data: []const u8) !void {
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) continue;
        const delimiter = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidGlyph;
        const code_point = try std.fmt.parseInt(u32, line[0..delimiter], 16);
        if (code_point < 0x20 or (code_point >= 0x7f and code_point < 0xa0)) continue;
        if (code_point >= unicode_limit) return error.InvalidGlyphCodePoint;
        const bitmap = line[delimiter + 1 ..];
        if (bitmap.len != 32 and bitmap.len != 64) return error.UnexpectedGlyphWidth;
        const row_digits = bitmap.len / 16;
        var record: [36]u8 = undefined;
        std.mem.writeInt(u32, record[0..4], code_point | (if (row_digits == 4) @as(u32, 1 << 21) else 0), .little);
        for (0..16) |row| {
            const bits = try std.fmt.parseInt(u16, bitmap[row * row_digits ..][0..row_digits], 16);
            std.mem.writeInt(u16, record[4 + row * 2 ..][0..2], bits, .little);
        }
        // The upper input replaces duplicate code points, matching the source generator.
        try glyphs.put(code_point, record);
    }
}

fn encodeGlyphs(allocator: std.mem.Allocator, glyphs: *const Glyphs) ![]u8 {
    const code_points = try allocator.alloc(u32, glyphs.count());
    defer allocator.free(code_points);
    var iterator = glyphs.keyIterator();
    var index: usize = 0;
    while (iterator.next()) |code_point| : (index += 1) code_points[index] = code_point.*;
    std.mem.sort(u32, code_points, {}, std.sort.asc(u32));
    const output = try allocator.alloc(u8, code_points.len * 36);
    for (code_points, 0..) |code_point, record_index| @memcpy(output[record_index * 36 ..][0..36], &glyphs.get(code_point).?);
    return output;
}

test "Unicode sources combine property bits and inclusive little-endian ranges" {
    var properties: [8]u16 = @splat(0);
    try applyProperties(&properties, "# header\n 0001..0002 ; Extend # comment\n0005 ; CR\r\n", .grapheme);
    try applyProperties(&properties, "0001 ; InCB ; Linker\n0002 ; InCB ; Consonant\n0006 ; Alphabetic\n", .conjunct);
    try applyProperties(&properties, "0002..0003 ; Extended_Pictographic\n0003 ; Emoji_Presentation\n0006 ; Emoji\n", .emoji);
    try applyProperties(&properties, "0003 ; W\n0004 ; F\n0007 ; A\n", .width);
    try std.testing.expectEqualSlices(u16, &.{ 0, 0x34, 0x54, 0x1c0, 0x80, 1, 0, 0 }, &properties);
    const encoded = try encodeProperties(std.testing.allocator, &properties);
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, &.{
        0, 0, 0, 0, 0,    0,
        1, 0, 0, 0, 0x34, 0,
        2, 0, 0, 0, 0x54, 0,
        3, 0, 0, 0, 0xc0, 1,
        4, 0, 0, 0, 0x80, 0,
        5, 0, 0, 0, 1,    0,
        7, 0, 0, 0, 0,    0,
    }, encoded);
    try std.testing.expectError(error.InvalidCodePointRange, applyProperties(&properties, "0008 ; LF", .grapheme));
    try std.testing.expectError(error.UnknownGraphemeProperty, applyProperties(&properties, "0001 ; Invalid", .grapheme));
}

test "font records sort code points, exclude controls, preserve rows and replace duplicates" {
    var glyphs = Glyphs.init(std.testing.allocator);
    defer glyphs.deinit();
    try parseGlyphs(&glyphs, "007F:00000000000000000000000000000000\n" ++
        "001F:00000000000000000000000000000000\n" ++
        "0100:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n" ++
        "0020:0102030405060708090A0B0C0D0E0F10\n" ++
        "0021:00000000000000000000000000000000\n");
    try parseGlyphs(&glyphs, "0021:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n");
    const font = try encodeGlyphs(std.testing.allocator, &glyphs);
    defer std.testing.allocator.free(font);
    try std.testing.expectEqual(@as(usize, 108), font.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0, 0, 0 }, font[0..4]);
    for (0..16) |row| try std.testing.expectEqualSlices(u8, &.{ @intCast(row + 1), 0 }, font[4 + row * 2 ..][0..2]);
    try std.testing.expectEqualSlices(u8, &.{ 0x21, 0, 0, 0 }, font[36..40]);
    for (0..16) |row| try std.testing.expectEqualSlices(u8, &.{ 0xff, 0 }, font[40 + row * 2 ..][0..2]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0x20, 0, 0x23, 1, 0x67, 0x45, 0xab, 0x89, 0xef, 0xcd }, font[72..84]);
    try std.testing.expectError(error.UnexpectedGlyphWidth, parseGlyphs(&glyphs, "0020:0000"));
}

test "pinned source digests reject modified data" {
    try verifyDigest("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    try std.testing.expectError(error.SourceDigestMismatch, verifyDigest("abd", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

test "native gzip decoder validates checksums and supports multiple members" {
    const compressed = [_]u8{
        0x1f, 0x8b, 0x08, 0,    0,    0,   0,    0,    0,    3,
        0x01, 0x0c, 0,    0xf3, 0xff, 'H', 'e',  'l',  'l',  'o',
        ' ',  'w',  'o',  'r',  'l',  'd', '\n', 0xd5, 0xe0, 0x39,
        0xb7, 0x0c, 0,    0,    0,
    };
    var members: [compressed.len * 2 + 2]u8 = @splat(0);
    @memcpy(members[0..compressed.len], &compressed);
    @memcpy(members[compressed.len..][0..compressed.len], &compressed);
    const decoded = try decompressGzip(std.testing.allocator, &members);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("Hello world\nHello world\n", decoded);
    var corrupted = compressed;
    corrupted[27] ^= 1;
    try std.testing.expectError(error.InvalidGzipChecksum, decompressGzip(std.testing.allocator, &corrupted));
    try std.testing.expectError(error.InvalidGzip, decompressGzip(std.testing.allocator, ""));
}

test "generator requires exactly one offline source directory" {
    var environ = std.process.Environ.Map.init(std.testing.allocator);
    defer environ.deinit();
    var ctx: common.Context = .{ .allocator = std.testing.allocator, .io = std.testing.io, .environ = &environ };
    try std.testing.expectError(error.InvalidArguments, run(&ctx, &.{}));
    try std.testing.expectError(error.InvalidArguments, run(&ctx, &.{ "sources", "extra" }));
}
