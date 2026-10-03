// Zig 0.17 orders an array's logical bits from its first element upward,
// independently of target byte order. These casts therefore always encode LE
// bytes, and the byte arrays retain alignment 1 for firmware and wire buffers.
pub fn readU16Le(bytes: []const u8) u16 {
    return @bitCast(bytes[0..2].*);
}

pub fn readU32Le(bytes: []const u8) u32 {
    return @bitCast(bytes[0..4].*);
}

pub fn readU64Le(bytes: []const u8) u64 {
    return @bitCast(bytes[0..8].*);
}

pub fn writeU16Le(bytes: []u8, value: u16) void {
    bytes[0..2].* = @bitCast(value);
}

pub fn writeU32Le(bytes: []u8, value: u32) void {
    bytes[0..4].* = @bitCast(value);
}

pub fn writeU64Le(bytes: []u8, value: u64) void {
    bytes[0..8].* = @bitCast(value);
}

test "little-endian helpers preserve wire bytes at runtime and comptime" {
    try checkWirePatterns();
    try comptime checkWirePatterns();
}

fn checkWirePatterns() !void {
    const std = @import("std");
    const source: [10]u8 align(8) = .{ 0xaa, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xaa };
    try std.testing.expectEqual(@as(u16, 0xcdef), readU16Le(source[1..]));
    try std.testing.expectEqual(@as(u32, 0x89abcdef), readU32Le(source[1..]));
    try std.testing.expectEqual(@as(u64, 0x0123456789abcdef), readU64Le(source[1..]));

    var dest: [10]u8 align(8) = @splat(0xaa);
    writeU16Le(dest[1..], 0x1234);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0x34, 0x12, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa }, &dest);

    dest = @splat(0xaa);
    writeU32Le(dest[1..], 0x12345678);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0x78, 0x56, 0x34, 0x12, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa }, &dest);

    dest = @splat(0xaa);
    writeU64Le(dest[1..], 0x0123456789abcdef);
    try std.testing.expectEqualSlices(u8, &source, &dest);
}
