const std = @import("std");

pub const CopyTextExactError = error{DestinationTooSmall};
pub const FNV1A_64_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
pub const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01B3;

pub fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

pub fn copyTextWithReserve(dest: []u8, src: []const u8, comptime reserve: usize) usize {
    const capacity = dest.len -| reserve;
    const len = @min(capacity, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

pub fn copyTextExact(dest: []u8, src: []const u8) CopyTextExactError!usize {
    if (src.len > dest.len) return error.DestinationTooSmall;
    @memcpy(dest[0..src.len], src);
    return src.len;
}

pub fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

pub fn fnv1a64(bytes: []const u8) u64 {
    return fnv1a64WithSeed(FNV1A_64_OFFSET_BASIS, bytes);
}

pub fn fnv1a64WithSeed(seed: u64, bytes: []const u8) u64 {
    var hash = seed;
    for (bytes) |byte| {
        hash = fnv1a64AppendByte(hash, byte);
    }
    return hash;
}

pub fn fnv1a64AppendByte(hash: u64, byte: u8) u64 {
    var next = hash;
    next ^= @as(u64, byte);
    next *%= FNV1A_64_PRIME;
    return next;
}

pub fn fnv1a64AppendU16LittleEndian(hash: u64, value: u16) u64 {
    return fnv1a64AppendIntegerLittleEndian(u16, hash, value);
}

pub fn fnv1a64AppendU32LittleEndian(hash: u64, value: u32) u64 {
    return fnv1a64AppendIntegerLittleEndian(u32, hash, value);
}

pub fn fnv1a64AppendU64LittleEndian(hash: u64, value: u64) u64 {
    return fnv1a64AppendIntegerLittleEndian(u64, hash, value);
}

fn fnv1a64AppendIntegerLittleEndian(comptime T: type, hash: u64, value: T) u64 {
    var next = hash;
    var remaining = value;
    inline for (0..@sizeOf(T)) |_| {
        next = fnv1a64AppendByte(next, @as(u8, @truncate(remaining & 0xFF)));
        remaining >>= 8;
    }
    return next;
}

pub fn bootProofFailure(comptime step: []const u8, err: anyerror) noreturn {
    std.debug.panic("boot proof failed: {s}: {s}", .{ step, @errorName(err) });
}

pub fn impossibleByInvariant(comptime message: []const u8) noreturn {
    std.debug.panic("impossible by invariant: {s}", .{message});
}

pub fn impossibleByInvariantError(comptime message: []const u8, err: anyerror) noreturn {
    std.debug.panic("impossible by invariant: {s}: {s}", .{ message, @errorName(err) });
}

test "copyTextExact rejects undersized destinations and preserves exact lengths" {
    const COPY_TEXT_TEST_BUFFER_BYTES: usize = 4;
    var buffer = [_]u8{0} ** COPY_TEXT_TEST_BUFFER_BYTES;

    try std.testing.expectEqual(@as(usize, COPY_TEXT_TEST_BUFFER_BYTES), try copyTextExact(&buffer, "zigo"));
    try std.testing.expectEqualStrings("zigo", &buffer);
    try std.testing.expectError(error.DestinationTooSmall, copyTextExact(buffer[0..3], "zigo"));
}

test "fnv1a helpers append integers as little endian bytes" {
    const seeded = fnv1a64("seed");

    var manual16 = seeded;
    manual16 = fnv1a64AppendByte(manual16, 0x34);
    manual16 = fnv1a64AppendByte(manual16, 0x12);
    try std.testing.expectEqual(manual16, fnv1a64AppendU16LittleEndian(seeded, 0x1234));

    var manual32 = seeded;
    manual32 = fnv1a64AppendByte(manual32, 0x78);
    manual32 = fnv1a64AppendByte(manual32, 0x56);
    manual32 = fnv1a64AppendByte(manual32, 0x34);
    manual32 = fnv1a64AppendByte(manual32, 0x12);
    try std.testing.expectEqual(manual32, fnv1a64AppendU32LittleEndian(seeded, 0x1234_5678));
}
