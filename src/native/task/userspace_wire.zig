const std = @import("std");
const binary_cursor = @import("binary_cursor");

pub const CopyTextExactError = error{DestinationTooSmall};
pub const FNV1A_64_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
pub const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01B3;
pub const Writer = binary_cursor.Writer;
pub const Reader = binary_cursor.Reader;

pub fn copyTextExact(dest: []u8, src: []const u8) CopyTextExactError!usize {
    if (src.len > dest.len) return error.DestinationTooSmall;
    @memcpy(dest[0..src.len], src);
    return src.len;
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

fn fnv1a64AppendIntegerLittleEndian(comptime T: type, hash: u64, value: T) u64 {
    var next = hash;
    var remaining = value;
    inline for (0..@sizeOf(T)) |_| {
        next = fnv1a64AppendByte(next, @as(u8, @truncate(remaining & 0xFF)));
        remaining >>= 8;
    }
    return next;
}

test "userspace wire cursor round-trips fixed and variable fields" {
    const Error = error{ Full, Corrupt };
    const TestWriter = Writer(Error, error.Full);
    const TestReader = Reader(Error, error.Corrupt);

    const TEST_WIRE_BUFFER_BYTES: usize = 16;
    var buffer: [TEST_WIRE_BUFFER_BYTES]u8 = undefined;
    var writer = TestWriter{ .buffer = &buffer };
    try writer.writeByte(0xAB);
    try writer.writeU16(0x1234);
    try writer.writeU32(0x5678_9ABC);
    try writer.writeBytes("ok");

    var reader = TestReader{ .buffer = buffer[0..writer.offset] };
    try std.testing.expectEqual(@as(u8, 0xAB), try reader.readByte());
    try std.testing.expectEqual(@as(u16, 0x1234), try reader.readU16());
    try std.testing.expectEqual(@as(u32, 0x5678_9ABC), try reader.readU32());
    try std.testing.expectEqualStrings("ok", try reader.readSlice(2));
}

test "userspace wire exact copy and fnv integer helpers are explicit" {
    const COPY_TEXT_TEST_BUFFER_BYTES: usize = 4;
    var buffer = [_]u8{0} ** COPY_TEXT_TEST_BUFFER_BYTES;
    try std.testing.expectEqual(@as(usize, COPY_TEXT_TEST_BUFFER_BYTES), try copyTextExact(&buffer, "zigo"));
    try std.testing.expectError(error.DestinationTooSmall, copyTextExact(buffer[0..3], "zigo"));

    const seeded = fnv1a64("seed");
    var manual = seeded;
    manual = fnv1a64AppendByte(manual, 0x78);
    manual = fnv1a64AppendByte(manual, 0x56);
    manual = fnv1a64AppendByte(manual, 0x34);
    manual = fnv1a64AppendByte(manual, 0x12);
    try std.testing.expectEqual(manual, fnv1a64AppendU32LittleEndian(seeded, 0x1234_5678));
}
