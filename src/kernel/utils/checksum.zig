pub fn sum8IsZero(bytes: []const u8) bool {
    const lanes = 32;
    const ByteLanes = @Vector(lanes, u8);
    var sums: ByteLanes = @splat(0);
    const vector_end = bytes.len & ~@as(usize, lanes - 1);
    var offset: usize = 0;
    while (offset < vector_end) : (offset += lanes) {
        // Only complete chunks are loaded: even a slice ending at an unmapped
        // page needs no padding or reads beyond its extent.
        const chunk: [lanes]u8 = bytes[offset..][0..lanes].*;
        sums +%= @as(ByteLanes, @bitCast(chunk));
    }
    // Each lane already wraps modulo 256. Widen before reducing so its maximum
    // horizontal sum, 32 * 255 = 8160, also fits with runtime overflow checks.
    var sum: u8 = @truncate(@reduce(.Add, @as(@Vector(lanes, u16), sums)));
    // At most 31 bytes remain. Finite contiguous chunks also keep the linker
    // from expanding an unrolled scalar tail into strided byte gathers.
    offset = vector_end;
    inline for (.{ 16, 8, 4, 2, 1 }) |tail_lanes| {
        if (bytes.len - offset >= tail_lanes) {
            const chunk: [tail_lanes]u8 = bytes[offset..][0..tail_lanes].*;
            const tail: @Vector(tail_lanes, u8) = @bitCast(chunk);
            sum +%= @as(u8, @truncate(@reduce(.Add, @as(@Vector(tail_lanes, u16), tail))));
            offset += tail_lanes;
        }
    }
    return sum == 0;
}

test "checksum contiguous chunks cover every short length alignment and tail" {
    const std = @import("std");
    var storage: [64 + 32 * 6 + 1]u8 = undefined;
    for (0..64) |alignment| {
        for (0..32 * 6 + 2) |length| {
            for (&storage, 0..) |*byte, index| byte.* = @truncate(index * 17 + length * 3 + 0x95);
            const bytes = storage[alignment..][0..length];
            var expected: u8 = 0;
            for (bytes) |byte| expected +%= byte;
            try std.testing.expectEqual(expected == 0, sum8IsZero(bytes));
            if (length == 0) continue;

            bytes[length - 1] -%= expected;
            try std.testing.expect(sum8IsZero(bytes));
            // Corrupt both edges and the middle, including complete-vector
            // bytes and the tail, after constructing a valid checksum.
            for ([_]usize{ 0, length / 2, length - 1 }) |index| {
                bytes[index] ^= 1;
                try std.testing.expect(!sum8IsZero(bytes));
                bytes[index] ^= 1;
            }
        }
    }
}

test "checksum wraps repeated byte lanes before its bounded widened reduction" {
    const std = @import("std");
    const storage: [32 * 300 + 33]u8 = @splat(255);
    for ([_]usize{ 31, 32, 33, 8191, 8192, 8224, 8255, 8256, 8257, storage.len }) |length| {
        var expected: u8 = 0;
        for (storage[0..length]) |byte| expected +%= byte;
        try std.testing.expectEqual(expected == 0, sum8IsZero(storage[0..length]));
    }
}

pub fn finishSum8(bytes: []u8, checksum_index: usize) void {
    finishSum8Prefix(bytes, checksum_index, bytes.len);
}

pub fn finishSum8Prefix(bytes: []u8, checksum_index: usize, length: usize) void {
    bytes[checksum_index] = 0;
    var sum: u8 = 0;
    for (bytes[0..length]) |byte| {
        sum +%= byte;
    }
    bytes[checksum_index] = 0 -% sum;
}
