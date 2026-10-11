const std = @import("std");

// Root format 6 binds the log and root checksums to seed-zero XXH64. These
// detect accidental corruption; signed metadata and SHA-256 content addresses
// remain the authentication boundary. Four independent lanes avoid FNV's
// byte-at-a-time dependency across large checkpoints.
pub fn checksumBytes(bytes: []const u8) u64 {
    return std.hash.XxHash64.hash(0, bytes);
}

test "volume XXH64 checksum has fixed portable known answers" {
    const vectors = .{
        .{ "", @as(u64, 0xef46db3751d8e999) },
        .{ "a", @as(u64, 0xd24ec4f1a98c6e5b) },
        .{ "abc", @as(u64, 0x44bc2cf5ad770999) },
        .{ "message digest", @as(u64, 0x066ed728fceeb3be) },
        .{ "abcdefghijklmnopqrstuvwxyz", @as(u64, 0xcfe1f278fa89835c) },
        .{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @as(u64, 0xaaa46907d3047814) },
        .{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", @as(u64, 0xe04a477f19ee145d) },
    };
    inline for (vectors) |vector| try std.testing.expectEqual(vector[1], checksumBytes(vector[0]));
}

test "volume checksum covers unaligned slices every stripe boundary and mutation" {
    var storage: [4096 + 8]u8 = undefined;
    for (&storage, 0..) |*byte, index| byte.* = @truncate(index * 17 + index / 13);
    for (0..8) |offset| {
        for ([_]usize{ 0, 1, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 4096 }) |length| {
            const bytes = storage[offset..][0..length];
            var streamed = std.hash.XxHash64.init(0);
            for (bytes) |byte| streamed.update(&[_]u8{byte});
            const before = checksumBytes(bytes);
            try std.testing.expectEqual(streamed.final(), before);
            if (length == 0) continue;
            for ([_]usize{ 0, length / 2, length - 1 }) |index| {
                bytes[index] ^= 1;
                try std.testing.expect(checksumBytes(bytes) != before);
                bytes[index] ^= 1;
            }
        }
    }
}
