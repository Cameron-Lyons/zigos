const std = @import("std");

pub const block_alignment: usize = 16;

pub const BlockHeader = struct {
    size: usize,
    is_free: bool,
    next: ?*@This(),
    prev: ?*@This(),
};

pub const FreeLinks = struct {
    next: ?*BlockHeader,
    prev: ?*BlockHeader,
};

pub const minimum_free_data_size: usize = @sizeOf(FreeLinks);

pub fn alignSize(size: usize, alignment: usize) ?usize {
    if (alignment == 0 or (alignment & (alignment - 1)) != 0) return null;
    const rounded = std.math.add(usize, size, alignment - 1) catch return null;
    return rounded & ~(alignment - 1);
}

pub fn splitRemainder(
    total_data_size: usize,
    requested_data_size: usize,
    header_size: usize,
    minimum_data_size: usize,
) ?usize {
    const consumed = std.math.add(usize, requested_data_size, header_size) catch return null;
    const minimum_total = std.math.add(usize, consumed, minimum_data_size) catch return null;
    if (total_data_size < minimum_total) return null;
    return total_data_size - consumed;
}

test "heap sizes align without overflow" {
    try std.testing.expectEqual(@as(?usize, 16), alignSize(1, 16));
    try std.testing.expectEqual(@as(?usize, 16), alignSize(16, 16));
    try std.testing.expectEqual(@as(?usize, 32), alignSize(17, 16));
    try std.testing.expectEqual(@as(?usize, null), alignSize(std.math.maxInt(usize), 16));
    try std.testing.expectEqual(@as(?usize, null), alignSize(16, 0));
    try std.testing.expectEqual(@as(?usize, null), alignSize(16, 24));
}

test "heap block splitting accepts the exact reusable tail threshold" {
    const header_size = @sizeOf(BlockHeader);

    try std.testing.expectEqual(
        @as(?usize, null),
        splitRemainder(63, 16, header_size, minimum_free_data_size),
    );
    try std.testing.expectEqual(
        @as(?usize, 16),
        splitRemainder(64, 16, header_size, minimum_free_data_size),
    );
    try std.testing.expectEqual(
        @as(?usize, 32),
        splitRemainder(80, 16, header_size, minimum_free_data_size),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        splitRemainder(std.math.maxInt(usize), std.math.maxInt(usize), header_size, minimum_free_data_size),
    );
}

test "heap metadata preserves aligned payloads and holds free-list links" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(BlockHeader));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(FreeLinks));
    try std.testing.expectEqual(@as(usize, 0), @sizeOf(BlockHeader) % block_alignment);
    try std.testing.expect(minimum_free_data_size >= @sizeOf(FreeLinks));
    try std.testing.expect(block_alignment >= @alignOf(FreeLinks));
}
