const std = @import("std");

pub const block_alignment: usize = 16;
pub const free_list_class_count: usize = 2;

pub const BlockHeader = struct {
    size: usize,
    state: u64,
    next: ?*@This(),
    prev: ?*@This(),
};

pub const FreeLinks = struct {
    next: ?*BlockHeader,
    prev: ?*BlockHeader,
};

pub const AlignedRange = struct {
    start: usize,
    end: usize,
};

pub const minimum_free_data_size: usize = @sizeOf(FreeLinks);
pub const block_state_allocated: u64 = 0x4c49_5645_424c_4f43;
pub const block_state_free: u64 = 0x4652_4545_424c_4f43;

pub fn freeListIndex(size: usize, large_block_threshold: usize) usize {
    return @intFromBool(size >= large_block_threshold);
}

pub fn allocationMarkerIndex(
    payload_address: usize,
    arena_start_address: usize,
    arena_size: usize,
    alignment: usize,
) ?usize {
    if (alignment == 0 or (alignment & (alignment - 1)) != 0) return null;
    if (payload_address < arena_start_address) return null;
    const offset = payload_address - arena_start_address;
    if (offset >= arena_size or offset % alignment != 0) return null;
    return offset / alignment;
}

pub fn alignSize(size: usize, alignment: usize) ?usize {
    if (alignment == 0 or (alignment & (alignment - 1)) != 0) return null;
    const rounded = std.math.add(usize, size, alignment - 1) catch return null;
    return rounded & ~(alignment - 1);
}

pub fn claimAlignedRange(
    cursor: usize,
    size: usize,
    alignment: usize,
    exclusive_end: usize,
) ?AlignedRange {
    if (size == 0) return null;
    const start = alignSize(cursor, alignment) orelse return null;
    const end = std.math.add(usize, start, size) catch return null;
    if (end > exclusive_end) return null;
    return .{ .start = start, .end = end };
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

test "aligned prefix claims are bounded and overflow safe" {
    try std.testing.expectEqual(
        @as(?AlignedRange, .{ .start = 0x1020, .end = 0x1060 }),
        claimAlignedRange(0x1011, 0x40, 16, 0x1100),
    );
    try std.testing.expectEqual(
        @as(?AlignedRange, .{ .start = 0x1100, .end = 0x1200 }),
        claimAlignedRange(0x10f1, 0x100, 256, 0x1200),
    );
    try std.testing.expectEqual(@as(?AlignedRange, null), claimAlignedRange(0x10f1, 0x101, 256, 0x1200));
    try std.testing.expectEqual(@as(?AlignedRange, null), claimAlignedRange(0x1000, 0, 16, 0x1200));
    try std.testing.expectEqual(@as(?AlignedRange, null), claimAlignedRange(0x1000, 16, 24, 0x1200));
    try std.testing.expectEqual(
        @as(?AlignedRange, null),
        claimAlignedRange(std.math.maxInt(usize) - 7, 16, 8, std.math.maxInt(usize)),
    );
}

test "heap metadata preserves aligned payloads and holds free-list links" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(BlockHeader));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(FreeLinks));
    try std.testing.expectEqual(@as(usize, 0), @sizeOf(BlockHeader) % block_alignment);
    try std.testing.expect(minimum_free_data_size >= @sizeOf(FreeLinks));
    try std.testing.expect(block_alignment >= @alignOf(FreeLinks));
}

test "heap allocation markers accept only aligned arena addresses" {
    try std.testing.expectEqual(@as(?usize, 0), allocationMarkerIndex(0x2000, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, 2), allocationMarkerIndex(0x2020, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, null), allocationMarkerIndex(0x1ff0, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, null), allocationMarkerIndex(0x2001, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, null), allocationMarkerIndex(0x3000, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, null), allocationMarkerIndex(0x2000, 0x2000, 4096, 0));
}

test "heap free-list classes separate sub-page and page-sized blocks" {
    const page_size: usize = 4096;

    try std.testing.expectEqual(@as(usize, 0), freeListIndex(page_size - 1, page_size));
    try std.testing.expectEqual(@as(usize, 1), freeListIndex(page_size, page_size));
    try std.testing.expectEqual(@as(usize, 1), freeListIndex(page_size * 4, page_size));
    try std.testing.expectEqual(@as(usize, 2), free_list_class_count);
}
