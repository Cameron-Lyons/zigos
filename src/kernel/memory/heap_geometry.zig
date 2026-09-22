const std = @import("std");

pub const block_alignment: usize = 16;
pub const size_classes = [_]usize{ 32, 64, 128, 256, 512, 1024, 2048, 4096 };
pub const free_list_class_count: usize = size_classes.len + 1;

pub const AlignedRange = struct {
    start: usize,
    end: usize,
};

pub const granule: usize = 32;
pub const payload_has_no_header = true;
pub const minimum_free_data_size: usize = granule;

pub fn freeListIndex(size: usize, large_block_threshold: usize) usize {
    if (size > large_block_threshold) return size_classes.len;
    return sizeClassIndex(size);
}

pub fn sizeClassIndex(size: usize) usize {
    for (size_classes, 0..) |limit, index| {
        if (size <= limit) return index;
    }
    return size_classes.len;
}

pub fn sizeClassBytes(index: usize) ?usize {
    if (index >= size_classes.len) return null;
    return size_classes[index];
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
    const header_size: usize = 0;

    try std.testing.expectEqual(
        @as(?usize, null),
        splitRemainder(63, 32, header_size, minimum_free_data_size),
    );
    try std.testing.expectEqual(
        @as(?usize, 32),
        splitRemainder(64, 32, header_size, minimum_free_data_size),
    );
    try std.testing.expectEqual(
        @as(?usize, 48),
        splitRemainder(80, 32, header_size, minimum_free_data_size),
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

test "heap metadata stays outside the payload" {
    try std.testing.expect(payload_has_no_header);
    try std.testing.expectEqual(@as(usize, 32), granule);
    try std.testing.expectEqual(@as(usize, 0), granule % block_alignment);
    try std.testing.expect(minimum_free_data_size >= granule);
}

test "heap allocation markers accept only aligned arena addresses" {
    try std.testing.expectEqual(@as(?usize, 0), allocationMarkerIndex(0x2000, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, 2), allocationMarkerIndex(0x2020, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, null), allocationMarkerIndex(0x1ff0, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, null), allocationMarkerIndex(0x2001, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, null), allocationMarkerIndex(0x3000, 0x2000, 4096, 16));
    try std.testing.expectEqual(@as(?usize, null), allocationMarkerIndex(0x2000, 0x2000, 4096, 0));
}

test "heap free-list classes round small blocks onto exact size classes" {
    const page_size: usize = 4096;

    try std.testing.expectEqual(@as(usize, 0), freeListIndex(16, page_size));
    try std.testing.expectEqual(@as(usize, 0), freeListIndex(32, page_size));
    try std.testing.expectEqual(@as(usize, 1), freeListIndex(33, page_size));
    try std.testing.expectEqual(@as(usize, 7), freeListIndex(page_size, page_size));
    try std.testing.expectEqual(@as(usize, size_classes.len), freeListIndex(page_size + 1, page_size));
    try std.testing.expectEqual(@as(usize, size_classes.len), freeListIndex(128, 64));
    try std.testing.expectEqual(@as(?usize, 32), sizeClassBytes(0));
    try std.testing.expectEqual(@as(?usize, null), sizeClassBytes(size_classes.len));
    try std.testing.expectEqual(size_classes.len + 1, free_list_class_count);
}
