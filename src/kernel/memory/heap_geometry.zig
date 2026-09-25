const std = @import("std");

pub const block_alignment: usize = 16;
pub const maximum_heap_bytes: usize = 16 * 1024 * 1024;
pub const second_level_bits = 5;
pub const second_level_count = 1 << second_level_bits;
const linear_limit = block_alignment * second_level_count;
const linear_limit_log2 = std.math.log2_int(usize, linear_limit);
pub const first_level_count = std.math.log2_int(usize, maximum_heap_bytes) - linear_limit_log2 + 2;

pub const SizeClass = struct { first: u5, second: u5 };

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

// Free blocks map down to their containing class. Requests round up to a
// class boundary so every block in the selected class is large enough.
pub fn sizeClass(size: usize) SizeClass {
    std.debug.assert(size >= minimum_free_data_size and size <= maximum_heap_bytes);
    if (size < linear_limit) return .{ .first = 0, .second = @intCast(size / block_alignment) };
    const exponent = std.math.log2_int(usize, size);
    return .{
        .first = @intCast(exponent - linear_limit_log2 + 1),
        .second = @intCast((size >> (exponent - second_level_bits)) - second_level_count),
    };
}

pub fn allocationSize(size: usize) ?usize {
    if (size == 0 or size > maximum_heap_bytes) return null;
    const alignment = if (size < linear_limit)
        block_alignment
    else
        @as(usize, 1) << (std.math.log2_int(usize, size) - second_level_bits);
    const rounded = alignSize(size, alignment) orelse return null;
    return if (rounded <= maximum_heap_bytes) rounded else null;
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

test "heap size classes round requests up without unbounded internal fragmentation" {
    try std.testing.expect(allocationSize(0) == null);
    try std.testing.expect(allocationSize(maximum_heap_bytes + 1) == null);
    try std.testing.expect(allocationSize(std.math.maxInt(usize)) == null);
    try std.testing.expectEqual(@as(?usize, 16), allocationSize(1));
    try std.testing.expectEqual(@as(?usize, 528), allocationSize(513));
    try std.testing.expectEqual(@as(?usize, 4224), allocationSize(4097));
    try std.testing.expectEqual(@as(?usize, maximum_heap_bytes), allocationSize(maximum_heap_bytes));

    var size: usize = block_alignment;
    while (size <= maximum_heap_bytes) : (size += block_alignment) {
        const rounded = allocationSize(size).?;
        try std.testing.expect(rounded >= size);
        try std.testing.expectEqual(@as(usize, 0), rounded % block_alignment);
        try std.testing.expect(rounded - size <= @max(block_alignment - 1, size / second_level_count));
        const class = sizeClass(rounded);
        try std.testing.expect(class.first < first_level_count);
        if (rounded > block_alignment) {
            const preceding = sizeClass(rounded - block_alignment);
            try std.testing.expect(preceding.first < class.first or
                (preceding.first == class.first and preceding.second < class.second));
        }
    }
}
