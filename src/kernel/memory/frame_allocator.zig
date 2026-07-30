const std = @import("std");

pub const FrameRun = struct {
    base: u32,
    count: u32,
};

pub const Stats = struct {
    total: u32,
    reserved: u32,
    allocated: u32,
    free: u32,
};

pub const Error = error{
    InvalidRun,
    Unaligned,
    OutOfRange,
    FrameAllocated,
    FrameReserved,
    NotAllocated,
};

pub fn Fixed(comptime memory_bytes: u32, comptime page_size: u32) type {
    if (page_size == 0 or (page_size & (page_size - 1)) != 0) {
        @compileError("page_size must be a power of two");
    }
    if (memory_bytes == 0 or memory_bytes % page_size != 0) {
        @compileError("memory_bytes must be a non-zero multiple of page_size");
    }

    const frame_count: u32 = memory_bytes / page_size;
    const bitmap_word_bits: u32 = @bitSizeOf(u32);
    const bitmap_word_count: usize = @intCast((frame_count + bitmap_word_bits - 1) / bitmap_word_bits);

    return struct {
        const Self = @This();

        reserved_bitmap: [bitmap_word_count]u32 = [_]u32{0} ** bitmap_word_count,
        allocated_bitmap: [bitmap_word_count]u32 = [_]u32{0} ** bitmap_word_count,
        reserved_count: u32 = 0,
        allocated_count: u32 = 0,
        search_frame_hint: u32 = 0,

        pub const total_frames = frame_count;
        pub const bytes_per_frame = page_size;

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.* = init();
        }

        pub fn reserve(self: *Self, run: FrameRun) Error!void {
            const start = try validateRun(run);

            var frame = start;
            while (frame < start + run.count) : (frame += 1) {
                if (self.bitIsSet(&self.allocated_bitmap, frame)) {
                    return error.FrameAllocated;
                }
            }

            frame = start;
            while (frame < start + run.count) : (frame += 1) {
                if (!self.bitIsSet(&self.reserved_bitmap, frame)) {
                    self.setBit(&self.reserved_bitmap, frame);
                    self.reserved_count += 1;
                }
            }

            if (start <= self.search_frame_hint and self.search_frame_hint < start + run.count) {
                self.search_frame_hint = if (start + run.count == frame_count) 0 else start + run.count;
            }
        }

        pub fn makeAvailable(self: *Self, run: FrameRun) Error!void {
            const start = try validateRun(run);

            var frame = start;
            while (frame < start + run.count) : (frame += 1) {
                if (self.bitIsSet(&self.allocated_bitmap, frame)) {
                    return error.FrameAllocated;
                }
            }

            frame = start;
            while (frame < start + run.count) : (frame += 1) {
                if (self.bitIsSet(&self.reserved_bitmap, frame)) {
                    self.clearBit(&self.reserved_bitmap, frame);
                    self.reserved_count -= 1;
                }
            }
            self.search_frame_hint = @min(self.search_frame_hint, start);
        }

        pub fn allocate(self: *Self, count: u32) ?FrameRun {
            if (count == 0 or count > frame_count) return null;

            const start = self.findRun(self.search_frame_hint, frame_count, count) orelse
                self.findRun(0, frame_count, count) orelse return null;

            self.setRange(&self.allocated_bitmap, start, count);
            self.allocated_count += count;
            self.search_frame_hint = if (start + count == frame_count) 0 else start + count;

            return .{
                .base = start * page_size,
                .count = count,
            };
        }

        pub fn release(self: *Self, run: FrameRun) Error!void {
            const start = try validateRun(run);

            var frame = start;
            while (frame < start + run.count) : (frame += 1) {
                if (self.bitIsSet(&self.reserved_bitmap, frame)) {
                    return error.FrameReserved;
                }
                if (!self.bitIsSet(&self.allocated_bitmap, frame)) {
                    return error.NotAllocated;
                }
            }

            frame = start;
            while (frame < start + run.count) : (frame += 1) {
                self.clearBit(&self.allocated_bitmap, frame);
            }
            self.allocated_count -= run.count;
            self.search_frame_hint = start;
        }

        pub fn stats(self: *const Self) Stats {
            return .{
                .total = frame_count,
                .reserved = self.reserved_count,
                .allocated = self.allocated_count,
                .free = frame_count - self.reserved_count - self.allocated_count,
            };
        }

        pub fn isReserved(self: *const Self, frame_address: u32) bool {
            if (frame_address % page_size != 0 or frame_address >= memory_bytes) return false;
            return self.bitIsSet(&self.reserved_bitmap, frame_address / page_size);
        }

        pub fn isAllocated(self: *const Self, frame_address: u32) bool {
            if (frame_address % page_size != 0 or frame_address >= memory_bytes) return false;
            return self.bitIsSet(&self.allocated_bitmap, frame_address / page_size);
        }

        fn validateRun(run: FrameRun) Error!u32 {
            if (run.count == 0) return error.InvalidRun;
            if (run.base % page_size != 0) return error.Unaligned;

            const start = run.base / page_size;
            if (start >= frame_count or run.count > frame_count - start) {
                return error.OutOfRange;
            }
            return start;
        }

        fn findRun(self: *const Self, start: u32, end: u32, count: u32) ?u32 {
            if (start >= end or count > end - start) return null;
            if (count == 1) return self.findFreeFrame(start, end);

            var candidate: u32 = start;
            var contiguous: u32 = 0;

            var word_index = start / bitmap_word_bits;
            const last_word_index = (end - 1) / bitmap_word_bits;
            while (word_index <= last_word_index) : (word_index += 1) {
                const word_start = word_index * bitmap_word_bits;
                const range_start = @max(start, word_start);
                const range_end = word_start + @min(bitmap_word_bits, end - word_start);
                const range_mask = wordRangeMask(range_start - word_start, range_end - word_start);
                const available = ~(self.reserved_bitmap[word_index] | self.allocated_bitmap[word_index]) & range_mask;

                if (available == 0) {
                    contiguous = 0;
                    continue;
                }

                if (available == range_mask) {
                    if (contiguous == 0) candidate = range_start;
                    contiguous += range_end - range_start;
                    if (contiguous >= count) return candidate;
                    continue;
                }

                var frame = range_start;
                while (frame < range_end) : (frame += 1) {
                    const bit: u5 = @intCast(frame - word_start);
                    if ((available & (@as(u32, 1) << bit)) == 0) {
                        contiguous = 0;
                        continue;
                    }

                    if (contiguous == 0) candidate = frame;
                    contiguous += 1;
                    if (contiguous == count) return candidate;
                }
            }
            return null;
        }

        fn findFreeFrame(self: *const Self, start: u32, end: u32) ?u32 {
            var word_index = start / bitmap_word_bits;
            const last_word_index = (end - 1) / bitmap_word_bits;
            while (word_index <= last_word_index) : (word_index += 1) {
                const word_start = word_index * bitmap_word_bits;
                const range_start = @max(start, word_start);
                const range_end = word_start + @min(bitmap_word_bits, end - word_start);
                const range_mask = wordRangeMask(range_start - word_start, range_end - word_start);
                const available = ~(self.reserved_bitmap[word_index] | self.allocated_bitmap[word_index]) & range_mask;
                if (available == 0) continue;

                const free_bit: u32 = @intCast(@ctz(available));
                return word_start + free_bit;
            }
            return null;
        }

        fn setRange(_: *Self, bitmap: *[bitmap_word_count]u32, start: u32, count: u32) void {
            const end = start + count;
            var word_index = start / bitmap_word_bits;
            const last_word_index = (end - 1) / bitmap_word_bits;
            while (word_index <= last_word_index) : (word_index += 1) {
                const word_start = word_index * bitmap_word_bits;
                const range_start = @max(start, word_start);
                const range_end = word_start + @min(bitmap_word_bits, end - word_start);
                bitmap[word_index] |= wordRangeMask(range_start - word_start, range_end - word_start);
            }
        }

        fn bitIsSet(_: *const Self, bitmap: *const [bitmap_word_count]u32, frame: u32) bool {
            const word: usize = @intCast(frame / bitmap_word_bits);
            const bit: u5 = @truncate(frame % bitmap_word_bits);
            return (bitmap[word] & (@as(u32, 1) << bit)) != 0;
        }

        fn setBit(_: *Self, bitmap: *[bitmap_word_count]u32, frame: u32) void {
            const word: usize = @intCast(frame / bitmap_word_bits);
            const bit: u5 = @truncate(frame % bitmap_word_bits);
            bitmap[word] |= @as(u32, 1) << bit;
        }

        fn clearBit(_: *Self, bitmap: *[bitmap_word_count]u32, frame: u32) void {
            const word: usize = @intCast(frame / bitmap_word_bits);
            const bit: u5 = @truncate(frame % bitmap_word_bits);
            bitmap[word] &= ~(@as(u32, 1) << bit);
        }

        fn wordRangeMask(start_bit: u32, end_bit: u32) u32 {
            return lowBitsMask(end_bit) & ~lowBitsMask(start_bit);
        }

        fn lowBitsMask(bit_count: u32) u32 {
            if (bit_count >= bitmap_word_bits) return std.math.maxInt(u32);
            const shift: u5 = @intCast(bit_count);
            return (@as(u32, 1) << shift) - 1;
        }
    };
}

test "reservations and allocations have exact independent accounting" {
    const Allocator = Fixed(16 * 4096, 4096);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 3 });
    try allocator.reserve(.{ .base = 2 * 4096, .count = 2 });

    const run = allocator.allocate(2).?;
    try std.testing.expectEqual(@as(u32, 4 * 4096), run.base);
    try std.testing.expectEqual(@as(u32, 2), run.count);
    try std.testing.expect(allocator.isReserved(3 * 4096));
    try std.testing.expect(allocator.isAllocated(5 * 4096));
    try std.testing.expectEqual(Stats{
        .total = 16,
        .reserved = 4,
        .allocated = 2,
        .free = 10,
    }, allocator.stats());
}

test "released runs are reusable and double frees are rejected" {
    const Allocator = Fixed(8 * 4096, 4096);
    var allocator = Allocator.init();

    const first = allocator.allocate(3).?;
    try allocator.release(first);
    try std.testing.expectError(error.NotAllocated, allocator.release(first));

    const reused = allocator.allocate(3).?;
    try std.testing.expectEqual(first, reused);
    try std.testing.expectEqual(@as(u32, 3), allocator.stats().allocated);
}

test "contiguous allocation respects fragmentation and physical boundaries" {
    const Allocator = Fixed(8 * 4096, 4096);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 1 * 4096, .count = 1 });
    try allocator.reserve(.{ .base = 3 * 4096, .count = 1 });
    try allocator.reserve(.{ .base = 5 * 4096, .count = 1 });
    try allocator.reserve(.{ .base = 7 * 4096, .count = 1 });

    try std.testing.expect(allocator.allocate(2) == null);
    try std.testing.expectEqual(@as(u32, 0), allocator.allocate(1).?.base);
    try std.testing.expectEqual(@as(u32, 2 * 4096), allocator.allocate(1).?.base);
}

test "single-frame allocation skips unavailable bitmap words" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(96 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 64 });
    allocator.search_frame_hint = 0;

    const run = allocator.allocate(1).?;
    try std.testing.expectEqual(@as(u32, 64 * page_size), run.base);
    try std.testing.expectEqual(@as(u32, 1), run.count);
}

test "single-frame allocation wraps from a non-word-aligned hint" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(70 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 2 });
    try allocator.reserve(.{ .base = 3 * page_size, .count = 67 });
    allocator.search_frame_hint = 33;

    try std.testing.expectEqual(@as(u32, 2 * page_size), allocator.allocate(1).?.base);
}

test "contiguous allocation wraps from a non-word-aligned hint" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(70 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 2 });
    try allocator.reserve(.{ .base = 5 * page_size, .count = 65 });
    allocator.search_frame_hint = 33;

    try std.testing.expectEqual(@as(u32, 2 * page_size), allocator.allocate(3).?.base);
}

test "contiguous allocation crosses bitmap word boundaries" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(96 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 30 });
    try allocator.reserve(.{ .base = 35 * page_size, .count = 61 });
    allocator.search_frame_hint = 0;

    const run = allocator.allocate(5).?;
    try std.testing.expectEqual(@as(u32, 30 * page_size), run.base);
    try std.testing.expectEqual(@as(u32, 5), run.count);
    for (30..35) |frame| {
        try std.testing.expect(allocator.isAllocated(@intCast(frame * page_size)));
    }
    try std.testing.expect(!allocator.isAllocated(29 * page_size));
    try std.testing.expect(!allocator.isAllocated(35 * page_size));
}

test "contiguous allocation consumes complete free bitmap words" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(128 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 32 });
    try allocator.reserve(.{ .base = 96 * page_size, .count = 32 });
    allocator.search_frame_hint = 0;

    const run = allocator.allocate(64).?;
    try std.testing.expectEqual(@as(u32, 32 * page_size), run.base);
    try std.testing.expectEqual(@as(u32, 64), run.count);
    try std.testing.expect(allocator.isAllocated(32 * page_size));
    try std.testing.expect(allocator.isAllocated(95 * page_size));
}

test "fragmented bitmap rejects unavailable contiguous runs" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(64 * page_size, page_size);
    var allocator = Allocator.init();

    var frame: u32 = 0;
    while (frame < Allocator.total_frames) : (frame += 2) {
        try allocator.reserve(.{ .base = frame * page_size, .count = 1 });
    }

    try std.testing.expectEqual(@as(u32, page_size), allocator.allocate(1).?.base);
    try std.testing.expect(allocator.allocate(2) == null);
}

test "partial final bitmap word never exposes out-of-range frames" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(35 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 34 });
    allocator.search_frame_hint = 0;

    try std.testing.expectEqual(@as(u32, 34 * page_size), allocator.allocate(1).?.base);
    try std.testing.expect(allocator.allocate(1) == null);
}

test "contiguous allocation can consume a partial final bitmap word" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(35 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 32 });

    const run = allocator.allocate(3).?;
    try std.testing.expectEqual(@as(u32, 32 * page_size), run.base);
    try std.testing.expectEqual(@as(u32, 3), run.count);
    try std.testing.expectEqual(@as(u32, 35), allocator.stats().reserved + allocator.stats().allocated);
}

test "partially allocated run release is rejected transactionally" {
    const Allocator = Fixed(8 * 4096, 4096);
    var allocator = Allocator.init();

    const run = allocator.allocate(2).?;
    try std.testing.expectError(error.NotAllocated, allocator.release(.{
        .base = run.base,
        .count = 3,
    }));
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().allocated);
    try std.testing.expect(allocator.isAllocated(run.base));
    try std.testing.expect(allocator.isAllocated(run.base + 4096));
}

test "zero misaligned and out-of-range releases are rejected" {
    const Allocator = Fixed(8 * 4096, 4096);
    var allocator = Allocator.init();

    try std.testing.expectError(error.InvalidRun, allocator.release(.{
        .base = 0,
        .count = 0,
    }));
    try std.testing.expectError(error.Unaligned, allocator.release(.{
        .base = 1,
        .count = 1,
    }));
    try std.testing.expectError(error.OutOfRange, allocator.release(.{
        .base = 8 * 4096,
        .count = 1,
    }));
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().allocated);
}

test "reserved frames cannot be released as allocations" {
    const Allocator = Fixed(8 * 4096, 4096);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 2 * 4096, .count = 2 });
    try std.testing.expectError(error.FrameReserved, allocator.release(.{
        .base = 2 * 4096,
        .count = 1,
    }));
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().reserved);
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().allocated);
}

test "reservation over a live allocation is rejected transactionally" {
    const Allocator = Fixed(8 * 4096, 4096);
    var allocator = Allocator.init();

    _ = allocator.allocate(1).?;
    try std.testing.expectError(error.FrameAllocated, allocator.reserve(.{
        .base = 0,
        .count = 2,
    }));
    try std.testing.expect(!allocator.isReserved(0));
    try std.testing.expect(!allocator.isReserved(4096));
    try std.testing.expectEqual(Stats{
        .total = 8,
        .reserved = 0,
        .allocated = 1,
        .free = 7,
    }, allocator.stats());
}

test "allocator reports exhaustion without changing statistics" {
    const Allocator = Fixed(4 * 4096, 4096);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 1 });
    _ = allocator.allocate(3).?;
    const before = allocator.stats();
    try std.testing.expect(allocator.allocate(1) == null);
    try std.testing.expectEqual(before, allocator.stats());
}

test "fail-closed availability opens only declared firmware runs" {
    const Allocator = Fixed(8 * 4096, 4096);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 8 });
    try allocator.makeAvailable(.{ .base = 2 * 4096, .count = 3 });
    try allocator.makeAvailable(.{ .base = 3 * 4096, .count = 2 });

    try std.testing.expectEqual(Stats{
        .total = 8,
        .reserved = 5,
        .allocated = 0,
        .free = 3,
    }, allocator.stats());
    try std.testing.expectEqual(@as(u32, 2 * 4096), allocator.allocate(3).?.base);
    try std.testing.expect(allocator.allocate(1) == null);
    try std.testing.expectError(error.FrameAllocated, allocator.makeAvailable(.{
        .base = 2 * 4096,
        .count = 1,
    }));
}
