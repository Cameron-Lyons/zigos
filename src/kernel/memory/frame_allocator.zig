const std = @import("std");

pub const PhysicalAddress = u64;

pub const FrameRun = struct {
    base: PhysicalAddress,
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

pub const MUTATES_RANGES_BY_BITMAP_WORD = true;
pub const RESERVATION_PREFLIGHT_USES_BITMAP_WORDS = true;
pub const CONTIGUOUS_SEARCH_USES_BITMAP_WORDS = true;
pub const SINGLE_FRAME_MUTATIONS_ARE_DIRECT = true;
pub const SUPPORTS_BOUNDED_PHYSICAL_ALLOCATION = true;

pub fn Fixed(comptime memory_bytes: u64, comptime page_size: u32) type {
    if (page_size == 0 or (page_size & (page_size - 1)) != 0) {
        @compileError("page_size must be a power of two");
    }
    if (memory_bytes == 0 or memory_bytes % page_size != 0) {
        @compileError("memory_bytes must be a non-zero multiple of page_size");
    }

    const frame_count_value = memory_bytes / page_size;
    if (frame_count_value > std.math.maxInt(u32)) {
        @compileError("frame count exceeds compact allocator indices");
    }

    const frame_count: u32 = @intCast(frame_count_value);
    const BitmapWord = u64;
    const bitmap_word_bits: u32 = @bitSizeOf(BitmapWord);
    const bitmap_word_count: usize = @intCast((frame_count_value + bitmap_word_bits - 1) / bitmap_word_bits);

    return struct {
        const Self = @This();

        reserved_bitmap: [bitmap_word_count]BitmapWord = [_]BitmapWord{0} ** bitmap_word_count,
        allocated_bitmap: [bitmap_word_count]BitmapWord = [_]BitmapWord{0} ** bitmap_word_count,
        reserved_count: u32 = 0,
        allocated_count: u32 = 0,
        search_frame_hint: u32 = 0,

        pub const total_frames = frame_count;
        pub const bytes_per_frame = page_size;
        pub const bits_per_bitmap_word = bitmap_word_bits;
        pub const max_range_word_probes = bitmap_word_count;
        pub const max_contiguous_search_word_probes = bitmap_word_count;

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            @memset(&self.reserved_bitmap, 0);
            @memset(&self.allocated_bitmap, 0);
            self.reserved_count = 0;
            self.allocated_count = 0;
            self.search_frame_hint = 0;
        }

        pub fn reserve(self: *Self, run: FrameRun) Error!void {
            const start = try self.reservableStart(run);
            self.reserveValidated(start, run.count);
        }

        pub fn validateReservation(self: *const Self, run: FrameRun) Error!void {
            _ = try self.reservableStart(run);
        }

        fn reservableStart(self: *const Self, run: FrameRun) Error!u32 {
            const start = try validateRun(run);
            if (self.rangeHasAny(&self.allocated_bitmap, start, run.count)) {
                return error.FrameAllocated;
            }
            return start;
        }

        fn reserveValidated(self: *Self, start: u32, count: u32) void {
            self.reserved_count += self.mutateRange(
                &self.reserved_bitmap,
                start,
                count,
                true,
                true,
            );

            if (start <= self.search_frame_hint and self.search_frame_hint < start + count) {
                self.search_frame_hint = if (start + count == frame_count) 0 else start + count;
            }
        }

        pub fn makeAvailable(self: *Self, run: FrameRun) Error!void {
            const start = try validateRun(run);

            if (self.rangeHasAny(&self.allocated_bitmap, start, run.count)) {
                return error.FrameAllocated;
            }
            self.reserved_count -= self.mutateRange(
                &self.reserved_bitmap,
                start,
                run.count,
                false,
                true,
            );
            self.search_frame_hint = @min(self.search_frame_hint, start);
        }

        pub fn allocate(self: *Self, count: u32) ?FrameRun {
            return self.allocateBetween(count, 0, memory_bytes);
        }

        pub fn allocateBelow(self: *Self, count: u32, exclusive_end: PhysicalAddress) ?FrameRun {
            return self.allocateBetween(count, 0, exclusive_end);
        }

        pub fn allocateBetween(
            self: *Self,
            count: u32,
            inclusive_start: PhysicalAddress,
            exclusive_end: PhysicalAddress,
        ) ?FrameRun {
            const lower_bytes = @min(inclusive_start, memory_bytes);
            const upper_bytes = @min(exclusive_end, memory_bytes);
            const lower_frame_value = lower_bytes / page_size + @intFromBool(lower_bytes % page_size != 0);
            const upper_frame_value = upper_bytes / page_size;
            if (lower_frame_value >= upper_frame_value) return null;

            const lower_frame: u32 = @intCast(lower_frame_value);
            const upper_frame: u32 = @intCast(upper_frame_value);
            if (count == 0 or count > upper_frame - lower_frame) return null;

            const search_start = if (self.search_frame_hint >= lower_frame and self.search_frame_hint < upper_frame)
                self.search_frame_hint
            else
                lower_frame;

            const start = if (count == 1)
                self.findFreeFrame(search_start, upper_frame) orelse
                    (if (search_start == lower_frame) null else self.findFreeFrame(lower_frame, upper_frame)) orelse return null
            else
                self.findRun(search_start, upper_frame, count) orelse
                    (if (search_start == lower_frame) null else self.findRun(lower_frame, upper_frame, count)) orelse return null;

            if (count == 1) {
                const word: usize = @intCast(start / bitmap_word_bits);
                const bit: u6 = @truncate(start % bitmap_word_bits);
                self.allocated_bitmap[word] |= @as(BitmapWord, 1) << bit;
            } else {
                _ = self.mutateRange(&self.allocated_bitmap, start, count, true, false);
            }
            self.allocated_count += count;
            self.search_frame_hint = if (start + count == frame_count) 0 else start + count;

            return .{
                .base = @as(PhysicalAddress, start) * page_size,
                .count = count,
            };
        }

        pub fn release(self: *Self, run: FrameRun) Error!void {
            const start = try validateRun(run);

            if (run.count == 1) {
                const word: usize = @intCast(start / bitmap_word_bits);
                const bit: u6 = @truncate(start % bitmap_word_bits);
                const mask = @as(BitmapWord, 1) << bit;
                if ((self.reserved_bitmap[word] & mask) != 0) return error.FrameReserved;
                if ((self.allocated_bitmap[word] & mask) == 0) return error.NotAllocated;
                self.allocated_bitmap[word] &= ~mask;
                self.allocated_count -= 1;
                self.search_frame_hint = start;
                return;
            }

            try self.validateReleasableRange(start, run.count);
            _ = self.mutateRange(&self.allocated_bitmap, start, run.count, false, false);
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

        pub fn isReserved(self: *const Self, frame_address: PhysicalAddress) bool {
            if (frame_address % page_size != 0 or frame_address >= memory_bytes) return false;
            return self.bitIsSet(&self.reserved_bitmap, @intCast(frame_address / page_size));
        }

        pub fn isAllocated(self: *const Self, frame_address: PhysicalAddress) bool {
            if (frame_address % page_size != 0 or frame_address >= memory_bytes) return false;
            return self.bitIsSet(&self.allocated_bitmap, @intCast(frame_address / page_size));
        }

        fn validateRun(run: FrameRun) Error!u32 {
            if (run.count == 0) return error.InvalidRun;
            if (run.base % page_size != 0) return error.Unaligned;

            const start_value = run.base / page_size;
            if (start_value >= frame_count) return error.OutOfRange;

            const start: u32 = @intCast(start_value);
            if (run.count > frame_count - start) {
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

                const range_width = range_end - range_start;
                const first_bit: u6 = @intCast(range_start - word_start);
                const normalized = available >> first_bit;
                const valid_mask = lowBitsMask(range_width);
                const unavailable = ~normalized & valid_mask;
                const prefix_free: u32 = @intCast(@ctz(unavailable));

                if (prefix_free != 0) {
                    if (contiguous == 0) candidate = range_start;
                    if (contiguous + prefix_free >= count) return candidate;
                }

                if (count <= range_width) {
                    const starts = consecutiveRunStarts(normalized, count) &
                        lowBitsMask(range_width - count + 1);
                    if (starts != 0) {
                        return range_start + @as(u32, @intCast(@ctz(starts)));
                    }
                }

                const leading_zeroes: u32 = @intCast(@clz(unavailable));
                contiguous = range_width - (bitmap_word_bits - leading_zeroes);
                if (contiguous != 0) candidate = range_end - contiguous;
            }
            return null;
        }

        fn consecutiveRunStarts(bits: BitmapWord, count: u32) BitmapWord {
            var starts = bits;
            var width: u32 = 1;
            while (width < count) {
                const step = @min(width, count - width);
                const shift: u6 = @intCast(step);
                starts &= starts >> shift;
                width += step;
            }
            return starts;
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

        fn rangeHasAny(
            _: *const Self,
            bitmap: *const [bitmap_word_count]BitmapWord,
            start: u32,
            count: u32,
        ) bool {
            const end = start + count;
            var word_index = start / bitmap_word_bits;
            const last_word_index = (end - 1) / bitmap_word_bits;
            while (word_index <= last_word_index) : (word_index += 1) {
                const word_start = word_index * bitmap_word_bits;
                const range_start = @max(start, word_start);
                const range_end = word_start + @min(bitmap_word_bits, end - word_start);
                const mask = wordRangeMask(range_start - word_start, range_end - word_start);
                if ((bitmap[word_index] & mask) != 0) return true;
            }
            return false;
        }

        fn mutateRange(
            _: *Self,
            bitmap: *[bitmap_word_count]BitmapWord,
            start: u32,
            count: u32,
            comptime set_bits: bool,
            comptime count_changes: bool,
        ) u32 {
            const end = start + count;
            var changed: u32 = 0;
            var word_index = start / bitmap_word_bits;
            const last_word_index = (end - 1) / bitmap_word_bits;
            while (word_index <= last_word_index) : (word_index += 1) {
                const word_start = word_index * bitmap_word_bits;
                const range_start = @max(start, word_start);
                const range_end = word_start + @min(bitmap_word_bits, end - word_start);
                const mask = wordRangeMask(range_start - word_start, range_end - word_start);
                if (count_changes) {
                    const affected = if (set_bits) mask & ~bitmap[word_index] else mask & bitmap[word_index];
                    changed += @popCount(affected);
                }
                if (set_bits) {
                    bitmap[word_index] |= mask;
                } else {
                    bitmap[word_index] &= ~mask;
                }
            }
            return changed;
        }

        fn validateReleasableRange(self: *const Self, start: u32, count: u32) Error!void {
            const end = start + count;
            var word_index = start / bitmap_word_bits;
            const last_word_index = (end - 1) / bitmap_word_bits;
            while (word_index <= last_word_index) : (word_index += 1) {
                const word_start = word_index * bitmap_word_bits;
                const range_start = @max(start, word_start);
                const range_end = word_start + @min(bitmap_word_bits, end - word_start);
                const mask = wordRangeMask(range_start - word_start, range_end - word_start);
                const reserved = self.reserved_bitmap[word_index] & mask;
                const missing = ~self.allocated_bitmap[word_index] & mask;
                if (reserved == 0 and missing == 0) continue;
                if (reserved == 0) return error.NotAllocated;
                if (missing == 0 or @ctz(reserved) <= @ctz(missing)) return error.FrameReserved;
                return error.NotAllocated;
            }
        }

        fn bitIsSet(_: *const Self, bitmap: *const [bitmap_word_count]BitmapWord, frame: u32) bool {
            const word: usize = @intCast(frame / bitmap_word_bits);
            const bit: u6 = @truncate(frame % bitmap_word_bits);
            return (bitmap[word] & (@as(BitmapWord, 1) << bit)) != 0;
        }

        fn wordRangeMask(start_bit: u32, end_bit: u32) BitmapWord {
            return lowBitsMask(end_bit) & ~lowBitsMask(start_bit);
        }

        fn lowBitsMask(bit_count: u32) BitmapWord {
            if (bit_count >= bitmap_word_bits) return std.math.maxInt(BitmapWord);
            const shift: u6 = @intCast(bit_count);
            return (@as(BitmapWord, 1) << shift) - 1;
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

test "single-frame mutations use native bitmap words and preserve accounting" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(96 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 1 });
    const run = allocator.allocate(1).?;
    try std.testing.expectEqual(@as(u32, page_size), run.base);
    try std.testing.expectEqual(@as(u32, 1), allocator.stats().allocated);
    try allocator.release(run);
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().allocated);
    try std.testing.expectError(error.NotAllocated, allocator.release(run));
    try std.testing.expect(SINGLE_FRAME_MUTATIONS_ARE_DIRECT);
    try std.testing.expectEqual(@as(u32, 64), Allocator.bits_per_bitmap_word);
}

test "physical frame addresses remain exact above 4 GiB" {
    const page_size: u32 = 4096;
    const high_frame_base: PhysicalAddress = @as(u64, std.math.maxInt(u32)) + 1;
    const Allocator = Fixed(high_frame_base + page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{
        .base = 0,
        .count = Allocator.total_frames - 1,
    });

    const run = allocator.allocate(1).?;
    try std.testing.expectEqual(high_frame_base, run.base);
    try std.testing.expect(allocator.isAllocated(high_frame_base));
    try allocator.release(run);
    try std.testing.expect(!allocator.isAllocated(high_frame_base));
}

test "bounded allocation never crosses its physical ceiling" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(16 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 7 });
    const final_low = allocator.allocateBelow(1, 8 * page_size).?;
    try std.testing.expectEqual(@as(PhysicalAddress, 7 * page_size), final_low.base);
    try std.testing.expect(allocator.allocateBelow(1, 8 * page_size) == null);

    const first_high = allocator.allocate(1).?;
    try std.testing.expectEqual(@as(PhysicalAddress, 8 * page_size), first_high.base);
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().allocated);
}

test "bounded allocation floors unaligned physical ceilings" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(4 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 1 });
    try std.testing.expect(allocator.allocateBelow(1, 2 * page_size - 1) == null);
    try std.testing.expectEqual(
        @as(PhysicalAddress, page_size),
        allocator.allocateBelow(1, 2 * page_size).?.base,
    );
}

test "range allocation honors both physical boundaries" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(16 * page_size, page_size);
    var allocator = Allocator.init();

    const first_high = allocator.allocateBetween(2, 8 * page_size, 12 * page_size).?;
    try std.testing.expectEqual(@as(PhysicalAddress, 8 * page_size), first_high.base);
    const second_high = allocator.allocateBetween(2, 8 * page_size + 1, 12 * page_size).?;
    try std.testing.expectEqual(@as(PhysicalAddress, 10 * page_size), second_high.base);
    try std.testing.expect(allocator.allocateBetween(1, 8 * page_size, 12 * page_size) == null);
    try std.testing.expectEqual(@as(PhysicalAddress, 0), allocator.allocateBelow(1, 8 * page_size).?.base);
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

    try allocator.release(run);
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().allocated);
    try std.testing.expectEqual(run, allocator.allocate(64).?);
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

test "bitmap-word contiguous search matches exhaustive first-fit results" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(8 * page_size, page_size);
    const Reference = struct {
        fn find(allocator: *const Allocator, start: u32, end: u32, count: u32) ?u32 {
            if (start >= end or count > end - start) return null;

            var candidate = start;
            while (candidate + count <= end) : (candidate += 1) {
                var frame = candidate;
                while (frame < candidate + count) : (frame += 1) {
                    if (allocator.isReserved(frame * page_size)) break;
                }
                if (frame == candidate + count) return candidate;
            }
            return null;
        }
    };

    var reserved_pattern: u32 = 0;
    while (reserved_pattern < 1 << Allocator.total_frames) : (reserved_pattern += 1) {
        var allocator = Allocator.init();
        var frame: u32 = 0;
        while (frame < Allocator.total_frames) : (frame += 1) {
            const bit: u5 = @intCast(frame);
            if ((reserved_pattern & (@as(u32, 1) << bit)) != 0) {
                try allocator.reserve(.{ .base = frame * page_size, .count = 1 });
            }
        }

        var start: u32 = 0;
        while (start < Allocator.total_frames) : (start += 1) {
            var end = start + 1;
            while (end <= Allocator.total_frames) : (end += 1) {
                var count: u32 = 1;
                while (count <= end - start) : (count += 1) {
                    try std.testing.expectEqual(
                        Reference.find(&allocator, start, end, count),
                        allocator.findRun(start, end, count),
                    );
                }
            }
        }
    }
}

test "fragmented full-space contiguous search is bounded by bitmap words" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(128 * 1024 * 1024, page_size);
    var allocator = Allocator.init();

    var frame: u32 = 0;
    while (frame < Allocator.total_frames) : (frame += 2) {
        try allocator.reserve(.{ .base = frame * page_size, .count = 1 });
    }

    try std.testing.expect(allocator.findRun(0, Allocator.total_frames, 2) == null);
    try std.testing.expect(CONTIGUOUS_SEARCH_USES_BITMAP_WORDS);
    try std.testing.expectEqual(@as(usize, 512), Allocator.max_contiguous_search_word_probes);
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
    const run = FrameRun{ .base = 0, .count = 2 };
    try std.testing.expectError(error.FrameAllocated, allocator.validateReservation(run));
    try std.testing.expectError(error.FrameAllocated, allocator.reserve(run));
    try std.testing.expect(!allocator.isReserved(0));
    try std.testing.expect(!allocator.isReserved(4096));
    try std.testing.expectEqual(Stats{
        .total = 8,
        .reserved = 0,
        .allocated = 1,
        .free = 7,
    }, allocator.stats());
    try std.testing.expect(RESERVATION_PREFLIGHT_USES_BITMAP_WORDS);
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
    const Allocator = Fixed(96 * 4096, 4096);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 96 });
    try allocator.makeAvailable(.{ .base = 16 * 4096, .count = 64 });
    try allocator.makeAvailable(.{ .base = 32 * 4096, .count = 32 });

    try std.testing.expectEqual(Stats{
        .total = 96,
        .reserved = 32,
        .allocated = 0,
        .free = 64,
    }, allocator.stats());
    try std.testing.expectEqual(@as(u32, 16 * 4096), allocator.allocate(64).?.base);
    try std.testing.expect(allocator.allocate(1) == null);
    try std.testing.expectError(error.FrameAllocated, allocator.makeAvailable(.{
        .base = 16 * 4096,
        .count = 1,
    }));
    try std.testing.expect(MUTATES_RANGES_BY_BITMAP_WORD);
    try std.testing.expectEqual(@as(usize, 2), Allocator.max_range_word_probes);
}
