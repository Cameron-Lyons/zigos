const std = @import("std");

pub const PhysicalAddress = u64;

pub const FrameRun = struct {
    base: PhysicalAddress,
    count: u32,
};

pub const AllocationCursor = struct {
    next_frame: u32 = 0,
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
    ReservationTableFull,
    ReservationsSealed,
};

pub const MUTATES_RANGES_BY_BITMAP_WORD = true;
pub const CONTIGUOUS_SEARCH_USES_BITMAP_WORDS = true;
pub const SINGLE_FRAME_MUTATIONS_ARE_DIRECT = true;
pub const SINGLE_FRAME_HINT_IS_PROBED_DIRECTLY = true;
pub const SUPPORTS_BOUNDED_PHYSICAL_ALLOCATION = true;
pub const SUPPORTS_INDEPENDENT_ALLOCATION_CURSORS = true;
pub const USES_SINGLE_UNAVAILABLE_BITMAP = true;
pub const RESERVATIONS_USE_NORMALIZED_RANGES = true;

const MAX_HANDOFF_BYTES: usize = 1024 * 1024;
const MIN_MEMORY_MAP_ENTRY_BYTES: usize = 24;
// Each firmware descriptor can introduce at most one disjoint reservation.
// The extra slots cover the initial aperture, live handoff ranges, and kernel image.
const EXTRA_BOOT_RESERVATION_RANGES: usize = 8;
const MAX_BOOT_RESERVATION_RANGES = MAX_HANDOFF_BYTES / MIN_MEMORY_MAP_ENTRY_BYTES +
    EXTRA_BOOT_RESERVATION_RANGES;

pub fn Fixed(comptime memory_bytes: u64, comptime page_size: u32) type {
    return FixedWithReservationCapacity(memory_bytes, page_size, MAX_BOOT_RESERVATION_RANGES);
}

fn FixedWithReservationCapacity(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    comptime requested_reservation_capacity: usize,
) type {
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
    const theoretical_reservation_capacity: usize = @intCast((frame_count_value + 1) / 2);
    const reservation_range_capacity = @min(requested_reservation_capacity, theoretical_reservation_capacity);
    if (reservation_range_capacity == 0) {
        @compileError("reservation range capacity must be non-zero");
    }

    return struct {
        const Self = @This();
        const ReservationRange = struct {
            start: u32,
            end: u32,
        };

        unavailable_bitmap: [bitmap_word_count]BitmapWord = [_]BitmapWord{0} ** bitmap_word_count,
        reservation_ranges: [reservation_range_capacity]ReservationRange = undefined,
        reservation_range_count: usize = 0,
        reservations_sealed: bool = false,
        known_unreserved_start: u32 = 0,
        known_unreserved_end: u32 = 0,
        reserved_count: u32 = 0,
        allocated_count: u32 = 0,
        search_frame_hint: u32 = 0,

        pub const total_frames = frame_count;
        pub const bytes_per_frame = page_size;
        pub const bits_per_bitmap_word = bitmap_word_bits;
        pub const max_range_word_probes = bitmap_word_count;
        pub const max_contiguous_search_word_probes = bitmap_word_count;
        pub const max_reservation_ranges = reservation_range_capacity;
        pub const reservation_range_bytes = @sizeOf(ReservationRange);

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            @memset(&self.unavailable_bitmap, 0);
            self.reservation_range_count = 0;
            self.reservations_sealed = false;
            self.known_unreserved_start = 0;
            self.known_unreserved_end = 0;
            self.reserved_count = 0;
            self.allocated_count = 0;
            self.search_frame_hint = 0;
        }

        pub fn reserve(self: *Self, run: FrameRun) Error!void {
            const start = try self.reservableStart(run);
            const end = start + run.count;

            self.reserved_count += self.mutateRange(
                &self.unavailable_bitmap,
                start,
                run.count,
                true,
                true,
            );

            if (start <= self.search_frame_hint and self.search_frame_hint < end) {
                self.search_frame_hint = if (end == frame_count) 0 else end;
            }
        }

        pub fn validateReservation(self: *const Self, run: FrameRun) Error!void {
            _ = try self.reservableStart(run);
        }

        fn reservableStart(self: *const Self, run: FrameRun) Error!u32 {
            const start = try validateRun(run);
            if (self.reservations_sealed) {
                if (self.rangeHasAllocated(start, start + run.count)) return error.FrameAllocated;
                return error.ReservationsSealed;
            }
            return start;
        }

        pub fn makeAvailable(self: *Self, run: FrameRun) Error!void {
            const start = try validateRun(run);
            const end = start + run.count;

            if (self.reservations_sealed) {
                if (self.rangeHasAllocated(start, end)) return error.FrameAllocated;
                return error.ReservationsSealed;
            }
            self.reserved_count -= self.mutateRange(
                &self.unavailable_bitmap,
                start,
                run.count,
                false,
                true,
            );
            self.search_frame_hint = @min(self.search_frame_hint, start);
        }

        pub fn sealReservations(self: *Self) Error!void {
            if (self.reservations_sealed) return;
            if (self.allocated_count != 0) return error.FrameAllocated;

            var range_count: usize = 0;
            var word_index: usize = 0;
            while (word_index < bitmap_word_count) : (word_index += 1) {
                const word_start: u32 = @intCast(word_index * bitmap_word_bits);
                const valid_bits = @min(bitmap_word_bits, frame_count - word_start);
                var bits = self.unavailable_bitmap[word_index] & lowBitsMask(valid_bits);
                while (bits != 0) {
                    const start_bit: u32 = @intCast(@ctz(bits));
                    const shifted = bits >> @as(u6, @intCast(start_bit));
                    const run_length: u32 = @intCast(@ctz(~shifted));
                    const end_bit = @min(valid_bits, start_bit + run_length);
                    const start = word_start + start_bit;
                    const end = word_start + end_bit;

                    if (range_count != 0 and self.reservation_ranges[range_count - 1].end == start) {
                        self.reservation_ranges[range_count - 1].end = end;
                    } else {
                        if (range_count == reservation_range_capacity) return error.ReservationTableFull;
                        self.reservation_ranges[range_count] = .{ .start = start, .end = end };
                        range_count += 1;
                    }
                    bits &= ~wordRangeMask(start_bit, end_bit);
                }
            }

            self.reservation_range_count = range_count;
            self.reservations_sealed = true;
        }

        fn ensureReservationsSealed(self: *Self) bool {
            if (self.reservations_sealed) return true;
            self.sealReservations() catch return false;
            return true;
        }

        pub fn allocate(self: *Self, count: u32) ?FrameRun {
            return self.allocateBetween(count, 0, memory_bytes);
        }

        pub fn allocateBelow(self: *Self, count: u32, exclusive_end: PhysicalAddress) ?FrameRun {
            return self.allocateBetween(count, 0, exclusive_end);
        }

        pub fn allocateBelowWithCursor(
            self: *Self,
            count: u32,
            exclusive_end: PhysicalAddress,
            cursor: *AllocationCursor,
        ) ?FrameRun {
            return self.allocateBetweenWithCursor(count, 0, exclusive_end, cursor);
        }

        pub fn allocateFrameBetween(
            self: *Self,
            inclusive_start: PhysicalAddress,
            exclusive_end: PhysicalAddress,
        ) ?PhysicalAddress {
            if (!self.ensureReservationsSealed()) return null;
            const lower_bytes = @min(inclusive_start, memory_bytes);
            const upper_bytes = @min(exclusive_end, memory_bytes);
            const lower_frame_value = lower_bytes / page_size + @intFromBool(lower_bytes % page_size != 0);
            const upper_frame_value = upper_bytes / page_size;
            if (lower_frame_value >= upper_frame_value) return null;

            const lower_frame: u32 = @intCast(lower_frame_value);
            const upper_frame: u32 = @intCast(upper_frame_value);
            const start = self.allocateFrameIndexBetween(lower_frame, upper_frame) orelse return null;
            return @as(PhysicalAddress, start) * page_size;
        }

        pub fn allocateBetween(
            self: *Self,
            count: u32,
            inclusive_start: PhysicalAddress,
            exclusive_end: PhysicalAddress,
        ) ?FrameRun {
            if (count == 1) {
                const base = self.allocateFrameBetween(inclusive_start, exclusive_end) orelse return null;
                return .{ .base = base, .count = 1 };
            }
            if (!self.ensureReservationsSealed()) return null;

            const lower_bytes = @min(inclusive_start, memory_bytes);
            const upper_bytes = @min(exclusive_end, memory_bytes);
            const lower_frame_value = lower_bytes / page_size + @intFromBool(lower_bytes % page_size != 0);
            const upper_frame_value = upper_bytes / page_size;
            if (lower_frame_value >= upper_frame_value) return null;

            const lower_frame: u32 = @intCast(lower_frame_value);
            const upper_frame: u32 = @intCast(upper_frame_value);
            if (count == 0 or count > upper_frame - lower_frame) return null;

            const search_start = if (self.search_frame_hint >= lower_frame and
                self.search_frame_hint < upper_frame)
                self.search_frame_hint
            else
                lower_frame;

            const start = self.findRun(search_start, upper_frame, count) orelse
                (if (search_start == lower_frame) null else self.findRun(lower_frame, upper_frame, count)) orelse return null;

            _ = self.mutateRange(&self.unavailable_bitmap, start, count, true, false);
            self.allocated_count += count;
            self.cacheKnownUnreservedRange(start, start + count);
            self.search_frame_hint = if (start + count == frame_count) 0 else start + count;

            return .{
                .base = @as(PhysicalAddress, start) * page_size,
                .count = count,
            };
        }

        pub fn allocateBetweenWithCursor(
            self: *Self,
            count: u32,
            inclusive_start: PhysicalAddress,
            exclusive_end: PhysicalAddress,
            cursor: *AllocationCursor,
        ) ?FrameRun {
            const shared_hint = self.search_frame_hint;
            self.search_frame_hint = cursor.next_frame;
            const run = self.allocateBetween(count, inclusive_start, exclusive_end);
            cursor.next_frame = self.search_frame_hint;
            self.search_frame_hint = shared_hint;
            return run;
        }

        pub fn release(self: *Self, run: FrameRun) Error!void {
            if (run.count == 1) return self.releaseFrame(run.base);
            const start = try validateRun(run);
            if (!self.reservations_sealed) try self.sealReservations();

            try self.validateReleasableRange(start, run.count);
            _ = self.mutateRange(&self.unavailable_bitmap, start, run.count, false, false);
            self.allocated_count -= run.count;
            self.search_frame_hint = start;
        }

        pub fn releaseFrame(self: *Self, base: PhysicalAddress) Error!void {
            if (base % page_size != 0) return error.Unaligned;
            const start_value = base / page_size;
            if (start_value >= frame_count) return error.OutOfRange;

            const start: u32 = @intCast(start_value);
            if (!self.reservations_sealed) try self.sealReservations();
            const word: usize = @intCast(start / bitmap_word_bits);
            const bit: u6 = @truncate(start % bitmap_word_bits);
            const mask = @as(BitmapWord, 1) << bit;
            if (!self.rangeIsKnownUnreserved(start, start + 1) and self.frameIsReserved(start)) {
                return error.FrameReserved;
            }
            if ((self.unavailable_bitmap[word] & mask) == 0) return error.NotAllocated;
            self.unavailable_bitmap[word] &= ~mask;
            self.allocated_count -= 1;
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
            const frame: u32 = @intCast(frame_address / page_size);
            if (!self.reservations_sealed) return self.bitIsSet(&self.unavailable_bitmap, frame);
            return self.frameIsReserved(frame);
        }

        pub fn isAllocated(self: *const Self, frame_address: PhysicalAddress) bool {
            if (frame_address % page_size != 0 or frame_address >= memory_bytes) return false;
            if (!self.reservations_sealed) return false;
            const frame: u32 = @intCast(frame_address / page_size);
            return self.bitIsSet(&self.unavailable_bitmap, frame) and !self.frameIsReserved(frame);
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
                const available = ~self.unavailable_bitmap[word_index] & range_mask;

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
                const available = ~self.unavailable_bitmap[word_index] & range_mask;
                if (available == 0) continue;

                const free_bit: u32 = @intCast(@ctz(available));
                return word_start + free_bit;
            }
            return null;
        }

        fn allocateFrameIndexBetween(self: *Self, lower_frame: u32, upper_frame: u32) ?u32 {
            const search_start = if (self.search_frame_hint >= lower_frame and
                self.search_frame_hint < upper_frame)
                self.search_frame_hint
            else
                lower_frame;

            const start = (if (self.frameIsFree(search_start))
                search_start
            else
                self.findFreeFrame(search_start + 1, upper_frame) orelse
                    (if (search_start == lower_frame) null else self.findFreeFrame(lower_frame, search_start))) orelse return null;

            const word: usize = @intCast(start / bitmap_word_bits);
            const bit: u6 = @truncate(start % bitmap_word_bits);
            self.unavailable_bitmap[word] |= @as(BitmapWord, 1) << bit;
            self.allocated_count += 1;
            self.cacheKnownUnreservedRange(start, start + 1);
            self.search_frame_hint = if (start + 1 == frame_count) 0 else start + 1;
            return start;
        }

        fn frameIsFree(self: *const Self, frame: u32) bool {
            const word: usize = @intCast(frame / bitmap_word_bits);
            const bit: u6 = @truncate(frame % bitmap_word_bits);
            const mask = @as(BitmapWord, 1) << bit;
            return (self.unavailable_bitmap[word] & mask) == 0;
        }

        fn rangeHasAnyUnavailable(self: *const Self, start: u32, count: u32) bool {
            const end = start + count;
            var word_index = start / bitmap_word_bits;
            const last_word_index = (end - 1) / bitmap_word_bits;
            while (word_index <= last_word_index) : (word_index += 1) {
                const word_start = word_index * bitmap_word_bits;
                const range_start = @max(start, word_start);
                const range_end = word_start + @min(bitmap_word_bits, end - word_start);
                const mask = wordRangeMask(range_start - word_start, range_end - word_start);
                if ((self.unavailable_bitmap[word_index] & mask) != 0) return true;
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
            const first_reserved = if (self.rangeIsKnownUnreserved(start, end))
                null
            else
                self.firstReservedFrame(start, end);
            const first_free = self.findFreeFrame(start, end);
            if (first_reserved == null and first_free == null) return;
            if (first_reserved == null) return error.NotAllocated;
            if (first_free == null or first_reserved.? <= first_free.?) return error.FrameReserved;
            return error.NotAllocated;
        }

        fn rangeHasAllocated(self: *const Self, start: u32, end: u32) bool {
            var cursor = start;
            var index = self.firstRangeEndingAfter(start);
            while (index < self.reservation_range_count) : (index += 1) {
                const reserved = self.reservation_ranges[index];
                if (reserved.start >= end) break;
                const gap_end = @min(reserved.start, end);
                if (cursor < gap_end and self.rangeHasAnyUnavailable(cursor, gap_end - cursor)) {
                    return true;
                }
                cursor = @max(cursor, @min(reserved.end, end));
                if (cursor == end) return false;
            }
            return cursor < end and self.rangeHasAnyUnavailable(cursor, end - cursor);
        }

        fn cacheKnownUnreservedRange(self: *Self, start: u32, end: u32) void {
            self.known_unreserved_start = start;
            self.known_unreserved_end = end;
        }

        fn rangeIsKnownUnreserved(self: *const Self, start: u32, end: u32) bool {
            return self.known_unreserved_start <= start and end <= self.known_unreserved_end;
        }

        fn firstRangeEndingAfter(self: *const Self, frame: u32) usize {
            var low: usize = 0;
            var high = self.reservation_range_count;
            while (low < high) {
                const middle = low + (high - low) / 2;
                if (self.reservation_ranges[middle].end <= frame) {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            return low;
        }

        fn frameIsReserved(self: *const Self, frame: u32) bool {
            const index = self.firstRangeEndingAfter(frame);
            return index < self.reservation_range_count and
                self.reservation_ranges[index].start <= frame;
        }

        fn firstReservedFrame(self: *const Self, start: u32, end: u32) ?u32 {
            const index = self.firstRangeEndingAfter(start);
            if (index == self.reservation_range_count) return null;
            const reserved = self.reservation_ranges[index];
            if (reserved.start >= end) return null;
            return @max(start, reserved.start);
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

test "normalized reservations split and merge without losing ownership" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(16 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 2 * page_size, .count = 8 });
    try allocator.makeAvailable(.{ .base = 5 * page_size, .count = 2 });
    var split = allocator;
    try split.sealReservations();
    try std.testing.expectEqual(@as(usize, 2), split.reservation_range_count);
    try std.testing.expect(split.isReserved(4 * page_size));
    try std.testing.expect(!split.isReserved(5 * page_size));
    try std.testing.expect(!split.isReserved(6 * page_size));
    try std.testing.expect(split.isReserved(7 * page_size));

    try allocator.reserve(.{ .base = 4 * page_size, .count = 4 });
    try allocator.sealReservations();
    try std.testing.expectEqual(@as(usize, 1), allocator.reservation_range_count);
    try std.testing.expectEqual(@as(u32, 8), allocator.stats().reserved);
    try std.testing.expect(allocator.isReserved(5 * page_size));
    try std.testing.expect(allocator.isReserved(6 * page_size));
}

test "normalized reservation updates match exhaustive frame ownership" {
    const page_size: u32 = 4096;
    const frame_total: u32 = 8;
    const Allocator = Fixed(frame_total * page_size, page_size);
    const Reference = struct {
        fn expectMask(allocator: *const Allocator, expected: u8) !void {
            var frame: u32 = 0;
            while (frame < frame_total) : (frame += 1) {
                const bit: u3 = @intCast(frame);
                try std.testing.expectEqual(
                    (expected & (@as(u8, 1) << bit)) != 0,
                    allocator.isReserved(frame * page_size),
                );
            }
            try std.testing.expectEqual(@as(u32, @popCount(expected)), allocator.stats().reserved);
        }
    };

    var initial_value: u16 = 0;
    while (initial_value < 1 << frame_total) : (initial_value += 1) {
        const initial: u8 = @intCast(initial_value);
        var allocator = Allocator.init();
        var frame: u32 = 0;
        while (frame < frame_total) : (frame += 1) {
            const bit: u3 = @intCast(frame);
            if ((initial & (@as(u8, 1) << bit)) != 0) {
                try allocator.reserve(.{ .base = frame * page_size, .count = 1 });
            }
        }

        var start: u32 = 0;
        while (start < frame_total) : (start += 1) {
            var end = start + 1;
            while (end <= frame_total) : (end += 1) {
                const count = end - start;
                const low: u3 = @intCast(start);
                const width_mask: u8 = if (count == frame_total)
                    std.math.maxInt(u8)
                else
                    (@as(u8, 1) << @as(u3, @intCast(count))) - 1;
                const run_mask = width_mask << low;

                var reserved = allocator;
                try reserved.reserve(.{ .base = start * page_size, .count = count });
                try Reference.expectMask(&reserved, initial | run_mask);

                var available = allocator;
                try available.makeAvailable(.{ .base = start * page_size, .count = count });
                try Reference.expectMask(&available, initial & ~run_mask);
            }
        }
    }
}

test "reservation sealing fails closed when normalized ownership exceeds capacity" {
    const page_size: u32 = 4096;
    const Allocator = FixedWithReservationCapacity(8 * page_size, page_size, 1);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 0, .count = 1 });
    try allocator.reserve(.{ .base = 2 * page_size, .count = 1 });
    try std.testing.expectError(
        error.ReservationTableFull,
        allocator.sealReservations(),
    );
    try std.testing.expect(!allocator.reservations_sealed);
    try std.testing.expect(allocator.isReserved(0));
    try std.testing.expect(allocator.isReserved(2 * page_size));
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().reserved);
    try std.testing.expect(allocator.allocate(1) == null);

    allocator.reset();
    try allocator.reserve(.{ .base = 0, .count = 4 });
    try allocator.sealReservations();
    try allocator.sealReservations();
    try std.testing.expect(allocator.reservations_sealed);
    try std.testing.expectEqual(@as(usize, 1), allocator.reservation_range_count);
    try std.testing.expectError(
        error.ReservationsSealed,
        allocator.reserve(.{ .base = 6 * page_size, .count = 1 }),
    );
    try std.testing.expectError(
        error.ReservationsSealed,
        allocator.makeAvailable(.{ .base = page_size, .count = 1 }),
    );
    try std.testing.expectEqual(@as(u32, 4), allocator.stats().reserved);
    try std.testing.expect(allocator.isReserved(page_size));
}

test "64 GiB allocator state stays below three MiB" {
    const Allocator = Fixed(64 * 1024 * 1024 * 1024, 4096);
    try std.testing.expect(USES_SINGLE_UNAVAILABLE_BITMAP);
    try std.testing.expect(RESERVATIONS_USE_NORMALIZED_RANGES);
    try std.testing.expectEqual(MAX_BOOT_RESERVATION_RANGES, Allocator.max_reservation_ranges);
    try std.testing.expectEqual(@as(usize, 8), Allocator.reservation_range_bytes);
    try std.testing.expect(@sizeOf(Allocator) < 3 * 1024 * 1024);
}

test "recent allocations cache only their immutable unreserved span" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(8 * page_size, page_size);
    var allocator = Allocator.init();

    try allocator.reserve(.{ .base = 2 * page_size, .count = 2 });
    const run = allocator.allocate(2).?;
    try std.testing.expect(allocator.rangeIsKnownUnreserved(0, 2));
    try std.testing.expect(!allocator.rangeIsKnownUnreserved(1, 3));
    try allocator.release(run);
    try std.testing.expectError(
        error.FrameReserved,
        allocator.release(.{ .base = 2 * page_size, .count = 1 }),
    );
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

test "single-frame allocation probes a released search hint directly" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(96 * page_size, page_size);
    var allocator = Allocator.init();

    const lower_bound = 65 * page_size;
    allocator.search_frame_hint = 65;
    const first = allocator.allocateFrameBetween(lower_bound, 96 * page_size).?;
    try allocator.releaseFrame(first);

    try std.testing.expectEqual(first, allocator.allocateFrameBetween(lower_bound, 96 * page_size).?);
    try std.testing.expect(SINGLE_FRAME_HINT_IS_PROBED_DIRECTLY);
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

test "bounded allocation cursors retain independent range progress" {
    const page_size: u32 = 4096;
    const Allocator = Fixed(16 * page_size, page_size);
    var allocator = Allocator.init();
    var low_cursor = AllocationCursor{};
    var high_cursor = AllocationCursor{ .next_frame = 8 };

    const first_high = allocator.allocateBetweenWithCursor(
        1,
        8 * page_size,
        16 * page_size,
        &high_cursor,
    ).?;
    const first_low = allocator.allocateBelowWithCursor(1, 8 * page_size, &low_cursor).?;
    const second_high = allocator.allocateBetweenWithCursor(
        1,
        8 * page_size,
        16 * page_size,
        &high_cursor,
    ).?;

    try std.testing.expectEqual(@as(PhysicalAddress, 8 * page_size), first_high.base);
    try std.testing.expectEqual(@as(PhysicalAddress, 0), first_low.base);
    try std.testing.expectEqual(@as(PhysicalAddress, 9 * page_size), second_high.base);
    try std.testing.expectEqual(@as(u32, 1), low_cursor.next_frame);
    try std.testing.expectEqual(@as(u32, 10), high_cursor.next_frame);
    try std.testing.expect(SUPPORTS_INDEPENDENT_ALLOCATION_CURSORS);
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
