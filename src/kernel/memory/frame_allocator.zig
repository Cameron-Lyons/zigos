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

/// A fixed-capacity physical-frame allocator with separate reservation and
/// live-allocation accounting. The type owns no storage outside itself, so it
/// can be exercised by host tests and embedded directly in the kernel.
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

        /// Permanently excludes a physical run from allocation. Repeating an
        /// overlapping reservation is idempotent, while overlap with a live
        /// allocation is rejected without partially changing the allocator.
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

        /// Marks a previously unavailable run allocatable. This is used at
        /// boot after reserving the complete physical aperture, then opening
        /// only full pages reported as type-1 RAM by firmware. Repeated and
        /// overlapping availability declarations are idempotent.
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

        /// Allocates a physically contiguous run. Search begins near the last
        /// allocation but performs a full non-wrapping scan before reporting
        /// exhaustion.
        pub fn allocate(self: *Self, count: u32) ?FrameRun {
            if (count == 0 or count > frame_count) return null;

            const start = self.findRun(self.search_frame_hint, frame_count, count) orelse
                self.findRun(0, frame_count, count) orelse return null;

            var frame = start;
            while (frame < start + count) : (frame += 1) {
                self.setBit(&self.allocated_bitmap, frame);
            }
            self.allocated_count += count;
            self.search_frame_hint = if (start + count == frame_count) 0 else start + count;

            return .{
                .base = start * page_size,
                .count = count,
            };
        }

        /// Releases exactly one previously allocated run. Validation happens
        /// before mutation, so double frees and mixed valid/invalid ranges do
        /// not corrupt the bitmaps or counters.
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

            var candidate: u32 = start;
            var contiguous: u32 = 0;
            var frame = start;
            while (frame < end) : (frame += 1) {
                if (self.isUnavailable(frame)) {
                    contiguous = 0;
                    candidate = frame + 1;
                    continue;
                }

                contiguous += 1;
                if (contiguous == count) return candidate;
            }
            return null;
        }

        fn isUnavailable(self: *const Self, frame: u32) bool {
            return self.bitIsSet(&self.reserved_bitmap, frame) or
                self.bitIsSet(&self.allocated_bitmap, frame);
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
