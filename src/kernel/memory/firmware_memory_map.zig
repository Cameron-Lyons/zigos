const std = @import("std");
const handoff = @import("../boot/handoff.zig");
const endian = @import("../utils/endian.zig");
const frame_allocator = @import("frame_allocator.zig");

pub const Error = handoff.Error || frame_allocator.Error || error{
    InvalidHandoffRange,
};

/// Initializes a fixed physical-frame allocator from a Multiboot memory map.
/// The complete managed aperture starts closed. Only pages fully enclosed by a
/// type-1 descriptor are opened, then every page touched by any other
/// descriptor is closed again. The second pass makes reserved memory win over
/// usable memory regardless of firmware descriptor order.
pub fn initializeAllocator(
    comptime memory_bytes: u32,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    memory_map: handoff.MemoryMap,
) Error!void {
    allocator.reset();
    try allocator.reserve(.{
        .base = 0,
        .count = frame_allocator.Fixed(memory_bytes, page_size).total_frames,
    });

    // Validate the whole byte stream before opening a single frame. A bad
    // trailing entry therefore leaves the allocator completely closed.
    var validator = memory_map.iterator();
    var entry_count: usize = 0;
    while (try validator.next()) |_| {
        entry_count += 1;
    }
    if (entry_count == 0) return error.InvalidMemoryMap;

    var usable = memory_map.iterator();
    while (try usable.next()) |entry| {
        if (!entry.isUsable()) continue;
        if (fullPageRun(memory_bytes, page_size, entry)) |run| {
            try allocator.makeAvailable(run);
        }
    }

    var unavailable = memory_map.iterator();
    while (try unavailable.next()) |entry| {
        if (entry.isUsable()) continue;
        if (touchedPageRun(memory_bytes, page_size, entry.base, entry.length, entry.end)) |run| {
            try allocator.reserve(run);
        }
    }
}

/// Permanently reserves every Multiboot range that remains observable after
/// paging and frame allocation are enabled. All extents must fit completely in
/// the managed identity aperture; otherwise later pointer dereferences would
/// be unsafe even if their in-aperture fragment were reserved.
pub fn reserveLiveHandoffRanges(
    comptime memory_bytes: u32,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    info_address: u32,
    info: handoff.Info,
) Error!void {
    var runs: [3]frame_allocator.FrameRun = undefined;
    var run_count: usize = 0;

    runs[run_count] = try liveRangeRun(
        memory_bytes,
        page_size,
        info_address,
        std.math.cast(usize, info.info_bytes) orelse return error.InvalidHandoffRange,
    );
    run_count += 1;

    if (!info.hasMemoryMap()) return error.MissingMemoryMap;
    runs[run_count] = try liveRangeRun(
        memory_bytes,
        page_size,
        info.mmap_addr,
        std.math.cast(usize, info.mmap_length) orelse return error.InvalidHandoffRange,
    );
    run_count += 1;

    if (info.hasCommandLine()) {
        runs[run_count] = try liveRangeRun(
            memory_bytes,
            page_size,
            info.cmdline_addr,
            std.math.cast(usize, info.cmdline_length) orelse return error.InvalidHandoffRange,
        );
        run_count += 1;
    }

    // Preserve cross-range transactionality if this helper is ever called
    // after allocation has started. Boot currently calls it before any frame
    // can be allocated.
    for (runs[0..run_count]) |run| {
        var frame: u32 = 0;
        while (frame < run.count) : (frame += 1) {
            if (allocator.isAllocated(run.base + frame * page_size)) {
                return error.FrameAllocated;
            }
        }
    }
    for (runs[0..run_count]) |run| {
        try allocator.reserve(run);
    }
}

fn fullPageRun(
    comptime memory_bytes: u32,
    comptime page_size: u32,
    entry: handoff.MemoryMapEntry,
) ?frame_allocator.FrameRun {
    if (entry.length == 0 or entry.base >= memory_bytes) return null;

    const page: u64 = page_size;
    const aperture_end: u64 = memory_bytes;
    const remainder = entry.base % page;
    const start = if (remainder == 0)
        entry.base
    else
        std.math.add(u64, entry.base, page - remainder) catch return null;
    const clipped_end = @min(entry.end, aperture_end);
    const end = clipped_end - (clipped_end % page);
    if (start >= end) return null;

    return .{
        .base = @intCast(start),
        .count = @intCast((end - start) / page),
    };
}

fn touchedPageRun(
    comptime memory_bytes: u32,
    comptime page_size: u32,
    base: u64,
    length: u64,
    end: u64,
) ?frame_allocator.FrameRun {
    if (length == 0 or base >= memory_bytes) return null;

    const page: u64 = page_size;
    const aperture_end: u64 = memory_bytes;
    const start = base - (base % page);
    const clipped_end = @min(end, aperture_end);
    const end_remainder = clipped_end % page;
    const rounded_end = if (end_remainder == 0)
        clipped_end
    else
        // memory_bytes is page-aligned and clipped_end is below it here, so
        // this checked ceiling cannot escape the managed aperture.
        std.math.add(u64, clipped_end, page - end_remainder) catch return null;
    if (start >= rounded_end) return null;

    return .{
        .base = @intCast(start),
        .count = @intCast((rounded_end - start) / page),
    };
}

fn liveRangeRun(
    comptime memory_bytes: u32,
    comptime page_size: u32,
    address: u32,
    length: usize,
) Error!frame_allocator.FrameRun {
    if (address == 0 or length == 0) return error.InvalidHandoffRange;

    const length_u64 = std.math.cast(u64, length) orelse return error.InvalidHandoffRange;
    const end = std.math.add(u64, address, length_u64) catch return error.InvalidHandoffRange;
    if (end > memory_bytes) return error.InvalidHandoffRange;

    return touchedPageRun(memory_bytes, page_size, address, length_u64, end) orelse
        error.InvalidHandoffRange;
}

const TEST_PAGE_SIZE: u32 = 4096;

fn appendEntry(bytes: []u8, offset: usize, base: u64, length: u64, kind: u32) usize {
    endian.writeU32Le(bytes[offset .. offset + 4], 20);
    endian.writeU64Le(bytes[offset + 4 .. offset + 12], base);
    endian.writeU64Le(bytes[offset + 12 .. offset + 20], length);
    endian.writeU32Le(bytes[offset + 20 .. offset + 24], kind);
    return offset + 24;
}

fn testInfo(flags: u32, mmap_addr: u32, mmap_length: u32, cmdline_addr: u32) handoff.Info {
    return .{
        .flags = flags,
        .mem_lower_kib = 0,
        .mem_upper_kib = 0,
        .cmdline_addr = cmdline_addr,
        .mmap_length = mmap_length,
        .mmap_addr = mmap_addr,
        .framebuffer_addr = 0,
        .framebuffer_pitch = 0,
        .framebuffer_width = 0,
        .framebuffer_height = 0,
        .framebuffer_bpp = 0,
        .framebuffer_type = 0,
        .framebuffer_rgb = [_]u8{0} ** 6,
    };
}

test "firmware map opens only complete usable pages" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var allocator = Allocator.init();
    var bytes = [_]u8{0} ** 24;
    _ = appendEntry(&bytes, 0, TEST_PAGE_SIZE / 2, 3 * TEST_PAGE_SIZE, 1);

    try initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot1MemoryMap(&bytes));

    try std.testing.expect(allocator.isReserved(0));
    try std.testing.expect(!allocator.isReserved(1 * TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(3 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
}

test "non-usable pages win over usable pages in either descriptor order" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var usable_first = [_]u8{0} ** 48;
    var offset = appendEntry(&usable_first, 0, 0, 6 * TEST_PAGE_SIZE, 1);
    _ = appendEntry(&usable_first, offset, 2 * TEST_PAGE_SIZE + 100, 200, 2);

    var reserved_first = [_]u8{0} ** 48;
    offset = appendEntry(&reserved_first, 0, 2 * TEST_PAGE_SIZE + 100, 200, 2);
    _ = appendEntry(&reserved_first, offset, 0, 6 * TEST_PAGE_SIZE, 1);

    var first = Allocator.init();
    var second = Allocator.init();
    try initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &first, handoff.multiboot1MemoryMap(&usable_first));
    try initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &second, handoff.multiboot1MemoryMap(&reserved_first));

    try std.testing.expect(first.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(second.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(first.stats(), second.stats());
    try std.testing.expectEqual(@as(u32, 5), first.stats().free);
}

test "non-usable page ceilings and aperture clipping are conservative" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var bytes = [_]u8{0} ** 72;
    var offset = appendEntry(&bytes, 0, 1, 8 * TEST_PAGE_SIZE, 1);
    offset = appendEntry(&bytes, offset, TEST_PAGE_SIZE - 1, 2, 2);
    _ = appendEntry(&bytes, offset, 8 * TEST_PAGE_SIZE - 1, 2, 4);

    var allocator = Allocator.init();
    try initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot1MemoryMap(&bytes));

    try std.testing.expect(allocator.isReserved(0));
    try std.testing.expect(allocator.isReserved(TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(7 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 5), allocator.stats().free);
}

test "malformed or overflowing firmware maps leave the aperture closed" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var allocator = Allocator.init();
    var bytes = [_]u8{0} ** 24;
    _ = appendEntry(&bytes, 0, std.math.maxInt(u64) - 1, 4, 1);

    try std.testing.expectError(
        error.InvalidMemoryMap,
        initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot1MemoryMap(&bytes)),
    );
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().free);

    try std.testing.expectError(
        error.InvalidMemoryMap,
        initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot1MemoryMap(&[_]u8{})),
    );
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().free);
}

test "live Multiboot information map and command-line pages stay reserved" {
    const memory_bytes = 16 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var allocator = Allocator.init();
    const info = testInfo(
        (1 << 2) | (1 << 6),
        3 * TEST_PAGE_SIZE + 100,
        TEST_PAGE_SIZE,
        6 * TEST_PAGE_SIZE + 4000,
    );

    try reserveLiveHandoffRanges(
        memory_bytes,
        TEST_PAGE_SIZE,
        &allocator,
        TEST_PAGE_SIZE + 100,
        info,
    );

    try std.testing.expect(allocator.isReserved(1 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(3 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(4 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(6 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(7 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 5), allocator.stats().reserved);
}

test "live Multiboot ranges outside the identity aperture fail transactionally" {
    const memory_bytes = 16 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var allocator = Allocator.init();
    const info = testInfo(
        (1 << 2) | (1 << 6),
        3 * TEST_PAGE_SIZE,
        24,
        memory_bytes - 100,
    );

    try std.testing.expectError(
        error.InvalidHandoffRange,
        reserveLiveHandoffRanges(
            memory_bytes,
            TEST_PAGE_SIZE,
            &allocator,
            TEST_PAGE_SIZE,
            info,
        ),
    );
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().reserved);
}
