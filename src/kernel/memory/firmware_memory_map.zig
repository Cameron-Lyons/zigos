const std = @import("std");
const handoff = @import("../boot/handoff.zig");
const endian = @import("../utils/endian.zig");
const frame_allocator = @import("frame_allocator.zig");

pub const Error = handoff.Error || frame_allocator.Error || error{
    InvalidHandoffRange,
};

pub fn initializeAllocator(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    memory_map: handoff.MemoryMap,
) Error!void {
    allocator.reset();
    try allocator.reserve(.{
        .base = 0,
        .count = frame_allocator.Fixed(memory_bytes, page_size).total_frames,
    });

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

pub fn reserveLiveHandoffRanges(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    info_address: u32,
    info: handoff.Info,
) Error!void {
    var runs: [5]frame_allocator.FrameRun = undefined;
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

    // Firmware may describe scanout storage as usable RAM. It remains owned by
    // the display even when its format is unsupported by our renderer.
    if (info.hasFramebuffer()) {
        const bytes = @as(u64, info.framebuffer_pitch) * info.framebuffer_height;
        const end = std.math.add(u64, info.framebuffer_addr, bytes) catch return error.InvalidHandoffRange;
        if (touchedPageRun(memory_bytes, page_size, info.framebuffer_addr, bytes, end)) |run| {
            runs[run_count] = run;
            run_count += 1;
        }
    }

    if (info.boot_tpm) |tpm| {
        runs[run_count] = try liveRangeRun(memory_bytes, page_size, std.math.cast(u32, tpm.log_address) orelse return error.InvalidHandoffRange, tpm.log_bytes);
        run_count += 1;
    }

    for (runs[0..run_count]) |run| {
        try allocator.validateReservation(run);
    }
    for (runs[0..run_count]) |run| {
        try allocator.reserve(run);
    }
}

pub fn reserveKernelRanges(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    kernel_start: u64,
    kernel_end: u64,
    heap_start: u64,
    heap_bytes: u64,
) Error!void {
    const low_reserved_bytes = 1024 * 1024;
    const heap_end = std.math.add(u64, heap_start, heap_bytes) catch return error.InvalidHandoffRange;
    if (kernel_start < low_reserved_bytes or kernel_end <= kernel_start or kernel_end > memory_bytes or
        heap_start < low_reserved_bytes or heap_bytes == 0 or heap_end > memory_bytes or
        kernel_start % page_size != 0 or kernel_end % page_size != 0 or
        heap_start % page_size != 0 or heap_bytes % page_size != 0 or
        (kernel_start < heap_end and heap_start < kernel_end)) return error.InvalidHandoffRange;
    try allocator.reserve(.{ .base = 0, .count = low_reserved_bytes / page_size });
    try allocator.reserve(.{ .base = kernel_start, .count = @intCast((kernel_end - kernel_start) / page_size) });
    try allocator.reserve(.{ .base = heap_start, .count = @intCast(heap_bytes / page_size) });
}

fn fullPageRun(
    comptime memory_bytes: u64,
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
    comptime memory_bytes: u64,
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
        std.math.add(u64, clipped_end, page - end_remainder) catch return null;
    if (start >= rounded_end) return null;

    return .{
        .base = @intCast(start),
        .count = @intCast((rounded_end - start) / page),
    };
}

fn liveRangeRun(
    comptime memory_bytes: u64,
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
    endian.writeU64Le(bytes[offset .. offset + 8], base);
    endian.writeU64Le(bytes[offset + 8 .. offset + 16], length);
    endian.writeU32Le(bytes[offset + 16 .. offset + 20], kind);
    endian.writeU32Le(bytes[offset + 20 .. offset + 24], 0);
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
        .info_bytes = 8,
        .cmdline_length = if (cmdline_addr == 0) 0 else 512,
        .mmap_entry_size = 24,
    };
}

test "firmware map opens only complete usable pages" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var bytes = [_]u8{0} ** 24;
    _ = appendEntry(&bytes, 0, TEST_PAGE_SIZE / 2, 3 * TEST_PAGE_SIZE, 1);

    try initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24));

    try std.testing.expect(allocator.isReserved(0));
    try std.testing.expect(!allocator.isReserved(1 * TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(3 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
}

test "kernel and EFI heap reservations preserve free gaps and firmware NVS" {
    const mib = 1024 * 1024;
    const memory_bytes = 128 * mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var bytes: [48]u8 = undefined;
    _ = appendEntry(&bytes, 0, 0, memory_bytes, 1);
    _ = appendEntry(&bytes, 24, 8 * mib, mib, 4);
    try initializeAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24));
    try reserveKernelRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, 16 * mib, 24 * mib, 64 * mib, 32 * mib);
    try allocator.sealReservations();
    for ([_]u64{ 0, mib - TEST_PAGE_SIZE, 8 * mib, 16 * mib, 24 * mib - TEST_PAGE_SIZE, 64 * mib, 96 * mib - TEST_PAGE_SIZE }) |address|
        try std.testing.expect(allocator.isReserved(address));
    for ([_]u64{ mib, 7 * mib, 9 * mib, 15 * mib, 24 * mib, 63 * mib, 96 * mib }) |address|
        try std.testing.expect(!allocator.isReserved(address));
    try std.testing.expectEqual(@as(u32, (1 + 1 + 8 + 32) * mib / TEST_PAGE_SIZE), allocator.stats().reserved);
}

test "kernel reservation rejects overlapping or overflowing EFI heap ranges atomically" {
    const mib = 1024 * 1024;
    const memory_bytes = 128 * mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    for ([_]u64{ 0, 16 * mib, 24 * mib - TEST_PAGE_SIZE, memory_bytes - TEST_PAGE_SIZE, std.math.maxInt(u64) }) |heap_base| {
        try std.testing.expectError(error.InvalidHandoffRange, reserveKernelRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, 16 * mib, 24 * mib, heap_base, 32 * mib));
        try std.testing.expectEqual(@as(u32, 0), allocator.stats().reserved);
    }
}

test "firmware map opens usable frames above 4 GiB" {
    const high_frame_base: u64 = @as(u64, std.math.maxInt(u32)) + 1;
    const memory_bytes = high_frame_base + 4 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var bytes = [_]u8{0} ** 24;
    _ = appendEntry(&bytes, 0, high_frame_base, 2 * TEST_PAGE_SIZE, 1);

    try initializeAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24));

    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
    try std.testing.expectEqual(high_frame_base, allocator.allocate(2).?.base);
}

test "non-usable pages win over usable pages in either descriptor order" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var usable_first = [_]u8{0} ** 48;
    var offset = appendEntry(&usable_first, 0, 0, 6 * TEST_PAGE_SIZE, 1);
    _ = appendEntry(&usable_first, offset, 2 * TEST_PAGE_SIZE + 100, 200, 2);

    var reserved_first = [_]u8{0} ** 48;
    offset = appendEntry(&reserved_first, 0, 2 * TEST_PAGE_SIZE + 100, 200, 2);
    _ = appendEntry(&reserved_first, offset, 0, 6 * TEST_PAGE_SIZE, 1);

    var first_storage: Allocator.Storage = undefined;
    var first = Allocator.init(&first_storage);
    var second_storage: Allocator.Storage = undefined;
    var second = Allocator.init(&second_storage);
    try initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &first, handoff.multiboot2MemoryMap(&usable_first, 24));
    try initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &second, handoff.multiboot2MemoryMap(&reserved_first, 24));

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

    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24));

    try std.testing.expect(allocator.isReserved(0));
    try std.testing.expect(allocator.isReserved(TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(7 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 5), allocator.stats().free);
}

test "malformed or overflowing firmware maps leave the aperture closed" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var bytes = [_]u8{0} ** 24;
    _ = appendEntry(&bytes, 0, std.math.maxInt(u64) - 1, 4, 1);

    try std.testing.expectError(
        error.InvalidMemoryMap,
        initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24)),
    );
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().free);

    try std.testing.expectError(
        error.InvalidMemoryMap,
        initializeAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&[_]u8{}, 24)),
    );
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().free);
}

test "live Multiboot information map and command-line pages stay reserved" {
    const memory_bytes = 16 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
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

test "copied TPM event log remains reserved and malformed extents fail before mutation" {
    const memory_bytes = 2 * 1024 * 1024;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var info = testInfo(1 << 6, 3 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 0);
    info.boot_tpm = .{ .log_address = 0x100000, .log_bytes = 2 * TEST_PAGE_SIZE + 1, .final_events = 2, .pcr11 = @splat(7) };
    try reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, TEST_PAGE_SIZE, info);
    for (0..3) |index| try std.testing.expect(allocator.isReserved(0x100000 + index * TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(0x100000 - TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(0x100000 + 3 * TEST_PAGE_SIZE));
    allocator.reset();
    info.boot_tpm.?.log_address = std.math.maxInt(u64);
    try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, TEST_PAGE_SIZE, info));
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().reserved);
}

test "firmware framebuffer storage is reserved across touched pages" {
    const memory_bytes = 16 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var info = testInfo(1 << 6, 3 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 0);
    info.flags |= 1 << 12;
    info.framebuffer_addr = 8 * TEST_PAGE_SIZE + 128;
    info.framebuffer_pitch = TEST_PAGE_SIZE;
    info.framebuffer_height = 2;
    try reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, TEST_PAGE_SIZE, info);
    for (8..11) |index| try std.testing.expect(allocator.isReserved(index * TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(7 * TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(11 * TEST_PAGE_SIZE));

    allocator.reset();
    info.framebuffer_addr = std.math.maxInt(u64) - 127;
    try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, TEST_PAGE_SIZE, info));
    try std.testing.expectEqual(@as(u32, 16), allocator.stats().free);
}

test "live Multiboot reservations are rejected after allocation begins" {
    const memory_bytes = 16 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    _ = allocator.allocate(7).?;
    const info = testInfo(
        1 << 6,
        3 * TEST_PAGE_SIZE,
        24,
        0,
    );

    try std.testing.expectError(
        error.ReservationsSealed,
        reserveLiveHandoffRanges(
            memory_bytes,
            TEST_PAGE_SIZE,
            &allocator,
            9 * TEST_PAGE_SIZE,
            info,
        ),
    );
    try std.testing.expect(!allocator.isReserved(9 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().reserved);
    try std.testing.expectEqual(@as(u32, 7), allocator.stats().allocated);
}

test "live Multiboot ranges outside the identity aperture fail transactionally" {
    const memory_bytes = 16 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
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
