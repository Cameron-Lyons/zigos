const std = @import("std");
const handoff = @import("../boot/handoff.zig");
const frame_allocator = @import("frame_allocator.zig");
const cache_policy = @import("../../arch/cache_policy.zig");
const paging_info = @import("../../boot/paging_info.zig");
const mcfg = @import("../platform/mcfg.zig");

pub const Error = handoff.Error || frame_allocator.Error || cache_policy.MtrrError || error{
    InvalidHandoffRange,
    RamNotAvailable,
    BootArenasAlreadyRetired,
};

// Caller-owned evidence for a single boot. A nonzero used_pages publishes a
// completed retirement; the active final hierarchy keeps precisely that prefix.
pub const BootArenaRetirement = struct {
    used_pages: u32 = 0,
    reclaimed_pages: u32 = 0,
    reserved_before: u32 = 0,
};

pub fn initializeAllocator(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    memory_map: handoff.MemoryMap,
    cache_view: cache_policy.ValidatedMtrrView,
) Error!void {
    allocator.reset();
    try allocator.reserve(.{
        .base = 0,
        .count = frame_allocator.Fixed(memory_bytes, page_size).total_frames,
    });
    // No partially admitted aperture survives a later descriptor or type error.
    errdefer allocator.reserve(.{
        .base = 0,
        .count = frame_allocator.Fixed(memory_bytes, page_size).total_frames,
    }) catch unreachable;

    if (memory_map.len == 0) return error.InvalidMemoryMap;
    for (memory_map) |entry| {
        if (!availableRamEntry(entry)) continue;
        try openWriteBackPages(memory_bytes, page_size, allocator, entry, cache_view);
    }
    for (memory_map) |entry| {
        if (availableRamEntry(entry)) continue;
        if (touchedPageRun(memory_bytes, page_size, entry.base, entry.length, entry.end())) |run| {
            try allocator.reserve(run);
        }
    }
}

// Intersect usable firmware extents with homogeneous effective WB intervals.
// Adjacent WB intervals are joined before rounding, so an artificial MTRR
// boundary inside a larger allocator page does not hide an otherwise WB page.
fn openWriteBackPages(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    entry: handoff.MemoryMapEntry,
    cache_view: cache_policy.ValidatedMtrrView,
) Error!void {
    const limit = @min(entry.end(), @min(memory_bytes, cache_view.physicalLimit()));
    var cursor = entry.base;
    var write_back_start: ?u64 = null;
    while (cursor < limit) {
        var segment: cache_policy.ValidatedMtrrView.Segment = undefined;
        try cache_view.queryInto(cursor, limit, &segment);
        if (segment.memory_type == .write_back) {
            if (write_back_start == null) write_back_start = cursor;
        } else if (write_back_start) |start| {
            try openCompletePages(memory_bytes, page_size, allocator, start, cursor);
            write_back_start = null;
        }
        cursor = segment.next_boundary;
    }
    if (write_back_start) |start| try openCompletePages(memory_bytes, page_size, allocator, start, limit);
}

inline fn openCompletePages(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    start: u64,
    end: u64,
) Error!void {
    if (fullPageRun(memory_bytes, page_size, .{ .base = start, .length = end - start, .kind = .available })) |run|
        try allocator.makeAvailable(run);
}

inline fn availableRamEntry(entry: handoff.MemoryMapEntry) bool {
    if (!entry.isUsable()) return false;
    return entry.firmware_type == std.math.maxInt(u32) or switch (entry.firmware_type) {
        1...4, 7 => true,
        else => false,
    };
}

inline fn describedRamEntry(entry: handoff.MemoryMapEntry) bool {
    const untyped_ram = switch (entry.kind) {
        .available, .acpi_reclaimable, .acpi_nvs, .firmware_runtime_ram => true,
        .reserved => false,
        else => return false,
    };
    return if (entry.firmware_type == std.math.maxInt(u32))
        untyped_ram
    else switch (entry.firmware_type) {
        1...7, 9, 10, 14 => true,
        else => false,
    };
}

pub fn requireAvailableRamWriteBack(memory_map: handoff.MemoryMap, start: u64, bytes: u64, cache_view: cache_policy.ValidatedMtrrView) Error!void {
    return requireRamSpanWriteBack(memory_map, start, bytes, cache_view, true);
}

// Reserved loader arenas need positively typed RAM, while the heap additionally
// needs available RAM. Neither API accepts unlisted gaps or unknown reservations.
pub fn requireRamWriteBack(memory_map: handoff.MemoryMap, start: u64, bytes: u64, cache_view: cache_policy.ValidatedMtrrView) Error!void {
    return requireRamSpanWriteBack(memory_map, start, bytes, cache_view, false);
}

fn requireRamSpanWriteBack(memory_map: handoff.MemoryMap, start: u64, bytes: u64, cache_view: cache_policy.ValidatedMtrrView, available: bool) Error!void {
    const end = std.math.add(u64, start, bytes) catch return error.InvalidHandoffRange;
    if (bytes == 0) return error.InvalidHandoffRange;
    try cache_view.requireWriteBack(start, bytes);

    for (memory_map) |entry| {
        if (entry.length == 0 or entry.base >= end or entry.end() <= start) continue;
        if (if (available) !availableRamEntry(entry) else !describedRamEntry(entry)) return error.RamNotAvailable;
    }
    var covered = start;
    while (covered < end) {
        var next = covered;
        for (memory_map) |entry| {
            if (entry.base <= covered and entry.end() > covered) next = @max(next, @min(entry.end(), end));
        }
        if (next == covered) return error.RamNotAvailable;
        covered = next;
    }
}

// The loader owns these disjoint allocations before the kernel makes its first
// early-heap claim. Described RAM and effective WB alone do not prove that a
// forged allocation cannot overwrite a live loader extent or another owned one.
// The kernel's BootInfo copy itself lives in the image, not in loader pages.
pub fn validateBootOwnedRanges(
    info: *const handoff.BootInfo,
    kernel_start: u64,
    kernel_end: u64,
    cache_view: cache_policy.ValidatedMtrrView,
) Error!void {
    const page: u64 = 4096;
    const image_limit = @import("../../arch/kernel_address.zig").image_physical_limit;
    const memory_map = info.memoryMap();
    const image = info.image;
    const arenas = info.paging;
    arenas.validate() catch return error.InvalidHandoffRange;
    const heap_bytes = @import("../../boot/image_info.zig").KERNEL_HEAP_BYTES;
    const heap_end = std.math.add(u64, image.heap_base, heap_bytes) catch return error.InvalidHandoffRange;
    if (kernel_start < 1024 * 1024 or kernel_start % page != 0 or kernel_end % page != 0 or
        kernel_end <= kernel_start or kernel_end > image_limit or
        image.heap_base < 1024 * 1024 or image.heap_base % page != 0 or heap_end > image_limit)
        return error.InvalidHandoffRange;

    const owned = [_]PhysicalSpan{
        .{ .start = kernel_start, .end = kernel_end },
        .{ .start = image.heap_base, .end = heap_end },
        .{ .start = arenas.transition_base, .end = arenas.transition_base + arenas.transitionBytes() },
        .{ .start = arenas.final_base, .end = arenas.final_base + arenas.finalBytes() },
    };
    for (owned, 0..) |span, index| {
        for (owned[index + 1 ..]) |other| {
            if (overlaps(span.start, span.end, other)) return error.InvalidHandoffRange;
        }
    }

    if (memory_map.len == 0) return error.InvalidHandoffRange;
    var live: [3]PhysicalSpan = undefined;
    var live_count: usize = 0;
    if (info.tpmLog()) |tpm| {
        try touchedOwnedSpan(tpm.log_address, tpm.log_bytes, &live[live_count]);
        live_count += 1;
    }
    if (info.efi_system_table != 0) {
        try touchedOwnedSpan(info.efi_system_table, page, &live[live_count]);
        live_count += 1;
    }
    // Scanout owns its touched pages even when firmware labels them usable RAM
    // or its pixel format is unsupported by the renderer.
    if (arenas.framebufferSpan() catch return error.InvalidHandoffRange) |span| {
        live[live_count] = .{ .start = span.start, .end = span.end };
        live_count += 1;
    }
    for (owned) |span| {
        for (live[0..live_count]) |protected| {
            if (overlaps(span.start, span.end, protected)) return error.InvalidHandoffRange;
        }
    }

    // Production provenance is native, even though the standalone RAM helpers
    // also support explicit host fixtures without an original EFI type.
    for (memory_map) |entry| {
        if (entry.firmware_type != std.math.maxInt(u32)) continue;
        for (owned) |span| {
            if (overlaps(entry.base, entry.end(), span)) return error.RamNotAvailable;
        }
    }
    try requireAvailableRamWriteBack(memory_map, kernel_start, kernel_end - kernel_start, cache_view);
    try requireAvailableRamWriteBack(memory_map, image.heap_base, heap_bytes, cache_view);
    try requireRamWriteBack(memory_map, arenas.transition_base, arenas.transitionBytes(), cache_view);
    try requireRamWriteBack(memory_map, arenas.final_base, arenas.finalBytes(), cache_view);
}

inline fn touchedOwnedSpan(base: u64, bytes: u64, out: *PhysicalSpan) Error!void {
    const end = std.math.add(u64, base, bytes) catch return error.InvalidHandoffRange;
    const rounded = std.math.add(u64, end, 4095) catch return error.InvalidHandoffRange;
    if (base == 0 or bytes == 0) return error.InvalidHandoffRange;
    out.* = .{ .start = base & ~@as(u64, 4095), .end = rounded & ~@as(u64, 4095) };
}

// Boot-exclusive operation: the final physical root must already be active,
// its complete builder-reported prefix must remain owned, and no frame allocation
// or reservation sealing may have occurred. The handoff keeps its original
// allocation receipts; retirement only changes the allocator's ownership.
// Retirement state must outlive this operation and reside outside the reclaimed
// backing, as do the allocator metadata and its authoritative handoff inputs.
pub fn reclaimBootPagingArenas(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    retirement: *BootArenaRetirement,
    info: *const handoff.BootInfo,
    kernel_start: u64,
    kernel_end: u64,
    cache_view: cache_policy.ValidatedMtrrView,
    active_root: u64,
    used_final_pages: u32,
) Error!void {
    if (retirement.used_pages != 0) return error.BootArenasAlreadyRetired;
    if (allocator.allocated_count != 0) return error.FrameAllocated;
    if (allocator.reservations_sealed) return error.ReservationsSealed;
    const arenas = info.paging;
    if (page_size != 4096 or used_final_pages < 3 or used_final_pages > arenas.final_pages)
        return error.InvalidHandoffRange;
    if (active_root != arenas.final_base) return error.InvalidHandoffRange;
    try validateBootOwnedRanges(info, kernel_start, kernel_end, cache_view);

    const arena_runs = [_]frame_allocator.FrameRun{
        .{ .base = arenas.transition_base, .count = arenas.transition_pages },
        .{ .base = arenas.final_base, .count = arenas.final_pages },
    };
    // The broader admission above establishes complete described RAM and WB.
    // Retirement additionally needs the original reclaimable loader allocation
    // type throughout both full receipts, including the retained final prefix.
    for (info.memoryMap()) |entry| {
        for (arena_runs) |run| {
            if (entry.length == 0 or entry.base >= run.base + @as(u64, run.count) * 4096 or entry.end() <= run.base) continue;
            if (entry.firmware_type != 2 or (entry.kind != .available and entry.kind != .reserved)) return error.RamNotAvailable;
        }
    }
    for (arena_runs) |run| {
        try allocator.validateReservation(run);
        var offset: u64 = 0;
        while (offset < @as(u64, run.count) * 4096) : (offset += 4096) {
            if (!allocator.isReserved(run.base + offset)) return error.FrameReserved;
        }
    }

    const tail = frame_allocator.FrameRun{
        .base = arenas.final_base + @as(u64, used_final_pages) * 4096,
        .count = arenas.final_pages - used_final_pages,
    };
    if (tail.count != 0) try allocator.validateReservation(tail);
    const reserved_before = allocator.stats().reserved;
    // Every run and the allocator phase were checked before either mutation.
    // The boot-exclusive contract prevents phase changes during this commit.
    allocator.makeAvailable(arena_runs[0]) catch unreachable;
    if (tail.count != 0) allocator.makeAvailable(tail) catch unreachable;
    retirement.* = .{
        .used_pages = used_final_pages,
        .reclaimed_pages = arena_runs[0].count + tail.count,
        .reserved_before = reserved_before,
    };
}

// The loader extents that outlive the kernel's BootInfo copy: scanout, the
// copied TPM log and both paging arenas.
pub fn reserveLiveHandoffRanges(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    info: *const handoff.BootInfo,
) Error!void {
    var runs: [4]frame_allocator.FrameRun = undefined;
    var run_count: usize = 0;
    const paging = info.paging;
    paging.validate() catch return error.InvalidHandoffRange;

    // Firmware may describe scanout storage as usable RAM. It remains owned by
    // the display even when its format is unsupported by our renderer.
    if (paging.framebufferSpan() catch return error.InvalidHandoffRange) |span| {
        if (touchedPageRun(memory_bytes, page_size, span.start, span.end - span.start, span.end)) |run| {
            runs[run_count] = run;
            run_count += 1;
        }
    }

    if (info.tpmLog()) |tpm| {
        runs[run_count] = try liveRangeRun(memory_bytes, page_size, tpm.log_address, tpm.log_bytes);
        run_count += 1;
    }

    const arenas = [_]struct { base: u64, length: u64 }{
        .{ .base = paging.transition_base, .length = paging.transitionBytes() },
        .{ .base = paging.final_base, .length = paging.finalBytes() },
    };
    for (arenas) |arena| {
        runs[run_count] = try liveRangeRun(memory_bytes, page_size, arena.base, arena.length);
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

pub const PhysicalSpan = struct { start: u64, end: u64 };

// Reservation alone is not device authority: the allocator also reserves RAM
// owned by the image, heap, firmware tables and the live loader extents.
pub const KernelMappingAuthority = struct {
    info: *const handoff.BootInfo,
    image: PhysicalSpan,
    heap: PhysicalSpan,
    managed_bytes: u64,
    pci_ecam: ?PhysicalSpan = null,

    // The caller authenticates this allocation against the checksummed MCFG.
    // Reserved firmware descriptors alone never grant device-mapping authority.
    pub inline fn registerPciEcam(self: *@This(), allocator: anytype, allocation: mcfg.Allocation) error{ InvalidRange, PhysicalOwnershipConflict }!void {
        if (allocation.segment_group != 0 or allocation.start_bus != 0 or
            allocation.start_bus > allocation.end_bus or allocation.base_address == 0 or
            allocation.base_address % mcfg.ECAM_BUS_BYTES != 0) return error.InvalidRange;
        const bytes = std.math.mul(u64, allocation.busCount(), mcfg.ECAM_BUS_BYTES) catch return error.InvalidRange;
        const end = std.math.add(u64, allocation.base_address, bytes) catch return error.InvalidRange;
        const span = PhysicalSpan{ .start = allocation.base_address, .end = end };
        if (self.pci_ecam) |registered| {
            if (registered.start != span.start or registered.end != span.end) return error.PhysicalOwnershipConflict;
        }
        var candidate = self.*;
        candidate.pci_ecam = span;
        if (!candidate.permits(allocator, span.start, span.end, true)) return error.PhysicalOwnershipConflict;
        self.pci_ecam = span;
    }

    pub inline fn permits(self: @This(), allocator: anytype, start: u64, end: u64, device: bool) bool {
        if (start == 0 or start % 4096 != 0 or end % 4096 != 0 or end <= start or overlaps(start, end, self.image) or overlaps(start, end, self.heap) or
            (self.info.efi_system_table != 0 and overlapsBytes(start, end, self.info.efi_system_table, 4096))) return false;
        if (self.info.tpmLog()) |tpm| {
            if (overlapsBytes(start, end, tpm.log_address, tpm.log_bytes)) return false;
        }
        const paging = self.info.paging;
        if (overlapsBytes(start, end, paging.transition_base, paging.transitionBytes()) or
            overlapsBytes(start, end, paging.final_base, paging.finalBytes())) return false;
        var physical = start;
        while (physical < @min(end, self.managed_bytes)) : (physical += 4096) {
            if (!allocator.isReserved(physical) or allocator.isAllocated(physical)) return false;
        }
        const framebuffer = device and self.framebufferSpanPermits(start, end);
        const pci_ecam = device and if (self.pci_ecam) |span| start >= span.start and end <= span.end else false;
        const memory_map = self.info.memoryMap();
        for (memory_map) |entry| {
            if (entry.length == 0 or !overlaps(start, end, .{ .start = entry.base, .end = entry.end() })) continue;
            if (device) {
                if (entry.kind != .device_mmio and
                    !(framebuffer and (entry.kind == .available or entry.kind == .reserved)) and
                    !(pci_ecam and entry.kind == .reserved and !describedRamEntry(entry))) return false;
            } else if (entry.kind != .acpi_reclaimable and entry.kind != .acpi_nvs and entry.kind != .firmware_runtime_ram) return false;
        }
        // Explicit MMIO and unlisted reserved gaps are both device apertures.
        // Firmware reads instead require complete positively classified RAM.
        if (device) return true;
        var covered = start;
        while (covered < end) {
            var next = covered;
            for (memory_map) |entry| {
                if (entry.base <= covered and entry.end() > covered) next = @max(next, @min(entry.end(), end));
            }
            if (next == covered) return false;
            covered = next;
        }
        return true;
    }

    inline fn framebufferSpanPermits(self: @This(), start: u64, end: u64) bool {
        const span = (self.info.paging.framebufferSpan() catch return false) orelse return false;
        return start >= span.start and end <= span.end;
    }
};

inline fn overlaps(start: u64, end: u64, protected: PhysicalSpan) bool {
    return protected.start < protected.end and start < protected.end and protected.start < end;
}

inline fn overlapsBytes(start: u64, end: u64, base: u64, bytes: u64) bool {
    if (bytes == 0) return false;
    const protected_end = std.math.add(u64, base, bytes) catch return true;
    return overlaps(start, end, .{ .start = base, .end = protected_end });
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
    const clipped_end = @min(entry.end(), aperture_end);
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
    address: u64,
    length: u64,
) Error!frame_allocator.FrameRun {
    if (address == 0 or length == 0) return error.InvalidHandoffRange;
    const end = std.math.add(u64, address, length) catch return error.InvalidHandoffRange;
    if (end > memory_bytes) return error.InvalidHandoffRange;
    return touchedPageRun(memory_bytes, page_size, address, length, end) orelse
        error.InvalidHandoffRange;
}

const TEST_PAGE_SIZE: u32 = 4096;
const TEST_MAX_ARENA_BYTES: u64 = @as(u64, paging_info.MAX_ARENA_PAGES) * TEST_PAGE_SIZE;
const TEST_WRITE_BACK_MTRRS = cache_policy.MtrrState{
    .physical_bits = 52,
    .default_type = cache_policy.MTRR_ENABLED | @backingInt(cache_policy.MemoryType.write_back),
};
const KERNEL_HEAP_BYTES = @import("../../boot/image_info.zig").KERNEL_HEAP_BYTES;

fn initializeTestAllocator(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    memory_map: handoff.MemoryMap,
) Error!void {
    return initializeAllocator(memory_bytes, page_size, allocator, memory_map, try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS));
}

// A host fixture descriptor without an original EFI type.
fn hostEntry(base: u64, length: u64, kind: handoff.MemoryKind) handoff.MemoryMapEntry {
    return .{ .base = base, .length = length, .kind = kind };
}

fn nativeEntry(base: u64, length: u64, kind: handoff.MemoryKind, firmware_type: u32) handoff.MemoryMapEntry {
    return .{ .base = base, .length = length, .kind = kind, .firmware_type = firmware_type, .attributes = 8 };
}

fn testBootInfo(memory_map: handoff.MemoryMap) handoff.BootInfo {
    var info = @import("../../boot/boot_info.zig").testInfo();
    info.setMemoryMap(memory_map);
    return info;
}

fn testVariableMtrr(base: u64, bytes: u64, memory_type: cache_policy.MemoryType, physical_bits: u8) cache_policy.VariableMtrr {
    const physical_mask = (@as(u64, 1) << @as(u6, @intCast(physical_bits))) - 1;
    return .{
        .base = base | @backingInt(memory_type),
        .mask = (physical_mask & ~(bytes - 1) & ~@as(u64, 4095)) | cache_policy.MTRR_VALID,
    };
}

test "firmware map opens only complete usable pages" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);

    try initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, &.{hostEntry(TEST_PAGE_SIZE / 2, 3 * TEST_PAGE_SIZE, .available)});

    try std.testing.expect(allocator.isReserved(0));
    try std.testing.expect(!allocator.isReserved(1 * TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(3 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
}

test "effective WB admission controls real frame allocation release and contiguous search" {
    const page = TEST_PAGE_SIZE;
    const memory_bytes = 32 * page;
    const Allocator = frame_allocator.Fixed(memory_bytes, page);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.bindStorage(&storage);
    var state = TEST_WRITE_BACK_MTRRS;
    state.capabilities = 3;
    state.variable[0] = testVariableMtrr(4 * page, 2 * page, .uncacheable, state.physical_bits);
    state.variable[1] = testVariableMtrr(8 * page, page, .write_through, state.physical_bits);
    state.variable[2] = testVariableMtrr(10 * page, page, .write_protected, state.physical_bits);
    const view = try cache_policy.ValidatedMtrrView.init(&state);
    try initializeAllocator(memory_bytes, page, &allocator, &.{ hostEntry(0, memory_bytes, .available), hostEntry(11 * page + 100, 1, .reserved) }, view);
    try std.testing.expectEqual(@as(u32, 27), allocator.stats().free);

    var allocated: [27]u64 = undefined;
    for (&allocated) |*address| {
        address.* = allocator.allocate(1).?.base;
        try view.requireWriteBack(address.*, page);
        try std.testing.expect(address.* != 11 * page);
    }
    try std.testing.expect(allocator.allocate(1) == null);
    for (allocated) |address| try allocator.release(.{ .base = address, .count = 1 });
    try std.testing.expectEqual(@as(u32, 27), allocator.stats().free);
    try std.testing.expectError(error.FrameReserved, allocator.release(.{ .base = 4 * page, .count = 1 }));
    const contiguous = allocator.allocate(5).?;
    try std.testing.expectEqual(@as(u64, 12 * page), contiguous.base);
    try view.requireWriteBack(contiguous.base, @as(u64, contiguous.count) * page);
    try allocator.release(contiguous);
    try std.testing.expect(allocator.allocate(32) == null);
}

test "WB interval admission coalesces equal types and rejects partially non-WB larger pages" {
    const page: u32 = 16 * 1024;
    const memory_bytes = 8 * page;
    const Allocator = frame_allocator.Fixed(memory_bytes, page);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.bindStorage(&storage);
    var state = TEST_WRITE_BACK_MTRRS;
    state.capabilities = 3;
    state.variable[0] = testVariableMtrr(0x1000, 0x1000, .write_back, state.physical_bits);
    state.variable[1] = testVariableMtrr(0x9000, 0x1000, .uncacheable, state.physical_bits);
    state.variable[2] = testVariableMtrr(0x12000, 0x1000, .write_through, state.physical_bits);
    const view = try cache_policy.ValidatedMtrrView.init(&state);
    try initializeAllocator(memory_bytes, page, &allocator, &.{hostEntry(0, memory_bytes, .available)}, view);
    try std.testing.expectEqual(@as(u32, 6), allocator.stats().free);
    for ([_]u64{ 0, 1, 3, 5, 6, 7 }) |frame| {
        const run = allocator.allocate(1).?;
        try std.testing.expectEqual(frame * page, run.base);
        try view.requireWriteBack(run.base, page);
    }
    try std.testing.expect(allocator.allocate(1) == null);
}

test "firmware availability is clipped to admitted physical address width" {
    const physical_limit: u64 = 1 << 32;
    const memory_bytes = physical_limit + 4 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.bindStorage(&storage);
    var state = TEST_WRITE_BACK_MTRRS;
    state.physical_bits = 32;
    const view = try cache_policy.ValidatedMtrrView.init(&state);
    try initializeAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, &.{hostEntry(physical_limit - 2 * TEST_PAGE_SIZE, 6 * TEST_PAGE_SIZE, .available)}, view);
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
    try std.testing.expectEqual(physical_limit - 2 * TEST_PAGE_SIZE, allocator.allocate(2).?.base);
    try std.testing.expect(allocator.allocate(1) == null);
    try std.testing.expect(allocator.isReserved(physical_limit));
}

test "native usable descriptors cannot disguise device or runtime memory" {
    const Allocator = frame_allocator.Fixed(4 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.bindStorage(&storage);
    try initializeTestAllocator(4 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, &.{
        nativeEntry(0, TEST_PAGE_SIZE, .available, 2),
        nativeEntry(TEST_PAGE_SIZE, TEST_PAGE_SIZE, .available, 11),
        nativeEntry(2 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, .available, 6),
    });
    try std.testing.expectEqual(@as(u32, 1), allocator.stats().free);
    try std.testing.expectEqual(@as(u64, 0), allocator.allocate(1).?.base);
    try std.testing.expect(allocator.allocate(1) == null);
}

test "early RAM admission requires complete coverage effective WB and appropriate ownership" {
    const page = TEST_PAGE_SIZE;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var map = [_]handoff.MemoryMapEntry{
        nativeEntry(4 * page, 2 * page, .reserved, 2),
        nativeEntry(0, 4 * page, .available, 7),
        nativeEntry(6 * page, 2 * page, .acpi_reclaimable, 9),
        nativeEntry(8 * page, page, .device_mmio, 11),
    };
    try requireAvailableRamWriteBack(&map, 0, 4 * page, view);
    try requireRamWriteBack(&map, 0, 8 * page, view);
    try std.testing.expectError(error.RamNotAvailable, requireAvailableRamWriteBack(&map, 0, 5 * page, view));
    try std.testing.expectError(error.RamNotAvailable, requireRamWriteBack(&map, 0, 9 * page, view));
    try std.testing.expectError(error.RamNotAvailable, requireRamWriteBack(&map, 9 * page, page, view));
    try std.testing.expectError(error.InvalidHandoffRange, requireRamWriteBack(&map, std.math.maxInt(u64), page, view));
    try std.testing.expectError(error.InvalidHandoffRange, requireRamWriteBack(&map, 0, 0, view));

    // A tiny non-usable overlap blocks an otherwise completely covered heap.
    map[3] = nativeEntry(2 * page + 1, 1, .reserved, 2);
    try std.testing.expectError(error.RamNotAvailable, requireAvailableRamWriteBack(&map, 0, 4 * page, view));
    try requireRamWriteBack(&map, 0, 4 * page, view);
    map[3].firmware_type = 0;
    try std.testing.expectError(error.RamNotAvailable, requireRamWriteBack(&map, 0, 4 * page, view));

    var state = TEST_WRITE_BACK_MTRRS;
    state.capabilities = 1;
    state.variable[0] = testVariableMtrr(page, page, .uncacheable, state.physical_bits);
    const mixed_view = try cache_policy.ValidatedMtrrView.init(&state);
    try std.testing.expectError(error.MixedMemoryTypes, requireAvailableRamWriteBack(&map, 0, 4 * page, mixed_view));
}

const BootOwnedTest = struct {
    const mib = 1024 * 1024;
    const memory_bytes = 160 * mib;
    const kernel_start: u64 = 16 * mib;
    const kernel_end: u64 = 24 * mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);

    // Unsorted descriptors distinguish available allocations from the two
    // positively typed reserved loader arenas.
    fn setMemoryMap(boot_info: *handoff.BootInfo) void {
        const arenas = boot_info.paging;
        const transition_end = arenas.transition_base + arenas.transitionBytes();
        const final_end = arenas.final_base + arenas.finalBytes();
        boot_info.setMemoryMap(&.{
            nativeEntry(arenas.final_base, arenas.finalBytes(), .reserved, 2),
            nativeEntry(0, arenas.transition_base, .available, 7),
            nativeEntry(final_end, memory_bytes - final_end, .available, 7),
            nativeEntry(arenas.transition_base, arenas.transitionBytes(), .reserved, 2),
            nativeEntry(transition_end, arenas.final_base - transition_end, .available, 7),
        });
    }

    fn info() handoff.BootInfo {
        var result = @import("../../boot/boot_info.zig").testInfo();
        result.efi_system_table = 8 * mib + 128;
        result.image = .{
            .firmware_authenticated = false,
            .kernel_digest = @splat(1),
            .cmdline_digest = @splat(2),
            .heap_base = 32 * mib,
        };
        result.paging = .{ .transition_pages = paging_info.MAX_ARENA_PAGES, .final_pages = paging_info.MAX_ARENA_PAGES, .transition_base = 80 * mib, .final_base = 112 * mib };
        result.tpm = .{ .log_address = 4 * mib, .log_bytes = TEST_PAGE_SIZE + 1, .final_events = 2, .pcr11 = @splat(7) };
        setMemoryMap(&result);
        return result;
    }

    fn expectUntouched(storage: *const Allocator.Storage) !void {
        for (std.mem.asBytes(storage)) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    }

    fn initializeAfterAdmission(allocator: *Allocator, boot_info: *const handoff.BootInfo, image_start: u64, image_end: u64, view: cache_policy.ValidatedMtrrView) Error!void {
        try validateBootOwnedRanges(boot_info, image_start, image_end, view);
        try initializeAllocator(memory_bytes, TEST_PAGE_SIZE, allocator, boot_info.memoryMap(), view);
    }

    fn prepareRetirement(storage: *Allocator.Storage, boot_info: *const handoff.BootInfo, view: cache_policy.ValidatedMtrrView) Error!Allocator {
        @memset(std.mem.asBytes(storage), 0xa5);
        var allocator = Allocator.bindStorage(storage);
        try initializeAfterAdmission(&allocator, boot_info, kernel_start, kernel_end, view);
        try reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, boot_info);
        try reserveKernelRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, kernel_start, kernel_end, boot_info.image.heap_base, KERNEL_HEAP_BYTES);
        return allocator;
    }

    fn reclaim(allocator: *Allocator, retirement: *BootArenaRetirement, boot_info: *const handoff.BootInfo, view: cache_policy.ValidatedMtrrView, active_root: u64, used_pages: u32) Error!void {
        return reclaimBootPagingArenas(memory_bytes, TEST_PAGE_SIZE, allocator, retirement, boot_info, kernel_start, kernel_end, view, active_root, used_pages);
    }

    fn expectRejectedRetirement(expected: Error, allocator: *Allocator, retirement: *BootArenaRetirement, boot_info: *const handoff.BootInfo, view: cache_policy.ValidatedMtrrView, active_root: u64, used_pages: u32) !void {
        const before = allocator.*;
        const storage_before = allocator.storage.*;
        const retirement_before = retirement.*;
        try std.testing.expectError(expected, reclaim(allocator, retirement, boot_info, view, active_root, used_pages));
        try std.testing.expectEqualDeep(before, allocator.*);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&storage_before), std.mem.asBytes(allocator.storage));
        try std.testing.expectEqualDeep(retirement_before, retirement.*);
    }
};

test "variable boot arena retirement recovers exact runs and preserves the complete final prefix" {
    const fixture = BootOwnedTest;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    for ([_]u32{ 3, 31, paging_info.MAX_ARENA_PAGES }) |transition_pages| {
        for ([_]u32{ 3, 31, paging_info.MAX_ARENA_PAGES }) |final_pages| {
            var info = fixture.info();
            info.paging.transition_pages = transition_pages;
            info.paging.final_pages = final_pages;
            fixture.setMemoryMap(&info);
            const arenas = info.paging;
            for ([_]u32{ 3, @min(17, final_pages), final_pages }) |used_pages| {
                var allocator = try fixture.prepareRetirement(&storage, &info, view);
                var retirement: BootArenaRetirement = .{};
                const before = allocator.stats();
                const bitmap_before = storage.unavailable_bitmap;
                try fixture.reclaim(&allocator, &retirement, &info, view, arenas.final_base, used_pages);
                const reclaimed = arenas.transition_pages + arenas.final_pages - used_pages;
                try std.testing.expectEqualDeep(BootArenaRetirement{
                    .used_pages = used_pages,
                    .reclaimed_pages = reclaimed,
                    .reserved_before = before.reserved,
                }, retirement);
                try std.testing.expectEqualDeep(frame_allocator.Stats{
                    .total = before.total,
                    .reserved = before.reserved - reclaimed,
                    .allocated = 0,
                    .free = before.free + reclaimed,
                }, allocator.stats());
                const tail_base = arenas.final_base + @as(u64, used_pages) * TEST_PAGE_SIZE;
                for (0..fixture.Allocator.total_frames) |index| {
                    const physical = index * TEST_PAGE_SIZE;
                    const was_reserved = (bitmap_before[index / 64] & (@as(u64, 1) << @as(u6, @intCast(index % 64)))) != 0;
                    const reopened = (physical >= arenas.transition_base and physical < arenas.transition_base + arenas.transitionBytes()) or
                        (physical >= tail_base and physical < arenas.final_base + arenas.finalBytes());
                    try std.testing.expectEqual(was_reserved and !reopened, allocator.isReserved(physical));
                }
                try std.testing.expect(!allocator.reservations_sealed);
                try fixture.expectRejectedRetirement(error.BootArenasAlreadyRetired, &allocator, &retirement, &info, view, arenas.final_base, used_pages);
                try allocator.sealReservations();
                const transition = allocator.allocateBetween(arenas.transition_pages, arenas.transition_base, arenas.transition_base + arenas.transitionBytes()).?;
                try std.testing.expectEqual(arenas.transition_base, transition.base);
                const tail = if (used_pages < arenas.final_pages)
                    allocator.allocateBetween(arenas.final_pages - used_pages, tail_base, arenas.final_base + arenas.finalBytes()).?
                else
                    null;
                if (tail) |run| try std.testing.expectEqual(tail_base, run.base);
                try std.testing.expect(allocator.allocateBetween(1, arenas.final_base, tail_base) == null);
                try allocator.release(transition);
                if (tail) |run| try allocator.release(run);
                try std.testing.expectEqual(before.free + reclaimed, allocator.stats().free);
                try std.testing.expectEqual(@as(u32, 0), allocator.stats().allocated);
                // The explicit one-shot state remains authoritative after allocation,
                // release and sealing; an old boot receipt cannot reopen either run.
                try fixture.expectRejectedRetirement(error.BootArenasAlreadyRetired, &allocator, &retirement, &info, view, arenas.final_base, used_pages);
            }
        }
    }
}

test "boot arena retirement rejects impossible prefix and inactive root without mutation" {
    const fixture = BootOwnedTest;
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, &info, view);
    var retirement: BootArenaRetirement = .{};
    for ([_]u32{ 0, 1, 2, paging_info.MAX_ARENA_PAGES + 1, std.math.maxInt(u32) }) |used_pages|
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, &info, view, info.paging.final_base, used_pages);
    for ([_]u64{ 0, info.paging.transition_base, info.paging.final_base + 1, @import("../../arch/kernel_address.zig").image_virtual_bias + info.paging.final_base }) |root|
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, &info, view, root, 17);
}

test "boot arena retirement requires loader-data provenance over both complete receipts" {
    const fixture = BootOwnedTest;
    var info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, &info, view);
    var retirement: BootArenaRetirement = .{};
    // Entries 0 and 3 are the final and transition arena receipts.
    for ([_]usize{ 0, 3 }) |arena_entry| {
        for ([_]u32{ 1, 3, 6, 7, 9, 11, std.math.maxInt(u32) }) |firmware_type| {
            fixture.setMemoryMap(&info);
            info.memory_map[arena_entry].firmware_type = firmware_type;
            try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, &info, view, info.paging.final_base, 17);
        }
    }
    // A last-page gap precedes mutation of the otherwise valid first reclaim run.
    fixture.setMemoryMap(&info);
    info.memory_map[0].length = TEST_MAX_ARENA_BYTES - TEST_PAGE_SIZE;
    try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, &info, view, info.paging.final_base, 17);

    fixture.setMemoryMap(&info);
    var overlapping = info;
    overlapping.memory_map[overlapping.memory_map_count] = nativeEntry(info.paging.final_base + 1, 1, .reserved, 7);
    overlapping.memory_map_count += 1;
    try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, &overlapping, view, info.paging.final_base, 17);
}

test "unequal arena receipts enforce their own provenance WB and GOP boundaries" {
    const fixture = BootOwnedTest;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    for ([_]struct { transition: u32, final: u32 }{ .{ .transition = 3, .final = 31 }, .{ .transition = 31, .final = 3 } }) |capacity| {
        var info = fixture.info();
        info.paging.transition_pages = capacity.transition;
        info.paging.final_pages = capacity.final;
        fixture.setMemoryMap(&info);
        const arenas = info.paging;
        var allocator = try fixture.prepareRetirement(&storage, &info, view);
        var retirement: BootArenaRetirement = .{};
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, &info, view, arenas.final_base, arenas.final_pages + 1);
        for ([_]u32{ 0, 2, paging_info.MAX_ARENA_PAGES + 1 }) |bad_capacity| {
            var bad_info = info;
            bad_info.paging.transition_pages = bad_capacity;
            try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, &bad_info, view, arenas.final_base, 3);
            bad_info = info;
            bad_info.paging.final_pages = bad_capacity;
            try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, &bad_info, view, arenas.final_base, 3);
        }
        for ([_]usize{ 0, 3 }) |arena_entry| {
            info.memory_map[arena_entry].firmware_type = 6;
            try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, &info, view, arenas.final_base, 3);
            fixture.setMemoryMap(&info);
        }
        info.memory_map[0].length = arenas.finalBytes() - TEST_PAGE_SIZE;
        try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, &info, view, arenas.final_base, 3);
        fixture.setMemoryMap(&info);
        for ([_]u64{ arenas.transition_base + arenas.transitionBytes() - TEST_PAGE_SIZE, arenas.final_base + arenas.finalBytes() - TEST_PAGE_SIZE }) |last_page| {
            var state = TEST_WRITE_BACK_MTRRS;
            state.capabilities = 1;
            state.variable[0] = testVariableMtrr(last_page, TEST_PAGE_SIZE, .uncacheable, state.physical_bits);
            const mixed_view = try cache_policy.ValidatedMtrrView.init(&state);
            try fixture.expectRejectedRetirement(error.MixedMemoryTypes, &allocator, &retirement, &info, mixed_view, arenas.final_base, 3);
        }
        info.paging.framebuffer_base = arenas.final_base + arenas.finalBytes() - 1;
        info.paging.framebuffer_bytes = 1;
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, &info, view, arenas.final_base, 3);
        // GOP immediately after a small arena was inside the old fixed 16 MiB
        // envelope. It is now a distinct protected allocation, never reclaimed.
        info.paging.framebuffer_base = arenas.final_base + arenas.finalBytes();
        info.paging.framebuffer_bytes = TEST_PAGE_SIZE;
        allocator = try fixture.prepareRetirement(&storage, &info, view);
        const before = allocator.stats();
        try fixture.reclaim(&allocator, &retirement, &info, view, arenas.final_base, 3);
        try std.testing.expectEqual(capacity.transition + capacity.final - 3, retirement.reclaimed_pages);
        try std.testing.expectEqual(before.reserved - retirement.reclaimed_pages, allocator.stats().reserved);
        try std.testing.expect(allocator.isReserved(info.paging.framebuffer_base));
        try std.testing.expect(!allocator.isReserved(arenas.transition_base + arenas.transitionBytes()));
    }
}

test "boot arena retirement checks WB backing including the retained final prefix" {
    const fixture = BootOwnedTest;
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, &info, view);
    var retirement: BootArenaRetirement = .{};
    for ([_]u64{ info.paging.transition_base, info.paging.final_base, info.paging.final_base + TEST_MAX_ARENA_BYTES - TEST_PAGE_SIZE }) |non_wb| {
        var state = TEST_WRITE_BACK_MTRRS;
        state.capabilities = 1;
        state.variable[0] = testVariableMtrr(non_wb, TEST_PAGE_SIZE, .uncacheable, state.physical_bits);
        const mixed_view = try cache_policy.ValidatedMtrrView.init(&state);
        try fixture.expectRejectedRetirement(error.MixedMemoryTypes, &allocator, &retirement, &info, mixed_view, info.paging.final_base, 17);
    }
}

test "boot arena retirement rechecks live ownership and geometry before opening arenas" {
    const fixture = BootOwnedTest;
    const original = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, &original, view);
    var retirement: BootArenaRetirement = .{};
    const Attack = enum { heap, tpm, gop, misaligned_arena, arena_overlap, zero_paging };
    for (std.enums.values(Attack)) |attack| {
        var info = original;
        switch (attack) {
            .heap => info.image.heap_base = info.paging.transition_base,
            .tpm => info.tpm.log_address = info.paging.final_base + 17 * TEST_PAGE_SIZE,
            .gop => {
                info.paging.framebuffer_base = info.paging.transition_base - TEST_PAGE_SIZE + 1;
                info.paging.framebuffer_bytes = TEST_PAGE_SIZE;
            },
            .misaligned_arena => info.paging.transition_base += 1,
            .arena_overlap => info.paging.transition_base = info.paging.final_base,
            .zero_paging => info.paging = std.mem.zeroes(paging_info.Info),
        }
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, &info, view, original.paging.final_base, 17);
    }
    // Losing even a page in the unused second run invalidates the complete
    // preflight, leaving the fully reserved transition run intact.
    for ([_]u64{ original.paging.transition_base, original.paging.final_base, original.paging.final_base + TEST_MAX_ARENA_BYTES - TEST_PAGE_SIZE }) |missing| {
        allocator = try fixture.prepareRetirement(&storage, &original, view);
        try allocator.makeAvailable(.{ .base = missing, .count = 1 });
        try fixture.expectRejectedRetirement(error.FrameReserved, &allocator, &retirement, &original, view, original.paging.final_base, 17);
    }
}

test "boot arena retirement is forbidden after sealing or the first frame allocation" {
    const fixture = BootOwnedTest;
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, &info, view);
    var retirement: BootArenaRetirement = .{};
    try allocator.sealReservations();
    try fixture.expectRejectedRetirement(error.ReservationsSealed, &allocator, &retirement, &info, view, info.paging.final_base, 17);
    const allocated = allocator.allocate(1).?;
    try fixture.expectRejectedRetirement(error.FrameAllocated, &allocator, &retirement, &info, view, info.paging.final_base, 17);
    try allocator.release(allocated);
    try fixture.expectRejectedRetirement(error.ReservationsSealed, &allocator, &retirement, &info, view, info.paging.final_base, 17);
}

test "boot arena retirement prevalidates the second run allocator aperture" {
    const fixture = BootOwnedTest;
    const memory_bytes = 100 * fixture.mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    const storage_before = storage;
    const allocator_before = allocator;
    var retirement: BootArenaRetirement = .{};
    try std.testing.expectError(error.OutOfRange, reclaimBootPagingArenas(memory_bytes, TEST_PAGE_SIZE, &allocator, &retirement, &info, fixture.kernel_start, fixture.kernel_end, view, info.paging.final_base, 17));
    try std.testing.expectEqualDeep(allocator_before, allocator);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&storage_before), std.mem.asBytes(&storage));
    try std.testing.expectEqualDeep(BootArenaRetirement{}, retirement);
}

test "boot arena retirement rejects allocator geometry that cannot represent table pages" {
    const fixture = BootOwnedTest;
    const page_size = 2 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(fixture.memory_bytes, page_size);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    const storage_before = storage;
    const allocator_before = allocator;
    var retirement: BootArenaRetirement = .{};
    try std.testing.expectError(error.InvalidHandoffRange, reclaimBootPagingArenas(fixture.memory_bytes, page_size, &allocator, &retirement, &info, fixture.kernel_start, fixture.kernel_end, view, info.paging.final_base, 17));
    try std.testing.expectEqualDeep(allocator_before, allocator);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&storage_before), std.mem.asBytes(&storage));
    try std.testing.expectEqualDeep(BootArenaRetirement{}, retirement);
}

test "boot owned admission reserves live loader extents before real bitmap ownership" {
    const fixture = BootOwnedTest;
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);

    try validateBootOwnedRanges(&info, fixture.kernel_start, fixture.kernel_end, view);
    try fixture.expectUntouched(&storage);
    try initializeAllocator(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, info.memoryMap(), view);
    try reserveLiveHandoffRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, &info);
    try reserveKernelRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, fixture.kernel_start, fixture.kernel_end, info.image.heap_base, KERNEL_HEAP_BYTES);
    try allocator.sealReservations();
    for ([_]u64{ 4 * fixture.mib, 4 * fixture.mib + TEST_PAGE_SIZE, 16 * fixture.mib, 32 * fixture.mib, 80 * fixture.mib, 112 * fixture.mib }) |address|
        try std.testing.expect(allocator.isReserved(address));
    // The kernel owns its BootInfo copy, so the loader's record pages are
    // ordinary available RAM.
    try std.testing.expect(!allocator.isReserved(2 * fixture.mib));
    try std.testing.expect(!allocator.isReserved(128 * fixture.mib));
    const run = allocator.allocate(1).?;
    try view.requireWriteBack(run.base, TEST_PAGE_SIZE);
    try allocator.release(run);
}

test "forged boot owned overlaps and live loader extents fail before bitmap writes" {
    const fixture = BootOwnedTest;
    const Attack = enum {
        heap_image,
        heap_tpm,
        heap_efi,
        arena_image,
        arena_heap,
        arena_tpm,
        arena_efi,
        arena_arena,
        image_tpm,
        image_efi_touched_neighbor,
        tpm_overflow,
        efi_overflow,
        zero_image,
        zero_paging,
        image_misaligned,
        heap_misaligned,
    };
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);
    for (std.enums.values(Attack)) |attack| {
        var info = fixture.info();
        var kernel_start = fixture.kernel_start;
        var kernel_end = fixture.kernel_end;
        switch (attack) {
            .heap_image => info.image.heap_base = fixture.kernel_start,
            .heap_tpm => info.image.heap_base = info.tpm.log_address,
            .heap_efi => info.image.heap_base = 8 * fixture.mib,
            .arena_image => info.paging.final_base = fixture.kernel_start,
            .arena_heap => info.paging.final_base = info.image.heap_base,
            .arena_tpm => info.paging.final_base = info.tpm.log_address,
            .arena_efi => info.paging.final_base = 8 * fixture.mib,
            .arena_arena => info.paging.final_base = info.paging.transition_base,
            .image_tpm => {
                kernel_start = info.tpm.log_address;
                kernel_end = kernel_start + TEST_PAGE_SIZE;
            },
            .image_efi_touched_neighbor => {
                kernel_start = 8 * fixture.mib + TEST_PAGE_SIZE;
                kernel_end = kernel_start + TEST_PAGE_SIZE;
            },
            .tpm_overflow => info.tpm.log_address = std.math.maxInt(u64),
            .efi_overflow => info.efi_system_table = std.math.maxInt(u64),
            .zero_image => info.image = std.mem.zeroes(@TypeOf(info.image)),
            .zero_paging => info.paging = std.mem.zeroes(paging_info.Info),
            .image_misaligned => kernel_start += 1,
            .heap_misaligned => info.image.heap_base += 1,
        }
        try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, &info, kernel_start, kernel_end, view));
        try fixture.expectUntouched(&storage);
    }
}

test "boot owned admission rejects untyped unavailable and partially non-WB backing" {
    const fixture = BootOwnedTest;
    var info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);

    // Entry 1 backs the kernel and heap. Every claimed allocation needs a
    // positively typed original EFI descriptor.
    info.memory_map[1].firmware_type = std.math.maxInt(u32);
    try std.testing.expectError(error.RamNotAvailable, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view));
    fixture.setMemoryMap(&info);
    info.memory_map[1].kind = .reserved;
    try std.testing.expectError(error.RamNotAvailable, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view));
    fixture.setMemoryMap(&info);
    info.memory_map[0].firmware_type = 11;
    try std.testing.expectError(error.RamNotAvailable, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view));
    fixture.setMemoryMap(&info);

    var state = TEST_WRITE_BACK_MTRRS;
    state.capabilities = 1;
    state.variable[0] = testVariableMtrr(info.image.heap_base + TEST_PAGE_SIZE, TEST_PAGE_SIZE, .write_through, state.physical_bits);
    const mixed_view = try cache_policy.ValidatedMtrrView.init(&state);
    try std.testing.expectError(error.MixedMemoryTypes, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, mixed_view));
    try fixture.expectUntouched(&storage);
}

test "scanout touched pages cannot become owned WB backing before bitmap writes" {
    const fixture = BootOwnedTest;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);
    // Unsupported geometry still describes live device storage. It is not
    // permission to reclaim an overlap that is otherwise positively typed WB.
    var info = fixture.info();
    const owned = [_]PhysicalSpan{
        .{ .start = fixture.kernel_start, .end = fixture.kernel_end },
        .{ .start = info.image.heap_base, .end = info.image.heap_base + KERNEL_HEAP_BYTES },
        .{ .start = info.paging.transition_base, .end = info.paging.transition_base + TEST_MAX_ARENA_BYTES },
        .{ .start = info.paging.final_base, .end = info.paging.final_base + TEST_MAX_ARENA_BYTES },
    };
    for (owned) |span| {
        try requireRamWriteBack(info.memoryMap(), span.start, span.end - span.start, view);
        for ([_]u64{ span.start - 1, span.start, span.end - 1 }) |base| {
            info.paging.framebuffer_base = base;
            info.paging.framebuffer_bytes = if (base == span.start - 1) 2 else 1;
            try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view));
            try fixture.expectUntouched(&storage);
        }
        // Exact adjacency is safe on either side; rounding must not claim an
        // extra page when the byte extent ends at an owned-page boundary.
        info.paging.framebuffer_bytes = 1;
        for ([_]u64{ span.start - 1, span.end }) |base| {
            info.paging.framebuffer_base = base;
            try validateBootOwnedRanges(&info, fixture.kernel_start, fixture.kernel_end, view);
            try fixture.expectUntouched(&storage);
        }
    }

    info.paging.framebuffer_base = 128 * fixture.mib;
    info.paging.framebuffer_bytes = 0;
    try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view));
    info.paging.framebuffer_base = std.math.maxInt(u64) - 4095;
    info.paging.framebuffer_bytes = 2 * TEST_PAGE_SIZE;
    try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view));
    try fixture.expectUntouched(&storage);
}

test "advertised GOP padding stays reserved independently of supported rendering" {
    const fixture = BootOwnedTest;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = fixture.Allocator.bindStorage(&storage);
    for ([_]bool{ false, true }) |visible| {
        var info = fixture.info();
        info.paging.framebuffer_base = 136 * fixture.mib + 128;
        info.paging.framebuffer_bytes = 3 * TEST_PAGE_SIZE + 1;
        if (visible) {
            info.framebuffer = .{
                .base = info.paging.framebuffer_base,
                .width = 32,
                .height = 32,
                .pitch = 128,
                .red_mask = 0xff0000,
                .green_mask = 0xff00,
                .blue_mask = 0xff,
            };
        }
        try fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view);
        try reserveLiveHandoffRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, &info);
        const span = (try info.paging.framebufferSpan()).?;
        for (0..4) |index| try std.testing.expect(allocator.isReserved(span.start + index * TEST_PAGE_SIZE));
        try std.testing.expect(!allocator.isReserved(span.start - TEST_PAGE_SIZE));
        try std.testing.expect(!allocator.isReserved(span.end));
        const authority = KernelMappingAuthority{
            .info = &info,
            .image = .{ .start = fixture.kernel_start, .end = fixture.kernel_end },
            .heap = .{ .start = info.image.heap_base, .end = info.image.heap_base + KERNEL_HEAP_BYTES },
            .managed_bytes = fixture.memory_bytes,
        };
        try std.testing.expect(authority.permits(&allocator, span.start, span.end, true));
        try std.testing.expect(authority.permits(&allocator, span.start, span.start + 2 * TEST_PAGE_SIZE, true));
        try std.testing.expect(authority.permits(&allocator, span.end - TEST_PAGE_SIZE, span.end, true));
        try std.testing.expect(!authority.permits(&allocator, span.start - TEST_PAGE_SIZE, span.start + TEST_PAGE_SIZE, true));
        try std.testing.expect(!authority.permits(&allocator, span.end - TEST_PAGE_SIZE, span.end + TEST_PAGE_SIZE, true));
        try std.testing.expect(!authority.permits(&allocator, span.start, span.end, false));
        if (visible) {
            const visible_bytes = @as(u64, info.framebuffer.pitch) * info.framebuffer.height;
            try std.testing.expect(visible_bytes < info.paging.framebuffer_bytes);
            try std.testing.expect(allocator.isReserved(span.start + 3 * TEST_PAGE_SIZE));
        } else try std.testing.expectEqual(@as(u64, 0), info.framebuffer.base);
    }
}

test "advertised GOP tail collisions reject unsupported and visible fixtures before bitmap writes" {
    const fixture = BootOwnedTest;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);
    for ([_]bool{ false, true }) |visible| {
        for ([_]u64{ fixture.kernel_start, 32 * fixture.mib, 80 * fixture.mib, 112 * fixture.mib }) |owned_start| {
            var info = fixture.info();
            info.paging.framebuffer_base = owned_start - 2 * TEST_PAGE_SIZE + 128;
            info.paging.framebuffer_bytes = 2 * TEST_PAGE_SIZE + 1;
            if (visible) {
                info.framebuffer = .{
                    .base = info.paging.framebuffer_base,
                    .pitch = TEST_PAGE_SIZE,
                    .height = 1,
                    .width = 1,
                    .red_mask = 0xff0000,
                    .green_mask = 0xff00,
                    .blue_mask = 0xff,
                };
            }
            // Only the advertised padding collides with an owned extent.
            try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view));
            if (owned_start == info.paging.transition_base or owned_start == info.paging.final_base)
                try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, &info));
            try fixture.expectUntouched(&storage);
        }
    }
}

test "advertised GOP malformed extents fail atomically without a render mode" {
    const fixture = BootOwnedTest;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);
    const bad_extents = [_]struct { base: u64, length: u64 }{
        .{ .base = 0, .length = 4096 },
        .{ .base = 136 * fixture.mib, .length = 0 },
        .{ .base = std.math.maxInt(u64) - 4095, .length = 8192 },
        .{ .base = std.math.maxInt(u64) - 100, .length = 1 },
        .{ .base = @import("../../arch/kernel_address.zig").direct_map_capacity, .length = 1 },
    };
    for (bad_extents) |extent| {
        var info = fixture.info();
        info.paging.framebuffer_base = extent.base;
        info.paging.framebuffer_bytes = extent.length;
        try std.testing.expectEqual(@as(u64, 0), info.framebuffer.base);
        try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, &info, fixture.kernel_start, fixture.kernel_end, view));
        try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, &info));
        try fixture.expectUntouched(&storage);
    }
}

test "kernel and EFI heap reservations preserve free gaps and firmware NVS" {
    const mib = 1024 * 1024;
    const memory_bytes = 128 * mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try initializeTestAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, &.{ hostEntry(0, memory_bytes, .available), hostEntry(8 * mib, mib, .acpi_nvs) });
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

    try initializeTestAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, &.{hostEntry(high_frame_base, 2 * TEST_PAGE_SIZE, .available)});

    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
    try std.testing.expectEqual(high_frame_base, allocator.allocate(2).?.base);
}

test "non-usable pages win over usable pages in either descriptor order" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    const usable_first = [_]handoff.MemoryMapEntry{ hostEntry(0, 6 * TEST_PAGE_SIZE, .available), hostEntry(2 * TEST_PAGE_SIZE + 100, 200, .reserved) };
    const reserved_first = [_]handoff.MemoryMapEntry{ usable_first[1], usable_first[0] };

    var first_storage: Allocator.Storage = undefined;
    var first = Allocator.init(&first_storage);
    var second_storage: Allocator.Storage = undefined;
    var second = Allocator.init(&second_storage);
    try initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &first, &usable_first);
    try initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &second, &reserved_first);

    try std.testing.expect(first.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(second.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(first.stats(), second.stats());
    try std.testing.expectEqual(@as(u32, 5), first.stats().free);
}

test "non-usable page ceilings and aperture clipping are conservative" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, &.{
        hostEntry(1, 8 * TEST_PAGE_SIZE, .available),
        hostEntry(TEST_PAGE_SIZE - 1, 2, .reserved),
        hostEntry(8 * TEST_PAGE_SIZE - 1, 2, .acpi_nvs),
    });

    try std.testing.expect(allocator.isReserved(0));
    try std.testing.expect(allocator.isReserved(TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(allocator.isReserved(7 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 5), allocator.stats().free);
}

test "an empty firmware map leaves the aperture closed" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try std.testing.expectError(error.InvalidMemoryMap, initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, &.{}));
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().free);
}

// Loader extents in the first 2 MiB: a TPM log at 1 MiB and both arenas.
fn lowLoaderInfo() handoff.BootInfo {
    var info = testBootInfo(&.{hostEntry(0, 2 * 1024 * 1024, .available)});
    info.paging = .{ .transition_pages = 3, .final_pages = 3, .transition_base = 0x180000, .final_base = 0x1c0000 };
    return info;
}

test "copied TPM event log remains reserved and malformed extents fail before mutation" {
    const memory_bytes = 2 * 1024 * 1024;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var info = lowLoaderInfo();
    info.tpm = .{ .log_address = 0x100000, .log_bytes = 2 * TEST_PAGE_SIZE + 1, .final_events = 2, .pcr11 = @splat(7) };
    try reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, &info);
    for (0..3) |index| try std.testing.expect(allocator.isReserved(0x100000 + index * TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(0x100000 - TEST_PAGE_SIZE));
    try std.testing.expect(!allocator.isReserved(0x100000 + 3 * TEST_PAGE_SIZE));
    allocator.reset();
    info.tpm.log_address = std.math.maxInt(u64);
    try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, &info));
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().reserved);
}

test "both loader paging arenas stay owned and cannot become framebuffer aliases" {
    const mib = 1024 * 1024;
    const memory_bytes = 128 * mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.bindStorage(&storage);
    var info = testBootInfo(&.{hostEntry(0, memory_bytes, .available)});
    try initializeTestAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, info.memoryMap());
    info.paging = .{ .transition_pages = 3, .final_pages = 31, .transition_base = 64 * mib, .final_base = 96 * mib };
    try reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, &info);
    const arenas = info.paging;
    for ([_]struct { base: u64, bytes: u64 }{
        .{ .base = arenas.transition_base, .bytes = arenas.transitionBytes() },
        .{ .base = arenas.final_base, .bytes = arenas.finalBytes() },
    }) |arena| {
        try std.testing.expect(allocator.isReserved(arena.base));
        try std.testing.expect(allocator.isReserved(arena.base + arena.bytes - TEST_PAGE_SIZE));
        try std.testing.expect(!allocator.isReserved(arena.base - TEST_PAGE_SIZE));
        try std.testing.expect(!allocator.isReserved(arena.base + arena.bytes));
    }
    try std.testing.expectEqual(arenas.transition_pages + arenas.final_pages, allocator.stats().reserved);

    info.paging.framebuffer_base = 64 * mib + 128;
    info.paging.framebuffer_bytes = 128 * 32;
    const authority = KernelMappingAuthority{
        .info = &info,
        .image = .{ .start = 16 * mib, .end = 24 * mib },
        .heap = .{ .start = 32 * mib, .end = 48 * mib },
        .managed_bytes = memory_bytes,
    };
    try std.testing.expect(!authority.permits(&allocator, 64 * mib, 64 * mib + 2 * TEST_PAGE_SIZE, true));
    try std.testing.expect(!authority.permits(&allocator, 96 * mib, 96 * mib + TEST_PAGE_SIZE, false));

    // The exact protected boundary applies to device authority as well as the
    // bitmap. A separately reserved GOP page just after the three-page arena
    // must not be mistaken for an old fixed 16 MiB allocation.
    var adjacent_info = info;
    adjacent_info.paging.framebuffer_base = arenas.transition_base + arenas.transitionBytes();
    adjacent_info.paging.framebuffer_bytes = TEST_PAGE_SIZE;
    try allocator.reserve(.{ .base = adjacent_info.paging.framebuffer_base, .count = 1 });
    var adjacent_authority = authority;
    adjacent_authority.info = &adjacent_info;
    try std.testing.expect(adjacent_authority.permits(&allocator, adjacent_info.paging.framebuffer_base, adjacent_info.paging.framebuffer_base + TEST_PAGE_SIZE, true));
    adjacent_info.paging.framebuffer_base -= TEST_PAGE_SIZE;
    try std.testing.expect(!adjacent_authority.permits(&allocator, adjacent_info.paging.framebuffer_base, adjacent_info.paging.framebuffer_base + TEST_PAGE_SIZE, true));

    allocator.reset();
    info.paging.final_base = memory_bytes - info.paging.finalBytes() + TEST_PAGE_SIZE;
    info.paging.framebuffer_base = 0;
    info.paging.framebuffer_bytes = 0;
    try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, &info));
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().reserved);
}

test "live loader reservations are rejected after allocation begins" {
    const memory_bytes = 2 * 1024 * 1024;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    _ = allocator.allocate(7).?;
    const info = lowLoaderInfo();
    try std.testing.expectError(error.ReservationsSealed, reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, &info));
    try std.testing.expect(!allocator.isReserved(info.paging.transition_base));
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().reserved);
    try std.testing.expectEqual(@as(u32, 7), allocator.stats().allocated);
}

test "live loader ranges outside the allocator aperture fail transactionally" {
    const memory_bytes = 2 * 1024 * 1024;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var info = lowLoaderInfo();
    info.tpm = .{ .log_address = memory_bytes - TEST_PAGE_SIZE, .log_bytes = 2 * TEST_PAGE_SIZE, .final_events = 2, .pcr11 = @splat(7) };
    try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, &info));
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().reserved);
}

test "device authority rejects every RAM class live range and allocated or unreserved gap" {
    const Allocator = frame_allocator.Fixed(64 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    var info = testBootInfo(&.{ hostEntry(16 * TEST_PAGE_SIZE, 2 * TEST_PAGE_SIZE, .device_mmio), hostEntry(32 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, .acpi_reclaimable) });
    const authority = KernelMappingAuthority{
        .info = &info,
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = 64 * TEST_PAGE_SIZE,
    };
    try std.testing.expect(authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 18 * TEST_PAGE_SIZE, true));
    try std.testing.expect(authority.permits(&allocator, 24 * TEST_PAGE_SIZE, 25 * TEST_PAGE_SIZE, true));
    for ([_]u32{ 1, 2, 3, 4, 5, 7, 0, 99 }) |kind| {
        info.memory_map[0].kind = @fromBackingInt(@intCast(kind));
        try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 18 * TEST_PAGE_SIZE, true));
    }
    info.memory_map[0].kind = .device_mmio;
    for ([_]u64{ 4 * TEST_PAGE_SIZE, 8 * TEST_PAGE_SIZE, 32 * TEST_PAGE_SIZE }) |physical| {
        try std.testing.expect(!authority.permits(&allocator, physical, physical + TEST_PAGE_SIZE, true));
    }
    info.efi_system_table = 16 * TEST_PAGE_SIZE + 128;
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 17 * TEST_PAGE_SIZE, true));
    info.efi_system_table = 0;
    try allocator.makeAvailable(.{ .base = 24 * TEST_PAGE_SIZE, .count = 2 });
    try std.testing.expect(!authority.permits(&allocator, 24 * TEST_PAGE_SIZE, 25 * TEST_PAGE_SIZE, true));
    _ = allocator.allocateBetween(1, 25 * TEST_PAGE_SIZE, 26 * TEST_PAGE_SIZE).?;
    try std.testing.expect(!authority.permits(&allocator, 25 * TEST_PAGE_SIZE, 26 * TEST_PAGE_SIZE, true));
    try std.testing.expect(!authority.permits(&allocator, 0, TEST_PAGE_SIZE, true));
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE + 1, 17 * TEST_PAGE_SIZE, true));
}

test "validated MCFG authority admits reserved ECAM pages without opening neighboring reserved RAM" {
    const memory_bytes = 8 * mcfg.ECAM_BUS_BYTES;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    const allocation = mcfg.Allocation{ .base_address = 4 * mcfg.ECAM_BUS_BYTES, .segment_group = 0, .start_bus = 0, .end_bus = 0 };
    const start = allocation.base_address;
    const end = start + mcfg.ECAM_BUS_BYTES;
    const info = testBootInfo(&.{hostEntry(start - TEST_PAGE_SIZE, mcfg.ECAM_BUS_BYTES + 2 * TEST_PAGE_SIZE, .reserved)});
    var authority = KernelMappingAuthority{
        .info = &info,
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = memory_bytes,
    };
    try std.testing.expect(!authority.permits(&allocator, start, end, true));
    try authority.registerPciEcam(&allocator, allocation);
    try authority.registerPciEcam(&allocator, allocation);
    try std.testing.expect(authority.permits(&allocator, start, start + TEST_PAGE_SIZE, true));
    try std.testing.expect(authority.permits(&allocator, end - TEST_PAGE_SIZE, end, true));
    try std.testing.expect(!authority.permits(&allocator, start - TEST_PAGE_SIZE, start + TEST_PAGE_SIZE, true));
    try std.testing.expect(!authority.permits(&allocator, end - TEST_PAGE_SIZE, end + TEST_PAGE_SIZE, true));
    try std.testing.expect(!authority.permits(&allocator, start, end, false));
    var replacement = allocation;
    replacement.end_bus = 1;
    try std.testing.expectError(error.PhysicalOwnershipConflict, authority.registerPciEcam(&allocator, replacement));
    try std.testing.expectEqual(end, authority.pci_ecam.?.end);

    try allocator.makeAvailable(.{ .base = start + TEST_PAGE_SIZE, .count = 1 });
    try std.testing.expect(!authority.permits(&allocator, start, end, true));
    try std.testing.expectError(error.PhysicalOwnershipConflict, authority.registerPciEcam(&allocator, allocation));
    _ = allocator.allocateBetween(1, start + TEST_PAGE_SIZE, start + 2 * TEST_PAGE_SIZE).?;
    try std.testing.expect(!authority.permits(&allocator, start, end, true));
}

test "MCFG authority registration rejects malformed allocations protected backing and conflicting RAM classes" {
    const memory_bytes = 8 * mcfg.ECAM_BUS_BYTES;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    const allocation = mcfg.Allocation{ .base_address = 4 * mcfg.ECAM_BUS_BYTES, .segment_group = 0, .start_bus = 0, .end_bus = 0 };
    const start = allocation.base_address;
    var info = testBootInfo(&.{ hostEntry(start, mcfg.ECAM_BUS_BYTES, .reserved), hostEntry(start + 2 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, .reserved) });
    const original = KernelMappingAuthority{
        .info = &info,
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = memory_bytes,
    };
    for ([_]u32{ 1, 3, 4, 5, 7, 0, 99 }) |kind| {
        info.memory_map[1].kind = @fromBackingInt(@intCast(kind));
        var authority = original;
        try std.testing.expectError(error.PhysicalOwnershipConflict, authority.registerPciEcam(&allocator, allocation));
        try std.testing.expect(authority.pci_ecam == null);
    }
    info.memory_map[1].kind = .reserved;
    for (0..3) |protected| {
        var authority = original;
        var protected_info = info;
        const protected_span = PhysicalSpan{ .start = start + TEST_PAGE_SIZE, .end = start + 2 * TEST_PAGE_SIZE };
        switch (protected) {
            0 => authority.image = protected_span,
            1 => authority.heap = protected_span,
            else => {
                protected_info.efi_system_table = protected_span.start;
                authority.info = &protected_info;
            },
        }
        try std.testing.expectError(error.PhysicalOwnershipConflict, authority.registerPciEcam(&allocator, allocation));
        try std.testing.expect(authority.pci_ecam == null);
    }
    const Attack = enum { zero, misaligned, other_segment, other_start_bus, reversed_bus, overflow };
    for (std.enums.values(Attack)) |attack| {
        var forged = allocation;
        switch (attack) {
            .zero => forged.base_address = 0,
            .misaligned => forged.base_address += TEST_PAGE_SIZE,
            .other_segment => forged.segment_group = 1,
            .other_start_bus => {
                forged.start_bus = 1;
                forged.end_bus = 1;
            },
            .reversed_bus => forged.start_bus = 1,
            .overflow => {
                forged.base_address = std.math.maxInt(u64) & ~(mcfg.ECAM_BUS_BYTES - 1);
                forged.end_bus = 1;
            },
        }
        var authority = original;
        try std.testing.expectError(error.InvalidRange, authority.registerPciEcam(&allocator, forged));
        try std.testing.expect(authority.pci_ecam == null);
    }
}

test "MCFG authority never treats native EFI reserved RAM as an ECAM device aperture" {
    const Allocator = frame_allocator.Fixed(64 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    // This aperture is above the allocator's managed range. EFI provenance must
    // still exclude positively classified RAM despite its reserved kind.
    const allocation = mcfg.Allocation{ .base_address = 4 * mcfg.ECAM_BUS_BYTES, .segment_group = 0, .start_bus = 0, .end_bus = 0 };
    var info = testBootInfo(&.{nativeEntry(allocation.base_address, mcfg.ECAM_BUS_BYTES, .reserved, 0)});
    const original = KernelMappingAuthority{
        .info = &info,
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = 64 * TEST_PAGE_SIZE,
    };
    var reserved = original;
    try reserved.registerPciEcam(&allocator, allocation);
    try std.testing.expect(reserved.permits(&allocator, allocation.base_address, allocation.base_address + TEST_PAGE_SIZE, true));
    for ([_]u32{ 1, 2, 3, 4, 5, 6, 7, 9, 10, 14 }) |firmware_type| {
        info.memory_map[0].firmware_type = firmware_type;
        var authority = original;
        try std.testing.expectError(error.PhysicalOwnershipConflict, authority.registerPciEcam(&allocator, allocation));
        try std.testing.expect(authority.pci_ecam == null);
        try std.testing.expect(!reserved.permits(&allocator, allocation.base_address, allocation.base_address + TEST_PAGE_SIZE, true));
    }
}

test "firmware authority needs complete allowed coverage and rejects overlapping conflicting descriptors" {
    const Allocator = frame_allocator.Fixed(64 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    // Unsorted adjacent ACPI/runtime descriptors cover the complete span.
    var info = testBootInfo(&.{
        hostEntry(18 * TEST_PAGE_SIZE, 2 * TEST_PAGE_SIZE, .firmware_runtime_ram),
        hostEntry(16 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, .acpi_reclaimable),
        hostEntry(17 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, .acpi_nvs),
    });
    const authority = KernelMappingAuthority{
        .info = &info,
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = 64 * TEST_PAGE_SIZE,
    };
    try std.testing.expect(authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 20 * TEST_PAGE_SIZE, false));
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 21 * TEST_PAGE_SIZE, false));
    try std.testing.expect(!authority.permits(&allocator, 24 * TEST_PAGE_SIZE, 25 * TEST_PAGE_SIZE, false));
    info.memory_map[2] = hostEntry(17 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, .device_mmio);
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 20 * TEST_PAGE_SIZE, false));
    info.memory_map[2] = hostEntry(18 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, .available);
    try std.testing.expect(!authority.permits(&allocator, 18 * TEST_PAGE_SIZE, 19 * TEST_PAGE_SIZE, false));
}

test "framebuffer exception admits only its reserved GOP pages and never protected backing" {
    const Allocator = frame_allocator.Fixed(64 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    var info = testBootInfo(&.{hostEntry(16 * TEST_PAGE_SIZE, 4 * TEST_PAGE_SIZE, .available)});
    info.paging.framebuffer_base = 16 * TEST_PAGE_SIZE + 128;
    info.paging.framebuffer_bytes = 128 * 32;
    var authority = KernelMappingAuthority{
        .info = &info,
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = 64 * TEST_PAGE_SIZE,
    };
    try std.testing.expect(authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 18 * TEST_PAGE_SIZE, true));
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 19 * TEST_PAGE_SIZE, true));
    authority.heap = .{ .start = 17 * TEST_PAGE_SIZE, .end = 18 * TEST_PAGE_SIZE };
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 18 * TEST_PAGE_SIZE, true));
}
