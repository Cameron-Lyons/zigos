const std = @import("std");
const handoff = @import("../boot/handoff.zig");
const endian = @import("../utils/endian.zig");
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

    var validator = memory_map.iterator();
    var entry_count: usize = 0;
    while (try validator.next()) |_| {
        entry_count += 1;
    }
    if (entry_count == 0) return error.InvalidMemoryMap;

    var usable = memory_map.iterator();
    while (try usable.next()) |entry| {
        if (!availableRamEntry(entry)) continue;
        try openWriteBackPages(memory_bytes, page_size, allocator, entry, cache_view);
    }

    var unavailable = memory_map.iterator();
    while (try unavailable.next()) |entry| {
        if (availableRamEntry(entry)) continue;
        if (touchedPageRun(memory_bytes, page_size, entry.base, entry.length, entry.end)) |run| {
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
    const limit = @min(entry.end, @min(memory_bytes, cache_view.physicalLimit()));
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
    if (fullPageRun(memory_bytes, page_size, .{ .base = start, .length = end - start, .end = end, .kind = 1 })) |run|
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
    switch (entry.kind) {
        1, 2, 3, 4, 7 => {},
        else => return false,
    }
    return if (entry.firmware_type == std.math.maxInt(u32))
        entry.kind == 1 or entry.kind == 3 or entry.kind == 4 or entry.kind == 7
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

    var iterator = memory_map.iterator();
    while (try iterator.next()) |entry| {
        if (entry.length == 0 or entry.base >= end or entry.end <= start) continue;
        if (if (available) !availableRamEntry(entry) else !describedRamEntry(entry)) return error.RamNotAvailable;
    }
    var covered = start;
    while (covered < end) {
        var next = covered;
        iterator = memory_map.iterator();
        while (try iterator.next()) |entry| {
            if (entry.base <= covered and entry.end > covered) next = @max(next, @min(entry.end, end));
        }
        if (next == covered) return error.RamNotAvailable;
        covered = next;
    }
}

// The loader owns these disjoint allocations before the kernel makes its first
// early-heap claim. Described RAM and effective WB alone do not prove that a
// forged allocation cannot overwrite the live handoff or another owned extent.
pub fn validateBootOwnedRanges(
    memory_map: handoff.MemoryMap,
    info_address: u32,
    info: handoff.Info,
    kernel_start: u64,
    kernel_end: u64,
    cache_view: cache_policy.ValidatedMtrrView,
) Error!void {
    const page: u64 = 4096;
    const image_limit = @import("../../arch/kernel_address.zig").image_physical_limit;
    const image = info.boot_image orelse return error.InvalidHandoffRange;
    const arenas = info.boot_paging orelse return error.InvalidHandoffRange;
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

    if (info_address == 0 or info.info_bytes < 8 or info.info_bytes > 1024 * 1024 or
        !info.hasMemoryMap() or memory_map.entry_size < 32 or info.mmap_entry_size != memory_map.entry_size or
        info.mmap_length != memory_map.bytes.len or info.mmap_length == 0)
        return error.InvalidHandoffRange;
    const info_end = std.math.add(u64, info_address, info.info_bytes) catch return error.InvalidHandoffRange;
    try requireContainedFragment(info_address, info_end, info.mmap_addr, info.mmap_length);
    if (info.hasCommandLine()) try requireContainedFragment(info_address, info_end, info.cmdline_addr, info.cmdline_length);
    if (info.hasAcpi2Rsdp()) try requireContainedFragment(info_address, info_end, info.acpi2_rsdp_addr, info.acpi2_rsdp_length);

    var live: [4]PhysicalSpan = undefined;
    var live_count: usize = 1;
    try touchedOwnedSpan(info_address, info.info_bytes, &live[0]);
    if (info.boot_tpm) |tpm| {
        try touchedOwnedSpan(tpm.log_address, tpm.log_bytes, &live[live_count]);
        live_count += 1;
        if (overlaps(live[0].start, live[0].end, live[live_count - 1])) return error.InvalidHandoffRange;
    }
    if (info.hasEfi64SystemTable()) {
        try touchedOwnedSpan(info.efi64_system_table_addr, page, &live[live_count]);
        live_count += 1;
    }
    // Scanout owns its touched pages even when firmware labels them usable RAM
    // or its pixel format is unsupported by the renderer.
    if (arenas.framebufferSpan() catch return error.InvalidHandoffRange) |span| {
        live[live_count] = .{ .start = span.start, .end = span.end };
        live_count += 1;
    } else if (info.hasFramebuffer()) {
        const framebuffer_bytes = @as(u64, info.framebuffer_pitch) * info.framebuffer_height;
        try touchedOwnedSpan(info.framebuffer_addr, framebuffer_bytes, &live[live_count]);
        live_count += 1;
    }
    for (owned) |span| {
        for (live[0..live_count]) |protected| {
            if (overlaps(span.start, span.end, protected)) return error.InvalidHandoffRange;
        }
    }

    // Production provenance is native, even though the standalone RAM helpers
    // also support explicit 24-byte host fixtures without an original EFI type.
    var iterator = memory_map.iterator();
    while (try iterator.next()) |entry| {
        if (entry.firmware_type != std.math.maxInt(u32)) continue;
        for (owned) |span| {
            if (overlaps(entry.base, entry.end, span)) return error.RamNotAvailable;
        }
    }
    try requireAvailableRamWriteBack(memory_map, kernel_start, kernel_end - kernel_start, cache_view);
    try requireAvailableRamWriteBack(memory_map, image.heap_base, heap_bytes, cache_view);
    try requireRamWriteBack(memory_map, arenas.transition_base, arenas.transitionBytes(), cache_view);
    try requireRamWriteBack(memory_map, arenas.final_base, arenas.finalBytes(), cache_view);
}

inline fn requireContainedFragment(start: u64, end: u64, fragment: u64, bytes: u64) Error!void {
    const fragment_end = std.math.add(u64, fragment, bytes) catch return error.InvalidHandoffRange;
    if (bytes == 0 or fragment < start or fragment_end > end) return error.InvalidHandoffRange;
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
    memory_map: handoff.MemoryMap,
    info_address: u32,
    info: handoff.Info,
    kernel_start: u64,
    kernel_end: u64,
    cache_view: cache_policy.ValidatedMtrrView,
    active_root: u64,
    used_final_pages: u32,
) Error!void {
    if (retirement.used_pages != 0) return error.BootArenasAlreadyRetired;
    if (allocator.allocated_count != 0) return error.FrameAllocated;
    if (allocator.reservations_sealed) return error.ReservationsSealed;
    const arenas = info.boot_paging orelse return error.InvalidHandoffRange;
    if (page_size != 4096 or used_final_pages < 3 or used_final_pages > arenas.final_pages)
        return error.InvalidHandoffRange;
    if (active_root != arenas.final_base) return error.InvalidHandoffRange;
    try validateBootOwnedRanges(memory_map, info_address, info, kernel_start, kernel_end, cache_view);

    const arena_runs = [_]frame_allocator.FrameRun{
        .{ .base = arenas.transition_base, .count = arenas.transition_pages },
        .{ .base = arenas.final_base, .count = arenas.final_pages },
    };
    // The broader admission above establishes complete described RAM and WB.
    // Retirement additionally needs the original reclaimable loader allocation
    // type throughout both full receipts, including the retained final prefix.
    var iterator = memory_map.iterator();
    while (try iterator.next()) |entry| {
        for (arena_runs) |run| {
            if (entry.length == 0 or entry.base >= run.base + @as(u64, run.count) * 4096 or entry.end <= run.base) continue;
            if (entry.firmware_type != 2 or (entry.kind != 1 and entry.kind != 2)) return error.RamNotAvailable;
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

pub fn reserveLiveHandoffRanges(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    info_address: u32,
    info: handoff.Info,
) Error!void {
    var runs: [7]frame_allocator.FrameRun = undefined;
    var run_count: usize = 0;
    if (info.boot_paging) |paging| paging.validate() catch return error.InvalidHandoffRange;

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
    const framebuffer_span = if (info.boot_paging) |paging| paging.framebufferSpan() catch return error.InvalidHandoffRange else null;
    if (framebuffer_span) |span| {
        if (touchedPageRun(memory_bytes, page_size, span.start, span.end - span.start, span.end)) |run| {
            runs[run_count] = run;
            run_count += 1;
        }
    } else if (info.hasFramebuffer()) {
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

    if (info.boot_paging) |paging| {
        const arenas = [_]struct { base: u64, length: u64 }{
            .{ .base = paging.transition_base, .length = paging.transitionBytes() },
            .{ .base = paging.final_base, .length = paging.finalBytes() },
        };
        for (arenas) |arena| {
            runs[run_count] = try liveRangeRun(memory_bytes, page_size, @intCast(arena.base), @intCast(arena.length));
            run_count += 1;
        }
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
// owned by the image, heap, firmware tables and the live loader handoff.
pub const KernelMappingAuthority = struct {
    memory_map: handoff.MemoryMap,
    info_address: u64,
    info: handoff.Info,
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
            overlapsBytes(start, end, self.info_address, self.info.info_bytes) or
            overlapsBytes(start, end, self.info.mmap_addr, self.info.mmap_length) or
            (self.info.hasCommandLine() and overlapsBytes(start, end, self.info.cmdline_addr, self.info.cmdline_length)) or
            (self.info.hasAcpi2Rsdp() and overlapsBytes(start, end, self.info.acpi2_rsdp_addr, self.info.acpi2_rsdp_length)) or
            (self.info.hasEfi64SystemTable() and overlapsBytes(start, end, self.info.efi64_system_table_addr, 4096))) return false;
        if (self.info.boot_tpm) |tpm| {
            if (overlapsBytes(start, end, tpm.log_address, tpm.log_bytes)) return false;
        }
        if (self.info.boot_paging) |paging| {
            if (overlapsBytes(start, end, paging.transition_base, paging.transitionBytes()) or
                overlapsBytes(start, end, paging.final_base, paging.finalBytes())) return false;
        }
        var physical = start;
        while (physical < @min(end, self.managed_bytes)) : (physical += 4096) {
            if (!allocator.isReserved(physical) or allocator.isAllocated(physical)) return false;
        }
        const framebuffer = device and self.framebufferSpanPermits(start, end);
        const pci_ecam = device and if (self.pci_ecam) |span| start >= span.start and end <= span.end else false;
        var iterator = self.memory_map.iterator();
        while (iterator.next() catch return false) |entry| {
            if (entry.length == 0 or !overlaps(start, end, .{ .start = entry.base, .end = entry.end })) continue;
            if (device) {
                if (entry.kind != @backingInt(handoff.MemoryKind.device_mmio) and
                    !(framebuffer and (entry.kind == 1 or entry.kind == 2)) and
                    !(pci_ecam and entry.kind == 2 and !describedRamEntry(entry))) return false;
            } else if (entry.kind != 3 and entry.kind != 4 and entry.kind != @backingInt(handoff.MemoryKind.firmware_runtime_ram)) return false;
        }
        // Explicit MMIO and unlisted reserved gaps are both device apertures.
        // Firmware reads instead require complete positively classified RAM.
        if (device) return true;
        var covered = start;
        while (covered < end) {
            var next = covered;
            iterator = self.memory_map.iterator();
            while (iterator.next() catch return false) |entry| {
                if (entry.base <= covered and entry.end > covered) next = @max(next, @min(entry.end, end));
            }
            if (next == covered) return false;
            covered = next;
        }
        return true;
    }

    inline fn framebufferSpanPermits(self: @This(), start: u64, end: u64) bool {
        if (self.info.boot_paging) |paging| {
            if (paging.framebufferSpan() catch return false) |span| return start >= span.start and end <= span.end;
        }
        const framebuffer = handoff.framebufferInfo(self.info) catch return false;
        const bytes = framebuffer.minimumBufferBytes() catch return false;
        const raw_end = std.math.add(u64, framebuffer.physical_address, bytes) catch return false;
        const rounded_end = std.math.add(u64, raw_end, 4095) catch return false;
        return start == (framebuffer.physical_address & ~@as(u64, 4095)) and end == (rounded_end & ~@as(u64, 4095));
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
const TEST_MAX_ARENA_BYTES: u64 = @as(u64, paging_info.MAX_ARENA_PAGES) * TEST_PAGE_SIZE;
const TEST_WRITE_BACK_MTRRS = cache_policy.MtrrState{
    .physical_bits = 52,
    .default_type = cache_policy.MTRR_ENABLED | @backingInt(cache_policy.MemoryType.write_back),
};

fn initializeTestAllocator(
    comptime memory_bytes: u64,
    comptime page_size: u32,
    allocator: *frame_allocator.Fixed(memory_bytes, page_size),
    memory_map: handoff.MemoryMap,
) Error!void {
    return initializeAllocator(memory_bytes, page_size, allocator, memory_map, try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS));
}

fn appendEntry(bytes: []u8, offset: usize, base: u64, length: u64, kind: u32) usize {
    endian.writeU64Le(bytes[offset .. offset + 8], base);
    endian.writeU64Le(bytes[offset + 8 .. offset + 16], length);
    endian.writeU32Le(bytes[offset + 16 .. offset + 20], kind);
    endian.writeU32Le(bytes[offset + 20 .. offset + 24], 0);
    return offset + 24;
}

fn appendNativeEntry(bytes: []u8, offset: usize, base: u64, length: u64, kind: u32, firmware_type: u32) usize {
    _ = appendEntry(bytes, offset, base, length, kind);
    endian.writeU32Le(bytes[offset + 20 .. offset + 24], firmware_type);
    endian.writeU64Le(bytes[offset + 24 .. offset + 32], 8);
    return offset + 32;
}

fn testVariableMtrr(base: u64, bytes: u64, memory_type: cache_policy.MemoryType, physical_bits: u8) cache_policy.VariableMtrr {
    const physical_mask = (@as(u64, 1) << @as(u6, @intCast(physical_bits))) - 1;
    return .{
        .base = base | @backingInt(memory_type),
        .mask = (physical_mask & ~(bytes - 1) & ~@as(u64, 4095)) | cache_policy.MTRR_VALID,
    };
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
        .framebuffer_rgb = @as([6]u8, @splat(0)),
        .info_bytes = 8,
        .cmdline_length = if (cmdline_addr == 0) 0 else 512,
        .mmap_entry_size = 24,
    };
}

test "firmware map opens only complete usable pages" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    var bytes = @as([24]u8, @splat(0));
    _ = appendEntry(&bytes, 0, TEST_PAGE_SIZE / 2, 3 * TEST_PAGE_SIZE, 1);

    try initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24));

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
    var bytes: [48]u8 = undefined;
    const offset = appendEntry(&bytes, 0, 0, memory_bytes, 1);
    _ = appendEntry(&bytes, offset, 11 * page + 100, 1, 2);
    try initializeAllocator(memory_bytes, page, &allocator, handoff.multiboot2MemoryMap(&bytes, 24), view);
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
    var bytes: [24]u8 = undefined;
    _ = appendEntry(&bytes, 0, 0, memory_bytes, 1);
    try initializeAllocator(memory_bytes, page, &allocator, handoff.multiboot2MemoryMap(&bytes, 24), view);
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
    var bytes: [24]u8 = undefined;
    _ = appendEntry(&bytes, 0, physical_limit - 2 * TEST_PAGE_SIZE, 6 * TEST_PAGE_SIZE, 1);
    try initializeAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24), view);
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
    try std.testing.expectEqual(physical_limit - 2 * TEST_PAGE_SIZE, allocator.allocate(2).?.base);
    try std.testing.expect(allocator.allocate(1) == null);
    try std.testing.expect(allocator.isReserved(physical_limit));
}

test "native usable descriptors cannot disguise device or runtime memory" {
    const Allocator = frame_allocator.Fixed(4 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.bindStorage(&storage);
    var bytes: [96]u8 = undefined;
    var offset = appendNativeEntry(&bytes, 0, 0, TEST_PAGE_SIZE, 1, 2);
    offset = appendNativeEntry(&bytes, offset, TEST_PAGE_SIZE, TEST_PAGE_SIZE, 1, 11);
    _ = appendNativeEntry(&bytes, offset, 2 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 1, 6);
    try initializeTestAllocator(4 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 32));
    try std.testing.expectEqual(@as(u32, 1), allocator.stats().free);
    try std.testing.expectEqual(@as(u64, 0), allocator.allocate(1).?.base);
    try std.testing.expect(allocator.allocate(1) == null);
}

test "early RAM admission requires complete coverage effective WB and appropriate ownership" {
    const page = TEST_PAGE_SIZE;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var bytes: [128]u8 = undefined;
    var offset = appendNativeEntry(&bytes, 0, 4 * page, 2 * page, 2, 2);
    offset = appendNativeEntry(&bytes, offset, 0, 4 * page, 1, 7);
    offset = appendNativeEntry(&bytes, offset, 6 * page, 2 * page, 3, 9);
    _ = appendNativeEntry(&bytes, offset, 8 * page, page, 6, 11);
    const map = handoff.multiboot2MemoryMap(&bytes, 32);
    try requireAvailableRamWriteBack(map, 0, 4 * page, view);
    try requireRamWriteBack(map, 0, 8 * page, view);
    try std.testing.expectError(error.RamNotAvailable, requireAvailableRamWriteBack(map, 0, 5 * page, view));
    try std.testing.expectError(error.RamNotAvailable, requireRamWriteBack(map, 0, 9 * page, view));
    try std.testing.expectError(error.RamNotAvailable, requireRamWriteBack(map, 9 * page, page, view));
    try std.testing.expectError(error.InvalidHandoffRange, requireRamWriteBack(map, std.math.maxInt(u64), page, view));
    try std.testing.expectError(error.InvalidHandoffRange, requireRamWriteBack(map, 0, 0, view));

    // A tiny non-usable overlap blocks an otherwise completely covered heap.
    _ = appendNativeEntry(&bytes, 96, 2 * page + 1, 1, 2, 2);
    try std.testing.expectError(error.RamNotAvailable, requireAvailableRamWriteBack(map, 0, 4 * page, view));
    try requireRamWriteBack(map, 0, 4 * page, view);
    endian.writeU32Le(bytes[116..120], 0);
    try std.testing.expectError(error.RamNotAvailable, requireRamWriteBack(map, 0, 4 * page, view));

    var state = TEST_WRITE_BACK_MTRRS;
    state.capabilities = 1;
    state.variable[0] = testVariableMtrr(page, page, .uncacheable, state.physical_bits);
    const mixed_view = try cache_policy.ValidatedMtrrView.init(&state);
    try std.testing.expectError(error.MixedMemoryTypes, requireAvailableRamWriteBack(map, 0, 4 * page, mixed_view));
}

const BootOwnedTest = struct {
    const mib = 1024 * 1024;
    const memory_bytes = 160 * mib;
    const info_address: u32 = 2 * mib + 64;
    const kernel_start: u64 = 16 * mib;
    const kernel_end: u64 = 24 * mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);

    fn memoryMap(bytes: *[160]u8) handoff.MemoryMap {
        return memoryMapWithPaging(bytes, info().boot_paging.?);
    }

    fn memoryMapWithPaging(bytes: *[160]u8, arenas: paging_info.Info) handoff.MemoryMap {
        // Unsorted descriptors distinguish available allocations from the two
        // positively typed reserved loader arenas.
        const transition_end = arenas.transition_base + arenas.transitionBytes();
        const final_end = arenas.final_base + arenas.finalBytes();
        var offset = appendNativeEntry(bytes, 0, arenas.final_base, arenas.finalBytes(), 2, 2);
        offset = appendNativeEntry(bytes, offset, 0, arenas.transition_base, 1, 7);
        offset = appendNativeEntry(bytes, offset, final_end, memory_bytes - final_end, 1, 7);
        offset = appendNativeEntry(bytes, offset, arenas.transition_base, arenas.transitionBytes(), 2, 2);
        _ = appendNativeEntry(bytes, offset, transition_end, arenas.final_base - transition_end, 1, 7);
        return handoff.multiboot2MemoryMap(bytes, 32);
    }

    fn info() handoff.Info {
        var result = testInfo((1 << 2) | (1 << 6) | (1 << 13) | (1 << 14), info_address + 80, 160, info_address + 256);
        result.info_bytes = TEST_PAGE_SIZE + 128;
        result.mmap_entry_size = 32;
        result.cmdline_length = 128;
        result.acpi2_rsdp_addr = info_address + 512;
        result.acpi2_rsdp_length = 36;
        result.efi64_system_table_addr = 8 * mib + 128;
        result.boot_image = .{
            .firmware_authenticated = false,
            .kernel_digest = @splat(1),
            .cmdline_digest = @splat(2),
            .heap_base = 32 * mib,
        };
        result.boot_paging = .{ .transition_pages = paging_info.MAX_ARENA_PAGES, .final_pages = paging_info.MAX_ARENA_PAGES, .transition_base = 80 * mib, .final_base = 112 * mib };
        result.boot_tpm = .{ .log_address = 4 * mib, .log_bytes = TEST_PAGE_SIZE + 1, .final_events = 2, .pcr11 = @splat(7) };
        return result;
    }

    fn expectUntouched(storage: *const Allocator.Storage) !void {
        for (std.mem.asBytes(storage)) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    }

    fn initializeAfterAdmission(allocator: *Allocator, map: handoff.MemoryMap, boot_info: handoff.Info, image_start: u64, image_end: u64, view: cache_policy.ValidatedMtrrView) Error!void {
        try validateBootOwnedRanges(map, info_address, boot_info, image_start, image_end, view);
        try initializeAllocator(memory_bytes, TEST_PAGE_SIZE, allocator, map, view);
    }

    fn prepareRetirement(storage: *Allocator.Storage, map: handoff.MemoryMap, boot_info: handoff.Info, view: cache_policy.ValidatedMtrrView) Error!Allocator {
        @memset(std.mem.asBytes(storage), 0xa5);
        var allocator = Allocator.bindStorage(storage);
        try initializeAfterAdmission(&allocator, map, boot_info, kernel_start, kernel_end, view);
        try reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, info_address, boot_info);
        try reserveKernelRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, kernel_start, kernel_end, boot_info.boot_image.?.heap_base, @import("../../boot/image_info.zig").KERNEL_HEAP_BYTES);
        return allocator;
    }

    fn reclaim(allocator: *Allocator, retirement: *BootArenaRetirement, map: handoff.MemoryMap, boot_info: handoff.Info, view: cache_policy.ValidatedMtrrView, active_root: u64, used_pages: u32) Error!void {
        return reclaimBootPagingArenas(memory_bytes, TEST_PAGE_SIZE, allocator, retirement, map, info_address, boot_info, kernel_start, kernel_end, view, active_root, used_pages);
    }

    fn expectRejectedRetirement(expected: Error, allocator: *Allocator, retirement: *BootArenaRetirement, map: handoff.MemoryMap, boot_info: handoff.Info, view: cache_policy.ValidatedMtrrView, active_root: u64, used_pages: u32) !void {
        const before = allocator.*;
        const storage_before = allocator.storage.*;
        const retirement_before = retirement.*;
        try std.testing.expectError(expected, reclaim(allocator, retirement, map, boot_info, view, active_root, used_pages));
        try std.testing.expectEqualDeep(before, allocator.*);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&storage_before), std.mem.asBytes(allocator.storage));
        try std.testing.expectEqualDeep(retirement_before, retirement.*);
    }
};

test "variable boot arena retirement recovers exact runs and preserves the complete final prefix" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    for ([_]u32{ 3, 31, paging_info.MAX_ARENA_PAGES }) |transition_pages| {
        for ([_]u32{ 3, 31, paging_info.MAX_ARENA_PAGES }) |final_pages| {
            var info = fixture.info();
            info.boot_paging.?.transition_pages = transition_pages;
            info.boot_paging.?.final_pages = final_pages;
            const arenas = info.boot_paging.?;
            const map = fixture.memoryMapWithPaging(&bytes, arenas);
            for ([_]u32{ 3, @min(17, final_pages), final_pages }) |used_pages| {
                var allocator = try fixture.prepareRetirement(&storage, map, info, view);
                var retirement: BootArenaRetirement = .{};
                const before = allocator.stats();
                const bitmap_before = storage.unavailable_bitmap;
                try fixture.reclaim(&allocator, &retirement, map, info, view, arenas.final_base, used_pages);
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
                try fixture.expectRejectedRetirement(error.BootArenasAlreadyRetired, &allocator, &retirement, map, info, view, arenas.final_base, used_pages);
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
                try fixture.expectRejectedRetirement(error.BootArenasAlreadyRetired, &allocator, &retirement, map, info, view, arenas.final_base, used_pages);
            }
        }
    }
}

test "boot arena retirement rejects impossible prefix and inactive root without mutation" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, map, info, view);
    var retirement: BootArenaRetirement = .{};
    for ([_]u32{ 0, 1, 2, paging_info.MAX_ARENA_PAGES + 1, std.math.maxInt(u32) }) |used_pages|
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, map, info, view, info.boot_paging.?.final_base, used_pages);
    for ([_]u64{ 0, info.boot_paging.?.transition_base, info.boot_paging.?.final_base + 1, @import("../../arch/kernel_address.zig").image_virtual_bias + info.boot_paging.?.final_base }) |root|
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, map, info, view, root, 17);
}

test "boot arena retirement requires loader-data provenance over both complete receipts" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, map, info, view);
    var retirement: BootArenaRetirement = .{};
    for ([_]usize{ 20, 116 }) |type_offset| {
        for ([_]u32{ 1, 3, 6, 7, 9, 11, std.math.maxInt(u32) }) |firmware_type| {
            _ = fixture.memoryMap(&bytes);
            endian.writeU32Le(bytes[type_offset..][0..4], firmware_type);
            try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, map, info, view, info.boot_paging.?.final_base, 17);
        }
    }
    // A last-page gap and a late malformed descriptor both precede mutation of
    // the otherwise valid first reclaim run.
    _ = fixture.memoryMap(&bytes);
    endian.writeU64Le(bytes[8..16], TEST_MAX_ARENA_BYTES - TEST_PAGE_SIZE);
    try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, map, info, view, info.boot_paging.?.final_base, 17);
    _ = fixture.memoryMap(&bytes);
    endian.writeU64Le(bytes[128..136], std.math.maxInt(u64));
    try fixture.expectRejectedRetirement(error.InvalidMemoryMap, &allocator, &retirement, map, info, view, info.boot_paging.?.final_base, 17);

    var overlapping: [192]u8 = undefined;
    std.mem.copyForwards(u8, overlapping[0..160], (fixture.memoryMap(&bytes)).bytes);
    _ = appendNativeEntry(&overlapping, 160, info.boot_paging.?.final_base + 1, 1, 2, 7);
    var overlapping_info = info;
    overlapping_info.mmap_length = overlapping.len;
    try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, handoff.multiboot2MemoryMap(&overlapping, 32), overlapping_info, view, info.boot_paging.?.final_base, 17);
}

test "unequal arena receipts enforce their own provenance WB and GOP boundaries" {
    const fixture = BootOwnedTest;
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var bytes: [160]u8 = undefined;
    var storage: fixture.Allocator.Storage = undefined;
    for ([_]struct { transition: u32, final: u32 }{ .{ .transition = 3, .final = 31 }, .{ .transition = 31, .final = 3 } }) |capacity| {
        var info = fixture.info();
        info.boot_paging.?.transition_pages = capacity.transition;
        info.boot_paging.?.final_pages = capacity.final;
        const arenas = info.boot_paging.?;
        const map = fixture.memoryMapWithPaging(&bytes, arenas);
        var allocator = try fixture.prepareRetirement(&storage, map, info, view);
        var retirement: BootArenaRetirement = .{};
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, map, info, view, arenas.final_base, arenas.final_pages + 1);
        for ([_]u32{ 0, 2, paging_info.MAX_ARENA_PAGES + 1 }) |bad_capacity| {
            var bad_info = info;
            bad_info.boot_paging.?.transition_pages = bad_capacity;
            try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, map, bad_info, view, arenas.final_base, 3);
            bad_info = info;
            bad_info.boot_paging.?.final_pages = bad_capacity;
            try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, map, bad_info, view, arenas.final_base, 3);
        }
        for ([_]usize{ 20, 116 }) |type_offset| {
            endian.writeU32Le(bytes[type_offset..][0..4], 6);
            try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, map, info, view, arenas.final_base, 3);
            _ = fixture.memoryMapWithPaging(&bytes, arenas);
        }
        endian.writeU64Le(bytes[8..16], arenas.finalBytes() - TEST_PAGE_SIZE);
        try fixture.expectRejectedRetirement(error.RamNotAvailable, &allocator, &retirement, map, info, view, arenas.final_base, 3);
        _ = fixture.memoryMapWithPaging(&bytes, arenas);
        for ([_]u64{ arenas.transition_base + arenas.transitionBytes() - TEST_PAGE_SIZE, arenas.final_base + arenas.finalBytes() - TEST_PAGE_SIZE }) |last_page| {
            var state = TEST_WRITE_BACK_MTRRS;
            state.capabilities = 1;
            state.variable[0] = testVariableMtrr(last_page, TEST_PAGE_SIZE, .uncacheable, state.physical_bits);
            const mixed_view = try cache_policy.ValidatedMtrrView.init(&state);
            try fixture.expectRejectedRetirement(error.MixedMemoryTypes, &allocator, &retirement, map, info, mixed_view, arenas.final_base, 3);
        }
        info.boot_paging.?.framebuffer_base = arenas.final_base + arenas.finalBytes() - 1;
        info.boot_paging.?.framebuffer_bytes = 1;
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, map, info, view, arenas.final_base, 3);
        // GOP immediately after a small arena was inside the old fixed 16 MiB
        // envelope. It is now a distinct protected allocation, never reclaimed.
        info.boot_paging.?.framebuffer_base = arenas.final_base + arenas.finalBytes();
        info.boot_paging.?.framebuffer_bytes = TEST_PAGE_SIZE;
        allocator = try fixture.prepareRetirement(&storage, map, info, view);
        const before = allocator.stats();
        try fixture.reclaim(&allocator, &retirement, map, info, view, arenas.final_base, 3);
        try std.testing.expectEqual(capacity.transition + capacity.final - 3, retirement.reclaimed_pages);
        try std.testing.expectEqual(before.reserved - retirement.reclaimed_pages, allocator.stats().reserved);
        try std.testing.expect(allocator.isReserved(info.boot_paging.?.framebuffer_base));
        try std.testing.expect(!allocator.isReserved(arenas.transition_base + arenas.transitionBytes()));
    }
}

test "boot arena retirement checks WB backing including the retained final prefix" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, map, info, view);
    var retirement: BootArenaRetirement = .{};
    for ([_]u64{ info.boot_paging.?.transition_base, info.boot_paging.?.final_base, info.boot_paging.?.final_base + TEST_MAX_ARENA_BYTES - TEST_PAGE_SIZE }) |non_wb| {
        var state = TEST_WRITE_BACK_MTRRS;
        state.capabilities = 1;
        state.variable[0] = testVariableMtrr(non_wb, TEST_PAGE_SIZE, .uncacheable, state.physical_bits);
        const mixed_view = try cache_policy.ValidatedMtrrView.init(&state);
        try fixture.expectRejectedRetirement(error.MixedMemoryTypes, &allocator, &retirement, map, info, mixed_view, info.boot_paging.?.final_base, 17);
    }
}

test "boot arena retirement rechecks live ownership and geometry before opening arenas" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const original = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, map, original, view);
    var retirement: BootArenaRetirement = .{};
    const Attack = enum { heap, tpm, live_info, gop, misaligned_arena, arena_overlap, missing_paging };
    for (std.enums.values(Attack)) |attack| {
        var info = original;
        switch (attack) {
            .heap => info.boot_image.?.heap_base = info.boot_paging.?.transition_base,
            .tpm => info.boot_tpm.?.log_address = info.boot_paging.?.final_base + 17 * TEST_PAGE_SIZE,
            .live_info => info.boot_paging.?.transition_base = 2 * fixture.mib,
            .gop => {
                info.boot_paging.?.framebuffer_base = info.boot_paging.?.transition_base - TEST_PAGE_SIZE + 1;
                info.boot_paging.?.framebuffer_bytes = TEST_PAGE_SIZE;
            },
            .misaligned_arena => info.boot_paging.?.transition_base += 1,
            .arena_overlap => info.boot_paging.?.transition_base = info.boot_paging.?.final_base,
            .missing_paging => info.boot_paging = null,
        }
        try fixture.expectRejectedRetirement(error.InvalidHandoffRange, &allocator, &retirement, map, info, view, original.boot_paging.?.final_base, 17);
    }
    // Losing even a page in the unused second run invalidates the complete
    // preflight, leaving the fully reserved transition run intact.
    for ([_]u64{ original.boot_paging.?.transition_base, original.boot_paging.?.final_base, original.boot_paging.?.final_base + TEST_MAX_ARENA_BYTES - TEST_PAGE_SIZE }) |missing| {
        allocator = try fixture.prepareRetirement(&storage, map, original, view);
        try allocator.makeAvailable(.{ .base = missing, .count = 1 });
        try fixture.expectRejectedRetirement(error.FrameReserved, &allocator, &retirement, map, original, view, original.boot_paging.?.final_base, 17);
    }
}

test "boot arena retirement is forbidden after sealing or the first frame allocation" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = try fixture.prepareRetirement(&storage, map, info, view);
    var retirement: BootArenaRetirement = .{};
    try allocator.sealReservations();
    try fixture.expectRejectedRetirement(error.ReservationsSealed, &allocator, &retirement, map, info, view, info.boot_paging.?.final_base, 17);
    const allocated = allocator.allocate(1).?;
    try fixture.expectRejectedRetirement(error.FrameAllocated, &allocator, &retirement, map, info, view, info.boot_paging.?.final_base, 17);
    try allocator.release(allocated);
    try fixture.expectRejectedRetirement(error.ReservationsSealed, &allocator, &retirement, map, info, view, info.boot_paging.?.final_base, 17);
}

test "boot arena retirement prevalidates the second run allocator aperture" {
    const fixture = BootOwnedTest;
    const memory_bytes = 100 * fixture.mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    const storage_before = storage;
    const allocator_before = allocator;
    var retirement: BootArenaRetirement = .{};
    try std.testing.expectError(error.OutOfRange, reclaimBootPagingArenas(memory_bytes, TEST_PAGE_SIZE, &allocator, &retirement, map, fixture.info_address, info, fixture.kernel_start, fixture.kernel_end, view, info.boot_paging.?.final_base, 17));
    try std.testing.expectEqualDeep(allocator_before, allocator);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&storage_before), std.mem.asBytes(&storage));
    try std.testing.expectEqualDeep(BootArenaRetirement{}, retirement);
}

test "boot arena retirement rejects allocator geometry that cannot represent table pages" {
    const fixture = BootOwnedTest;
    const page_size = 2 * TEST_PAGE_SIZE;
    const Allocator = frame_allocator.Fixed(fixture.memory_bytes, page_size);
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    const storage_before = storage;
    const allocator_before = allocator;
    var retirement: BootArenaRetirement = .{};
    try std.testing.expectError(error.InvalidHandoffRange, reclaimBootPagingArenas(fixture.memory_bytes, page_size, &allocator, &retirement, map, fixture.info_address, info, fixture.kernel_start, fixture.kernel_end, view, info.boot_paging.?.final_base, 17));
    try std.testing.expectEqualDeep(allocator_before, allocator);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&storage_before), std.mem.asBytes(&storage));
    try std.testing.expectEqualDeep(BootArenaRetirement{}, retirement);
}

test "boot owned admission permits contained handoff fragments before real bitmap ownership" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);

    try validateBootOwnedRanges(map, fixture.info_address, info, fixture.kernel_start, fixture.kernel_end, view);
    try fixture.expectUntouched(&storage);
    try initializeAllocator(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, map, view);
    try reserveLiveHandoffRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, fixture.info_address, info);
    try reserveKernelRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, fixture.kernel_start, fixture.kernel_end, info.boot_image.?.heap_base, @import("../../boot/image_info.zig").KERNEL_HEAP_BYTES);
    try allocator.sealReservations();
    for ([_]u64{ 2 * fixture.mib, 2 * fixture.mib + TEST_PAGE_SIZE, 4 * fixture.mib, 4 * fixture.mib + TEST_PAGE_SIZE, 16 * fixture.mib, 32 * fixture.mib, 80 * fixture.mib, 112 * fixture.mib }) |address|
        try std.testing.expect(allocator.isReserved(address));
    try std.testing.expect(!allocator.isReserved(128 * fixture.mib));
    const run = allocator.allocate(1).?;
    try view.requireWriteBack(run.base, TEST_PAGE_SIZE);
    try allocator.release(run);
}

test "forged boot owned overlaps and external handoff fragments fail before bitmap writes" {
    const fixture = BootOwnedTest;
    const Attack = enum {
        heap_image,
        heap_info,
        heap_tpm,
        heap_efi,
        arena_image,
        arena_heap,
        arena_info,
        arena_tpm,
        arena_efi,
        arena_arena,
        image_info,
        image_tpm,
        image_efi_touched_neighbor,
        map_external,
        command_line_external,
        rsdp_external,
        tpm_info_touched_page,
        tpm_overflow,
        efi_overflow,
        missing_image,
        missing_paging,
        image_misaligned,
        heap_misaligned,
    };
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);
    for (std.enums.values(Attack)) |attack| {
        var info = fixture.info();
        var kernel_start = fixture.kernel_start;
        var kernel_end = fixture.kernel_end;
        switch (attack) {
            .heap_image => info.boot_image.?.heap_base = fixture.kernel_start,
            .heap_info => info.boot_image.?.heap_base = 2 * fixture.mib,
            .heap_tpm => info.boot_image.?.heap_base = info.boot_tpm.?.log_address,
            .heap_efi => info.boot_image.?.heap_base = 8 * fixture.mib,
            .arena_image => info.boot_paging.?.final_base = fixture.kernel_start,
            .arena_heap => info.boot_paging.?.final_base = info.boot_image.?.heap_base,
            .arena_info => info.boot_paging.?.final_base = 2 * fixture.mib,
            .arena_tpm => info.boot_paging.?.final_base = info.boot_tpm.?.log_address,
            .arena_efi => info.boot_paging.?.final_base = 8 * fixture.mib,
            .arena_arena => info.boot_paging.?.final_base = info.boot_paging.?.transition_base,
            .image_info => {
                kernel_start = 2 * fixture.mib;
                kernel_end = kernel_start + TEST_PAGE_SIZE;
            },
            .image_tpm => {
                kernel_start = info.boot_tpm.?.log_address;
                kernel_end = kernel_start + TEST_PAGE_SIZE;
            },
            .image_efi_touched_neighbor => {
                kernel_start = 8 * fixture.mib + TEST_PAGE_SIZE;
                kernel_end = kernel_start + TEST_PAGE_SIZE;
            },
            .map_external => info.mmap_addr = @intCast(info.boot_paging.?.final_base),
            .command_line_external => info.cmdline_addr = @intCast(fixture.kernel_start),
            .rsdp_external => info.acpi2_rsdp_addr = @intCast(info.boot_paging.?.final_base),
            .tpm_info_touched_page => info.boot_tpm.?.log_address = 2 * fixture.mib,
            .tpm_overflow => info.boot_tpm.?.log_address = std.math.maxInt(u64),
            .efi_overflow => info.efi64_system_table_addr = std.math.maxInt(u64),
            .missing_image => info.boot_image = null,
            .missing_paging => info.boot_paging = null,
            .image_misaligned => kernel_start += 1,
            .heap_misaligned => info.boot_image.?.heap_base += 1,
        }
        try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, map, info, kernel_start, kernel_end, view));
        try fixture.expectUntouched(&storage);
    }
}

test "boot owned admission rejects untyped unavailable and partially non-WB backing" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const info = fixture.info();
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);

    // Native stride alone is insufficient without a positively typed original
    // EFI descriptor for every claimed allocation.
    endian.writeU32Le(bytes[52..56], std.math.maxInt(u32));
    try std.testing.expectError(error.RamNotAvailable, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
    _ = fixture.memoryMap(&bytes);
    endian.writeU32Le(bytes[48..52], 2);
    try std.testing.expectError(error.RamNotAvailable, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
    _ = fixture.memoryMap(&bytes);
    endian.writeU32Le(bytes[20..24], 11);
    try std.testing.expectError(error.RamNotAvailable, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
    _ = fixture.memoryMap(&bytes);
    endian.writeU64Le(bytes[128..136], std.math.maxInt(u64));
    try std.testing.expectError(error.InvalidMemoryMap, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
    _ = fixture.memoryMap(&bytes);
    var legacy_info = info;
    legacy_info.mmap_entry_size = 24;
    try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, handoff.multiboot2MemoryMap(&bytes, 24), legacy_info, fixture.kernel_start, fixture.kernel_end, view));

    var state = TEST_WRITE_BACK_MTRRS;
    state.capabilities = 1;
    state.variable[0] = testVariableMtrr(info.boot_image.?.heap_base + TEST_PAGE_SIZE, TEST_PAGE_SIZE, .write_through, state.physical_bits);
    const mixed_view = try cache_policy.ValidatedMtrrView.init(&state);
    try std.testing.expectError(error.MixedMemoryTypes, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, mixed_view));
    try fixture.expectUntouched(&storage);
}

test "scanout touched pages cannot become owned WB backing before bitmap writes" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);
    var info = fixture.info();
    info.flags |= 1 << 12;
    // Unsupported geometry still describes live device storage. It is not
    // permission to reclaim an overlap that is otherwise positively typed WB.
    info.framebuffer_bpp = 8;
    info.framebuffer_type = 2;
    info.framebuffer_height = 1;
    const owned = [_]PhysicalSpan{
        .{ .start = fixture.kernel_start, .end = fixture.kernel_end },
        .{ .start = info.boot_image.?.heap_base, .end = info.boot_image.?.heap_base + @import("../../boot/image_info.zig").KERNEL_HEAP_BYTES },
        .{ .start = info.boot_paging.?.transition_base, .end = info.boot_paging.?.transition_base + TEST_MAX_ARENA_BYTES },
        .{ .start = info.boot_paging.?.final_base, .end = info.boot_paging.?.final_base + TEST_MAX_ARENA_BYTES },
    };
    for (owned) |span| {
        try requireRamWriteBack(map, span.start, span.end - span.start, view);
        for ([_]u64{ span.start - 1, span.start, span.end - 1 }) |base| {
            info.framebuffer_addr = base;
            info.framebuffer_pitch = if (base == span.start - 1) 2 else 1;
            try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
            try fixture.expectUntouched(&storage);
        }
        // Exact adjacency is safe on either side; rounding must not claim an
        // extra page when the byte extent ends at an owned-page boundary.
        info.framebuffer_pitch = 1;
        for ([_]u64{ span.start - 1, span.end }) |base| {
            info.framebuffer_addr = base;
            try validateBootOwnedRanges(map, fixture.info_address, info, fixture.kernel_start, fixture.kernel_end, view);
            try fixture.expectUntouched(&storage);
        }
    }

    info.framebuffer_addr = 128 * fixture.mib;
    info.framebuffer_pitch = 0;
    try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
    info.framebuffer_pitch = 4096;
    info.framebuffer_height = 0;
    try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
    info.framebuffer_height = 2;
    info.framebuffer_addr = std.math.maxInt(u64) - 4095;
    try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
    try fixture.expectUntouched(&storage);
}

test "advertised GOP padding stays reserved independently of supported rendering" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    var allocator = fixture.Allocator.bindStorage(&storage);
    for ([_]bool{ false, true }) |visible| {
        var info = fixture.info();
        info.boot_paging.?.framebuffer_base = 136 * fixture.mib + 128;
        info.boot_paging.?.framebuffer_bytes = 3 * TEST_PAGE_SIZE + 1;
        if (visible) {
            info.flags |= 1 << 12;
            info.framebuffer_addr = info.boot_paging.?.framebuffer_base;
            info.framebuffer_width = 32;
            info.framebuffer_height = 32;
            info.framebuffer_pitch = 128;
            info.framebuffer_bpp = 32;
            info.framebuffer_type = 1;
            info.framebuffer_rgb = .{ 16, 8, 8, 8, 0, 8 };
        }
        try fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view);
        try reserveLiveHandoffRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, fixture.info_address, info);
        const span = (try info.boot_paging.?.framebufferSpan()).?;
        for (0..4) |index| try std.testing.expect(allocator.isReserved(span.start + index * TEST_PAGE_SIZE));
        try std.testing.expect(!allocator.isReserved(span.start - TEST_PAGE_SIZE));
        try std.testing.expect(!allocator.isReserved(span.end));
        const authority = KernelMappingAuthority{
            .memory_map = map,
            .info_address = fixture.info_address,
            .info = info,
            .image = .{ .start = fixture.kernel_start, .end = fixture.kernel_end },
            .heap = .{ .start = info.boot_image.?.heap_base, .end = info.boot_image.?.heap_base + @import("../../boot/image_info.zig").KERNEL_HEAP_BYTES },
            .managed_bytes = fixture.memory_bytes,
        };
        try std.testing.expect(authority.permits(&allocator, span.start, span.end, true));
        try std.testing.expect(authority.permits(&allocator, span.start, span.start + 2 * TEST_PAGE_SIZE, true));
        try std.testing.expect(authority.permits(&allocator, span.end - TEST_PAGE_SIZE, span.end, true));
        try std.testing.expect(!authority.permits(&allocator, span.start - TEST_PAGE_SIZE, span.start + TEST_PAGE_SIZE, true));
        try std.testing.expect(!authority.permits(&allocator, span.end - TEST_PAGE_SIZE, span.end + TEST_PAGE_SIZE, true));
        try std.testing.expect(!authority.permits(&allocator, span.start, span.end, false));
        if (visible) {
            const visible_bytes = @as(u64, info.framebuffer_pitch) * info.framebuffer_height;
            try std.testing.expect(visible_bytes < info.boot_paging.?.framebuffer_bytes);
            try std.testing.expect(allocator.isReserved(span.start + 3 * TEST_PAGE_SIZE));
        } else try std.testing.expect(!info.hasFramebuffer());
    }
}

test "advertised GOP tail collisions reject unsupported and visible fixtures before bitmap writes" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
    const view = try cache_policy.ValidatedMtrrView.init(&TEST_WRITE_BACK_MTRRS);
    var storage: fixture.Allocator.Storage = undefined;
    @memset(std.mem.asBytes(&storage), 0xa5);
    var allocator = fixture.Allocator.bindStorage(&storage);
    for ([_]bool{ false, true }) |visible| {
        for ([_]u64{ fixture.kernel_start, 32 * fixture.mib, 80 * fixture.mib, 112 * fixture.mib }) |owned_start| {
            var info = fixture.info();
            info.boot_paging.?.framebuffer_base = owned_start - 2 * TEST_PAGE_SIZE + 128;
            info.boot_paging.?.framebuffer_bytes = 2 * TEST_PAGE_SIZE + 1;
            if (visible) {
                info.flags |= 1 << 12;
                info.framebuffer_addr = info.boot_paging.?.framebuffer_base;
                info.framebuffer_pitch = TEST_PAGE_SIZE;
                info.framebuffer_height = 1;
                info.framebuffer_bpp = 32;
                info.framebuffer_type = 1;
            }
            // Only advertised padding collides. The older visible/default-zero
            // fixture admits this geometry and cannot protect the extra tail.
            var fallback = info;
            fallback.boot_paging.?.framebuffer_base = 0;
            fallback.boot_paging.?.framebuffer_bytes = 0;
            try validateBootOwnedRanges(map, fixture.info_address, fallback, fixture.kernel_start, fixture.kernel_end, view);
            try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
            if (owned_start == info.boot_paging.?.transition_base or owned_start == info.boot_paging.?.final_base)
                try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, fixture.info_address, info));
            try fixture.expectUntouched(&storage);
        }
    }
}

test "advertised GOP malformed extents fail atomically without a render tag" {
    const fixture = BootOwnedTest;
    var bytes: [160]u8 = undefined;
    const map = fixture.memoryMap(&bytes);
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
        info.boot_paging.?.framebuffer_base = extent.base;
        info.boot_paging.?.framebuffer_bytes = extent.length;
        try std.testing.expect(!info.hasFramebuffer());
        try std.testing.expectError(error.InvalidHandoffRange, fixture.initializeAfterAdmission(&allocator, map, info, fixture.kernel_start, fixture.kernel_end, view));
        try std.testing.expectError(error.InvalidHandoffRange, reserveLiveHandoffRanges(fixture.memory_bytes, TEST_PAGE_SIZE, &allocator, fixture.info_address, info));
        try fixture.expectUntouched(&storage);
    }
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
    try initializeTestAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24));
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
    var bytes = @as([24]u8, @splat(0));
    _ = appendEntry(&bytes, 0, high_frame_base, 2 * TEST_PAGE_SIZE, 1);

    try initializeTestAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24));

    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
    try std.testing.expectEqual(high_frame_base, allocator.allocate(2).?.base);
}

test "non-usable pages win over usable pages in either descriptor order" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var usable_first = @as([48]u8, @splat(0));
    var offset = appendEntry(&usable_first, 0, 0, 6 * TEST_PAGE_SIZE, 1);
    _ = appendEntry(&usable_first, offset, 2 * TEST_PAGE_SIZE + 100, 200, 2);

    var reserved_first = @as([48]u8, @splat(0));
    offset = appendEntry(&reserved_first, 0, 2 * TEST_PAGE_SIZE + 100, 200, 2);
    _ = appendEntry(&reserved_first, offset, 0, 6 * TEST_PAGE_SIZE, 1);

    var first_storage: Allocator.Storage = undefined;
    var first = Allocator.init(&first_storage);
    var second_storage: Allocator.Storage = undefined;
    var second = Allocator.init(&second_storage);
    try initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &first, handoff.multiboot2MemoryMap(&usable_first, 24));
    try initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &second, handoff.multiboot2MemoryMap(&reserved_first, 24));

    try std.testing.expect(first.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expect(second.isReserved(2 * TEST_PAGE_SIZE));
    try std.testing.expectEqual(first.stats(), second.stats());
    try std.testing.expectEqual(@as(u32, 5), first.stats().free);
}

test "non-usable page ceilings and aperture clipping are conservative" {
    const Allocator = frame_allocator.Fixed(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var bytes = @as([72]u8, @splat(0));
    var offset = appendEntry(&bytes, 0, 1, 8 * TEST_PAGE_SIZE, 1);
    offset = appendEntry(&bytes, offset, TEST_PAGE_SIZE - 1, 2, 2);
    _ = appendEntry(&bytes, offset, 8 * TEST_PAGE_SIZE - 1, 2, 4);

    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24));

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
    var bytes = @as([24]u8, @splat(0));
    _ = appendEntry(&bytes, 0, std.math.maxInt(u64) - 1, 4, 1);

    try std.testing.expectError(
        error.InvalidMemoryMap,
        initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&bytes, 24)),
    );
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().free);

    try std.testing.expectError(
        error.InvalidMemoryMap,
        initializeTestAllocator(8 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, &allocator, handoff.multiboot2MemoryMap(&[_]u8{}, 24)),
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

test "both loader paging arenas stay owned and cannot become framebuffer aliases" {
    const mib = 1024 * 1024;
    const memory_bytes = 128 * mib;
    const Allocator = frame_allocator.Fixed(memory_bytes, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.bindStorage(&storage);
    var bytes: [24]u8 = undefined;
    _ = appendEntry(&bytes, 0, 0, memory_bytes, 1);
    const map = handoff.multiboot2MemoryMap(&bytes, 24);
    try initializeTestAllocator(memory_bytes, TEST_PAGE_SIZE, &allocator, map);
    var info = testInfo(FLAG_FOR_TEST_MMAP | (1 << 12), 2 * TEST_PAGE_SIZE, 24, 0);
    info.boot_paging = .{ .transition_pages = 3, .final_pages = 31, .transition_base = 64 * mib, .final_base = 96 * mib };
    try reserveLiveHandoffRanges(memory_bytes, TEST_PAGE_SIZE, &allocator, TEST_PAGE_SIZE, info);
    const arenas = info.boot_paging.?;
    for ([_]struct { base: u64, bytes: u64 }{
        .{ .base = arenas.transition_base, .bytes = arenas.transitionBytes() },
        .{ .base = arenas.final_base, .bytes = arenas.finalBytes() },
    }) |arena| {
        try std.testing.expect(allocator.isReserved(arena.base));
        try std.testing.expect(allocator.isReserved(arena.base + arena.bytes - TEST_PAGE_SIZE));
        try std.testing.expect(!allocator.isReserved(arena.base - TEST_PAGE_SIZE));
        try std.testing.expect(!allocator.isReserved(arena.base + arena.bytes));
    }
    try std.testing.expectEqual(arenas.transition_pages + arenas.final_pages + 2, allocator.stats().reserved);

    info.framebuffer_addr = 64 * mib + 128;
    info.framebuffer_width = 32;
    info.framebuffer_height = 32;
    info.framebuffer_pitch = 128;
    info.framebuffer_bpp = 32;
    info.framebuffer_type = 1;
    info.framebuffer_rgb = .{ 16, 8, 8, 8, 0, 8 };
    const authority = KernelMappingAuthority{
        .memory_map = map,
        .info_address = TEST_PAGE_SIZE,
        .info = info,
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
    adjacent_info.framebuffer_addr = arenas.transition_base + arenas.transitionBytes();
    try allocator.reserve(.{ .base = adjacent_info.framebuffer_addr, .count = 1 });
    var adjacent_authority = authority;
    adjacent_authority.info = adjacent_info;
    try std.testing.expect(adjacent_authority.permits(&allocator, adjacent_info.framebuffer_addr, adjacent_info.framebuffer_addr + TEST_PAGE_SIZE, true));
    adjacent_info.framebuffer_addr -= TEST_PAGE_SIZE;
    adjacent_authority.info = adjacent_info;
    try std.testing.expect(!adjacent_authority.permits(&allocator, adjacent_info.framebuffer_addr, adjacent_info.framebuffer_addr + TEST_PAGE_SIZE, true));

    allocator.reset();
    info.boot_paging.?.final_base = memory_bytes - info.boot_paging.?.finalBytes() + TEST_PAGE_SIZE;
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

test "device authority rejects every RAM class live range and allocated or unreserved gap" {
    const Allocator = frame_allocator.Fixed(64 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    var bytes: [48]u8 = undefined;
    _ = appendEntry(&bytes, 0, 16 * TEST_PAGE_SIZE, 2 * TEST_PAGE_SIZE, 6);
    _ = appendEntry(&bytes, 24, 32 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 3);
    var authority = KernelMappingAuthority{
        .memory_map = handoff.multiboot2MemoryMap(&bytes, 24),
        .info_address = TEST_PAGE_SIZE,
        .info = testInfo(FLAG_FOR_TEST_MMAP, 2 * TEST_PAGE_SIZE, 48, 0),
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = 64 * TEST_PAGE_SIZE,
    };
    try std.testing.expect(authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 18 * TEST_PAGE_SIZE, true));
    try std.testing.expect(authority.permits(&allocator, 24 * TEST_PAGE_SIZE, 25 * TEST_PAGE_SIZE, true));
    for ([_]u32{ 1, 2, 3, 4, 5, 7, 0, 99 }) |kind| {
        _ = appendEntry(&bytes, 0, 16 * TEST_PAGE_SIZE, 2 * TEST_PAGE_SIZE, kind);
        try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 18 * TEST_PAGE_SIZE, true));
    }
    _ = appendEntry(&bytes, 0, 16 * TEST_PAGE_SIZE, 2 * TEST_PAGE_SIZE, 6);
    for ([_]u64{ TEST_PAGE_SIZE, 2 * TEST_PAGE_SIZE, 4 * TEST_PAGE_SIZE, 8 * TEST_PAGE_SIZE, 32 * TEST_PAGE_SIZE }) |physical| {
        try std.testing.expect(!authority.permits(&allocator, physical, physical + TEST_PAGE_SIZE, true));
    }
    try allocator.makeAvailable(.{ .base = 24 * TEST_PAGE_SIZE, .count = 2 });
    try std.testing.expect(!authority.permits(&allocator, 24 * TEST_PAGE_SIZE, 25 * TEST_PAGE_SIZE, true));
    _ = allocator.allocateBetween(1, 25 * TEST_PAGE_SIZE, 26 * TEST_PAGE_SIZE).?;
    try std.testing.expect(!authority.permits(&allocator, 25 * TEST_PAGE_SIZE, 26 * TEST_PAGE_SIZE, true));
    authority.info.flags |= 1 << 13;
    authority.info.acpi2_rsdp_addr = 16 * TEST_PAGE_SIZE + 128;
    authority.info.acpi2_rsdp_length = 36;
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 17 * TEST_PAGE_SIZE, true));
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
    var bytes: [24]u8 = undefined;
    _ = appendEntry(&bytes, 0, start - TEST_PAGE_SIZE, mcfg.ECAM_BUS_BYTES + 2 * TEST_PAGE_SIZE, 2);
    var authority = KernelMappingAuthority{
        .memory_map = handoff.multiboot2MemoryMap(&bytes, 24),
        .info_address = TEST_PAGE_SIZE,
        .info = testInfo(FLAG_FOR_TEST_MMAP, 2 * TEST_PAGE_SIZE, bytes.len, 0),
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
    var bytes: [48]u8 = undefined;
    _ = appendEntry(&bytes, 0, start, mcfg.ECAM_BUS_BYTES, 2);
    _ = appendEntry(&bytes, 24, start + 2 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 2);
    const original = KernelMappingAuthority{
        .memory_map = handoff.multiboot2MemoryMap(&bytes, 24),
        .info_address = TEST_PAGE_SIZE,
        .info = testInfo(FLAG_FOR_TEST_MMAP, 2 * TEST_PAGE_SIZE, bytes.len, 0),
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = memory_bytes,
    };
    for ([_]u32{ 1, 3, 4, 5, 7, 0, 99 }) |kind| {
        _ = appendEntry(&bytes, 24, start + 2 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, kind);
        var authority = original;
        try std.testing.expectError(error.PhysicalOwnershipConflict, authority.registerPciEcam(&allocator, allocation));
        try std.testing.expect(authority.pci_ecam == null);
    }
    _ = appendEntry(&bytes, 24, start + 2 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 2);
    for (0..3) |protected| {
        var authority = original;
        const protected_span = PhysicalSpan{ .start = start + TEST_PAGE_SIZE, .end = start + 2 * TEST_PAGE_SIZE };
        switch (protected) {
            0 => authority.image = protected_span,
            1 => authority.heap = protected_span,
            else => authority.info_address = protected_span.start,
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
    // still exclude positively classified RAM despite its kind2 reservation.
    const allocation = mcfg.Allocation{ .base_address = 4 * mcfg.ECAM_BUS_BYTES, .segment_group = 0, .start_bus = 0, .end_bus = 0 };
    var bytes: [32]u8 = undefined;
    _ = appendNativeEntry(&bytes, 0, allocation.base_address, mcfg.ECAM_BUS_BYTES, 2, 0);
    const original = KernelMappingAuthority{
        .memory_map = handoff.multiboot2MemoryMap(&bytes, 32),
        .info_address = TEST_PAGE_SIZE,
        .info = testInfo(FLAG_FOR_TEST_MMAP, 2 * TEST_PAGE_SIZE, bytes.len, 0),
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = 64 * TEST_PAGE_SIZE,
    };
    var reserved = original;
    try reserved.registerPciEcam(&allocator, allocation);
    try std.testing.expect(reserved.permits(&allocator, allocation.base_address, allocation.base_address + TEST_PAGE_SIZE, true));
    for ([_]u32{ 1, 2, 3, 4, 5, 6, 7, 9, 10, 14 }) |firmware_type| {
        _ = appendNativeEntry(&bytes, 0, allocation.base_address, mcfg.ECAM_BUS_BYTES, 2, firmware_type);
        var authority = original;
        try std.testing.expectError(error.PhysicalOwnershipConflict, authority.registerPciEcam(&allocator, allocation));
        try std.testing.expect(authority.pci_ecam == null);
        try std.testing.expect(!reserved.permits(&allocator, allocation.base_address, allocation.base_address + TEST_PAGE_SIZE, true));
    }
}

const FLAG_FOR_TEST_MMAP: u32 = 1 << 6;

test "firmware authority needs complete allowed coverage and rejects overlapping conflicting descriptors" {
    const Allocator = frame_allocator.Fixed(64 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    var bytes: [72]u8 = undefined;
    // Unsorted adjacent ACPI/runtime descriptors cover the complete span.
    _ = appendEntry(&bytes, 0, 18 * TEST_PAGE_SIZE, 2 * TEST_PAGE_SIZE, 7);
    _ = appendEntry(&bytes, 24, 16 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 3);
    _ = appendEntry(&bytes, 48, 17 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 4);
    const authority = KernelMappingAuthority{
        .memory_map = handoff.multiboot2MemoryMap(&bytes, 24),
        .info_address = TEST_PAGE_SIZE,
        .info = testInfo(FLAG_FOR_TEST_MMAP, 2 * TEST_PAGE_SIZE, 72, 0),
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = 64 * TEST_PAGE_SIZE,
    };
    try std.testing.expect(authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 20 * TEST_PAGE_SIZE, false));
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 21 * TEST_PAGE_SIZE, false));
    try std.testing.expect(!authority.permits(&allocator, 24 * TEST_PAGE_SIZE, 25 * TEST_PAGE_SIZE, false));
    _ = appendEntry(&bytes, 48, 17 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 6);
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 20 * TEST_PAGE_SIZE, false));
    _ = appendEntry(&bytes, 48, 18 * TEST_PAGE_SIZE, TEST_PAGE_SIZE, 1);
    try std.testing.expect(!authority.permits(&allocator, 18 * TEST_PAGE_SIZE, 19 * TEST_PAGE_SIZE, false));
    _ = appendEntry(&bytes, 48, 0xffff_ffff_ffff_f000, 2 * TEST_PAGE_SIZE, 6);
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 17 * TEST_PAGE_SIZE, false));
}

test "framebuffer exception admits only its exact reserved touched pages and never protected backing" {
    const Allocator = frame_allocator.Fixed(64 * TEST_PAGE_SIZE, TEST_PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.init(&storage);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    var bytes: [24]u8 = undefined;
    _ = appendEntry(&bytes, 0, 16 * TEST_PAGE_SIZE, 4 * TEST_PAGE_SIZE, 1);
    var info = testInfo(FLAG_FOR_TEST_MMAP | (1 << 12), 2 * TEST_PAGE_SIZE, 24, 0);
    info.framebuffer_addr = 16 * TEST_PAGE_SIZE + 128;
    info.framebuffer_width = 32;
    info.framebuffer_height = 32;
    info.framebuffer_pitch = 128;
    info.framebuffer_bpp = 32;
    info.framebuffer_type = 1;
    info.framebuffer_rgb = .{ 16, 8, 8, 8, 0, 8 };
    var authority = KernelMappingAuthority{
        .memory_map = handoff.multiboot2MemoryMap(&bytes, 24),
        .info_address = TEST_PAGE_SIZE,
        .info = info,
        .image = .{ .start = 4 * TEST_PAGE_SIZE, .end = 8 * TEST_PAGE_SIZE },
        .heap = .{ .start = 8 * TEST_PAGE_SIZE, .end = 12 * TEST_PAGE_SIZE },
        .managed_bytes = 64 * TEST_PAGE_SIZE,
    };
    try std.testing.expect(authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 18 * TEST_PAGE_SIZE, true));
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 17 * TEST_PAGE_SIZE, true));
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 19 * TEST_PAGE_SIZE, true));
    authority.heap = .{ .start = 17 * TEST_PAGE_SIZE, .end = 18 * TEST_PAGE_SIZE };
    try std.testing.expect(!authority.permits(&allocator, 16 * TEST_PAGE_SIZE, 18 * TEST_PAGE_SIZE, true));
}
