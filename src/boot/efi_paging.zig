const std = @import("std");
const kernel_address = @import("../arch/kernel_address.zig");
const cache_policy = @import("../arch/cache_policy.zig");
pub const sparse = @import("../arch/sparse_physical_map.zig");
const efi_handoff = @import("efi_handoff.zig");
const efi_elf = @import("efi_elf.zig");
pub const Mode = efi_elf.Mode;

pub const PAGE_BYTES: usize = 4096;
pub const MAX_PAGE_COUNT: usize = efi_handoff.paging_info.MAX_ARENA_PAGES;
pub const ALIAS_BYTES: u64 = kernel_address.image_physical_limit;
pub const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
pub const Error = error{ InvalidPhysicalRange, InvalidPagingMode, TransitionAliasConflict, InvalidMemoryMap, BufferTooSmall, AddressOverflow };

pub fn validateTransition(cr4: u64, instruction_address: u64, stack_address: u64) Error!void {
    if (cr4 & (1 << 12) != 0) return error.InvalidPagingMode;
    for ([_]u64{ instruction_address, stack_address }) |address| {
        const root_index = (address >> 39) & 511;
        if (root_index == 256 or root_index == 511) return error.TransitionAliasConflict;
    }
}

pub fn mappedBytes(mode: Mode) u64 {
    return if (mode == .native_high) kernel_address.direct_map_capacity else ALIAS_BYTES;
}

// The arrays live in each caller's stack frame throughout the synchronous
// count/build call. No configuration borrows a returned local array.
const Plan = struct {
    direct: [256]sparse.Region = undefined,
    image: [efi_elf.MAX_LOAD_SEGMENTS]sparse.Region = undefined,
    overlays: [efi_elf.MAX_LOAD_SEGMENTS + 1]sparse.Region = undefined,
    direct_count: usize = 0,
    image_count: usize = 0,
    overlay_count: usize = 0,

    fn config(self: *const Plan, mode: Mode, cache: cache_policy.ValidatedMtrrView) sparse.Config {
        return .{
            .cache = cache,
            .image = self.image[0..self.image_count],
            .direct = self.direct[0..self.direct_count],
            .direct_overlays = self.overlays[0..self.overlay_count],
            .allow_1g = mode == .native_high,
            .direct_limit = mappedBytes(mode),
        };
    }
};

fn prepareInto(image: efi_elf.Image, entries: []const efi_handoff.MmapEntry, heap_base: u64, framebuffer_span: ?efi_handoff.paging_info.Span, out: *Plan) !void {
    if (image.segment_count == 0 or image.segment_count > efi_elf.MAX_LOAD_SEGMENTS) return error.InvalidPhysicalRange;
    out.direct_count = try ramRegions(entries, &out.direct, framebuffer_span);
    out.image_count = image.segment_count;
    for (image.segments[0..image.segment_count], 0..) |segment, index| {
        const rounded = std.math.add(u64, segment.mem_size, PAGE_BYTES - 1) catch return error.AddressOverflow;
        const bytes = rounded & ~@as(u64, PAGE_BYTES - 1);
        const end = std.math.add(u64, segment.phys_addr, bytes) catch return error.AddressOverflow;
        if (segment.mem_size == 0 or (segment.flags != efi_elf.PF_R and segment.flags != (efi_elf.PF_R | efi_elf.PF_X) and segment.flags != (efi_elf.PF_R | efi_elf.PF_W)))
            return error.InvalidPhysicalRange;
        out.image[index] = .{ .start = segment.phys_addr, .end = end, .permissions = .{ .writable = segment.flags & 2 != 0, .executable = segment.flags & 1 != 0, .force_4k = segment.flags & 2 != 0 } };
    }
    sortRegions(out.image[0..out.image_count]);
    out.overlay_count = 0;
    for (out.image[0..out.image_count]) |region| {
        if (region.permissions.writable) continue;
        out.overlays[out.overlay_count] = .{ .start = region.start, .end = region.end, .permissions = .{ .writable = false } };
        out.overlay_count += 1;
    }
    const heap_end = std.math.add(u64, heap_base, efi_handoff.image_info.KERNEL_HEAP_BYTES) catch return error.AddressOverflow;
    out.overlays[out.overlay_count] = .{ .start = heap_base, .end = heap_end, .permissions = .{ .force_4k = true } };
    out.overlay_count += 1;
    sortRegions(out.overlays[0..out.overlay_count]);
}

pub fn countForModeInto(mode: Mode, image: efi_elf.Image, entries: []const efi_handoff.MmapEntry, cache: cache_policy.ValidatedMtrrView, heap_base: u64, framebuffer_span: ?efi_handoff.paging_info.Span, out: *sparse.Counts) !void {
    var plan: Plan = undefined;
    try prepareInto(image, entries, heap_base, framebuffer_span, &plan);
    try sparse.countInto(plan.config(mode, cache), out);
}

pub fn buildForMode(
    arena: []align(PAGE_BYTES) std.os.uefi.Page,
    physical_base: u64,
    active_root: *const [512]u64,
    mode: Mode,
    image: efi_elf.Image,
    entries: []const efi_handoff.MmapEntry,
    cache: cache_policy.ValidatedMtrrView,
    heap_base: u64,
    paging_info: efi_handoff.paging_info.Info,
) !u64 {
    try paging_info.validate();
    if (arena.len < 3 or arena.len > MAX_PAGE_COUNT or physical_base != paging_info.transition_base or arena.len != paging_info.transition_pages)
        return error.InvalidPhysicalRange;
    var plan: Plan = undefined;
    try prepareInto(image, entries, heap_base, try paging_info.framebufferSpan(), &plan);
    var result: sparse.Result = undefined;
    const tables: [*]align(PAGE_BYTES) [512]u64 = @ptrCast(arena.ptr);
    try sparse.build(tables[0..arena.len], physical_base, active_root, plan.config(mode, cache), &result);
    return result.root_physical;
}

// Retain original EFI RAM provenance even for the reserved table arenas.
// Unknown/reserved/device descriptors never grant direct-map authority.
pub fn ramRegions(entries: []const efi_handoff.MmapEntry, out: []sparse.Region, device: ?efi_handoff.paging_info.Span) Error!usize {
    if (entries.len == 0 or entries.len > 256) return error.InvalidMemoryMap;
    if (device) |span| {
        if (span.start >= span.end or span.start % PAGE_BYTES != 0 or span.end % PAGE_BYTES != 0) return error.InvalidPhysicalRange;
    }
    var count: usize = 0;
    var previous_end: u64 = 0;
    for (entries, 0..) |entry, index| {
        const end = std.math.add(u64, entry.base, entry.length) catch return error.AddressOverflow;
        if (entry.length == 0 or (index != 0 and entry.base < previous_end)) return error.InvalidMemoryMap;
        previous_end = end;
        if (!efi_handoff.memory_kind.efiTypeIsRam(entry.firmware_type)) continue;
        if (entry.kind != 1 and entry.kind != 2 and entry.kind != 3 and entry.kind != 4 and entry.kind != 7) continue;
        const writable = entry.kind == 1 or entry.kind == 2;
        if (device) |excluded| {
            if (entry.base < excluded.end and excluded.start < end) {
                try appendRamRegion(out, &count, entry.base, @min(end, excluded.start), writable);
                try appendRamRegion(out, &count, @max(entry.base, excluded.end), end, writable);
                continue;
            }
        }
        try appendRamRegion(out, &count, entry.base, end, writable);
    }
    if (count == 0) return error.InvalidMemoryMap;
    return count;
}

fn appendRamRegion(out: []sparse.Region, count: *usize, start: u64, end: u64, writable: bool) Error!void {
    if (end <= start) return;
    if (count.* != 0 and out[count.* - 1].end == start and out[count.* - 1].permissions.writable == writable) {
        out[count.* - 1].end = end;
        return;
    }
    if (count.* == out.len) return error.BufferTooSmall;
    out[count.*] = .{ .start = start, .end = end, .permissions = .{ .writable = writable } };
    count.* += 1;
}

pub fn sortEntries(entries: []efi_handoff.MmapEntry) void {
    if (entries.len < 2) return;
    for (1..entries.len) |index| {
        const value = entries[index];
        var position = index;
        while (position != 0 and entries[position - 1].base > value.base) : (position -= 1) entries[position] = entries[position - 1];
        entries[position] = value;
    }
}

pub fn sortRegions(regions: []sparse.Region) void {
    if (regions.len < 2) return;
    for (1..regions.len) |index| {
        const value = regions[index];
        var position = index;
        while (position != 0 and regions[position - 1].start > value.start) : (position -= 1) regions[position] = regions[position - 1];
        regions[position] = value;
    }
}

pub fn requireRamRange(entries: []const efi_handoff.MmapEntry, start: u64, bytes: u64) Error!void {
    const end = std.math.add(u64, start, bytes) catch return error.AddressOverflow;
    if (bytes == 0) return error.InvalidPhysicalRange;
    var cursor = start;
    for (entries) |entry| {
        const entry_end = std.math.add(u64, entry.base, entry.length) catch return error.AddressOverflow;
        if (entry_end <= cursor) continue;
        if (entry.base > cursor or !efi_handoff.memory_kind.efiTypeIsRam(entry.firmware_type)) return error.InvalidPhysicalRange;
        cursor = @min(end, entry_end);
        if (cursor == end) return;
    }
    return error.InvalidPhysicalRange;
}

pub fn appendMemoryDescriptor(
    entries: []efi_handoff.MmapEntry,
    count: *usize,
    base: u64,
    length: u64,
    kind: u32,
    firmware_type: u32,
    attributes: u64,
    arenas: ?efi_handoff.paging_info.Info,
) Error!void {
    const end = std.math.add(u64, base, length) catch return error.AddressOverflow;
    const receipts = arenas orelse return appendRange(entries, count, base, end, kind, firmware_type, attributes);
    receipts.validate() catch return error.InvalidPhysicalRange;
    var spans = [_]efi_handoff.paging_info.Span{
        .{ .start = receipts.transition_base, .end = receipts.transition_base + receipts.transitionBytes() },
        .{ .start = receipts.final_base, .end = receipts.final_base + receipts.finalBytes() },
    };
    if (spans[0].start > spans[1].start) std.mem.swap(efi_handoff.paging_info.Span, &spans[0], &spans[1]);
    var cursor = base;
    for (spans) |span| {
        if (span.start >= end or span.end <= cursor) continue;
        const start = @max(cursor, span.start);
        try appendRange(entries, count, cursor, start, kind, firmware_type, attributes);
        const limit = @min(end, span.end);
        try appendRange(entries, count, start, limit, efi_handoff.MULTIBOOT_MEMORY_RESERVED, firmware_type, attributes);
        cursor = limit;
    }
    try appendRange(entries, count, cursor, end, kind, firmware_type, attributes);
}

fn appendRange(entries: []efi_handoff.MmapEntry, count: *usize, start: u64, end: u64, kind: u32, firmware_type: u32, attributes: u64) Error!void {
    if (start == end) return;
    if (count.* >= entries.len) return error.BufferTooSmall;
    entries[count.*] = .{ .base = start, .length = end - start, .kind = kind, .firmware_type = firmware_type, .attributes = attributes };
    count.* += 1;
}

test "EFI handoff reserves disjoint table arenas without losing RAM provenance" {
    const arenas = efi_handoff.paging_info.Info{ .transition_base = 0x2000000, .transition_pages = 5, .final_base = 0x4000000, .final_pages = 9 };
    var entries: [5]efi_handoff.MmapEntry = undefined;
    var count: usize = 0;
    try appendMemoryDescriptor(&entries, &count, 0x1000000, 0x5000000, 1, 2, 8, arenas);
    try std.testing.expectEqual(@as(usize, 5), count);
    try std.testing.expectEqual(@as(u32, 2), entries[1].kind);
    try std.testing.expectEqual(@as(u32, 2), entries[3].kind);
    try std.testing.expectEqual(arenas.transitionBytes(), entries[1].length);
    try std.testing.expectEqual(arenas.finalBytes(), entries[3].length);
    for (entries) |entry| {
        try std.testing.expectEqual(@as(u32, 2), entry.firmware_type);
        try std.testing.expectEqual(@as(u64, 8), entry.attributes);
    }
    var regions: [5]sparse.Region = undefined;
    try std.testing.expectEqual(@as(usize, 1), try ramRegions(&entries, &regions, null));
    try std.testing.expectEqual(@as(u64, 0x1000000), regions[0].start);
    try std.testing.expectEqual(@as(u64, 0x6000000), regions[0].end);
    try requireRamRange(&entries, 0x1000000, 0x5000000);
    entries[2].firmware_type = 11;
    try std.testing.expectError(error.InvalidPhysicalRange, requireRamRange(&entries, 0x1000000, 0x5000000));
}

test "EFI RAM authority rejects gaps overlap unknown memory and overflow" {
    var regions: [4]sparse.Region = undefined;
    var entries = [_]efi_handoff.MmapEntry{
        .{ .base = 0x1000, .length = 0x1000, .kind = 1, .firmware_type = 7 },
        .{ .base = 0x3000, .length = 0x1000, .kind = 6, .firmware_type = 11 },
        .{ .base = 0x5000, .length = 0x1000, .kind = 2 },
    };
    try std.testing.expectEqual(@as(usize, 1), try ramRegions(&entries, &regions, null));
    try std.testing.expectError(error.InvalidPhysicalRange, requireRamRange(&entries, 0x1000, 0x2000));
    entries[1].base = 0x1000;
    try std.testing.expectError(error.InvalidMemoryMap, ramRegions(&entries, &regions, null));
    entries[1].base = std.math.maxInt(u64);
    try std.testing.expectError(error.AddressOverflow, ramRegions(entries[1..2], &regions, null));
    try validateTransition(0, 0x12340000, 0x56780000);
    try std.testing.expectError(error.InvalidPagingMode, validateTransition(1 << 12, 0x1234, 0x5678));
    try std.testing.expectError(error.TransitionAliasConflict, validateTransition(0, kernel_address.image_virtual_bias + 4096, 0x5678));
    try std.testing.expectError(error.TransitionAliasConflict, validateTransition(0, 0x1234, kernel_address.direct_map_base + 4096));
}

test "EFI RAM authority excludes the complete GOP allocation across descriptor boundaries" {
    const entries = [_]efi_handoff.MmapEntry{
        .{ .base = 0x1000, .length = 0x3000, .kind = 1, .firmware_type = 7 },
        .{ .base = 0x4000, .length = 0x4000, .kind = 2, .firmware_type = 2 },
        .{ .base = 0x8000, .length = 0x2000, .kind = 3, .firmware_type = 9 },
    };
    var regions: [3]sparse.Region = undefined;
    const count = try ramRegions(&entries, &regions, .{ .start = 0x3000, .end = 0x9000 });
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualDeep(sparse.Region{ .start = 0x1000, .end = 0x3000 }, regions[0]);
    try std.testing.expectEqualDeep(sparse.Region{ .start = 0x9000, .end = 0xa000, .permissions = .{ .writable = false } }, regions[1]);
    try std.testing.expectEqual(@as(usize, 1), try ramRegions(entries[0..2], &regions, .{ .start = 0x8000, .end = 0xa000 }));
    try std.testing.expectError(error.InvalidMemoryMap, ramRegions(&entries, &regions, .{ .start = 0x1000, .end = 0xa000 }));
    try std.testing.expectError(error.InvalidPhysicalRange, ramRegions(&entries, &regions, .{ .start = 0x3001, .end = 0x9000 }));
    var single: [1]sparse.Region = undefined;
    try std.testing.expectError(error.BufferTooSmall, ramRegions(entries[0..1], &single, .{ .start = 0x2000, .end = 0x3000 }));
}

fn countFixtureImage() efi_elf.Image {
    var image = efi_elf.Image{ .entry = kernel_address.image_virtual_bias + 32 * 1024 * 1024, .segment_count = 3 };
    image.segments[0] = .{ .phys_addr = 32 * 1024 * 1024, .mem_size = 2 * 1024 * 1024, .file_offset = 0, .file_size = 1, .flags = efi_elf.PF_R | efi_elf.PF_X };
    image.segments[1] = .{ .phys_addr = 34 * 1024 * 1024, .mem_size = 2 * 1024 * 1024, .file_offset = 0, .file_size = 1, .flags = efi_elf.PF_R };
    image.segments[2] = .{ .phys_addr = 36 * 1024 * 1024, .mem_size = 4097, .file_offset = 0, .file_size = 1, .flags = efi_elf.PF_R | efi_elf.PF_W };
    return image;
}

test "EFI count and build share exact capacities and preserve clone and unused canaries" {
    const state = cache_policy.MtrrState{ .physical_bits = 40, .default_type = cache_policy.MTRR_ENABLED | 6 };
    const cache = try cache_policy.ValidatedMtrrView.init(&state);
    const entries = [_]efi_handoff.MmapEntry{.{ .base = 0, .length = 2 * sparse.HUGE_PAGE_BYTES, .kind = 1, .firmware_type = 7 }};
    const image = countFixtureImage();
    for ([_]Mode{ .native_high, .isolated_low_proof }) |mode| {
        var counts: sparse.Counts = undefined;
        try countForModeInto(mode, image, &entries, cache, 64 * 1024 * 1024, null, &counts);
        try std.testing.expect(counts.used_pages >= 3 and counts.used_pages < 64);
        try std.testing.expectEqual(@as(u64, if (mode == .native_high) 1 else 0), counts.leaf_1g);
        var tables: [64]sparse.Table align(PAGE_BYTES) = @splat(@splat(0xabab_abab_abab_abab));
        const pages: [*]align(PAGE_BYTES) std.os.uefi.Page = @ptrCast(&tables);
        var active: sparse.Table = undefined;
        for (&active, 0..) |*value, index| value.* = @as(u64, index) * PAGE_BYTES | 3;
        var receipt = efi_handoff.paging_info.Info{
            .transition_base = 0x100000,
            .transition_pages = @intCast(counts.used_pages),
            .final_base = 0x200000,
            .final_pages = @intCast(counts.used_pages),
        };
        receipt.transition_pages -= 1;
        try std.testing.expectError(error.ArenaCapacity, buildForMode(pages[0 .. counts.used_pages - 1], receipt.transition_base, &active, mode, image, &entries, cache, 64 * 1024 * 1024, receipt));
        for (tables) |page| try std.testing.expect(std.mem.allEqual(u64, &page, 0xabab_abab_abab_abab));
        receipt.transition_pages += 1;
        try std.testing.expectError(error.InvalidPhysicalRange, buildForMode(pages[0 .. counts.used_pages - 1], receipt.transition_base, &active, mode, image, &entries, cache, 64 * 1024 * 1024, receipt));
        try std.testing.expectError(error.InvalidPhysicalRange, buildForMode(pages[0..counts.used_pages], receipt.transition_base + PAGE_BYTES, &active, mode, image, &entries, cache, 64 * 1024 * 1024, receipt));
        for (tables) |page| try std.testing.expect(std.mem.allEqual(u64, &page, 0xabab_abab_abab_abab));
        try std.testing.expectEqual(receipt.transition_base, try buildForMode(pages[0..counts.used_pages], receipt.transition_base, &active, mode, image, &entries, cache, 64 * 1024 * 1024, receipt));
        for (active, 0..) |value, index| if (index != 256 and index != 511) try std.testing.expectEqual(value, tables[0][index]);
        for (tables[counts.used_pages..]) |page| try std.testing.expect(std.mem.allEqual(u64, &page, 0xabab_abab_abab_abab));
    }
}

test "EFI ELF transition planning equals final native geometry with merged immutable overlay and global leaves" {
    const state = cache_policy.MtrrState{ .physical_bits = 40, .default_type = cache_policy.MTRR_ENABLED | 6 };
    const cache = try cache_policy.ValidatedMtrrView.init(&state);
    const entries = [_]efi_handoff.MmapEntry{.{ .base = 0, .length = 2 * sparse.HUGE_PAGE_BYTES, .kind = 1, .firmware_type = 7 }};
    const image = countFixtureImage();
    var plan: Plan = undefined;
    try prepareInto(image, &entries, 64 * 1024 * 1024, null, &plan);
    var transition: sparse.Counts = undefined;
    try countForModeInto(.native_high, image, &entries, cache, 64 * 1024 * 1024, null, &transition);
    var final = plan.config(.native_high, cache);
    const overlays = [_]sparse.Region{
        .{ .start = 32 * 1024 * 1024, .end = 36 * 1024 * 1024, .permissions = .{ .writable = false } },
        .{ .start = 64 * 1024 * 1024, .end = 96 * 1024 * 1024, .permissions = .{ .force_4k = true } },
    };
    final.direct_overlays = &overlays;
    final.global = true;
    var final_counts: sparse.Counts = undefined;
    try sparse.countInto(final, &final_counts);
    try std.testing.expectEqualDeep(transition, final_counts);
}

test "EFI planning malformed extents preserve caller output and unallocated descriptors stay native" {
    const state = cache_policy.MtrrState{ .physical_bits = 40, .default_type = cache_policy.MTRR_ENABLED | 6 };
    const cache = try cache_policy.ValidatedMtrrView.init(&state);
    const entries = [_]efi_handoff.MmapEntry{.{ .base = 0, .length = sparse.HUGE_PAGE_BYTES, .kind = 1, .firmware_type = 7 }};
    const expected = sparse.Counts{ .used_pages = 71, .leaf_4k = 72, .leaf_2m = 73, .leaf_1g = 74 };
    var counts = expected;
    var image = countFixtureImage();
    image.segments[0].mem_size = std.math.maxInt(u64);
    try std.testing.expectError(error.AddressOverflow, countForModeInto(.native_high, image, &entries, cache, 64 * 1024 * 1024, null, &counts));
    try std.testing.expectEqualDeep(expected, counts);
    image = countFixtureImage();
    try std.testing.expectError(error.AddressOverflow, countForModeInto(.native_high, image, &entries, cache, std.math.maxInt(u64), null, &counts));
    try std.testing.expectEqualDeep(expected, counts);
    image.segment_count = efi_elf.MAX_LOAD_SEGMENTS + 1;
    try std.testing.expectError(error.InvalidPhysicalRange, countForModeInto(.native_high, image, &entries, cache, 64 * 1024 * 1024, null, &counts));
    try std.testing.expectEqualDeep(expected, counts);
    var descriptors: [1]efi_handoff.MmapEntry = undefined;
    var count: usize = 0;
    try appendMemoryDescriptor(&descriptors, &count, 0x100000, 0x800000, 1, 7, 8, null);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualDeep(efi_handoff.MmapEntry{ .base = 0x100000, .length = 0x800000, .kind = 1, .firmware_type = 7, .attributes = 8 }, descriptors[0]);
}
