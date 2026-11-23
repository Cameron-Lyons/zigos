const std = @import("std");
const x86 = @import("../../../arch/x86.zig");
const cache_policy = @import("../../../arch/cache_policy.zig");
const firmware_memory_map = @import("../firmware_memory_map.zig");
const table64 = @import("../page_table64.zig");
const virtual_layout = @import("../virtual_layout.zig");
const paging = @import("../paging64.zig");

// Pure admission proofs over the direct map: a backend supplies ownership and
// table reads, so the same walks run on live hierarchies and host models.

const PAGE_SIZE: u32 = virtual_layout.PAGE_BYTES;
const MANAGED_PHYSICAL_BYTES = paging.MANAGED_PHYSICAL_BYTES;
const LARGE_2M_PAGE_SIZE: u64 = 1 << table64.PAGE_DIRECTORY_SHIFT;
const PageTable = table64.Table;
const directMapAddress = paging.directMapAddress;
const tableIndex = table64.index;
const entryPresent = table64.isPresent;
const entryAddress = table64.address;
const ENTRY_PRESENT = table64.PRESENT;
const ENTRY_WRITABLE = table64.WRITABLE;
const ENTRY_USER = table64.USER;
const ENTRY_WRITE_THROUGH = table64.WRITE_THROUGH;
const ENTRY_CACHE_DISABLE = table64.CACHE_DISABLE;
const ENTRY_LARGE_PAGE = table64.LARGE_PAGE;
const PML4_SHIFT = table64.PML4_SHIFT;
const PDPT_SHIFT = table64.PDPT_SHIFT;
const PAGE_DIRECTORY_SHIFT = table64.PAGE_DIRECTORY_SHIFT;
const PAGE_TABLE_SHIFT = table64.PAGE_TABLE_SHIFT;

pub inline fn checkedUserRoot(backend: anytype, directory: usize, switch_cr3: usize) ?u64 {
    const physical = virtual_layout.directMappedPhysicalAddress(directory, MANAGED_PHYSICAL_BYTES) orelse return null;
    if (physical == 0 or physical % PAGE_SIZE != 0 or
        (switch_cr3 & ~(x86.CR3_ADDRESS_MASK | x86.CR3_PCID_MASK | x86.CR3_NO_FLUSH)) != 0 or
        (switch_cr3 & x86.CR3_ADDRESS_MASK) != physical or !backend.owns(physical)) return null;
    const alias = backend.writableAlias(physical) orelse return null;
    if (alias != directory) return null;
    return physical;
}

test "retained user root admission requires allocated backing and an exact writable WB alias" {
    const physical: u64 = 0x2000;
    const alias = directMapAddress(physical).?;
    const Backend = struct {
        allocated: bool = true,
        cached: bool = false,
        alias: ?usize,
        reads: usize = 0,

        pub fn owns(self: *@This(), value: u64) bool {
            return value == physical and self.allocated and !self.cached;
        }

        pub fn writableAlias(self: *@This(), value: u64) ?usize {
            self.reads += 1;
            return if (value == physical) self.alias else null;
        }
    };
    var backend = Backend{ .alias = alias };
    try std.testing.expectEqual(physical, checkedUserRoot(&backend, alias, physical).?);
    try std.testing.expectEqual(physical, checkedUserRoot(&backend, alias, physical | 17 | x86.CR3_NO_FLUSH).?);
    for ([_]struct { directory: usize, cr3: usize }{
        .{ .directory = 0, .cr3 = physical },
        .{ .directory = directMapAddress(0).?, .cr3 = 0 },
        .{ .directory = alias + 1, .cr3 = physical },
        .{ .directory = alias, .cr3 = physical + PAGE_SIZE },
        .{ .directory = alias, .cr3 = physical | (@as(usize, 1) << 62) },
    }) |invalid| {
        const before = backend.reads;
        try std.testing.expectEqual(@as(?u64, null), checkedUserRoot(&backend, invalid.directory, invalid.cr3));
        try std.testing.expectEqual(before, backend.reads);
    }
    backend.allocated = false;
    try std.testing.expectEqual(@as(?u64, null), checkedUserRoot(&backend, alias, physical));
    backend.allocated = true;
    backend.cached = true;
    try std.testing.expectEqual(@as(?u64, null), checkedUserRoot(&backend, alias, physical));
    backend.cached = false;
    backend.alias = null;
    try std.testing.expectEqual(@as(?u64, null), checkedUserRoot(&backend, alias, physical));
    backend.alias = alias + PAGE_SIZE;
    try std.testing.expectEqual(@as(?u64, null), checkedUserRoot(&backend, alias, physical));
}

// Spans are sorted, disjoint and half-open; adjacent spans with different
// write permissions remain separate. An empty range proves nothing.
pub fn spansCover(spans: []const firmware_memory_map.PhysicalSpan, start: u64, end: u64) bool {
    if (start >= end) return false;
    var low: usize = 0;
    var high = spans.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (spans[middle].start <= start) low = middle + 1 else high = middle;
    }
    if (low == 0) return false;
    var index = low - 1;
    var cursor = start;
    while (cursor < end) : (index += 1) {
        if (index == spans.len or spans[index].start > cursor or spans[index].end <= cursor) return false;
        cursor = spans[index].end;
    }
    return true;
}

test "direct RAM span admission requires complete coverage across adjacent spans only" {
    // Two adjacent spans, then a framebuffer-sized hole before the last span.
    const spans = [_]firmware_memory_map.PhysicalSpan{
        .{ .start = 0x10_0000, .end = 0x20_0000 },
        .{ .start = 0x20_0000, .end = 0x40_0000 },
        .{ .start = 0x8000_0000, .end = 0x9000_0000 },
    };
    for ([_]struct { start: u64, end: u64, covered: bool }{
        .{ .start = 0x10_0000, .end = 0x10_1000, .covered = true },
        .{ .start = 0x1F_F000, .end = 0x20_1000, .covered = true },
        .{ .start = 0x10_0000, .end = 0x40_0000, .covered = true },
        .{ .start = 0x8FFF_F000, .end = 0x9000_0000, .covered = true },
        .{ .start = 0x0F_F000, .end = 0x10_1000, .covered = false },
        .{ .start = 0x3F_F000, .end = 0x40_1000, .covered = false },
        .{ .start = 0x40_0000, .end = 0x40_1000, .covered = false },
        .{ .start = 0x3F_F000, .end = 0x8000_1000, .covered = false },
        .{ .start = 0x7FFF_F000, .end = 0x8000_1000, .covered = false },
        .{ .start = 0x8FFF_F000, .end = 0x9000_1000, .covered = false },
        .{ .start = 0x9000_0000, .end = 0x9000_1000, .covered = false },
        .{ .start = 0, .end = 0x1000, .covered = false },
        .{ .start = 0x10_0000, .end = 0x10_0000, .covered = false },
        .{ .start = 0x20_0000, .end = 0x10_0000, .covered = false },
    }) |case| try std.testing.expectEqual(case.covered, spansCover(&spans, case.start, case.end));
    try std.testing.expect(!spansCover(&.{}, 0x10_0000, 0x10_1000));
}

fn mappedRamSpanWith(backend: anytype, root: *const PageTable, physical: u64, bytes: u64, cache: cache_policy.ValidatedMtrrView) ?usize {
    return mappedRamSpanPermissionsWith(backend, root, physical, bytes, cache, false);
}

pub fn mappedRamSpanPermissionsWith(backend: anytype, root: *const PageTable, physical: u64, bytes: u64, cache: cache_policy.ValidatedMtrrView, write: bool) ?usize {
    const end = std.math.add(u64, physical, bytes) catch return null;
    if (bytes == 0 or end > MANAGED_PHYSICAL_BYTES) return null;
    cache.requireWriteBack(physical, bytes) catch return null;
    const alias = directMapAddress(physical) orelse return null;
    var cursor = physical;
    while (cursor < end) {
        const virtual = directMapAddress(cursor) orelse return null;
        var current = root;
        var found = false;
        for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT, PAGE_TABLE_SHIFT }, 0..) |shift, level| {
            const entry = current[tableIndex(virtual, shift)];
            if (!entryPresent(entry) or entry & ENTRY_USER != 0 or (write and entry & ENTRY_WRITABLE == 0)) return null;
            const large = level != 3 and table64.isLargePage(entry);
            if (large and level != 1 and level != 2) return null;
            if (large or level == 3) {
                const leaf_bytes: u64 = if (large) @as(u64, 1) << shift else PAGE_SIZE;
                const pat_bit: u64 = if (large) 1 << 12 else ENTRY_LARGE_PAGE;
                if (table64.isExecutable(entry) or entry & (ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE | pat_bit) != 0 or
                    entryAddress(entry) != (cursor & ~(leaf_bytes - 1))) return null;
                cursor = @min(end, (cursor & ~(leaf_bytes - 1)) + leaf_bytes);
                found = true;
                break;
            }
            if (entry & (ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE) != 0) return null;
            current = backend.table(entry) orelse return null;
        }
        if (!found) return null;
    }
    return alias;
}

test "sparse physical readers prove complete supervisor NX WB aliases before pointers" {
    const Model = struct {
        pdpt: PageTable = @splat(0),
        directory: PageTable = @splat(0),
        pages: PageTable = @splat(0),
        reads: usize = 0,

        pub fn table(self: *@This(), entry: u64) ?*const PageTable {
            self.reads += 1;
            return switch (entryAddress(entry)) {
                0x1000 => &self.pdpt,
                0x2000 => &self.directory,
                0x3000 => &self.pages,
                else => null,
            };
        }
    };
    const state: cache_policy.MtrrState = .{ .physical_bits = 36, .default_type = cache_policy.MTRR_ENABLED | 6 };
    const view = try cache_policy.ValidatedMtrrView.init(&state);
    var root: PageTable = @splat(0);
    root[256] = 0x1000 | ENTRY_PRESENT;
    var model = Model{};
    model.pdpt[0] = 0x2000 | ENTRY_PRESENT;
    model.directory[0] = 0x3000 | ENTRY_PRESENT;
    const valid = 0x5000 | ENTRY_PRESENT | table64.NO_EXECUTE;
    model.pages[5] = valid;
    try std.testing.expectEqual(directMapAddress(0x5000), mappedRamSpanWith(&model, &root, 0x5000, PAGE_SIZE, view));
    try std.testing.expect(mappedRamSpanPermissionsWith(&model, &root, 0x5000, PAGE_SIZE, view, true) == null);
    root[256] |= ENTRY_WRITABLE;
    model.pdpt[0] |= ENTRY_WRITABLE;
    model.directory[0] |= ENTRY_WRITABLE;
    model.pages[5] |= ENTRY_WRITABLE;
    try std.testing.expectEqual(directMapAddress(0x5000), mappedRamSpanPermissionsWith(&model, &root, 0x5000, PAGE_SIZE, view, true));
    for ([_]*u64{ &root[256], &model.pdpt[0], &model.directory[0], &model.pages[5] }) |entry| {
        entry.* &= ~ENTRY_WRITABLE;
        try std.testing.expect(mappedRamSpanPermissionsWith(&model, &root, 0x5000, PAGE_SIZE, view, true) == null);
        try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, PAGE_SIZE, view) != null);
        entry.* |= ENTRY_WRITABLE;
    }
    model.pages[5] = valid;
    try std.testing.expectEqual(directMapAddress(0x5fff), mappedRamSpanWith(&model, &root, 0x5fff, 1, view));
    try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5fff, 2, view) == null);
    for ([_]u64{ valid | ENTRY_USER, valid | ENTRY_WRITE_THROUGH, valid | ENTRY_CACHE_DISABLE, valid | ENTRY_LARGE_PAGE, valid & ~table64.NO_EXECUTE, valid & ~ENTRY_PRESENT, valid + PAGE_SIZE }) |invalid| {
        model.pages[5] = invalid;
        try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, 1, view) == null);
    }
    model.pages[5] = valid;
    root[256] |= ENTRY_USER;
    model.reads = 0;
    try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, 1, view) == null);
    try std.testing.expectEqual(@as(usize, 0), model.reads);
    root[256] &= ~ENTRY_USER;
    for ([_]u64{ ENTRY_WRITE_THROUGH, ENTRY_CACHE_DISABLE }) |selector| {
        root[256] |= selector;
        model.reads = 0;
        try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, 1, view) == null);
        try std.testing.expectEqual(@as(usize, 0), model.reads);
        root[256] &= ~selector;
    }
    model.directory[0] = ENTRY_PRESENT | ENTRY_LARGE_PAGE | table64.NO_EXECUTE;
    try std.testing.expectEqual(directMapAddress(0x5000), mappedRamSpanWith(&model, &root, 0x5000, PAGE_SIZE, view));
    model.pdpt[0] = ENTRY_PRESENT | ENTRY_LARGE_PAGE | table64.NO_EXECUTE;
    try std.testing.expectEqual(directMapAddress(0x5000), mappedRamSpanWith(&model, &root, 0x5000, LARGE_2M_PAGE_SIZE, view));
    // A requested WB/UC crossing is rejected before any hierarchy read.
    var mixed_state = state;
    mixed_state.capabilities = 1;
    mixed_state.variable[0] = .{ .base = 0x6000, .mask = (((@as(u64, 1) << 36) - 1) & ~@as(u64, PAGE_SIZE - 1)) | cache_policy.MTRR_VALID };
    const mixed = try cache_policy.ValidatedMtrrView.init(&mixed_state);
    model.reads = 0;
    try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5fff, 2, mixed) == null);
    try std.testing.expectEqual(@as(usize, 0), model.reads);
    for ([_]u64{ 0, std.math.maxInt(u64) }) |length| {
        try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, length, mixed) == null);
    }
}
