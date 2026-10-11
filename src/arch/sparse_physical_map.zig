const std = @import("std");
const cache_policy = @import("cache_policy.zig");
const kernel_address = @import("kernel_address.zig");

pub const PAGE_BYTES: u64 = 4096;
pub const LARGE_PAGE_BYTES: u64 = 2 * 1024 * 1024;
pub const HUGE_PAGE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_REGIONS: usize = 256;
pub const MAX_OVERLAYS: usize = 32;
pub const MAX_ARENA_PAGES: usize = 4096;
pub const Table = [512]u64;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const LARGE: u64 = 1 << 7;
const GLOBAL: u64 = 1 << 8;
const NX: u64 = 1 << 63;

pub const Permissions = struct {
    writable: bool = true,
    executable: bool = false,
    force_4k: bool = false,

    fn same(self: Permissions, other: Permissions) bool {
        return self.writable == other.writable and self.executable == other.executable and self.force_4k == other.force_4k;
    }
};

// Direct regions are RAM authority, not an assertion that their effective
// cache type is WB. The planner intersects them with the validated MTRRs.
// Partial pages are omitted unless adjacent authority with the same permission
// completes the page. Image and overlay extents require full aligned coverage.
pub const Region = struct { start: u64, end: u64, permissions: Permissions = .{} };
pub const Config = struct {
    cache: cache_policy.ValidatedMtrrView,
    image: []const Region,
    direct: []const Region,
    direct_overlays: []const Region = &.{},
    global: bool = false,
    allow_1g: bool = true,
    direct_limit: u64 = kernel_address.direct_map_capacity,
};
pub const Error = cache_policy.MtrrError || error{
    InvalidRegion,
    RegionOverlap,
    TooManyRegions,
    InvalidPermissions,
    PermissionConflict,
    PartialAuthorization,
    InvalidArena,
    ArenaReadOnly,
    ArenaCapacity,
    AliasedActiveRoot,
    AliasedInputs,
    AliasedOutput,
};
pub const Counts = struct {
    used_pages: usize,
    leaf_4k: u64,
    leaf_2m: u64,
    leaf_1g: u64,
};
pub const Result = struct { root_physical: u64, used_pages: usize };
pub const LeafRun = struct { start: u64, end: u64, leaf_bytes: u64, permissions: Permissions };
pub const Alias = enum { image, direct };

fn mappingLimit(config: *const Config) u64 {
    return @min(config.direct_limit, config.cache.physicalLimit());
}

fn validateRegions(regions: []const Region, limit: u64, aligned: bool, direct: bool) Error!void {
    if (regions.len > MAX_REGIONS) return error.TooManyRegions;
    var previous_end: u64 = 0;
    for (regions, 0..) |region, index| {
        if (region.start >= region.end or region.end > limit) return error.InvalidRegion;
        if (index != 0 and region.start < previous_end) return error.RegionOverlap;
        if (aligned and (region.start % PAGE_BYTES != 0 or region.end % PAGE_BYTES != 0)) return error.InvalidRegion;
        if (region.permissions.writable and region.permissions.executable or direct and region.permissions.executable)
            return error.InvalidPermissions;
        previous_end = region.end;
    }
}

fn requireAuthorization(regions: []const Region, start: u64, end: u64, writable: bool) Error!void {
    var cursor = start;
    for (regions) |region| {
        if (region.end <= cursor) continue;
        if (region.start > cursor) return error.PartialAuthorization;
        if (writable and !region.permissions.writable) return error.ArenaReadOnly;
        cursor = @min(end, region.end);
        if (cursor == end) return;
    }
    return error.PartialAuthorization;
}

fn validate(config: *const Config) Error!void {
    if (config.direct_limit == 0 or config.direct_limit % PAGE_BYTES != 0 or config.direct_limit > kernel_address.direct_map_capacity)
        return error.InvalidRegion;
    try validateRegions(config.direct, config.cache.physicalLimit(), false, true);
    try validateRegions(config.image, @min(kernel_address.image_physical_limit, config.cache.physicalLimit()), true, false);
    if (config.direct_overlays.len > MAX_OVERLAYS) return error.TooManyRegions;
    try validateRegions(config.direct_overlays, mappingLimit(config), true, true);
    for (config.image) |region| {
        try requireAuthorization(config.direct, region.start, region.end, region.permissions.writable);
        try config.cache.requireWriteBack(region.start, region.end - region.start);
        // An immutable image alias must not have a writable direct synonym.
        // This includes executable text and read-only non-executable data.
        if (!region.permissions.writable) try requireReadOnlyDirect(config, region.start, region.end);
    }
    for (config.direct_overlays) |region| {
        try requireAuthorization(config.direct, region.start, region.end, region.permissions.writable);
        try config.cache.requireWriteBack(region.start, region.end - region.start);
    }
}

fn requireReadOnlyDirect(config: *const Config, start: u64, end: u64) Error!void {
    var cursor = start;
    var region_index: usize = 0;
    var overlay_index: usize = 0;
    while (cursor < end) {
        while (config.direct[region_index].end <= cursor) region_index += 1;
        while (overlay_index < config.direct_overlays.len and config.direct_overlays[overlay_index].end <= cursor) overlay_index += 1;
        var boundary = @min(end, config.direct[region_index].end);
        var permissions = config.direct[region_index].permissions;
        if (overlay_index < config.direct_overlays.len) {
            const overlay = config.direct_overlays[overlay_index];
            if (overlay.start <= cursor) {
                permissions = overlay.permissions;
                boundary = @min(boundary, overlay.end);
            } else boundary = @min(boundary, overlay.start);
        }
        if (permissions.writable) return error.PermissionConflict;
        cursor = boundary;
    }
}

// Iteration cost follows RAM, permission and MTRR boundaries, never aperture
// pages. WB intervals are coalesced before page rounding, including artificial
// MTRR boundaries whose effective type stays WB.
const RegionIterator = struct {
    config: *const Config,
    alias: Alias,
    region_index: usize,
    overlay_index: usize,
    cursor: u64,
    pending: Region,
    has_pending: bool,

    fn rawInto(self: *RegionIterator, out: *Region) bool {
        if (self.alias == .image) {
            if (self.region_index == self.config.image.len) return false;
            out.* = self.config.image[self.region_index];
            self.region_index += 1;
            return true;
        }
        while (self.region_index < self.config.direct.len) {
            const region = &self.config.direct[self.region_index];
            self.cursor = @max(self.cursor, region.start);
            const limit = @min(region.end, mappingLimit(self.config));
            if (self.cursor >= limit) {
                self.region_index += 1;
                continue;
            }
            while (self.overlay_index < self.config.direct_overlays.len and self.config.direct_overlays[self.overlay_index].end <= self.cursor)
                self.overlay_index += 1;
            var end = limit;
            var permissions = region.permissions;
            if (self.overlay_index < self.config.direct_overlays.len) {
                const overlay = &self.config.direct_overlays[self.overlay_index];
                if (overlay.start <= self.cursor) {
                    permissions = overlay.permissions;
                    end = @min(end, overlay.end);
                } else end = @min(end, overlay.start);
            }
            var segment: cache_policy.ValidatedMtrrView.Segment = undefined;
            self.config.cache.queryInto(self.cursor, end, &segment) catch unreachable;
            end = segment.next_boundary;
            const start = self.cursor;
            self.cursor = end;
            if (segment.memory_type == .write_back) {
                out.* = .{ .start = start, .end = end, .permissions = permissions };
                return true;
            }
        }
        return false;
    }

    fn nextInto(self: *RegionIterator, out: *Region) bool {
        while (true) {
            var region: Region = undefined;
            if (self.has_pending) {
                region = self.pending;
                self.has_pending = false;
            } else if (!self.rawInto(&region)) return false;
            var following: Region = undefined;
            while (self.rawInto(&following)) {
                if (region.end == following.start and region.permissions.same(following.permissions)) {
                    region.end = following.end;
                } else {
                    self.pending = following;
                    self.has_pending = true;
                    break;
                }
            }
            region.start = (region.start + PAGE_BYTES - 1) & ~(PAGE_BYTES - 1);
            region.end &= ~(PAGE_BYTES - 1);
            if (region.start < region.end) {
                out.* = region;
                return true;
            }
        }
    }
};

pub const LeafRunIterator = struct {
    regions: RegionIterator,
    current: Region,
    has_current: bool,
    cursor: u64,

    // The config and its sources must remain alive and immutable throughout
    // iteration. Failed construction leaves the caller's iterator untouched.
    pub fn initInto(config: *const Config, alias: Alias, out: *LeafRunIterator) Error!void {
        try validate(config);
        out.resetValidated(config, alias);
    }

    fn resetValidated(self: *LeafRunIterator, config: *const Config, alias: Alias) void {
        self.regions.config = config;
        self.regions.alias = alias;
        self.regions.region_index = 0;
        self.regions.overlay_index = 0;
        self.regions.cursor = 0;
        self.regions.has_pending = false;
        self.has_current = false;
        self.cursor = 0;
    }

    // An exhausted iterator leaves the output unchanged.
    pub fn nextInto(self: *LeafRunIterator, out: *LeafRun) bool {
        if (!self.has_current or self.cursor == self.current.end) {
            if (!self.regions.nextInto(&self.current)) return false;
            self.has_current = true;
            self.cursor = self.current.start;
        }
        const region = &self.current;
        const start = self.cursor;
        const remaining = region.end - start;
        var bytes = PAGE_BYTES;
        var end = region.end;
        if (!region.permissions.force_4k) {
            if (self.regions.config.allow_1g and start % HUGE_PAGE_BYTES == 0 and remaining >= HUGE_PAGE_BYTES) {
                bytes = HUGE_PAGE_BYTES;
                end = start + remaining / bytes * bytes;
            } else if (start % LARGE_PAGE_BYTES == 0 and remaining >= LARGE_PAGE_BYTES) {
                bytes = LARGE_PAGE_BYTES;
                end = start + remaining / bytes * bytes;
                if (self.regions.config.allow_1g) end = @min(end, (start / HUGE_PAGE_BYTES + 1) * HUGE_PAGE_BYTES);
            } else end = @min(end, (start / LARGE_PAGE_BYTES + 1) * LARGE_PAGE_BYTES);
        }
        self.cursor = end;
        out.* = .{ .start = start, .end = end, .leaf_bytes = bytes, .permissions = region.permissions };
        return true;
    }
};

fn countBuckets(start: u64, end: u64, bucket_bytes: u64, previous: *?u64) usize {
    const first = start / bucket_bytes;
    const last = (end - 1) / bucket_bytes;
    const repeated: u64 = if (previous.* != null and previous.*.? == first) 1 else 0;
    previous.* = last;
    return @intCast(last - first + 1 - repeated);
}

pub fn countInto(config: Config, out: *Counts) Error!void {
    try validate(&config);
    var result: Counts = .{ .used_pages = 3, .leaf_4k = 0, .leaf_2m = 0, .leaf_1g = 0 };
    for ([_]Alias{ .image, .direct }) |alias| {
        var iterator: LeafRunIterator = undefined;
        iterator.resetValidated(&config, alias);
        var previous_directory: ?u64 = null;
        var previous_table: ?u64 = null;
        var run: LeafRun = undefined;
        while (iterator.nextInto(&run)) {
            const leaves = (run.end - run.start) / run.leaf_bytes;
            if (run.leaf_bytes == HUGE_PAGE_BYTES) {
                result.leaf_1g += leaves;
            } else {
                result.used_pages += countBuckets(run.start, run.end, HUGE_PAGE_BYTES, &previous_directory);
                if (run.leaf_bytes == LARGE_PAGE_BYTES) {
                    result.leaf_2m += leaves;
                } else {
                    result.leaf_4k += leaves;
                    result.used_pages += countBuckets(run.start, run.end, LARGE_PAGE_BYTES, &previous_table);
                }
            }
            if (result.used_pages > MAX_ARENA_PAGES) return error.ArenaCapacity;
        }
    }
    out.* = result;
}

const Builder = struct {
    pages: []align(4096) Table,
    physical_base: u64,
    used: usize = 3,
    global: bool,

    fn child(self: *Builder, parent: *Table, slot: usize) *Table {
        if (parent[slot] == 0) {
            parent[slot] = self.physical_base + self.used * PAGE_BYTES | PRESENT | WRITABLE;
            self.used += 1;
        }
        const index: usize = @intCast(((parent[slot] & ADDRESS_MASK) - self.physical_base) / PAGE_BYTES);
        return &self.pages[index];
    }

    fn emit(self: *Builder, alias: Alias, run: *const LeafRun) void {
        const bias: u64 = if (alias == .image) kernel_address.image_virtual_bias else kernel_address.direct_map_base;
        const pdpt = &self.pages[if (alias == .image) @as(usize, 1) else 2];
        var address = run.start;
        while (address < run.end) : (address += run.leaf_bytes) {
            const virtual = bias + address;
            var flags: u64 = PRESENT;
            if (run.permissions.writable) flags |= WRITABLE;
            if (!run.permissions.executable) flags |= NX;
            if (self.global) flags |= GLOBAL;
            const pdpt_index: usize = @intCast((virtual >> 30) & 511);
            if (run.leaf_bytes == HUGE_PAGE_BYTES) {
                pdpt[pdpt_index] = address | flags | LARGE;
            } else {
                const directory = self.child(pdpt, pdpt_index);
                const directory_index: usize = @intCast((virtual >> 21) & 511);
                if (run.leaf_bytes == LARGE_PAGE_BYTES) {
                    directory[directory_index] = address | flags | LARGE;
                } else {
                    const table = self.child(directory, directory_index);
                    table[@intCast((virtual >> 12) & 511)] = address | flags;
                }
            }
        }
    }
};

// All request, cache, authority, arena and capacity checks precede the first
// store. Inputs and the validated cache snapshot must remain immutable through
// both passes. Only used pages are touched; unused arena pages retain canaries.
// NXE must be enabled by the caller before this root is installed.
pub fn build(pages: []align(4096) Table, physical_base: u64, active_root: ?*const Table, config: Config, out: *Result) Error!void {
    if (pages.len == 0 or pages.len > MAX_ARENA_PAGES or physical_base < PAGE_BYTES or physical_base % PAGE_BYTES != 0)
        return error.InvalidArena;
    const arena_bytes = std.math.mul(u64, @intCast(pages.len), PAGE_BYTES) catch return error.InvalidArena;
    const arena_end = std.math.add(u64, physical_base, arena_bytes) catch return error.InvalidArena;
    const destination_start = @intFromPtr(pages.ptr);
    const destination_end = std.math.add(usize, destination_start, @intCast(arena_bytes)) catch return error.InvalidArena;
    // The second pass reads these sources after the arena is cleared. Reject
    // even overlap with its unused suffix so the arena retains sole ownership.
    for ([_][]const Region{ config.image, config.direct, config.direct_overlays }) |source| {
        const source_bytes = std.math.mul(usize, source.len, @sizeOf(Region)) catch return error.InvalidRegion;
        if (try overlaps(destination_start, destination_end, @intFromPtr(source.ptr), source_bytes)) return error.AliasedInputs;
    }
    if (try overlaps(destination_start, destination_end, @intFromPtr(config.cache.state), @sizeOf(cache_policy.MtrrState))) return error.AliasedInputs;
    if (try overlaps(destination_start, destination_end, @intFromPtr(out), @sizeOf(Result))) return error.AliasedOutput;
    if (active_root) |source| {
        if (try overlaps(destination_start, destination_end, @intFromPtr(source), @sizeOf(Table))) return error.AliasedActiveRoot;
    }
    var counts: Counts = undefined;
    try countInto(config, &counts);
    if (counts.used_pages > pages.len) return error.ArenaCapacity;
    if (arena_end > mappingLimit(&config)) return error.InvalidArena;
    try requireAuthorization(config.direct, physical_base, arena_end, true);
    try config.cache.requireWriteBack(physical_base, arena_bytes);
    for (config.direct_overlays) |overlay| {
        if (overlay.start < arena_end and overlay.end > physical_base and !overlay.permissions.writable) return error.ArenaReadOnly;
    }

    for (pages[0..counts.used_pages]) |*page| @memset(page, 0);
    if (active_root) |source| pages[0] = source.*;
    pages[0][511] = physical_base + PAGE_BYTES | PRESENT | WRITABLE;
    pages[0][256] = physical_base + 2 * PAGE_BYTES | PRESENT | WRITABLE;
    var builder: Builder = .{ .pages = pages, .physical_base = physical_base, .global = config.global };
    for ([_]Alias{ .image, .direct }) |alias| {
        var iterator: LeafRunIterator = undefined;
        iterator.resetValidated(&config, alias);
        var run: LeafRun = undefined;
        while (iterator.nextInto(&run)) builder.emit(alias, &run);
    }
    std.debug.assert(builder.used == counts.used_pages);
    out.* = .{ .root_physical = physical_base, .used_pages = builder.used };
}

fn overlaps(destination_start: usize, destination_end: usize, source_start: usize, source_bytes: usize) Error!bool {
    if (source_bytes == 0) return false;
    const source_end = std.math.add(usize, source_start, source_bytes) catch return error.InvalidArena;
    return source_start < destination_end and source_end > destination_start;
}

fn fixture() cache_policy.MtrrState {
    return .{ .physical_bits = 40, .default_type = cache_policy.MTRR_ENABLED | 6 };
}

fn variableFixture(start: u64, bytes: u64, memory_type: cache_policy.MemoryType) cache_policy.VariableMtrr {
    return .{ .base = start | @backingInt(memory_type), .mask = ((@as(u64, 1) << 40) - 1) & ~(bytes - 1) | cache_policy.MTRR_VALID };
}

fn testConfig(state: *const cache_policy.MtrrState, direct: []const Region) !Config {
    return .{ .cache = try cache_policy.ValidatedMtrrView.init(state), .image = &.{}, .direct = direct };
}

fn testLeaf(pages: []const Table, physical_base: u64, virtual: u64) ?struct { value: u64, bytes: u64 } {
    var table = &pages[0];
    for ([_]u6{ 39, 30, 21, 12 }) |shift| {
        const entry = table[@as(usize, @intCast((virtual >> shift) & 511))];
        if (entry & PRESENT == 0) return null;
        if (shift == 12) return .{ .value = entry, .bytes = PAGE_BYTES };
        if (entry & LARGE != 0) return .{ .value = entry, .bytes = @as(u64, 1) << shift };
        const index: usize = @intCast(((entry & ADDRESS_MASK) - physical_base) / PAGE_BYTES);
        table = &pages[index];
    }
    unreachable;
}

test "sparse full WB aperture counts huge leaves without page iteration" {
    const state = fixture();
    const regions = [_]Region{.{ .start = 0, .end = kernel_address.direct_map_capacity }};
    const config = try testConfig(&state, &regions);
    var counts: Counts = undefined;
    try countInto(config, &counts);
    try std.testing.expectEqual(Counts{ .used_pages = 3, .leaf_4k = 0, .leaf_2m = 0, .leaf_1g = 512 }, counts);
    var iterator: LeafRunIterator = undefined;
    try LeafRunIterator.initInto(&config, .direct, &iterator);
    var run: LeafRun = undefined;
    try std.testing.expect(iterator.nextInto(&run));
    try std.testing.expectEqual(@as(u64, HUGE_PAGE_BYTES), run.leaf_bytes);
    try std.testing.expectEqual(kernel_address.direct_map_capacity, run.end);
    const original = run;
    try std.testing.expect(!iterator.nextInto(&run));
    try std.testing.expect(!iterator.nextInto(&run));
    try std.testing.expectEqual(original, run);
}

test "sparse coalesces partial contiguous authority before inward page rounding" {
    const state = fixture();
    const regions = [_]Region{
        .{ .start = 1, .end = 2000 },
        .{ .start = 2000, .end = 8192 },
        .{ .start = 8193, .end = 12287 },
    };
    var config = try testConfig(&state, &regions);
    var iterator: LeafRunIterator = undefined;
    try LeafRunIterator.initInto(&config, .direct, &iterator);
    var run: LeafRun = undefined;
    try std.testing.expect(iterator.nextInto(&run));
    try std.testing.expectEqual(LeafRun{ .start = 4096, .end = 8192, .leaf_bytes = PAGE_BYTES, .permissions = .{} }, run);
    const original = run;
    try std.testing.expect(!iterator.nextInto(&run));
    try std.testing.expectEqual(original, run);
    const aligned = [_]Region{
        .{ .start = 0, .end = 123 },
        .{ .start = 123, .end = HUGE_PAGE_BYTES },
    };
    config = try testConfig(&state, &aligned);
    try LeafRunIterator.initInto(&config, .direct, &iterator);
    try std.testing.expect(iterator.nextInto(&run));
    try std.testing.expectEqual(HUGE_PAGE_BYTES, run.leaf_bytes);
}

test "sparse omits RAM gaps and non-WB cache boundaries before huge selection" {
    var state = fixture();
    state.capabilities = 1;
    state.variable[0] = variableFixture(HUGE_PAGE_BYTES + PAGE_BYTES, PAGE_BYTES, .uncacheable);
    const regions = [_]Region{
        .{ .start = 0, .end = 2 * HUGE_PAGE_BYTES },
        .{ .start = 3 * HUGE_PAGE_BYTES, .end = 4 * HUGE_PAGE_BYTES },
    };
    const config = try testConfig(&state, &regions);
    var iterator: LeafRunIterator = undefined;
    try LeafRunIterator.initInto(&config, .direct, &iterator);
    var run: LeafRun = undefined;
    try std.testing.expect(iterator.nextInto(&run));
    const first = run;
    try std.testing.expectEqual(HUGE_PAGE_BYTES, first.end);
    try std.testing.expectEqual(HUGE_PAGE_BYTES, first.leaf_bytes);
    try std.testing.expect(iterator.nextInto(&run));
    const before = run;
    try std.testing.expectEqual(HUGE_PAGE_BYTES, before.start);
    try std.testing.expectEqual(HUGE_PAGE_BYTES + PAGE_BYTES, before.end);
    try std.testing.expectEqual(PAGE_BYTES, before.leaf_bytes);
    try std.testing.expect(iterator.nextInto(&run));
    const after = run;
    try std.testing.expectEqual(HUGE_PAGE_BYTES + 2 * PAGE_BYTES, after.start);
    try std.testing.expectEqual(PAGE_BYTES, after.leaf_bytes);
    try std.testing.expect(iterator.nextInto(&run));
    const middle = run;
    try std.testing.expectEqual(HUGE_PAGE_BYTES + LARGE_PAGE_BYTES, middle.start);
    try std.testing.expectEqual(2 * HUGE_PAGE_BYTES, middle.end);
    try std.testing.expectEqual(LARGE_PAGE_BYTES, middle.leaf_bytes);
    try std.testing.expect(iterator.nextInto(&run));
    const last = run;
    try std.testing.expectEqual(3 * HUGE_PAGE_BYTES, last.start);
    try std.testing.expectEqual(HUGE_PAGE_BYTES, last.leaf_bytes);
    try std.testing.expect(!iterator.nextInto(&run));
    try std.testing.expectEqual(last, run);
}

test "sparse merges identical effective WB across fixed and variable boundaries" {
    var state = fixture();
    state.capabilities = cache_policy.MTRR_FIXED_SUPPORTED | 1;
    state.default_type |= cache_policy.MTRR_FIXED_ENABLED;
    state.fixed = @splat(0x0606_0606_0606_0606);
    state.variable[0] = variableFixture(2 * LARGE_PAGE_BYTES, LARGE_PAGE_BYTES, .write_back);
    const regions = [_]Region{.{ .start = 0, .end = HUGE_PAGE_BYTES }};
    const config = try testConfig(&state, &regions);
    var iterator: LeafRunIterator = undefined;
    try LeafRunIterator.initInto(&config, .direct, &iterator);
    var run: LeafRun = undefined;
    try std.testing.expect(iterator.nextInto(&run));
    try std.testing.expectEqual(HUGE_PAGE_BYTES, run.end);
    try std.testing.expectEqual(HUGE_PAGE_BYTES, run.leaf_bytes);
    const original = run;
    try std.testing.expect(!iterator.nextInto(&run));
    try std.testing.expectEqual(original, run);
}

test "sparse rejected iterator initialization preserves pending runs and output" {
    const state = fixture();
    const regions = [_]Region{
        .{ .start = 0, .end = PAGE_BYTES },
        .{ .start = PAGE_BYTES, .end = 2 * PAGE_BYTES, .permissions = .{ .writable = false } },
    };
    const config = try testConfig(&state, &regions);
    var iterator: LeafRunIterator = undefined;
    try LeafRunIterator.initInto(&config, .direct, &iterator);
    var run: LeafRun = undefined;
    try std.testing.expect(iterator.nextInto(&run));
    try std.testing.expectEqual(LeafRun{ .start = 0, .end = PAGE_BYTES, .leaf_bytes = PAGE_BYTES, .permissions = .{} }, run);

    const malformed = [_]Region{.{ .start = PAGE_BYTES, .end = PAGE_BYTES }};
    var invalid = config;
    invalid.direct = &malformed;
    try std.testing.expectError(error.InvalidRegion, LeafRunIterator.initInto(&invalid, .image, &iterator));
    try std.testing.expectEqual(&config, iterator.regions.config);
    try std.testing.expect(iterator.nextInto(&run));
    try std.testing.expectEqual(LeafRun{ .start = PAGE_BYTES, .end = 2 * PAGE_BYTES, .leaf_bytes = PAGE_BYTES, .permissions = .{ .writable = false } }, run);
    const original = run;
    try std.testing.expect(!iterator.nextInto(&run));
    try std.testing.expectEqual(original, run);
}

test "sparse permission boundaries force guardable pages and reject writable image synonyms" {
    const state = fixture();
    const direct = [_]Region{.{ .start = 0, .end = 2 * HUGE_PAGE_BYTES }};
    const image = [_]Region{.{ .start = 32 * LARGE_PAGE_BYTES, .end = 33 * LARGE_PAGE_BYTES, .permissions = .{ .writable = false, .executable = true } }};
    const overlays = [_]Region{
        .{ .start = 16 * LARGE_PAGE_BYTES, .end = 32 * LARGE_PAGE_BYTES, .permissions = .{ .force_4k = true } },
        .{ .start = image[0].start, .end = image[0].end, .permissions = .{ .writable = false } },
    };
    var config = try testConfig(&state, &direct);
    config.image = &image;
    var counts: Counts = undefined;
    try std.testing.expectError(error.PermissionConflict, countInto(config, &counts));
    config.direct_overlays = &overlays;
    try countInto(config, &counts);
    try std.testing.expectEqual(@as(u64, 8192), counts.leaf_4k);
    try std.testing.expectEqual(@as(u64, 1), counts.leaf_1g);
    try std.testing.expectEqual(@as(usize, 21), counts.used_pages); // 3 base, 2 PDs, 16 PTs.
    config.allow_1g = false;
    try countInto(config, &counts);
    try std.testing.expectEqual(@as(u64, 0), counts.leaf_1g);
    try std.testing.expectEqual(@as(usize, 22), counts.used_pages);
}

test "sparse validates malformed bounds overlaps authorization cache and permissions" {
    const state = fixture();
    const direct = [_]Region{.{ .start = 0, .end = HUGE_PAGE_BYTES }};
    var config = try testConfig(&state, &direct);
    var counts: Counts = .{ .used_pages = 77, .leaf_4k = 88, .leaf_2m = 99, .leaf_1g = 111 };
    const original = counts;
    const invalid = [_]Region{.{ .start = std.math.maxInt(u64), .end = 0 }};
    config.direct = &invalid;
    try std.testing.expectError(error.InvalidRegion, countInto(config, &counts));
    const overlap = [_]Region{ .{ .start = 4096, .end = 8192 }, .{ .start = 4096, .end = 12288 } };
    config.direct = &overlap;
    try std.testing.expectError(error.RegionOverlap, countInto(config, &counts));
    const writable_code = [_]Region{.{ .start = 0, .end = PAGE_BYTES, .permissions = .{ .executable = true } }};
    config.direct = &writable_code;
    try std.testing.expectError(error.InvalidPermissions, countInto(config, &counts));
    config.direct = &direct;
    const outside = [_]Region{.{ .start = HUGE_PAGE_BYTES, .end = HUGE_PAGE_BYTES + PAGE_BYTES }};
    config.direct_overlays = &outside;
    try std.testing.expectError(error.PartialAuthorization, countInto(config, &counts));
    const partial = [_]Region{.{ .start = 1, .end = PAGE_BYTES }};
    config.direct_overlays = &partial;
    try std.testing.expectError(error.InvalidRegion, countInto(config, &counts));
    config.direct_overlays = &.{};
    config.direct_limit = std.math.maxInt(u64);
    try std.testing.expectError(error.InvalidRegion, countInto(config, &counts));
    try std.testing.expectEqual(original, counts);

    var changed = state;
    changed.capabilities = 1;
    changed.variable[0] = variableFixture(0, PAGE_BYTES, .uncacheable);
    config = try testConfig(&changed, &direct);
    const required = [_]Region{.{ .start = 0, .end = PAGE_BYTES }};
    config.direct_overlays = &required;
    try std.testing.expectError(error.MemoryNotWriteBack, countInto(config, &counts));
    changed.capabilities = cache_policy.MTRR_WC_SUPPORTED | 2;
    changed.variable[0] = variableFixture(0, LARGE_PAGE_BYTES, .write_back);
    changed.variable[1] = variableFixture(0, LARGE_PAGE_BYTES, .write_combining);
    try std.testing.expectError(error.UndefinedMtrrOverlap, cache_policy.ValidatedMtrrView.init(&changed));
}

test "sparse count rejects bounded capacity before output mutation" {
    const state = fixture();
    const regions = [_]Region{.{ .start = 0, .end = kernel_address.direct_map_capacity, .permissions = .{ .force_4k = true } }};
    var counts: Counts = .{ .used_pages = 11, .leaf_4k = 22, .leaf_2m = 33, .leaf_1g = 44 };
    const original = counts;
    try std.testing.expectError(error.ArenaCapacity, countInto(try testConfig(&state, &regions), &counts));
    try std.testing.expectEqual(original, counts);
    const many: [MAX_REGIONS + 1]Region = @splat(.{ .start = 0, .end = PAGE_BYTES });
    try std.testing.expectError(error.TooManyRegions, countInto(try testConfig(&state, &many), &counts));
}

test "sparse writable overlays and image cannot promote read-only RAM authority" {
    const state = fixture();
    const readonly = [_]Region{.{ .start = 0, .end = HUGE_PAGE_BYTES, .permissions = .{ .writable = false } }};
    const writable = [_]Region{.{ .start = 0, .end = PAGE_BYTES }};
    var config = try testConfig(&state, &readonly);
    var counts: Counts = undefined;
    config.image = &writable;
    try std.testing.expectError(error.ArenaReadOnly, countInto(config, &counts));
    config.image = &.{};
    config.direct_overlays = &writable;
    try std.testing.expectError(error.ArenaReadOnly, countInto(config, &counts));
}

test "sparse builder emits matching WB W^X roots and preserves clone and unused pages" {
    const state = fixture();
    const direct = [_]Region{.{ .start = 0, .end = 2 * LARGE_PAGE_BYTES }};
    const image = [_]Region{.{ .start = LARGE_PAGE_BYTES, .end = LARGE_PAGE_BYTES + PAGE_BYTES, .permissions = .{ .writable = false, .executable = true } }};
    const overlays = [_]Region{
        .{ .start = 0, .end = LARGE_PAGE_BYTES, .permissions = .{ .force_4k = true } },
        .{ .start = image[0].start, .end = image[0].end, .permissions = .{ .writable = false, .force_4k = true } },
    };
    var config = try testConfig(&state, &direct);
    config.image = &image;
    config.direct_overlays = &overlays;
    config.global = true;
    var pages: [10]Table align(4096) = @splat(@splat(0xa5a5_a5a5_a5a5_a5a5));
    var clone: Table = undefined;
    for (&clone, 0..) |*entry, index| entry.* = @as(u64, index) * PAGE_BYTES | 3;
    var result: Result = undefined;
    try build(&pages, PAGE_BYTES, &clone, config, &result);
    try std.testing.expectEqual(Result{ .root_physical = PAGE_BYTES, .used_pages = 8 }, result);
    for (clone, 0..) |entry, index| {
        if (index != 256 and index != 511) try std.testing.expectEqual(entry, pages[0][index]);
    }
    for (pages[result.used_pages..]) |page| try std.testing.expect(std.mem.allEqual(u64, &page, 0xa5a5_a5a5_a5a5_a5a5));
    const code = testLeaf(&pages, PAGE_BYTES, kernel_address.image_virtual_bias + image[0].start).?;
    try std.testing.expectEqual(PAGE_BYTES, code.bytes);
    try std.testing.expectEqual(image[0].start | PRESENT | GLOBAL, code.value);
    const synonym = testLeaf(&pages, PAGE_BYTES, kernel_address.direct_map_base + image[0].start).?;
    try std.testing.expectEqual(image[0].start | PRESENT | GLOBAL | NX, synonym.value);
    const heap = testLeaf(&pages, PAGE_BYTES, kernel_address.direct_map_base + PAGE_BYTES).?;
    try std.testing.expectEqual(PAGE_BYTES | PRESENT | WRITABLE | GLOBAL | NX, heap.value);
    try std.testing.expectEqual(@as(?@TypeOf(code), null), testLeaf(&pages, PAGE_BYTES, kernel_address.direct_map_base + 2 * LARGE_PAGE_BYTES));
    try build(&pages, PAGE_BYTES, null, config, &result);
    try std.testing.expect(std.mem.allEqual(u64, pages[0][0..256], 0));
    try std.testing.expect(std.mem.allEqual(u64, pages[0][257..511], 0));
}

test "sparse builder admission and capacity reject without changing any arena or result" {
    const state = fixture();
    const direct = [_]Region{.{ .start = 0, .end = LARGE_PAGE_BYTES, .permissions = .{ .force_4k = true } }};
    const config = try testConfig(&state, &direct);
    var pages: [6]Table align(4096) = @splat(@splat(0x7171_7171_7171_7171));
    var result: Result = .{ .root_physical = 0xfeed, .used_pages = 91 };
    const original = result;
    try std.testing.expectError(error.ArenaCapacity, build(pages[0..4], PAGE_BYTES, null, config, &result));
    try std.testing.expectError(error.InvalidArena, build(&pages, 1, null, config, &result));
    try std.testing.expectError(error.PartialAuthorization, build(&pages, 2 * LARGE_PAGE_BYTES, null, config, &result));
    try std.testing.expectError(error.AliasedActiveRoot, build(&pages, PAGE_BYTES, &pages[5], config, &result));
    for (pages) |page| try std.testing.expect(std.mem.allEqual(u64, &page, 0x7171_7171_7171_7171));
    try std.testing.expectEqual(original, result);
    const readonly = [_]Region{.{ .start = 0, .end = LARGE_PAGE_BYTES, .permissions = .{ .writable = false } }};
    try std.testing.expectError(error.ArenaReadOnly, build(&pages, PAGE_BYTES, null, try testConfig(&state, &readonly), &result));
    var changed = state;
    changed.capabilities = 1;
    changed.variable[0] = variableFixture(PAGE_BYTES, PAGE_BYTES, .uncacheable);
    try std.testing.expectError(error.MixedMemoryTypes, build(&pages, PAGE_BYTES, null, try testConfig(&changed, &direct), &result));
    for (pages) |page| try std.testing.expect(std.mem.allEqual(u64, &page, 0x7171_7171_7171_7171));
}

test "sparse builder rejects every aliased source and output before any arena store" {
    const state = fixture();
    const direct = [_]Region{.{ .start = 0, .end = LARGE_PAGE_BYTES }};
    const Kind = enum { image, direct, overlay, cache, output };
    for ([_]Kind{ .image, .direct, .overlay, .cache, .output }) |kind| {
        var pages: [10]Table align(4096) = @splat(@splat(0x7373_7373_7373_7373));
        var config = try testConfig(&state, &direct);
        var result: Result = .{ .root_physical = 0xface, .used_pages = 17 };
        var output = &result;
        // The unused suffix is still arena-owned. Each source is valid before
        // build, so rejection cannot depend on malformed-input validation.
        const region: *[1]Region = @ptrCast(&pages[9]);
        switch (kind) {
            .image => {
                region[0] = .{ .start = 0, .end = PAGE_BYTES };
                config.image = region;
            },
            .direct => {
                region[0] = direct[0];
                config.direct = region;
            },
            .overlay => {
                region[0] = .{ .start = 0, .end = PAGE_BYTES };
                config.direct_overlays = region;
            },
            .cache => {
                const aliased_state: *cache_policy.MtrrState = @ptrCast(&pages[9]);
                aliased_state.* = state;
                config.cache = try cache_policy.ValidatedMtrrView.init(aliased_state);
            },
            .output => output = @ptrCast(&pages[9]),
        }
        const original = pages;
        const original_result = result;
        const expected = if (kind == .output) error.AliasedOutput else error.AliasedInputs;
        try std.testing.expectError(expected, build(&pages, PAGE_BYTES, null, config, output));
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&original), std.mem.asBytes(&pages));
        try std.testing.expectEqual(original_result, result);
    }

    // An input can begin inside the arena and extend into disjoint backing.
    // Check complete source extents rather than only their starting pointer.
    var backing: [11]Table align(4096) = @splat(@splat(0x4141_4141_4141_4141));
    const straddling_state: *cache_policy.MtrrState = @ptrCast(&backing[9][511]);
    straddling_state.* = state;
    var config = try testConfig(&state, &direct);
    config.cache = try cache_policy.ValidatedMtrrView.init(straddling_state);
    const original = backing;
    var result: Result = .{ .root_physical = 0xbeef, .used_pages = 31 };
    try std.testing.expectError(error.AliasedInputs, build(backing[0..10], PAGE_BYTES, null, config, &result));
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&original), std.mem.asBytes(&backing));
    try std.testing.expectEqual(Result{ .root_physical = 0xbeef, .used_pages = 31 }, result);
    try std.testing.expect(try overlaps(100, 200, 50, 60));
    try std.testing.expect(!try overlaps(100, 200, 50, 50));
    try std.testing.expect(!try overlaps(100, 200, 200, 10));
    try std.testing.expectError(error.InvalidArena, overlaps(100, 200, std.math.maxInt(usize), 1));
}

fn countEmitted(pages: []const Table, physical_base: u64, table: *const Table, shift: u6, out: *Counts) void {
    for (table) |entry| {
        if (entry & PRESENT == 0) continue;
        if (shift == 12) {
            out.leaf_4k += 1;
        } else if (entry & LARGE != 0) {
            if (shift == 30) out.leaf_1g += 1 else out.leaf_2m += 1;
        } else {
            out.used_pages += 1;
            const index: usize = @intCast(((entry & ADDRESS_MASK) - physical_base) / PAGE_BYTES);
            countEmitted(pages, physical_base, &pages[index], shift - 9, out);
        }
    }
}

test "sparse count and actual tables agree across adversarial cache permission and RAM edges" {
    for (0..33) |iteration| {
        const offset: u64 = @as(u64, @intCast(iteration)) * PAGE_BYTES;
        var state = fixture();
        state.capabilities = 1;
        const uncached = 4 * LARGE_PAGE_BYTES + offset;
        state.variable[0] = variableFixture(uncached, PAGE_BYTES, .uncacheable);
        const direct = [_]Region{
            .{ .start = 0, .end = HUGE_PAGE_BYTES - offset },
            .{ .start = HUGE_PAGE_BYTES + offset, .end = 2 * HUGE_PAGE_BYTES },
        };
        const image = [_]Region{.{ .start = LARGE_PAGE_BYTES, .end = LARGE_PAGE_BYTES + PAGE_BYTES, .permissions = .{ .writable = false, .executable = true } }};
        const overlays = [_]Region{
            .{ .start = 0, .end = 16 * PAGE_BYTES, .permissions = .{ .force_4k = true } },
            .{ .start = image[0].start, .end = image[0].end, .permissions = .{ .writable = false } },
        };
        var config = try testConfig(&state, &direct);
        config.image = &image;
        config.direct_overlays = &overlays;
        config.allow_1g = iteration % 2 == 0;
        config.global = iteration % 3 == 0;
        var expected: Counts = undefined;
        try countInto(config, &expected);
        var pages: [32]Table align(4096) = @splat(@splat(0xaabb_ccdd_eeff_0011));
        var result: Result = undefined;
        try build(&pages, PAGE_BYTES, null, config, &result);
        var emitted: Counts = .{ .used_pages = 3, .leaf_4k = 0, .leaf_2m = 0, .leaf_1g = 0 };
        countEmitted(&pages, PAGE_BYTES, &pages[1], 30, &emitted);
        countEmitted(&pages, PAGE_BYTES, &pages[2], 30, &emitted);
        try std.testing.expectEqual(expected, emitted);
        try std.testing.expectEqual(expected.used_pages, result.used_pages);
        for (pages[result.used_pages..]) |page| try std.testing.expect(std.mem.allEqual(u64, &page, 0xaabb_ccdd_eeff_0011));
        try std.testing.expect(testLeaf(&pages, PAGE_BYTES, kernel_address.direct_map_base + uncached) == null);
        if (offset != 0) {
            try std.testing.expect(testLeaf(&pages, PAGE_BYTES, kernel_address.direct_map_base + HUGE_PAGE_BYTES - PAGE_BYTES) == null);
            try std.testing.expect(testLeaf(&pages, PAGE_BYTES, kernel_address.direct_map_base + HUGE_PAGE_BYTES) == null);
        }
        const readonly = testLeaf(&pages, PAGE_BYTES, kernel_address.direct_map_base + image[0].start).?.value;
        try std.testing.expect(readonly & WRITABLE == 0 and readonly & NX != 0);
    }
}
