const std = @import("std");
const mapper = @import("kernel_physical_mapper.zig");
const pt = @import("page_table64.zig");
const layout = @import("virtual_layout.zig");
const cache = @import("../../arch/cache_policy.zig");
const PAGE = 4096;
const GIB = 1 << 30;
const MIB2 = 1 << 21;
const WB = pt.PRESENT | pt.WRITABLE | pt.GLOBAL | pt.NO_EXECUTE;
const VA = layout.device_memory.base;

const Model = struct {
    directory: pt.Table = @splat(0),
    tables: [40]pt.Table = @splat(@splat(0)),
    used: u32 = 2,
    capacity: u32 = 40,
    physical_allowed: bool = true,
    transition_allowed: bool = true,
    begins: u32 = 0,
    cache_flushes: u32 = 0,
    tlb_flushes: u32 = 0,
    ends: u32 = 0,
    invalidations: u32 = 0,
    held: bool = false,
    valid_order: bool = true,
    expect_virtual: usize = VA,
    expect_physical: u64 = GIB - PAGE,
    expect_bytes: usize = 2 * PAGE,
    expect_kind: mapper.Kind = .device,

    fn init() Model {
        var self = Model{};
        self.directory[pt.index(layout.physical_memory.base, 39)] = pt.make(PAGE, pt.PRESENT | pt.WRITABLE, 0);
        self.tables[0][0] = pt.make(2 * PAGE, pt.PRESENT | pt.WRITABLE, 0);
        for (&self.tables[1], 0..) |*entry, i| entry.* = pt.make(i * MIB2, WB | pt.LARGE_PAGE | 0x60, 0);
        for (self.tables[0][1..], 1..) |*entry, i| entry.* = pt.make(i * GIB, WB | pt.LARGE_PAGE | 0x60, 0);
        return self;
    }

    pub fn root(self: *Model) *pt.Table {
        return &self.directory;
    }
    pub fn tableAt(self: *Model, physical_address: usize) *pt.Table {
        return &self.tables[physical_address / PAGE - 1];
    }
    pub fn table(self: *Model, entry: u64) ?*pt.Table {
        const physical_address = @import("page_table64.zig").address(entry);
        if (physical_address == 0 or physical_address % PAGE != 0 or physical_address / PAGE > self.used) return null;
        return self.tableAt(physical_address);
    }
    fn leaf(self: *Model, virtual: usize) ?struct { value: u64, shift: u6 } {
        var current = &self.directory;
        for ([_]u6{ 39, 30, 21, 12 }) |shift| {
            const value = current[@import("page_table64.zig").index(virtual, shift)];
            if (!@import("page_table64.zig").isPresent(value)) return null;
            if (shift == 12 or @import("page_table64.zig").isLargePage(value)) return .{ .value = value, .shift = shift };
            current = self.table(value) orelse return null;
        }
        unreachable;
    }
    fn physical(self: *Model, virtual: usize) ?usize {
        const entry = self.leaf(virtual) orelse return null;
        const mask = (@as(usize, 1) << entry.shift) - 1;
        return (@import("page_table64.zig").address(entry.value) & ~mask) | (virtual & mask);
    }
    pub fn validatePhysical(self: *Model, _: u64, _: usize, _: mapper.Kind) mapper.Error!void {
        if (!self.physical_allowed) return error.PhysicalOwnershipConflict;
    }
    pub fn validateTransition(self: *Model, _: bool) mapper.Error!void {
        if (!self.transition_allowed) return error.CacheTransitionUnavailable;
    }
    pub fn reserveTables(self: *Model, count: u32) ?mapper.Pool {
        if (self.held) self.valid_order = false;
        if (count > self.capacity - self.used) return null;
        const base = (@as(u64, self.used) + 1) * PAGE;
        self.used += count;
        return .{ .base = base, .count = count };
    }
    pub fn begin(self: *Model, _: bool) void {
        self.begins += 1;
        self.held = true;
    }
    pub fn flush(self: *Model, cache_changed: bool, translated_changed: bool) void {
        if (!self.held) self.valid_order = false;
        if (cache_changed) {
            self.cache_flushes += 1;
            var offset: usize = 0;
            while (offset < self.expect_bytes) : (offset += PAGE) {
                if (self.leaf(layout.physical_memory.base + @as(usize, @intCast(self.expect_physical)) + offset) != null or self.leaf(self.expect_virtual + offset) != null) self.valid_order = false;
            }
        } else if (translated_changed) self.tlb_flushes += 1;
    }
    pub fn invalidateLocal(self: *Model, _: usize) void {
        if (!self.held) self.valid_order = false;
        self.invalidations += 1;
    }
    pub fn end(self: *Model, _: bool) void {
        var offset: usize = 0;
        while (offset < self.expect_bytes) : (offset += PAGE) {
            const leaf_value = (self.leaf(self.expect_virtual + offset) orelse {
                self.valid_order = false;
                continue;
            }).value;
            if (self.physical(self.expect_virtual + offset) != self.expect_physical + offset or
                leaf_value & (pt.CACHE_DISABLE | pt.WRITE_THROUGH) != (if (self.expect_kind == .device) cache.UNCACHEABLE_SELECTOR else 0)) self.valid_order = false;
        }
        self.ends += 1;
        self.held = false;
    }
};

test "device transaction splits both huge geometries retires WB before UC and preserves neighbors" {
    var model = Model.init();
    const before_low = model.leaf(layout.physical_memory.base + GIB - MIB2).?.value;
    const before_high = model.leaf(layout.physical_memory.base + GIB + MIB2).?.value;
    try mapper.map(&model, VA, GIB - PAGE, 2 * PAGE, .device, true);
    try std.testing.expect(model.valid_order);
    try std.testing.expectEqual(@as(u32, 8), model.used); // Three splits plus three destination tables.
    try std.testing.expectEqual(@as(u32, 1), model.cache_flushes);
    try std.testing.expectEqual(@as(u32, 2), model.invalidations);
    try std.testing.expectEqual(@as(?usize, GIB - 2 * PAGE), model.physical(layout.physical_memory.base + GIB - 2 * PAGE));
    try std.testing.expectEqual(@as(?usize, GIB + PAGE), model.physical(layout.physical_memory.base + GIB + PAGE));
    try std.testing.expectEqual(before_low & ~@as(u64, pt.LARGE_PAGE), model.leaf(layout.physical_memory.base + GIB - MIB2).?.value);
    try std.testing.expectEqual(before_high, model.leaf(layout.physical_memory.base + GIB + MIB2).?.value & ~@as(u64, 0x000f_ffff_ffff_f000) | GIB);
    try std.testing.expectEqual(@as(u6, 21), model.leaf(layout.physical_memory.base + GIB + MIB2).?.shift);
}

test "scratch replacement clears translations once while fresh UC aliases and identical AD maps avoid remote work" {
    var model = Model.init();
    try mapper.map(&model, VA, GIB - PAGE, 2 * PAGE, .device, true);
    model.expect_physical = 2 * GIB - PAGE;
    try mapper.map(&model, VA, model.expect_physical, 2 * PAGE, .device, false);
    try std.testing.expect(model.valid_order);
    try std.testing.expectEqual(@as(u32, 2), model.cache_flushes);
    const old_used = model.used;
    const old_begins = model.begins;
    var current = &model.directory;
    for ([_]u6{ 39, 30, 21 }) |shift| current = model.table(current[pt.index(VA, shift)]).?;
    current[pt.index(VA, 12)] |= 0x60;
    const old_leaf = current[pt.index(VA, 12)];
    try mapper.map(&model, VA, model.expect_physical, 2 * PAGE, .device, false);
    try std.testing.expectEqual(old_leaf, current[pt.index(VA, 12)]);
    try std.testing.expectEqual(old_begins, model.begins);
    try std.testing.expectEqual(old_used, model.used);
    model.expect_virtual = VA + 4 * PAGE;
    try mapper.map(&model, model.expect_virtual, model.expect_physical, 2 * PAGE, .device, false);
    try std.testing.expectEqual(@as(u32, 2), model.cache_flushes);
    try std.testing.expectEqual(@as(u32, 0), model.tlb_flushes);
    model.expect_virtual = VA;
    try mapper.map(&model, VA, model.expect_physical, 2 * PAGE, .device, true);
    try std.testing.expectEqual(@as(u32, 1), model.tlb_flushes);
    try std.testing.expect(model.valid_order);
}

test "preflight errors including late destination collision and table exhaustion leave every byte untouched" {
    var model = Model.init();
    const original = model;
    model.physical_allowed = false;
    try std.testing.expectError(error.PhysicalOwnershipConflict, mapper.map(&model, VA, GIB - PAGE, 2 * PAGE, .device, true));
    model.physical_allowed = true;
    model.capacity = 7; // Needs six additional frames, only five remain.
    try std.testing.expectError(error.OutOfMemory, mapper.map(&model, VA, GIB - PAGE, 2 * PAGE, .device, true));
    model.capacity = 40;
    model.transition_allowed = false;
    try std.testing.expectError(error.CacheTransitionUnavailable, mapper.map(&model, VA, GIB - PAGE, 2 * PAGE, .device, true));
    model.transition_allowed = true;
    try std.testing.expectEqualSlices(u64, &original.directory, &model.directory);
    try std.testing.expectEqualDeep(original.tables, model.tables);
    try std.testing.expectEqual(original.used, model.used);
    try std.testing.expectEqual(@as(u32, 0), model.begins);
    try mapper.map(&model, VA, GIB - PAGE, 2 * PAGE, .device, true);
    var current = &model.directory;
    for ([_]u6{ 39, 30, 21 }) |shift| current = model.table(current[pt.index(VA, shift)]).?;
    current[pt.index(VA + PAGE, 12)] |= pt.USER;
    const collided = model;
    try std.testing.expectError(error.MappingCollision, mapper.map(&model, VA, 3 * GIB - PAGE, 2 * PAGE, .device, false));
    try std.testing.expectEqualDeep(collided, model);
}

test "whole huge device leaves retire without split and firmware WB remaps retain direct aliases" {
    var model = Model.init();
    model.expect_physical = GIB;
    model.expect_bytes = GIB;
    // A full destination needs 512 PTs; use a whole 2 MiB leaf instead.
    model.expect_physical = 4 * MIB2;
    model.expect_bytes = MIB2;
    try mapper.map(&model, VA, model.expect_physical, model.expect_bytes, .device, true);
    try std.testing.expectEqual(@as(u32, 5), model.used);
    try std.testing.expect(model.valid_order);
    var firmware = Model.init();
    firmware.expect_physical = 8 * MIB2;
    firmware.expect_kind = .firmware;
    const direct_before = firmware.tables;
    try mapper.map(&firmware, VA, firmware.expect_physical, 2 * PAGE, .firmware, false);
    try std.testing.expectEqualSlices(u64, &direct_before[0], &firmware.tables[0]);
    try std.testing.expectEqualSlices(u64, &direct_before[1], &firmware.tables[1]);
    try std.testing.expectEqual(@as(u32, 0), firmware.cache_flushes);
    firmware.expect_physical += 2 * PAGE;
    try mapper.map(&firmware, VA, firmware.expect_physical, 2 * PAGE, .firmware, false);
    try std.testing.expectEqual(@as(u32, 1), firmware.tlb_flushes);
    try std.testing.expect(firmware.valid_order);
}

test "hostile geometry direct leaf ownership and PAT selectors fail before reservation" {
    var model = Model.init();
    for ([_]struct { v: usize, p: u64, b: usize }{ .{ .v = VA + 1, .p = GIB, .b = PAGE }, .{ .v = VA, .p = GIB + 1, .b = PAGE }, .{ .v = VA, .p = GIB, .b = 0 }, .{ .v = VA, .p = GIB, .b = PAGE + 1 }, .{ .v = layout.native_stacks.base, .p = GIB, .b = PAGE }, .{ .v = VA, .p = 1 << 52, .b = PAGE } }) |range| {
        try std.testing.expectError(error.InvalidRange, mapper.map(&model, range.v, range.p, range.b, .device, true));
    }
    try std.testing.expectError(error.AddressOverflow, mapper.map(&model, VA, 0xffff_ffff_ffff_f000, 2 * PAGE, .device, true));
    for ([_]u64{ pt.USER, pt.CACHE_DISABLE, 1 << 12, @as(u64, 1) << 9 }) |bad| {
        model.tables[0][1] |= bad;
        try std.testing.expectError(error.InvalidDirectAlias, mapper.map(&model, VA, GIB, PAGE, .device, true));
        model.tables[0][1] &= ~bad;
    }
    try std.testing.expectEqual(@as(u32, 2), model.used);
    try std.testing.expectEqual(@as(u32, 0), model.begins);
}
