const std = @import("std");
const table = @import("page_table64.zig");
const layout = @import("virtual_layout.zig");
const cache = @import("../../arch/cache_policy.zig");

pub const Kind = enum { device, firmware };
pub const Error = error{
    WrongCpu,
    InterruptContext,
    WrongAddressSpace,
    Unavailable,
    InvalidRange,
    AddressOverflow,
    PhysicalOwnershipConflict,
    MappingCollision,
    InvalidDirectAlias,
    OutOfMemory,
    CacheTransitionUnavailable,
};

const PAGE: usize = layout.PAGE_BYTES;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const HARDWARE_BITS: u64 = (1 << 5) | (1 << 6);
const CACHE_BITS: u64 = table.WRITE_THROUGH | table.CACHE_DISABLE | table.LARGE_PAGE;
const BORROWED: u3 = 0;
const DYNAMIC: u3 = 1;

comptime {
    if ((layout.device_memory.base >> 30) != ((layout.device_memory.endExclusive().? - 1) >> 30))
        @compileError("the physical mapper requires one bounded device PDPT slot");
}

pub const Pool = struct { base: u64 = 0, count: u32 = 0, used: u32 = 0 };

const Leaf = struct { entry: *u64, shift: u6 };

inline fn walk(backend: anytype, address: usize, destination: bool) Error!Leaf {
    var current = backend.root();
    for ([_]u6{ 39, 30, 21, 12 }) |shift| {
        const entry = &current[table.index(address, shift)];
        if (!table.isPresent(entry.*) or shift == 12 or table.isLargePage(entry.*))
            return .{ .entry = entry, .shift = shift };
        if ((entry.* & table.USER) != 0 or table.owner(entry.*) > DYNAMIC or
            (destination and entry.* & table.WRITABLE == 0) or
            (entry.* & (table.WRITE_THROUGH | table.CACHE_DISABLE)) != 0)
            return error.MappingCollision;
        current = backend.table(entry.*) orelse return error.MappingCollision;
    }
    unreachable;
}

inline fn extentEnd(address: u64, shift: u6, limit: u64) u64 {
    const bytes = @as(u64, 1) << shift;
    return @min((address & ~(bytes - 1)) + bytes, limit);
}

inline fn flags(kind: Kind, writable: bool) u64 {
    return table.PRESENT | table.GLOBAL | table.NO_EXECUTE |
        (if (kind == .device) cache.UNCACHEABLE_SELECTOR else cache.WRITE_BACK_SELECTOR) |
        (if (writable) table.WRITABLE else 0);
}

inline fn same(old: u64, replacement: u64) bool {
    return (old & ~HARDWARE_BITS) == (replacement & ~HARDWARE_BITS);
}

inline fn validateDestination(old: u64, kind: Kind) Error!void {
    if (old == 0) return;
    if (!table.isPresent(old) or table.owner(old) != BORROWED or
        (old & (table.USER | table.NO_EXECUTE | table.GLOBAL)) != (table.NO_EXECUTE | table.GLOBAL) or
        (old & CACHE_BITS) != (if (kind == .device) cache.UNCACHEABLE_SELECTOR else cache.WRITE_BACK_SELECTOR) or
        (kind == .firmware and old & table.WRITABLE != 0)) return error.MappingCollision;
}

inline fn countDestination(backend: anytype, virtual: usize, physical: u64, bytes: usize, kind: Kind, writable: bool, changed: *bool, translated_changed: *bool) Error!u32 {
    var count: u32 = 0;
    const end = virtual + bytes;
    var address = virtual;
    while (address < end) {
        const leaf = try walk(backend, address, true);
        if (leaf.shift != 12) {
            if (leaf.entry.* != 0) return error.MappingCollision;
            const chunk_end: usize = @intCast(extentEnd(address, leaf.shift, end));
            // The destination is bounded to one 1 GiB device-window PDPT slot.
            const first_pt = address >> 21;
            const last_pt = (chunk_end - 1) >> 21;
            count += @as(u32, @intCast(last_pt - first_pt + 1)) + @as(u32, if (leaf.shift == 39) 2 else if (leaf.shift == 30) 1 else 0);
            changed.* = true;
            address = chunk_end;
            continue;
        }
        try validateDestination(leaf.entry.*, kind);
        if (!same(leaf.entry.*, table.make(@intCast(physical + address - virtual), flags(kind, writable), BORROWED))) {
            changed.* = true;
            translated_changed.* = translated_changed.* or table.isPresent(leaf.entry.*);
        }
        address += PAGE;
    }
    return count;
}

inline fn validateDirect(leaf: Leaf, physical: u64) Error!void {
    const old = leaf.entry.*;
    if (old == 0) return;
    const size = @as(u64, 1) << leaf.shift;
    const pat_bit: u64 = if (leaf.shift == 12) table.LARGE_PAGE else 1 << 12;
    if (!table.isPresent(old) or leaf.shift == 39 or table.owner(old) != BORROWED or
        (old & (table.USER | table.GLOBAL | table.NO_EXECUTE)) != (table.GLOBAL | table.NO_EXECUTE) or
        (old & (table.WRITE_THROUGH | table.CACHE_DISABLE | pat_bit)) != 0 or
        (table.address(old) & ~(size - 1)) != (physical & ~(size - 1))) return error.InvalidDirectAlias;
}

inline fn countDirect(backend: anytype, physical: u64, end: u64, changed: *bool) Error!u32 {
    var count: u32 = 0;
    var address = physical;
    const limit = @min(end, @as(u64, layout.physical_memory.bytes));
    while (address < limit) {
        const leaf = try walk(backend, layout.physical_memory.base + @as(usize, @intCast(address)), false);
        try validateDirect(leaf, address);
        const chunk_end = extentEnd(address, leaf.shift, limit);
        if (leaf.entry.* != 0) {
            changed.* = true;
            const size = @as(u64, 1) << leaf.shift;
            if (leaf.shift > 12 and (address % size != 0 or chunk_end - address != size)) {
                count += 1;
                if (leaf.shift == 30) {
                    var child = address;
                    while (child < chunk_end) {
                        const child_end = extentEnd(child, 21, chunk_end);
                        if (child % (1 << 21) != 0 or child_end - child != 1 << 21) count += 1;
                        child = child_end;
                    }
                }
            }
        }
        address = chunk_end;
    }
    return count;
}

inline fn newTable(backend: anytype, pool: *Pool) struct { pointer: *table.Table, physical: usize } {
    std.debug.assert(pool.used < pool.count);
    const physical: usize = @intCast(pool.base + @as(u64, pool.used) * PAGE);
    pool.used += 1;
    const pointer = backend.tableAt(physical);
    @memset(pointer, 0);
    return .{ .pointer = pointer, .physical = physical };
}

inline fn splitDirect(backend: anytype, pool: *Pool, leaf: Leaf) void {
    const old = leaf.entry.*;
    const lower_shift: u6 = leaf.shift - 9;
    const size = @as(usize, 1) << lower_shift;
    const base = table.address(old) & ~((@as(usize, 1) << leaf.shift) - 1);
    const child = newTable(backend, pool);
    const child_flags = (old & ~ADDRESS_MASK) & ~(if (lower_shift == 12) table.LARGE_PAGE else @as(u64, 0));
    for (child.pointer, 0..) |*entry, index| entry.* = table.make(base + index * size, child_flags, BORROWED);
    const parent_flags = table.PRESENT | (old & (table.WRITABLE | table.NO_EXECUTE));
    @atomicStore(u64, leaf.entry, table.make(child.physical, parent_flags, DYNAMIC), .release);
}

inline fn detachDirect(backend: anytype, pool: *Pool, physical: u64, end: u64) void {
    var address = physical;
    const limit = @min(end, @as(u64, layout.physical_memory.bytes));
    while (address < limit) {
        const leaf = walk(backend, layout.physical_memory.base + @as(usize, @intCast(address)), false) catch unreachable;
        const chunk_end = extentEnd(address, leaf.shift, limit);
        if (leaf.entry.* != 0) {
            const size = @as(u64, 1) << leaf.shift;
            if (leaf.shift > 12 and (address % size != 0 or chunk_end - address != size)) {
                splitDirect(backend, pool, leaf);
                continue;
            }
            @atomicStore(u64, leaf.entry, 0, .release);
        }
        address = chunk_end;
    }
}

inline fn destinationTable(backend: anytype, pool: *Pool, virtual: usize) *table.Table {
    var current = backend.root();
    for ([_]u6{ 39, 30, 21 }) |shift| {
        const entry = &current[table.index(virtual, shift)];
        if (entry.* == 0) {
            const child = newTable(backend, pool);
            @atomicStore(u64, entry, table.make(child.physical, table.PRESENT | table.WRITABLE, DYNAMIC), .release);
            current = child.pointer;
        } else current = backend.table(entry.*) orelse unreachable;
    }
    return current;
}

// A single writer owns the kernel hierarchy. Preflight and one all-or-nothing
// table reservation precede every mutation; commit has no fallible operation.
// The backend's cache transition holds other CPUs until detached WB aliases
// have been flushed and fresh UC leaves are published.
pub fn map(backend: anytype, virtual: usize, physical: u64, bytes: usize, kind: Kind, writable: bool) Error!void {
    if (virtual % PAGE != 0 or physical % PAGE != 0 or physical == 0 or bytes == 0 or bytes % PAGE != 0 or
        (kind == .firmware and writable)) return error.InvalidRange;
    const virtual_end = std.math.add(usize, virtual, bytes) catch return error.AddressOverflow;
    const physical_end = std.math.add(u64, physical, bytes) catch return error.AddressOverflow;
    if (virtual < layout.device_memory.base or virtual_end > layout.device_memory.endExclusive().? or
        !table.physicalAddressFits(@intCast(physical_end - 1))) return error.InvalidRange;
    try backend.validatePhysical(physical, bytes, kind);
    var changed = false;
    var translated_changed = false;
    const destination_tables = try countDestination(backend, virtual, physical, bytes, kind, writable, &changed, &translated_changed);
    var cache_changed = false;
    const direct_tables = if (kind == .device) try countDirect(backend, physical, physical_end, &cache_changed) else 0;
    if (!changed and !cache_changed) return;
    try backend.validateTransition(cache_changed);
    const count = destination_tables + direct_tables;
    var pool = if (count == 0) Pool{} else backend.reserveTables(count) orelse return error.OutOfMemory;
    backend.begin(cache_changed);
    if (cache_changed) detachDirect(backend, &pool, physical, physical_end);
    // Detach only changed destination leaves. Identical leaves retain A/D.
    var address = virtual;
    while (address < virtual_end) {
        const leaf = walk(backend, address, true) catch unreachable;
        if (leaf.shift == 12) {
            const replacement = table.make(@intCast(physical + address - virtual), flags(kind, writable), BORROWED);
            if (!same(leaf.entry.*, replacement)) @atomicStore(u64, leaf.entry, 0, .release);
        }
        address = @intCast(extentEnd(address, leaf.shift, virtual_end));
    }
    backend.flush(cache_changed, translated_changed);
    address = virtual;
    while (address < virtual_end) : (address += PAGE) {
        const destination = destinationTable(backend, &pool, address);
        const entry = &destination[table.index(address, 12)];
        if (entry.* == 0) @atomicStore(u64, entry, table.make(@intCast(physical + address - virtual), flags(kind, writable), BORROWED), .release);
        backend.invalidateLocal(address);
    }
    std.debug.assert(pool.used == pool.count);
    backend.end(cache_changed);
}

test {
    _ = @import("kernel_physical_mapper_test.zig");
}
