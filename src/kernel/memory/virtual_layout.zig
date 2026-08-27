const std = @import("std");
const table64 = @import("page_table64.zig");

pub const PAGE_BYTES: usize = 4096;
pub const PHYSICAL_WINDOW_CAPACITY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

pub const Region = struct {
    base: usize,
    bytes: usize,

    pub fn endExclusive(self: Region) ?usize {
        return std.math.add(usize, self.base, self.bytes) catch null;
    }

    pub fn contains(self: Region, address: usize) bool {
        const end = self.endExclusive() orelse return false;
        return address >= self.base and address < end;
    }
};

pub const physical_memory = Region{
    .base = 0xFFFF_8000_0000_0000,
    .bytes = @intCast(PHYSICAL_WINDOW_CAPACITY_BYTES),
};

pub const device_memory = Region{
    .base = 0xFFFF_C000_0000_0000,
    .bytes = 1024 * 1024 * 1024,
};

pub fn regionsDisjoint(first: Region, second: Region) bool {
    const first_end = first.endExclusive() orelse return false;
    const second_end = second.endExclusive() orelse return false;
    return first_end <= second.base or second_end <= first.base;
}

pub fn directMappedAddress(physical_address: u64, mapped_bytes: u64) ?usize {
    if (mapped_bytes > PHYSICAL_WINDOW_CAPACITY_BYTES or physical_address >= mapped_bytes) return null;
    const offset = std.math.cast(usize, physical_address) orelse return null;
    return std.math.add(usize, physical_memory.base, offset) catch null;
}

pub fn directMappedPhysicalAddress(virtual_address: usize, mapped_bytes: u64) ?u64 {
    if (mapped_bytes > PHYSICAL_WINDOW_CAPACITY_BYTES or virtual_address < physical_memory.base) return null;
    const offset = virtual_address - physical_memory.base;
    if (@as(u64, @intCast(offset)) >= mapped_bytes) return null;
    return @intCast(offset);
}

comptime {
    const physical_end = physical_memory.endExclusive() orelse
        @compileError("the physical-memory window must not overflow");
    const device_end = device_memory.endExclusive() orelse
        @compileError("the device-memory window must not overflow");
    if (!table64.isCanonicalVirtualAddress(physical_memory.base) or
        !table64.isCanonicalVirtualAddress(physical_end - 1) or
        !table64.isCanonicalVirtualAddress(device_memory.base) or
        !table64.isCanonicalVirtualAddress(device_end - 1))
    {
        @compileError("kernel virtual-memory windows must be canonical");
    }
    if (!regionsDisjoint(physical_memory, device_memory)) {
        @compileError("kernel virtual-memory windows must be disjoint");
    }
}

test "kernel virtual-memory windows are canonical and disjoint" {
    try std.testing.expect(regionsDisjoint(physical_memory, device_memory));
    try std.testing.expect(table64.isCanonicalVirtualAddress(physical_memory.base));
    try std.testing.expect(table64.isCanonicalVirtualAddress(physical_memory.endExclusive().? - 1));
    try std.testing.expect(table64.isCanonicalVirtualAddress(device_memory.base));
    try std.testing.expect(table64.isCanonicalVirtualAddress(device_memory.endExclusive().? - 1));
}

test "direct physical aliases are bounded and reversible" {
    const mapped_bytes: u64 = 8 * 1024 * 1024 * 1024;
    const high_physical: u64 = 0x1_0000_3000;
    const high_virtual = directMappedAddress(high_physical, mapped_bytes).?;

    try std.testing.expectEqual(physical_memory.base + high_physical, high_virtual);
    try std.testing.expectEqual(high_physical, directMappedPhysicalAddress(high_virtual, mapped_bytes).?);
    try std.testing.expect(directMappedAddress(mapped_bytes, mapped_bytes) == null);
    try std.testing.expect(directMappedPhysicalAddress(physical_memory.base + mapped_bytes, mapped_bytes) == null);
    try std.testing.expect(directMappedAddress(0, PHYSICAL_WINDOW_CAPACITY_BYTES + 1) == null);
}
