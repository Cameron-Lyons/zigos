const std = @import("std");

pub const TABLE_ENTRIES = 512;
pub const INDEX_MASK: usize = TABLE_ENTRIES - 1;
pub const PML4_SHIFT: u6 = 39;
pub const PDPT_SHIFT: u6 = 30;
pub const PAGE_DIRECTORY_SHIFT: u6 = 21;
pub const PAGE_TABLE_SHIFT: u6 = 12;

pub const PRESENT: u64 = 1 << 0;
pub const WRITABLE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const WRITE_THROUGH: u64 = 1 << 3;
pub const CACHE_DISABLE: u64 = 1 << 4;
pub const GLOBAL: u64 = 1 << 8;
pub const NO_EXECUTE: u64 = 1 << 63;

const OWNER_SHIFT = 9;
const OWNER_MASK: u64 = 0x7 << OWNER_SHIFT;
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PAGE_OFFSET_MASK: u64 = 0xFFF;

pub const Entry = u64;
pub const Table = [TABLE_ENTRIES]Entry;

pub fn index(virtual_address: usize, shift: u6) usize {
    return (virtual_address >> shift) & INDEX_MASK;
}

pub fn isCanonicalVirtualAddress(address_value: usize) bool {
    const upper = address_value >> 48;
    const sign_bit = (address_value >> 47) & 1;
    return if (sign_bit == 0) upper == 0 else upper == 0xFFFF;
}

pub fn physicalAddressFits(address_value: usize) bool {
    return (@as(u64, address_value) & ~(ADDRESS_MASK | PAGE_OFFSET_MASK)) == 0;
}

pub fn isPresent(entry: Entry) bool {
    return (entry & PRESENT) != 0;
}

pub fn owner(entry: Entry) u3 {
    return @truncate((entry & OWNER_MASK) >> OWNER_SHIFT);
}

pub fn address(entry: Entry) usize {
    return @intCast(entry & ADDRESS_MASK);
}

pub fn isExecutable(entry: Entry) bool {
    return isPresent(entry) and (entry & NO_EXECUTE) == 0;
}

pub fn withExecutePermission(entry: Entry, executable: bool) Entry {
    return if (executable) entry & ~NO_EXECUTE else entry | NO_EXECUTE;
}

pub fn make(physical_address: usize, flags: u64, entry_owner: u3) Entry {
    return (@as(u64, physical_address) & ADDRESS_MASK) |
        flags |
        (@as(u64, entry_owner) << OWNER_SHIFT);
}

test "four-level entry preserves address flags and software owner" {
    const entry = make(0x000A_BCDE_F123_4000, PRESENT | WRITABLE | USER | NO_EXECUTE, 5);
    try std.testing.expect(isPresent(entry));
    try std.testing.expectEqual(@as(usize, 0x000A_BCDE_F123_4000), address(entry));
    try std.testing.expectEqual(@as(u3, 5), owner(entry));
    try std.testing.expect((entry & WRITABLE) != 0);
    try std.testing.expect((entry & USER) != 0);
    try std.testing.expect(!isExecutable(entry));
}

test "execute permission is the inverse of the hardware NX bit" {
    const leaf = make(0x4000, PRESENT | USER, 1);
    try std.testing.expect(isExecutable(withExecutePermission(leaf, true)));
    try std.testing.expect(!isExecutable(withExecutePermission(leaf, false)));
    try std.testing.expect(!isExecutable(0));
}

test "each four-level index consumes exactly nine address bits" {
    try std.testing.expectEqual(@as(usize, 511), index(@as(usize, 511) << PAGE_TABLE_SHIFT, PAGE_TABLE_SHIFT));
    try std.testing.expectEqual(@as(usize, 511), index(@as(usize, 511) << PAGE_DIRECTORY_SHIFT, PAGE_DIRECTORY_SHIFT));
    try std.testing.expectEqual(@as(usize, 511), index(@as(usize, 511) << PDPT_SHIFT, PDPT_SHIFT));
    try std.testing.expectEqual(@as(usize, 511), index(@as(usize, 511) << PML4_SHIFT, PML4_SHIFT));
}

test "four-level addresses accept canonical kernel mappings and 52-bit physical frames" {
    try std.testing.expect(isCanonicalVirtualAddress(0x0000_7FFF_FFFF_F000));
    try std.testing.expect(isCanonicalVirtualAddress(0xFFFF_8000_0000_0000));
    try std.testing.expect(!isCanonicalVirtualAddress(0x0000_8000_0000_0000));
    try std.testing.expect(!isCanonicalVirtualAddress(0xFFFF_7FFF_FFFF_F000));
    try std.testing.expect(physicalAddressFits(0x000F_FFFF_FFFF_FFFF));
    try std.testing.expect(!physicalAddressFits(0x0010_0000_0000_0000));
}

comptime {
    if (@sizeOf(Entry) != 8) @compileError("x86-64 paging entries must be 8 bytes");
    if (@sizeOf(Table) != 4096) @compileError("x86-64 page tables must occupy one frame");
}
