const std = @import("std");

// The ELF image occupies the signed top 2 GiB code-model window; physical
// allocations and firmware handoff fields always retain their physical values.
pub const image_virtual_bias: usize = 0xffff_ffff_8000_0000;
pub const image_physical_limit: u64 = 1024 * 1024 * 1024;
pub const direct_map_base: usize = 0xffff_8000_0000_0000;
pub const direct_map_capacity: u64 = 512 * 1024 * 1024 * 1024;

pub fn imageVirtualAddress(physical_address: u64) ?usize {
    if (physical_address >= image_physical_limit) return null;
    return image_virtual_bias + @as(usize, @intCast(physical_address));
}

pub fn imagePhysicalAddress(virtual_address: usize) ?u64 {
    if (virtual_address < image_virtual_bias) return null;
    const physical = virtual_address - image_virtual_bias;
    if (physical >= image_physical_limit) return null;
    return @intCast(physical);
}

pub fn directMappedAddress(physical_address: u64, mapped_bytes: u64) ?usize {
    if (mapped_bytes > direct_map_capacity or physical_address >= mapped_bytes) return null;
    return direct_map_base + @as(usize, @intCast(physical_address));
}

pub fn directMappedPhysicalAddress(virtual_address: usize, mapped_bytes: u64) ?u64 {
    if (mapped_bytes > direct_map_capacity or virtual_address < direct_map_base) return null;
    const physical = virtual_address - direct_map_base;
    if (physical >= mapped_bytes) return null;
    return @intCast(physical);
}

pub fn kernelPhysicalAddress(virtual_address: usize, mapped_bytes: u64) ?u64 {
    return imagePhysicalAddress(virtual_address) orelse directMappedPhysicalAddress(virtual_address, mapped_bytes);
}

test "kernel image addresses preserve low physical load addresses" {
    const physical: u64 = 32 * 1024 * 1024;
    try std.testing.expectEqual(image_virtual_bias + physical, imageVirtualAddress(physical).?);
    try std.testing.expectEqual(physical, imagePhysicalAddress(imageVirtualAddress(physical).?).?);
    try std.testing.expectEqual(image_physical_limit - 1, imagePhysicalAddress(imageVirtualAddress(image_physical_limit - 1).?).?);
    try std.testing.expect(imageVirtualAddress(image_physical_limit) == null);
    try std.testing.expect(imagePhysicalAddress(image_virtual_bias - 1) == null);
    try std.testing.expect(imagePhysicalAddress(image_virtual_bias + image_physical_limit) == null);
}

test "physical conversion distinguishes image and direct aliases" {
    const physical: u64 = 0x1_0000_3000;
    const direct = directMappedAddress(physical, direct_map_capacity).?;
    try std.testing.expectEqual(physical, kernelPhysicalAddress(direct, direct_map_capacity).?);
    try std.testing.expectEqual(@as(u64, 32 * 1024 * 1024), kernelPhysicalAddress(imageVirtualAddress(32 * 1024 * 1024).?, direct_map_capacity).?);
    try std.testing.expect(kernelPhysicalAddress(32 * 1024 * 1024, direct_map_capacity) == null);
    try std.testing.expect(directMappedAddress(direct_map_capacity, direct_map_capacity) == null);
    try std.testing.expect(directMappedAddress(0, direct_map_capacity + 1) == null);
    try std.testing.expect(directMappedPhysicalAddress(direct_map_base + direct_map_capacity, direct_map_capacity) == null);
}
