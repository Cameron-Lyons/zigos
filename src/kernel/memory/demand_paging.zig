const builtin = @import("builtin");
const std = @import("std");

pub const DEMAND_PAGES_USER_OBJECTS = true;
pub const REGISTERS_MAPPED_OBJECTS = true;
pub const COPIES_ON_WRITE = true;
pub const MAX_REGIONS: usize = 128;

pub const Kind = enum(u8) {
    anonymous_zero,
    object_physical,
    object_cow,
};

pub const Region = struct {
    virt_start: u32 = 0,
    virt_end_exclusive: u32 = 0,
    writable: bool = false,
    kind: Kind = .anonymous_zero,
    physical_base: u64 = 0,
};

const SpaceRegion = struct {
    space_id: usize = 0,
    region: Region = .{},
};

var regions: [MAX_REGIONS]SpaceRegion = [_]SpaceRegion{.{}} ** MAX_REGIONS;
var region_count: u8 = 0;

pub fn reset() void {
    regions = [_]SpaceRegion{.{}} ** MAX_REGIONS;
    region_count = 0;
}

pub fn register(region: Region) bool {
    return registerInSpace(0, region);
}

pub fn registerForSpace(space: anytype, region: Region) bool {
    return registerInSpace(spaceIdOf(space), region);
}

pub fn registerRange(virt_start: u64, size_bytes: u64, writable: bool, kind: Kind, physical_base: u64) bool {
    const start = std.math.cast(u32, virt_start) orelse return false;
    const size = std.math.cast(u32, size_bytes) orelse return false;
    if (size == 0 or start > std.math.maxInt(u32) - size) return false;
    return register(.{
        .virt_start = start,
        .virt_end_exclusive = start + size,
        .writable = writable,
        .kind = kind,
        .physical_base = physical_base,
    });
}

pub fn regionFor(fault_address: u32) ?*Region {
    return regionForSpaceId(0, fault_address);
}

pub fn resolve(fault_address: u32, write: bool) bool {
    const region = regionFor(fault_address) orelse return false;
    return !write or region.writable or region.kind == .object_cow;
}

pub fn resolveAndMap(space: anytype, fault_address: u32, write: bool) bool {
    const region = regionForSpaceId(spaceIdOf(space), fault_address) orelse return false;
    if (write and !region.writable and region.kind != .object_cow) return false;
    if (comptime builtin.target.os.tag != .freestanding) return true;
    return mapOnePage(space, region, fault_address, write);
}

fn spaceIdOf(space: anytype) usize {
    return switch (@typeInfo(@TypeOf(space))) {
        .pointer => @intFromPtr(space),
        else => 0,
    };
}

fn registerInSpace(space_id: usize, region: Region) bool {
    if (region.virt_end_exclusive <= region.virt_start) return false;
    if (region_count >= MAX_REGIONS) return false;
    regions[region_count] = .{ .space_id = space_id, .region = region };
    region_count += 1;
    return true;
}

fn regionForSpaceId(space_id: usize, fault_address: u32) ?*Region {
    var index: u8 = 0;
    var global_match: ?*Region = null;
    while (index < region_count) : (index += 1) {
        const slot = &regions[index];
        if (fault_address < slot.region.virt_start or fault_address >= slot.region.virt_end_exclusive) continue;
        if (slot.space_id == space_id) return &slot.region;
        if (slot.space_id == 0) global_match = &slot.region;
    }
    return global_match;
}

fn mapOnePage(space: anytype, region: *const Region, fault_address: u32, write: bool) bool {
    const paging = @import("paging64.zig");
    const page_start = fault_address & ~@as(u32, 0xFFF);
    const writable = region.writable or (write and region.kind == .object_cow);
    const permissions = paging.UserPermissions{
        .writable = writable,
        .executable = false,
        .write_through = false,
        .cache_disabled = region.kind == .object_physical,
    };
    const offset = page_start - region.virt_start;
    switch (region.kind) {
        .anonymous_zero => {
            paging.mapOwnedUserRange(space, page_start, 0x1000, permissions) catch |err| switch (err) {
                error.AlreadyMapped => {},
                else => return false,
            };
        },
        .object_physical => {
            paging.mapBorrowedPhysicalUserRange(
                space,
                page_start,
                region.physical_base + offset,
                0x1000,
                permissions,
            ) catch |err| switch (err) {
                error.AlreadyMapped => {},
                else => return false,
            };
        },
        .object_cow => {
            paging.mapOwnedUserRange(space, page_start, 0x1000, permissions) catch |err| switch (err) {
                error.AlreadyMapped => {},
                else => return false,
            };
            if (region.physical_base != 0) {
                paging.copyOwnedUserPageFromPhysical(
                    space,
                    page_start,
                    region.physical_base + offset,
                ) catch return false;
            }
        },
    }
    return true;
}

test "demand paging registers object-backed regions" {
    reset();
    try std.testing.expect(register(.{
        .virt_start = 0x4000_0000,
        .virt_end_exclusive = 0x4000_2000,
        .writable = true,
        .kind = .object_physical,
        .physical_base = 0x1000,
    }));
    try std.testing.expect(regionFor(0x4000_0FFF) != null);
    try std.testing.expect(regionFor(0x4000_2000) == null);
    try std.testing.expect(resolve(0x4000_1000, true));
    try std.testing.expect(COPIES_ON_WRITE);
    reset();
}

test "demand paging registers a mapped object range" {
    reset();
    try std.testing.expect(registerRange(0x7000_0000, 0x2000, true, .object_physical, 0x2000));
    try std.testing.expect(resolve(0x7000_1000, false));
    reset();
}

test "demand paging keeps per-space stack regions" {
    reset();
    var first: u8 = 1;
    var second: u8 = 2;
    try std.testing.expect(registerForSpace(&first, .{
        .virt_start = 0xB000_0000,
        .virt_end_exclusive = 0xB000_1000,
        .writable = true,
        .kind = .anonymous_zero,
    }));
    try std.testing.expect(registerForSpace(&second, .{
        .virt_start = 0xB000_0000,
        .virt_end_exclusive = 0xB000_1000,
        .writable = false,
        .kind = .object_cow,
    }));
    try std.testing.expect(resolveAndMap(&first, 0xB000_0004, true));
    try std.testing.expect(resolveAndMap(&second, 0xB000_0004, false));
    reset();
}
