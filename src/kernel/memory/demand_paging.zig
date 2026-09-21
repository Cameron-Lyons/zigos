const builtin = @import("builtin");
const std = @import("std");

pub const DEMAND_PAGES_USER_OBJECTS = true;
pub const REGISTERS_MAPPED_OBJECTS = true;
pub const COPIES_ON_WRITE = true;
pub const ISOLATES_REGIONS_BY_SPACE = true;
pub const RELEASES_REGIONS_WITH_SPACE = true;
pub const MAX_REGIONS: usize = 128;

pub const Kind = enum(u8) {
    anonymous_zero,
    object_physical,
    object_cow,
};

pub const Region = struct {
    virt_start: u64 = 0,
    virt_end_exclusive: u64 = 0,
    writable: bool = false,
    kind: Kind = .anonymous_zero,
    physical_base: u64 = 0,
    protection_key: u4 = 0,
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
    if (size_bytes == 0) return false;
    const end = std.math.add(u64, virt_start, size_bytes) catch return false;
    return register(.{
        .virt_start = virt_start,
        .virt_end_exclusive = end,
        .writable = writable,
        .kind = kind,
        .physical_base = physical_base,
    });
}

pub fn unregisterSpace(space: anytype) void {
    if (comptime !RELEASES_REGIONS_WITH_SPACE) return;
    const space_id = spaceIdOf(space);
    if (space_id == 0) return;
    var write: u8 = 0;
    var read: u8 = 0;
    while (read < region_count) : (read += 1) {
        if (regions[read].space_id == space_id) {
            if (comptime builtin.target.os.tag == .freestanding) {
                const region = regions[read].region;
                @import("paging64.zig").releaseUserRange(
                    space,
                    @intCast(region.virt_start),
                    @intCast(region.virt_end_exclusive - region.virt_start),
                ) catch @panic("invalid retired demand-paging range");
            }
            continue;
        }
        regions[write] = regions[read];
        write += 1;
    }
    if (write < region_count) {
        @memset(regions[write..region_count], .{});
    }
    region_count = write;
}

pub fn regionFor(fault_address: u64) ?*Region {
    return regionForSpaceId(0, fault_address);
}

pub fn resolve(fault_address: u64, write: bool) bool {
    const region = regionFor(fault_address) orelse return false;
    return !write or region.writable or region.kind == .object_cow;
}

pub fn resolveAndMap(space: anytype, fault_address: u64, write: bool) bool {
    const region = regionForSpaceId(spaceIdOf(space), fault_address) orelse return false;
    if (write and !region.writable and region.kind != .object_cow) return false;
    if (comptime builtin.target.os.tag != .freestanding) return true;
    return mapOnePage(space, region, fault_address, write);
}

pub fn regionOverlapsSpace(space: anytype, virt_start: u64, virt_end_exclusive: u64) bool {
    if (virt_end_exclusive <= virt_start) return false;
    const space_id = spaceIdOf(space);
    var index: u8 = 0;
    while (index < region_count) : (index += 1) {
        const slot = &regions[index];
        if (slot.space_id != space_id) continue;
        if (virt_end_exclusive <= slot.region.virt_start) continue;
        if (virt_start >= slot.region.virt_end_exclusive) continue;
        return true;
    }
    return false;
}

fn spaceIdOf(space: anytype) usize {
    return switch (@typeInfo(@TypeOf(space))) {
        .pointer => |pointer| blk: {
            if (comptime hasDirectoryField(pointer.child)) {
                break :blk @intFromPtr(space.directory);
            }
            break :blk @intFromPtr(space);
        },
        else => 0,
    };
}

fn hasDirectoryField(comptime Child: type) bool {
    return switch (@typeInfo(Child)) {
        .@"struct" => @hasField(Child, "directory"),
        else => false,
    };
}

fn registerInSpace(space_id: usize, region: Region) bool {
    if (region.virt_end_exclusive <= region.virt_start) return false;
    if (region_count >= MAX_REGIONS) return false;
    const slot = SpaceRegion{ .space_id = space_id, .region = region };
    var index: u8 = 0;
    while (index < region_count and regionPrecedes(regions[index], slot)) : (index += 1) {}
    var shift = region_count;
    while (shift > index) : (shift -= 1) {
        regions[shift] = regions[shift - 1];
    }
    regions[index] = slot;
    region_count += 1;
    return true;
}

fn regionPrecedes(left: SpaceRegion, right: SpaceRegion) bool {
    if (left.space_id != right.space_id) return left.space_id < right.space_id;
    if (left.region.virt_start != right.region.virt_start) return left.region.virt_start < right.region.virt_start;
    return left.region.virt_end_exclusive < right.region.virt_end_exclusive;
}

fn regionForSpaceId(space_id: usize, fault_address: u64) ?*Region {
    var lo: u8 = 0;
    var hi: u8 = region_count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const slot = &regions[mid];
        const starts_at_or_before = slot.space_id < space_id or
            (slot.space_id == space_id and slot.region.virt_start <= fault_address);
        if (starts_at_or_before) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    var index: usize = lo;
    while (index > 0) {
        index -= 1;
        const slot = &regions[index];
        if (slot.space_id != space_id) break;
        if (fault_address < slot.region.virt_end_exclusive) return &slot.region;
    }
    return null;
}

fn mapOnePage(space: anytype, region: *const Region, fault_address: u64, write: bool) bool {
    const paging = @import("paging64.zig");
    const page_start = fault_address & ~@as(u64, 0xFFF);
    const writable = region.writable or (write and region.kind == .object_cow);
    const permissions = paging.UserPermissions{
        .writable = writable,
        .executable = false,
        .write_through = false,
        .cache_disabled = region.kind == .object_physical,
        .protection_key = region.protection_key,
    };
    const offset = page_start - region.virt_start;
    switch (region.kind) {
        .anonymous_zero => {
            paging.mapOwnedUserRange(space, @intCast(page_start), 0x1000, permissions) catch |err| switch (err) {
                error.AlreadyMapped => {},
                else => return false,
            };
        },
        .object_physical => {
            paging.mapBorrowedPhysicalUserRange(
                space,
                @intCast(page_start),
                region.physical_base + offset,
                0x1000,
                permissions,
            ) catch |err| switch (err) {
                error.AlreadyMapped => {},
                else => return false,
            };
        },
        .object_cow => {
            paging.mapOwnedUserRange(space, @intCast(page_start), 0x1000, permissions) catch |err| switch (err) {
                error.AlreadyMapped => {},
                else => return false,
            };
            if (region.physical_base != 0) {
                paging.copyOwnedUserPageFromPhysical(
                    space,
                    @intCast(page_start),
                    region.physical_base + offset,
                ) catch return false;
            }
        },
    }
    return true;
}

test "demand paging resolves the containing region when ranges overlap" {
    reset();
    try std.testing.expect(register(.{
        .virt_start = 0x5000_0000,
        .virt_end_exclusive = 0x5000_3000,
        .writable = true,
        .kind = .anonymous_zero,
    }));
    try std.testing.expect(register(.{
        .virt_start = 0x5000_1000,
        .virt_end_exclusive = 0x5000_1800,
        .writable = false,
        .kind = .object_physical,
        .physical_base = 0x8000,
    }));
    const inner = regionFor(0x5000_1400) orelse return error.MissingRegion;
    try std.testing.expectEqual(Kind.object_physical, inner.kind);
    const outer = regionFor(0x5000_2000) orelse return error.MissingRegion;
    try std.testing.expectEqual(Kind.anonymous_zero, outer.kind);
    reset();
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
        .virt_start = 0x0000_007F_0000_0000,
        .virt_end_exclusive = 0x0000_007F_0000_1000,
        .writable = true,
        .kind = .anonymous_zero,
    }));
    try std.testing.expect(registerForSpace(&second, .{
        .virt_start = 0x0000_007F_0000_0000,
        .virt_end_exclusive = 0x0000_007F_0000_1000,
        .writable = false,
        .kind = .object_cow,
    }));
    try std.testing.expect(resolveAndMap(&first, 0x0000_007F_0000_0004, true));
    try std.testing.expect(resolveAndMap(&second, 0x0000_007F_0000_0004, false));
    reset();
}

test "demand paging does not map another space's objects" {
    reset();
    var owner: u8 = 1;
    var stranger: u8 = 2;
    try std.testing.expect(registerForSpace(&owner, .{
        .virt_start = 0x7000_0000,
        .virt_end_exclusive = 0x7000_1000,
        .writable = true,
        .kind = .object_physical,
        .physical_base = 0x2000,
    }));
    try std.testing.expect(registerRange(0x7000_0000, 0x1000, true, .object_physical, 0x2000));
    try std.testing.expect(!resolveAndMap(&stranger, 0x7000_0000, false));
    try std.testing.expect(resolveAndMap(&owner, 0x7000_0000, false));
    try std.testing.expect(ISOLATES_REGIONS_BY_SPACE);
    reset();
}

test "demand paging identifies spaces by shared page directory" {
    reset();
    const Directory = struct { dummy: u8 = 0 };
    var directory = Directory{};
    var first = struct { directory: *Directory }{ .directory = &directory };
    var second = struct { directory: *Directory }{ .directory = &directory };
    try std.testing.expect(registerForSpace(&first, .{
        .virt_start = 0x0000_007F_FFFF_0000,
        .virt_end_exclusive = 0x0000_007F_FFFF_1000,
        .writable = true,
        .kind = .anonymous_zero,
    }));
    try std.testing.expect(regionOverlapsSpace(&second, 0x0000_007F_FFFF_0000, 0x0000_007F_FFFF_1000));
    try std.testing.expect(!regionOverlapsSpace(&second, 0x0000_007F_FFFE_0000, 0x0000_007F_FFFE_1000));
    reset();
}

test "demand paging unregisters retired spaces" {
    reset();
    var space: u8 = 1;
    var iteration: usize = 0;
    while (iteration < MAX_REGIONS + 1) : (iteration += 1) {
        try std.testing.expect(registerForSpace(&space, .{
            .virt_start = 0x0000_007F_0000_0000,
            .virt_end_exclusive = 0x0000_007F_0000_1000,
            .writable = true,
            .kind = .anonymous_zero,
        }));
        unregisterSpace(&space);
    }
    try std.testing.expect(registerForSpace(&space, .{
        .virt_start = 0x0000_007F_0000_0000,
        .virt_end_exclusive = 0x0000_007F_0000_1000,
        .writable = true,
        .kind = .anonymous_zero,
    }));
    try std.testing.expect(RELEASES_REGIONS_WITH_SPACE);
    reset();
}
