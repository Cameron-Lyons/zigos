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

const MAX_ADDRESS_SPACES: usize = 16;

const SpaceSlot = struct {
    space_id: usize = 0,
    occupied: bool = false,
    region_count: u8 = 0,
    regions: [MAX_REGIONS]Region = @as([MAX_REGIONS]Region, @splat(.{})),
};

var spaces: [MAX_ADDRESS_SPACES]SpaceSlot = @as([MAX_ADDRESS_SPACES]SpaceSlot, @splat(.{}));

pub fn reset() void {
    spaces = @as([MAX_ADDRESS_SPACES]SpaceSlot, @splat(.{}));
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
    const slot = findSpace(space_id) orelse return;
    if (comptime builtin.target.os.tag == .freestanding) {
        var index: u8 = 0;
        while (index < slot.region_count) : (index += 1) {
            const region = slot.regions[index];
            @import("paging64.zig").releaseUserRange(
                space,
                @intCast(region.virt_start),
                @intCast(region.virt_end_exclusive - region.virt_start),
            ) catch @panic("invalid retired demand-paging range");
        }
    }
    slot.* = .{};
}

// Remove exactly one owned region while other tasks keep the space alive.
// Partial or foreign ranges must leave the registrations and mappings intact.
pub fn unregisterRegionForSpace(space: anytype, virt_start: u64, virt_end_exclusive: u64) bool {
    if (virt_end_exclusive <= virt_start) return false;
    const slot = findSpace(spaceIdOf(space)) orelse return false;
    for (slot.regions[0..slot.region_count], 0..) |region, index| {
        if (region.virt_start != virt_start or region.virt_end_exclusive != virt_end_exclusive) continue;
        if (comptime builtin.target.os.tag == .freestanding) {
            @import("paging64.zig").releaseUserRange(space, @intCast(virt_start), @intCast(virt_end_exclusive - virt_start)) catch
                @panic("invalid retired demand-paging region");
        }
        const last = slot.region_count - 1;
        std.mem.copyForwards(Region, slot.regions[index..last], slot.regions[index + 1 .. slot.region_count]);
        slot.regions[last] = .{};
        slot.region_count = last;
        if (last == 0) slot.* = .{};
        return true;
    }
    return false;
}

pub fn regionFor(fault_address: u64) ?*Region {
    return regionForSpaceId(0, fault_address);
}

pub fn resolve(fault_address: u64, write: bool) bool {
    const region = regionFor(fault_address) orelse return false;
    return !write or region.writable or region.kind == .object_cow;
}

pub fn resolveAndMap(space: anytype, fault_address: u64, write: bool) bool {
    return resolveFault(space, fault_address, 0x4 | @as(u32, if (write) 0x2 else 0));
}

// Prepare only bytes that the kernel will touch. Metadata permission checks
// remain the caller's responsibility; this checks actual private user backing.
pub fn prepareUserRange(space: anytype, virtual_start: usize, size_bytes: usize, write: bool) bool {
    return prepareUserRangeWith(@import("paging64.zig"), space, virtual_start, size_bytes, write);
}

fn prepareUserRangeWith(comptime paging: type, space: anytype, virtual_start: usize, size_bytes: usize, write: bool) bool {
    if (size_bytes == 0) return true;
    const end = std.math.add(usize, virtual_start, size_bytes) catch return false;
    if (end > 0x0000_8000_0000_0000) return false;
    var address = virtual_start;
    while (address < end) {
        var permissions = paging.ownedUserPagePermissions(space, address);
        if (permissions == null or (write and !permissions.?.writable)) {
            const region = regionForSpaceId(spaceIdOf(space), address) orelse return false;
            if ((region.virt_start & 0xFFF) != 0) return false;
            if (region.kind == .object_physical or (write and !region.writable and region.kind != .object_cow)) return false;
            if (permissions != null and region.kind != .object_cow) return false;
            if (!resolveRegionFault(paging, space, region, address, write, permissions != null)) return false;
            permissions = paging.ownedUserPagePermissions(space, address);
        }
        const after = permissions orelse return false;
        if (!after.user or (write and (!after.writable or after.executable))) return false;
        const remaining_in_page = 0x1000 - (address & 0xFFF);
        address += @min(end - address, remaining_in_page);
    }
    return true;
}

pub fn resolveFault(space: anytype, fault_address: u64, error_code: u32) bool {
    if (!resolvableFault(error_code)) return false;
    const present = (error_code & 0x1) != 0;
    const write = (error_code & 0x2) != 0;
    const region = regionForSpaceId(spaceIdOf(space), fault_address) orelse return false;
    if (write and !region.writable and region.kind != .object_cow) return false;
    if (present and region.kind != .object_cow) return false;
    if (comptime builtin.target.os.tag != .freestanding) return true;
    return resolveRegionFault(@import("paging64.zig"), space, region, fault_address, write, present);
}

fn resolvableFault(error_code: u32) bool {
    // Demand paging resolves user data faults only. Reserved PTE bits, NX,
    // protection keys, shadow stacks, and other protection failures retain
    // their ordinary fault containment path.
    if ((error_code & 0x4) == 0 or (error_code & ~@as(u32, 0x7)) != 0) return false;
    return (error_code & 0x1) == 0 or (error_code & 0x2) != 0;
}

pub fn regionOverlapsSpace(space: anytype, virt_start: u64, virt_end_exclusive: u64) bool {
    if (virt_end_exclusive <= virt_start) return false;
    const slot = findSpace(spaceIdOf(space)) orelse return false;
    var index: u8 = 0;
    while (index < slot.region_count) : (index += 1) {
        const region = slot.regions[index];
        if (virt_end_exclusive <= region.virt_start) continue;
        if (virt_start >= region.virt_end_exclusive) continue;
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
    const slot = spaceSlot(space_id) orelse return false;
    if (slot.region_count >= MAX_REGIONS) return false;
    var index: u8 = 0;
    while (index < slot.region_count and slot.regions[index].virt_start <= region.virt_start) : (index += 1) {}
    var shift = slot.region_count;
    while (shift > index) : (shift -= 1) {
        slot.regions[shift] = slot.regions[shift - 1];
    }
    slot.regions[index] = region;
    slot.region_count += 1;
    return true;
}

fn spaceSlot(space_id: usize) ?*SpaceSlot {
    if (findSpace(space_id)) |slot| return slot;
    for (spaces[0..]) |*slot| {
        if (slot.occupied) continue;
        slot.* = .{
            .space_id = space_id,
            .occupied = true,
        };
        return slot;
    }
    return null;
}

fn findSpace(space_id: usize) ?*SpaceSlot {
    for (spaces[0..]) |*slot| {
        if (slot.occupied and slot.space_id == space_id) return slot;
    }
    return null;
}

fn regionForSpaceId(space_id: usize, fault_address: u64) ?*Region {
    const slot = findSpace(space_id) orelse return null;
    var lo: u8 = 0;
    var hi: u8 = slot.region_count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (slot.regions[mid].virt_start <= fault_address) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    var index: usize = lo;
    while (index > 0) {
        index -= 1;
        if (fault_address < slot.regions[index].virt_end_exclusive) return &slot.regions[index];
        if (slot.regions[index].virt_start > fault_address) break;
    }
    return null;
}

fn resolveRegionFault(
    comptime paging: type,
    space: anytype,
    region: *const Region,
    fault_address: u64,
    write: bool,
    present: bool,
) bool {
    const page_start = fault_address & ~@as(u64, 0xFFF);
    if (present) {
        if (!write or region.kind != .object_cow) return false;
        return paging.promoteOwnedUserPageForWrite(space, @intCast(page_start)) catch false;
    }
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
                error.AlreadyMapped => {
                    // The source snapshot was copied when this private page
                    // was first materialized. Repeated faults must not recopy
                    // over changes made by the task.
                    if (write) _ = paging.promoteOwnedUserPageForWrite(space, @intCast(page_start)) catch return false;
                    return true;
                },
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

const UserCopyTestModel = struct {
    const base: usize = 0x4000_0000;
    const Page = struct {
        present: bool = false,
        owned: bool = true,
        user: bool = true,
        writable: bool = false,
        executable: bool = false,
        value: u8 = 0,
    };
    pages: [3]Page = @splat(.{}),
    allocations: usize = 0,
    copies: usize = 0,
    promotions: usize = 0,
    source: u8 = 7,
    fail_allocation: bool = false,
    lose_ownership: bool = false,
    ineffective_promotion: bool = false,

    fn page(self: *@This(), address: usize) ?*Page {
        if (address < base or address >= base + 3 * 0x1000) return null;
        return &self.pages[(address - base) / 0x1000];
    }
};

const UserCopyTestPaging = struct {
    pub const UserPermissions = struct {
        writable: bool,
        executable: bool,
        write_through: bool,
        cache_disabled: bool,
        protection_key: u4,
    };
    const PagePermissions = struct { writable: bool, executable: bool, user: bool };

    pub fn ownedUserPagePermissions(model: *UserCopyTestModel, address: usize) ?PagePermissions {
        const page = model.page(address) orelse return null;
        if (!page.present or !page.owned or !page.user) return null;
        return .{ .writable = page.writable, .executable = page.executable, .user = page.user };
    }

    pub fn mapOwnedUserRange(model: *UserCopyTestModel, address: usize, _: usize, permissions: UserPermissions) error{ AlreadyMapped, OutOfMemory }!void {
        const page = model.page(address) orelse return error.OutOfMemory;
        if (page.present) return error.AlreadyMapped;
        if (model.fail_allocation) return error.OutOfMemory;
        page.present = true;
        page.writable = permissions.writable;
        page.executable = permissions.executable;
        page.owned = !model.lose_ownership;
        model.allocations += 1;
    }

    pub fn mapBorrowedPhysicalUserRange(_: *UserCopyTestModel, _: usize, _: u64, _: usize, _: UserPermissions) error{ AlreadyMapped, UnexpectedMapping }!void {
        return error.UnexpectedMapping;
    }

    pub fn copyOwnedUserPageFromPhysical(model: *UserCopyTestModel, address: usize, _: u64) error{PageNotOwned}!void {
        const page = model.page(address) orelse return error.PageNotOwned;
        if (!page.owned) return error.PageNotOwned;
        page.value = model.source;
        model.copies += 1;
    }

    pub fn promoteOwnedUserPageForWrite(model: *UserCopyTestModel, address: usize) error{PageNotOwned}!bool {
        const page = model.page(address) orelse return error.PageNotOwned;
        if (!page.present or !page.owned or !page.user or page.executable) return error.PageNotOwned;
        if (page.writable or model.ineffective_promotion) return false;
        page.writable = true;
        model.promotions += 1;
        return true;
    }
};

test "user copy preparation materializes only touched pages and preserves readonly backing" {
    const previous = spaces;
    defer spaces = previous;
    reset();
    var model = UserCopyTestModel{};
    try std.testing.expect(registerForSpace(&model, .{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 3 * 0x1000,
    }));
    try std.testing.expect(prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base + 0xFFA, 32, false));
    try std.testing.expectEqual(@as(usize, 2), model.allocations);
    try std.testing.expect(model.pages[0].present and model.pages[1].present and !model.pages[2].present);
    try std.testing.expect(!model.pages[0].writable);
    model.pages[0].value = 41;
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    try std.testing.expectEqual(@as(u8, 41), model.pages[0].value);
    try std.testing.expectEqual(@as(usize, 0), model.promotions);
    try std.testing.expectEqual(@as(usize, 2), model.allocations);

    reset();
    var writable = UserCopyTestModel{};
    try std.testing.expect(registerForSpace(&writable, .{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 3 * 0x1000,
        .writable = true,
    }));
    try std.testing.expect(prepareUserRangeWith(UserCopyTestPaging, &writable, UserCopyTestModel.base + 0xFFA, 32, true));
    try std.testing.expect(writable.pages[0].writable and writable.pages[1].writable and !writable.pages[2].present);
    try std.testing.expectEqual(@as(usize, 2), writable.allocations);
}

test "user copy preparation promotes authenticated private copies without recopying" {
    const previous = spaces;
    defer spaces = previous;
    reset();
    var model = UserCopyTestModel{};
    try std.testing.expect(registerForSpace(&model, .{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x1000,
        .kind = .object_cow,
        .physical_base = 0x8000,
    }));
    try std.testing.expect(prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, false));
    try std.testing.expectEqual(@as(u8, 7), model.pages[0].value);
    model.source = 9;
    try std.testing.expect(prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    try std.testing.expectEqual(@as(u8, 7), model.pages[0].value);
    model.pages[0].value = 42;
    try std.testing.expect(prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    try std.testing.expectEqual(@as(u8, 42), model.pages[0].value);
    try std.testing.expectEqual(@as(usize, 1), model.allocations);
    try std.testing.expectEqual(@as(usize, 1), model.copies);
    try std.testing.expectEqual(@as(usize, 1), model.promotions);
    model.pages[0].writable = false;
    model.ineffective_promotion = true;
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
}

test "user copy preparation rejects foreign permissions collisions and allocation failure" {
    const previous = spaces;
    defer spaces = previous;
    reset();
    var model = UserCopyTestModel{};
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, false));
    try std.testing.expect(registerForSpace(&model, .{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x1000,
        .writable = true,
    }));
    model.fail_allocation = true;
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    model.fail_allocation = false;
    model.lose_ownership = true;
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    try std.testing.expect(!model.pages[0].owned);
    model.lose_ownership = false;
    model.pages[0] = .{ .present = true, .owned = false, .writable = true };
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, false));
    model.pages[0] = .{ .present = true, .user = false, .writable = true };
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    model.pages[0] = .{ .present = true, .writable = true, .executable = true };
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    try std.testing.expect(prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, false));

    reset();
    model = .{};
    try std.testing.expect(registerForSpace(&model, .{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x1000,
        .writable = true,
        .kind = .object_physical,
        .physical_base = 0x8000,
    }));
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, false));
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, std.math.maxInt(usize), 2, true));
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, 0x0000_8000_0000_0000, 1, false));
    try std.testing.expect(prepareUserRangeWith(UserCopyTestPaging, &model, 0, 0, true));
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

test "retiring one shared-space region preserves siblings and reuses capacity" {
    reset();
    defer reset();
    var space: u8 = 1;
    var foreign: u8 = 2;
    const base = 0x0000_007F_0000_0000;
    for (0..3) |index| {
        try std.testing.expect(registerForSpace(&space, .{
            .virt_start = base + index * 0x1000,
            .virt_end_exclusive = base + (index + 1) * 0x1000,
            .writable = true,
        }));
    }
    try std.testing.expect(!unregisterRegionForSpace(&foreign, base + 0x1000, base + 0x2000));
    try std.testing.expect(!unregisterRegionForSpace(&space, base + 0x1000, base + 0x1800));
    for (0..MAX_REGIONS + 1) |_| {
        try std.testing.expect(unregisterRegionForSpace(&space, base + 0x1000, base + 0x2000));
        try std.testing.expect(!resolveAndMap(&space, base + 0x1000, true));
        try std.testing.expect(resolveAndMap(&space, base, true));
        try std.testing.expect(resolveAndMap(&space, base + 0x2000, true));
        try std.testing.expect(registerForSpace(&space, .{
            .virt_start = base + 0x1000,
            .virt_end_exclusive = base + 0x2000,
            .writable = true,
        }));
    }
    for (0..3) |index| try std.testing.expect(unregisterRegionForSpace(&space, base + index * 0x1000, base + (index + 1) * 0x1000));
    try std.testing.expect(findSpace(spaceIdOf(&space)) == null);
}

test "demand faults resolve private-copy writes but preserve protection failures" {
    reset();
    defer reset();
    var space: u8 = 1;
    try std.testing.expect(registerForSpace(&space, .{
        .virt_start = 0x7000_0000,
        .virt_end_exclusive = 0x7000_1000,
        .kind = .object_cow,
        .physical_base = 0x2000,
    }));
    try std.testing.expect(resolveFault(&space, 0x7000_0004, 0x4));
    try std.testing.expect(resolveFault(&space, 0x7000_0004, 0x6));
    try std.testing.expect(resolveFault(&space, 0x7000_0004, 0x7));
    for ([_]u32{ 0, 2, 3, 5, 0xF, 0x14, 0x16, 0x27, 0x47, 0x8007 }) |error_code| {
        try std.testing.expect(!resolveFault(&space, 0x7000_0004, error_code));
    }
    try std.testing.expect(registerForSpace(&space, .{
        .virt_start = 0x7000_1000,
        .virt_end_exclusive = 0x7000_2000,
        .kind = .anonymous_zero,
        .writable = false,
    }));
    try std.testing.expect(resolveFault(&space, 0x7000_1000, 0x4));
    try std.testing.expect(!resolveFault(&space, 0x7000_1000, 0x6));
    try std.testing.expect(!resolveFault(&space, 0x7000_1000, 0x7));
    try std.testing.expect(!resolveFault(&space, 0x7000_3000, 0x7));
}

test "private-copy read then write promotes without copying over task changes" {
    const Model = struct {
        present: bool = false,
        writable: bool = false,
        source: u8 = 7,
        private: u8 = 0,
        copies: usize = 0,
        allocations: usize = 0,
        promotions: usize = 0,
    };
    const Paging = struct {
        pub const UserPermissions = struct {
            writable: bool,
            executable: bool,
            write_through: bool,
            cache_disabled: bool,
            protection_key: u4,
        };

        pub fn mapOwnedUserRange(model: *Model, _: usize, _: usize, permissions: UserPermissions) error{ AlreadyMapped, OutOfMemory }!void {
            if (model.present) return error.AlreadyMapped;
            model.present = true;
            model.writable = permissions.writable;
            model.allocations += 1;
        }

        pub fn mapBorrowedPhysicalUserRange(_: *Model, _: usize, _: u64, _: usize, _: UserPermissions) error{ AlreadyMapped, UnexpectedMapping }!void {
            return error.UnexpectedMapping;
        }

        pub fn copyOwnedUserPageFromPhysical(model: *Model, _: usize, _: u64) error{}!void {
            model.private = model.source;
            model.copies += 1;
        }

        pub fn promoteOwnedUserPageForWrite(model: *Model, _: usize) error{PageNotOwned}!bool {
            if (!model.present) return error.PageNotOwned;
            if (model.writable) return false;
            model.writable = true;
            model.promotions += 1;
            return true;
        }
    };
    const region = Region{
        .virt_start = 0x7000_0000,
        .virt_end_exclusive = 0x7000_1000,
        .kind = .object_cow,
        .physical_base = 0x2000,
    };
    var model = Model{};
    try std.testing.expect(resolveRegionFault(Paging, &model, &region, 0x7000_0004, false, false));
    try std.testing.expect(!model.writable);
    try std.testing.expectEqual(@as(u8, 7), model.private);
    model.source = 9;
    try std.testing.expect(resolveRegionFault(Paging, &model, &region, 0x7000_0004, true, true));
    try std.testing.expect(model.writable);
    try std.testing.expectEqual(@as(u8, 7), model.private);
    model.private = 42;
    try std.testing.expect(resolveRegionFault(Paging, &model, &region, 0x7000_0004, false, false));
    try std.testing.expect(resolveRegionFault(Paging, &model, &region, 0x7000_0004, true, false));
    try std.testing.expectEqual(@as(u8, 42), model.private);
    try std.testing.expectEqual(@as(usize, 1), model.allocations);
    try std.testing.expectEqual(@as(usize, 1), model.copies);
    try std.testing.expectEqual(@as(usize, 1), model.promotions);
    try std.testing.expect(!resolveRegionFault(Paging, &model, &region, 0x7000_0004, true, true));
}
