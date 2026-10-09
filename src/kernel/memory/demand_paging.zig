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
    shared_ram,
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
// The BSP keeps IF=0, the task/root quiescent and admission valid through the
// immediate copy; no callback or yield may intervene.
pub fn prepareUserRange(space: anytype, virtual_start: usize, size_bytes: usize, write: bool) bool {
    return prepareUserRangeWith(@import("paging64.zig"), space, virtual_start, size_bytes, write);
}

// Obtained from the live shared-object Table, never from user metadata. The
// caller retains its task/token authority, BSP ownership and IF=0 until its
// single copy consumes the returned alias; no yield or callback may intervene.
pub const SharedCopyAuthority = struct {
    virtual_base: u64,
    physical_base: u64,
    size_bytes: usize,
};

pub fn validateSharedUserRangeRegistration(
    space: anytype,
    authority: SharedCopyAuthority,
    virtual_start: usize,
    size_bytes: usize,
    write: bool,
    protection_key: u4,
) bool {
    _ = write;
    // Current shared objects use ordinary writable RAM and key zero. Private
    // COW registrations and caller-selected keys grant no shared-copy access.
    if (size_bytes == 0 or authority.size_bytes == 0 or protection_key != 0 or
        authority.virtual_base & 0xFFF != 0 or authority.physical_base & 0xFFF != 0) return false;
    const logical_end = std.math.add(u64, authority.virtual_base, authority.size_bytes) catch return false;
    const copy_end = std.math.add(u64, virtual_start, size_bytes) catch return false;
    if (logical_end > 0x0000_8000_0000_0000 or virtual_start < authority.virtual_base or copy_end > logical_end) return false;
    const physical_end = std.math.add(u64, authority.physical_base, authority.size_bytes) catch return false;
    if (physical_end > @import("paging64.zig").MANAGED_PHYSICAL_BYTES) return false;
    const slot = findSpace(spaceIdOf(space)) orelse return false;
    var matched = false;
    for (slot.regions[0..slot.region_count]) |region| {
        if (region.virt_end_exclusive <= authority.virtual_base or region.virt_start >= logical_end) continue;
        if (matched or region.virt_start != authority.virtual_base or region.virt_end_exclusive != logical_end or
            region.physical_base != authority.physical_base or region.kind != .shared_ram or
            !region.writable or region.protection_key != protection_key) return false;
        matched = true;
    }
    return matched;
}

pub fn prepareSharedUserRange(
    space: anytype,
    authority: SharedCopyAuthority,
    virtual_start: usize,
    size_bytes: usize,
    write: bool,
    protection_key: u4,
) ?usize {
    return prepareSharedUserRangeWith(@import("paging64.zig"), space, authority, virtual_start, size_bytes, write, protection_key);
}

fn prepareSharedUserRangeWith(
    comptime paging: type,
    space: anytype,
    authority: SharedCopyAuthority,
    virtual_start: usize,
    size_bytes: usize,
    write: bool,
    protection_key: u4,
) ?usize {
    if (!validateSharedUserRangeRegistration(space, authority, virtual_start, size_bytes, write, protection_key)) return null;
    const physical = std.math.add(u64, authority.physical_base, virtual_start - authority.virtual_base) catch return null;
    return paging.prepareSharedPhysicalUserRange(space, virtual_start, physical, size_bytes, write, protection_key);
}

test "shared copy registration requires exact live logical authority and rejects padding shadows and COW" {
    reset();
    defer reset();
    var space: u8 = 0;
    var foreign: u8 = 0;
    const authority = SharedCopyAuthority{ .virtual_base = 0x7000_0000, .physical_base = 0xA000, .size_bytes = 0x1003 };
    const region = Region{
        .virt_start = authority.virtual_base,
        .virt_end_exclusive = authority.virtual_base + authority.size_bytes,
        .physical_base = authority.physical_base,
        .kind = .shared_ram,
        .writable = true,
    };
    try std.testing.expect(!validateSharedUserRangeRegistration(&space, authority, 0x7000_0FF0, 19, true, 0));
    try std.testing.expect(registerForSpace(&space, region));
    try std.testing.expect(validateSharedUserRangeRegistration(&space, authority, 0x7000_0FF0, 19, true, 0));
    try std.testing.expect(validateSharedUserRangeRegistration(&space, authority, 0x7000_1002, 1, false, 0));
    try std.testing.expect(!validateSharedUserRangeRegistration(&foreign, authority, 0x7000_0FF0, 19, false, 0));
    for ([_]struct { start: usize, size: usize }{
        .{ .start = 0x7000_0FF0, .size = 20 },
        .{ .start = 0x7000_1003, .size = 1 },
        .{ .start = 0x6FFF_FFFF, .size = 2 },
        .{ .start = 0x7000_0000, .size = 0 },
        .{ .start = std.math.maxInt(usize), .size = 2 },
    }) |range| try std.testing.expect(!validateSharedUserRangeRegistration(&space, authority, range.start, range.size, true, 0));
    var wrong = authority;
    wrong.physical_base += 0x1000;
    try std.testing.expect(!validateSharedUserRangeRegistration(&space, wrong, 0x7000_0000, 1, false, 0));
    wrong = authority;
    wrong.size_bytes = 0x2000;
    try std.testing.expect(!validateSharedUserRangeRegistration(&space, wrong, 0x7000_0000, 1, false, 0));
    try std.testing.expect(!validateSharedUserRangeRegistration(&space, authority, 0x7000_0000, 1, false, 3));
    try std.testing.expect(unregisterRegionForSpace(&space, region.virt_start, region.virt_end_exclusive));
    for ([_]Region{
        blk: {
            var r = region;
            r.writable = false;
            break :blk r;
        },
        blk: {
            var r = region;
            r.kind = .object_cow;
            break :blk r;
        },
        blk: {
            var r = region;
            r.protection_key = 3;
            break :blk r;
        },
    }) |invalid| {
        try std.testing.expect(registerForSpace(&space, invalid));
        try std.testing.expect(!validateSharedUserRangeRegistration(&space, authority, 0x7000_0000, 1, false, 0));
        try std.testing.expect(unregisterRegionForSpace(&space, invalid.virt_start, invalid.virt_end_exclusive));
    }
    try std.testing.expect(registerForSpace(&space, region));
    try std.testing.expect(registerForSpace(&space, .{
        .virt_start = 0x7000_1000,
        .virt_end_exclusive = 0x7000_1003,
        .physical_base = 0xB000,
        .kind = .shared_ram,
        .writable = true,
    }));
    try std.testing.expect(!validateSharedUserRangeRegistration(&space, authority, 0x7000_0FF0, 19, true, 0));
}

test "shared copy preparation passes exact offset only after registration admission" {
    const Model = struct { calls: usize = 0, physical: u64 = 0, write: bool = false };
    const Paging = struct {
        pub fn prepareSharedPhysicalUserRange(model: *Model, _: usize, physical: u64, _: usize, write: bool, key: u4) ?usize {
            if (key != 0) return null;
            model.calls += 1;
            model.physical = physical;
            model.write = write;
            return 0xFFFF_8000_0000_0000 + physical;
        }
    };
    reset();
    defer reset();
    var model = Model{};
    const authority = SharedCopyAuthority{ .virtual_base = 0x7000_0000, .physical_base = 0xA000, .size_bytes = 0x1010 };
    try std.testing.expect(prepareSharedUserRangeWith(Paging, &model, authority, 0x7000_0FF0, 32, true, 0) == null);
    try std.testing.expectEqual(@as(usize, 0), model.calls);
    try std.testing.expect(registerForSpace(&model, .{
        .virt_start = authority.virtual_base,
        .virt_end_exclusive = authority.virtual_base + authority.size_bytes,
        .kind = .shared_ram,
        .physical_base = authority.physical_base,
        .writable = true,
    }));
    try std.testing.expectEqual(@as(?usize, 0xFFFF_8000_0000_AFF0), prepareSharedUserRangeWith(Paging, &model, authority, 0x7000_0FF0, 32, true, 0));
    try std.testing.expectEqual(@as(u64, 0xAFF0), model.physical);
    try std.testing.expect(model.write);
    try std.testing.expectEqual(@as(usize, 1), model.calls);
    try std.testing.expect(prepareSharedUserRangeWith(Paging, &model, authority, 0x7000_1000, 17, false, 0) == null);
    try std.testing.expectEqual(@as(usize, 1), model.calls);
}

fn prepareUserRangeWith(comptime paging: type, space: anytype, virtual_start: usize, size_bytes: usize, write: bool) bool {
    if (size_bytes == 0) return true;
    const end = std.math.add(usize, virtual_start, size_bytes) catch return false;
    if (end > 0x0000_8000_0000_0000) return false;
    var batch: paging.UserWriteBatch = undefined;
    if (!paging.UserWriteBatch.initInto(space, &batch)) return false;
    // Every late rejection/OOM must acknowledge earlier permission changes
    // before the caller can copy, retire backing, or restore interrupts.
    defer batch.finish();
    var address = virtual_start;
    while (address < end) {
        var permissions: ?paging.PagePermissions = null;
        var leaf_end: usize = undefined;
        if (!paging.inspectOwnedUserPreparationPageInto(space, address, write, &permissions, &leaf_end)) return false;
        if (permissions == null or (write and !permissions.?.writable)) {
            const region = regionForSpaceId(spaceIdOf(space), address) orelse return false;
            if ((region.virt_start & 0xFFF) != 0) return false;
            if (region.kind == .shared_ram or (write and !region.writable and region.kind != .object_cow)) return false;
            if (permissions != null and region.kind != .object_cow) return false;
            if (!resolveRegionFaultWithBatch(paging, space, region, address, write, permissions != null, &batch)) return false;
            if (!paging.inspectOwnedUserPreparationPageInto(space, address, write, &permissions, &leaf_end)) return false;
        }
        const after = permissions orelse return false;
        if (!after.user or (write and (!after.writable or after.executable))) return false;
        // A fully admitted huge leaf has homogeneous permissions and owned
        // backing. Inspect its complete span once instead of once per 4 KiB.
        address = @min(end, leaf_end);
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
    return resolveRegionFaultWithBatch(paging, space, region, fault_address, write, present, null);
}

fn resolveRegionFaultWithBatch(
    comptime paging: type,
    space: anytype,
    region: *const Region,
    fault_address: u64,
    write: bool,
    present: bool,
    batch: anytype,
) bool {
    const page_start = fault_address & ~@as(u64, 0xFFF);
    // Registrations may describe a partial page. Never wrap its first aligned
    // page below the region into a physical backing offset or a promotion.
    const offset = std.math.sub(u64, page_start, region.virt_start) catch return false;
    if (present) {
        if (!write or region.kind != .object_cow) return false;
        return promoteRegionPage(paging, space, @intCast(page_start), batch) catch false;
    }
    const writable = region.writable or (write and region.kind == .object_cow);
    const permissions = paging.UserPermissions{
        .writable = writable,
        .executable = false,
        .write_through = false,
        // Shared objects own ordinary RAM and use the same cached memory type
        // as the kernel direct alias. Device MMIO uses the broker mapper.
        .cache_disabled = false,
        .protection_key = region.protection_key,
    };
    switch (region.kind) {
        .anonymous_zero => {
            paging.mapOwnedUserRange(space, @intCast(page_start), 0x1000, permissions) catch |err| switch (err) {
                error.AlreadyMapped => {},
                else => return false,
            };
        },
        .shared_ram => {
            paging.mapBorrowedPhysicalUserRange(
                space,
                @intCast(page_start),
                std.math.add(u64, region.physical_base, offset) catch return false,
                0x1000,
                permissions,
            ) catch |err| switch (err) {
                error.AlreadyMapped => {},
                else => return false,
            };
        },
        .object_cow => {
            const mapping = if (region.physical_base == 0)
                paging.mapOwnedUserRange(space, @intCast(page_start), 0x1000, permissions)
            else
                paging.mapOwnedUserPageFromPhysical(
                    space,
                    @intCast(page_start),
                    std.math.add(u64, region.physical_base, offset) catch return false,
                    permissions,
                );
            mapping catch |err| switch (err) {
                error.AlreadyMapped => {
                    // The source snapshot was copied when this private page
                    // was first materialized. Repeated faults must not recopy
                    // over changes made by the task.
                    if (write) _ = promoteRegionPage(paging, space, @intCast(page_start), batch) catch return false;
                    return true;
                },
                else => return false,
            };
        },
    }
    return true;
}

inline fn promoteRegionPage(comptime paging: type, space: anytype, address: usize, batch: anytype) !bool {
    if (comptime @TypeOf(batch) == @TypeOf(null)) return paging.promoteOwnedUserPageForWrite(space, address);
    return batch.promote(address);
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
    zero_initializations: usize = 0,
    mapping_attempts: usize = 0,
    borrowed_mappings: usize = 0,
    borrowed_physical: u64 = 0,
    borrowed_cache_disabled: bool = false,
    borrowed_protection_key: u4 = 0,
    allow_borrowed: bool = false,
    promotions: usize = 0,
    barriers: usize = 0,
    acknowledged: bool = false,
    cpu: u8 = 0,
    interrupts_enabled: bool = false,
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
    pub const UserWriteBatch = struct {
        model: *UserCopyTestModel,
        changed: bool = false,

        pub fn initInto(model: *UserCopyTestModel, out: *@This()) bool {
            if (model.cpu != 0 or model.interrupts_enabled) return false;
            out.* = .{ .model = model };
            return true;
        }

        pub fn promote(self: *@This(), address: usize) error{PageNotOwned}!bool {
            const changed = try publish(self.model, address);
            self.changed = self.changed or changed;
            return changed;
        }

        pub fn finish(self: *@This()) void {
            if (!self.changed) return;
            self.model.barriers += 1;
            self.model.acknowledged = true;
            self.changed = false;
        }
    };

    pub const UserPermissions = struct {
        writable: bool,
        executable: bool,
        write_through: bool,
        cache_disabled: bool,
        protection_key: u4,
    };
    pub const PagePermissions = struct { writable: bool, executable: bool, user: bool };

    pub fn inspectOwnedUserPreparationPageInto(model: *UserCopyTestModel, address: usize, write: bool, out: *?PagePermissions, leaf_end: *usize) bool {
        const page = model.page(address) orelse return false;
        if (page.present and (!page.owned or !page.user or (write and page.executable))) return false;
        out.* = ownedUserPagePermissions(model, address);
        leaf_end.* = (address & ~@as(usize, 0xFFF)) + 0x1000;
        return true;
    }

    pub fn ownedUserPagePermissions(model: *UserCopyTestModel, address: usize) ?PagePermissions {
        const page = model.page(address) orelse return null;
        if (!page.present or !page.owned or !page.user) return null;
        return .{ .writable = page.writable, .executable = page.executable, .user = page.user };
    }

    pub fn mapOwnedUserRange(model: *UserCopyTestModel, address: usize, _: usize, permissions: UserPermissions) error{ AlreadyMapped, OutOfMemory }!void {
        model.mapping_attempts += 1;
        const page = model.page(address) orelse return error.OutOfMemory;
        if (page.present) return error.AlreadyMapped;
        if (model.fail_allocation) return error.OutOfMemory;
        page.present = true;
        page.writable = permissions.writable;
        page.executable = permissions.executable;
        page.owned = !model.lose_ownership;
        page.value = 0;
        model.allocations += 1;
        model.zero_initializations += 1;
    }

    pub fn mapBorrowedPhysicalUserRange(model: *UserCopyTestModel, address: usize, physical: u64, _: usize, permissions: UserPermissions) error{ AlreadyMapped, UnexpectedMapping }!void {
        model.mapping_attempts += 1;
        if (!model.allow_borrowed) return error.UnexpectedMapping;
        const page = model.page(address) orelse return error.UnexpectedMapping;
        if (page.present) return error.AlreadyMapped;
        page.* = .{
            .present = true,
            .owned = false,
            .writable = permissions.writable,
            .executable = permissions.executable,
        };
        model.borrowed_physical = physical;
        model.borrowed_cache_disabled = permissions.cache_disabled;
        model.borrowed_protection_key = permissions.protection_key;
        model.borrowed_mappings += 1;
    }

    pub fn mapOwnedUserPageFromPhysical(model: *UserCopyTestModel, address: usize, _: u64, permissions: UserPermissions) error{ AlreadyMapped, OutOfMemory }!void {
        model.mapping_attempts += 1;
        const page = model.page(address) orelse return error.OutOfMemory;
        if (page.present) return error.AlreadyMapped;
        if (model.fail_allocation) return error.OutOfMemory;
        page.* = .{
            .present = true,
            .owned = !model.lose_ownership,
            .writable = permissions.writable,
            .executable = permissions.executable,
            .value = model.source,
        };
        model.allocations += 1;
        model.copies += 1;
    }

    pub fn promoteOwnedUserPageForWrite(model: *UserCopyTestModel, address: usize) error{PageNotOwned}!bool {
        const changed = try publish(model, address);
        if (changed) {
            model.barriers += 1;
            model.acknowledged = true;
        }
        return changed;
    }

    fn publish(model: *UserCopyTestModel, address: usize) error{PageNotOwned}!bool {
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
        .kind = .shared_ram,
        .physical_base = 0x8000,
    }));
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, false));
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, std.math.maxInt(usize), 2, true));
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, 0x0000_8000_0000_0000, 1, false));
    try std.testing.expect(prepareUserRangeWith(UserCopyTestPaging, &model, 0, 0, true));
}

test "private COW preparation batches actual leaf publication and completes late failure barriers" {
    const Paging = @import("paging64.zig").WritePreparationTestPaging;
    const previous = spaces;
    defer spaces = previous;
    var model: Paging.Model = undefined;
    for ([_]bool{ false, true }) |identifiers_enabled| {
        for ([_]bool{ false, true }) |active| {
            reset();
            try model.init();
            defer model.deinit();
            model.identifiers_enabled = identifiers_enabled;
            model.active = active;
            try std.testing.expect(registerForSpace(&model, .{
                .virt_start = Paging.Model.base,
                .virt_end_exclusive = Paging.Model.base + 2 * 0x1000,
                .kind = .object_cow,
            }));
            model.expected_writable = 0b011;
            const untouched = model.payload;
            // The third page has no registration: the first two changes must
            // already be acknowledged when false prevents the payload copy.
            var copied = false;
            if (prepareUserRangeWith(Paging, &model, Paging.Model.base, 3 * 0x1000, true)) copied = true;
            try std.testing.expect(!copied and model.valid and model.acknowledged);
            try std.testing.expectEqualDeep(untouched, model.payload);
            try std.testing.expectEqual(@as(usize, 1), model.barriers);
            try std.testing.expectEqual(@as(usize, 1), model.remote_count);
            try std.testing.expectEqual(@as(usize, @intFromBool(identifiers_enabled)), model.local_count);
            try std.testing.expectEqual(@as(usize, @intFromBool(!identifiers_enabled and active)), model.reload_count);
            try std.testing.expect(prepareUserRangeWith(Paging, &model, Paging.Model.base, 2 * 0x1000, true));
            try std.testing.expectEqual(@as(usize, 1), model.barriers);
            // Single hardware-fault resolution retains the immediate path.
            const region = Region{ .virt_start = Paging.Model.base, .virt_end_exclusive = Paging.Model.base + 3 * 0x1000, .kind = .object_cow };
            model.expected_writable = 0b111;
            model.acknowledged = false;
            try std.testing.expect(resolveRegionFault(Paging, &model, &region, Paging.Model.base + 2 * 0x1000, true, true));
            try std.testing.expect(model.acknowledged and model.valid);
            try std.testing.expectEqual(@as(usize, 2), model.barriers);
        }
    }
}

test "private COW preparation finishes promotion before late OOM and leaves partial materialization reclaimable" {
    const Paging = @import("paging64.zig").WritePreparationTestPaging;
    const previous = spaces;
    defer spaces = previous;
    reset();
    var model: Paging.Model = undefined;
    try model.init();
    defer model.deinit();
    try std.testing.expect(registerForSpace(&model, .{
        .virt_start = Paging.Model.base,
        .virt_end_exclusive = Paging.Model.base + 3 * 0x1000,
        .kind = .object_cow,
    }));
    for (1..3) |index| {
        model.leaf(Paging.Model.base + index * 0x1000).* = 0;
        try model.frames.release(.{ .base = model.data[index], .count = 1 });
    }
    const allocated_before = model.frames.stats().allocated;
    model.expected_writable = 0b001;
    model.fail_allocation = true;
    const untouched = model.payload;
    try std.testing.expect(!prepareUserRangeWith(Paging, &model, Paging.Model.base, 3 * 0x1000, true));
    try std.testing.expectEqualDeep(untouched, model.payload);
    try std.testing.expect(model.valid and model.acknowledged);
    try std.testing.expectEqual(@as(usize, 1), model.barriers);
    try std.testing.expectEqual(allocated_before, model.frames.stats().allocated);
    // A late OOM retains the new private page, but still exposes no payload;
    // retirement releases both the old copy and partial materialization only
    // after the earlier permission barrier has completed.
    model.fail_allocation = false;
    model.allocation_budget = 1;
    try std.testing.expect(!prepareUserRangeWith(Paging, &model, Paging.Model.base, 3 * 0x1000, true));
    try std.testing.expectEqual(@as(usize, 1), model.barriers);
    try std.testing.expectEqual(allocated_before + 1, model.frames.stats().allocated);
    try std.testing.expect(model.leaf(Paging.Model.base + 0x1000).* != 0);
    try std.testing.expectEqual(@as(u64, 0), model.leaf(Paging.Model.base + 2 * 0x1000).*);
    model.retire();
    try std.testing.expect(model.valid);
    try std.testing.expectEqual(@as(u32, 0), model.frames.stats().allocated);
}

test "private preparation admits a complete huge leaf with one allocated-span inspection" {
    const Paging = @import("paging64.zig").WritePreparationTestPaging;
    const previous = spaces;
    defer spaces = previous;
    reset();
    var model: Paging.Model = undefined;
    try model.init();
    defer model.deinit();
    try model.installHuge();
    try std.testing.expect(prepareUserRangeWith(Paging, &model, Paging.Model.base, 2 * 1024 * 1024, true));
    try std.testing.expectEqual(@as(usize, 1), model.huge_span_queries);
    try std.testing.expectEqual(@as(usize, 0), model.barriers);
    try std.testing.expectEqual(@as(usize, 0), model.materializations);
    model.retire();
    try std.testing.expect(model.valid);
    try std.testing.expectEqual(@as(u32, 0), model.frames.stats().allocated);
}

test "private COW preparation rejects malformed present and nonpresent backing before mapping fallback" {
    const paging = @import("paging64.zig");
    const Paging = paging.WritePreparationTestPaging;
    const table = @import("page_table64.zig");
    const previous = spaces;
    defer spaces = previous;
    reset();
    var model: Paging.Model = undefined;
    try model.init();
    defer model.deinit();
    try std.testing.expect(registerForSpace(&model, .{
        .virt_start = Paging.Model.base,
        .virt_end_exclusive = Paging.Model.base + 3 * 0x1000,
        .kind = .object_cow,
    }));
    const original = model.space.directory[0];
    const baseline = model.frames.stats();
    for ([_]u64{
        original & ~table.USER,
        original & ~table.WRITABLE,
        original | table.LARGE_PAGE,
        original | table.CACHE_DISABLE,
        original | table.WRITE_THROUGH,
        original | table.GLOBAL,
        original | (@as(u64, 1) << 54),
        table.withOwner(original, 3),
        table.withProtectionKey(original, 4),
        table.make(15 * 0x1000, table.PRESENT | table.USER | table.WRITABLE, 2),
        original & ~table.PRESENT,
    }) |forged| {
        model.space.directory[0] = forged;
        try std.testing.expect(!prepareUserRangeWith(Paging, &model, Paging.Model.base, 1, true));
        try std.testing.expectEqualDeep(baseline, model.frames.stats());
        try std.testing.expectEqual(@as(usize, 0), model.materializations);
        try std.testing.expectEqual(@as(usize, 0), model.barriers);
    }
    model.space.directory[0] = original;
    const leaf = model.leaf(Paging.Model.base);
    const valid = leaf.*;
    for ([_]u64{
        valid & ~table.PRESENT,
        valid & ~table.USER,
        valid & ~table.NO_EXECUTE,
        valid | table.CACHE_DISABLE,
        valid | table.WRITE_THROUGH,
        valid | table.GLOBAL,
        valid | (@as(u64, 1) << 53),
        valid | table.LARGE_PAGE,
        table.withOwner(valid, 0),
        table.make(15 * 0x1000, table.PRESENT | table.USER | table.WRITABLE | table.NO_EXECUTE, 1),
    }) |forged| {
        leaf.* = forged;
        try std.testing.expect(!prepareUserRangeWith(Paging, &model, Paging.Model.base, 1, true));
        try std.testing.expectEqualDeep(baseline, model.frames.stats());
        try std.testing.expectEqual(@as(usize, 0), model.materializations);
        try std.testing.expectEqual(@as(usize, 0), model.barriers);
    }
    // Effective NX from a parent cannot authorize an executable leaf write.
    model.space.directory[0] = original | table.NO_EXECUTE;
    leaf.* = (valid | table.WRITABLE) & ~table.NO_EXECUTE;
    try std.testing.expect(!prepareUserRangeWith(Paging, &model, Paging.Model.base, 1, true));
    try std.testing.expect(prepareUserRangeWith(Paging, &model, Paging.Model.base, 1, false));
    leaf.* = valid;
    model.space.directory[0] = original;
    // Rejected late present data still completes the earlier published change.
    model.expected_writable = 1;
    const late = model.leaf(Paging.Model.base + 0x1000);
    const saved = late.*;
    late.* = table.withOwner(saved, 0);
    try std.testing.expect(!prepareUserRangeWith(Paging, &model, Paging.Model.base, 2 * 0x1000, true));
    try std.testing.expect(model.valid and model.acknowledged);
    try std.testing.expectEqual(@as(usize, 1), model.barriers);
    late.* = saved;
    model.retire();
    try std.testing.expectEqual(@as(u32, 0), model.frames.stats().allocated);
}

test "private copy preparation rejects foreign CPU or enabled interrupts before mapping" {
    const previous = spaces;
    defer spaces = previous;
    reset();
    var model = UserCopyTestModel{};
    try std.testing.expect(registerForSpace(&model, .{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x1000,
        .writable = true,
    }));
    for (1..@import("../cpu_identity.zig").MAX_CPUS) |cpu| {
        model.cpu = @intCast(cpu);
        try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    }
    model.cpu = 0;
    model.interrupts_enabled = true;
    try std.testing.expect(!prepareUserRangeWith(UserCopyTestPaging, &model, UserCopyTestModel.base, 1, true));
    try std.testing.expectEqual(@as(usize, 0), model.mapping_attempts);
    try std.testing.expectEqual(@as(usize, 0), model.barriers);
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
        .kind = .shared_ram,
        .physical_base = 0x8000,
    }));
    const inner = regionFor(0x5000_1400) orelse return error.MissingRegion;
    try std.testing.expectEqual(Kind.shared_ram, inner.kind);
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
        .kind = .shared_ram,
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
    try std.testing.expect(registerRange(0x7000_0000, 0x2000, true, .shared_ram, 0x2000));
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
        .kind = .shared_ram,
        .physical_base = 0x2000,
    }));
    try std.testing.expect(registerRange(0x7000_0000, 0x1000, true, .shared_ram, 0x2000));
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

        pub fn mapOwnedUserPageFromPhysical(model: *Model, _: usize, _: u64, permissions: UserPermissions) error{AlreadyMapped}!void {
            if (model.present) return error.AlreadyMapped;
            model.private = model.source;
            model.copies += 1;
            model.writable = permissions.writable;
            model.allocations += 1;
            model.present = true;
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

test "private-copy faults initialize once without a zero pass and preserve failed allocations" {
    const region = Region{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x1000,
        .kind = .object_cow,
        .physical_base = 0x8000,
    };
    var model = UserCopyTestModel{ .fail_allocation = true };
    model.pages[0].value = 0x42;
    try std.testing.expect(!resolveRegionFault(UserCopyTestPaging, &model, &region, UserCopyTestModel.base, true, false));
    try std.testing.expect(!model.pages[0].present);
    try std.testing.expectEqual(@as(u8, 0x42), model.pages[0].value);
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    try std.testing.expectEqual(@as(usize, 0), model.copies);

    model.fail_allocation = false;
    try std.testing.expect(resolveRegionFault(UserCopyTestPaging, &model, &region, UserCopyTestModel.base, true, false));
    try std.testing.expect(model.pages[0].present and model.pages[0].writable);
    try std.testing.expectEqual(model.source, model.pages[0].value);
    try std.testing.expectEqual(@as(usize, 1), model.allocations);
    try std.testing.expectEqual(@as(usize, 1), model.copies);
    try std.testing.expectEqual(@as(usize, 0), model.zero_initializations);
    model.pages[0].value = 0x33;
    model.source = 0x99;
    try std.testing.expect(resolveRegionFault(UserCopyTestPaging, &model, &region, UserCopyTestModel.base, true, false));
    try std.testing.expectEqual(@as(u8, 0x33), model.pages[0].value);
    try std.testing.expectEqual(@as(usize, 1), model.copies);
}

test "zero-backed private-copy faults clear the page without copying physical memory" {
    const region = Region{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x1000,
        .kind = .object_cow,
    };
    var model = UserCopyTestModel{};
    model.pages[0].value = 0x42;
    try std.testing.expect(resolveRegionFault(UserCopyTestPaging, &model, &region, UserCopyTestModel.base, false, false));
    try std.testing.expect(model.pages[0].present and !model.pages[0].writable);
    try std.testing.expectEqual(@as(u8, 0), model.pages[0].value);
    try std.testing.expectEqual(@as(usize, 1), model.allocations);
    try std.testing.expectEqual(@as(usize, 1), model.zero_initializations);
    try std.testing.expectEqual(@as(usize, 0), model.copies);
}

test "private-copy faults reject overflowing physical source offsets before allocation" {
    const region = Region{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x3000,
        .kind = .object_cow,
        .physical_base = std.math.maxInt(u64) & ~@as(u64, 0xFFF),
    };
    var model = UserCopyTestModel{};
    try std.testing.expect(!resolveRegionFault(UserCopyTestPaging, &model, &region, UserCopyTestModel.base + 0x1000, true, false));
    try std.testing.expect(!model.pages[1].present);
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    try std.testing.expectEqual(@as(usize, 0), model.copies);
}

test "shared RAM faults preserve page offsets and cached borrowed permissions" {
    const region = Region{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x3000,
        .writable = true,
        .kind = .shared_ram,
        .physical_base = 0xF000_0000,
        .protection_key = 6,
    };
    var model = UserCopyTestModel{ .allow_borrowed = true };
    try std.testing.expect(resolveRegionFault(UserCopyTestPaging, &model, &region, UserCopyTestModel.base + 0x1007, true, false));
    try std.testing.expect(model.pages[1].present and !model.pages[1].owned and model.pages[1].writable);
    try std.testing.expect(!model.pages[1].executable);
    try std.testing.expectEqual(@as(u64, 0xF000_1000), model.borrowed_physical);
    try std.testing.expect(!model.borrowed_cache_disabled);
    try std.testing.expectEqual(@as(u4, 6), model.borrowed_protection_key);
    try std.testing.expectEqual(@as(usize, 1), model.borrowed_mappings);
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    try std.testing.expectEqual(@as(usize, 0), model.copies);
    try std.testing.expect(resolveRegionFault(UserCopyTestPaging, &model, &region, UserCopyTestModel.base + 0x1007, true, false));
    try std.testing.expectEqual(@as(usize, 1), model.borrowed_mappings);
}

test "borrowed physical faults reject overflowing backing offsets before mapping" {
    const region = Region{
        .virt_start = UserCopyTestModel.base,
        .virt_end_exclusive = UserCopyTestModel.base + 0x3000,
        .writable = true,
        .kind = .shared_ram,
        .physical_base = std.math.maxInt(u64) & ~@as(u64, 0xFFF),
    };
    var model = UserCopyTestModel{ .allow_borrowed = true };
    model.pages[1].value = 0x42;
    try std.testing.expect(!resolveRegionFault(UserCopyTestPaging, &model, &region, UserCopyTestModel.base + 0x1000, true, false));
    try std.testing.expect(!model.pages[1].present);
    try std.testing.expectEqual(@as(u8, 0x42), model.pages[1].value);
    try std.testing.expectEqual(@as(usize, 0), model.mapping_attempts);
    try std.testing.expectEqual(@as(usize, 0), model.borrowed_mappings);
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    try std.testing.expectEqual(@as(usize, 0), model.copies);
}

test "demand faults reject first partial page underflow before any mapping or promotion" {
    for ([_]Kind{ .anonymous_zero, .shared_ram, .object_cow }) |kind| {
        const region = Region{
            .virt_start = UserCopyTestModel.base + 1,
            .virt_end_exclusive = UserCopyTestModel.base + 0x1000,
            .writable = true,
            .kind = kind,
            .physical_base = 0x8000,
        };
        var model = UserCopyTestModel{ .allow_borrowed = true };
        model.pages[0].value = 0x42;
        try std.testing.expect(!resolveRegionFault(UserCopyTestPaging, &model, &region, region.virt_start, true, false));
        try std.testing.expect(!model.pages[0].present);
        try std.testing.expectEqual(@as(u8, 0x42), model.pages[0].value);
        try std.testing.expectEqual(@as(usize, 0), model.mapping_attempts);
        try std.testing.expectEqual(@as(usize, 0), model.borrowed_mappings);
        try std.testing.expectEqual(@as(usize, 0), model.allocations);
        try std.testing.expectEqual(@as(usize, 0), model.copies);
        model.pages[0].present = true;
        try std.testing.expect(!resolveRegionFault(UserCopyTestPaging, &model, &region, region.virt_start, true, true));
        try std.testing.expect(!model.pages[0].writable);
        try std.testing.expectEqual(@as(usize, 0), model.promotions);
    }
}
