const std = @import("std");
const shared_memory = @import("shared_memory.zig");
const ids = @import("../core/ids.zig");
const userspace_layout = @import("../core/userspace_layout.zig");
const Table = shared_memory.Table;
const MappingLifetime = shared_memory.MappingLifetime;
const FreestandingMappingDescriptor = shared_memory.FreestandingMappingDescriptor;
const MAX_SHARED_MEMORY_OBJECTS = shared_memory.MAX_SHARED_MEMORY_OBJECTS;
const MAX_MAPPINGS_PER_OBJECT = shared_memory.MAX_MAPPINGS_PER_OBJECT;
const PAGE_SIZE = shared_memory.PAGE_SIZE;
const MAPPING_EDGE_CAPACITY = MAX_SHARED_MEMORY_OBJECTS * MAX_MAPPINGS_PER_OBJECT;
const MMU_MAPPING_CAPACITY = MAX_SHARED_MEMORY_OBJECTS * shared_memory.MMU_OBJECT_MAPPING_SCAN_BOUND;
const TASK_SHARED_VIRTUAL_BASE = userspace_layout.shared_start;

const TestDemandMappingLifetime = struct {
    const demand = @import("../../kernel/memory/demand_paging.zig");
    space: u8 = 1,
    reject_registration: bool = false,
    registered: [MAPPING_EDGE_CAPACITY]?FreestandingMappingDescriptor = @splat(null),
    registrations: usize = 0,
    unregistrations: usize = 0,
    saw_unpublished_registration: bool = false,
    saw_live_teardown: bool = false,

    fn lifetime(self: *@This()) MappingLifetime {
        return .{ .context = self, .register = register, .unregister = unregister };
    }

    fn register(context: *anyopaque, table: *Table, mapping: FreestandingMappingDescriptor, writable: bool, cow: bool) ?u64 {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.reject_registration) return null;
        if (table.hasMapping(mapping.object_id, mapping.task_id)) return null;
        const end = std.math.add(u64, mapping.virtual_base, mapping.size_bytes) catch return null;
        if (demand.regionOverlapsSpace(&self.space, mapping.virtual_base, end)) return null;
        for (&self.registered) |*entry| {
            if (entry.* != null) continue;
            if (!demand.registerForSpace(&self.space, .{
                .virt_start = mapping.virtual_base,
                .virt_end_exclusive = end,
                .writable = writable,
                .kind = if (cow) .object_cow else .object_physical,
                .physical_base = mapping.physical_base,
            })) return null;
            entry.* = mapping;
            self.registrations += 1;
            self.saw_unpublished_registration = true;
            return mapping.task_id.raw();
        }
        return null;
    }

    fn unregister(context: *anyopaque, table: *Table, token: u64, mapping: FreestandingMappingDescriptor) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (token != mapping.task_id.raw() or !table.hasMapping(mapping.object_id, mapping.task_id)) return false;
        for (&self.registered) |*entry| {
            const registered = entry.* orelse continue;
            if (!registered.object_id.eql(mapping.object_id) or !registered.task_id.eql(mapping.task_id) or
                registered.virtual_base != mapping.virtual_base or registered.physical_base != mapping.physical_base or
                registered.size_bytes != mapping.size_bytes) continue;
            const end = std.math.add(u64, mapping.virtual_base, mapping.size_bytes) catch return false;
            if (!demand.unregisterRegionForSpace(&self.space, mapping.virtual_base, end)) return false;
            entry.* = null;
            self.unregistrations += 1;
            self.saw_live_teardown = true;
            return true;
        }
        return false;
    }
};

test "shared mapping lifetime unmap and revoke remove access before address reuse" {
    const demand = @import("../../kernel/memory/demand_paging.zig");
    demand.reset();
    defer demand.reset();
    var context = TestDemandMappingLifetime{};
    var table = Table.initWithMappingLifetime(context.lifetime());
    defer table.deinit();
    const owner = ids.task(7);
    const peer = ids.task(8);
    const object = try table.create(owner, PAGE_SIZE);
    try table.map(object.id, owner);
    try table.map(object.id, peer);
    const first = try table.freestandingTaskMappingDescriptor(object.id, owner);
    const second = try table.freestandingTaskMappingDescriptor(object.id, peer);
    var foreign_space: u8 = 2;
    try std.testing.expect(demand.registerForSpace(&foreign_space, .{
        .virt_start = first.virtual_base,
        .virt_end_exclusive = first.virtual_base + PAGE_SIZE,
        .writable = true,
    }));
    const unrelated = TASK_SHARED_VIRTUAL_BASE + 0x10_0000;
    try std.testing.expect(demand.registerForSpace(&context.space, .{
        .virt_start = unrelated,
        .virt_end_exclusive = unrelated + PAGE_SIZE,
        .writable = true,
    }));
    try std.testing.expect(demand.resolveFault(&context.space, first.virtual_base, 4));
    try std.testing.expect(try table.unmap(object.id, owner));
    try std.testing.expect(!demand.resolveFault(&context.space, first.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&context.space, second.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&foreign_space, first.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&context.space, unrelated, 4));
    _ = try table.revoke(object.id);
    try std.testing.expect(!demand.resolveFault(&context.space, second.virtual_base, 4));
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
    const replacement = try table.create(owner, PAGE_SIZE);
    try std.testing.expect(!replacement.id.eql(object.id));
    try table.map(replacement.id, owner);
    const reused = try table.freestandingTaskMappingDescriptor(replacement.id, owner);
    try std.testing.expectEqual(first.virtual_base, reused.virtual_base);
    try std.testing.expect(demand.resolveFault(&context.space, reused.virtual_base, 4));
    try std.testing.expectError(error.SharedMemoryNotFound, table.unmap(object.id, owner));
    _ = try table.revoke(replacement.id);
    try std.testing.expect(!demand.resolveFault(&context.space, reused.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&foreign_space, first.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&context.space, unrelated, 4));
    try std.testing.expect(context.saw_unpublished_registration and context.saw_live_teardown);
    try std.testing.expectEqual(context.registrations, context.unregistrations);
}

test "shared mapping lifetime registration failure rolls back capacity and virtual reservation" {
    const demand = @import("../../kernel/memory/demand_paging.zig");
    demand.reset();
    defer demand.reset();
    var context = TestDemandMappingLifetime{ .reject_registration = true };
    var table = Table.initWithMappingLifetime(context.lifetime());
    defer table.deinit();
    const object = try table.create(ids.task(7), PAGE_SIZE);
    const first_page: u64 = 1;
    for (0..MMU_MAPPING_CAPACITY + 1) |_| {
        try std.testing.expectError(error.MappingRegistrationFailed, table.map(object.id, ids.task(7)));
        try std.testing.expectEqual(@as(usize, 0), table.mappingsForTask(ids.task(7)));
        try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
        try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(object.id)).mapped_task_count);
    }
    context.reject_registration = false;
    const foreign_start: u64 = 0x6000_0000;
    for (0..demand.MAX_REGIONS) |index| {
        const start = foreign_start + index * PAGE_SIZE;
        try std.testing.expect(demand.registerForSpace(&context.space, .{
            .virt_start = start,
            .virt_end_exclusive = start + PAGE_SIZE,
            .writable = true,
        }));
    }
    try std.testing.expectError(error.MappingRegistrationFailed, table.map(object.id, ids.task(7)));
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
    for (0..demand.MAX_REGIONS) |index| {
        const start = foreign_start + index * PAGE_SIZE;
        try std.testing.expect(demand.resolveFault(&context.space, start, 4));
        try std.testing.expect(demand.unregisterRegionForSpace(&context.space, start, start + PAGE_SIZE));
    }
    for (0..MAX_MAPPINGS_PER_OBJECT) |index| try table.map(object.id, ids.task(7 + index));
    try std.testing.expectEqual(MAX_MAPPINGS_PER_OBJECT, table.activeFreestandingMappings(object.id));
    try std.testing.expectEqual(TASK_SHARED_VIRTUAL_BASE + first_page * PAGE_SIZE, (try table.freestandingTaskMappingDescriptor(object.id, ids.task(7))).virtual_base);
    for (0..MAX_MAPPINGS_PER_OBJECT) |index| try std.testing.expect(table.hasMapping(object.id, ids.task(7 + index)));
    _ = try table.revoke(object.id);
    try std.testing.expectEqual(context.registrations, context.unregistrations);
}

test "shared mapping lifetime task retirement tears down owned and peer access" {
    const demand = @import("../../kernel/memory/demand_paging.zig");
    demand.reset();
    defer demand.reset();
    var context = TestDemandMappingLifetime{};
    var table = Table.initWithMappingLifetime(context.lifetime());
    defer table.deinit();
    const owned = try table.create(ids.task(10), PAGE_SIZE);
    const peer = try table.create(ids.task(20), PAGE_SIZE);
    try table.map(owned.id, ids.task(10));
    try table.map(owned.id, ids.task(11));
    try table.map(peer.id, ids.task(10));
    try table.map(peer.id, ids.task(11));
    const owned_owner = try table.freestandingTaskMappingDescriptor(owned.id, ids.task(10));
    const owned_peer = try table.freestandingTaskMappingDescriptor(owned.id, ids.task(11));
    const retired_peer = try table.freestandingTaskMappingDescriptor(peer.id, ids.task(10));
    const survivor = try table.freestandingTaskMappingDescriptor(peer.id, ids.task(11));
    const retired = table.retireTask(ids.task(10));
    try std.testing.expectEqual(@as(u16, 1), retired.revoked_owned_objects);
    try std.testing.expectEqual(@as(u16, 1), retired.removed_peer_mappings);
    try std.testing.expect(!demand.resolveFault(&context.space, owned_owner.virtual_base, 4));
    try std.testing.expect(!demand.resolveFault(&context.space, owned_peer.virtual_base, 4));
    try std.testing.expect(!demand.resolveFault(&context.space, retired_peer.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&context.space, survivor.virtual_base, 4));
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(peer.id));
    try std.testing.expectEqual(@as(usize, 0), table.mappingsForTask(ids.task(10)));
    table.deinit();
    try std.testing.expect(!demand.resolveFault(&context.space, survivor.virtual_base, 4));
    try std.testing.expectEqual(context.registrations, context.unregistrations);
}

test "shared mapping lifetime address-space retirement preserves peer objects and permits remap" {
    const demand = @import("../../kernel/memory/demand_paging.zig");
    demand.reset();
    defer demand.reset();
    var context = TestDemandMappingLifetime{};
    var table = Table.initWithMappingLifetime(context.lifetime());
    const first = try table.create(ids.task(7), PAGE_SIZE);
    const ring = try table.createSealedRing(ids.task(8), ids.task(7), PAGE_SIZE);
    try table.map(first.id, ids.task(7));
    try table.map(first.id, ids.task(8));
    const old = try table.freestandingTaskMappingDescriptor(first.id, ids.task(7));
    const ring_old = try table.freestandingTaskMappingDescriptor(ring.id, ids.task(7));
    const peer = try table.freestandingTaskMappingDescriptor(first.id, ids.task(8));
    const ring_peer = try table.freestandingTaskMappingDescriptor(ring.id, ids.task(8));
    table.retireMappingLifetime(7);
    try std.testing.expectEqual(@as(usize, 0), table.mappingsForTask(ids.task(7)));
    try std.testing.expectEqual(@as(usize, 2), table.activeCount());
    try std.testing.expect(!demand.resolveFault(&context.space, old.virtual_base, 4));
    try std.testing.expect(!demand.resolveFault(&context.space, ring_old.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&context.space, peer.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&context.space, ring_peer.virtual_base, 4));
    try table.map(first.id, ids.task(7));
    const replacement = try table.freestandingTaskMappingDescriptor(first.id, ids.task(7));
    try std.testing.expect(replacement.virtual_base != old.virtual_base);
    try std.testing.expect(!demand.resolveFault(&context.space, old.virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&context.space, replacement.virtual_base, 4));
    table.deinit();
    try std.testing.expect(!demand.resolveFault(&context.space, replacement.virtual_base, 4));
    try std.testing.expect(!demand.resolveFault(&context.space, peer.virtual_base, 4));
    try std.testing.expect(!demand.resolveFault(&context.space, ring_peer.virtual_base, 4));
    try std.testing.expectEqual(context.registrations, context.unregistrations);
}
