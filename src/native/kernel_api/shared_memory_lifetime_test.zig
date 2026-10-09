const std = @import("std");
const shared_memory = @import("shared_memory.zig");
const ids = @import("../core/ids.zig");
const userspace_layout = @import("../core/userspace_layout.zig");
const Table = shared_memory.Table;
const MappingLifetime = shared_memory.MappingLifetime;
const FreestandingMappingDescriptor = shared_memory.FreestandingMappingDescriptor;
const TaskCopySpan = shared_memory.TaskCopySpan;
const MAX_SHARED_MEMORY_OBJECTS = shared_memory.MAX_SHARED_MEMORY_OBJECTS;
const MAX_MAPPINGS_PER_OBJECT = shared_memory.MAX_MAPPINGS_PER_OBJECT;
const PAGE_SIZE = shared_memory.PAGE_SIZE;
const MAPPING_EDGE_CAPACITY = MAX_SHARED_MEMORY_OBJECTS * MAX_MAPPINGS_PER_OBJECT;
const MMU_MAPPING_CAPACITY = MAX_SHARED_MEMORY_OBJECTS * shared_memory.MMU_OBJECT_MAPPING_SCAN_BOUND;
const TASK_SHARED_VIRTUAL_BASE = userspace_layout.shared_start;
const task_copy_canary = TaskCopySpan{ .virtual_base = 0x1122, .physical_base = 0x3344, .size_bytes = 0x5566 };

fn expectCopyRejected(
    expected: anyerror,
    table: *const Table,
    task_id: ids.TaskId,
    token: u64,
    start: u64,
    len: usize,
) !void {
    var span = task_copy_canary;
    try std.testing.expectError(expected, table.taskCopySpanInto(task_id, token, start, len, &span));
    try std.testing.expectEqualDeep(task_copy_canary, span);
}

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
                .kind = if (cow) .object_cow else .shared_ram,
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

test "shared mapping lifetime swap removal unregisters each mapping exactly once" {
    const demand = @import("../../kernel/memory/demand_paging.zig");
    demand.reset();
    defer demand.reset();
    var context = TestDemandMappingLifetime{};
    var table = Table.initWithMappingLifetime(context.lifetime());
    defer table.deinit();
    const object = try table.create(ids.task(7), PAGE_SIZE);
    var descriptors: [MAX_MAPPINGS_PER_OBJECT]FreestandingMappingDescriptor = undefined;
    for (&descriptors, 0..) |*descriptor, index| {
        const task_id = ids.task(100 + index);
        try table.map(object.id, task_id);
        descriptor.* = try table.freestandingTaskMappingDescriptor(object.id, task_id);
    }

    // The first removal relocates the tail. Remove that survivor through the
    // task index, a middle entry through unmap, then the current tail.
    try std.testing.expect(try table.unmap(object.id, ids.task(100)));
    try std.testing.expectEqual(@as(usize, 1), context.unregistrations);
    try std.testing.expect(!demand.resolveFault(&context.space, descriptors[0].virtual_base, 4));
    try std.testing.expect(demand.resolveFault(&context.space, descriptors[MAX_MAPPINGS_PER_OBJECT - 1].virtual_base, 4));
    const retired = table.retireTask(ids.task(100 + MAX_MAPPINGS_PER_OBJECT - 1));
    try std.testing.expectEqual(@as(u16, 1), retired.removed_peer_mappings);
    try std.testing.expectEqual(@as(usize, 2), context.unregistrations);
    try std.testing.expect(try table.unmap(object.id, ids.task(103)));
    try std.testing.expectEqual(@as(usize, 3), context.unregistrations);
    try std.testing.expect(try table.unmap(object.id, ids.task(104)));
    try std.testing.expectEqual(@as(usize, 4), context.unregistrations);
    try std.testing.expect(!try table.unmap(object.id, ids.task(104)));
    try std.testing.expectEqual(@as(usize, 4), context.unregistrations);

    for (descriptors, 0..) |descriptor, index| {
        const removed = index == 0 or index == MAX_MAPPINGS_PER_OBJECT - 1 or index == 3 or index == 4;
        try std.testing.expectEqual(!removed, demand.resolveFault(&context.space, descriptor.virtual_base, 4));
        if (!removed) {
            try std.testing.expectEqualDeep(descriptor, try table.freestandingTaskMappingDescriptor(object.id, descriptor.task_id));
        }
    }
    _ = try table.revoke(object.id);
    try std.testing.expectEqual(MAX_MAPPINGS_PER_OBJECT, context.unregistrations);
    try std.testing.expectEqual(context.registrations, context.unregistrations);
    for (descriptors) |descriptor| {
        try std.testing.expect(!demand.resolveFault(&context.space, descriptor.virtual_base, 4));
    }
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
    table.retireTaskMappingLifetime(ids.task(7), 7);
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

const RoutedDemandMappingLifetime = struct {
    const demand = @import("../../kernel/memory/demand_paging.zig");
    const Route = struct {
        task_id: ids.TaskId,
        token: u64,
        space: u8 = 0,
        mappings: [MAX_SHARED_MEMORY_OBJECTS]?FreestandingMappingDescriptor = @splat(null),
        registrations: usize = 0,
        unregistrations: usize = 0,
    };
    routes: [2]Route,

    fn lifetime(self: *@This()) MappingLifetime {
        return .{ .context = self, .register = register, .unregister = unregister };
    }

    fn routeFor(self: *@This(), task_id: ids.TaskId) ?*Route {
        for (&self.routes) |*route| if (route.task_id.eql(task_id)) return route;
        return null;
    }

    fn register(context: *anyopaque, table: *Table, mapping: FreestandingMappingDescriptor, writable: bool, cow: bool) ?u64 {
        const self: *@This() = @ptrCast(@alignCast(context));
        const route = self.routeFor(mapping.task_id) orelse return null;
        if (table.hasMapping(mapping.object_id, mapping.task_id)) return null;
        const end = std.math.add(u64, mapping.virtual_base, mapping.size_bytes) catch return null;
        for (&route.mappings) |*entry| {
            if (entry.* != null) continue;
            if (!demand.registerForSpace(&route.space, .{
                .virt_start = mapping.virtual_base,
                .virt_end_exclusive = end,
                .writable = writable,
                .kind = if (cow) .object_cow else .shared_ram,
                .physical_base = mapping.physical_base,
            })) return null;
            entry.* = mapping;
            route.registrations += 1;
            return route.token;
        }
        return null;
    }

    fn unregister(context: *anyopaque, table: *Table, token: u64, mapping: FreestandingMappingDescriptor) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        const route = self.routeFor(mapping.task_id) orelse return false;
        if (token != route.token or !table.hasMapping(mapping.object_id, mapping.task_id)) return false;
        for (&route.mappings) |*entry| {
            const registered = entry.* orelse continue;
            if (!std.meta.eql(registered, mapping)) continue;
            const end = std.math.add(u64, mapping.virtual_base, mapping.size_bytes) catch return false;
            if (!demand.unregisterRegionForSpace(&route.space, mapping.virtual_base, end)) return false;
            entry.* = null;
            route.unregistrations += 1;
            return true;
        }
        return false;
    }
};

test "shared mapping lifetime task retirement isolates equal opaque tokens across full routed capacity" {
    const demand = @import("../../kernel/memory/demand_paging.zig");
    demand.reset();
    defer demand.reset();
    const equal_token: u64 = 0x0000_0001_0000_0001;
    const owner = ids.task(701);
    const peer = ids.task(702);
    var context = RoutedDemandMappingLifetime{ .routes = .{
        .{ .task_id = owner, .token = equal_token },
        .{ .task_id = peer, .token = equal_token },
    } };
    var table = Table.initWithMappingLifetime(context.lifetime());
    defer table.deinit();
    var objects: [MAX_SHARED_MEMORY_OBJECTS]ids.SharedMemoryId = undefined;
    var owner_mappings: [MAX_SHARED_MEMORY_OBJECTS]FreestandingMappingDescriptor = undefined;
    var peer_mappings: [MAX_SHARED_MEMORY_OBJECTS]FreestandingMappingDescriptor = undefined;
    for (&objects, &owner_mappings, &peer_mappings, 0..) |*object_id, *first, *second, index| {
        // Reverse membership order on alternating objects exercises both
        // tail removal and task-index relocation of the surviving peer.
        const object = try table.create(if (index % 2 == 0) owner else peer, PAGE_SIZE + 7);
        try table.map(object.id, if (index % 2 == 0) owner else peer);
        try table.map(object.id, if (index % 2 == 0) peer else owner);
        object_id.* = object.id;
        first.* = try table.freestandingTaskMappingDescriptor(object.id, owner);
        second.* = try table.freestandingTaskMappingDescriptor(object.id, peer);
    }
    try std.testing.expectEqual(@as(u16, MAX_SHARED_MEMORY_OBJECTS), table.mappingsForTask(owner));
    try std.testing.expectEqual(@as(u16, MAX_SHARED_MEMORY_OBJECTS), table.mappingsForTask(peer));
    table.retireTaskMappingLifetime(ids.TaskId.zero, equal_token);
    table.retireTaskMappingLifetime(ids.task(703), equal_token);
    table.retireTaskMappingLifetime(owner, 0);
    table.retireTaskMappingLifetime(owner, equal_token + 1);
    try std.testing.expectEqual(@as(usize, 0), context.routes[0].unregistrations);
    try std.testing.expectEqual(@as(usize, 0), context.routes[1].unregistrations);
    table.retireTaskMappingLifetime(owner, equal_token);
    try std.testing.expectEqual(@as(u16, 0), table.mappingsForTask(owner));
    try std.testing.expectEqual(@as(u16, MAX_SHARED_MEMORY_OBJECTS), table.mappingsForTask(peer));
    try std.testing.expectEqual(MAX_SHARED_MEMORY_OBJECTS, table.activeCount());
    try std.testing.expectEqual(MAX_SHARED_MEMORY_OBJECTS, context.routes[0].unregistrations);
    try std.testing.expectEqual(@as(usize, 0), context.routes[1].unregistrations);
    for (objects, owner_mappings, peer_mappings) |object_id, first, second| {
        try expectCopyRejected(error.MappingNotFound, &table, owner, equal_token, first.virtual_base, 1);
        try std.testing.expect(!demand.resolveFault(&context.routes[0].space, first.virtual_base, 4));
        try std.testing.expect(demand.resolveFault(&context.routes[1].space, second.virtual_base, 4));
        try std.testing.expectEqualDeep(second, try table.freestandingTaskMappingDescriptor(object_id, peer));
        var span = task_copy_canary;
        try table.taskCopySpanInto(peer, equal_token, second.virtual_base, PAGE_SIZE + 7, &span);
        try std.testing.expectEqual(second.physical_base, span.physical_base);
    }
    // The rematerialized owner has a new full generation. A stale receipt
    // cannot remove it or the peer's still-live numerically equal old token.
    context.routes[0].token += @as(u64, 1) << 32;
    for (objects) |object_id| {
        try table.map(object_id, owner);
        const replacement = try table.freestandingTaskMappingDescriptor(object_id, owner);
        try expectCopyRejected(error.StaleMappingDescriptor, &table, owner, equal_token, replacement.virtual_base, 1);
    }
    table.retireTaskMappingLifetime(owner, equal_token);
    try std.testing.expectEqual(@as(u16, MAX_SHARED_MEMORY_OBJECTS), table.mappingsForTask(owner));
    try std.testing.expectEqual(@as(usize, 0), context.routes[1].unregistrations);
    table.retireTaskMappingLifetime(peer, equal_token);
    try std.testing.expectEqual(@as(u16, 0), table.mappingsForTask(peer));
    try std.testing.expectEqual(@as(u16, MAX_SHARED_MEMORY_OBJECTS), table.mappingsForTask(owner));
    table.retireTaskMappingLifetime(owner, context.routes[0].token);
    try std.testing.expectEqual(@as(u16, 0), table.mappingsForTask(owner));
    try std.testing.expectEqual(@as(usize, 2 * MAX_SHARED_MEMORY_OBJECTS), context.routes[0].unregistrations);
    try std.testing.expectEqual(MAX_SHARED_MEMORY_OBJECTS, context.routes[1].unregistrations);
}

// This hosted fixture owns genuine frame-allocator runs and dirty byte storage.
// It exercises the same zero/publication/release transaction used in production.
const OwnedPhysicalFixture = struct {
    const frame = @import("../../kernel/memory/frame_allocator.zig");
    const Allocator = frame.Fixed(64 * PAGE_SIZE, PAGE_SIZE);
    const physical_base: u64 = 0x1_0000_0000;
    storage: Allocator.Storage = undefined,
    allocator: Allocator = undefined,
    memory: [64 * PAGE_SIZE]u8 = @splat(0xa5),
    mappings: [MAPPING_EDGE_CAPACITY]?FreestandingMappingDescriptor = @splat(null),
    tokens: [MAPPING_EDGE_CAPACITY]u64 = @splat(0),
    next_token: u64 = 1,
    reject_allocation: bool = false,
    reject_bytes_once: bool = false,
    reject_registration: bool = false,
    allocations: usize = 0,
    releases: usize = 0,
    registrations: usize = 0,
    unregistrations: usize = 0,
    released_with_live_mapping: bool = false,
    released_erased: usize = 0,
    probe_unpublished_copy: bool = false,
    unpublished_copy_denials: usize = 0,
    unpublished_copy_admitted: bool = false,
    unpublished_copy_output_changed: bool = false,

    fn init(self: *@This()) void {
        self.allocator = Allocator.init(&self.storage);
    }

    fn backing(self: *@This()) shared_memory.HostedPhysicalBacking {
        return .{ .context = self, .allocate = allocate, .bytes = bytes, .release = release };
    }

    fn lifetime(self: *@This()) MappingLifetime {
        return .{ .context = self, .register = register, .unregister = unregister };
    }

    fn allocate(context: *anyopaque, count: u32) ?u64 {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.reject_allocation) return null;
        const run = self.allocator.allocate(count) orelse return null;
        self.allocations += 1;
        return physical_base + run.base;
    }

    fn bytes(context: *anyopaque, base: u64, count: u32) ?[]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.reject_bytes_once) {
            self.reject_bytes_once = false;
            return null;
        }
        if (base < physical_base or base % PAGE_SIZE != 0) return null;
        const relative = base - physical_base;
        const end = std.math.add(u64, relative, @as(u64, count) * PAGE_SIZE) catch return null;
        if (end > self.memory.len) return null;
        for (0..count) |index| {
            if (!self.allocator.isAllocated(relative + index * PAGE_SIZE)) return null;
        }
        return self.memory[@intCast(relative)..@intCast(end)];
    }

    fn release(context: *anyopaque, base: u64, count: u32) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const run_bytes = bytes(context, base, count).?;
        for (self.mappings) |entry| {
            if (entry) |mapping| {
                if (mapping.physical_base == base) self.released_with_live_mapping = true;
            }
        }
        if (std.mem.allEqual(u8, run_bytes, 0)) self.released_erased += 1;
        self.allocator.release(.{ .base = base - physical_base, .count = count }) catch unreachable;
        self.releases += 1;
    }

    fn register(context: *anyopaque, table: *Table, mapping: FreestandingMappingDescriptor, writable: bool, cow: bool) ?u64 {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.reject_registration) return null;
        std.debug.assert(writable and !cow);
        std.debug.assert(!table.hasMapping(mapping.object_id, mapping.task_id));
        _ = bytes(context, mapping.physical_base, @intCast(mapping.page_count)) orelse return null;
        for (&self.mappings, &self.tokens) |*entry, *token| {
            if (entry.* != null) continue;
            entry.* = mapping;
            token.* = self.next_token;
            self.next_token += 1;
            self.registrations += 1;
            if (self.probe_unpublished_copy) {
                var span = task_copy_canary;
                const denied = blk: {
                    table.taskCopySpanInto(mapping.task_id, token.*, mapping.virtual_base, mapping.size_bytes, &span) catch
                        break :blk true;
                    break :blk false;
                };
                if (denied) self.unpublished_copy_denials += 1 else self.unpublished_copy_admitted = true;
                if (!std.meta.eql(span, task_copy_canary)) self.unpublished_copy_output_changed = true;
            }
            return token.*;
        }
        return null;
    }

    fn unregister(context: *anyopaque, table: *Table, token: u64, mapping: FreestandingMappingDescriptor) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (!table.hasMapping(mapping.object_id, mapping.task_id)) return false;
        if (bytes(context, mapping.physical_base, @intCast(mapping.page_count)) == null) return false;
        for (&self.mappings, &self.tokens) |*entry, *registered_token| {
            const prior = entry.* orelse continue;
            if (registered_token.* != token or !prior.object_id.eql(mapping.object_id) or
                !prior.task_id.eql(mapping.task_id) or prior.virtual_base != mapping.virtual_base or
                prior.physical_base != mapping.physical_base or prior.page_count != mapping.page_count or
                prior.size_bytes != mapping.size_bytes) continue;
            entry.* = null;
            registered_token.* = 0;
            self.unregistrations += 1;
            return true;
        }
        return false;
    }

    fn taskBytes(self: *@This(), task_id: ids.TaskId) ?[]u8 {
        for (self.mappings) |entry| {
            const mapping = entry orelse continue;
            if (mapping.task_id.eql(task_id)) return bytes(self, mapping.physical_base, @intCast(mapping.page_count));
        }
        return null;
    }

    fn tokenFor(self: *const @This(), object_id: ids.SharedMemoryId, task_id: ids.TaskId) ?u64 {
        for (self.mappings, self.tokens) |entry, token| {
            const mapping = entry orelse continue;
            if (mapping.object_id.eql(object_id) and mapping.task_id.eql(task_id)) return token;
        }
        return null;
    }
};

test "shared copy authority binds exact task lifetime and returns only logical mapping bounds" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const owner = ids.task(601);
    const peer = ids.task(602);
    const object = try table.createSealedRing(owner, peer, PAGE_SIZE + 7);
    const mapping = try table.freestandingTaskMappingDescriptor(object.id, owner);
    const peer_mapping = try table.freestandingTaskMappingDescriptor(object.id, peer);
    const token = fixture.tokenFor(object.id, owner).?;
    const peer_token = fixture.tokenFor(object.id, peer).?;
    var span = task_copy_canary;
    try table.taskCopySpanInto(owner, token, mapping.virtual_base + PAGE_SIZE - 1, 8, &span);
    try std.testing.expectEqualDeep(TaskCopySpan{
        .virtual_base = mapping.virtual_base,
        .physical_base = object.page_base,
        .size_bytes = PAGE_SIZE + 7,
    }, span);
    try table.taskCopySpanInto(peer, peer_token, peer_mapping.virtual_base, object.size_bytes, &span);
    try std.testing.expectEqual(peer_mapping.virtual_base, span.virtual_base);
    try std.testing.expectEqual(object.page_base, span.physical_base);
    try expectCopyRejected(error.StaleMappingDescriptor, &table, owner, peer_token, mapping.virtual_base, 1);
    try expectCopyRejected(error.MappingNotFound, &table, peer, peer_token, mapping.virtual_base, 1);
    try expectCopyRejected(error.MappingNotFound, &table, ids.task(603), token, mapping.virtual_base, 1);
    try expectCopyRejected(error.MappingRegistrationFailed, &table, owner, 0, mapping.virtual_base, 1);
    try expectCopyRejected(error.MappingNotFound, &table, ids.TaskId.zero, token, mapping.virtual_base, 1);
}

test "shared copy rejects padding cross-object spans and overflowing ranges without publishing output" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const task = ids.task(611);
    const first = try table.create(task, PAGE_SIZE + 7);
    const second = try table.create(task, PAGE_SIZE);
    try table.map(first.id, task);
    try table.map(second.id, task);
    const mapping = try table.freestandingTaskMappingDescriptor(first.id, task);
    const next = try table.freestandingTaskMappingDescriptor(second.id, task);
    const token = fixture.tokenFor(first.id, task).?;
    try std.testing.expectEqual(mapping.virtual_base + 2 * PAGE_SIZE, next.virtual_base);
    try expectCopyRejected(error.MappingDescriptorMismatch, &table, task, token, mapping.virtual_base + PAGE_SIZE, 8);
    try expectCopyRejected(error.MappingNotFound, &table, task, token, mapping.virtual_base + first.size_bytes, 1);
    try expectCopyRejected(error.MappingDescriptorMismatch, &table, task, token, mapping.virtual_base, 3 * PAGE_SIZE);
    try expectCopyRejected(error.MappingNotFound, &table, task, token, mapping.virtual_base - 1, 2 * PAGE_SIZE + 2);
    try expectCopyRejected(error.MappingDescriptorMismatch, &table, task, token, std.math.maxInt(u64), 1);
    try expectCopyRejected(error.MappingDescriptorMismatch, &table, task, token, mapping.virtual_base, std.math.maxInt(usize));
    try expectCopyRejected(error.SizeZero, &table, task, token, mapping.virtual_base, 0);
    {
        const slot = table.backing.arena.getByHandle(.{ .value = first.id.raw() }).?;
        slot.object.page_base = std.math.maxInt(u64) & ~@as(u64, PAGE_SIZE - 1);
        defer slot.object.page_base = first.page_base;
        try expectCopyRejected(error.MappingDescriptorMismatch, &table, task, token, mapping.virtual_base, 1);
    }
    {
        const slot = table.backing.arena.getByHandle(.{ .value = first.id.raw() }).?;
        slot.object.size_bytes = std.math.maxInt(usize);
        defer slot.object.size_bytes = first.size_bytes;
        try expectCopyRejected(error.MappingDescriptorMismatch, &table, task, token, mapping.virtual_base, 1);
    }
    try std.testing.expectEqual(@as(usize, 2), table.mappingsForTask(task));
    try std.testing.expectEqual(@as(u32, 3), fixture.allocator.stats().allocated);
}

test "host metadata-only mapping cannot authorize a supervisor copy without registered lifetime" {
    var table = Table.init();
    defer table.deinit();
    const task = ids.task(615);
    const object = try table.create(task, PAGE_SIZE);
    try table.map(object.id, task);
    const mapping = try table.freestandingTaskMappingDescriptor(object.id, task);
    try expectCopyRejected(error.StaleMappingDescriptor, &table, task, 1, mapping.virtual_base, PAGE_SIZE);
    try expectCopyRejected(error.MappingRegistrationFailed, &table, task, 0, mapping.virtual_base, PAGE_SIZE);
}

test "shared copy registration reentry cannot authorize an unpublished task membership" {
    var fixture = OwnedPhysicalFixture{ .probe_unpublished_copy = true };
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const owner = ids.task(621);
    const peer = ids.task(622);
    const object = try table.createSealedRing(owner, peer, PAGE_SIZE);
    try std.testing.expectEqual(@as(usize, 2), fixture.unpublished_copy_denials);
    try std.testing.expect(!fixture.unpublished_copy_admitted and !fixture.unpublished_copy_output_changed);
    const mapping = try table.freestandingTaskMappingDescriptor(object.id, peer);
    var span = task_copy_canary;
    try table.taskCopySpanInto(peer, fixture.tokenFor(object.id, peer).?, mapping.virtual_base, PAGE_SIZE, &span);
    try std.testing.expectEqual(mapping.virtual_base, span.virtual_base);
}

test "shared copy unmap retirement and generational slot reuse invalidate prior authority" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const task = ids.task(631);
    const object = try table.create(task, PAGE_SIZE);
    try table.map(object.id, task);
    const original = try table.freestandingTaskMappingDescriptor(object.id, task);
    const old_token = fixture.tokenFor(object.id, task).?;
    try std.testing.expect(try table.unmap(object.id, task));
    try expectCopyRejected(error.MappingNotFound, &table, task, old_token, original.virtual_base, 1);
    try table.map(object.id, task);
    const remapped = try table.freestandingTaskMappingDescriptor(object.id, task);
    const remapped_token = fixture.tokenFor(object.id, task).?;
    try expectCopyRejected(error.StaleMappingDescriptor, &table, task, old_token, remapped.virtual_base, 1);
    table.retireTaskMappingLifetime(task, remapped_token);
    try expectCopyRejected(error.MappingNotFound, &table, task, remapped_token, remapped.virtual_base, 1);
    try table.map(object.id, task);
    const revoked = try table.freestandingTaskMappingDescriptor(object.id, task);
    const revoked_token = fixture.tokenFor(object.id, task).?;
    _ = try table.revoke(object.id);
    try expectCopyRejected(error.MappingNotFound, &table, task, revoked_token, revoked.virtual_base, 1);
    const replacement = try table.create(task, PAGE_SIZE);
    try std.testing.expect(!replacement.id.eql(object.id));
    try table.map(replacement.id, task);
    const current = try table.freestandingTaskMappingDescriptor(replacement.id, task);
    const current_token = fixture.tokenFor(replacement.id, task).?;
    try std.testing.expectEqual(original.virtual_base, current.virtual_base);
    try expectCopyRejected(error.StaleMappingDescriptor, &table, task, old_token, current.virtual_base, 1);
    // A stale object generation must not become authority through a live index.
    {
        const slot = table.backing.arena.getByHandle(.{ .value = replacement.id.raw() }).?;
        slot.object.id = object.id;
        defer slot.object.id = replacement.id;
        try expectCopyRejected(error.StaleMappingDescriptor, &table, task, current_token, current.virtual_base, 1);
    }
    var span = task_copy_canary;
    try table.taskCopySpanInto(task, current_token, current.virtual_base, PAGE_SIZE, &span);
    try std.testing.expectEqual(replacement.page_base, span.physical_base);
}

test "shared copy cannot authorize retained revoked DMA backing" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const task = ids.task(641);
    const object = try table.createWithAccess(task, PAGE_SIZE, .{ .gpu = true });
    defer _ = table.detachAccelerator(object.id, .gpu) catch false;
    try table.map(object.id, task);
    try table.attachAccelerator(object.id, .gpu);
    const mapping = try table.freestandingTaskMappingDescriptor(object.id, task);
    const token = fixture.tokenFor(object.id, task).?;
    _ = try table.revoke(object.id);
    try std.testing.expectEqual(@as(u32, 1), fixture.allocator.stats().allocated);
    try expectCopyRejected(error.MappingNotFound, &table, task, token, mapping.virtual_base, 1);
    try std.testing.expect(try table.detachAccelerator(object.id, .gpu));
    try std.testing.expectEqual(@as(u32, 0), fixture.allocator.stats().allocated);
}

test "shared copy task index covers full object capacity and survives mapping edge relocation" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const task = ids.task(651);
    const peer = ids.task(652);
    var objects: [MAX_SHARED_MEMORY_OBJECTS]ids.SharedMemoryId = undefined;
    for (&objects) |*object_id| {
        const object = try table.create(task, PAGE_SIZE);
        object_id.* = object.id;
        // Task and peer share one executor-lifetime token in this fixture.
        fixture.next_token = 77;
        try table.map(object.id, task);
        fixture.next_token = 77;
        try table.map(object.id, peer);
    }
    try std.testing.expectEqual(MAX_SHARED_MEMORY_OBJECTS, table.mappingsForTask(task));
    for (objects) |object_id| {
        const mapping = try table.freestandingTaskMappingDescriptor(object_id, task);
        var span = task_copy_canary;
        try table.taskCopySpanInto(task, 77, mapping.virtual_base, PAGE_SIZE, &span);
        try std.testing.expectEqual(mapping.physical_base, span.physical_base);
    }
    const removed = try table.freestandingTaskMappingDescriptor(objects[0], task);
    try std.testing.expect(try table.unmap(objects[0], task));
    try expectCopyRejected(error.MappingNotFound, &table, task, 77, removed.virtual_base, 1);
    const relocated = try table.freestandingTaskMappingDescriptor(objects[0], peer);
    var span = task_copy_canary;
    try table.taskCopySpanInto(peer, 77, relocated.virtual_base, PAGE_SIZE, &span);
    try std.testing.expectEqual(relocated.physical_base, span.physical_base);
}

test "owned shared ring backing is rounded zeroed shared writable RAM and retires access before release" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const owner = ids.task(301);
    const peer = ids.task(302);
    const object = try table.createSealedRing(owner, peer, PAGE_SIZE + 7);
    try std.testing.expectEqual(@as(usize, 2), object.page_count);
    try std.testing.expect(object.page_base >= OwnedPhysicalFixture.physical_base);
    try std.testing.expectEqual(@as(u32, 2), fixture.allocator.stats().allocated);
    const owner_bytes = fixture.taskBytes(owner).?;
    const peer_bytes = fixture.taskBytes(peer).?;
    try std.testing.expectEqual(@as(usize, 2 * PAGE_SIZE), owner_bytes.len);
    try std.testing.expect(std.mem.allEqual(u8, owner_bytes, 0));
    owner_bytes[0] = 0x31;
    owner_bytes[PAGE_SIZE + 6] = 0x42;
    try std.testing.expectEqual(@as(u8, 0x31), peer_bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x42), peer_bytes[PAGE_SIZE + 6]);
    peer_bytes[17] = 0x53;
    try std.testing.expectEqual(@as(u8, 0x53), owner_bytes[17]);
    try std.testing.expectError(error.ObjectSealed, table.map(object.id, ids.task(303)));
    _ = try table.revoke(object.id);
    try std.testing.expect(fixture.taskBytes(owner) == null and fixture.taskBytes(peer) == null);
    try std.testing.expectEqual(@as(u32, 0), fixture.allocator.stats().allocated);
    try std.testing.expectEqual(@as(usize, 2), fixture.unregistrations);
    try std.testing.expectEqual(@as(usize, 1), fixture.released_erased);
    try std.testing.expect(!fixture.released_with_live_mapping);

    // Free physical RAM can become dirty independently of this table. A new
    // allocation zeros every page again, including padding beyond size_bytes.
    @memset(&fixture.memory, 0x77);
    const replacement = try table.create(owner, PAGE_SIZE + 7);
    try std.testing.expect(!replacement.id.eql(object.id));
    try std.testing.expect(std.mem.allEqual(u8, OwnedPhysicalFixture.bytes(&fixture, replacement.page_base, 2).?, 0));
}

test "shared backing allocation and access failures publish no object or ownership" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const owner = ids.task(311);
    fixture.reject_allocation = true;
    try std.testing.expectError(error.OutOfMemory, table.create(owner, PAGE_SIZE));
    fixture.reject_allocation = false;
    fixture.reject_bytes_once = true;
    try std.testing.expectError(error.OutOfMemory, table.create(owner, PAGE_SIZE));
    try std.testing.expectEqual(@as(u32, 0), fixture.allocator.stats().allocated);
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
    try std.testing.expectEqual(@as(usize, 0), table.liveOwnedBytesForTask(owner));
    const allocations = fixture.allocations;
    try std.testing.expectError(error.OutOfMemory, table.create(owner, (@as(usize, std.math.maxInt(u32)) + 1) * PAGE_SIZE));
    try std.testing.expectEqual(allocations, fixture.allocations);
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
    const older = try table.create(owner, PAGE_SIZE);
    const older_bytes = OwnedPhysicalFixture.bytes(&fixture, older.page_base, 1).?;
    older_bytes[0] = 0x65;
    for (0..MAX_SHARED_MEMORY_OBJECTS * 2) |_| {
        const unpublished = try table.create(owner, 2 * PAGE_SIZE);
        fixture.reject_registration = true;
        try std.testing.expectError(error.MappingRegistrationFailed, table.map(unpublished.id, owner));
        fixture.reject_registration = false;
        table.rollbackCreate(unpublished.id);
        try std.testing.expectEqual(@as(u32, 1), fixture.allocator.stats().allocated);
        try std.testing.expectEqual(@as(usize, 1), table.activeCount());
        try std.testing.expectEqual(@as(usize, 0), table.mappingsForTask(owner));
        try std.testing.expectEqual(@as(u8, 0x65), older_bytes[0]);
    }
}

test "revoked accelerator backing stays pinned until every completed attachment releases" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    defer table.deinit();
    const owner = ids.task(321);
    const peer = ids.task(322);
    const object = try table.createWithAccess(owner, PAGE_SIZE + 1, .{ .gpu = true, .npu = true });
    const survivor = try table.create(peer, PAGE_SIZE);
    try table.map(object.id, owner);
    try table.map(object.id, peer);
    try table.map(survivor.id, peer);
    try table.attachAccelerator(object.id, .gpu);
    try table.attachAccelerator(object.id, .npu);
    try table.seal(object.id);
    const dma_bytes = OwnedPhysicalFixture.bytes(&fixture, object.page_base, 2).?;
    dma_bytes[0] = 0x91;
    try std.testing.expectError(error.AcceleratorStillAttached, table.tryDeinit());
    try std.testing.expectEqual(@as(usize, 2), table.activeCount());
    try std.testing.expectEqual(@as(usize, 0), fixture.unregistrations);
    try std.testing.expectEqual(@as(usize, 0), fixture.releases);
    try std.testing.expect(table.hasMapping(survivor.id, peer));
    _ = try table.revoke(object.id);
    try std.testing.expectEqual(@as(usize, 1), table.activeCount());
    try std.testing.expectEqual(@as(usize, 0), table.liveOwnedBytesForTask(owner));
    try std.testing.expectEqual(@as(usize, 2), fixture.unregistrations);
    try std.testing.expectEqual(@as(u32, 3), fixture.allocator.stats().allocated);
    try std.testing.expectEqual(@as(u8, 0x91), dma_bytes[0]);
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(object.id));
    try std.testing.expectError(error.SharedMemoryNotFound, table.map(object.id, owner));
    try std.testing.expectError(error.SharedMemoryNotFound, table.unmap(object.id, owner));
    try std.testing.expectError(error.SharedMemoryNotFound, table.revoke(object.id));
    try std.testing.expectError(error.SharedMemoryNotFound, table.attachAccelerator(object.id, .media));
    try table.validateAcceleratorRelease(object.id, .gpu);
    try std.testing.expect(try table.detachAccelerator(object.id, .gpu));
    try std.testing.expectError(error.AcceleratorNotAttached, table.validateAcceleratorRelease(object.id, .gpu));
    try std.testing.expectEqual(@as(u32, 3), fixture.allocator.stats().allocated);
    try std.testing.expectError(error.AcceleratorStillAttached, table.requireQuiescent());
    try std.testing.expect(try table.detachAccelerator(object.id, .npu));
    try std.testing.expectEqual(@as(u32, 1), fixture.allocator.stats().allocated);
    try std.testing.expectEqual(@as(usize, 1), fixture.released_erased);
    try std.testing.expectError(error.SharedMemoryNotFound, table.validateAcceleratorRelease(object.id, .npu));
    try table.requireQuiescent();
    try std.testing.expect(table.hasMapping(survivor.id, peer));
    try table.tryDeinit();
    try std.testing.expectEqual(@as(u32, 0), fixture.allocator.stats().allocated);
    try std.testing.expectEqual(@as(usize, 3), fixture.unregistrations);
    try std.testing.expectEqual(@as(usize, 2), fixture.released_erased);
    try std.testing.expect(!fixture.released_with_live_mapping);
}

test "retired accelerator pins consume bounded arena capacity and reject stale releases" {
    var fixture = OwnedPhysicalFixture{};
    fixture.init();
    var table = Table.initWithHostedPhysicalBacking(fixture.backing(), fixture.lifetime());
    var retired_ids: [MAX_SHARED_MEMORY_OBJECTS]ids.SharedMemoryId = undefined;
    for (&retired_ids, 0..) |*object_id, index| {
        const object = try table.createWithAccess(ids.task(400 + index), PAGE_SIZE, .{ .gpu = true });
        object_id.* = object.id;
        try table.attachAccelerator(object.id, .gpu);
        _ = try table.revoke(object.id);
    }
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
    try std.testing.expectEqual(@as(u32, MAX_SHARED_MEMORY_OBJECTS), fixture.allocator.stats().allocated);
    const allocations = fixture.allocations;
    try std.testing.expectError(error.TableFull, table.create(ids.task(500), PAGE_SIZE));
    try std.testing.expectEqual(allocations, fixture.allocations);
    try std.testing.expectError(error.AcceleratorStillAttached, table.tryDeinit());
    try std.testing.expect(try table.detachAccelerator(retired_ids[0], .gpu));
    const replacement = try table.createWithAccess(ids.task(500), PAGE_SIZE, .{ .gpu = true });
    try std.testing.expect(!replacement.id.eql(retired_ids[0]));
    try table.attachAccelerator(replacement.id, .gpu);
    try std.testing.expectError(error.SharedMemoryNotFound, table.detachAccelerator(retired_ids[0], .gpu));
    try std.testing.expect(try table.isAcceleratorAttached(replacement.id, .gpu));
    for (retired_ids[1..]) |object_id| try std.testing.expect(try table.detachAccelerator(object_id, .gpu));
    try std.testing.expectEqual(@as(u32, 1), fixture.allocator.stats().allocated);
    try std.testing.expect(try table.detachAccelerator(replacement.id, .gpu));
    try table.tryDeinit();
    try std.testing.expectEqual(@as(u32, 0), fixture.allocator.stats().allocated);
    try std.testing.expectEqual(fixture.allocations, fixture.releases);
    try std.testing.expect(!fixture.released_with_live_mapping);
}
