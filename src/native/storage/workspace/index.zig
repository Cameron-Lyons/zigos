const std = @import("std");

const id_index = @import("../../core/id_index.zig");
const indexed_arena = @import("../../core/indexed_arena.zig");
const native_util = @import("../../core/util.zig");

pub const EntrySlotIndex = u8;
pub const EntryIndexSlot = EntrySlotIndex;
pub const EntryObjectIndexSlot = EntrySlotIndex;
pub const no_entry_slot: EntrySlotIndex = std.math.maxInt(EntrySlotIndex);
pub const UPDATES_PATH_INDEX_INCREMENTALLY = true;
pub const UPDATES_OBJECT_INDEX_INCREMENTALLY = true;
pub const REMOVES_INDEX_ENTRIES_WITHOUT_TOMBSTONES = true;

pub fn emptyEntryIndexTable(comptime capacity: usize) [capacity]EntryIndexSlot {
    return [_]EntryIndexSlot{no_entry_slot} ** capacity;
}

pub fn emptyEntryObjectIndexTable(comptime capacity: usize) [capacity]EntryObjectIndexSlot {
    return [_]EntryObjectIndexSlot{no_entry_slot} ** capacity;
}

pub fn isLiveEntrySlot(slot: EntrySlotIndex) bool {
    return slot != no_entry_slot;
}

pub fn pathHash(path: []const u8) u64 {
    return native_util.fnv1a64(path);
}

pub fn rebuildPathSlots(comptime capacity: usize, slots: *[capacity]EntryIndexSlot, entries: anytype) void {
    slots.* = emptyEntryIndexTable(capacity);
    for (entries, 0..) |entry, slot_index| {
        insertEntryPathSlot(capacity, slots, entries, entry.pathSlice(), slot_index);
    }
}

pub fn rebuildObjectSlots(comptime capacity: usize, slots: *[capacity]EntryObjectIndexSlot, entries: anytype) void {
    slots.* = emptyEntryObjectIndexTable(capacity);
    for (entries, 0..) |entry, slot_index| {
        insertEntryObjectSlot(capacity, slots, entry.object_id.raw(), slot_index);
    }
}

pub fn findIndexedEntryPath(
    comptime capacity: usize,
    slots: *const [capacity]EntryIndexSlot,
    entries: anytype,
    path: []const u8,
) ?usize {
    return findIndexedEntryPathWithHash(capacity, slots, entries, path, pathHash(path));
}

pub fn findIndexedEntryPathWithHash(
    comptime capacity: usize,
    slots: *const [capacity]EntryIndexSlot,
    entries: anytype,
    path: []const u8,
    path_hash: u64,
) ?usize {
    const key = entryPathIndexKeyFromHash(path_hash);
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) return null;
        const entry_index: usize = entry_slot;
        if (entry_index >= entries.len) native_util.impossibleByInvariant("entry path index points outside workspace entries");
        if (std.mem.eql(u8, entries[entry_index].pathSlice(), path)) return entry_index;
        index = nextIndex(capacity, index);
    }
    return null;
}

pub fn insertEntryPathSlot(
    comptime capacity: usize,
    slots: *[capacity]EntryIndexSlot,
    entries: anytype,
    path: []const u8,
    slot_index: usize,
) void {
    if (slot_index >= no_entry_slot) native_util.impossibleByInvariant("workspace entry index fits compact slot references");
    const key = entryPathIndexKey(path);
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) {
            slots[index] = @intCast(slot_index);
            return;
        }
        const existing_index: usize = entry_slot;
        if (existing_index >= entries.len) native_util.impossibleByInvariant("entry path index points outside workspace entries");
        if (std.mem.eql(u8, entries[existing_index].pathSlice(), path)) {
            slots[index] = @intCast(slot_index);
            return;
        }
        index = nextIndex(capacity, index);
    }
    native_util.impossibleByInvariant("entry path index capacity covers workspace entries");
}

pub fn removeEntryPathSlot(
    comptime capacity: usize,
    slots: *[capacity]EntryIndexSlot,
    entries: anytype,
    path: []const u8,
    slot_index: usize,
) void {
    const key = entryPathIndexKey(path);
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) return;
        if (entry_slot == slot_index) {
            const entry_index: usize = entry_slot;
            if (entry_index >= entries.len) native_util.impossibleByInvariant("entry path index points outside workspace entries");
            if (std.mem.eql(u8, entries[entry_index].pathSlice(), path)) {
                closeProbeHole(capacity, slots, entries, index, .path);
                return;
            }
        }
        index = nextIndex(capacity, index);
    }
}

pub fn findIndexedEntryObject(
    comptime capacity: usize,
    slots: *const [capacity]EntryObjectIndexSlot,
    entries: anytype,
    object_id: anytype,
) ?usize {
    const key = objectIdIndexKey(object_id);
    if (key == 0) return null;
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) return null;
        const entry_index: usize = entry_slot;
        if (entry_index >= entries.len) native_util.impossibleByInvariant("entry object index points outside workspace entries");
        if (entries[entry_index].object_id.raw() == key) return entry_index;
        index = nextIndex(capacity, index);
    }
    return null;
}

pub fn insertEntryObjectSlot(comptime capacity: usize, slots: *[capacity]EntryObjectIndexSlot, object_id: u64, slot_index: usize) void {
    const key = objectIdIndexKey(object_id);
    if (key == 0) return;
    if (slot_index >= no_entry_slot) native_util.impossibleByInvariant("workspace object index fits compact slot references");
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) {
            slots[index] = @intCast(slot_index);
            return;
        }
        index = nextIndex(capacity, index);
    }
    native_util.impossibleByInvariant("entry object index capacity covers workspace entries");
}

pub fn removeEntryObjectSlot(
    comptime capacity: usize,
    slots: *[capacity]EntryObjectIndexSlot,
    entries: anytype,
    slot_index: usize,
    object_id: u64,
) void {
    const key = objectIdIndexKey(object_id);
    if (key == 0) return;
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) return;
        if (entry_slot == slot_index) {
            const entry_index: usize = entry_slot;
            if (entry_index >= entries.len) native_util.impossibleByInvariant("entry object index points outside workspace entries");
            if (entries[entry_index].object_id.raw() != key) return;
            closeProbeHole(capacity, slots, entries, index, .object);
            return;
        }
        index = nextIndex(capacity, index);
    }
}

const IndexKind = enum { path, object };

fn closeProbeHole(comptime capacity: usize, slots: *[capacity]EntrySlotIndex, entries: anytype, removed_index: usize, comptime kind: IndexKind) void {
    // Canonical entries supply each home bucket. Close only probe paths that
    // cross the removed bucket before callers compact or replace entries.
    // A full object table has no empty terminator; visit each other bucket once.
    var hole = removed_index;
    var index = nextIndex(capacity, hole);
    for (0..capacity - 1) |_| {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) break;
        const entry_index: usize = entry_slot;
        if (entry_index >= entries.len) native_util.impossibleByInvariant("workspace index deletion references a canonical entry");
        const key = switch (kind) {
            .path => entryPathIndexKey(entries[entry_index].pathSlice()),
            .object => entries[entry_index].object_id.raw(),
        };
        const home = id_index.hash(key, capacity);
        if (probeDistance(capacity, home, hole) < probeDistance(capacity, home, index)) {
            slots[hole] = entry_slot;
            hole = index;
        }
        index = nextIndex(capacity, index);
    }
    slots[hole] = no_entry_slot;
}

inline fn nextIndex(comptime capacity: usize, index: usize) usize {
    if (capacity == 0) @compileError("workspace indexes require at least one bucket");
    return if (index == capacity - 1) 0 else index + 1;
}

inline fn probeDistance(comptime capacity: usize, home: usize, index: usize) usize {
    return if (index >= home) index - home else capacity - home + index;
}

pub fn adjustEntrySlotsAfterInsert(comptime capacity: usize, slots: *[capacity]EntrySlotIndex, insert_index: usize) void {
    for (slots) |*slot| {
        if (!isLiveEntrySlot(slot.*)) continue;
        if (slot.* >= insert_index) slot.* += 1;
    }
}

pub fn adjustEntrySlotsAfterRemove(comptime capacity: usize, slots: *[capacity]EntrySlotIndex, remove_index: usize) void {
    for (slots) |*slot| {
        if (!isLiveEntrySlot(slot.*)) continue;
        if (slot.* > remove_index) slot.* -= 1;
    }
}

fn entryPathIndexKey(path: []const u8) u64 {
    return entryPathIndexKeyFromHash(pathHash(path));
}

fn entryPathIndexKeyFromHash(path_hash: u64) u64 {
    return indexed_arena.nonZeroKey(path_hash);
}

fn objectIdIndexKey(object_id: anytype) u64 {
    return switch (@TypeOf(object_id)) {
        u64 => object_id,
        else => object_id.raw(),
    };
}

const TestEntry = struct {
    path: []const u8,
    object_id: struct {
        value: u64,
        fn raw(self: @This()) u64 {
            return self.value;
        }
    },

    fn pathSlice(self: *const TestEntry) []const u8 {
        return self.path;
    }
};

test "entry path index probes through matching hash collisions" {
    const capacity = 4;
    const entries = [_]TestEntry{
        .{ .path = "different-path", .object_id = .{ .value = 1 } },
        .{ .path = "target-path", .object_id = .{ .value = 2 } },
    };
    var slots = emptyEntryIndexTable(capacity);
    const key = entryPathIndexKey(entries[1].pathSlice());
    const first_index = id_index.hash(key, capacity);
    const second_index = (first_index + 1) % capacity;
    slots[first_index] = 0;

    insertEntryPathSlot(capacity, &slots, &entries, entries[1].pathSlice(), 1);

    try std.testing.expectEqual(@as(EntryIndexSlot, 0), slots[first_index]);
    try std.testing.expectEqual(@as(EntryIndexSlot, 1), slots[second_index]);
    try std.testing.expectEqual(
        @as(?usize, 1),
        findIndexedEntryPath(capacity, &slots, &entries, entries[1].pathSlice()),
    );
}

test "entry path index closes deletions without breaking probe chains" {
    const capacity = 4;
    var entries = [_]TestEntry{
        .{ .path = "alpha", .object_id = .{ .value = 1 } },
        .{ .path = "beta", .object_id = .{ .value = 2 } },
        .{ .path = "gamma", .object_id = .{ .value = 3 } },
    };
    var slots = emptyEntryIndexTable(capacity);
    insertEntryPathSlot(capacity, &slots, &entries, entries[0].pathSlice(), 0);
    insertEntryPathSlot(capacity, &slots, &entries, entries[1].pathSlice(), 1);

    removeEntryPathSlot(capacity, &slots, &entries, entries[0].pathSlice(), 0);
    try std.testing.expectEqual(@as(?usize, 1), findIndexedEntryPath(capacity, &slots, &entries, entries[1].pathSlice()));
    try std.testing.expectEqual(@as(?usize, null), findIndexedEntryPath(capacity, &slots, &entries, entries[0].pathSlice()));

    entries[0] = .{ .path = "gamma", .object_id = .{ .value = 3 } };
    insertEntryPathSlot(capacity, &slots, &entries, entries[0].pathSlice(), 0);
    try std.testing.expectEqual(@as(?usize, 0), findIndexedEntryPath(capacity, &slots, &entries, "gamma"));
    try std.testing.expectEqual(@as(?usize, 1), findIndexedEntryPath(capacity, &slots, &entries, "beta"));
}

test "entry slot indexes shift around incremental inserts and deletes" {
    const capacity = 8;
    var slots = emptyEntryIndexTable(capacity);
    slots[0] = 0;
    slots[1] = 2;
    adjustEntrySlotsAfterInsert(capacity, &slots, 1);
    try std.testing.expectEqual(@as(EntryIndexSlot, 0), slots[0]);
    try std.testing.expectEqual(@as(EntryIndexSlot, 3), slots[1]);
    try std.testing.expectEqual(no_entry_slot, slots[2]);

    adjustEntrySlotsAfterRemove(capacity, &slots, 1);
    try std.testing.expectEqual(@as(EntryIndexSlot, 0), slots[0]);
    try std.testing.expectEqual(@as(EntryIndexSlot, 2), slots[1]);
    try std.testing.expectEqual(no_entry_slot, slots[2]);
}

test "workspace deletion preserves every small full colliding table order" {
    inline for (.{ 1, 2, 3, 4, 5 }) |capacity| {
        var buffers: [capacity][32]u8 = undefined;
        const entries = collidingEntries(capacity, capacity - 1, &buffers);
        try checkInsertionOrders(capacity, entries, emptyEntryIndexTable(capacity), emptyEntryObjectIndexTable(capacity), @splat(false), 0);
    }
}

test "workspace deletion preserves unrelated homes across wrapped probe chains" {
    inline for (.{ 7, 8, 15 }) |capacity| {
        var collision_buffers: [3][32]u8 = undefined;
        const collisions = collidingEntries(capacity, capacity - 1, &collision_buffers);
        var zero_buffers: [1][32]u8 = undefined;
        const zero = collidingEntries(capacity, 0, &zero_buffers);
        var one_buffers: [1][32]u8 = undefined;
        const one = collidingEntries(capacity, 1, &one_buffers);
        const entries = [_]TestEntry{ collisions[0], zero[0], collisions[1], one[0], collisions[2] };
        var paths = emptyEntryIndexTable(capacity);
        var objects = emptyEntryObjectIndexTable(capacity);
        for (entries, 0..) |entry, slot| {
            insertEntryPathSlot(capacity, &paths, &entries, entry.path, slot);
            insertEntryObjectSlot(capacity, &objects, entry.object_id.raw(), slot);
        }
        removeEntryPathSlot(capacity, &paths, &entries, entries[0].path, 0);
        removeEntryObjectSlot(capacity, &objects, &entries, 0, entries[0].object_id.raw());
        try expectIndexes(capacity, entries, &paths, &objects, .{ false, true, true, true, true });
    }
}

test "workspace object deletion retains aliases for the same object" {
    const capacity = 5;
    var buffers: [capacity][32]u8 = undefined;
    var entries = collidingEntries(capacity, capacity - 1, &buffers);
    for (entries[1..]) |*entry| entry.object_id = entries[0].object_id;
    var objects = emptyEntryObjectIndexTable(capacity);
    for (entries, 0..) |entry, slot| insertEntryObjectSlot(capacity, &objects, entry.object_id.raw(), slot);
    const removed = [_]usize{ 0, 3, 1, 4, 2 };
    var live: [capacity]bool = @splat(true);
    for (removed, 0..) |slot, count| {
        removeEntryObjectSlot(capacity, &objects, &entries, slot, entries[slot].object_id.raw());
        live[slot] = false;
        const found = findIndexedEntryObject(capacity, &objects, &entries, entries[0].object_id.raw());
        if (count == capacity - 1) {
            try std.testing.expectEqual(@as(?usize, null), found);
        } else {
            try std.testing.expect(live[found orelse return error.MissingAlias]);
        }
        for (objects) |entry_slot| if (entry_slot != no_entry_slot) {
            try std.testing.expect(live[entry_slot]);
        };
    }
}

test "workspace indexes agree with sorted entries through random mutations" {
    inline for (.{ 1, 3, 8, 17 }) |capacity| {
        const candidate_count = capacity * 3;
        var buffers: [candidate_count][32]u8 = undefined;
        var candidates: [candidate_count]TestEntry = undefined;
        for (&candidates, 0..) |*entry, i| {
            entry.* = .{
                .path = try std.fmt.bufPrint(&buffers[i], "path-{d:0>3}", .{i}),
                // Repeated object IDs exercise multiple paths to one object.
                .object_id = .{ .value = @intCast(i % (capacity + 1) + 1) },
            };
        }
        var entries: [capacity]TestEntry = undefined;
        var count: usize = 0;
        var paths = emptyEntryIndexTable(capacity);
        var objects = emptyEntryObjectIndexTable(capacity);
        var rng = std.Random.DefaultPrng.init(0xFF4E_68A1 + capacity);
        const random = rng.random();
        for (0..4_000) |_| {
            const candidate = candidates[random.uintLessThan(usize, candidate_count)];
            var position: usize = 0;
            while (position < count and std.mem.order(u8, entries[position].path, candidate.path) == .lt) : (position += 1) {}
            const exists = position < count and std.mem.eql(u8, entries[position].path, candidate.path);
            if (exists and random.boolean()) {
                removeEntryPathSlot(capacity, &paths, entries[0..count], candidate.path, position);
                removeEntryObjectSlot(capacity, &objects, entries[0..count], position, entries[position].object_id.raw());
                std.mem.copyForwards(TestEntry, entries[position .. count - 1], entries[position + 1 .. count]);
                count -= 1;
                adjustEntrySlotsAfterRemove(capacity, &paths, position);
                adjustEntrySlotsAfterRemove(capacity, &objects, position);
            } else if (exists) {
                const replacement_id = random.uintLessThan(u64, capacity + 1) + 1;
                removeEntryObjectSlot(capacity, &objects, entries[0..count], position, entries[position].object_id.raw());
                entries[position].object_id.value = replacement_id;
                insertEntryObjectSlot(capacity, &objects, replacement_id, position);
            } else if (count < capacity) {
                std.mem.copyBackwards(TestEntry, entries[position + 1 .. count + 1], entries[position..count]);
                count += 1;
                entries[position] = candidate;
                adjustEntrySlotsAfterInsert(capacity, &paths, position);
                adjustEntrySlotsAfterInsert(capacity, &objects, position);
                insertEntryPathSlot(capacity, &paths, entries[0..count], candidate.path, position);
                insertEntryObjectSlot(capacity, &objects, candidate.object_id.raw(), position);
            }
            for (candidates) |query| {
                var expected_path: ?usize = null;
                var object_exists = false;
                for (entries[0..count], 0..) |entry, slot| {
                    if (std.mem.eql(u8, entry.path, query.path)) expected_path = slot;
                    if (entry.object_id.raw() == query.object_id.raw()) object_exists = true;
                }
                try std.testing.expectEqual(expected_path, findIndexedEntryPath(capacity, &paths, entries[0..count], query.path));
                const found = findIndexedEntryObject(capacity, &objects, entries[0..count], query.object_id.raw());
                try std.testing.expectEqual(object_exists, found != null);
                if (found) |slot| try std.testing.expectEqual(query.object_id.raw(), entries[slot].object_id.raw());
            }
            var path_count: usize = 0;
            var object_count: usize = 0;
            for (paths) |slot| if (slot != no_entry_slot) {
                try std.testing.expect(slot < count);
                path_count += 1;
            };
            for (objects) |slot| if (slot != no_entry_slot) {
                try std.testing.expect(slot < count);
                object_count += 1;
            };
            try std.testing.expectEqual(count, path_count);
            try std.testing.expectEqual(count, object_count);
        }
    }
}

fn collidingEntries(comptime capacity: usize, home: usize, buffers: anytype) [buffers.len]TestEntry {
    var entries: [buffers.len]TestEntry = undefined;
    var path_candidate: u64 = 1;
    var object_candidate: u64 = 1;
    for (&entries, 0..) |*entry, i| {
        while (true) : (path_candidate += 1) {
            const path = std.fmt.bufPrint(&buffers[i], "key-{d}", .{path_candidate}) catch unreachable;
            if (id_index.hash(entryPathIndexKey(path), capacity) != home) continue;
            entry.path = path;
            path_candidate += 1;
            break;
        }
        while (id_index.hash(object_candidate, capacity) != home) : (object_candidate += 1) {}
        entry.object_id.value = object_candidate;
        object_candidate += 1;
    }
    return entries;
}

fn checkInsertionOrders(comptime capacity: usize, entries: [capacity]TestEntry, path_table: [capacity]EntryIndexSlot, object_table: [capacity]EntryObjectIndexSlot, live: [capacity]bool, count: usize) !void {
    try expectIndexes(capacity, entries, &path_table, &object_table, live);
    if (count == capacity) return checkRemovalOrders(capacity, entries, path_table, object_table, live, count);
    for (0..capacity) |slot| {
        if (live[slot]) continue;
        var paths = path_table;
        var objects = object_table;
        var next_live = live;
        insertEntryPathSlot(capacity, &paths, &entries, entries[slot].path, slot);
        insertEntryObjectSlot(capacity, &objects, entries[slot].object_id.raw(), slot);
        next_live[slot] = true;
        try checkInsertionOrders(capacity, entries, paths, objects, next_live, count + 1);
    }
}

fn checkRemovalOrders(comptime capacity: usize, entries: [capacity]TestEntry, path_table: [capacity]EntryIndexSlot, object_table: [capacity]EntryObjectIndexSlot, live: [capacity]bool, count: usize) !void {
    try expectIndexes(capacity, entries, &path_table, &object_table, live);
    if (count == 0) return;
    for (0..capacity) |slot| {
        if (!live[slot]) continue;
        var paths = path_table;
        var objects = object_table;
        var next_live = live;
        removeEntryPathSlot(capacity, &paths, &entries, entries[slot].path, slot);
        removeEntryObjectSlot(capacity, &objects, &entries, slot, entries[slot].object_id.raw());
        next_live[slot] = false;
        try checkRemovalOrders(capacity, entries, paths, objects, next_live, count - 1);
    }
}

fn expectIndexes(comptime capacity: usize, entries: anytype, paths: *const [capacity]EntryIndexSlot, objects: *const [capacity]EntryObjectIndexSlot, live: [entries.len]bool) !void {
    for (entries, 0..) |entry, slot| {
        const expected: ?usize = if (live[slot]) slot else null;
        try std.testing.expectEqual(expected, findIndexedEntryPath(capacity, paths, &entries, entry.path));
        try std.testing.expectEqual(expected, findIndexedEntryObject(capacity, objects, &entries, entry.object_id.raw()));
    }
    var count: usize = 0;
    for (paths.*, objects.*) |path_slot, object_slot| {
        if (path_slot != no_entry_slot) {
            try std.testing.expect(live[path_slot]);
            count += 1;
        }
        if (object_slot != no_entry_slot) try std.testing.expect(live[object_slot]);
    }
    var expected_count: usize = 0;
    for (live) |value| expected_count += @intFromBool(value);
    try std.testing.expectEqual(expected_count, count);
}
