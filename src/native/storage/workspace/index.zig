const std = @import("std");

const id_index = @import("../../core/id_index.zig");
const indexed_arena = @import("../../core/indexed_arena.zig");
const native_util = @import("../../core/util.zig");

pub const EntrySlotIndex = u8;
pub const EntryIndexSlot = EntrySlotIndex;
pub const EntryObjectIndexSlot = EntrySlotIndex;
pub const no_entry_slot: EntrySlotIndex = std.math.maxInt(EntrySlotIndex);
pub const tombstone_entry_slot: EntrySlotIndex = no_entry_slot - 1;
pub const UPDATES_PATH_INDEX_INCREMENTALLY = true;
pub const UPDATES_OBJECT_INDEX_INCREMENTALLY = true;

pub fn emptyEntryIndexTable(comptime capacity: usize) [capacity]EntryIndexSlot {
    return [_]EntryIndexSlot{no_entry_slot} ** capacity;
}

pub fn emptyEntryObjectIndexTable(comptime capacity: usize) [capacity]EntryObjectIndexSlot {
    return [_]EntryObjectIndexSlot{no_entry_slot} ** capacity;
}

pub fn isLiveEntrySlot(slot: EntrySlotIndex) bool {
    return slot != no_entry_slot and slot != tombstone_entry_slot;
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
        if (isLiveEntrySlot(entry_slot)) {
            const entry_index: usize = entry_slot;
            if (entry_index >= entries.len) native_util.impossibleByInvariant("entry path index points outside workspace entries");
            if (std.mem.eql(u8, entries[entry_index].pathSlice(), path)) return entry_index;
        }
        index = (index + 1) % capacity;
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
    if (slot_index >= tombstone_entry_slot) native_util.impossibleByInvariant("workspace entry index fits compact slot references");
    const key = entryPathIndexKey(path);
    var index = id_index.hash(key, capacity);
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) {
            slots[first_tombstone orelse index] = @intCast(slot_index);
            return;
        }
        if (entry_slot == tombstone_entry_slot) {
            if (first_tombstone == null) first_tombstone = index;
        } else {
            const existing_index: usize = entry_slot;
            if (existing_index >= entries.len) native_util.impossibleByInvariant("entry path index points outside workspace entries");
            if (std.mem.eql(u8, entries[existing_index].pathSlice(), path)) {
                slots[index] = @intCast(slot_index);
                return;
            }
        }
        index = (index + 1) % capacity;
    }
    if (first_tombstone) |tombstone_index| {
        slots[tombstone_index] = @intCast(slot_index);
        return;
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
        if (isLiveEntrySlot(entry_slot) and entry_slot == slot_index) {
            const entry_index: usize = entry_slot;
            if (entry_index >= entries.len) native_util.impossibleByInvariant("entry path index points outside workspace entries");
            if (std.mem.eql(u8, entries[entry_index].pathSlice(), path)) {
                slots[index] = tombstone_entry_slot;
                return;
            }
        }
        index = (index + 1) % capacity;
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
        if (isLiveEntrySlot(entry_slot)) {
            const entry_index: usize = entry_slot;
            if (entry_index >= entries.len) native_util.impossibleByInvariant("entry object index points outside workspace entries");
            if (entries[entry_index].object_id.raw() == key) return entry_index;
        }
        index = (index + 1) % capacity;
    }
    return null;
}

pub fn insertEntryObjectSlot(comptime capacity: usize, slots: *[capacity]EntryObjectIndexSlot, object_id: u64, slot_index: usize) void {
    const key = objectIdIndexKey(object_id);
    if (key == 0) return;
    if (slot_index >= tombstone_entry_slot) native_util.impossibleByInvariant("workspace object index fits compact slot references");
    var index = id_index.hash(key, capacity);
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) {
            slots[first_tombstone orelse index] = @intCast(slot_index);
            return;
        }
        if (entry_slot == tombstone_entry_slot and first_tombstone == null) first_tombstone = index;
        index = (index + 1) % capacity;
    }
    if (first_tombstone) |tombstone_index| {
        slots[tombstone_index] = @intCast(slot_index);
        return;
    }
    native_util.impossibleByInvariant("entry object index capacity covers workspace entries");
}

pub fn removeEntryObjectSlot(
    comptime capacity: usize,
    slots: *[capacity]EntryObjectIndexSlot,
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
        if (isLiveEntrySlot(entry_slot) and entry_slot == slot_index) {
            slots[index] = tombstone_entry_slot;
            return;
        }
        index = (index + 1) % capacity;
    }
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

test "entry path index reuses tombstones without breaking probe chains" {
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
    slots[2] = tombstone_entry_slot;
    slots[3] = no_entry_slot;
    adjustEntrySlotsAfterInsert(capacity, &slots, 1);
    try std.testing.expectEqual(@as(EntryIndexSlot, 0), slots[0]);
    try std.testing.expectEqual(@as(EntryIndexSlot, 3), slots[1]);
    try std.testing.expectEqual(tombstone_entry_slot, slots[2]);

    adjustEntrySlotsAfterRemove(capacity, &slots, 1);
    try std.testing.expectEqual(@as(EntryIndexSlot, 0), slots[0]);
    try std.testing.expectEqual(@as(EntryIndexSlot, 2), slots[1]);
    try std.testing.expectEqual(tombstone_entry_slot, slots[2]);
}
