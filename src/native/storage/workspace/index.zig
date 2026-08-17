const std = @import("std");

const id_index = @import("../../core/id_index.zig");
const indexed_arena = @import("../../core/indexed_arena.zig");
const native_util = @import("../../core/util.zig");

pub const EntryIndexSlot = struct {
    state: id_index.State = .empty,
    path_hash: u64 = 0,
    slot_index: usize = 0,
};

pub const EntryObjectIndexSlot = struct {
    object_id: u64 = 0,
    slot_index: u8 = 0,
};

pub fn emptyEntryIndexTable(comptime capacity: usize) [capacity]EntryIndexSlot {
    return [_]EntryIndexSlot{EntryIndexSlot{}} ** capacity;
}

pub fn emptyEntryObjectIndexTable(comptime capacity: usize) [capacity]EntryObjectIndexSlot {
    return [_]EntryObjectIndexSlot{EntryObjectIndexSlot{}} ** capacity;
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
    const key = entryPathIndexKey(path);
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const slot = slots[index];
        switch (slot.state) {
            .empty => return null,
            .filled => {
                if (slot.path_hash == key) {
                    if (slot.slot_index >= entries.len) {
                        native_util.impossibleByInvariant("entry path index points outside workspace entries");
                    }
                    if (std.mem.eql(u8, entries[slot.slot_index].pathSlice(), path)) {
                        return slot.slot_index;
                    }
                }
            },
            .tombstone => {},
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
    const key = entryPathIndexKey(path);
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (slots[index].state) {
            .empty, .tombstone => {
                slots[index] = .{
                    .state = .filled,
                    .path_hash = key,
                    .slot_index = slot_index,
                };
                return;
            },
            .filled => {
                if (slots[index].path_hash == key) {
                    const existing_index = slots[index].slot_index;
                    if (existing_index >= entries.len) {
                        native_util.impossibleByInvariant("entry path index points outside workspace entries");
                    }
                    if (std.mem.eql(u8, entries[existing_index].pathSlice(), path)) {
                        slots[index].slot_index = slot_index;
                        return;
                    }
                }
            },
        }
        index = (index + 1) % capacity;
    }
    native_util.impossibleByInvariant("entry path index capacity covers workspace entries");
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
        const slot = slots[index];
        if (slot.object_id == 0) return null;
        if (slot.object_id == key) {
            const entry_index: usize = slot.slot_index;
            if (entry_index < entries.len and entries[entry_index].object_id.raw() == key) {
                return entry_index;
            }
            return null;
        }
        index = (index + 1) % capacity;
    }
    return null;
}

pub fn insertEntryObjectSlot(comptime capacity: usize, slots: *[capacity]EntryObjectIndexSlot, object_id: u64, slot_index: usize) void {
    const key = objectIdIndexKey(object_id);
    if (key == 0) return;
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        if (slots[index].object_id == 0) {
            slots[index] = .{
                .object_id = key,
                .slot_index = @intCast(slot_index),
            };
            return;
        }
        if (slots[index].object_id == key) {
            return;
        }
        index = (index + 1) % capacity;
    }
    native_util.impossibleByInvariant("entry object index capacity covers workspace entries");
}

fn entryPathIndexKey(path: []const u8) u64 {
    return indexed_arena.nonZeroKey(native_util.fnv1a64(path));
}

fn objectIdIndexKey(object_id: anytype) u64 {
    return switch (@TypeOf(object_id)) {
        u64 => object_id,
        else => object_id.raw(),
    };
}

const TestEntry = struct {
    path: []const u8,

    fn pathSlice(self: *const TestEntry) []const u8 {
        return self.path;
    }
};

test "entry path index probes through matching hash collisions" {
    const capacity = 4;
    const entries = [_]TestEntry{
        .{ .path = "different-path" },
        .{ .path = "target-path" },
    };
    var slots = emptyEntryIndexTable(capacity);
    const key = entryPathIndexKey(entries[1].pathSlice());
    const first_index = id_index.hash(key, capacity);
    const second_index = (first_index + 1) % capacity;
    slots[first_index] = .{
        .state = .filled,
        .path_hash = key,
        .slot_index = 0,
    };

    insertEntryPathSlot(capacity, &slots, &entries, entries[1].pathSlice(), 1);

    try std.testing.expectEqual(@as(usize, 0), slots[first_index].slot_index);
    try std.testing.expectEqual(@as(usize, 1), slots[second_index].slot_index);
    try std.testing.expectEqual(
        @as(?usize, 1),
        findIndexedEntryPath(capacity, &slots, &entries, entries[1].pathSlice()),
    );
}
