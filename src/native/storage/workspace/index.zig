const std = @import("std");

const id_index = @import("../../core/id_index.zig");
const indexed_arena = @import("../../core/indexed_arena.zig");
const native_util = @import("../../core/util.zig");

pub const EntryIndexSlot = struct {
    state: id_index.State = .empty,
    path_hash: u64 = 0,
    slot_index: usize = 0,
};

pub fn emptyEntryIndexTable(comptime capacity: usize) [capacity]EntryIndexSlot {
    return [_]EntryIndexSlot{EntryIndexSlot{}} ** capacity;
}

pub fn pathHash(path: []const u8) u64 {
    return native_util.fnv1a64(path);
}

pub fn rebuildPathSlots(comptime capacity: usize, slots: *[capacity]EntryIndexSlot, entries: anytype) void {
    slots.* = emptyEntryIndexTable(capacity);
    for (entries, 0..) |entry, slot_index| {
        insertEntryPathSlot(capacity, slots, entry.pathSlice(), slot_index);
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
                    if (slot.slot_index < entries.len and std.mem.eql(u8, entries[slot.slot_index].pathSlice(), path)) {
                        return slot.slot_index;
                    }
                    return null;
                }
            },
            .tombstone => {},
        }
        index = (index + 1) % capacity;
    }
    return null;
}

pub fn insertEntryPathSlot(comptime capacity: usize, slots: *[capacity]EntryIndexSlot, path: []const u8, slot_index: usize) void {
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
                    slots[index].slot_index = slot_index;
                    return;
                }
            },
        }
        index = (index + 1) % capacity;
    }
    native_util.impossibleByInvariant("entry path index capacity covers workspace entries");
}

fn entryPathIndexKey(path: []const u8) u64 {
    return indexed_arena.nonZeroKey(native_util.fnv1a64(path));
}
