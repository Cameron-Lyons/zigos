const std = @import("std");

const id_index = @import("../../core/id_index.zig");
const indexed_arena = @import("../../core/indexed_arena.zig");
const native_util = @import("../../core/util.zig");

pub const EntrySlotIndex = u8;
pub const EntryIndexSlot = EntrySlotIndex;
pub const EntryObjectIndexSlot = EntrySlotIndex;
pub const no_entry_slot: EntrySlotIndex = std.math.maxInt(EntrySlotIndex);

pub fn emptyEntryIndexTable(comptime capacity: usize) [capacity]EntryIndexSlot {
    return [_]EntryIndexSlot{no_entry_slot} ** capacity;
}

pub fn emptyEntryObjectIndexTable(comptime capacity: usize) [capacity]EntryObjectIndexSlot {
    return [_]EntryObjectIndexSlot{no_entry_slot} ** capacity;
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
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) return null;
        const entry_index: usize = entry_slot;
        if (entry_index >= entries.len) native_util.impossibleByInvariant("entry path index points outside workspace entries");
        if (std.mem.eql(u8, entries[entry_index].pathSlice(), path)) return entry_index;
        index = (index + 1) % capacity;
    }
    return null;
}

pub fn insertEntryPathSlot(comptime capacity: usize, slots: *[capacity]EntryIndexSlot, path: []const u8, slot_index: usize) void {
    if (slot_index >= no_entry_slot) native_util.impossibleByInvariant("workspace entry index fits compact slot references");
    const key = entryPathIndexKey(path);
    var index = id_index.hash(key, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        if (slots[index] == no_entry_slot) {
            slots[index] = @intCast(slot_index);
            return;
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
        const entry_slot = slots[index];
        if (entry_slot == no_entry_slot) return null;
        const entry_index: usize = entry_slot;
        if (entry_index >= entries.len) native_util.impossibleByInvariant("entry object index points outside workspace entries");
        if (entries[entry_index].object_id.raw() == key) return entry_index;
        index = (index + 1) % capacity;
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
        if (slots[index] == no_entry_slot) {
            slots[index] = @intCast(slot_index);
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
