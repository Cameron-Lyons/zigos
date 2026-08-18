const std = @import("std");
const native_util = @import("util.zig");

pub const State = enum(u8) {
    empty,
    filled,
    tombstone,
};

pub fn SlotIndex(comptime capacity: usize) type {
    if (capacity == 0) @compileError("id index requires at least one slot");
    if (capacity <= @as(usize, std.math.maxInt(u8)) + 1) return u8;
    if (capacity <= @as(usize, std.math.maxInt(u16)) + 1) return u16;
    if (@bitSizeOf(usize) > 32 and capacity <= 4_294_967_296) return u32;
    return usize;
}

pub fn Table(comptime capacity: usize) type {
    const Index = SlotIndex(capacity);
    return struct {
        ids: [capacity]u64 = [_]u64{0} ** capacity,
        slot_indices: [capacity]Index = [_]Index{0} ** capacity,
        states: [capacity]State = [_]State{.empty} ** capacity,
    };
}

pub inline fn emptyTable(comptime capacity: usize) Table(capacity) {
    return .{};
}

pub inline fn lookup(comptime capacity: usize, table: *const Table(capacity), id: u64) ?usize {
    if (id == 0) return null;

    var index = hash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table.states[index]) {
            .empty => return null,
            .filled => if (table.ids[index] == id) return @intCast(table.slot_indices[index]),
            .tombstone => {},
        }
        index = (index + 1) % capacity;
    }
    return null;
}

pub inline fn insert(comptime capacity: usize, table: *Table(capacity), id: u64, slot_index: usize, comptime invariant_message: []const u8) void {
    if (id == 0) native_util.impossibleByInvariant(invariant_message);
    if (slot_index >= capacity) native_util.impossibleByInvariant("id index slot fits its compact index type");

    var index = hash(id, capacity);
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table.states[index]) {
            .empty => {
                const insert_index = first_tombstone orelse index;
                table.states[insert_index] = .filled;
                table.ids[insert_index] = id;
                table.slot_indices[insert_index] = @intCast(slot_index);
                return;
            },
            .filled => {
                if (table.ids[index] == id) {
                    table.slot_indices[index] = @intCast(slot_index);
                    return;
                }
            },
            .tombstone => {
                if (first_tombstone == null) first_tombstone = index;
            },
        }
        index = (index + 1) % capacity;
    }

    if (first_tombstone) |insert_index| {
        compactAndInsert(capacity, table, id, slot_index, insert_index);
        return;
    }

    native_util.impossibleByInvariant("id index capacity covers all live slots");
}

pub inline fn insertAbsent(
    comptime capacity: usize,
    table: *Table(capacity),
    id: u64,
    slot_index: usize,
    comptime invariant_message: []const u8,
) void {
    if (id == 0) native_util.impossibleByInvariant(invariant_message);
    if (slot_index >= capacity) native_util.impossibleByInvariant("id index slot fits its compact index type");

    var index = hash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table.states[index]) {
            .empty, .tombstone => {
                table.states[index] = .filled;
                table.ids[index] = id;
                table.slot_indices[index] = @intCast(slot_index);
                return;
            },
            .filled => if (table.ids[index] == id) {
                native_util.impossibleByInvariant("absent id index insertion received a duplicate key");
            },
        }
        index = (index + 1) % capacity;
    }

    native_util.impossibleByInvariant("id index capacity covers all live slots");
}

pub inline fn remove(comptime capacity: usize, table: *Table(capacity), id: u64) void {
    if (id == 0) return;

    var index = hash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table.states[index]) {
            .empty => return,
            .filled => {
                if (table.ids[index] == id) {
                    table.states[index] = .tombstone;
                    table.ids[index] = 0;
                    table.slot_indices[index] = 0;
                    return;
                }
            },
            .tombstone => {},
        }
        index = (index + 1) % capacity;
    }
}

pub inline fn hash(id: u64, comptime capacity: usize) usize {
    return @as(usize, @intCast((id *% 0x9E37_79B9_7F4A_7C15) % capacity));
}

inline fn compactAndInsert(
    comptime capacity: usize,
    table: *Table(capacity),
    id: u64,
    slot_index: usize,
    fallback_index: usize,
) void {
    var compacted = emptyTable(capacity);
    for (table.states, 0..) |state, index| {
        if (state != .filled) continue;
        insertIntoSparseTable(capacity, &compacted, table.ids[index], @intCast(table.slot_indices[index]), fallback_index);
    }
    insertIntoSparseTable(capacity, &compacted, id, slot_index, fallback_index);
    table.* = compacted;
}

inline fn insertIntoSparseTable(
    comptime capacity: usize,
    table: *Table(capacity),
    id: u64,
    slot_index: usize,
    fallback_index: usize,
) void {
    if (slot_index >= capacity) native_util.impossibleByInvariant("id index slot fits its compact index type");
    var index = hash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        if (table.states[index] == .empty) {
            table.states[index] = .filled;
            table.ids[index] = id;
            table.slot_indices[index] = @intCast(slot_index);
            return;
        }
        index = (index + 1) % capacity;
    }

    table.states[fallback_index] = .filled;
    table.ids[fallback_index] = id;
    table.slot_indices[fallback_index] = @intCast(slot_index);
}

test "id indexes select the narrowest slot representation for their capacity" {
    const ByteTable = Table(256);
    const WordTable = Table(1_536);

    try std.testing.expect(SlotIndex(256) == u8);
    try std.testing.expect(SlotIndex(257) == u16);
    try std.testing.expect(SlotIndex(65_536) == u16);
    try std.testing.expect(SlotIndex(65_537) == u32);
    try std.testing.expectEqual(@as(usize, 2_048), @sizeOf(@FieldType(ByteTable, "ids")));
    try std.testing.expectEqual(@as(usize, 256), @sizeOf(@FieldType(ByteTable, "slot_indices")));
    try std.testing.expectEqual(@as(usize, 256), @sizeOf(@FieldType(ByteTable, "states")));
    try std.testing.expectEqual(@as(usize, 2_560), @sizeOf(ByteTable));
    try std.testing.expectEqual(@as(usize, 16_896), @sizeOf(WordTable));
    try std.testing.expect(@alignOf(@FieldType(WordTable, "ids")) >= @alignOf(u64));
    try std.testing.expect(@sizeOf(WordTable) < 1_536 * 16);
}

test "compact id indexes retain the highest slot for each integer width" {
    var byte_index = emptyTable(256);
    insert(256, &byte_index, 1, 255, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 255), lookup(256, &byte_index, 1));

    var word_index = emptyTable(257);
    insert(257, &word_index, 2, 256, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 256), lookup(257, &word_index, 2));
}

test "compact id indexes preserve lookup replacement removal and tombstone reuse" {
    var table = emptyTable(8);
    insert(8, &table, 11, 3, "test ids are nonzero");
    insert(8, &table, 19, 4, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 3), lookup(8, &table, 11));
    try std.testing.expectEqual(@as(?usize, 4), lookup(8, &table, 19));

    insert(8, &table, 11, 6, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 6), lookup(8, &table, 11));
    remove(8, &table, 11);
    try std.testing.expectEqual(@as(?usize, null), lookup(8, &table, 11));

    insertAbsent(8, &table, 27, 7, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 7), lookup(8, &table, 27));
}

test "compact id indexes preserve full-table tombstone compaction" {
    var table = emptyTable(4);
    for (1..5) |id| insert(4, &table, id, id - 1, "test ids are nonzero");
    remove(4, &table, 2);
    insert(4, &table, 5, 1, "test ids are nonzero");

    try std.testing.expectEqual(@as(?usize, 0), lookup(4, &table, 1));
    try std.testing.expectEqual(@as(?usize, null), lookup(4, &table, 2));
    try std.testing.expectEqual(@as(?usize, 2), lookup(4, &table, 3));
    try std.testing.expectEqual(@as(?usize, 3), lookup(4, &table, 4));
    try std.testing.expectEqual(@as(?usize, 1), lookup(4, &table, 5));
}
