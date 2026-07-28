const native_util = @import("util.zig");

pub const State = enum(u8) {
    empty,
    filled,
    tombstone,
};

pub const Slot = struct {
    state: State = .empty,
    id: u64 = 0,
    slot_index: usize = 0,
};

pub inline fn emptyTable(comptime capacity: usize) [capacity]Slot {
    return [_]Slot{Slot{}} ** capacity;
}

pub inline fn lookup(comptime capacity: usize, table: *const [capacity]Slot, id: u64) ?usize {
    if (id == 0) return null;

    var index = hash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry = table[index];
        switch (entry.state) {
            .empty => return null,
            .filled => if (entry.id == id) return entry.slot_index,
            .tombstone => {},
        }
        index = (index + 1) % capacity;
    }
    return null;
}

pub inline fn insert(comptime capacity: usize, table: *[capacity]Slot, id: u64, slot_index: usize, comptime invariant_message: []const u8) void {
    if (id == 0) native_util.impossibleByInvariant(invariant_message);

    var index = hash(id, capacity);
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table[index].state) {
            .empty => {
                const insert_index = first_tombstone orelse index;
                table[insert_index] = .{
                    .state = .filled,
                    .id = id,
                    .slot_index = slot_index,
                };
                return;
            },
            .filled => {
                if (table[index].id == id) {
                    table[index].slot_index = slot_index;
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

/// Insert a key that the caller has already proved absent. Unlike insert(),
/// this can claim the first tombstone immediately instead of probing onward
/// for a possible duplicate, which keeps high-churn arena indexes bounded by
/// the nearest reusable bucket.
pub inline fn insertAbsent(
    comptime capacity: usize,
    table: *[capacity]Slot,
    id: u64,
    slot_index: usize,
    comptime invariant_message: []const u8,
) void {
    if (id == 0) native_util.impossibleByInvariant(invariant_message);

    var index = hash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table[index].state) {
            .empty, .tombstone => {
                table[index] = .{
                    .state = .filled,
                    .id = id,
                    .slot_index = slot_index,
                };
                return;
            },
            .filled => if (table[index].id == id) {
                native_util.impossibleByInvariant("absent id index insertion received a duplicate key");
            },
        }
        index = (index + 1) % capacity;
    }

    native_util.impossibleByInvariant("id index capacity covers all live slots");
}

pub inline fn remove(comptime capacity: usize, table: *[capacity]Slot, id: u64) void {
    if (id == 0) return;

    var index = hash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table[index].state) {
            .empty => return,
            .filled => {
                if (table[index].id == id) {
                    table[index].state = .tombstone;
                    table[index].id = 0;
                    table[index].slot_index = 0;
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
    table: *[capacity]Slot,
    id: u64,
    slot_index: usize,
    fallback_index: usize,
) void {
    var compacted = emptyTable(capacity);
    for (table.*) |entry| {
        if (entry.state != .filled) continue;
        insertIntoSparseTable(capacity, &compacted, entry.id, entry.slot_index, fallback_index);
    }
    insertIntoSparseTable(capacity, &compacted, id, slot_index, fallback_index);
    table.* = compacted;
}

inline fn insertIntoSparseTable(
    comptime capacity: usize,
    table: *[capacity]Slot,
    id: u64,
    slot_index: usize,
    fallback_index: usize,
) void {
    var index = hash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        if (table[index].state == .empty) {
            table[index] = .{
                .state = .filled,
                .id = id,
                .slot_index = slot_index,
            };
            return;
        }
        index = (index + 1) % capacity;
    }

    table[fallback_index] = .{
        .state = .filled,
        .id = id,
        .slot_index = slot_index,
    };
}
