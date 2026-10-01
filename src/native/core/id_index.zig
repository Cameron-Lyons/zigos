const std = @import("std");
const native_util = @import("util.zig");

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
        // Zero is reserved by every caller, so membership needs no extra state.
        ids: [capacity]u64 = [_]u64{0} ** capacity,
        slot_indices: [capacity]Index = [_]Index{0} ** capacity,
    };
}

pub inline fn emptyTable(comptime capacity: usize) Table(capacity) {
    return .{};
}

pub inline fn lookup(comptime capacity: usize, table: *const Table(capacity), id: u64) ?usize {
    if (id == 0) return null;

    var index = hash(id, capacity);
    for (0..capacity) |_| {
        const stored_id = table.ids[index];
        if (stored_id == 0) return null;
        if (stored_id == id) return @intCast(table.slot_indices[index]);
        index = nextIndex(index, capacity);
    }
    return null;
}

pub inline fn insert(comptime capacity: usize, table: *Table(capacity), id: u64, slot_index: usize, comptime invariant_message: []const u8) void {
    if (id == 0) native_util.impossibleByInvariant(invariant_message);
    if (slot_index >= capacity) native_util.impossibleByInvariant("id index slot fits its compact index type");

    var index = hash(id, capacity);
    for (0..capacity) |_| {
        const stored_id = table.ids[index];
        if (stored_id == 0 or stored_id == id) {
            table.ids[index] = id;
            table.slot_indices[index] = @intCast(slot_index);
            return;
        }
        index = nextIndex(index, capacity);
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
    for (0..capacity) |_| {
        const stored_id = table.ids[index];
        if (stored_id == 0) {
            table.ids[index] = id;
            table.slot_indices[index] = @intCast(slot_index);
            return;
        }
        if (stored_id == id) native_util.impossibleByInvariant("absent id index insertion received a duplicate key");
        index = nextIndex(index, capacity);
    }
    native_util.impossibleByInvariant("id index capacity covers all live slots");
}

pub inline fn remove(comptime capacity: usize, table: *Table(capacity), id: u64) void {
    if (id == 0) return;

    var hole = hash(id, capacity);
    for (0..capacity) |_| {
        const stored_id = table.ids[hole];
        if (stored_id == 0) return;
        if (stored_id == id) break;
        hole = nextIndex(hole, capacity);
    } else return;

    // Shift only entries whose probe path crosses the hole. A full table has
    // no empty terminator, so stop before scanning the original slot again.
    // This preserves lookup termination without accumulating deleted entries
    // or rebuilding a second table on the kernel stack.
    var index = nextIndex(hole, capacity);
    for (0..capacity - 1) |_| {
        const stored_id = table.ids[index];
        if (stored_id == 0) break;
        const home = hash(stored_id, capacity);
        if (probeDistance(home, hole, capacity) < probeDistance(home, index, capacity)) {
            table.ids[hole] = stored_id;
            table.slot_indices[hole] = table.slot_indices[index];
            hole = index;
        }
        index = nextIndex(index, capacity);
    }
    table.ids[hole] = 0;
    table.slot_indices[hole] = 0;
}

pub inline fn hash(id: u64, comptime capacity: usize) usize {
    if (capacity == 0) @compileError("id index requires at least one slot");
    // Mix all 64 bits before reduction. Multiplication alone discards handle
    // generations and every other high bit when capacity is a power of two.
    var mixed = id;
    mixed = (mixed ^ (mixed >> 30)) *% 0xBF58_476D_1CE4_E5B9;
    mixed = (mixed ^ (mixed >> 27)) *% 0x94D0_49BB_1331_11EB;
    mixed ^= mixed >> 31;
    return @intCast(mixed % capacity);
}

inline fn nextIndex(index: usize, comptime capacity: usize) usize {
    return if (index == capacity - 1) 0 else index + 1;
}

inline fn probeDistance(home: usize, index: usize, comptime capacity: usize) usize {
    return if (index >= home) index - home else capacity - home + index;
}

test "id indexes select the narrowest slot representation without membership bytes" {
    const ByteTable = Table(256);
    const WordTable = Table(1_536);

    try std.testing.expect(SlotIndex(256) == u8);
    try std.testing.expect(SlotIndex(257) == u16);
    try std.testing.expect(SlotIndex(65_536) == u16);
    try std.testing.expect(SlotIndex(65_537) == u32);
    try std.testing.expectEqual(@as(usize, 2_048), @sizeOf(@FieldType(ByteTable, "ids")));
    try std.testing.expectEqual(@as(usize, 256), @sizeOf(@FieldType(ByteTable, "slot_indices")));
    try std.testing.expectEqual(@as(usize, 2_304), @sizeOf(ByteTable));
    try std.testing.expectEqual(@as(usize, 15_360), @sizeOf(WordTable));
    try std.testing.expect(@alignOf(@FieldType(WordTable, "ids")) >= @alignOf(u64));
}

test "compact id indexes retain the highest slot for each integer width" {
    var byte_index = emptyTable(256);
    insert(256, &byte_index, 1, 255, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 255), lookup(256, &byte_index, 1));

    var word_index = emptyTable(257);
    insert(257, &word_index, 2, 256, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 256), lookup(257, &word_index, 2));
}

test "id indexes mix handle generations before selecting power of two buckets" {
    var buckets: [256]bool = @splat(false);
    for (1..257) |generation| buckets[hash((@as(u64, generation) << 32) | 7, 256)] = true;
    var occupied: usize = 0;
    for (buckets) |used| occupied += @intFromBool(used);
    // The former low-bit hash put every generation of this slot in one bucket.
    try std.testing.expect(occupied >= 128);
}

test "id indexes preserve updates and zero-key misses" {
    var table = emptyTable(8);
    const keys = collidingKeys(8, 7, 3);
    insert(8, &table, keys[0], 3, "test ids are nonzero");
    insert(8, &table, keys[1], 4, "test ids are nonzero");
    insert(8, &table, keys[0], 6, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 6), lookup(8, &table, keys[0]));
    remove(8, &table, keys[0]);
    try std.testing.expectEqual(@as(?usize, null), lookup(8, &table, keys[0]));
    try std.testing.expectEqual(@as(?usize, 4), lookup(8, &table, keys[1]));
    insertAbsent(8, &table, keys[2], 7, "test ids are nonzero");
    try std.testing.expectEqual(@as(?usize, 7), lookup(8, &table, keys[2]));
    try std.testing.expect(lookup(8, &table, 0) == null);
    const before = table;
    remove(8, &table, 0);
    remove(8, &table, keys[0]);
    try std.testing.expectEqualDeep(before, table);
}

test "id index deletion preserves every small colliding insertion and removal order" {
    inline for (.{ 1, 2, 3, 4, 5 }) |capacity| {
        const keys = collidingKeys(capacity, capacity - 1, capacity + 1);
        try checkInsertionOrders(capacity, emptyTable(capacity), keys, @splat(false), 0);
    }
}

test "id index deletion skips unrelated homes within wrapped probe chains" {
    inline for (.{ 7, 8, 15 }) |capacity| {
        const collision = collidingKeys(capacity, capacity - 1, 3);
        const at_zero = collidingKeys(capacity, 0, 1)[0];
        const at_one = collidingKeys(capacity, 1, 1)[0];
        var table = emptyTable(capacity);
        insertAbsent(capacity, &table, collision[0], 0, "test");
        insertAbsent(capacity, &table, at_zero, 1, "test");
        insertAbsent(capacity, &table, collision[1], 2, "test");
        insertAbsent(capacity, &table, at_one, 3, "test");
        insertAbsent(capacity, &table, collision[2], 4, "test");
        remove(capacity, &table, collision[0]);
        try std.testing.expect(lookup(capacity, &table, collision[0]) == null);
        try std.testing.expectEqual(@as(?usize, 1), lookup(capacity, &table, at_zero));
        try std.testing.expectEqual(@as(?usize, 2), lookup(capacity, &table, collision[1]));
        try std.testing.expectEqual(@as(?usize, 3), lookup(capacity, &table, at_one));
        try std.testing.expectEqual(@as(?usize, 4), lookup(capacity, &table, collision[2]));
    }
}

test "id index randomized churn matches an independent bounded key model" {
    inline for (.{ 1, 3, 8, 17, 32 }) |capacity| {
        const domain = 64;
        var table = emptyTable(capacity);
        var expected: [domain]?usize = @splat(null);
        var count: usize = 0;
        var prng = std.Random.DefaultPrng.init(0x5EED + capacity);
        const random = prng.random();
        for (0..10_000) |_| {
            const key_index = random.uintLessThan(usize, domain);
            const id = (@as(u64, key_index + 1) << 32) | @as(u64, key_index % 7);
            if (random.boolean()) {
                remove(capacity, &table, id);
                if (expected[key_index] != null) count -= 1;
                expected[key_index] = null;
            } else if (expected[key_index] != null or count < capacity) {
                const slot_index = random.uintLessThan(usize, capacity);
                if (expected[key_index] == null) count += 1;
                insert(capacity, &table, id, slot_index, "test");
                expected[key_index] = slot_index;
            }
            for (expected, 0..) |slot_index, i| {
                const query = (@as(u64, i + 1) << 32) | @as(u64, i % 7);
                try std.testing.expectEqual(slot_index, lookup(capacity, &table, query));
            }
        }
    }
}

test "id indexes return to an empty table after visiting every home bucket" {
    inline for (.{ 1, 7, 32 }) |capacity| {
        var table = emptyTable(capacity);
        for (0..capacity) |home| {
            const id = collidingKeys(capacity, home, 1)[0];
            insertAbsent(capacity, &table, id, 0, "test");
            remove(capacity, &table, id);
        }
        try std.testing.expectEqualDeep(emptyTable(capacity), table);
    }
}

fn collidingKeys(comptime capacity: usize, home: usize, comptime count: usize) [count]u64 {
    var result: [count]u64 = undefined;
    var found: usize = 0;
    var candidate: u64 = 1;
    while (found < count) : (candidate += 1) {
        if (hash(candidate, capacity) != home) continue;
        result[found] = candidate;
        found += 1;
    }
    return result;
}

fn checkInsertionOrders(
    comptime capacity: usize,
    table: Table(capacity),
    keys: [capacity + 1]u64,
    inserted: [capacity]bool,
    count: usize,
) !void {
    if (count == capacity) {
        var expected: [capacity]?usize = undefined;
        for (&expected, 0..) |*slot, i| slot.* = i;
        return checkRemovalOrders(capacity, table, keys, expected);
    }
    for (inserted, 0..) |used, i| {
        if (used) continue;
        var next_table = table;
        var next_inserted = inserted;
        insertAbsent(capacity, &next_table, keys[i], i, "test");
        next_inserted[i] = true;
        try checkInsertionOrders(capacity, next_table, keys, next_inserted, count + 1);
    }
}

fn checkRemovalOrders(
    comptime capacity: usize,
    table: Table(capacity),
    keys: [capacity + 1]u64,
    expected: [capacity]?usize,
) !void {
    for (expected, 0..) |slot_index, i| try std.testing.expectEqual(slot_index, lookup(capacity, &table, keys[i]));
    try std.testing.expect(lookup(capacity, &table, keys[capacity]) == null);
    for (expected, 0..) |slot_index, i| {
        if (slot_index == null) continue;
        var next_table = table;
        var next_expected = expected;
        remove(capacity, &next_table, keys[i]);
        next_expected[i] = null;
        // The newly freed hole must accept a missing key even when the table
        // was full, and deletion must preserve every other mapping afterward.
        var reused = next_table;
        insertAbsent(capacity, &reused, keys[capacity], i, "test");
        try std.testing.expectEqual(@as(?usize, i), lookup(capacity, &reused, keys[capacity]));
        for (next_expected, 0..) |value, j| try std.testing.expectEqual(value, lookup(capacity, &reused, keys[j]));
        try checkRemovalOrders(capacity, next_table, keys, next_expected);
    }
}
