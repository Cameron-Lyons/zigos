const builtin = @import("builtin");
const std = @import("std");
const id_index = @import("id_index.zig");
const native_util = @import("util.zig");

pub fn firstFreeSlot(comptime Slot: type, comptime capacity: usize, slots: *[capacity]Slot) ?*Slot {
    for (slots) |*slot| {
        if (!slot.in_use) return slot;
    }
    return null;
}

pub fn firstFreeSlotIndex(comptime Slot: type, comptime capacity: usize, slots: *const [capacity]Slot) ?usize {
    for (slots, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

pub fn findSlot(
    comptime Slot: type,
    comptime capacity: usize,
    slots: *[capacity]Slot,
    context: anytype,
    comptime matches: anytype,
) ?*Slot {
    for (slots) |*slot| {
        if (!slot.in_use) continue;
        if (matches(context, slot)) return slot;
    }
    return null;
}

pub fn findConstSlot(
    comptime Slot: type,
    comptime capacity: usize,
    slots: *const [capacity]Slot,
    context: anytype,
    comptime matches: anytype,
) ?*const Slot {
    for (slots) |*slot| {
        if (!slot.in_use) continue;
        if (matches(context, slot)) return slot;
    }
    return null;
}

pub fn countInUse(comptime Slot: type, comptime capacity: usize, slots: *const [capacity]Slot) usize {
    var count: usize = 0;
    for (slots) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

pub fn countMatching(
    comptime Slot: type,
    comptime capacity: usize,
    slots: *const [capacity]Slot,
    context: anytype,
    comptime matches: anytype,
) usize {
    var count: usize = 0;
    for (slots) |*slot| {
        if (!slot.in_use) continue;
        if (matches(context, slot)) count += 1;
    }
    return count;
}

pub fn findIndexedSlot(
    comptime Slot: type,
    comptime capacity: usize,
    comptime index_capacity: usize,
    slots: *[capacity]Slot,
    index_slots: *const [index_capacity]id_index.Slot,
    id: u64,
    comptime idOf: anytype,
    context: anytype,
    comptime matches: anytype,
) ?*Slot {
    if (id_index.lookup(index_capacity, index_slots, id)) |slot_index| {
        if (slot_index >= capacity) native_util.impossibleByInvariant("fixed table index points outside slots");
        const slot = &slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("fixed table index points at a free slot");
        if (idOf(slot) != id) native_util.impossibleByInvariant("fixed table index points at the wrong key");
        if (!matches(context, slot)) native_util.impossibleByInvariant("fixed table indexed key does not satisfy the exact lookup");
        return slot;
    }
    if (debugIndexChecksEnabled() and findSlot(Slot, capacity, slots, context, matches) != null) {
        native_util.impossibleByInvariant("fixed table index missed a live slot");
    }
    return null;
}

pub fn findIndexedConstSlot(
    comptime Slot: type,
    comptime capacity: usize,
    comptime index_capacity: usize,
    slots: *const [capacity]Slot,
    index_slots: *const [index_capacity]id_index.Slot,
    id: u64,
    comptime idOf: anytype,
    context: anytype,
    comptime matches: anytype,
) ?*const Slot {
    if (id_index.lookup(index_capacity, index_slots, id)) |slot_index| {
        if (slot_index >= capacity) native_util.impossibleByInvariant("fixed table index points outside slots");
        const slot = &slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("fixed table index points at a free slot");
        if (idOf(slot) != id) native_util.impossibleByInvariant("fixed table index points at the wrong key");
        if (!matches(context, slot)) native_util.impossibleByInvariant("fixed table indexed key does not satisfy the exact lookup");
        return slot;
    }
    if (debugIndexChecksEnabled() and findConstSlot(Slot, capacity, slots, context, matches) != null) {
        native_util.impossibleByInvariant("fixed table index missed a live slot");
    }
    return null;
}

fn debugIndexChecksEnabled() bool {
    return builtin.mode == .Debug;
}

const TestSlot = struct {
    in_use: bool = false,
    id: u64 = 0,
    label: []const u8 = "",
};

const TestFind = struct {
    fn byId(id: u64, slot: *const TestSlot) bool {
        return slot.id == id;
    }

    fn byLabel(label: []const u8, slot: *const TestSlot) bool {
        return std.mem.eql(u8, slot.label, label);
    }

    fn idOf(slot: *const TestSlot) u64 {
        return slot.id;
    }
};

test "fixed table helper allocates finds counts and uses id indexes" {
    var slots = [_]TestSlot{TestSlot{}} ** 4;
    var index = id_index.emptyTable(8);

    const first = firstFreeSlot(TestSlot, slots.len, &slots).?;
    first.* = .{ .in_use = true, .id = 41, .label = "alpha" };
    id_index.insert(index.len, &index, first.id, 0, "test index covers slots");

    const second_index = firstFreeSlotIndex(TestSlot, slots.len, &slots).?;
    slots[second_index] = .{ .in_use = true, .id = 42, .label = "beta" };
    id_index.insert(index.len, &index, slots[second_index].id, second_index, "test index covers slots");

    try std.testing.expectEqual(@as(usize, 2), countInUse(TestSlot, slots.len, &slots));
    try std.testing.expectEqual(@as(usize, 1), countMatching(TestSlot, slots.len, &slots, "beta", TestFind.byLabel));
    try std.testing.expectEqualStrings("alpha", findSlot(TestSlot, slots.len, &slots, @as(u64, 41), TestFind.byId).?.label);
    try std.testing.expectEqualStrings("beta", findIndexedSlot(
        TestSlot,
        slots.len,
        index.len,
        &slots,
        &index,
        42,
        TestFind.idOf,
        @as(u64, 42),
        TestFind.byId,
    ).?.label);
}
