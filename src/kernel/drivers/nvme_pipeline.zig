const std = @import("std");

pub const DEPTH: usize = 2;

// submit must either return an accepted command or fail before submission.
// Revocation/cancellation stops refill, but every accepted DMA command retains
// its slot until an authenticated completion or caller containment.
pub fn transfer(comptime Payload: type, io: anytype, total_sectors: usize, chunk_sectors: usize, sector_bytes: usize) @TypeOf(io.*).Error!void {
    var slots = SlotSet(Payload){};
    var next_sector: usize = 0;
    var failure: ?@TypeOf(io.*).Error = null;
    while (next_sector < total_sectors or slots.active_count != 0) {
        if (failure == null) {
            if (io.cancelled()) failure = error.Cancelled else if (!io.authorized()) failure = error.AuthorityRevoked;
        }
        while (failure == null and next_sector < total_sectors and slots.active_count < DEPTH) {
            const slot_index = slots.freeIndex() orelse unreachable;
            const chunk = @min(total_sectors - next_sector, chunk_sectors);
            const command = io.submit(slot_index, next_sector, chunk) catch |err| {
                failure = err;
                break;
            };
            if (!slots.activate(slot_index, command, next_sector, chunk * sector_bytes)) unreachable;
            next_sector += chunk;
        }
        if (slots.active_count == 0) break;
        var pending: [DEPTH]Payload = undefined;
        const cid = try io.wait(slots.collect(&pending));
        const completed = slots.complete(cid) orelse return error.CompletionOwnershipMismatch;
        io.completed(completed);
    }
    if (failure == null) {
        if (io.cancelled()) failure = error.Cancelled else if (!io.authorized()) failure = error.AuthorityRevoked;
    }
    if (failure) |err| return err;
}

pub fn SlotSet(comptime Payload: type) type {
    comptime {
        if (!@hasField(Payload, "cid") or @FieldType(Payload, "cid") != u16) {
            @compileError("NVMe pipeline payloads require a u16 cid field");
        }
    }
    return struct {
        const Self = @This();

        pub const Completed = struct {
            index: usize,
            payload: Payload,
            sector_offset: usize,
            byte_count: usize,
        };

        const Slot = struct {
            active: bool = false,
            payload: Payload = undefined,
            sector_offset: usize = 0,
            byte_count: usize = 0,
        };

        slots: [DEPTH]Slot = @as([DEPTH]Slot, @splat(.{})),
        active_count: usize = 0,

        pub fn freeIndex(self: *const Self) ?usize {
            for (self.slots, 0..) |slot, index| {
                if (!slot.active) return index;
            }
            return null;
        }

        pub fn activate(
            self: *Self,
            index: usize,
            payload: Payload,
            sector_offset: usize,
            byte_count: usize,
        ) bool {
            if (index >= self.slots.len or self.slots[index].active) return false;
            self.slots[index] = .{
                .active = true,
                .payload = payload,
                .sector_offset = sector_offset,
                .byte_count = byte_count,
            };
            self.active_count += 1;
            return true;
        }

        pub fn collect(self: *const Self, output: *[DEPTH]Payload) []const Payload {
            var count: usize = 0;
            for (self.slots) |slot| {
                if (!slot.active) continue;
                output[count] = slot.payload;
                count += 1;
            }
            return output[0..count];
        }

        pub fn complete(self: *Self, cid: u16) ?Completed {
            for (&self.slots, 0..) |*slot, index| {
                if (!slot.active or slot.payload.cid != cid) continue;
                const completed = Completed{
                    .index = index,
                    .payload = slot.payload,
                    .sector_offset = slot.sector_offset,
                    .byte_count = slot.byte_count,
                };
                slot.active = false;
                self.active_count -= 1;
                return completed;
            }
            return null;
        }
    };
}

test "two-slot NVMe pipeline accepts out-of-order completions" {
    const Payload = struct { cid: u16 };
    const Slots = SlotSet(Payload);
    var slots = Slots{};

    const first = slots.freeIndex().?;
    try std.testing.expect(slots.activate(first, .{ .cid = 41 }, 0, 128 * 1024));
    const second = slots.freeIndex().?;
    try std.testing.expect(slots.activate(second, .{ .cid = 42 }, 256, 128 * 1024));
    try std.testing.expect(slots.freeIndex() == null);
    try std.testing.expectEqual(DEPTH, slots.active_count);

    var pending: [DEPTH]Payload = undefined;
    const collected = slots.collect(&pending);
    try std.testing.expectEqual(@as(usize, 2), collected.len);
    try std.testing.expectEqual(@as(u16, 41), collected[0].cid);
    try std.testing.expectEqual(@as(u16, 42), collected[1].cid);
    const completed_second = slots.complete(42).?;
    try std.testing.expectEqual(second, completed_second.index);
    try std.testing.expectEqual(@as(usize, 256), completed_second.sector_offset);
    try std.testing.expectEqual(@as(usize, 1), slots.active_count);
    try std.testing.expect(slots.freeIndex() != null);
    try std.testing.expect(slots.complete(99) == null);
    try std.testing.expectEqual(@as(u16, 41), slots.complete(41).?.payload.cid);
    try std.testing.expectEqual(@as(usize, 0), slots.active_count);
}
