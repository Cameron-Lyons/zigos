const std = @import("std");
const abi = @import("abi.zig");

pub const MAX_SHARED_MEMORY_OBJECTS: usize = 24;
pub const MAX_MAPPINGS_PER_OBJECT: usize = 8;

pub const Object = struct {
    id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    revocation_generation: u32,
    revoked: bool,
    mapped_task_ids: [MAX_MAPPINGS_PER_OBJECT]u64,
    mapping_count: usize,
};

pub const Error = error{
    AlreadyMapped,
    MappingNotFound,
    Revoked,
    SizeZero,
    TableFull,
    SharedMemoryNotFound,
};

const ObjectSlot = struct {
    in_use: bool = false,
    object: Object = zeroObject(),
};

pub const Table = struct {
    next_object_id: u64 = 1,
    slots: [MAX_SHARED_MEMORY_OBJECTS]ObjectSlot = [_]ObjectSlot{ObjectSlot{}} ** MAX_SHARED_MEMORY_OBJECTS,

    pub fn init() Table {
        return .{};
    }

    pub fn create(self: *Table, owner_task_id: u64, size_bytes: usize) Error!Object {
        if (size_bytes == 0) return error.SizeZero;

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.object = .{
                .id = self.allocateObjectId(),
                .owner_task_id = owner_task_id,
                .size_bytes = size_bytes,
                .revocation_generation = 1,
                .revoked = false,
                .mapped_task_ids = [_]u64{0} ** MAX_MAPPINGS_PER_OBJECT,
                .mapping_count = 0,
            };
            return slot.object;
        }

        return error.TableFull;
    }

    pub fn map(self: *Table, object_id: u64, task_id: u64) Error!void {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;

        for (object.mapped_task_ids[0..object.mapping_count]) |mapped_task_id| {
            if (mapped_task_id == task_id) return error.AlreadyMapped;
        }
        if (object.mapping_count >= object.mapped_task_ids.len) return error.TableFull;

        object.mapped_task_ids[object.mapping_count] = task_id;
        object.mapping_count += 1;
    }

    pub fn unmap(self: *Table, object_id: u64, task_id: u64) Error!bool {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        var index: usize = 0;
        while (index < object.mapping_count) : (index += 1) {
            if (object.mapped_task_ids[index] != task_id) continue;

            var tail = index;
            while (tail + 1 < object.mapping_count) : (tail += 1) {
                object.mapped_task_ids[tail] = object.mapped_task_ids[tail + 1];
            }
            object.mapping_count -= 1;
            object.mapped_task_ids[object.mapping_count] = 0;
            return true;
        }
        return false;
    }

    pub fn revoke(self: *Table, object_id: u64) Error!void {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        object.revoked = true;
        object.revocation_generation += 1;
        object.mapping_count = 0;
        object.mapped_task_ids = [_]u64{0} ** MAX_MAPPINGS_PER_OBJECT;
    }

    pub fn descriptor(self: *const Table, object_id: u64) Error!abi.SharedMemoryDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return .{
            .object_id = object.id,
            .owner_task_id = object.owner_task_id,
            .size_bytes = object.size_bytes,
            .revocation_generation = object.revocation_generation,
            .mapped_task_count = @intCast(object.mapping_count),
            .flags = if (object.revoked) 1 else 0,
        };
    }

    pub fn mappingsForTask(self: *const Table, task_id: u64) u16 {
        var count: u16 = 0;
        for (self.slots) |slot| {
            if (!slot.in_use or slot.object.revoked) continue;
            for (slot.object.mapped_task_ids[0..slot.object.mapping_count]) |mapped_task_id| {
                if (mapped_task_id == task_id) count += 1;
            }
        }
        return count;
    }

    fn allocateObjectId(self: *Table) u64 {
        defer self.next_object_id += 1;
        return self.next_object_id;
    }

    fn find(self: *Table, object_id: u64) ?*Object {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.object.id == object_id) return &slot.object;
        }
        return null;
    }

    fn findConst(self: *const Table, object_id: u64) ?*const Object {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.object.id == object_id) return &slot.object;
        }
        return null;
    }
};

fn zeroObject() Object {
    return .{
        .id = 0,
        .owner_task_id = 0,
        .size_bytes = 0,
        .revocation_generation = 0,
        .revoked = false,
        .mapped_task_ids = [_]u64{0} ** MAX_MAPPINGS_PER_OBJECT,
        .mapping_count = 0,
    };
}

test "shared memory objects map unmap and revoke across tasks" {
    var table = Table.init();
    const object = try table.create(7, 4096);

    try table.map(object.id, 7);
    try table.map(object.id, 8);
    try std.testing.expectEqual(@as(u16, 2), (try table.descriptor(object.id)).mapped_task_count);
    try std.testing.expect(try table.unmap(object.id, 8));

    try table.revoke(object.id);
    const descriptor = try table.descriptor(object.id);
    try std.testing.expectEqual(@as(u16, 0), descriptor.mapped_task_count);
    try std.testing.expectEqual(@as(u16, 1), descriptor.flags);
    try std.testing.expectError(error.Revoked, table.map(object.id, 9));
}
