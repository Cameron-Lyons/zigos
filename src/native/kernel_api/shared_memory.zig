const std = @import("std");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");

pub const MAX_SHARED_MEMORY_OBJECTS: usize = 24;
pub const MAX_MAPPINGS_PER_OBJECT: usize = 8;
const SHARED_MEMORY_INDEX_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * 2;
const MAPPING_EDGE_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * MAX_MAPPINGS_PER_OBJECT;
const MAPPING_INDEX_CAPACITY: usize = MAPPING_EDGE_CAPACITY * 2;

pub const ComputeTarget = enum(u8) {
    cpu,
    gpu,
    npu,
    media,
};

pub const ComputeAccess = packed struct(u8) {
    cpu: bool = true,
    gpu: bool = false,
    npu: bool = false,
    media: bool = false,
    _reserved: u4 = 0,

    pub fn allows(self: ComputeAccess, target: ComputeTarget) bool {
        return switch (target) {
            .cpu => self.cpu,
            .gpu => self.gpu,
            .npu => self.npu,
            .media => self.media,
        };
    }

    pub fn empty() ComputeAccess {
        return .{ .cpu = false };
    }
};

pub const Object = struct {
    id: ids.SharedMemoryId,
    owner_task_id: ids.TaskId,
    size_bytes: usize,
    revocation_generation: u32,
    attachment_generation: u32,
    revoked: bool,
    compute_access: ComputeAccess,
    attached_compute: ComputeAccess,
    mapped_task_ids: [MAX_MAPPINGS_PER_OBJECT]ids.TaskId,
    mapping_count: usize,

    pub fn allowsCompute(self: *const Object, target: ComputeTarget) bool {
        return self.compute_access.allows(target);
    }

    pub fn attachedTo(self: *const Object, target: ComputeTarget) bool {
        return self.attached_compute.allows(target);
    }
};

pub const Error = error{
    AcceleratorAccessDenied,
    AcceleratorAlreadyAttached,
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

const ObjectArena = indexed_arena.IndexedArenaWithKey(ids.SharedMemoryId, ObjectSlot, MAX_SHARED_MEMORY_OBJECTS, SHARED_MEMORY_INDEX_CAPACITY, objectSlotId);
const MappingIndex = indexed_arena.MultimapIndex(MAPPING_EDGE_CAPACITY, MAPPING_EDGE_CAPACITY, MAPPING_INDEX_CAPACITY);

pub const Table = struct {
    next_object_id: u64 = 1,
    arena: ObjectArena = ObjectArena.init(),
    mapping_index: MappingIndex = MappingIndex.init(),

    pub fn init() Table {
        return .{};
    }

    pub fn create(self: *Table, owner_task_id: ids.TaskId, size_bytes: usize) Error!Object {
        return self.createWithAccess(owner_task_id, size_bytes, .{});
    }

    pub fn createWithAccess(
        self: *Table,
        owner_task_id: ids.TaskId,
        size_bytes: usize,
        compute_access: ComputeAccess,
    ) Error!Object {
        if (size_bytes == 0) return error.SizeZero;

        const object_id = self.allocateObjectId();
        const slot = self.arena.reserve(object_id) orelse return error.TableFull;
        slot.object = .{
            .id = object_id,
            .owner_task_id = owner_task_id,
            .size_bytes = size_bytes,
            .revocation_generation = 1,
            .attachment_generation = 1,
            .revoked = false,
            .compute_access = compute_access,
            .attached_compute = ComputeAccess.empty(),
            .mapped_task_ids = [_]ids.TaskId{ids.TaskId.zero} ** MAX_MAPPINGS_PER_OBJECT,
            .mapping_count = 0,
        };
        return slot.object;
    }

    pub fn map(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!void {
        const object_slot_index = self.arena.slotIndexOf(object_id) orelse return error.SharedMemoryNotFound;
        const object = &self.arena.slots[object_slot_index].object;
        if (object.revoked) return error.Revoked;

        for (object.mapped_task_ids[0..object.mapping_count]) |mapped_task_id| {
            if (mapped_task_id.eql(task_id)) return error.AlreadyMapped;
        }
        if (object.mapping_count >= object.mapped_task_ids.len) return error.TableFull;

        if (!self.mapping_index.append(task_id.raw(), mappingEdgeIndex(object_slot_index, object.mapping_count))) return error.TableFull;
        object.mapped_task_ids[object.mapping_count] = task_id;
        object.mapping_count += 1;
    }

    pub fn unmap(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!bool {
        const object_slot_index = self.arena.slotIndexOf(object_id) orelse return error.SharedMemoryNotFound;
        const object = &self.arena.slots[object_slot_index].object;
        var index: usize = 0;
        while (index < object.mapping_count) : (index += 1) {
            if (!object.mapped_task_ids[index].eql(task_id)) continue;

            _ = self.mapping_index.remove(task_id.raw(), mappingEdgeIndex(object_slot_index, index));
            var tail = index;
            while (tail + 1 < object.mapping_count) : (tail += 1) {
                const moved_task_id = object.mapped_task_ids[tail + 1];
                _ = self.mapping_index.remove(moved_task_id.raw(), mappingEdgeIndex(object_slot_index, tail + 1));
                if (!self.mapping_index.append(moved_task_id.raw(), mappingEdgeIndex(object_slot_index, tail))) return error.TableFull;
                object.mapped_task_ids[tail] = moved_task_id;
            }
            object.mapping_count -= 1;
            object.mapped_task_ids[object.mapping_count] = ids.TaskId.zero;
            return true;
        }
        return false;
    }

    pub fn revoke(self: *Table, object_id: ids.SharedMemoryId) Error!void {
        const object_slot_index = self.arena.slotIndexOf(object_id) orelse return error.SharedMemoryNotFound;
        const object = &self.arena.slots[object_slot_index].object;
        for (object.mapped_task_ids[0..object.mapping_count], 0..) |task_id, mapping_index| {
            _ = self.mapping_index.remove(task_id.raw(), mappingEdgeIndex(object_slot_index, mapping_index));
        }
        object.revoked = true;
        object.revocation_generation += 1;
        object.attachment_generation += 1;
        object.attached_compute = ComputeAccess.empty();
        object.mapping_count = 0;
        object.mapped_task_ids = [_]ids.TaskId{ids.TaskId.zero} ** MAX_MAPPINGS_PER_OBJECT;
    }

    pub fn attachAccelerator(self: *Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!void {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        if (!object.allowsCompute(target)) return error.AcceleratorAccessDenied;
        if (object.attachedTo(target)) return error.AcceleratorAlreadyAttached;

        setComputeAccess(&object.attached_compute, target, true);
        object.attachment_generation += 1;
    }

    pub fn detachAccelerator(self: *Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!bool {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (!object.attachedTo(target)) return false;

        setComputeAccess(&object.attached_compute, target, false);
        object.attachment_generation += 1;
        return true;
    }

    pub fn descriptor(self: *const Table, object_id: ids.SharedMemoryId) Error!abi.SharedMemoryDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return .{
            .object_id = object.id.raw(),
            .owner_task_id = object.owner_task_id.raw(),
            .size_bytes = object.size_bytes,
            .revocation_generation = object.revocation_generation,
            .mapped_task_count = @intCast(object.mapping_count),
            .flags = if (object.revoked) 1 else 0,
        };
    }

    pub fn allowsAccelerator(self: *const Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!bool {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return object.allowsCompute(target);
    }

    pub fn isAcceleratorAttached(self: *const Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!bool {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return object.attachedTo(target);
    }

    pub fn mappingsForTask(self: *const Table, task_id: ids.TaskId) u16 {
        return @intCast(self.mapping_index.count(task_id.raw()));
    }

    pub fn liveOwnedBytesForTask(self: *const Table, task_id: ids.TaskId) usize {
        var total: usize = 0;
        for (self.arena.slots) |slot| {
            if (!slot.in_use or slot.object.revoked or !slot.object.owner_task_id.eql(task_id)) continue;
            total = std.math.add(usize, total, slot.object.size_bytes) catch return std.math.maxInt(usize);
        }
        return total;
    }

    pub fn liveMappedBytesForTask(self: *const Table, task_id: ids.TaskId) usize {
        var total: usize = 0;
        for (self.arena.slots) |slot| {
            if (!slot.in_use or slot.object.revoked) continue;
            for (slot.object.mapped_task_ids[0..slot.object.mapping_count]) |mapped_task_id| {
                if (!mapped_task_id.eql(task_id)) continue;
                total = std.math.add(usize, total, slot.object.size_bytes) catch return std.math.maxInt(usize);
                break;
            }
        }
        return total;
    }

    pub fn objectSize(self: *const Table, object_id: ids.SharedMemoryId) Error!usize {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return object.size_bytes;
    }

    pub fn hasMapping(self: *const Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) bool {
        const object = self.findConst(object_id) orelse return false;
        if (object.revoked) return false;
        for (object.mapped_task_ids[0..object.mapping_count]) |mapped_task_id| {
            if (mapped_task_id.eql(task_id)) return true;
        }
        return false;
    }

    fn allocateObjectId(self: *Table) ids.SharedMemoryId {
        defer self.next_object_id += 1;
        return ids.sharedMemory(self.next_object_id);
    }

    fn find(self: *Table, object_id: ids.SharedMemoryId) ?*Object {
        const slot = self.arena.get(object_id) orelse return null;
        return &slot.object;
    }

    fn findConst(self: *const Table, object_id: ids.SharedMemoryId) ?*const Object {
        const slot = self.arena.getConst(object_id) orelse return null;
        return &slot.object;
    }
};

fn objectSlotId(slot: *const ObjectSlot) ids.SharedMemoryId {
    return slot.object.id;
}

fn mappingEdgeIndex(object_slot_index: usize, mapping_index: usize) usize {
    return object_slot_index * MAX_MAPPINGS_PER_OBJECT + mapping_index;
}

fn zeroObject() Object {
    return .{
        .id = ids.SharedMemoryId.zero,
        .owner_task_id = ids.TaskId.zero,
        .size_bytes = 0,
        .revocation_generation = 0,
        .attachment_generation = 0,
        .revoked = false,
        .compute_access = .{},
        .attached_compute = ComputeAccess.empty(),
        .mapped_task_ids = [_]ids.TaskId{ids.TaskId.zero} ** MAX_MAPPINGS_PER_OBJECT,
        .mapping_count = 0,
    };
}

fn setComputeAccess(access: *ComputeAccess, target: ComputeTarget, value: bool) void {
    switch (target) {
        .cpu => access.cpu = value,
        .gpu => access.gpu = value,
        .npu => access.npu = value,
        .media => access.media = value,
    }
}

test "shared memory objects map unmap and revoke across tasks" {
    var table = Table.init();
    const object = try table.create(ids.task(7), 4096);

    try table.map(object.id, ids.task(7));
    try table.map(object.id, ids.task(8));
    try std.testing.expectEqual(@as(u16, 2), (try table.descriptor(object.id)).mapped_task_count);
    try std.testing.expect(try table.unmap(object.id, ids.task(8)));

    try table.revoke(object.id);
    const descriptor = try table.descriptor(object.id);
    try std.testing.expectEqual(@as(u16, 0), descriptor.mapped_task_count);
    try std.testing.expectEqual(@as(u16, 1), descriptor.flags);
    try std.testing.expectError(error.Revoked, table.map(object.id, ids.task(9)));
}

test "shared memory objects label accelerator access and explicit zero-copy attachments" {
    var table = Table.init();
    const object = try table.createWithAccess(ids.task(7), 16 * 1024, .{
        .gpu = true,
        .media = true,
    });

    try std.testing.expect(table.find(object.id).?.allowsCompute(.gpu));
    try std.testing.expect(!table.find(object.id).?.allowsCompute(.npu));
    try table.attachAccelerator(object.id, .media);
    try std.testing.expect(table.find(object.id).?.attachedTo(.media));
    try std.testing.expectError(error.AcceleratorAccessDenied, table.attachAccelerator(object.id, .npu));
    try std.testing.expect(try table.detachAccelerator(object.id, .media));
    try std.testing.expect(!table.find(object.id).?.attachedTo(.media));

    try table.attachAccelerator(object.id, .gpu);
    try table.revoke(object.id);
    try std.testing.expect(!table.find(object.id).?.attachedTo(.gpu));
    try std.testing.expectError(error.Revoked, table.attachAccelerator(object.id, .gpu));
}
