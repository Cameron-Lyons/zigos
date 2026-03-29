const std = @import("std");
const abi = @import("../core/abi.zig");

pub const MAX_SHARED_MEMORY_OBJECTS: usize = 24;
pub const MAX_MAPPINGS_PER_OBJECT: usize = 8;

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
    id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    revocation_generation: u32,
    attachment_generation: u32,
    revoked: bool,
    compute_access: ComputeAccess,
    attached_compute: ComputeAccess,
    mapped_task_ids: [MAX_MAPPINGS_PER_OBJECT]u64,
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

pub const Table = struct {
    next_object_id: u64 = 1,
    slots: [MAX_SHARED_MEMORY_OBJECTS]ObjectSlot = [_]ObjectSlot{ObjectSlot{}} ** MAX_SHARED_MEMORY_OBJECTS,

    pub fn init() Table {
        return .{};
    }

    pub fn create(self: *Table, owner_task_id: u64, size_bytes: usize) Error!Object {
        return self.createWithAccess(owner_task_id, size_bytes, .{});
    }

    pub fn createWithAccess(
        self: *Table,
        owner_task_id: u64,
        size_bytes: usize,
        compute_access: ComputeAccess,
    ) Error!Object {
        if (size_bytes == 0) return error.SizeZero;

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.object = .{
                .id = self.allocateObjectId(),
                .owner_task_id = owner_task_id,
                .size_bytes = size_bytes,
                .revocation_generation = 1,
                .attachment_generation = 1,
                .revoked = false,
                .compute_access = compute_access,
                .attached_compute = ComputeAccess.empty(),
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
        object.attachment_generation += 1;
        object.attached_compute = ComputeAccess.empty();
        object.mapping_count = 0;
        object.mapped_task_ids = [_]u64{0} ** MAX_MAPPINGS_PER_OBJECT;
    }

    pub fn attachAccelerator(self: *Table, object_id: u64, target: ComputeTarget) Error!void {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        if (!object.allowsCompute(target)) return error.AcceleratorAccessDenied;
        if (object.attachedTo(target)) return error.AcceleratorAlreadyAttached;

        setComputeAccess(&object.attached_compute, target, true);
        object.attachment_generation += 1;
    }

    pub fn detachAccelerator(self: *Table, object_id: u64, target: ComputeTarget) Error!bool {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (!object.attachedTo(target)) return false;

        setComputeAccess(&object.attached_compute, target, false);
        object.attachment_generation += 1;
        return true;
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

    pub fn allowsAccelerator(self: *const Table, object_id: u64, target: ComputeTarget) Error!bool {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return object.allowsCompute(target);
    }

    pub fn isAcceleratorAttached(self: *const Table, object_id: u64, target: ComputeTarget) Error!bool {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return object.attachedTo(target);
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
        .attachment_generation = 0,
        .revoked = false,
        .compute_access = .{},
        .attached_compute = ComputeAccess.empty(),
        .mapped_task_ids = [_]u64{0} ** MAX_MAPPINGS_PER_OBJECT,
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

test "shared memory objects label accelerator access and explicit zero-copy attachments" {
    var table = Table.init();
    const object = try table.createWithAccess(7, 16 * 1024, .{
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
