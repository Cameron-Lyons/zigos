const std = @import("std");
const abi = @import("../core/abi.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");

pub const MAX_SHARED_MEMORY_OBJECTS: usize = 24;
pub const MAX_MAPPINGS_PER_OBJECT: usize = 8;
pub const PAGE_SIZE: usize = 4096;
const SHARED_MEMORY_INDEX_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * 2;
const MAPPING_EDGE_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * MAX_MAPPINGS_PER_OBJECT;
const MAPPING_INDEX_CAPACITY: usize = MAPPING_EDGE_CAPACITY * 2;
const MMU_MAPPING_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * (MAX_MAPPINGS_PER_OBJECT + 3);
const MMU_MAPPING_INDEX_CAPACITY: usize = MMU_MAPPING_CAPACITY * 2;
const FREESTANDING_PHYSICAL_BASE: u64 = 0x0010_0000;
const TASK_SHARED_VIRTUAL_BASE: u64 = 0x0000_4000_0000;
const ACCELERATOR_APERTURE_BASE: u64 = 0x0000_8000_0000;

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
    page_base: u64,
    page_count: usize,
    label_hash: u64,
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

pub const MappingDescriptor = struct {
    object_id: ids.SharedMemoryId,
    task_id: ids.TaskId,
    target: ?ComputeTarget = null,
    page_base: u64,
    page_count: usize,
    size_bytes: usize,
    label_hash: u64,
    revocation_generation: u32,
    attachment_generation: u32,
    zero_copy: bool,
};

pub const FreestandingMappingDescriptor = struct {
    object_id: ids.SharedMemoryId,
    task_id: ids.TaskId = ids.TaskId.zero,
    target: ?ComputeTarget = null,
    virtual_base: u64,
    physical_base: u64,
    page_count: usize,
    size_bytes: usize,
    label_hash: u64,
    revocation_generation: u32,
    attachment_generation: u32,
    zero_copy: bool,
};

pub const Error = error{
    AcceleratorAccessDenied,
    AcceleratorAlreadyAttached,
    AcceleratorNotAttached,
    AlreadyMapped,
    MappingDescriptorMismatch,
    MappingNotFound,
    Revoked,
    SizeZero,
    StaleMappingDescriptor,
    TableFull,
    SharedMemoryNotFound,
};

const MmuMappingKind = enum(u8) {
    task,
    accelerator,
};

const MmuMapping = struct {
    in_use: bool = false,
    object_id: ids.SharedMemoryId = ids.SharedMemoryId.zero,
    kind: MmuMappingKind = .task,
    domain_id: u64 = 0,
    virtual_base: u64 = 0,
    physical_base: u64 = 0,
    page_count: usize = 0,
    size_bytes: usize = 0,
    label_hash: u64 = 0,
    revocation_generation: u32 = 0,
    attachment_generation: u32 = 0,
    zero_copy: bool = false,
    revoked: bool = false,
};

fn mmuMappingSlotKey(slot: *const MmuMapping) u64 {
    return mmuMappingKey(slot.object_id, slot.kind, slot.domain_id);
}

const MmuMappingArena = indexed_arena.IndexedArenaWithKey(u64, MmuMapping, MMU_MAPPING_CAPACITY, MMU_MAPPING_INDEX_CAPACITY, mmuMappingSlotKey);
const MmuObjectMappingIndex = indexed_arena.MultimapIndex(MMU_MAPPING_CAPACITY, MMU_MAPPING_CAPACITY, MMU_MAPPING_INDEX_CAPACITY);

pub const FreestandingMmu = struct {
    next_physical_frame: u64 = 1,
    next_task_virtual_page: u64 = 1,
    next_accelerator_virtual_page: u64 = 1,
    mappings: MmuMappingArena = MmuMappingArena.init(),
    object_mapping_index: MmuObjectMappingIndex = MmuObjectMappingIndex.init(),

    pub fn init() FreestandingMmu {
        return .{};
    }

    pub fn allocatePhysicalFrames(self: *FreestandingMmu, count: usize) Error!u64 {
        if (count == 0) return error.SizeZero;
        const base_frame = self.next_physical_frame;
        const next_frame = std.math.add(u64, base_frame, @intCast(count)) catch return error.TableFull;
        const frame_offset = std.math.mul(u64, base_frame, PAGE_SIZE) catch return error.TableFull;
        self.next_physical_frame = next_frame;
        return std.math.add(u64, FREESTANDING_PHYSICAL_BASE, frame_offset) catch return error.TableFull;
    }

    pub fn mapTask(
        self: *FreestandingMmu,
        object: *const Object,
        task_id: ids.TaskId,
    ) Error!FreestandingMappingDescriptor {
        if (object.revoked) return error.Revoked;
        const key = mmuMappingKey(object.id, .task, task_id.raw());
        if (self.mappings.getConst(key) != null) return error.AlreadyMapped;
        const slot_index = self.mappings.reserveIndex(key) orelse return error.TableFull;
        if (!self.object_mapping_index.append(object.id.raw(), slot_index)) {
            _ = self.mappings.removeIndex(slot_index);
            return error.TableFull;
        }
        const virtual_base = self.allocateTaskVirtual(object.page_count) catch |err| {
            _ = self.object_mapping_index.remove(object.id.raw(), slot_index);
            _ = self.mappings.removeIndex(slot_index);
            return err;
        };
        const slot = &self.mappings.slots[slot_index];
        slot.* = mappingFromObject(object, .task, task_id.raw(), virtual_base, false);
        return descriptorFromMmuMapping(slot);
    }

    pub fn unmapTask(self: *FreestandingMmu, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!bool {
        return self.removeMapping(object_id, mmuMappingKey(object_id, .task, task_id.raw()));
    }

    pub fn mapAccelerator(
        self: *FreestandingMmu,
        object: *const Object,
        target: ComputeTarget,
    ) Error!FreestandingMappingDescriptor {
        if (object.revoked) return error.Revoked;
        const domain_id = acceleratorDomainId(target);
        const key = mmuMappingKey(object.id, .accelerator, domain_id);
        if (self.mappings.getConst(key) != null) return error.AcceleratorAlreadyAttached;
        const slot_index = self.mappings.reserveIndex(key) orelse return error.TableFull;
        if (!self.object_mapping_index.append(object.id.raw(), slot_index)) {
            _ = self.mappings.removeIndex(slot_index);
            return error.TableFull;
        }
        const virtual_base = self.allocateAcceleratorVirtual(object.page_count) catch |err| {
            _ = self.object_mapping_index.remove(object.id.raw(), slot_index);
            _ = self.mappings.removeIndex(slot_index);
            return err;
        };
        const slot = &self.mappings.slots[slot_index];
        slot.* = mappingFromObject(object, .accelerator, domain_id, virtual_base, true);
        return descriptorFromMmuMapping(slot);
    }

    pub fn unmapAccelerator(self: *FreestandingMmu, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!bool {
        return self.removeMapping(object_id, mmuMappingKey(object_id, .accelerator, acceleratorDomainId(target)));
    }

    pub fn revokeObject(self: *FreestandingMmu, object_id: ids.SharedMemoryId) void {
        var slot_index = self.object_mapping_index.head(object_id.raw());
        while (slot_index != indexed_arena.no_index) {
            const next_slot_index = self.object_mapping_index.next(slot_index);
            const mapping = self.mappingForObjectIndex(object_id, slot_index) orelse {
                slot_index = next_slot_index;
                continue;
            };
            _ = mapping;
            _ = self.object_mapping_index.remove(object_id.raw(), slot_index);
            _ = self.mappings.removeIndex(slot_index);
            slot_index = next_slot_index;
        }
    }

    pub fn updateObjectAttachmentGeneration(
        self: *FreestandingMmu,
        object_id: ids.SharedMemoryId,
        attachment_generation: u32,
    ) void {
        var slot_index = self.object_mapping_index.head(object_id.raw());
        while (slot_index != indexed_arena.no_index) : (slot_index = self.object_mapping_index.next(slot_index)) {
            const mapping = self.mappingForObjectIndex(object_id, slot_index) orelse continue;
            mapping.attachment_generation = attachment_generation;
        }
    }

    pub fn taskMappingDescriptor(
        self: *const FreestandingMmu,
        object_id: ids.SharedMemoryId,
        task_id: ids.TaskId,
    ) Error!FreestandingMappingDescriptor {
        const mapping = self.findAny(object_id, .task, task_id.raw()) orelse return error.MappingNotFound;
        if (mapping.revoked) return error.Revoked;
        return descriptorFromMmuMapping(mapping);
    }

    pub fn acceleratorMappingDescriptor(
        self: *const FreestandingMmu,
        object_id: ids.SharedMemoryId,
        target: ComputeTarget,
    ) Error!FreestandingMappingDescriptor {
        const mapping = self.findAny(object_id, .accelerator, acceleratorDomainId(target)) orelse return error.AcceleratorNotAttached;
        if (mapping.revoked) return error.Revoked;
        return descriptorFromMmuMapping(mapping);
    }

    pub fn activeMappingsForObject(self: *const FreestandingMmu, object_id: ids.SharedMemoryId) usize {
        var count: usize = 0;
        var slot_index = self.object_mapping_index.head(object_id.raw());
        while (slot_index != indexed_arena.no_index) : (slot_index = self.object_mapping_index.next(slot_index)) {
            const mapping = self.mappingForObjectIndexConst(object_id, slot_index) orelse continue;
            if (!mapping.revoked) count += 1;
        }
        return count;
    }

    fn allocateTaskVirtual(self: *FreestandingMmu, page_count: usize) Error!u64 {
        const base_page = self.next_task_virtual_page;
        const next_page = std.math.add(u64, base_page, @intCast(page_count)) catch return error.TableFull;
        const page_offset = std.math.mul(u64, base_page, PAGE_SIZE) catch return error.TableFull;
        self.next_task_virtual_page = next_page;
        return std.math.add(u64, TASK_SHARED_VIRTUAL_BASE, page_offset) catch return error.TableFull;
    }

    fn allocateAcceleratorVirtual(self: *FreestandingMmu, page_count: usize) Error!u64 {
        const base_page = self.next_accelerator_virtual_page;
        const next_page = std.math.add(u64, base_page, @intCast(page_count)) catch return error.TableFull;
        const page_offset = std.math.mul(u64, base_page, PAGE_SIZE) catch return error.TableFull;
        self.next_accelerator_virtual_page = next_page;
        return std.math.add(u64, ACCELERATOR_APERTURE_BASE, page_offset) catch return error.TableFull;
    }

    fn findAny(
        self: *const FreestandingMmu,
        object_id: ids.SharedMemoryId,
        kind: MmuMappingKind,
        domain_id: u64,
    ) ?*const MmuMapping {
        return self.mappings.getConst(mmuMappingKey(object_id, kind, domain_id));
    }

    fn removeMapping(self: *FreestandingMmu, object_id: ids.SharedMemoryId, key: u64) bool {
        const slot_index = self.mappings.slotIndexOf(key) orelse return false;
        const mapping = self.mappingForObjectIndex(object_id, slot_index) orelse return false;
        _ = mapping;
        _ = self.object_mapping_index.remove(object_id.raw(), slot_index);
        return self.mappings.removeIndex(slot_index);
    }

    fn mappingForObjectIndex(self: *FreestandingMmu, object_id: ids.SharedMemoryId, slot_index: usize) ?*MmuMapping {
        if (slot_index >= self.mappings.slots.len) return null;
        const mapping = &self.mappings.slots[slot_index];
        if (!mapping.in_use or !mapping.object_id.eql(object_id)) return null;
        return mapping;
    }

    fn mappingForObjectIndexConst(self: *const FreestandingMmu, object_id: ids.SharedMemoryId, slot_index: usize) ?*const MmuMapping {
        if (slot_index >= self.mappings.slots.len) return null;
        const mapping = &self.mappings.slots[slot_index];
        if (!mapping.in_use or !mapping.object_id.eql(object_id)) return null;
        return mapping;
    }
};

const ObjectSlot = struct {
    in_use: bool = false,
    object: Object = zeroObject(),
};

const ObjectArena = indexed_arena.IndexedArenaWithKey(ids.SharedMemoryId, ObjectSlot, MAX_SHARED_MEMORY_OBJECTS, SHARED_MEMORY_INDEX_CAPACITY, objectSlotId);
const ObjectOwnerIndex = indexed_arena.MultimapIndex(MAX_SHARED_MEMORY_OBJECTS, MAX_SHARED_MEMORY_OBJECTS, SHARED_MEMORY_INDEX_CAPACITY);
const MappingIndex = indexed_arena.MultimapIndex(MAPPING_EDGE_CAPACITY, MAPPING_EDGE_CAPACITY, MAPPING_INDEX_CAPACITY);
const ObjectTaskMappingIndex = indexed_arena.UniqueIndex(MAPPING_INDEX_CAPACITY);

pub const Table = struct {
    next_object_id: u64 = 1,
    mmu: FreestandingMmu = FreestandingMmu.init(),
    arena: ObjectArena = ObjectArena.init(),
    object_owner_index: ObjectOwnerIndex = ObjectOwnerIndex.init(),
    mapping_index: MappingIndex = MappingIndex.init(),
    object_task_mapping_index: ObjectTaskMappingIndex = ObjectTaskMappingIndex.init(),

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
        return self.createLabeledWithAccess(owner_task_id, size_bytes, "", compute_access);
    }

    pub fn createLabeledWithAccess(
        self: *Table,
        owner_task_id: ids.TaskId,
        size_bytes: usize,
        label: []const u8,
        compute_access: ComputeAccess,
    ) Error!Object {
        if (size_bytes == 0) return error.SizeZero;

        const object_id = self.nextReservableObjectId() orelse return error.TableFull;
        const page_count = pageCount(size_bytes);
        const page_base = try self.mmu.allocatePhysicalFrames(page_count);
        const slot_index = self.arena.reserveIndex(object_id) orelse return error.TableFull;
        if (!self.object_owner_index.append(owner_task_id.raw(), slot_index)) {
            _ = self.arena.removeIndex(slot_index);
            return error.TableFull;
        }
        const slot = &self.arena.slots[slot_index];
        slot.object = .{
            .id = object_id,
            .owner_task_id = owner_task_id,
            .size_bytes = size_bytes,
            .page_base = page_base,
            .page_count = page_count,
            .label_hash = labelHash(label),
            .revocation_generation = 1,
            .attachment_generation = 1,
            .revoked = false,
            .compute_access = compute_access,
            .attached_compute = ComputeAccess.empty(),
            .mapped_task_ids = [_]ids.TaskId{ids.TaskId.zero} ** MAX_MAPPINGS_PER_OBJECT,
            .mapping_count = 0,
        };
        self.advanceNextObjectIdFrom(object_id);
        return slot.object;
    }

    pub fn map(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!void {
        const object_slot_index = self.arena.slotIndexOf(object_id) orelse return error.SharedMemoryNotFound;
        const object = &self.arena.slots[object_slot_index].object;
        if (object.revoked) return error.Revoked;

        const task_mapping_key = objectTaskMappingKey(object_id, task_id);
        if (self.object_task_mapping_index.contains(task_mapping_key)) return error.AlreadyMapped;
        if (object.mapping_count >= object.mapped_task_ids.len) return error.TableFull;

        const edge_index = mappingEdgeIndex(object_slot_index, object.mapping_count);
        if (!self.mapping_index.append(task_id.raw(), edge_index)) return error.TableFull;
        self.object_task_mapping_index.insert(task_mapping_key, edge_index);
        object.mapped_task_ids[object.mapping_count] = task_id;
        object.mapping_count += 1;
        _ = self.mmu.mapTask(object, task_id) catch |err| {
            object.mapping_count -= 1;
            object.mapped_task_ids[object.mapping_count] = ids.TaskId.zero;
            _ = self.mapping_index.remove(task_id.raw(), mappingEdgeIndex(object_slot_index, object.mapping_count));
            self.object_task_mapping_index.remove(task_mapping_key);
            return err;
        };
    }

    pub fn unmap(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!bool {
        const object_slot_index = self.arena.slotIndexOf(object_id) orelse return error.SharedMemoryNotFound;
        const object = &self.arena.slots[object_slot_index].object;
        const task_mapping_key = objectTaskMappingKey(object_id, task_id);
        const edge_index = self.object_task_mapping_index.lookup(task_mapping_key) orelse return false;
        if (mappingEdgeObjectSlotIndex(edge_index) != object_slot_index) return false;
        const index = mappingEdgeMappingIndex(edge_index);
        if (index >= object.mapping_count or !object.mapped_task_ids[index].eql(task_id)) return false;

        self.object_task_mapping_index.remove(task_mapping_key);
        _ = self.mapping_index.remove(task_id.raw(), edge_index);
        var tail = index;
        while (tail + 1 < object.mapping_count) : (tail += 1) {
            const moved_task_id = object.mapped_task_ids[tail + 1];
            const old_edge_index = mappingEdgeIndex(object_slot_index, tail + 1);
            const new_edge_index = mappingEdgeIndex(object_slot_index, tail);
            _ = self.mapping_index.remove(moved_task_id.raw(), old_edge_index);
            if (!self.mapping_index.append(moved_task_id.raw(), new_edge_index)) return error.TableFull;
            self.object_task_mapping_index.insert(objectTaskMappingKey(object_id, moved_task_id), new_edge_index);
            object.mapped_task_ids[tail] = moved_task_id;
        }
        object.mapping_count -= 1;
        object.mapped_task_ids[object.mapping_count] = ids.TaskId.zero;
        _ = try self.mmu.unmapTask(object_id, task_id);
        return true;
    }

    pub fn revoke(self: *Table, object_id: ids.SharedMemoryId) Error!void {
        const object_slot_index = self.arena.slotIndexOf(object_id) orelse return error.SharedMemoryNotFound;
        const object = &self.arena.slots[object_slot_index].object;
        if (!object.revoked) {
            _ = self.object_owner_index.remove(object.owner_task_id.raw(), object_slot_index);
        }
        for (object.mapped_task_ids[0..object.mapping_count], 0..) |task_id, mapping_index| {
            _ = self.mapping_index.remove(task_id.raw(), mappingEdgeIndex(object_slot_index, mapping_index));
            self.object_task_mapping_index.remove(objectTaskMappingKey(object_id, task_id));
        }
        self.mmu.revokeObject(object_id);
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

        const previous_generation = object.attachment_generation;
        setComputeAccess(&object.attached_compute, target, true);
        object.attachment_generation += 1;
        self.mmu.updateObjectAttachmentGeneration(object_id, object.attachment_generation);
        _ = self.mmu.mapAccelerator(object, target) catch |err| {
            setComputeAccess(&object.attached_compute, target, false);
            object.attachment_generation = previous_generation;
            self.mmu.updateObjectAttachmentGeneration(object_id, previous_generation);
            return err;
        };
    }

    pub fn detachAccelerator(self: *Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!bool {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (!object.attachedTo(target)) return false;

        _ = try self.mmu.unmapAccelerator(object_id, target);
        setComputeAccess(&object.attached_compute, target, false);
        object.attachment_generation += 1;
        self.mmu.updateObjectAttachmentGeneration(object_id, object.attachment_generation);
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

    pub fn taskMappingDescriptor(
        self: *const Table,
        object_id: ids.SharedMemoryId,
        task_id: ids.TaskId,
    ) Error!MappingDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        if (!self.hasMapping(object_id, task_id)) return error.MappingNotFound;
        return mappingDescriptorFor(object, task_id, null, false);
    }

    pub fn validateTaskMappingDescriptor(
        self: *const Table,
        mapping_descriptor: MappingDescriptor,
    ) Error!void {
        const object = self.findConst(mapping_descriptor.object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        if (!self.hasMapping(mapping_descriptor.object_id, mapping_descriptor.task_id)) return error.MappingNotFound;
        try validateMappingDescriptorForObject(object, mapping_descriptor, mapping_descriptor.task_id, null, false);
    }

    pub fn acceleratorMappingDescriptor(
        self: *const Table,
        object_id: ids.SharedMemoryId,
        target: ComputeTarget,
    ) Error!MappingDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        if (!object.attachedTo(target)) return error.AcceleratorNotAttached;
        return mappingDescriptorFor(object, ids.TaskId.zero, target, true);
    }

    pub fn validateAcceleratorMappingDescriptor(
        self: *const Table,
        mapping_descriptor: MappingDescriptor,
        target: ComputeTarget,
    ) Error!void {
        const object = self.findConst(mapping_descriptor.object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        if (!mapping_descriptor.task_id.eql(ids.TaskId.zero) or
            !computeTargetsEqual(mapping_descriptor.target, target) or
            !mapping_descriptor.zero_copy)
        {
            return error.MappingDescriptorMismatch;
        }
        if (!object.attachedTo(target)) return error.AcceleratorNotAttached;
        try validateMappingDescriptorForObject(object, mapping_descriptor, ids.TaskId.zero, target, true);
    }

    pub fn freestandingTaskMappingDescriptor(
        self: *const Table,
        object_id: ids.SharedMemoryId,
        task_id: ids.TaskId,
    ) Error!FreestandingMappingDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        return self.mmu.taskMappingDescriptor(object_id, task_id);
    }

    pub fn validateFreestandingTaskMappingDescriptor(
        self: *const Table,
        mapping_descriptor: FreestandingMappingDescriptor,
    ) Error!void {
        const object = self.findConst(mapping_descriptor.object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        const current = try self.mmu.taskMappingDescriptor(mapping_descriptor.object_id, mapping_descriptor.task_id);
        try validateFreestandingDescriptorForObject(object, current, mapping_descriptor, mapping_descriptor.task_id, null, false);
    }

    pub fn freestandingAcceleratorMappingDescriptor(
        self: *const Table,
        object_id: ids.SharedMemoryId,
        target: ComputeTarget,
    ) Error!FreestandingMappingDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        return self.mmu.acceleratorMappingDescriptor(object_id, target);
    }

    pub fn validateFreestandingAcceleratorMappingDescriptor(
        self: *const Table,
        mapping_descriptor: FreestandingMappingDescriptor,
        target: ComputeTarget,
    ) Error!void {
        const object = self.findConst(mapping_descriptor.object_id) orelse return error.SharedMemoryNotFound;
        if (object.revoked) return error.Revoked;
        if (!mapping_descriptor.task_id.eql(ids.TaskId.zero) or
            !computeTargetsEqual(mapping_descriptor.target, target) or
            !mapping_descriptor.zero_copy)
        {
            return error.MappingDescriptorMismatch;
        }
        const current = try self.mmu.acceleratorMappingDescriptor(mapping_descriptor.object_id, target);
        try validateFreestandingDescriptorForObject(object, current, mapping_descriptor, ids.TaskId.zero, target, true);
    }

    pub fn activeFreestandingMappings(self: *const Table, object_id: ids.SharedMemoryId) usize {
        return self.mmu.activeMappingsForObject(object_id);
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
        var slot_index = self.object_owner_index.head(task_id.raw());
        while (slot_index != indexed_arena.no_index) : (slot_index = self.object_owner_index.next(slot_index)) {
            if (slot_index >= self.arena.slots.len) continue;
            const slot = &self.arena.slots[slot_index];
            if (!slot.in_use or slot.object.revoked or !slot.object.owner_task_id.eql(task_id)) continue;
            total = std.math.add(usize, total, slot.object.size_bytes) catch return std.math.maxInt(usize);
        }
        return total;
    }

    pub fn liveMappedBytesForTask(self: *const Table, task_id: ids.TaskId) usize {
        var total: usize = 0;
        var edge_index = self.mapping_index.head(task_id.raw());
        while (edge_index != indexed_arena.no_index) : (edge_index = self.mapping_index.next(edge_index)) {
            const object_slot_index = mappingEdgeObjectSlotIndex(edge_index);
            const mapping_index = mappingEdgeMappingIndex(edge_index);
            if (object_slot_index >= self.arena.slots.len) continue;
            const slot = &self.arena.slots[object_slot_index];
            if (!slot.in_use or slot.object.revoked or mapping_index >= slot.object.mapping_count) continue;
            if (!slot.object.mapped_task_ids[mapping_index].eql(task_id)) continue;
            total = std.math.add(usize, total, slot.object.size_bytes) catch return std.math.maxInt(usize);
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
        return self.object_task_mapping_index.contains(objectTaskMappingKey(object_id, task_id));
    }

    fn nextReservableObjectId(self: *const Table) ?ids.SharedMemoryId {
        if (self.arena.countInUse() >= MAX_SHARED_MEMORY_OBJECTS) return null;

        var object_id = normalizeObjectId(self.next_object_id);
        var attempts: usize = 0;
        while (attempts <= MAX_SHARED_MEMORY_OBJECTS) : (attempts += 1) {
            const candidate = ids.sharedMemory(object_id);
            if (self.findConst(candidate) == null) return candidate;
            object_id = nextObjectIdAfter(object_id);
        }
        return null;
    }

    fn advanceNextObjectIdFrom(self: *Table, object_id: ids.SharedMemoryId) void {
        self.next_object_id = nextObjectIdAfter(object_id.raw());
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

fn normalizeObjectId(object_id: u64) u64 {
    return if (object_id == 0) 1 else object_id;
}

fn nextObjectIdAfter(object_id: u64) u64 {
    const next = object_id +% 1;
    return normalizeObjectId(next);
}

fn mmuMappingKey(object_id: ids.SharedMemoryId, kind: MmuMappingKind, domain_id: u64) u64 {
    const kind_offset: usize = @sizeOf(u64);
    const domain_offset: usize = kind_offset + @sizeOf(u8);
    var bytes: [@sizeOf(u64) + @sizeOf(u8) + @sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..@sizeOf(u64)], object_id.raw(), .little);
    bytes[kind_offset] = @intFromEnum(kind);
    std.mem.writeInt(u64, bytes[domain_offset..][0..@sizeOf(u64)], domain_id, .little);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(hash_seeds.shared_memory_mapping_key, &bytes));
}

fn objectTaskMappingKey(object_id: ids.SharedMemoryId, task_id: ids.TaskId) u64 {
    var bytes: [@sizeOf(u64) * 2]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..@sizeOf(u64)], object_id.raw(), .little);
    std.mem.writeInt(u64, bytes[@sizeOf(u64)..][0..@sizeOf(u64)], task_id.raw(), .little);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(hash_seeds.shared_memory_task_mapping_key, &bytes));
}

fn mappingEdgeIndex(object_slot_index: usize, mapping_index: usize) usize {
    return object_slot_index * MAX_MAPPINGS_PER_OBJECT + mapping_index;
}

fn mappingEdgeObjectSlotIndex(edge_index: usize) usize {
    return edge_index / MAX_MAPPINGS_PER_OBJECT;
}

fn mappingEdgeMappingIndex(edge_index: usize) usize {
    return edge_index % MAX_MAPPINGS_PER_OBJECT;
}

fn zeroObject() Object {
    return .{
        .id = ids.SharedMemoryId.zero,
        .owner_task_id = ids.TaskId.zero,
        .size_bytes = 0,
        .page_base = 0,
        .page_count = 0,
        .label_hash = 0,
        .revocation_generation = 0,
        .attachment_generation = 0,
        .revoked = false,
        .compute_access = .{},
        .attached_compute = ComputeAccess.empty(),
        .mapped_task_ids = [_]ids.TaskId{ids.TaskId.zero} ** MAX_MAPPINGS_PER_OBJECT,
        .mapping_count = 0,
    };
}

fn pageCount(size_bytes: usize) usize {
    return (size_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
}

fn labelHash(label: []const u8) u64 {
    return std.hash.Wyhash.hash(hash_seeds.shared_memory_label_key, label);
}

fn mappingDescriptorFor(
    object: *const Object,
    task_id: ids.TaskId,
    target: ?ComputeTarget,
    zero_copy: bool,
) MappingDescriptor {
    return .{
        .object_id = object.id,
        .task_id = task_id,
        .target = target,
        .page_base = object.page_base,
        .page_count = object.page_count,
        .size_bytes = object.size_bytes,
        .label_hash = object.label_hash,
        .revocation_generation = object.revocation_generation,
        .attachment_generation = object.attachment_generation,
        .zero_copy = zero_copy,
    };
}

fn validateMappingDescriptorForObject(
    object: *const Object,
    descriptor: MappingDescriptor,
    task_id: ids.TaskId,
    target: ?ComputeTarget,
    zero_copy: bool,
) Error!void {
    if (!descriptor.object_id.eql(object.id) or
        !descriptor.task_id.eql(task_id) or
        !computeTargetsEqual(descriptor.target, target) or
        descriptor.page_base != object.page_base or
        descriptor.page_count != object.page_count or
        descriptor.size_bytes != object.size_bytes or
        descriptor.label_hash != object.label_hash or
        descriptor.zero_copy != zero_copy)
    {
        return error.MappingDescriptorMismatch;
    }
    if (descriptor.revocation_generation != object.revocation_generation or
        descriptor.attachment_generation != object.attachment_generation)
    {
        return error.StaleMappingDescriptor;
    }
}

fn validateFreestandingDescriptorForObject(
    object: *const Object,
    current: FreestandingMappingDescriptor,
    descriptor: FreestandingMappingDescriptor,
    task_id: ids.TaskId,
    target: ?ComputeTarget,
    zero_copy: bool,
) Error!void {
    if (!descriptor.object_id.eql(object.id) or
        !descriptor.task_id.eql(task_id) or
        !computeTargetsEqual(descriptor.target, target) or
        descriptor.virtual_base != current.virtual_base or
        descriptor.physical_base != object.page_base or
        descriptor.physical_base != current.physical_base or
        descriptor.page_count != object.page_count or
        descriptor.size_bytes != object.size_bytes or
        descriptor.label_hash != object.label_hash or
        descriptor.zero_copy != zero_copy)
    {
        return error.MappingDescriptorMismatch;
    }
    if (descriptor.revocation_generation != object.revocation_generation or
        descriptor.revocation_generation != current.revocation_generation or
        descriptor.attachment_generation != object.attachment_generation or
        descriptor.attachment_generation != current.attachment_generation)
    {
        return error.StaleMappingDescriptor;
    }
}

fn computeTargetsEqual(lhs: ?ComputeTarget, rhs: ?ComputeTarget) bool {
    if (lhs == null or rhs == null) return lhs == null and rhs == null;
    return lhs.? == rhs.?;
}

fn mappingFromObject(
    object: *const Object,
    kind: MmuMappingKind,
    domain_id: u64,
    virtual_base: u64,
    zero_copy: bool,
) MmuMapping {
    return .{
        .in_use = true,
        .object_id = object.id,
        .kind = kind,
        .domain_id = domain_id,
        .virtual_base = virtual_base,
        .physical_base = object.page_base,
        .page_count = object.page_count,
        .size_bytes = object.size_bytes,
        .label_hash = object.label_hash,
        .revocation_generation = object.revocation_generation,
        .attachment_generation = object.attachment_generation,
        .zero_copy = zero_copy,
        .revoked = false,
    };
}

fn descriptorFromMmuMapping(mapping: *const MmuMapping) FreestandingMappingDescriptor {
    return .{
        .object_id = mapping.object_id,
        .task_id = if (mapping.kind == .task) ids.task(mapping.domain_id) else ids.TaskId.zero,
        .target = if (mapping.kind == .accelerator) computeTargetFromDomainId(mapping.domain_id) else null,
        .virtual_base = mapping.virtual_base,
        .physical_base = mapping.physical_base,
        .page_count = mapping.page_count,
        .size_bytes = mapping.size_bytes,
        .label_hash = mapping.label_hash,
        .revocation_generation = mapping.revocation_generation,
        .attachment_generation = mapping.attachment_generation,
        .zero_copy = mapping.zero_copy,
    };
}

fn acceleratorDomainId(target: ComputeTarget) u64 {
    return @as(u64, @intFromEnum(target)) + 1;
}

fn computeTargetFromDomainId(domain_id: u64) ?ComputeTarget {
    return switch (domain_id) {
        1 => .cpu,
        2 => .gpu,
        3 => .npu,
        4 => .media,
        else => null,
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
    const object = try table.createLabeledWithAccess(ids.task(7), 4096, "ipc-ring", .{});
    const peer_object = try table.create(ids.task(8), PAGE_SIZE * 2);

    try std.testing.expectEqual(@as(usize, 1), table.object_owner_index.count(ids.task(7).raw()));
    try std.testing.expectEqual(@as(usize, PAGE_SIZE), table.liveOwnedBytesForTask(ids.task(7)));
    try std.testing.expectEqual(@as(usize, PAGE_SIZE * 2), table.liveOwnedBytesForTask(ids.task(8)));
    try table.map(object.id, ids.task(7));
    try table.map(object.id, ids.task(8));
    try std.testing.expectError(error.AlreadyMapped, table.map(object.id, ids.task(7)));
    try std.testing.expect(table.hasMapping(object.id, ids.task(7)));
    try std.testing.expect(table.hasMapping(object.id, ids.task(8)));
    try std.testing.expectEqual(@as(u16, 1), table.mappingsForTask(ids.task(8)));
    try std.testing.expectEqual(@as(usize, PAGE_SIZE), table.liveMappedBytesForTask(ids.task(8)));
    try std.testing.expectEqual(@as(u16, 2), (try table.descriptor(object.id)).mapped_task_count);
    const owner_mapping = try table.taskMappingDescriptor(object.id, ids.task(7));
    const peer_mapping = try table.taskMappingDescriptor(object.id, ids.task(8));
    try std.testing.expectEqual(object.page_base, owner_mapping.page_base);
    try std.testing.expectEqual(owner_mapping.page_base, peer_mapping.page_base);
    try std.testing.expectEqual(@as(usize, 1), owner_mapping.page_count);
    try std.testing.expectEqual(object.label_hash, owner_mapping.label_hash);
    try std.testing.expect(!owner_mapping.zero_copy);
    try std.testing.expect(try table.unmap(object.id, ids.task(8)));
    try std.testing.expect(!table.hasMapping(object.id, ids.task(8)));
    try std.testing.expectEqual(@as(u16, 0), table.mappingsForTask(ids.task(8)));
    try std.testing.expectEqual(@as(usize, 0), table.liveMappedBytesForTask(ids.task(8)));
    try std.testing.expectError(error.MappingNotFound, table.taskMappingDescriptor(object.id, ids.task(8)));

    try table.revoke(object.id);
    const descriptor = try table.descriptor(object.id);
    try std.testing.expectEqual(@as(usize, 0), table.object_owner_index.count(ids.task(7).raw()));
    try std.testing.expectEqual(@as(usize, 0), table.liveOwnedBytesForTask(ids.task(7)));
    try std.testing.expectEqual(@as(usize, PAGE_SIZE * 2), table.liveOwnedBytesForTask(ids.task(8)));
    try std.testing.expect(!peer_object.id.eql(object.id));
    try std.testing.expectEqual(@as(u16, 0), descriptor.mapped_task_count);
    try std.testing.expect(!table.hasMapping(object.id, ids.task(7)));
    try std.testing.expectEqual(@as(u16, 0), table.mappingsForTask(ids.task(7)));
    try std.testing.expectEqual(@as(u16, 1), descriptor.flags);
    try std.testing.expectError(error.Revoked, table.taskMappingDescriptor(object.id, ids.task(7)));
    try std.testing.expectError(error.Revoked, table.map(object.id, ids.task(9)));
}

test "shared memory object ids wrap without zero and skip active objects" {
    var table = Table.init();

    table.next_object_id = std.math.maxInt(u64);
    const max_object = try table.create(ids.task(7), PAGE_SIZE);
    try std.testing.expectEqual(std.math.maxInt(u64), max_object.id.raw());
    try std.testing.expectEqual(@as(u64, 1), table.next_object_id);
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(ids.SharedMemoryId.zero));

    const wrapped_object = try table.create(ids.task(8), PAGE_SIZE);
    try std.testing.expectEqual(@as(u64, 1), wrapped_object.id.raw());
    try std.testing.expectEqual(@as(u64, 2), table.next_object_id);
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(ids.SharedMemoryId.zero));

    table.next_object_id = 1;
    const skipped_object = try table.create(ids.task(9), PAGE_SIZE);
    try std.testing.expectEqual(@as(u64, 2), skipped_object.id.raw());
    try std.testing.expectEqual(@as(u64, 3), table.next_object_id);
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(ids.SharedMemoryId.zero));
}

test "shared memory object ids do not advance when creation fails" {
    var table = Table.init();

    table.next_object_id = 77;
    try std.testing.expectError(error.SizeZero, table.create(ids.task(7), 0));
    try std.testing.expectEqual(@as(u64, 77), table.next_object_id);

    for (0..MAX_SHARED_MEMORY_OBJECTS) |index| {
        _ = try table.create(ids.task(@intCast(index + 100)), PAGE_SIZE);
    }

    const next_before_full = table.next_object_id;
    try std.testing.expectError(error.TableFull, table.create(ids.task(1_000), PAGE_SIZE));
    try std.testing.expectEqual(next_before_full, table.next_object_id);
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(ids.sharedMemory(next_before_full)));
}

test "shared memory objects label accelerator access and explicit zero-copy attachments" {
    var table = Table.init();
    const object = try table.createLabeledWithAccess(ids.task(7), PAGE_SIZE * 4, "media-frame-buffer", .{
        .gpu = true,
        .media = true,
    });

    try std.testing.expect(table.find(object.id).?.allowsCompute(.gpu));
    try std.testing.expect(!table.find(object.id).?.allowsCompute(.npu));
    try table.attachAccelerator(object.id, .media);
    try std.testing.expect(table.find(object.id).?.attachedTo(.media));
    const media_mapping = try table.acceleratorMappingDescriptor(object.id, .media);
    try std.testing.expect(media_mapping.zero_copy);
    try std.testing.expectEqual(ComputeTarget.media, media_mapping.target.?);
    try std.testing.expectEqual(object.page_base, media_mapping.page_base);
    try std.testing.expectEqual(object.label_hash, media_mapping.label_hash);
    try std.testing.expectError(error.AcceleratorAccessDenied, table.attachAccelerator(object.id, .npu));
    try std.testing.expect(try table.detachAccelerator(object.id, .media));
    try std.testing.expect(!table.find(object.id).?.attachedTo(.media));
    try std.testing.expectError(error.AcceleratorNotAttached, table.acceleratorMappingDescriptor(object.id, .media));

    try table.attachAccelerator(object.id, .gpu);
    const gpu_mapping = try table.acceleratorMappingDescriptor(object.id, .gpu);
    try std.testing.expectEqual(media_mapping.page_base, gpu_mapping.page_base);
    try table.revoke(object.id);
    try std.testing.expect(!table.find(object.id).?.attachedTo(.gpu));
    try std.testing.expectError(error.Revoked, table.acceleratorMappingDescriptor(object.id, .gpu));
    try std.testing.expectError(error.Revoked, table.attachAccelerator(object.id, .gpu));
}

test "shared memory objects map through freestanding mmu and revoke accelerator mappings" {
    var table = Table.init();
    const object = try table.createLabeledWithAccess(ids.task(20), PAGE_SIZE * 2, "mmu-frame-buffer", .{
        .gpu = true,
        .media = true,
    });

    try table.map(object.id, ids.task(20));
    try table.map(object.id, ids.task(21));
    try std.testing.expectError(error.AlreadyMapped, table.mmu.mapTask(table.find(object.id).?, ids.task(20)));
    try std.testing.expectEqual(@as(usize, 2), table.mmu.mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 2), table.mmu.object_mapping_index.count(object.id.raw()));
    const owner_mapping = try table.freestandingTaskMappingDescriptor(object.id, ids.task(20));
    const peer_mapping = try table.freestandingTaskMappingDescriptor(object.id, ids.task(21));
    try std.testing.expect(owner_mapping.physical_base != 0);
    try std.testing.expect(owner_mapping.virtual_base != 0);
    try std.testing.expect(peer_mapping.virtual_base != 0);
    try std.testing.expect(owner_mapping.virtual_base != peer_mapping.virtual_base);
    try std.testing.expectEqual(owner_mapping.physical_base, peer_mapping.physical_base);
    try std.testing.expectEqual(@as(usize, 2), owner_mapping.page_count);
    try std.testing.expectEqual(object.label_hash, owner_mapping.label_hash);
    try std.testing.expect(!owner_mapping.zero_copy);
    try std.testing.expectEqual(@as(usize, 2), table.activeFreestandingMappings(object.id));

    try table.attachAccelerator(object.id, .gpu);
    try std.testing.expectError(error.AcceleratorAlreadyAttached, table.mmu.mapAccelerator(table.find(object.id).?, .gpu));
    try std.testing.expectEqual(@as(usize, 3), table.mmu.mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 3), table.mmu.object_mapping_index.count(object.id.raw()));
    const gpu_mapping = try table.freestandingAcceleratorMappingDescriptor(object.id, .gpu);
    try std.testing.expect(gpu_mapping.zero_copy);
    try std.testing.expectEqual(ComputeTarget.gpu, gpu_mapping.target.?);
    try std.testing.expectEqual(owner_mapping.physical_base, gpu_mapping.physical_base);
    try std.testing.expect(gpu_mapping.virtual_base != owner_mapping.virtual_base);
    try std.testing.expectEqual(@as(usize, 3), table.activeFreestandingMappings(object.id));

    const other_object = try table.create(ids.task(22), PAGE_SIZE);
    try table.map(other_object.id, ids.task(22));
    try std.testing.expectEqual(@as(usize, 4), table.mmu.mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(other_object.id));
    try table.revoke(object.id);
    try std.testing.expectEqual(@as(usize, 1), table.mmu.mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 0), table.mmu.object_mapping_index.count(object.id.raw()));
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(other_object.id));
    try std.testing.expectError(error.Revoked, table.freestandingTaskMappingDescriptor(object.id, ids.task(20)));
    try std.testing.expectError(error.Revoked, table.freestandingAcceleratorMappingDescriptor(object.id, .gpu));
}

test "shared memory rejects stale task and accelerator descriptors after generation changes" {
    var table = Table.init();
    const object = try table.createLabeledWithAccess(ids.task(30), PAGE_SIZE * 4, "service-path-frame-buffer", .{
        .gpu = true,
        .media = true,
    });

    try table.map(object.id, ids.task(30));
    const task_descriptor = try table.taskMappingDescriptor(object.id, ids.task(30));
    const task_mmu_descriptor = try table.freestandingTaskMappingDescriptor(object.id, ids.task(30));
    try table.validateTaskMappingDescriptor(task_descriptor);
    try table.validateFreestandingTaskMappingDescriptor(task_mmu_descriptor);

    try table.attachAccelerator(object.id, .gpu);
    const gpu_descriptor = try table.acceleratorMappingDescriptor(object.id, .gpu);
    const gpu_mmu_descriptor = try table.freestandingAcceleratorMappingDescriptor(object.id, .gpu);
    try table.validateAcceleratorMappingDescriptor(gpu_descriptor, .gpu);
    try table.validateFreestandingAcceleratorMappingDescriptor(gpu_mmu_descriptor, .gpu);
    try std.testing.expectEqual(gpu_descriptor.attachment_generation, (try table.taskMappingDescriptor(object.id, ids.task(30))).attachment_generation);
    try std.testing.expectEqual(gpu_mmu_descriptor.attachment_generation, (try table.freestandingTaskMappingDescriptor(object.id, ids.task(30))).attachment_generation);
    try std.testing.expectError(error.StaleMappingDescriptor, table.validateTaskMappingDescriptor(task_descriptor));
    try std.testing.expectError(error.StaleMappingDescriptor, table.validateFreestandingTaskMappingDescriptor(task_mmu_descriptor));

    var tampered = gpu_descriptor;
    tampered.label_hash +%= 1;
    try std.testing.expectError(error.MappingDescriptorMismatch, table.validateAcceleratorMappingDescriptor(tampered, .gpu));
    try std.testing.expectError(error.MappingDescriptorMismatch, table.validateAcceleratorMappingDescriptor(gpu_descriptor, .media));

    const refreshed_task_descriptor = try table.taskMappingDescriptor(object.id, ids.task(30));
    const refreshed_task_mmu_descriptor = try table.freestandingTaskMappingDescriptor(object.id, ids.task(30));
    try std.testing.expect(try table.detachAccelerator(object.id, .gpu));
    try std.testing.expectEqual(@as(usize, 1), table.mmu.object_mapping_index.count(object.id.raw()));
    try std.testing.expectError(error.AcceleratorNotAttached, table.validateAcceleratorMappingDescriptor(gpu_descriptor, .gpu));
    try std.testing.expectError(error.AcceleratorNotAttached, table.validateFreestandingAcceleratorMappingDescriptor(gpu_mmu_descriptor, .gpu));
    try std.testing.expectError(error.StaleMappingDescriptor, table.validateTaskMappingDescriptor(refreshed_task_descriptor));
    try std.testing.expectError(error.StaleMappingDescriptor, table.validateFreestandingTaskMappingDescriptor(refreshed_task_mmu_descriptor));

    const post_detach_task_descriptor = try table.taskMappingDescriptor(object.id, ids.task(30));
    try table.revoke(object.id);
    try std.testing.expectError(error.Revoked, table.validateTaskMappingDescriptor(post_detach_task_descriptor));
    try std.testing.expectError(error.Revoked, table.validateAcceleratorMappingDescriptor(gpu_descriptor, .gpu));
    try std.testing.expectError(error.Revoked, table.validateFreestandingTaskMappingDescriptor(refreshed_task_mmu_descriptor));
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
}
