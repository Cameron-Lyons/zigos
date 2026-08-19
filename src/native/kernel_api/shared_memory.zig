const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const userspace_layout = @import("../core/userspace_layout.zig");
const root = @import("root");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

const heap_backed_table = builtin.target.os.tag == .freestanding;

pub const MAX_SHARED_MEMORY_OBJECTS: usize = 24;
pub const MAX_MAPPINGS_PER_OBJECT: usize = 8;
pub const PAGE_SIZE: usize = 4096;
const SHARED_MEMORY_INDEX_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * 2;
pub const SHARED_MEMORY_PRIMARY_INDEX_LOOKUPS_PER_OPERATION: u8 = 0;
pub const SHARED_MEMORY_ID_COLLISION_PROBES_PER_INSERT: u8 = 0;
pub const OBJECT_TASK_MAPPING_SCAN_BOUND: usize = MAX_MAPPINGS_PER_OBJECT;
pub const MMU_OBJECT_MAPPING_SCAN_BOUND: usize = MAX_MAPPINGS_PER_OBJECT + 3;
pub const MMU_PRIMARY_INDEX_LOOKUPS_PER_OPERATION: u8 = 0;
const MAPPING_EDGE_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * MAX_MAPPINGS_PER_OBJECT;
const MAPPING_INDEX_CAPACITY: usize = MAPPING_EDGE_CAPACITY * 2;
const MMU_MAPPING_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * MMU_OBJECT_MAPPING_SCAN_BOUND;
const no_mmu_mapping: u16 = std.math.maxInt(u16);
const FREESTANDING_PHYSICAL_BASE: u64 = 0x0010_0000;
const TASK_SHARED_VIRTUAL_BASE: u64 = userspace_layout.shared_start;
const TASK_SHARED_VIRTUAL_END_EXCLUSIVE: u64 = userspace_layout.shared_end_exclusive;
const ACCELERATOR_APERTURE_BASE: u64 = userspace_layout.accelerator_start;
const ACCELERATOR_APERTURE_END_EXCLUSIVE: u64 = userspace_layout.accelerator_end_exclusive;

comptime {
    if (MMU_MAPPING_CAPACITY >= no_mmu_mapping) {
        @compileError("MMU mapping capacity exceeds compact intrusive index range");
    }
}

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
    compute_access: ComputeAccess,
    attached_compute: ComputeAccess,
    mapped_task_ids: [MAX_MAPPINGS_PER_OBJECT]ids.TaskId,
    mapping_count: usize,
    mmu_mapping_head: u16 = no_mmu_mapping,
    mmu_mapping_count: u16 = 0,

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

pub const TaskRetirement = struct {
    revoked_owned_objects: u16 = 0,
    removed_peer_mappings: u16 = 0,
    revoked_object_ids: [MAX_SHARED_MEMORY_OBJECTS]ids.SharedMemoryId = [_]ids.SharedMemoryId{ids.SharedMemoryId.zero} ** MAX_SHARED_MEMORY_OBJECTS,

    pub fn revokedObjectIds(self: *const TaskRetirement) []const ids.SharedMemoryId {
        return self.revoked_object_ids[0..self.revoked_owned_objects];
    }
};

pub const Error = error{
    AcceleratorAccessDenied,
    AcceleratorAlreadyAttached,
    AcceleratorNotAttached,
    AlreadyMapped,
    MappingDescriptorMismatch,
    MappingNotFound,
    OutOfMemory,
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
    object_next: u16 = no_mmu_mapping,
    object_prev: u16 = no_mmu_mapping,
};

const MmuMappingArena = indexed_arena.GenerationalArena("MmuMapping", MmuMapping, MMU_MAPPING_CAPACITY);

pub const FreestandingMmu = struct {
    next_physical_frame: u64 = 1,
    next_task_virtual_page: u64 = 1,
    next_accelerator_virtual_page: u64 = 1,
    mappings: MmuMappingArena = MmuMappingArena.init(),

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

    fn mapTask(
        self: *FreestandingMmu,
        object: *Object,
        task_id: ids.TaskId,
    ) Error!FreestandingMappingDescriptor {
        if (self.findIndex(object, .task, task_id.raw()) != null) return error.AlreadyMapped;
        if (object.mmu_mapping_count >= MMU_OBJECT_MAPPING_SCAN_BOUND) return error.TableFull;
        const slot_index = self.mappings.reserveIndex() orelse return error.TableFull;
        const virtual_base = self.allocateTaskVirtual(object.page_count) catch |err| {
            _ = self.mappings.removeIndex(slot_index);
            return err;
        };
        const slot = &self.mappings.slots[slot_index];
        slot.* = mappingFromObject(object, .task, task_id.raw(), virtual_base);
        self.linkObjectMapping(object, slot_index);
        return descriptorFromMmuMapping(object, slot);
    }

    fn unmapTask(self: *FreestandingMmu, object: *Object, task_id: ids.TaskId) Error!bool {
        return self.removeMapping(object, .task, task_id.raw());
    }

    fn mapAccelerator(
        self: *FreestandingMmu,
        object: *Object,
        target: ComputeTarget,
    ) Error!FreestandingMappingDescriptor {
        if (target == .cpu) return error.AcceleratorAccessDenied;
        const domain_id = acceleratorDomainId(target);
        if (self.findIndex(object, .accelerator, domain_id) != null) return error.AcceleratorAlreadyAttached;
        if (object.mmu_mapping_count >= MMU_OBJECT_MAPPING_SCAN_BOUND) return error.TableFull;
        const slot_index = self.mappings.reserveIndex() orelse return error.TableFull;
        const virtual_base = self.allocateAcceleratorVirtual(object.page_count) catch |err| {
            _ = self.mappings.removeIndex(slot_index);
            return err;
        };
        const slot = &self.mappings.slots[slot_index];
        slot.* = mappingFromObject(object, .accelerator, domain_id, virtual_base);
        self.linkObjectMapping(object, slot_index);
        return descriptorFromMmuMapping(object, slot);
    }

    fn unmapAccelerator(self: *FreestandingMmu, object: *Object, target: ComputeTarget) Error!bool {
        return self.removeMapping(object, .accelerator, acceleratorDomainId(target));
    }

    fn revokeObject(self: *FreestandingMmu, object: *Object) void {
        if (object.mmu_mapping_count > MMU_OBJECT_MAPPING_SCAN_BOUND) {
            native_util.impossibleByInvariant("shared-memory MMU object list stays within its fixed scan bound");
        }
        while (object.mmu_mapping_count != 0) {
            if (object.mmu_mapping_head == no_mmu_mapping) {
                native_util.impossibleByInvariant("non-empty shared-memory MMU object list has a head");
            }
            const slot_index: usize = object.mmu_mapping_head;
            if (slot_index >= self.mappings.slots.len) {
                native_util.impossibleByInvariant("shared-memory MMU object list points outside mapping slots");
            }
            const mapping = &self.mappings.slots[slot_index];
            if (!mapping.in_use or !mapping.object_id.eql(object.id)) {
                native_util.impossibleByInvariant("shared-memory MMU object list points at the wrong live mapping");
            }
            self.unlinkObjectMapping(object, slot_index);
            if (!self.mappings.removeIndex(slot_index)) {
                native_util.impossibleByInvariant("shared-memory MMU revoke removes every linked mapping");
            }
        }
        if (object.mmu_mapping_head != no_mmu_mapping) {
            native_util.impossibleByInvariant("empty shared-memory MMU object list has no head");
        }
    }

    fn taskMappingDescriptor(
        self: *const FreestandingMmu,
        object: *const Object,
        task_id: ids.TaskId,
    ) Error!FreestandingMappingDescriptor {
        const mapping = self.findAny(object, .task, task_id.raw()) orelse return error.MappingNotFound;
        return descriptorFromMmuMapping(object, mapping);
    }

    fn acceleratorMappingDescriptor(
        self: *const FreestandingMmu,
        object: *const Object,
        target: ComputeTarget,
    ) Error!FreestandingMappingDescriptor {
        const mapping = self.findAny(object, .accelerator, acceleratorDomainId(target)) orelse return error.AcceleratorNotAttached;
        return descriptorFromMmuMapping(object, mapping);
    }

    fn activeMappingsForObject(_: *const FreestandingMmu, object: *const Object) usize {
        return object.mmu_mapping_count;
    }

    fn allocateTaskVirtual(self: *FreestandingMmu, page_count: usize) Error!u64 {
        const base_page = self.next_task_virtual_page;
        const next_page = std.math.add(u64, base_page, @intCast(page_count)) catch return error.TableFull;
        const page_offset = std.math.mul(u64, base_page, PAGE_SIZE) catch return error.TableFull;
        const byte_count = std.math.mul(u64, @as(u64, @intCast(page_count)), PAGE_SIZE) catch return error.TableFull;
        const virtual_base = std.math.add(u64, TASK_SHARED_VIRTUAL_BASE, page_offset) catch return error.TableFull;
        const virtual_end = std.math.add(u64, virtual_base, byte_count) catch return error.TableFull;
        if (virtual_end > TASK_SHARED_VIRTUAL_END_EXCLUSIVE) return error.TableFull;
        self.next_task_virtual_page = next_page;
        return virtual_base;
    }

    fn allocateAcceleratorVirtual(self: *FreestandingMmu, page_count: usize) Error!u64 {
        const base_page = self.next_accelerator_virtual_page;
        const next_page = std.math.add(u64, base_page, @intCast(page_count)) catch return error.TableFull;
        const page_offset = std.math.mul(u64, base_page, PAGE_SIZE) catch return error.TableFull;
        const byte_count = std.math.mul(u64, @as(u64, @intCast(page_count)), PAGE_SIZE) catch return error.TableFull;
        const virtual_base = std.math.add(u64, ACCELERATOR_APERTURE_BASE, page_offset) catch return error.TableFull;
        const virtual_end = std.math.add(u64, virtual_base, byte_count) catch return error.TableFull;
        if (virtual_end > ACCELERATOR_APERTURE_END_EXCLUSIVE) return error.TableFull;
        self.next_accelerator_virtual_page = next_page;
        return virtual_base;
    }

    fn findAny(
        self: *const FreestandingMmu,
        object: *const Object,
        kind: MmuMappingKind,
        domain_id: u64,
    ) ?*const MmuMapping {
        const slot_index = self.findIndex(object, kind, domain_id) orelse return null;
        return &self.mappings.slots[slot_index];
    }

    fn findIndex(
        self: *const FreestandingMmu,
        object: *const Object,
        kind: MmuMappingKind,
        domain_id: u64,
    ) ?usize {
        const expected_count: usize = object.mmu_mapping_count;
        if (expected_count > MMU_OBJECT_MAPPING_SCAN_BOUND) {
            native_util.impossibleByInvariant("shared-memory MMU object list stays within its fixed scan bound");
        }
        var compact_index = object.mmu_mapping_head;
        var visited: usize = 0;
        while (compact_index != no_mmu_mapping) : (visited += 1) {
            if (visited >= expected_count) {
                native_util.impossibleByInvariant("shared-memory MMU object list length matches its count");
            }
            const slot_index: usize = compact_index;
            if (slot_index >= self.mappings.slots.len) {
                native_util.impossibleByInvariant("shared-memory MMU object list points outside mapping slots");
            }
            const mapping = &self.mappings.slots[slot_index];
            if (!mapping.in_use or !mapping.object_id.eql(object.id)) {
                native_util.impossibleByInvariant("shared-memory MMU object list points at the wrong live mapping");
            }
            if (mapping.kind == kind and mapping.domain_id == domain_id) return slot_index;
            compact_index = mapping.object_next;
        }
        if (visited != expected_count) {
            native_util.impossibleByInvariant("shared-memory MMU object list length matches its count");
        }
        return null;
    }

    fn removeMapping(self: *FreestandingMmu, object: *Object, kind: MmuMappingKind, domain_id: u64) bool {
        const slot_index = self.findIndex(object, kind, domain_id) orelse return false;
        self.unlinkObjectMapping(object, slot_index);
        if (!self.mappings.removeIndex(slot_index)) {
            native_util.impossibleByInvariant("shared-memory MMU unmap removes a live linked mapping");
        }
        return true;
    }

    fn linkObjectMapping(self: *FreestandingMmu, object: *Object, slot_index: usize) void {
        const compact_index: u16 = @intCast(slot_index);
        const mapping = &self.mappings.slots[slot_index];
        std.debug.assert(mapping.in_use and mapping.object_id.eql(object.id));
        if (object.mmu_mapping_count >= MMU_OBJECT_MAPPING_SCAN_BOUND) {
            native_util.impossibleByInvariant("shared-memory MMU object list stays within its fixed scan bound");
        }
        mapping.object_prev = no_mmu_mapping;
        mapping.object_next = object.mmu_mapping_head;
        if (object.mmu_mapping_head != no_mmu_mapping) {
            self.mappings.slots[object.mmu_mapping_head].object_prev = compact_index;
        }
        object.mmu_mapping_head = compact_index;
        object.mmu_mapping_count += 1;
    }

    fn unlinkObjectMapping(self: *FreestandingMmu, object: *Object, slot_index: usize) void {
        const mapping = &self.mappings.slots[slot_index];
        std.debug.assert(mapping.in_use and mapping.object_id.eql(object.id));
        if (mapping.object_prev == no_mmu_mapping) {
            std.debug.assert(object.mmu_mapping_head == slot_index);
            object.mmu_mapping_head = mapping.object_next;
        } else {
            self.mappings.slots[mapping.object_prev].object_next = mapping.object_next;
        }
        if (mapping.object_next != no_mmu_mapping) {
            self.mappings.slots[mapping.object_next].object_prev = mapping.object_prev;
        }
        mapping.object_next = no_mmu_mapping;
        mapping.object_prev = no_mmu_mapping;
        std.debug.assert(object.mmu_mapping_count > 0);
        object.mmu_mapping_count -= 1;
    }
};

const ObjectSlot = struct {
    in_use: bool = false,
    object: Object = zeroObject(),
};

pub const ObjectArena = indexed_arena.GenerationalArena("SharedMemoryId", ObjectSlot, MAX_SHARED_MEMORY_OBJECTS);
const ObjectHandle = ObjectArena.Handle;
pub const ObjectOwnerIndex = indexed_arena.MultimapIndex(MAX_SHARED_MEMORY_OBJECTS, MAX_SHARED_MEMORY_OBJECTS, SHARED_MEMORY_INDEX_CAPACITY);
const MappingIndex = indexed_arena.MultimapIndex(MAPPING_EDGE_CAPACITY, MAPPING_EDGE_CAPACITY, MAPPING_INDEX_CAPACITY);

const TableBacking = struct {
    mmu: FreestandingMmu = FreestandingMmu.init(),
    arena: ObjectArena = ObjectArena.init(),
    object_owner_index: ObjectOwnerIndex = ObjectOwnerIndex.init(),
    mapping_index: MappingIndex = MappingIndex.init(),

    fn init() TableBacking {
        return .{};
    }

    fn initializeAllocated(self: *TableBacking) void {
        @memset(std.mem.asBytes(self), 0);
        self.mmu.next_physical_frame = 1;
        self.mmu.next_task_virtual_page = 1;
        self.mmu.next_accelerator_virtual_page = 1;
        self.mmu.mappings.free_head = indexed_arena.reusableNoIndex(MMU_MAPPING_CAPACITY);
        self.arena.free_head = indexed_arena.reusableNoIndex(MAX_SHARED_MEMORY_OBJECTS);
        initializeObjectOwnerIndex(&self.object_owner_index);
        initializeMappingIndex(&self.mapping_index);
    }

    fn initializeObjectOwnerIndex(index: *ObjectOwnerIndex) void {
        for (&index.buckets) |*bucket| bucket.* = .{};
        for (&index.links) |*link| link.* = .{};
        index.free_bucket_head = indexed_arena.reusableNoIndex(MAX_SHARED_MEMORY_OBJECTS);
    }

    fn initializeMappingIndex(index: *MappingIndex) void {
        for (&index.buckets) |*bucket| bucket.* = .{};
        for (&index.links) |*link| link.* = .{};
        index.free_bucket_head = indexed_arena.reusableNoIndex(MAPPING_EDGE_CAPACITY);
    }
};

const TableBackingStorage = if (heap_backed_table) ?*TableBacking else TableBacking;

pub const Table = struct {
    backing: TableBackingStorage = if (heap_backed_table) null else TableBacking.init(),

    pub fn init() Table {
        return .{};
    }

    comptime {
        if (heap_backed_table and @sizeOf(@This()) > 64) {
            @compileError("heap-backed shared-memory tables exceed their compact resident layout");
        }
    }

    pub fn deinit(self: *Table) void {
        if (comptime heap_backed_table) {
            if (self.backing) |backing| {
                @memset(std.mem.asBytes(backing), 0);
                kernel_memory.kfree(@ptrCast(backing));
                self.backing = null;
            }
        } else {
            self.backing = TableBacking.init();
        }
    }

    fn backingPtr(self: *Table) ?*TableBacking {
        if (comptime heap_backed_table) return self.backing;
        return &self.backing;
    }

    fn backingConst(self: *const Table) ?*const TableBacking {
        if (comptime heap_backed_table) return self.backing;
        return &self.backing;
    }

    fn ensureBacking(self: *Table) error{OutOfMemory}!*TableBacking {
        if (self.backingPtr()) |backing| return backing;
        if (comptime heap_backed_table) {
            const allocation = kernel_memory.kmalloc(@sizeOf(TableBacking)) orelse return error.OutOfMemory;
            const backing: *TableBacking = @ptrCast(@alignCast(allocation));
            backing.initializeAllocated();
            self.backing = backing;
            return backing;
        }
        return &self.backing;
    }

    fn mmuForTests(self: *Table) *FreestandingMmu {
        return &self.backingPtr().?.mmu;
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
        const backing = try self.ensureBacking();
        const handle = backing.arena.reserveHandle() orelse return error.TableFull;
        errdefer if (!backing.arena.removeHandle(handle)) {
            native_util.impossibleByInvariant("failed shared-memory creation releases its reserved object slot");
        };
        const object_id = ids.sharedMemory(handle.value);
        const page_count = pageCount(size_bytes);
        const page_base = try backing.mmu.allocatePhysicalFrames(page_count);
        const slot = backing.arena.getByHandle(handle) orelse
            native_util.impossibleByInvariant("reserved shared-memory handle is live");
        slot.* = .{
            .in_use = true,
            .object = .{
                .id = object_id,
                .owner_task_id = owner_task_id,
                .size_bytes = size_bytes,
                .page_base = page_base,
                .page_count = page_count,
                .label_hash = labelHash(label),
                .revocation_generation = handle.generation(),
                .attachment_generation = 1,
                .compute_access = compute_access,
                .attached_compute = ComputeAccess.empty(),
                .mapped_task_ids = [_]ids.TaskId{ids.TaskId.zero} ** MAX_MAPPINGS_PER_OBJECT,
                .mapping_count = 0,
                .mmu_mapping_head = no_mmu_mapping,
                .mmu_mapping_count = 0,
            },
        };
        if (!backing.object_owner_index.append(owner_task_id.raw(), handle.slotIndex())) {
            native_util.impossibleByInvariant("shared-memory owner index capacity covers object slots");
        }
        return slot.object;
    }

    pub fn map(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!void {
        const backing = self.backingPtr() orelse return error.SharedMemoryNotFound;
        const object_handle = ObjectHandle{ .value = object_id.raw() };
        const object_slot = backing.arena.getByHandle(object_handle) orelse return error.SharedMemoryNotFound;
        const object_slot_index = object_handle.slotIndex();
        const object = &object_slot.object;

        if (objectTaskMappingPosition(object, task_id) != null) return error.AlreadyMapped;
        if (object.mapping_count >= object.mapped_task_ids.len) return error.TableFull;

        const edge_index = mappingEdgeIndex(object_slot_index, object.mapping_count);
        if (!backing.mapping_index.append(task_id.raw(), edge_index)) return error.TableFull;
        object.mapped_task_ids[object.mapping_count] = task_id;
        object.mapping_count += 1;
        _ = backing.mmu.mapTask(object, task_id) catch |err| {
            object.mapping_count -= 1;
            object.mapped_task_ids[object.mapping_count] = ids.TaskId.zero;
            _ = backing.mapping_index.remove(task_id.raw(), mappingEdgeIndex(object_slot_index, object.mapping_count));
            return err;
        };
    }

    pub fn unmap(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!bool {
        const backing = self.backingPtr() orelse return error.SharedMemoryNotFound;
        const object_handle = ObjectHandle{ .value = object_id.raw() };
        const object_slot = backing.arena.getByHandle(object_handle) orelse return error.SharedMemoryNotFound;
        const object_slot_index = object_handle.slotIndex();
        const object = &object_slot.object;
        const index = objectTaskMappingPosition(object, task_id) orelse return false;
        const edge_index = mappingEdgeIndex(object_slot_index, index);

        _ = backing.mapping_index.remove(task_id.raw(), edge_index);
        var tail = index;
        while (tail + 1 < object.mapping_count) : (tail += 1) {
            const moved_task_id = object.mapped_task_ids[tail + 1];
            const old_edge_index = mappingEdgeIndex(object_slot_index, tail + 1);
            const new_edge_index = mappingEdgeIndex(object_slot_index, tail);
            _ = backing.mapping_index.remove(moved_task_id.raw(), old_edge_index);
            if (!backing.mapping_index.append(moved_task_id.raw(), new_edge_index)) return error.TableFull;
            object.mapped_task_ids[tail] = moved_task_id;
        }
        object.mapping_count -= 1;
        object.mapped_task_ids[object.mapping_count] = ids.TaskId.zero;
        _ = try backing.mmu.unmapTask(object, task_id);
        return true;
    }

    pub fn revoke(self: *Table, object_id: ids.SharedMemoryId) Error!abi.SharedMemoryDescriptor {
        const backing = self.backingPtr() orelse return error.SharedMemoryNotFound;
        const object_handle = ObjectHandle{ .value = object_id.raw() };
        const object_slot = backing.arena.getByHandle(object_handle) orelse return error.SharedMemoryNotFound;
        const object_slot_index = object_handle.slotIndex();
        const object = &object_slot.object;
        _ = backing.object_owner_index.remove(object.owner_task_id.raw(), object_slot_index);
        for (object.mapped_task_ids[0..object.mapping_count], 0..) |task_id, mapping_index| {
            _ = backing.mapping_index.remove(task_id.raw(), mappingEdgeIndex(object_slot_index, mapping_index));
        }
        backing.mmu.revokeObject(object);
        object.revocation_generation += 1;
        object.attachment_generation += 1;
        object.attached_compute = ComputeAccess.empty();
        object.mapping_count = 0;
        object.mapped_task_ids = [_]ids.TaskId{ids.TaskId.zero} ** MAX_MAPPINGS_PER_OBJECT;
        const revoked_descriptor = descriptorForObject(object, true);
        if (!backing.arena.removeHandle(object_handle)) {
            native_util.impossibleByInvariant("revoked shared-memory handle remains live through teardown");
        }
        if (backing.arena.countInUse() == 0 and backing.mmu.mappings.countInUse() == 0) {
            backing.mmu.next_physical_frame = 1;
            backing.mmu.next_task_virtual_page = 1;
            backing.mmu.next_accelerator_virtual_page = 1;
        }
        return revoked_descriptor;
    }

    pub fn retireTask(self: *Table, task_id: ids.TaskId) TaskRetirement {
        var retired = TaskRetirement{};
        const backing = self.backingPtr() orelse return retired;
        while (true) {
            const object_slot_index = backing.object_owner_index.head(task_id.raw());
            if (object_slot_index == indexed_arena.no_index) break;
            if (object_slot_index >= backing.arena.slots.len) {
                native_util.impossibleByInvariant("shared-memory owner index points outside object slots");
            }
            const slot = &backing.arena.slots[object_slot_index];
            if (!slot.in_use or !slot.object.owner_task_id.eql(task_id)) {
                native_util.impossibleByInvariant("shared-memory owner index points at the wrong live object");
            }
            const object_id = slot.object.id;
            _ = self.revoke(object_id) catch |err|
                native_util.impossibleByInvariantError("task retirement revokes an indexed shared-memory object", err);
            retired.revoked_object_ids[retired.revoked_owned_objects] = object_id;
            retired.revoked_owned_objects += 1;
        }

        while (true) {
            const edge_index = backing.mapping_index.head(task_id.raw());
            if (edge_index == indexed_arena.no_index) break;
            const object_slot_index = mappingEdgeObjectSlotIndex(edge_index);
            const object_mapping_index = mappingEdgeMappingIndex(edge_index);
            if (object_slot_index >= backing.arena.slots.len) {
                native_util.impossibleByInvariant("shared-memory task mapping points outside object slots");
            }
            const slot = &backing.arena.slots[object_slot_index];
            if (!slot.in_use or
                object_mapping_index >= slot.object.mapping_count or
                !slot.object.mapped_task_ids[object_mapping_index].eql(task_id))
            {
                native_util.impossibleByInvariant("shared-memory task mapping index points at the wrong live mapping");
            }
            const removed = self.unmap(slot.object.id, task_id) catch |err|
                native_util.impossibleByInvariantError("task retirement unmaps an indexed shared-memory mapping", err);
            if (!removed) {
                native_util.impossibleByInvariant("task retirement removes every indexed shared-memory mapping");
            }
            retired.removed_peer_mappings += 1;
        }
        return retired;
    }

    pub fn attachAccelerator(self: *Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!void {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (target == .cpu) return error.AcceleratorAccessDenied;
        if (!object.allowsCompute(target)) return error.AcceleratorAccessDenied;
        if (object.attachedTo(target)) return error.AcceleratorAlreadyAttached;

        const previous_generation = object.attachment_generation;
        setComputeAccess(&object.attached_compute, target, true);
        object.attachment_generation += 1;
        _ = self.backingPtr().?.mmu.mapAccelerator(object, target) catch |err| {
            setComputeAccess(&object.attached_compute, target, false);
            object.attachment_generation = previous_generation;
            return err;
        };
    }

    pub fn detachAccelerator(self: *Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!bool {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (!object.attachedTo(target)) return false;

        _ = try self.backingPtr().?.mmu.unmapAccelerator(object, target);
        setComputeAccess(&object.attached_compute, target, false);
        object.attachment_generation += 1;
        return true;
    }

    pub fn descriptor(self: *const Table, object_id: ids.SharedMemoryId) Error!abi.SharedMemoryDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return descriptorForObject(object, false);
    }

    pub fn taskMappingDescriptor(
        self: *const Table,
        object_id: ids.SharedMemoryId,
        task_id: ids.TaskId,
    ) Error!MappingDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        if (!self.hasMapping(object_id, task_id)) return error.MappingNotFound;
        return mappingDescriptorFor(object, task_id, null, false);
    }

    pub fn validateTaskMappingDescriptor(
        self: *const Table,
        mapping_descriptor: MappingDescriptor,
    ) Error!void {
        const object = self.findConst(mapping_descriptor.object_id) orelse return error.SharedMemoryNotFound;
        if (!self.hasMapping(mapping_descriptor.object_id, mapping_descriptor.task_id)) return error.MappingNotFound;
        try validateMappingDescriptorForObject(object, mapping_descriptor, mapping_descriptor.task_id, null, false);
    }

    pub fn acceleratorMappingDescriptor(
        self: *const Table,
        object_id: ids.SharedMemoryId,
        target: ComputeTarget,
    ) Error!MappingDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        if (!object.attachedTo(target)) return error.AcceleratorNotAttached;
        return mappingDescriptorFor(object, ids.TaskId.zero, target, true);
    }

    pub fn validateAcceleratorMappingDescriptor(
        self: *const Table,
        mapping_descriptor: MappingDescriptor,
        target: ComputeTarget,
    ) Error!void {
        const object = self.findConst(mapping_descriptor.object_id) orelse return error.SharedMemoryNotFound;
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
        return self.backingConst().?.mmu.taskMappingDescriptor(object, task_id);
    }

    pub fn validateFreestandingTaskMappingDescriptor(
        self: *const Table,
        mapping_descriptor: FreestandingMappingDescriptor,
    ) Error!void {
        const object = self.findConst(mapping_descriptor.object_id) orelse return error.SharedMemoryNotFound;
        const current = try self.backingConst().?.mmu.taskMappingDescriptor(object, mapping_descriptor.task_id);
        try validateFreestandingDescriptorForObject(object, current, mapping_descriptor, mapping_descriptor.task_id, null, false);
    }

    pub fn freestandingAcceleratorMappingDescriptor(
        self: *const Table,
        object_id: ids.SharedMemoryId,
        target: ComputeTarget,
    ) Error!FreestandingMappingDescriptor {
        const object = self.findConst(object_id) orelse return error.SharedMemoryNotFound;
        return self.backingConst().?.mmu.acceleratorMappingDescriptor(object, target);
    }

    pub fn validateFreestandingAcceleratorMappingDescriptor(
        self: *const Table,
        mapping_descriptor: FreestandingMappingDescriptor,
        target: ComputeTarget,
    ) Error!void {
        const object = self.findConst(mapping_descriptor.object_id) orelse return error.SharedMemoryNotFound;
        if (!mapping_descriptor.task_id.eql(ids.TaskId.zero) or
            !computeTargetsEqual(mapping_descriptor.target, target) or
            !mapping_descriptor.zero_copy)
        {
            return error.MappingDescriptorMismatch;
        }
        const current = try self.backingConst().?.mmu.acceleratorMappingDescriptor(object, target);
        try validateFreestandingDescriptorForObject(object, current, mapping_descriptor, ids.TaskId.zero, target, true);
    }

    pub fn activeFreestandingMappings(self: *const Table, object_id: ids.SharedMemoryId) usize {
        const object = self.findConst(object_id) orelse return 0;
        return self.backingConst().?.mmu.activeMappingsForObject(object);
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
        const backing = self.backingConst() orelse return 0;
        return @intCast(backing.mapping_index.count(task_id.raw()));
    }

    pub fn liveOwnedBytesForTask(self: *const Table, task_id: ids.TaskId) usize {
        const backing = self.backingConst() orelse return 0;
        var total: usize = 0;
        var slot_index = backing.object_owner_index.head(task_id.raw());
        while (slot_index != indexed_arena.no_index) : (slot_index = backing.object_owner_index.next(slot_index)) {
            if (slot_index >= backing.arena.slots.len) continue;
            const slot = &backing.arena.slots[slot_index];
            if (!slot.in_use or !slot.object.owner_task_id.eql(task_id)) continue;
            total = std.math.add(usize, total, slot.object.size_bytes) catch return std.math.maxInt(usize);
        }
        return total;
    }

    pub fn liveMappedBytesForTask(self: *const Table, task_id: ids.TaskId) usize {
        const backing = self.backingConst() orelse return 0;
        var total: usize = 0;
        var edge_index = backing.mapping_index.head(task_id.raw());
        while (edge_index != indexed_arena.no_index) : (edge_index = backing.mapping_index.next(edge_index)) {
            const object_slot_index = mappingEdgeObjectSlotIndex(edge_index);
            const mapping_index = mappingEdgeMappingIndex(edge_index);
            if (object_slot_index >= backing.arena.slots.len) continue;
            const slot = &backing.arena.slots[object_slot_index];
            if (!slot.in_use or mapping_index >= slot.object.mapping_count) continue;
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
        return objectTaskMappingPosition(object, task_id) != null;
    }

    pub fn activeCount(self: *const Table) usize {
        const backing = self.backingConst() orelse return 0;
        return backing.arena.countInUse();
    }

    fn find(self: *Table, object_id: ids.SharedMemoryId) ?*Object {
        const backing = self.backingPtr() orelse return null;
        const slot = backing.arena.getByHandle(ObjectHandle{ .value = object_id.raw() }) orelse return null;
        return &slot.object;
    }

    fn findConst(self: *const Table, object_id: ids.SharedMemoryId) ?*const Object {
        const backing = self.backingConst() orelse return null;
        const slot = backing.arena.getConstByHandle(ObjectHandle{ .value = object_id.raw() }) orelse return null;
        return &slot.object;
    }
};

fn objectTaskMappingPosition(object: *const Object, task_id: ids.TaskId) ?usize {
    if (object.mapping_count > OBJECT_TASK_MAPPING_SCAN_BOUND) {
        native_util.impossibleByInvariant("shared-memory object task mappings stay within their fixed scan bound");
    }
    for (object.mapped_task_ids[0..object.mapping_count], 0..) |mapped_task_id, mapping_index| {
        if (mapped_task_id.eql(task_id)) return mapping_index;
    }
    return null;
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
        .compute_access = .{},
        .attached_compute = ComputeAccess.empty(),
        .mapped_task_ids = [_]ids.TaskId{ids.TaskId.zero} ** MAX_MAPPINGS_PER_OBJECT,
        .mapping_count = 0,
        .mmu_mapping_head = no_mmu_mapping,
        .mmu_mapping_count = 0,
    };
}

fn descriptorForObject(object: *const Object, revoked: bool) abi.SharedMemoryDescriptor {
    return .{
        .object_id = object.id.raw(),
        .owner_task_id = object.owner_task_id.raw(),
        .size_bytes = object.size_bytes,
        .revocation_generation = object.revocation_generation,
        .mapped_task_count = @intCast(object.mapping_count),
        .flags = if (revoked) 1 else 0,
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
        descriptor.attachment_generation != object.attachment_generation)
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
) MmuMapping {
    return .{
        .in_use = true,
        .object_id = object.id,
        .kind = kind,
        .domain_id = domain_id,
        .virtual_base = virtual_base,
    };
}

fn descriptorFromMmuMapping(object: *const Object, mapping: *const MmuMapping) FreestandingMappingDescriptor {
    return .{
        .object_id = mapping.object_id,
        .task_id = if (mapping.kind == .task) ids.task(mapping.domain_id) else ids.TaskId.zero,
        .target = if (mapping.kind == .accelerator) computeTargetFromDomainId(mapping.domain_id) else null,
        .virtual_base = mapping.virtual_base,
        .physical_base = object.page_base,
        .page_count = object.page_count,
        .size_bytes = object.size_bytes,
        .label_hash = object.label_hash,
        .revocation_generation = object.revocation_generation,
        .attachment_generation = object.attachment_generation,
        .zero_copy = mapping.kind == .accelerator,
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

test "allocated shared memory backing initializes every arena and index" {
    var backing: TableBacking = undefined;
    backing.initializeAllocated();

    try std.testing.expectEqual(@as(u64, 1), backing.mmu.next_physical_frame);
    try std.testing.expectEqual(@as(usize, 0), backing.arena.countInUse());
    try std.testing.expectEqual(@as(usize, 0), backing.mmu.mappings.countInUse());

    const object_handle = backing.arena.reserveHandle().?;
    try std.testing.expectEqual(@as(u32, 1), object_handle.generation());
    try std.testing.expect(backing.arena.removeHandle(object_handle));

    try std.testing.expect(backing.object_owner_index.append(7, 0));
    try std.testing.expectEqual(@as(usize, 1), backing.object_owner_index.count(7));
    try std.testing.expect(backing.object_owner_index.remove(7, 0));

    try std.testing.expect(backing.mapping_index.append(9, 0));
    try std.testing.expectEqual(@as(usize, 1), backing.mapping_index.count(9));
    try std.testing.expect(backing.mapping_index.remove(9, 0));

    const mapping_index = backing.mmu.mappings.reserveIndex().?;
    try std.testing.expect(backing.mmu.mappings.removeIndex(mapping_index));
}

test "shared memory objects map unmap and revoke across tasks" {
    var table = Table.init();
    const object = try table.createLabeledWithAccess(ids.task(7), 4096, "ipc-ring", .{});
    const peer_object = try table.create(ids.task(8), PAGE_SIZE * 2);

    try std.testing.expectEqual(@as(usize, 1), table.backingPtr().?.object_owner_index.count(ids.task(7).raw()));
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

    const descriptor = try table.revoke(object.id);
    try std.testing.expectEqual(@as(usize, 0), table.backingPtr().?.object_owner_index.count(ids.task(7).raw()));
    try std.testing.expectEqual(@as(usize, 0), table.liveOwnedBytesForTask(ids.task(7)));
    try std.testing.expectEqual(@as(usize, PAGE_SIZE * 2), table.liveOwnedBytesForTask(ids.task(8)));
    try std.testing.expect(!peer_object.id.eql(object.id));
    try std.testing.expectEqual(@as(u16, 0), descriptor.mapped_task_count);
    try std.testing.expect(!table.hasMapping(object.id, ids.task(7)));
    try std.testing.expectEqual(@as(u16, 0), table.mappingsForTask(ids.task(7)));
    try std.testing.expectEqual(@as(u16, 1), descriptor.flags);
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(object.id));
    try std.testing.expectError(error.SharedMemoryNotFound, table.taskMappingDescriptor(object.id, ids.task(7)));
    try std.testing.expectError(error.SharedMemoryNotFound, table.map(object.id, ids.task(9)));
}

test "revoking the final shared memory object reclaims descriptor cursors" {
    var table = Table.init();
    const object = try table.createWithAccess(ids.task(7), PAGE_SIZE, .{
        .cpu = true,
        .gpu = true,
    });
    try table.map(object.id, ids.task(7));
    try table.attachAccelerator(object.id, .gpu);

    _ = try table.revoke(object.id);

    const mmu = table.mmuForTests();
    try std.testing.expectEqual(@as(u64, 1), mmu.next_physical_frame);
    try std.testing.expectEqual(@as(u64, 1), mmu.next_task_virtual_page);
    try std.testing.expectEqual(@as(u64, 1), mmu.next_accelerator_virtual_page);
}

test "bounded object task scans preserve compacted mappings" {
    var table = Table.init();
    const object = try table.create(ids.task(1), PAGE_SIZE);

    try table.map(object.id, ids.task(2));
    try table.map(object.id, ids.task(3));
    try table.map(object.id, ids.task(4));
    try std.testing.expect(try table.unmap(object.id, ids.task(3)));
    try std.testing.expect(table.hasMapping(object.id, ids.task(2)));
    try std.testing.expect(!table.hasMapping(object.id, ids.task(3)));
    try std.testing.expect(table.hasMapping(object.id, ids.task(4)));
    try std.testing.expectEqual(@as(u16, 1), table.mappingsForTask(ids.task(4)));
    _ = try table.taskMappingDescriptor(object.id, ids.task(4));

    try std.testing.expect(try table.unmap(object.id, ids.task(2)));
    try std.testing.expect(table.hasMapping(object.id, ids.task(4)));
    try std.testing.expectError(error.AlreadyMapped, table.map(object.id, ids.task(4)));
    try std.testing.expectEqual(@as(u16, 1), (try table.descriptor(object.id)).mapped_task_count);
}

test "task retirement revokes owned objects and removes only its peer mappings" {
    var table = Table.init();
    const owned = try table.createLabeledWithAccess(ids.task(10), PAGE_SIZE, "owned", .{ .gpu = true });
    const owned_idle = try table.create(ids.task(10), PAGE_SIZE * 2);
    const peer = try table.create(ids.task(11), PAGE_SIZE * 3);

    try table.map(owned.id, ids.task(10));
    try table.map(owned.id, ids.task(11));
    try table.attachAccelerator(owned.id, .gpu);
    try table.map(peer.id, ids.task(10));
    try table.map(peer.id, ids.task(11));
    try table.map(peer.id, ids.task(12));
    try std.testing.expectEqual(@as(usize, 6), table.mmuForTests().mappings.countInUse());

    const retired = table.retireTask(ids.task(10));
    try std.testing.expectEqual(@as(u16, 2), retired.revoked_owned_objects);
    try std.testing.expectEqual(@as(u16, 1), retired.removed_peer_mappings);
    try std.testing.expectEqual(@as(usize, 2), retired.revokedObjectIds().len);
    try std.testing.expect(retired.revokedObjectIds()[0].eql(owned.id) or retired.revokedObjectIds()[1].eql(owned.id));
    try std.testing.expect(retired.revokedObjectIds()[0].eql(owned_idle.id) or retired.revokedObjectIds()[1].eql(owned_idle.id));
    try std.testing.expectEqual(@as(usize, 0), table.liveOwnedBytesForTask(ids.task(10)));
    try std.testing.expectEqual(@as(u16, 0), table.mappingsForTask(ids.task(10)));
    try std.testing.expectEqual(@as(u16, 1), table.mappingsForTask(ids.task(11)));
    try std.testing.expectEqual(@as(usize, 2), table.mmuForTests().mappings.countInUse());
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(owned.id));
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(owned_idle.id));
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(peer.id)).flags);
    try std.testing.expectEqual(@as(u16, 2), (try table.descriptor(peer.id)).mapped_task_count);
    try std.testing.expectError(error.MappingNotFound, table.taskMappingDescriptor(peer.id, ids.task(10)));
    _ = try table.taskMappingDescriptor(peer.id, ids.task(11));
    _ = try table.taskMappingDescriptor(peer.id, ids.task(12));
    try std.testing.expectError(error.SharedMemoryNotFound, table.acceleratorMappingDescriptor(owned.id, .gpu));

    const repeated = table.retireTask(ids.task(10));
    try std.testing.expectEqual(@as(u16, 0), repeated.revoked_owned_objects);
    try std.testing.expectEqual(@as(u16, 0), repeated.removed_peer_mappings);
}

test "shared memory object ids reject stale handles after slot reuse" {
    var table = Table.init();
    const object = try table.create(ids.task(7), PAGE_SIZE);
    const original_handle = ObjectHandle{ .value = object.id.raw() };

    const revoked = try table.revoke(object.id);
    try std.testing.expectEqual(@as(u16, 1), revoked.flags);
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(object.id));

    const replacement = try table.create(ids.task(8), PAGE_SIZE);
    const replacement_handle = ObjectHandle{ .value = replacement.id.raw() };
    try std.testing.expectEqual(original_handle.slotIndex(), replacement_handle.slotIndex());
    try std.testing.expect(!object.id.eql(replacement.id));
    try std.testing.expectError(error.SharedMemoryNotFound, table.map(object.id, ids.task(8)));
    try std.testing.expectEqual(replacement.id.raw(), (try table.descriptor(replacement.id)).object_id);
}

test "shared memory object creation failures preserve capacity and frame allocation" {
    var table = Table.init();

    try std.testing.expectError(error.SizeZero, table.create(ids.task(7), 0));
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());

    for (0..MAX_SHARED_MEMORY_OBJECTS) |index| {
        _ = try table.create(ids.task(@intCast(index + 100)), PAGE_SIZE);
    }

    const next_frame_before_full = table.mmuForTests().next_physical_frame;
    try std.testing.expectError(error.TableFull, table.create(ids.task(1_000), PAGE_SIZE));
    try std.testing.expectEqual(MAX_SHARED_MEMORY_OBJECTS, table.activeCount());
    try std.testing.expectEqual(next_frame_before_full, table.mmuForTests().next_physical_frame);
}

test "shared memory identity paths avoid primary indexes and collision probes" {
    try std.testing.expectEqual(@as(u8, 0), SHARED_MEMORY_PRIMARY_INDEX_LOOKUPS_PER_OPERATION);
    try std.testing.expectEqual(@as(u8, 0), SHARED_MEMORY_ID_COLLISION_PROBES_PER_INSERT);
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
    _ = try table.revoke(object.id);
    try std.testing.expect(table.find(object.id) == null);
    try std.testing.expectError(error.SharedMemoryNotFound, table.acceleratorMappingDescriptor(object.id, .gpu));
    try std.testing.expectError(error.SharedMemoryNotFound, table.attachAccelerator(object.id, .gpu));
}

test "shared memory objects map through freestanding mmu and revoke accelerator mappings" {
    var table = Table.init();
    const object = try table.createLabeledWithAccess(ids.task(20), PAGE_SIZE * 2, "mmu-frame-buffer", .{
        .gpu = true,
        .media = true,
    });

    try table.map(object.id, ids.task(20));
    try table.map(object.id, ids.task(21));
    try std.testing.expectError(error.AlreadyMapped, table.mmuForTests().mapTask(table.find(object.id).?, ids.task(20)));
    try std.testing.expectEqual(@as(usize, 2), table.mmuForTests().mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 2), table.activeFreestandingMappings(object.id));
    const owner_mapping = try table.freestandingTaskMappingDescriptor(object.id, ids.task(20));
    const peer_mapping = try table.freestandingTaskMappingDescriptor(object.id, ids.task(21));
    try std.testing.expect(owner_mapping.physical_base != 0);
    try std.testing.expect(owner_mapping.virtual_base >= userspace_layout.shared_start);
    try std.testing.expect(owner_mapping.virtual_base < userspace_layout.shared_end_exclusive);
    try std.testing.expect(peer_mapping.virtual_base >= userspace_layout.shared_start);
    try std.testing.expect(peer_mapping.virtual_base < userspace_layout.shared_end_exclusive);
    try std.testing.expect(owner_mapping.virtual_base != peer_mapping.virtual_base);
    try std.testing.expectEqual(owner_mapping.physical_base, peer_mapping.physical_base);
    try std.testing.expectEqual(@as(usize, 2), owner_mapping.page_count);
    try std.testing.expectEqual(object.label_hash, owner_mapping.label_hash);
    try std.testing.expect(!owner_mapping.zero_copy);
    try std.testing.expectEqual(@as(usize, 2), table.activeFreestandingMappings(object.id));

    try table.attachAccelerator(object.id, .gpu);
    try std.testing.expectError(error.AcceleratorAlreadyAttached, table.mmuForTests().mapAccelerator(table.find(object.id).?, .gpu));
    try std.testing.expectEqual(@as(usize, 3), table.mmuForTests().mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 3), table.activeFreestandingMappings(object.id));
    const gpu_mapping = try table.freestandingAcceleratorMappingDescriptor(object.id, .gpu);
    try std.testing.expect(gpu_mapping.zero_copy);
    try std.testing.expectEqual(ComputeTarget.gpu, gpu_mapping.target.?);
    try std.testing.expectEqual(owner_mapping.physical_base, gpu_mapping.physical_base);
    try std.testing.expect(gpu_mapping.virtual_base >= userspace_layout.accelerator_start);
    try std.testing.expect(gpu_mapping.virtual_base < userspace_layout.accelerator_end_exclusive);
    try std.testing.expectEqual(@as(usize, 3), table.activeFreestandingMappings(object.id));

    const other_object = try table.create(ids.task(22), PAGE_SIZE);
    try table.map(other_object.id, ids.task(22));
    try std.testing.expectEqual(@as(usize, 4), table.mmuForTests().mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(other_object.id));
    _ = try table.revoke(object.id);
    try std.testing.expectEqual(@as(usize, 1), table.mmuForTests().mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(other_object.id));
    try std.testing.expectError(error.SharedMemoryNotFound, table.freestandingTaskMappingDescriptor(object.id, ids.task(20)));
    try std.testing.expectError(error.SharedMemoryNotFound, table.freestandingAcceleratorMappingDescriptor(object.id, .gpu));
}

test "compact mmu object lists unlink head middle and tail independently" {
    var table = Table.init();
    const object = try table.createLabeledWithAccess(ids.task(40), PAGE_SIZE, "compact-mmu-list", .{
        .gpu = true,
        .media = true,
    });
    const peer_object = try table.create(ids.task(50), PAGE_SIZE);

    try table.map(object.id, ids.task(40));
    try table.map(object.id, ids.task(41));
    try table.attachAccelerator(object.id, .gpu);
    try table.attachAccelerator(object.id, .media);
    try std.testing.expectError(error.AcceleratorAccessDenied, table.attachAccelerator(object.id, .cpu));
    try table.map(peer_object.id, ids.task(50));
    try std.testing.expectEqual(@as(usize, 4), table.activeFreestandingMappings(object.id));
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(peer_object.id));

    try std.testing.expect(try table.detachAccelerator(object.id, .gpu));
    try std.testing.expect(try table.unmap(object.id, ids.task(40)));
    try std.testing.expectEqual(@as(usize, 2), table.activeFreestandingMappings(object.id));
    _ = try table.freestandingTaskMappingDescriptor(object.id, ids.task(41));
    _ = try table.freestandingAcceleratorMappingDescriptor(object.id, .media);
    _ = try table.freestandingTaskMappingDescriptor(peer_object.id, ids.task(50));

    try std.testing.expect(try table.detachAccelerator(object.id, .media));
    try std.testing.expect(try table.unmap(object.id, ids.task(41)));
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(peer_object.id));
    try std.testing.expectEqual(@as(usize, 1), table.mmuForTests().mappings.countInUse());
}

test "compact mmu revoke preserves a peer that reused a freed mapping slot" {
    var table = Table.init();
    const object = try table.create(ids.task(60), PAGE_SIZE);
    const peer_object = try table.create(ids.task(70), PAGE_SIZE);

    try table.map(object.id, ids.task(61));
    try table.map(object.id, ids.task(62));
    const released_slot = table.mmuForTests().findIndex(table.find(object.id).?, .task, ids.task(61).raw()).?;
    try std.testing.expect(try table.unmap(object.id, ids.task(61)));

    try table.map(peer_object.id, ids.task(71));
    const reused_slot = table.mmuForTests().findIndex(table.find(peer_object.id).?, .task, ids.task(71).raw()).?;
    try std.testing.expectEqual(released_slot, reused_slot);
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(object.id));
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(peer_object.id));

    _ = try table.revoke(object.id);
    try std.testing.expectEqual(@as(usize, 1), table.mmuForTests().mappings.countInUse());
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(peer_object.id));
    const peer_mapping = try table.freestandingTaskMappingDescriptor(peer_object.id, ids.task(71));
    try std.testing.expectEqual(peer_object.id, peer_mapping.object_id);
}

test "freestanding mmu preserves duplicate mapping errors when full" {
    var table = Table.init();
    var object_ids = [_]ids.SharedMemoryId{ids.SharedMemoryId.zero} ** MAX_SHARED_MEMORY_OBJECTS;
    for (&object_ids, 0..) |*object_id, object_index| {
        const object = try table.create(ids.task(1_000 + object_index), PAGE_SIZE);
        object_id.* = object.id;
        const stored_object = table.find(object.id).?;
        for (0..MAX_MAPPINGS_PER_OBJECT) |mapping_index| {
            const task_id = ids.task(20_000 + object_index * MAX_MAPPINGS_PER_OBJECT + mapping_index);
            _ = try table.mmuForTests().mapTask(stored_object, task_id);
        }
        _ = try table.mmuForTests().mapAccelerator(stored_object, .gpu);
        _ = try table.mmuForTests().mapAccelerator(stored_object, .npu);
        _ = try table.mmuForTests().mapAccelerator(stored_object, .media);
    }

    const stored_object = table.find(object_ids[0]).?;
    try std.testing.expectEqual(MMU_MAPPING_CAPACITY, table.mmuForTests().mappings.countInUse());
    try std.testing.expectEqual(MMU_OBJECT_MAPPING_SCAN_BOUND, table.activeFreestandingMappings(object_ids[0]));
    try std.testing.expectError(error.AlreadyMapped, table.mmuForTests().mapTask(stored_object, ids.task(20_000)));
    try std.testing.expectError(error.AcceleratorAlreadyAttached, table.mmuForTests().mapAccelerator(stored_object, .gpu));
    try std.testing.expectError(error.TableFull, table.mmuForTests().mapTask(stored_object, ids.task(30_000)));
    try std.testing.expectEqual(MMU_MAPPING_CAPACITY, table.mmuForTests().mappings.countInUse());
    try std.testing.expectEqual(MMU_OBJECT_MAPPING_SCAN_BOUND, table.activeFreestandingMappings(object_ids[0]));

    for (object_ids) |object_id| _ = try table.revoke(object_id);
    try std.testing.expectEqual(@as(usize, 0), table.mmuForTests().mappings.countInUse());
    try std.testing.expectEqual(no_mmu_mapping, stored_object.mmu_mapping_head);
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
    try std.testing.expectEqual(@as(usize, 1), table.activeFreestandingMappings(object.id));
    try std.testing.expectError(error.AcceleratorNotAttached, table.validateAcceleratorMappingDescriptor(gpu_descriptor, .gpu));
    try std.testing.expectError(error.AcceleratorNotAttached, table.validateFreestandingAcceleratorMappingDescriptor(gpu_mmu_descriptor, .gpu));
    try std.testing.expectError(error.StaleMappingDescriptor, table.validateTaskMappingDescriptor(refreshed_task_descriptor));
    try std.testing.expectError(error.StaleMappingDescriptor, table.validateFreestandingTaskMappingDescriptor(refreshed_task_mmu_descriptor));

    const post_detach_task_descriptor = try table.taskMappingDescriptor(object.id, ids.task(30));
    _ = try table.revoke(object.id);
    try std.testing.expectError(error.SharedMemoryNotFound, table.validateTaskMappingDescriptor(post_detach_task_descriptor));
    try std.testing.expectError(error.SharedMemoryNotFound, table.validateAcceleratorMappingDescriptor(gpu_descriptor, .gpu));
    try std.testing.expectError(error.SharedMemoryNotFound, table.validateFreestandingTaskMappingDescriptor(refreshed_task_mmu_descriptor));
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
}
