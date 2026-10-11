const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const userspace_layout = @import("../core/userspace_layout.zig");
const table_backing = @import("../core/table_backing.zig");
const cpu_identity = @import("../../kernel/cpu_identity.zig");
const x86 = if (builtin.target.os.tag == .freestanding) @import("../../arch/x86.zig") else struct {};
const paging = if (builtin.target.os.tag == .freestanding)
    @import("root").kernel_paging
else
    struct {};

const heap_backed_table = builtin.target.os.tag == .freestanding;

pub const MAX_SHARED_MEMORY_OBJECTS: usize = 24;
pub const MAX_MAPPINGS_PER_OBJECT: usize = 8;
pub const PAGE_SIZE: usize = 4096;
pub const OBJECT_SIZE_CEILING_BYTES: usize = 128;
const SHARED_MEMORY_INDEX_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * 2;
pub const SHARED_MEMORY_PRIMARY_INDEX_LOOKUPS_PER_OPERATION: u8 = 0;
pub const SHARED_MEMORY_ID_COLLISION_PROBES_PER_INSERT: u8 = 0;
pub const OBJECT_TASK_MAPPING_SCAN_BOUND: usize = MAX_MAPPINGS_PER_OBJECT;
pub const MMU_OBJECT_MAPPING_SCAN_BOUND: usize = MAX_MAPPINGS_PER_OBJECT + 3;
pub const MMU_PRIMARY_INDEX_LOOKUPS_PER_OPERATION: u8 = 0;
pub const SEALS_IPC_RINGS = true;
pub const REGISTERS_DEMAND_PAGED_MAPPINGS = true;
// A nonzero token binds a registration to its original address-space lifetime.
// Failed registration must leave no region or hardware mapping behind.
pub const MappingLifetime = struct {
    context: *anyopaque,
    register: *const fn (*anyopaque, *Table, FreestandingMappingDescriptor, bool, bool) ?u64,
    unregister: *const fn (*anyopaque, *Table, u64, FreestandingMappingDescriptor) bool,

    pub inline fn eql(self: @This(), other: @This()) bool {
        return self.context == other.context and self.register == other.register and self.unregister == other.unregister;
    }
};

var mapped_object_lifetime: ?MappingLifetime = null;
var default_lifetime_registrations: u32 = 0;
const DefaultLifetimeTesting = if (builtin.is_test) struct {
    var registered_host_backend = false;
} else struct {};

pub fn bindMappedObjectLifetime(lifetime: MappingLifetime) bool {
    if (!defaultLifetimeOwner() or mapped_object_lifetime != null) return false;
    mapped_object_lifetime = lifetime;
    return true;
}

pub inline fn mappedObjectLifetimeIsBound(expected: MappingLifetime) bool {
    const lifetime = mapped_object_lifetime orelse return false;
    return lifetime.eql(expected);
}

// Tables retain this callback through every published token and through the
// registration callback itself. Its BSP-owned context must outlive them all.
pub fn unbindMappedObjectLifetime(expected: MappingLifetime) bool {
    if (!defaultLifetimeOwner() or default_lifetime_registrations != 0 or
        !mappedObjectLifetimeIsBound(expected)) return false;
    mapped_object_lifetime = null;
    return true;
}

inline fn defaultLifetimeOwner() bool {
    if (cpu_identity.currentIndex() != 0) return false;
    return if (comptime builtin.target.os.tag == .freestanding) !x86.interruptsEnabled() else true;
}
const MAPPING_EDGE_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * MAX_MAPPINGS_PER_OBJECT;
const MAPPING_INDEX_CAPACITY: usize = MAPPING_EDGE_CAPACITY * 2;
const MMU_MAPPING_CAPACITY: usize = MAX_SHARED_MEMORY_OBJECTS * MMU_OBJECT_MAPPING_SCAN_BOUND;
const no_mmu_mapping: u16 = std.math.maxInt(u16);
const ObjectMappingCount = u16;
const HOST_MODEL_PHYSICAL_BASE: u64 = 0x0010_0000;
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
    sealed: bool = false,
    ring: bool = false,
    _reserved: u2 = 0,

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
    mapping_count: ObjectMappingCount,
    mmu_mapping_head: u16 = no_mmu_mapping,
    mmu_mapping_count: u16 = 0,

    pub fn allowsCompute(self: *const Object, target: ComputeTarget) bool {
        return self.compute_access.allows(target);
    }

    pub fn attachedTo(self: *const Object, target: ComputeTarget) bool {
        return self.attached_compute.allows(target);
    }

    pub fn isSealed(self: *const Object) bool {
        return self.compute_access.sealed;
    }

    pub fn isRing(self: *const Object) bool {
        return self.compute_access.ring;
    }

    comptime {
        if (MAX_MAPPINGS_PER_OBJECT > std.math.maxInt(ObjectMappingCount)) {
            @compileError("shared-memory task mapping capacity exceeds its compact count");
        }
        if (@sizeOf(@This()) > OBJECT_SIZE_CEILING_BYTES) {
            @compileError("shared-memory object exceeds its compact size ceiling");
        }
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

// An immediate copy admission describes the complete logical mapping, not its
// rounded allocation. The caller must keep Table mutation serialized through
// preparation and copying; this value neither pins nor extends its lifetime.
pub const TaskCopySpan = struct {
    virtual_base: u64,
    physical_base: u64,
    size_bytes: usize,
};

pub const TaskRetirement = struct {
    revoked_owned_objects: u16 = 0,
    removed_peer_mappings: u16 = 0,
    revoked_object_ids: [MAX_SHARED_MEMORY_OBJECTS]ids.SharedMemoryId = @as([MAX_SHARED_MEMORY_OBJECTS]ids.SharedMemoryId, @splat(ids.SharedMemoryId.zero)),

    pub fn revokedObjectIds(self: *const TaskRetirement) []const ids.SharedMemoryId {
        return self.revoked_object_ids[0..self.revoked_owned_objects];
    }
};

pub const Error = error{
    AcceleratorAccessDenied,
    AcceleratorAlreadyAttached,
    AcceleratorNotAttached,
    AcceleratorStillAttached,
    AlreadyMapped,
    MappingDescriptorMismatch,
    MappingNotFound,
    MappingRegistrationFailed,
    OutOfMemory,
    SizeZero,
    StaleMappingDescriptor,
    TableFull,
    SharedMemoryNotFound,
    ObjectSealed,
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
    registration_token: u64 = 0,
    object_next: u16 = no_mmu_mapping,
    object_prev: u16 = no_mmu_mapping,
};

const MmuMappingArena = indexed_arena.GenerationalArena("MmuMapping", MmuMapping, MMU_MAPPING_CAPACITY);

// Hosted fixtures can supply actual frame ownership and bytes. Production has
// one allocator: paging's owned general-frame runs and their default-cache aliases.
pub const HostedPhysicalBacking = struct {
    context: *anyopaque,
    allocate: *const fn (*anyopaque, u32) ?u64,
    bytes: *const fn (*anyopaque, u64, u32) ?[]u8,
    release: *const fn (*anyopaque, u64, u32) void,
};

const NativePhysicalBacking = struct {
    fn allocate(_: @This(), count: u32) ?u64 {
        const run = paging.allocGeneralFrames(count) orelse return null;
        return run.base;
    }

    fn bytes(_: @This(), base: u64, count: u32) ?[]u8 {
        const byte_count = std.math.mul(usize, count, PAGE_SIZE) catch return null;
        const last = std.math.add(u64, base, byte_count - 1) catch return null;
        const alias = paging.directMapAddress(base) orelse return null;
        _ = paging.directMapAddress(last) orelse return null;
        return @as([*]u8, @ptrFromInt(alias))[0..byte_count];
    }

    fn release(_: @This(), base: u64, count: u32) void {
        paging.releaseGeneralFrames(.{ .base = base, .count = count }) catch |err|
            native_util.impossibleByInvariantError("shared-memory backing releases its owned frame run", err);
    }
};

const HostedBackingAdapter = struct {
    backend: HostedPhysicalBacking,

    fn allocate(self: @This(), count: u32) ?u64 {
        return self.backend.allocate(self.backend.context, count);
    }

    fn bytes(self: @This(), base: u64, count: u32) ?[]u8 {
        return self.backend.bytes(self.backend.context, base, count);
    }

    fn release(self: @This(), base: u64, count: u32) void {
        self.backend.release(self.backend.context, base, count);
    }
};

fn allocateZeroedFrames(backend: anytype, count: usize) Error!u64 {
    const frames = std.math.cast(u32, count) orelse return error.OutOfMemory;
    const byte_count = std.math.mul(usize, count, PAGE_SIZE) catch return error.OutOfMemory;
    const base = backend.allocate(frames) orelse return error.OutOfMemory;
    errdefer backend.release(base, frames);
    if (base % PAGE_SIZE != 0) return error.OutOfMemory;
    const bytes = backend.bytes(base, frames) orelse return error.OutOfMemory;
    if (bytes.len != byte_count) return error.OutOfMemory;
    @memset(bytes, 0);
    return base;
}

fn eraseAndReleaseFrames(backend: anytype, base: u64, count: usize) void {
    const frames: u32 = @intCast(count);
    const bytes = backend.bytes(base, frames) orelse
        native_util.impossibleByInvariant("owned shared-memory frames retain their direct access until release");
    if (bytes.len != count * PAGE_SIZE) {
        native_util.impossibleByInvariant("owned shared-memory direct access covers its complete frame run");
    }
    std.crypto.secureZero(u8, bytes);
    backend.release(base, frames);
}

pub const FreestandingMmu = struct {
    // This cursor describes hosted metadata fixtures only; never physical RAM.
    next_physical_frame: u64 = 1,
    hosted_physical_backing: if (heap_backed_table) void else ?HostedPhysicalBacking = if (heap_backed_table) {} else null,
    next_task_virtual_page: u64 = 1,
    next_accelerator_virtual_page: u64 = 1,
    mappings: MmuMappingArena = MmuMappingArena.init(),

    pub fn init() FreestandingMmu {
        return .{};
    }

    pub fn allocatePhysicalFrames(self: *FreestandingMmu, count: usize) Error!u64 {
        if (count == 0) return error.SizeZero;
        if (comptime heap_backed_table) return allocateZeroedFrames(NativePhysicalBacking{}, count);
        if (self.hosted_physical_backing) |backend| {
            return allocateZeroedFrames(HostedBackingAdapter{ .backend = backend }, count);
        }
        const base_frame = self.next_physical_frame;
        const next_frame = std.math.add(u64, base_frame, @intCast(count)) catch return error.TableFull;
        const frame_offset = std.math.mul(u64, base_frame, PAGE_SIZE) catch return error.TableFull;
        const physical_base = std.math.add(u64, HOST_MODEL_PHYSICAL_BASE, frame_offset) catch return error.TableFull;
        const end_offset = std.math.mul(u64, next_frame, PAGE_SIZE) catch return error.TableFull;
        _ = std.math.add(u64, HOST_MODEL_PHYSICAL_BASE, end_offset) catch return error.TableFull;
        self.next_physical_frame = next_frame;
        return physical_base;
    }

    fn releasePhysicalFrames(self: *FreestandingMmu, base: u64, count: usize) void {
        if (comptime heap_backed_table) {
            eraseAndReleaseFrames(NativePhysicalBacking{}, base, count);
            return;
        }
        if (self.hosted_physical_backing) |backend| {
            eraseAndReleaseFrames(HostedBackingAdapter{ .backend = backend }, base, count);
        }
    }

    fn usesHostedPhysicalModel(self: *const FreestandingMmu) bool {
        if (comptime heap_backed_table) return false;
        return self.hosted_physical_backing == null;
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
        self.removeResolvedMapping(object, slot_index);
        return true;
    }

    fn removeResolvedMapping(self: *FreestandingMmu, object: *Object, slot_index: usize) void {
        self.unlinkObjectMapping(object, slot_index);
        if (!self.mappings.removeIndex(slot_index)) {
            native_util.impossibleByInvariant("shared-memory MMU unmap removes a live linked mapping");
        }
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
    retired: bool = false,
    object: Object = zeroObject(),
};

pub const ObjectArena = indexed_arena.GenerationalArena("SharedMemoryId", ObjectSlot, MAX_SHARED_MEMORY_OBJECTS);
const ObjectHandle = ObjectArena.Handle;
pub const ObjectOwnerIndex = indexed_arena.MultimapIndex(MAX_SHARED_MEMORY_OBJECTS, MAX_SHARED_MEMORY_OBJECTS, SHARED_MEMORY_INDEX_CAPACITY);
const MappingIndex = indexed_arena.MultimapIndex(MAPPING_EDGE_CAPACITY, MAPPING_EDGE_CAPACITY, MAPPING_INDEX_CAPACITY);

const TableBacking = struct {
    mmu: FreestandingMmu = FreestandingMmu.init(),
    arena: ObjectArena = ObjectArena.init(),
    retired_count: u8 = 0,
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
    mapping_lifetime: ?MappingLifetime = null,
    uses_default_lifetime: bool = true,

    pub fn init() Table {
        return .{};
    }

    pub fn initWithMappingLifetime(lifetime: MappingLifetime) Table {
        return .{ .mapping_lifetime = lifetime, .uses_default_lifetime = false };
    }

    pub fn initWithHostedPhysicalBacking(backend: HostedPhysicalBacking, lifetime: ?MappingLifetime) Table {
        if (comptime heap_backed_table) @compileError("hosted physical fixtures cannot replace production frame ownership");
        var table = Table.init();
        table.backing.mmu.hosted_physical_backing = backend;
        if (lifetime) |registered| {
            table.mapping_lifetime = registered;
            table.uses_default_lifetime = false;
        }
        return table;
    }

    comptime {
        if (heap_backed_table and @sizeOf(@This()) > 64) {
            @compileError("heap-backed shared-memory tables exceed their compact resident layout");
        }
    }

    pub fn hasAcceleratorAttachments(self: *const Table) bool {
        const backing = self.backingConst() orelse return false;
        for (backing.arena.slots) |slot| {
            if (slot.in_use and hasAttachedAccelerators(&slot.object)) return true;
        }
        return false;
    }

    // Call before dropping any services that own this table. Revocation removes
    // CPU access, but only device completion/reset makes accelerator DMA quiet.
    pub fn requireQuiescent(self: *const Table) Error!void {
        if (self.hasAcceleratorAttachments()) return error.AcceleratorStillAttached;
    }

    pub fn tryDeinit(self: *Table) Error!void {
        try self.requireQuiescent();
        if (self.backingPtr()) |backing| {
            for (&backing.arena.slots) |*slot| {
                if (!slot.in_use) continue;
                _ = self.revoke(slot.object.id) catch |err|
                    native_util.impossibleByInvariantError("shared-memory table teardown revokes each live object", err);
            }
        }
        if (comptime heap_backed_table) {
            if (self.backing) |backing| {
                table_backing.free(TableBacking, backing);
                self.backing = null;
            }
        } else {
            self.backing = TableBacking.init();
        }
        self.mapping_lifetime = null;
        self.uses_default_lifetime = true;
    }

    pub fn deinit(self: *Table) void {
        self.tryDeinit() catch |err|
            native_util.impossibleByInvariantError("shared-memory table teardown requires completed accelerator claims", err);
    }

    fn registerDemandMapping(self: *Table, _: *const Object, mapping: FreestandingMappingDescriptor) Error!u64 {
        if (self.uses_default_lifetime) {
            // Hosted metadata tables have no hardware owner unless explicitly
            // supplied. A production mapping always needs its paired backend.
            if (comptime !heap_backed_table) {
                if (comptime !builtin.is_test) return 0;
                if (!DefaultLifetimeTesting.registered_host_backend) return 0;
            }
            const registered = mapped_object_lifetime orelse return error.MappingRegistrationFailed;
            if (self.mapping_lifetime) |prior| {
                if (!prior.eql(registered)) {
                    const backing = self.backingPtr() orelse return error.MappingRegistrationFailed;
                    for (backing.mmu.mappings.slots) |entry| {
                        if (entry.in_use and entry.registration_token != 0) return error.MappingRegistrationFailed;
                    }
                }
            }
            self.mapping_lifetime = registered;
            if (default_lifetime_registrations == std.math.maxInt(u32)) return error.MappingRegistrationFailed;
            // Reserve callback lifetime before entering a trusted adapter: a
            // reentrant compare-unbind must not drop its own live context.
            default_lifetime_registrations += 1;
        }
        errdefer if (self.uses_default_lifetime) {
            default_lifetime_registrations -= 1;
        };
        const lifetime = self.mapping_lifetime orelse return error.MappingRegistrationFailed;
        const token = lifetime.register(lifetime.context, self, mapping, true, false) orelse
            return error.MappingRegistrationFailed;
        if (token == 0) native_util.impossibleByInvariant("successful shared-memory registration supplies a nonzero lifetime token");
        return token;
    }

    fn unregisterDemandMapping(self: *Table, object: *const Object, mapping: *MmuMapping) void {
        if (mapping.registration_token == 0) return;
        const lifetime = self.mapping_lifetime orelse
            native_util.impossibleByInvariant("registered shared-memory mapping retains its paired lifetime backend");
        if (!lifetime.unregister(lifetime.context, self, mapping.registration_token, descriptorFromMmuMapping(object, mapping))) {
            native_util.impossibleByInvariant("shared-memory teardown removes access before recycling its mapping");
        }
        mapping.registration_token = 0;
        if (self.uses_default_lifetime) {
            std.debug.assert(default_lifetime_registrations != 0);
            default_lifetime_registrations -= 1;
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
            const backing = table_backing.alloc(TableBacking) orelse return error.OutOfMemory;
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
                .mapped_task_ids = @as([MAX_MAPPINGS_PER_OBJECT]ids.TaskId, @splat(ids.TaskId.zero)),
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

    pub fn createSealedRing(
        self: *Table,
        owner_task_id: ids.TaskId,
        peer_task_id: ids.TaskId,
        size_bytes: usize,
    ) Error!Object {
        const object = try self.createLabeledWithAccess(owner_task_id, size_bytes, "ipc-ring", .{
            .cpu = true,
            .ring = true,
        });
        errdefer _ = self.revoke(object.id) catch {};
        try self.map(object.id, owner_task_id);
        if (!peer_task_id.eql(owner_task_id)) {
            try self.map(object.id, peer_task_id);
        }
        try self.seal(object.id);
        return self.findConst(object.id).?.*;
    }

    pub fn seal(self: *Table, object_id: ids.SharedMemoryId) Error!void {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        object.compute_access.sealed = true;
    }

    pub fn map(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!void {
        const backing = self.backingPtr() orelse return error.SharedMemoryNotFound;
        const object_handle = ObjectHandle{ .value = object_id.raw() };
        const object_slot = backing.arena.getByHandle(object_handle) orelse return error.SharedMemoryNotFound;
        if (object_slot.retired) return error.SharedMemoryNotFound;
        const object_slot_index = object_handle.slotIndex();
        const object = &object_slot.object;
        if (object.isSealed()) return error.ObjectSealed;

        if (objectTaskMappingPosition(object, task_id) != null) return error.AlreadyMapped;
        if (object.mapping_count >= object.mapped_task_ids.len) return error.TableFull;

        const edge_index = mappingEdgeIndex(object_slot_index, object.mapping_count);
        if (!backing.mapping_index.append(task_id.raw(), edge_index)) return error.TableFull;
        errdefer if (!backing.mapping_index.remove(task_id.raw(), edge_index)) {
            native_util.impossibleByInvariant("failed shared-memory map releases its reserved task index edge");
        };
        const previous_virtual_page = backing.mmu.next_task_virtual_page;
        const mapping_descriptor = try backing.mmu.mapTask(object, task_id);
        errdefer {
            if (!(backing.mmu.unmapTask(object, task_id) catch false)) {
                native_util.impossibleByInvariant("failed shared-memory map releases its reserved MMU mapping");
            }
            backing.mmu.next_task_virtual_page = previous_virtual_page;
        }
        const mapping_index = backing.mmu.findIndex(object, .task, task_id.raw()) orelse
            native_util.impossibleByInvariant("reserved shared-memory mapping remains linked until publication");
        backing.mmu.mappings.slots[mapping_index].registration_token = try self.registerDemandMapping(object, mapping_descriptor);
        object.mapped_task_ids[object.mapping_count] = task_id;
        object.mapping_count += 1;
    }

    pub fn unmap(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId) Error!bool {
        return self.unmapInternal(object_id, task_id, false);
    }

    fn unmapInternal(self: *Table, object_id: ids.SharedMemoryId, task_id: ids.TaskId, allow_sealed: bool) Error!bool {
        const backing = self.backingPtr() orelse return error.SharedMemoryNotFound;
        const object_handle = ObjectHandle{ .value = object_id.raw() };
        const object_slot = backing.arena.getByHandle(object_handle) orelse return error.SharedMemoryNotFound;
        if (object_slot.retired) return error.SharedMemoryNotFound;
        const object_slot_index = object_handle.slotIndex();
        const object = &object_slot.object;
        if (object.isSealed() and !allow_sealed) return error.ObjectSealed;
        const index = objectTaskMappingPosition(object, task_id) orelse return false;
        const edge_index = mappingEdgeIndex(object_slot_index, index);

        const mmu_index = backing.mmu.findIndex(object, .task, task_id.raw()) orelse
            native_util.impossibleByInvariant("published shared-memory task mapping retains its MMU registration");
        self.unregisterDemandMapping(object, &backing.mmu.mappings.slots[mmu_index]);

        if (!backing.mapping_index.remove(task_id.raw(), edge_index)) {
            native_util.impossibleByInvariant("shared-memory unmap removes its published task index edge");
        }
        // Task mapping order is internal. Fill the hole from the tail so only
        // one survivor changes its task index edge, independent of position.
        const last_index = object.mapping_count - 1;
        if (index != last_index) {
            const moved_task_id = object.mapped_task_ids[last_index];
            const old_edge_index = mappingEdgeIndex(object_slot_index, last_index);
            if (!backing.mapping_index.remove(moved_task_id.raw(), old_edge_index)) {
                native_util.impossibleByInvariant("shared-memory unmap relocates a published task index edge");
            }
            if (!backing.mapping_index.append(moved_task_id.raw(), edge_index)) {
                native_util.impossibleByInvariant("shared-memory unmap reuses the released task index edge");
            }
            object.mapped_task_ids[index] = moved_task_id;
        }
        object.mapping_count = last_index;
        object.mapped_task_ids[last_index] = ids.TaskId.zero;
        backing.mmu.removeResolvedMapping(object, mmu_index);
        return true;
    }

    pub fn revoke(self: *Table, object_id: ids.SharedMemoryId) Error!abi.SharedMemoryDescriptor {
        const backing = self.backingPtr() orelse return error.SharedMemoryNotFound;
        const object_handle = ObjectHandle{ .value = object_id.raw() };
        const object_slot = backing.arena.getByHandle(object_handle) orelse return error.SharedMemoryNotFound;
        if (object_slot.retired) return error.SharedMemoryNotFound;
        const object_slot_index = object_handle.slotIndex();
        const object = &object_slot.object;
        var mmu_index = object.mmu_mapping_head;
        var visited: usize = 0;
        while (mmu_index != no_mmu_mapping) : (visited += 1) {
            if (visited >= object.mmu_mapping_count or mmu_index >= backing.mmu.mappings.slots.len) {
                native_util.impossibleByInvariant("shared-memory revoke traverses its bounded MMU mapping list");
            }
            const mapping = &backing.mmu.mappings.slots[mmu_index];
            if (!mapping.in_use or !mapping.object_id.eql(object.id)) {
                native_util.impossibleByInvariant("shared-memory revoke tears down only its owned live MMU mappings");
            }
            if (mapping.kind == .task) self.unregisterDemandMapping(object, mapping);
            mmu_index = mapping.object_next;
        }
        if (visited != object.mmu_mapping_count) {
            native_util.impossibleByInvariant("shared-memory revoke tears down every linked MMU mapping");
        }
        _ = backing.object_owner_index.remove(object.owner_task_id.raw(), object_slot_index);
        for (object.mapped_task_ids[0..object.mapping_count], 0..) |task_id, mapping_index| {
            _ = backing.mapping_index.remove(task_id.raw(), mappingEdgeIndex(object_slot_index, mapping_index));
        }
        backing.mmu.revokeObject(object);
        object.revocation_generation += 1;
        object.attachment_generation += 1;
        object.mapping_count = 0;
        object.mapped_task_ids = @as([MAX_MAPPINGS_PER_OBJECT]ids.TaskId, @splat(ids.TaskId.zero));
        const revoked_descriptor = descriptorForObject(object, true);
        if (hasAttachedAccelerators(object)) {
            // Retain the original generational slot as a pin. Only a completed
            // accelerator claim can release it through detachAccelerator.
            object_slot.retired = true;
            backing.retired_count += 1;
        } else {
            self.releaseObjectSlot(object_handle);
        }
        return revoked_descriptor;
    }

    fn releaseObjectSlot(self: *Table, handle: ObjectHandle) void {
        const backing = self.backingPtr().?;
        const slot = backing.arena.getByHandle(handle) orelse
            native_util.impossibleByInvariant("shared-memory release retains its owned object slot");
        std.debug.assert(slot.object.mapping_count == 0 and slot.object.mmu_mapping_count == 0);
        std.debug.assert(!hasAttachedAccelerators(&slot.object));
        backing.mmu.releasePhysicalFrames(slot.object.page_base, slot.object.page_count);
        if (slot.retired) backing.retired_count -= 1;
        if (!backing.arena.removeHandle(handle)) {
            native_util.impossibleByInvariant("shared-memory release removes its exact owned generational slot");
        }
        if (backing.arena.countInUse() == 0 and backing.mmu.mappings.countInUse() == 0) {
            backing.mmu.next_physical_frame = 1;
            backing.mmu.next_task_virtual_page = 1;
            backing.mmu.next_accelerator_virtual_page = 1;
        }
    }

    // Creation rollback precedes publication and releases only this run. The
    // arithmetic tail rewind belongs exclusively to hosted metadata fixtures.
    pub fn rollbackCreate(self: *Table, object_id: ids.SharedMemoryId) void {
        const backing = self.backingPtr() orelse
            native_util.impossibleByInvariant("unpublished shared memory retains its backing");
        const slot = backing.arena.getByHandle(ObjectHandle{ .value = object_id.raw() }) orelse
            native_util.impossibleByInvariant("unpublished shared memory retains its live handle");
        const object = &slot.object;
        if (slot.retired or object.mapping_count != 0 or object.mmu_mapping_count != 0 or hasAttachedAccelerators(object)) {
            native_util.impossibleByInvariant("unpublished shared memory is unmapped and unpinned");
        }
        const model = backing.mmu.usesHostedPhysicalModel();
        const frame_start = if (model) (object.page_base - HOST_MODEL_PHYSICAL_BASE) / PAGE_SIZE else 0;
        if (model and backing.mmu.next_physical_frame != frame_start + object.page_count) {
            native_util.impossibleByInvariant("unpublished hosted shared memory owns the model allocator tail");
        }
        _ = self.revoke(object_id) catch |err|
            native_util.impossibleByInvariantError("shared-memory rollback revokes its live object", err);
        if (model) backing.mmu.next_physical_frame = frame_start;
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
            const removed = self.unmapInternal(slot.object.id, task_id, true) catch |err|
                native_util.impossibleByInvariantError("task retirement unmaps an indexed shared-memory mapping", err);
            if (!removed) {
                native_util.impossibleByInvariant("task retirement removes every indexed shared-memory mapping");
            }
            retired.removed_peer_mappings += 1;
        }
        return retired;
    }

    // Arena handles are local to an Executor. Retire only this exact task's
    // opaque lifetime token, never another arena's numerically equal handle.
    pub fn retireTaskMappingLifetime(self: *Table, task_id: ids.TaskId, registration_token: u64) void {
        if (task_id.eql(ids.TaskId.zero) or registration_token == 0) return;
        const backing = self.backingPtr() orelse return;
        var edge_index = backing.mapping_index.head(task_id.raw());
        var visited: usize = 0;
        while (edge_index != indexed_arena.no_index) {
            if (visited >= MAX_SHARED_MEMORY_OBJECTS or edge_index >= MAPPING_EDGE_CAPACITY) {
                native_util.impossibleByInvariant("address-space retirement traverses its bounded task mapping index");
            }
            visited += 1;
            const next_edge = backing.mapping_index.next(edge_index);
            const slot = &backing.arena.slots[mappingEdgeObjectSlotIndex(edge_index)];
            const position = mappingEdgeMappingIndex(edge_index);
            if (!slot.in_use or slot.retired or position >= slot.object.mapping_count or
                !slot.object.mapped_task_ids[position].eql(task_id))
                native_util.impossibleByInvariant("address-space retirement retains its exact published task mapping");
            const mapping_index = backing.mmu.findIndex(&slot.object, .task, task_id.raw()) orelse
                native_util.impossibleByInvariant("published shared-memory task mapping retains its MMU registration");
            if (backing.mmu.mappings.slots[mapping_index].registration_token == registration_token) {
                if (!(self.unmapInternal(slot.object.id, task_id, true) catch |err|
                    native_util.impossibleByInvariantError("address-space retirement unmaps its shared-memory registration", err)))
                    native_util.impossibleByInvariant("address-space retirement removes every matching shared-memory registration");
            }
            edge_index = next_edge;
        }
    }

    pub fn attachAccelerator(self: *Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!void {
        const object = self.find(object_id) orelse return error.SharedMemoryNotFound;
        if (object.isSealed()) return error.ObjectSealed;
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

    // Unlike public lookup, release authenticates the retained original ID.
    // Sealing freezes new topology; it cannot prevent completed DMA cleanup.
    pub fn validateAcceleratorRelease(self: *const Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!void {
        if (target == .cpu) return error.AcceleratorAccessDenied;
        const backing = self.backingConst() orelse return error.SharedMemoryNotFound;
        const slot = backing.arena.getConstByHandle(ObjectHandle{ .value = object_id.raw() }) orelse return error.SharedMemoryNotFound;
        if (!slot.object.attachedTo(target)) return error.AcceleratorNotAttached;
    }

    // The caller must establish device completion or reset before detaching;
    // removing metadata alone never establishes DMA quiescence.
    pub fn detachAccelerator(self: *Table, object_id: ids.SharedMemoryId, target: ComputeTarget) Error!bool {
        try self.validateAcceleratorRelease(object_id, target);
        const backing = self.backingPtr().?;
        const handle = ObjectHandle{ .value = object_id.raw() };
        const slot = backing.arena.getByHandle(handle).?;
        const object = &slot.object;
        if (!slot.retired) {
            if (!(try backing.mmu.unmapAccelerator(object, target))) {
                native_util.impossibleByInvariant("live accelerator attachment retains its MMU metadata");
            }
        }
        setComputeAccess(&object.attached_compute, target, false);
        object.attachment_generation += 1;
        if (slot.retired and !hasAttachedAccelerators(object)) self.releaseObjectSlot(handle);
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

    pub fn taskCopySpanInto(
        self: *const Table,
        task_id: ids.TaskId,
        registration_token: u64,
        start: u64,
        len: usize,
        out: *TaskCopySpan,
    ) Error!void {
        if (len == 0) return error.SizeZero;
        if (registration_token == 0) return error.MappingRegistrationFailed;
        if (task_id.eql(ids.TaskId.zero)) return error.MappingNotFound;
        const end = std.math.add(u64, start, len) catch return error.MappingDescriptorMismatch;
        const backing = self.backingConst() orelse return error.MappingNotFound;
        var edge_index = backing.mapping_index.head(task_id.raw());
        var visited: usize = 0;
        while (edge_index != indexed_arena.no_index) : (edge_index = backing.mapping_index.next(edge_index)) {
            if (visited >= MAX_SHARED_MEMORY_OBJECTS or edge_index >= MAPPING_EDGE_CAPACITY) {
                return error.MappingDescriptorMismatch;
            }
            visited += 1;
            const object_slot_index = mappingEdgeObjectSlotIndex(edge_index);
            const position = mappingEdgeMappingIndex(edge_index);
            const slot = &backing.arena.slots[object_slot_index];
            // map reserves its task-index edge before invoking registration.
            // It becomes authority only after publishing task membership.
            if (!slot.in_use or slot.retired or position >= slot.object.mapping_count or
                !slot.object.mapped_task_ids[position].eql(task_id)) continue;
            const object = &slot.object;
            if (backing.arena.getConstByHandle(.{ .value = object.id.raw() }) != slot) {
                return error.StaleMappingDescriptor;
            }
            const mapping = backing.mmu.findAny(object, .task, task_id.raw()) orelse return error.MappingNotFound;
            const logical_end = std.math.add(u64, mapping.virtual_base, object.size_bytes) catch
                return error.MappingDescriptorMismatch;
            if (start < mapping.virtual_base or start >= logical_end) continue;
            if (end > logical_end) return error.MappingDescriptorMismatch;
            if (mapping.registration_token != registration_token) return error.StaleMappingDescriptor;
            const mapped_bytes = std.math.mul(u64, object.page_count, PAGE_SIZE) catch
                return error.MappingDescriptorMismatch;
            if (object.size_bytes == 0 or object.size_bytes > mapped_bytes or
                mapping.virtual_base < TASK_SHARED_VIRTUAL_BASE or
                mapping.virtual_base % PAGE_SIZE != 0 or object.page_base % PAGE_SIZE != 0)
            {
                return error.MappingDescriptorMismatch;
            }
            const mapped_end = std.math.add(u64, mapping.virtual_base, mapped_bytes) catch
                return error.MappingDescriptorMismatch;
            if (mapped_end > TASK_SHARED_VIRTUAL_END_EXCLUSIVE) return error.MappingDescriptorMismatch;
            _ = std.math.add(u64, object.page_base, mapped_bytes) catch return error.MappingDescriptorMismatch;
            out.* = .{
                .virtual_base = mapping.virtual_base,
                .physical_base = object.page_base,
                .size_bytes = object.size_bytes,
            };
            return;
        }
        return error.MappingNotFound;
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
        return backing.arena.countInUse() - backing.retired_count;
    }

    fn find(self: *Table, object_id: ids.SharedMemoryId) ?*Object {
        const backing = self.backingPtr() orelse return null;
        const slot = backing.arena.getByHandle(ObjectHandle{ .value = object_id.raw() }) orelse return null;
        if (slot.retired) return null;
        return &slot.object;
    }

    fn findConst(self: *const Table, object_id: ids.SharedMemoryId) ?*const Object {
        const backing = self.backingConst() orelse return null;
        const slot = backing.arena.getConstByHandle(ObjectHandle{ .value = object_id.raw() }) orelse return null;
        if (slot.retired) return null;
        return &slot.object;
    }
};

fn hasAttachedAccelerators(object: *const Object) bool {
    return object.attached_compute.gpu or object.attached_compute.npu or object.attached_compute.media;
}

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
        .mapped_task_ids = @as([MAX_MAPPINGS_PER_OBJECT]ids.TaskId, @splat(ids.TaskId.zero)),
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
    return size_bytes / PAGE_SIZE + @intFromBool(size_bytes % PAGE_SIZE != 0);
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
    return @as(u64, @backingInt(target)) + 1;
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

test "shared memory objects keep bounded mapping counts compact" {
    try std.testing.expectEqual(OBJECT_SIZE_CEILING_BYTES, @sizeOf(Object));
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

test "unpublished shared memory rollback restores frame reservation and invalidates its handle" {
    var table = Table.init();
    const owner = ids.task(10);
    const existing = try table.create(owner, PAGE_SIZE);
    const frame_cursor = table.mmuForTests().next_physical_frame;
    var previous_id = ids.SharedMemoryId.zero;
    for (0..MAX_SHARED_MEMORY_OBJECTS * 2) |_| {
        const unpublished = try table.create(owner, 2 * PAGE_SIZE);
        try std.testing.expect(!unpublished.id.eql(previous_id));
        table.rollbackCreate(unpublished.id);
        previous_id = unpublished.id;
        try std.testing.expectEqual(frame_cursor, table.mmuForTests().next_physical_frame);
        try std.testing.expectEqual(@as(usize, 1), table.activeCount());
        try std.testing.expectEqual(PAGE_SIZE, table.liveOwnedBytesForTask(owner));
        try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(unpublished.id));
        _ = try table.descriptor(existing.id);
    }
    const next = try table.create(owner, PAGE_SIZE);
    try std.testing.expectEqual(existing.page_base + PAGE_SIZE, next.page_base);
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
    try std.testing.expectError(error.AcceleratorStillAttached, table.requireQuiescent());
    try std.testing.expect(try table.detachAccelerator(object.id, .gpu));

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

test "shared memory removes first middle and last mappings without disturbing survivors" {
    inline for (.{ 0, MAX_MAPPINGS_PER_OBJECT / 2, MAX_MAPPINGS_PER_OBJECT - 1 }) |removed_index| {
        var table = Table.init();
        defer table.deinit();
        const object = try table.createWithAccess(ids.task(1), PAGE_SIZE, .{ .gpu = true, .npu = true, .media = true });
        const peer = try table.create(ids.task(2), PAGE_SIZE * 2);
        var descriptors: [MAX_MAPPINGS_PER_OBJECT]FreestandingMappingDescriptor = undefined;
        for (0..MAX_MAPPINGS_PER_OBJECT) |index| {
            const task_id = ids.task(100 + index);
            try table.map(object.id, task_id);
            try table.map(peer.id, task_id);
        }
        inline for (.{ ComputeTarget.gpu, ComputeTarget.npu, ComputeTarget.media }) |target| {
            try table.attachAccelerator(object.id, target);
        }
        for (&descriptors, 0..) |*descriptor, index| {
            descriptor.* = try table.freestandingTaskMappingDescriptor(object.id, ids.task(100 + index));
        }

        const removed_task = ids.task(100 + removed_index);
        try std.testing.expect(try table.unmap(object.id, removed_task));
        try std.testing.expect(!try table.unmap(object.id, removed_task));
        try std.testing.expectEqual(@as(u16, 1), table.mappingsForTask(removed_task));
        try std.testing.expectEqual(PAGE_SIZE * 2, table.liveMappedBytesForTask(removed_task));
        try std.testing.expectError(error.MappingNotFound, table.freestandingTaskMappingDescriptor(object.id, removed_task));
        try std.testing.expectEqual(MMU_OBJECT_MAPPING_SCAN_BOUND - 1, table.activeFreestandingMappings(object.id));

        const stored = table.find(object.id).?;
        const object_slot_index = (ObjectHandle{ .value = object.id.raw() }).slotIndex();
        try std.testing.expect(stored.mapped_task_ids[MAX_MAPPINGS_PER_OBJECT - 1].isZero());
        for (stored.mapped_task_ids[0..stored.mapping_count], 0..) |task_id, index| {
            const original_index = task_id.raw() - 100;
            const expected_index = if (index == removed_index) MAX_MAPPINGS_PER_OBJECT - 1 else index;
            try std.testing.expectEqual(expected_index, original_index);
            try std.testing.expectEqualDeep(descriptors[original_index], try table.freestandingTaskMappingDescriptor(object.id, task_id));
            try std.testing.expectEqual(@as(u16, 2), table.mappingsForTask(task_id));
            try std.testing.expectEqual(PAGE_SIZE * 3, table.liveMappedBytesForTask(task_id));
            const expected_edge = mappingEdgeIndex(object_slot_index, index);
            const mapping_index = &table.backingPtr().?.mapping_index;
            try std.testing.expectEqual(task_id.raw(), mapping_index.buckets[mapping_index.bucketIndexForSlot(expected_edge).?].key);
        }
        try std.testing.expect(table.backingPtr().?.mapping_index.bucketIndexForSlot(mappingEdgeIndex(object_slot_index, MAX_MAPPINGS_PER_OBJECT - 1)) == null);

        // Retire the survivor relocated into the hole, then revoke the object.
        // Both paths must follow its updated edge and preserve the peer object.
        const retired_task = ids.task(100 + if (removed_index == MAX_MAPPINGS_PER_OBJECT - 1) @as(usize, 0) else MAX_MAPPINGS_PER_OBJECT - 1);
        const retired = table.retireTask(retired_task);
        try std.testing.expectEqual(@as(u16, 2), retired.removed_peer_mappings);
        try std.testing.expectEqual(@as(u16, 0), retired.revoked_owned_objects);
        try std.testing.expectEqual(@as(u16, 0), table.mappingsForTask(retired_task));
        try std.testing.expect(!table.hasMapping(object.id, retired_task));
        try std.testing.expect(!table.hasMapping(peer.id, retired_task));
        _ = try table.revoke(object.id);
        inline for (.{ ComputeTarget.gpu, ComputeTarget.npu, ComputeTarget.media }) |target| {
            try std.testing.expect(try table.detachAccelerator(object.id, target));
        }
        try std.testing.expectEqual(MAX_MAPPINGS_PER_OBJECT - 1, table.activeFreestandingMappings(peer.id));
        for (0..MAX_MAPPINGS_PER_OBJECT) |index| {
            const task_id = ids.task(100 + index);
            if (task_id.eql(retired_task)) continue;
            try std.testing.expect(table.hasMapping(peer.id, task_id));
            try std.testing.expectEqual(@as(u16, 1), table.mappingsForTask(task_id));
            try std.testing.expectEqual(PAGE_SIZE * 2, table.liveMappedBytesForTask(task_id));
        }
    }
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

test "shared memory exhaustion retires object slots before allocating frames" {
    var table = Table.init();
    defer table.deinit();
    const backing = try table.ensureBacking();
    backing.arena.slot_generations[0] = indexed_arena.MAX_HANDLE_GENERATION;
    const last = try table.create(ids.task(7), PAGE_SIZE);
    _ = try table.revoke(last.id);
    const next = try table.create(ids.task(8), PAGE_SIZE);
    try std.testing.expectEqual(@as(usize, 1), (ObjectHandle{ .value = next.id.raw() }).slotIndex());
    try std.testing.expectError(error.SharedMemoryNotFound, table.map(last.id, ids.task(8)));
    _ = try table.revoke(next.id);
    @memset(&backing.arena.slot_generations, indexed_arena.EXHAUSTED_HANDLE_GENERATION);
    const next_frame = table.mmuForTests().next_physical_frame;
    try std.testing.expectError(error.TableFull, table.create(ids.task(9), PAGE_SIZE));
    try std.testing.expectEqual(next_frame, table.mmuForTests().next_physical_frame);
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
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

test "shared memory page rounding handles the complete size domain" {
    const maximum = std.math.maxInt(usize);
    for ([_]usize{ 0, 1, PAGE_SIZE - 1, PAGE_SIZE, PAGE_SIZE + 1, maximum - PAGE_SIZE, maximum - 1, maximum }) |size| {
        const expected: usize = @intCast((@as(u128, size) + PAGE_SIZE - 1) / PAGE_SIZE);
        try std.testing.expectEqual(expected, pageCount(size));
    }
}

test "shared memory physical reservation validates its complete extent before advancing" {
    const maximum = std.math.maxInt(u64);
    const last_end_frame = (maximum - HOST_MODEL_PHYSICAL_BASE) / PAGE_SIZE;
    var mmu = FreestandingMmu.init();
    try std.testing.expectError(error.SizeZero, mmu.allocatePhysicalFrames(0));
    try std.testing.expectEqual(@as(u64, 1), mmu.next_physical_frame);
    try std.testing.expectError(error.TableFull, mmu.allocatePhysicalFrames(std.math.maxInt(usize)));
    try std.testing.expectEqual(@as(u64, 1), mmu.next_physical_frame);

    mmu.next_physical_frame = last_end_frame;
    try std.testing.expectError(error.TableFull, mmu.allocatePhysicalFrames(1));
    try std.testing.expectEqual(last_end_frame, mmu.next_physical_frame);
    mmu.next_physical_frame = maximum / PAGE_SIZE;
    try std.testing.expectError(error.TableFull, mmu.allocatePhysicalFrames(1));
    try std.testing.expectEqual(maximum / PAGE_SIZE, mmu.next_physical_frame);

    mmu.next_physical_frame = last_end_frame - 1;
    const last_base = try mmu.allocatePhysicalFrames(1);
    try std.testing.expectEqual(HOST_MODEL_PHYSICAL_BASE + (last_end_frame - 1) * PAGE_SIZE, last_base);
    try std.testing.expectEqual(last_end_frame, mmu.next_physical_frame);
    try std.testing.expectError(error.TableFull, mmu.allocatePhysicalFrames(1));
    try std.testing.expectEqual(last_end_frame, mmu.next_physical_frame);
}

test "shared memory oversized creation leaves live objects and reusable capacity intact" {
    var table = Table.init();
    defer table.deinit();
    const owner = ids.task(7);
    const existing = try table.create(owner, PAGE_SIZE);
    try table.map(existing.id, owner);
    const mapping = try table.freestandingTaskMappingDescriptor(existing.id, owner);
    const next_frame = table.mmuForTests().next_physical_frame;
    for ([_]usize{ std.math.maxInt(usize), std.math.maxInt(usize) - PAGE_SIZE + 1 }) |size| {
        try std.testing.expectError(error.TableFull, table.create(owner, size));
        try std.testing.expectEqual(next_frame, table.mmuForTests().next_physical_frame);
        try std.testing.expectEqual(@as(usize, 1), table.activeCount());
        try std.testing.expectEqual(@as(usize, PAGE_SIZE), table.liveOwnedBytesForTask(owner));
        try std.testing.expectEqualDeep(mapping, try table.freestandingTaskMappingDescriptor(existing.id, owner));
    }
    for (1..MAX_SHARED_MEMORY_OBJECTS) |_| _ = try table.create(owner, PAGE_SIZE);
    try std.testing.expectEqual(MAX_SHARED_MEMORY_OBJECTS, table.activeCount());
    try std.testing.expectEqual(@as(usize, MAX_SHARED_MEMORY_OBJECTS * PAGE_SIZE), table.liveOwnedBytesForTask(owner));
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
    var object_ids = @as([MAX_SHARED_MEMORY_OBJECTS]ids.SharedMemoryId, @splat(ids.SharedMemoryId.zero));
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

test "sealed ipc rings map owner and peer then reject remap" {
    var table = Table.init();
    const owner = ids.task(11);
    const peer = ids.task(12);
    const object = try table.createSealedRing(owner, peer, PAGE_SIZE);

    try std.testing.expect(object.isRing());
    try std.testing.expect(object.isSealed());
    try std.testing.expect(table.find(object.id).?.isSealed());
    try std.testing.expect(table.hasMapping(object.id, owner));
    try std.testing.expect(table.hasMapping(object.id, peer));
    try std.testing.expectError(error.ObjectSealed, table.map(object.id, ids.task(13)));
    try std.testing.expectError(error.ObjectSealed, table.unmap(object.id, peer));
    try std.testing.expectError(error.ObjectSealed, table.attachAccelerator(object.id, .gpu));

    const retired = table.retireTask(peer);
    try std.testing.expectEqual(@as(u16, 0), retired.revoked_owned_objects);
    try std.testing.expectEqual(@as(u16, 1), retired.removed_peer_mappings);
    try std.testing.expect(!table.hasMapping(object.id, peer));
    try std.testing.expect(table.find(object.id).?.isSealed());

    const descriptor = try table.revoke(object.id);
    try std.testing.expectEqual(@as(u16, 0), descriptor.mapped_task_count);
    try std.testing.expectError(error.SharedMemoryNotFound, table.descriptor(object.id));
}

test "shared default mapping lifetime binds one BSP owner and retains callbacks through publication" {
    const Context = struct {
        fail_register: bool = false,
        registrations: usize = 0,
        unregistrations: usize = 0,
        refused_register_unbind: usize = 0,
        refused_unregister_unbind: usize = 0,

        fn lifetime(self: *@This()) MappingLifetime {
            return .{ .context = self, .register = register, .unregister = unregister };
        }

        fn register(context: *anyopaque, _: *Table, _: FreestandingMappingDescriptor, _: bool, _: bool) ?u64 {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (mappedObjectLifetimeIsBound(self.lifetime()) and !unbindMappedObjectLifetime(self.lifetime()))
                self.refused_register_unbind += 1;
            if (self.fail_register) return null;
            self.registrations += 1;
            return 0x0000_0001_0000_0001;
        }

        fn unregister(context: *anyopaque, table: *Table, _: u64, mapping: FreestandingMappingDescriptor) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!table.hasMapping(mapping.object_id, mapping.task_id)) return false;
            if (mappedObjectLifetimeIsBound(self.lifetime()) and !unbindMappedObjectLifetime(self.lifetime()))
                self.refused_unregister_unbind += 1;
            self.unregistrations += 1;
            return true;
        }
    };
    const prior_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(prior_cpu);
    try std.testing.expect(mapped_object_lifetime == null);
    try std.testing.expectEqual(@as(u32, 0), default_lifetime_registrations);
    const prior_policy = DefaultLifetimeTesting.registered_host_backend;
    DefaultLifetimeTesting.registered_host_backend = true;
    defer DefaultLifetimeTesting.registered_host_backend = prior_policy;
    var context = Context{ .fail_register = true };
    var other = Context{};
    for (1..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expect(!bindMappedObjectLifetime(context.lifetime()));
    }
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(bindMappedObjectLifetime(context.lifetime()));
    defer std.debug.assert(unbindMappedObjectLifetime(context.lifetime()));
    try std.testing.expect(!bindMappedObjectLifetime(context.lifetime()));
    try std.testing.expect(!bindMappedObjectLifetime(other.lifetime()));
    try std.testing.expect(!unbindMappedObjectLifetime(other.lifetime()));
    var first = Table.init();
    defer first.deinit();
    var second = Table.init();
    defer second.deinit();
    const first_object = try first.create(ids.task(801), PAGE_SIZE);
    const second_object = try second.create(ids.task(802), PAGE_SIZE);
    try std.testing.expectError(error.MappingRegistrationFailed, first.map(first_object.id, ids.task(801)));
    try std.testing.expectEqual(@as(u32, 0), default_lifetime_registrations);
    try std.testing.expectEqual(@as(u16, 0), first.mappingsForTask(ids.task(801)));
    try std.testing.expectEqual(@as(usize, 1), context.refused_register_unbind);
    context.fail_register = false;
    try first.map(first_object.id, ids.task(801));
    try second.map(second_object.id, ids.task(802));
    try std.testing.expectEqual(@as(u32, 2), default_lifetime_registrations);
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expect(!unbindMappedObjectLifetime(context.lifetime()));
        try std.testing.expect(mappedObjectLifetimeIsBound(context.lifetime()));
    }
    cpu_identity.setIndexForTest(0);
    first.retireTaskMappingLifetime(ids.task(801), 0x0000_0001_0000_0001);
    try std.testing.expectEqual(@as(u32, 1), default_lifetime_registrations);
    try std.testing.expect(!unbindMappedObjectLifetime(context.lifetime()));
    try std.testing.expectEqual(@as(u16, 1), second.mappingsForTask(ids.task(802)));
    second.retireTaskMappingLifetime(ids.task(802), 0x0000_0001_0000_0001);
    try std.testing.expectEqual(@as(u32, 0), default_lifetime_registrations);
    try std.testing.expectEqual(@as(usize, 3), context.refused_register_unbind);
    try std.testing.expectEqual(@as(usize, 2), context.refused_unregister_unbind);
    try std.testing.expectEqual(context.registrations, context.unregistrations);
    // With no tokens left, foreign owners still cannot release the callback.
    for (1..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expect(!unbindMappedObjectLifetime(context.lifetime()));
    }
    cpu_identity.setIndexForTest(0);
}
