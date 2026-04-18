const accelerator_scheduler = @import("accelerator_scheduler.zig");
const builtin = @import("builtin");
const launch_helpers = @import("task_runtime_launch.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const runtime_host = @import("task_runtime_host.zig");
const std = @import("std");

pub const MAX_TASKS: usize = 32;
pub const MAX_TASK_CAPABILITIES: usize = 24;
pub const MAX_TASK_COMPONENTS: usize = 8;
pub const MAX_AUDIT_EVENTS: usize = 16;
pub const MAX_TASK_BUNDLE_ID_BYTES: usize = 64;
pub const MAX_EXECUTABLE_SEGMENTS: usize = 8;
pub const MAX_IMAGE_HASH_BYTES: usize = 32;
pub const INDEX_CAPACITY: usize = MAX_TASKS * 2;
pub const CAPABILITY_INDEX_CAPACITY: usize = MAX_TASK_CAPABILITIES * 2;
pub const DEFAULT_USER_STACK_TOP: u64 = 0xBFFF_F000;
pub const DEFAULT_USER_STACK_SIZE_BYTES: usize = 64 * 1024;
pub const DEFAULT_SYNTHETIC_ENTRY_POINT: u64 = 0x0804_8000;
pub const DEFAULT_SYNTHETIC_IMAGE_BYTES: usize = 8 * 1024;

pub const TaskState = enum(u8) {
    staged,
    active,
    suspended,
    terminated,
};

pub const ComponentClass = enum(u8) {
    session_manager,
    app_component,
    service_component,
};

pub const ProcessClass = enum(u8) {
    session_host,
    app_sandbox,
    service_sandbox,
};

pub const NamespaceClass = enum(u8) {
    session_private,
    app_private,
    service_private,
};

pub const ExecutionSubstrate = enum(u8) {
    typed_component_abi,
    early_elf_runner,
};

pub const LaunchBoundary = enum(u8) {
    direct_request,
    userspace_process,
};

pub const SegmentAccess = packed struct(u8) {
    read: bool = true,
    write: bool = false,
    execute: bool = false,
    _reserved: u5 = 0,
};

pub const ExecutableSegmentSpec = struct {
    virtual_address: u64 = 0,
    file_offset: u32 = 0,
    file_size: u32 = 0,
    memory_size: u32 = 0,
    alignment: u32 = 0x1000,
    access: SegmentAccess = .{},
};

pub const ExecutableImageSpec = struct {
    entry_point: u64 = 0,
    stack_top: u64 = DEFAULT_USER_STACK_TOP,
    stack_size_bytes: usize = DEFAULT_USER_STACK_SIZE_BYTES,
    file_size_bytes: usize = 0,
    file_sha256: [MAX_IMAGE_HASH_BYTES]u8 = [_]u8{0} ** MAX_IMAGE_HASH_BYTES,
    segment_count: usize = 0,
    segments: [MAX_EXECUTABLE_SEGMENTS]ExecutableSegmentSpec = [_]ExecutableSegmentSpec{ExecutableSegmentSpec{}} ** MAX_EXECUTABLE_SEGMENTS,

    pub fn isPresent(self: *const ExecutableImageSpec) bool {
        return self.entry_point != 0 and self.segment_count != 0;
    }
};

pub const AddressSpaceLoadState = enum(u8) {
    empty,
    executable_loaded,
};

pub const AddressSpaceRegionKind = enum(u8) {
    load_segment,
    stack,
};

pub const AddressSpaceRegionRecord = struct {
    kind: AddressSpaceRegionKind,
    virtual_address: u64,
    size_bytes: usize,
    file_offset: u32,
    file_size: u32,
    access: SegmentAccess,
};

pub const AddressSpaceRecord = struct {
    id: u64,
    owner_task_id: u64,
    process_id: u64,
    image_id: u64,
    load_state: AddressSpaceLoadState,
    entry_point: u64,
    instruction_pointer: u64,
    stack_pointer: u64,
    stack_top: u64,
    stack_size_bytes: usize,
    load_segment_count: usize,
    region_count: usize,
    image_sha256: [MAX_IMAGE_HASH_BYTES]u8,
    regions: [MAX_EXECUTABLE_SEGMENTS + 1]AddressSpaceRegionRecord,

    pub fn hasMappedExecutable(self: *const AddressSpaceRecord) bool {
        return self.load_state == .executable_loaded;
    }
};

pub const ExecutionComponentSpec = struct {
    substrate: ExecutionSubstrate = .typed_component_abi,
    label: []const u8 = "",
    entry: []const u8 = "",
};

pub const ExecutionComponentRecord = struct {
    id: u64,
    substrate: ExecutionSubstrate,
    label_len: usize,
    label: [48]u8,
    entry_len: usize,
    entry: [64]u8,

    pub fn labelSlice(self: *const ExecutionComponentRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn entrySlice(self: *const ExecutionComponentRecord) []const u8 {
        return self.entry[0..self.entry_len];
    }
};

pub const ResourceBudget = struct {
    cpu_time_ticks: u64,
    memory_bytes: usize,
    endpoint_slots: u16,
    shared_memory_bytes: usize,
    resource_class: ?accelerator_scheduler.ResourceClass = null,
    background_allowed: bool = false,

    pub fn effectiveResourceClass(self: ResourceBudget) accelerator_scheduler.ResourceClass {
        if (self.resource_class) |resource_class| return resource_class;
        return if (self.background_allowed)
            .background_light
        else
            .foreground_interactive;
    }
};

pub const AuditEventKind = enum(u8) {
    created,
    terminated,
    capability_granted,
    capability_revoked,
    component_attached,
    permission_prompted,
    permission_reviewed,
    policy_allowed,
    policy_denied,
    background_dispatched,
    service_connected,
    service_restarted,
};

pub const AuditEvent = struct {
    kind: AuditEventKind,
    capability_id: u64 = 0,
    detail: u32 = 0,
    tick: u64 = 0,
};

pub const LaunchProvenanceSpec = struct {
    boundary: LaunchBoundary = .direct_request,
    image_id: u64 = 0,
    component_abi_version: u16 = 0,
    signed: bool = false,
    bundle_id: []const u8 = "",
};

pub const LaunchProvenanceRecord = struct {
    boundary: LaunchBoundary,
    image_id: u64,
    component_abi_version: u16,
    signed: bool,
    bundle_id_len: usize,
    bundle_id: [MAX_TASK_BUNDLE_ID_BYTES]u8,

    pub fn bundleIdSlice(self: *const LaunchProvenanceRecord) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }
};

pub const TaskCreateRequest = struct {
    owner: principal.PrincipalId,
    component_class: ComponentClass,
    budget: ResourceBudget,
    ui_surface_id: ?u64 = null,
    local_only: bool = false,
    initial_component: ExecutionComponentSpec = .{},
    launch: LaunchProvenanceSpec = .{},
    userspace_image: ?*const ExecutableImageSpec = null,
};

const IndexState = enum(u8) {
    empty,
    filled,
    tombstone,
};

pub const IdIndexSlot = struct {
    state: IndexState = .empty,
    id: u64 = 0,
    slot_index: usize = 0,
};

pub const TaskColdRecord = struct {
    execution_components: [MAX_TASK_COMPONENTS]ExecutionComponentRecord = [_]ExecutionComponentRecord{zeroExecutionComponent()} ** MAX_TASK_COMPONENTS,
    capability_ids: [MAX_TASK_CAPABILITIES]u64 = [_]u64{0} ** MAX_TASK_CAPABILITIES,
    capability_index_slots: [CAPABILITY_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(CAPABILITY_INDEX_CAPACITY),
    audit_trail: [MAX_AUDIT_EVENTS]AuditEvent = [_]AuditEvent{AuditEvent{ .kind = .created }} ** MAX_AUDIT_EVENTS,
    userspace_image: ExecutableImageSpec = .{},
};

pub const TaskRecord = struct {
    id: u64,
    process_id: u64,
    address_space_id: u64,
    namespace_id: u64,
    process_generation: u32,
    process_class: ProcessClass,
    namespace_class: NamespaceClass,
    owner: principal.PrincipalId,
    state: TaskState,
    component_class: ComponentClass,
    execution_component_count: usize,
    capability_count: usize,
    budget: ResourceBudget,
    audit_start: usize,
    audit_count: usize,
    ui_surface_id: ?u64,
    resource_class: accelerator_scheduler.ResourceClass,
    background_allowed: bool,
    background_active_count: u16 = 0,
    background_cpu_consumed_ticks: u64 = 0,
    background_reserved_memory_bytes: usize = 0,
    background_reserved_shared_memory_bytes: usize = 0,
    background_peak_memory_bytes: usize = 0,
    background_peak_shared_memory_bytes: usize = 0,
    last_background_network: manifest.BackgroundNetworkMode = .none,
    last_background_visibility: manifest.BackgroundVisibility = .status_only,
    last_background_tick: u64 = 0,
    zero_ambient_authority: bool,
    local_only: bool,
    launch: LaunchProvenanceRecord,
    cold_state: ?*TaskColdRecord,

    pub fn resourceClass(self: *const TaskRecord) accelerator_scheduler.ResourceClass {
        return self.resource_class;
    }

    pub fn hasDedicatedHost(self: *const TaskRecord) bool {
        return self.process_id != 0 and self.address_space_id != 0 and self.namespace_id != 0;
    }

    pub fn runsAsUserspaceProcess(self: *const TaskRecord) bool {
        return self.launch.boundary == .userspace_process;
    }

    pub fn launchBundleIdSlice(self: *const TaskRecord) []const u8 {
        return self.launch.bundleIdSlice();
    }

    pub fn executionComponents(self: *const TaskRecord) []const ExecutionComponentRecord {
        return taskColdConst(self).execution_components[0..self.execution_component_count];
    }

    pub fn capabilityIds(self: *const TaskRecord) []const u64 {
        return taskColdConst(self).capability_ids[0..self.capability_count];
    }

    pub fn userspaceImage(self: *const TaskRecord) *const ExecutableImageSpec {
        return &taskColdConst(self).userspace_image;
    }

    pub fn hasLoadedExecutable(self: *const TaskRecord) bool {
        return self.userspaceImage().isPresent();
    }

    pub fn auditEventAt(self: *const TaskRecord, index: usize) ?AuditEvent {
        if (index >= self.audit_count) return null;
        return taskColdConst(self).audit_trail[(self.audit_start + index) % MAX_AUDIT_EVENTS];
    }

    pub fn latestAuditEvent(self: *const TaskRecord) ?AuditEvent {
        if (self.audit_count == 0) return null;
        return self.auditEventAt(self.audit_count - 1);
    }
};

pub const Error = error{
    AddressSpaceTableFull,
    ComponentTableFull,
    CapabilityTableFull,
    InvalidUserspaceImage,
    TaskNotFound,
    TaskTableFull,
};

pub const TaskSlot = struct {
    in_use: bool = false,
    task: TaskRecord = zeroTask(),
};

pub const AddressSpaceSlot = struct {
    in_use: bool = false,
    address_space: AddressSpaceRecord = zeroAddressSpace(),
};

pub const Snapshot = struct {
    next_task_id: u64,
    next_process_id: u64,
    next_address_space_id: u64,
    next_namespace_id: u64,
    next_component_id: u64,
    task_index_slots: [INDEX_CAPACITY]IdIndexSlot,
    address_space_index_slots: [INDEX_CAPACITY]IdIndexSlot,
    tasks: [MAX_TASKS]TaskSlot,
    task_cold: [MAX_TASKS]TaskColdRecord,
    address_spaces: [MAX_TASKS]AddressSpaceSlot,
};

const detached_task_cold = zeroTaskCold();

pub fn zeroTask() TaskRecord {
    return .{
        .id = 0,
        .process_id = 0,
        .address_space_id = 0,
        .namespace_id = 0,
        .process_generation = 0,
        .process_class = .service_sandbox,
        .namespace_class = .service_private,
        .owner = .{ .kind = .service, .serial = 0 },
        .state = .staged,
        .component_class = .service_component,
        .execution_component_count = 0,
        .capability_count = 0,
        .budget = .{
            .cpu_time_ticks = 0,
            .memory_bytes = 0,
            .endpoint_slots = 0,
            .shared_memory_bytes = 0,
            .background_allowed = false,
        },
        .audit_start = 0,
        .audit_count = 0,
        .ui_surface_id = null,
        .resource_class = .foreground_interactive,
        .background_allowed = false,
        .background_active_count = 0,
        .background_cpu_consumed_ticks = 0,
        .background_reserved_memory_bytes = 0,
        .background_reserved_shared_memory_bytes = 0,
        .background_peak_memory_bytes = 0,
        .background_peak_shared_memory_bytes = 0,
        .last_background_network = .none,
        .last_background_visibility = .status_only,
        .last_background_tick = 0,
        .zero_ambient_authority = true,
        .local_only = false,
        .launch = zeroLaunchProvenance(),
        .cold_state = null,
    };
}

pub fn allocateHost(
    self: anytype,
    component_class: ComponentClass,
    owner_task_id: u64,
    image_id: u64,
    userspace_image: ExecutableImageSpec,
) Error!runtime_host.HostAssignment(ProcessClass, NamespaceClass) {
    return runtime_host.allocateHost(
        Error,
        ProcessClass,
        NamespaceClass,
        self,
        component_class,
        owner_task_id,
        image_id,
        userspace_image,
    );
}

pub fn reassignHost(
    self: anytype,
    component_class: ComponentClass,
    owner_task_id: u64,
    image_id: u64,
    userspace_image: ExecutableImageSpec,
    replace_address_space_id: u64,
) Error!runtime_host.HostAssignment(ProcessClass, NamespaceClass) {
    return runtime_host.reassignHost(
        Error,
        ProcessClass,
        NamespaceClass,
        self,
        component_class,
        owner_task_id,
        image_id,
        userspace_image,
        replace_address_space_id,
    );
}

pub fn saturatingSub(current: usize, amount: usize) usize {
    return runtime_host.saturatingSub(current, amount);
}

pub fn emptyIndexTable(comptime capacity: usize) [capacity]IdIndexSlot {
    return [_]IdIndexSlot{IdIndexSlot{}} ** capacity;
}

pub fn zeroTaskCold() TaskColdRecord {
    return .{};
}

pub fn resetTaskCold(dest: *TaskColdRecord) void {
    zeroBytes(std.mem.asBytes(dest));
}

pub fn copyTaskCold(dest: *TaskColdRecord, src: *const TaskColdRecord) void {
    copyBytes(std.mem.asBytes(dest), std.mem.asBytes(src));
}

pub fn taskCold(task: *TaskRecord) *TaskColdRecord {
    return task.cold_state orelse unreachable;
}

pub fn taskColdConst(task: *const TaskRecord) *const TaskColdRecord {
    return task.cold_state orelse &detached_task_cold;
}

pub fn copyTaskColdStates(task_slots: []const TaskSlot, dest: []TaskColdRecord, src: []const TaskColdRecord) void {
    var index: usize = 0;
    while (index < dest.len) : (index += 1) {
        resetTaskCold(&dest[index]);
        if (index >= task_slots.len or !task_slots[index].in_use) continue;
        copyTaskCold(&dest[index], &src[index]);
    }
}

pub fn bindTaskColdStates(task_slots: []TaskSlot, task_cold: []TaskColdRecord) void {
    for (task_slots, 0..) |*slot, slot_index| {
        slot.task.cold_state = if (slot.in_use and slot_index < task_cold.len)
            &task_cold[slot_index]
        else
            null;
    }
}

pub fn copySlots(comptime T: type, dest: []T, src: []const T) void {
    copyBytes(std.mem.sliceAsBytes(dest), std.mem.sliceAsBytes(src));
}

pub fn copyBytes(dest: []u8, src: []const u8) void {
    if (builtin.target.cpu.arch == .x86 and builtin.target.os.tag == .freestanding) {
        const count: u32 = @intCast(@min(dest.len, src.len));
        if (count == 0) return;
        asm volatile (
            \\cld
            \\rep movsb
            :
            : [dst] "{edi}" (dest.ptr),
              [src] "{esi}" (src.ptr),
              [count] "{ecx}" (count),
            : .{ .memory = true });
        return;
    }

    var index: usize = 0;
    while (index < dest.len and index < src.len) : (index += 1) {
        dest[index] = src[index];
    }
}

pub fn zeroBytes(dest: []u8) void {
    if (builtin.target.cpu.arch == .x86 and builtin.target.os.tag == .freestanding) {
        const count: u32 = @intCast(dest.len);
        if (count == 0) return;
        asm volatile (
            \\cld
            \\rep stosb
            :
            : [dst] "{edi}" (dest.ptr),
              [count] "{ecx}" (count),
              [value] "{eax}" (@as(u32, 0)),
            : .{ .memory = true });
        return;
    }

    var index: usize = 0;
    while (index < dest.len) : (index += 1) {
        dest[index] = 0;
    }
}

pub fn indexLookup(comptime capacity: usize, table: *const [capacity]IdIndexSlot, id: u64) ?usize {
    if (id == 0) return null;

    var index = indexHash(id, capacity);
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

pub fn indexInsert(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64, slot_index: usize) void {
    if (id == 0) unreachable;

    var index = indexHash(id, capacity);
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

    unreachable;
}

pub fn indexRemove(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64) void {
    if (id == 0) return;

    var index = indexHash(id, capacity);
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

pub fn indexHash(id: u64, comptime capacity: usize) usize {
    return @as(usize, @intCast((id *% 0x9E37_79B9_7F4A_7C15) % capacity));
}

pub fn taskCapabilityIndex(task: *const TaskRecord, capability_id: u64) ?usize {
    const cold = taskColdConst(task);
    const slot_index = indexLookup(CAPABILITY_INDEX_CAPACITY, &cold.capability_index_slots, capability_id) orelse return null;
    if (slot_index >= task.capability_count) return null;
    if (cold.capability_ids[slot_index] != capability_id) return null;
    return slot_index;
}

pub fn taskHasCapability(task: *const TaskRecord, capability_id: u64) bool {
    const cold = taskColdConst(task);
    if (taskCapabilityIndex(task, capability_id) != null) return true;

    var index: usize = 0;
    while (index < task.capability_count) : (index += 1) {
        if (cold.capability_ids[index] == capability_id) return true;
    }
    return false;
}

pub fn rebuildCapabilityIndex(task: *TaskRecord) void {
    const cold = taskCold(task);
    cold.capability_index_slots = emptyIndexTable(CAPABILITY_INDEX_CAPACITY);
    var index: usize = 0;
    while (index < task.capability_count) : (index += 1) {
        indexInsert(CAPABILITY_INDEX_CAPACITY, &cold.capability_index_slots, cold.capability_ids[index], index);
    }
}

pub fn zeroAddressSpace() AddressSpaceRecord {
    return runtime_host.zeroAddressSpace(
        AddressSpaceRecord,
        AddressSpaceRegionRecord,
        MAX_EXECUTABLE_SEGMENTS + 1,
    );
}

pub fn zeroAddressSpaceRegion() AddressSpaceRegionRecord {
    return runtime_host.zeroAddressSpaceRegion(AddressSpaceRegionRecord);
}

pub fn validateUserspaceImage(image: ExecutableImageSpec) Error!ExecutableImageSpec {
    return launch_helpers.validateUserspaceImage(Error, MAX_EXECUTABLE_SEGMENTS, image);
}

pub fn installAddressSpace(
    self: anytype,
    replace_address_space_id: ?u64,
    address_space: AddressSpaceRecord,
) Error!void {
    return runtime_host.installAddressSpace(Error, self, replace_address_space_id, address_space);
}

pub fn findAddressSpaceSlot(self: anytype, address_space_id: u64) ?*@TypeOf(self.address_spaces[0]) {
    return runtime_host.findAddressSpaceSlot(self, address_space_id);
}

pub fn zeroExecutionComponent() ExecutionComponentRecord {
    return launch_helpers.zeroExecutionComponent(ExecutionComponentRecord);
}

pub fn zeroLaunchProvenance() LaunchProvenanceRecord {
    return launch_helpers.zeroLaunchProvenance(LaunchProvenanceRecord);
}

pub fn defaultInitialComponent(request: TaskCreateRequest) ExecutionComponentSpec {
    return launch_helpers.defaultInitialComponent(request);
}

pub fn makeLaunchProvenance(spec: LaunchProvenanceSpec) LaunchProvenanceRecord {
    return launch_helpers.makeLaunchProvenance(LaunchProvenanceRecord, spec);
}

pub fn makeExecutionComponent(runtime: anytype, component: ExecutionComponentSpec) ExecutionComponentRecord {
    return launch_helpers.makeExecutionComponent(ExecutionComponentRecord, runtime, component);
}

pub fn syntheticUserspaceImage(label: []const u8, entry: []const u8) ExecutableImageSpec {
    return launch_helpers.syntheticUserspaceImage(
        ExecutableImageSpec,
        label,
        entry,
        DEFAULT_SYNTHETIC_ENTRY_POINT,
        DEFAULT_USER_STACK_TOP,
        DEFAULT_USER_STACK_SIZE_BYTES,
        DEFAULT_SYNTHETIC_IMAGE_BYTES,
    );
}
