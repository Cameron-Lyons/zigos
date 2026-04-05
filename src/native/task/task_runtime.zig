const accelerator_scheduler = @import("accelerator_scheduler.zig");
const manifest = @import("../policy/manifest.zig");
const std = @import("std");
const principal = @import("../core/principal.zig");
const runtime_host = @import("task_runtime_host.zig");
const launch_helpers = @import("task_runtime_launch.zig");

pub const MAX_TASKS: usize = 32;
pub const MAX_TASK_CAPABILITIES: usize = 24;
pub const MAX_TASK_COMPONENTS: usize = 8;
pub const MAX_AUDIT_EVENTS: usize = 16;
pub const MAX_TASK_BUNDLE_ID_BYTES: usize = 64;
pub const MAX_EXECUTABLE_SEGMENTS: usize = 8;
pub const MAX_IMAGE_HASH_BYTES: usize = 32;
const INDEX_CAPACITY: usize = MAX_TASKS * 2;
const CAPABILITY_INDEX_CAPACITY: usize = MAX_TASK_CAPABILITIES * 2;
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

const IdIndexSlot = struct {
    state: IndexState = .empty,
    id: u64 = 0,
    slot_index: usize = 0,
};

const TaskColdRecord = struct {
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

const TaskSlot = struct {
    in_use: bool = false,
    task: TaskRecord = zeroTask(),
};

const AddressSpaceSlot = struct {
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

const HostAssignment = runtime_host.HostAssignment(ProcessClass, NamespaceClass);
const detached_task_cold = zeroTaskCold();

pub const Runtime = struct {
    next_task_id: u64 = 1,
    next_process_id: u64 = 1,
    next_address_space_id: u64 = 1,
    next_namespace_id: u64 = 1,
    next_component_id: u64 = 1,
    task_index_slots: [INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(INDEX_CAPACITY),
    address_space_index_slots: [INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(INDEX_CAPACITY),
    tasks: [MAX_TASKS]TaskSlot = [_]TaskSlot{TaskSlot{}} ** MAX_TASKS,
    task_cold: [MAX_TASKS]TaskColdRecord = [_]TaskColdRecord{zeroTaskCold()} ** MAX_TASKS,
    address_spaces: [MAX_TASKS]AddressSpaceSlot = [_]AddressSpaceSlot{AddressSpaceSlot{}} ** MAX_TASKS,

    pub fn init() Runtime {
        return Runtime{};
    }

    pub fn initSnapshot() Snapshot {
        return .{
            .next_task_id = 1,
            .next_process_id = 1,
            .next_address_space_id = 1,
            .next_namespace_id = 1,
            .next_component_id = 1,
            .task_index_slots = emptyIndexTable(INDEX_CAPACITY),
            .address_space_index_slots = emptyIndexTable(INDEX_CAPACITY),
            .tasks = [_]TaskSlot{TaskSlot{}} ** MAX_TASKS,
            .task_cold = [_]TaskColdRecord{zeroTaskCold()} ** MAX_TASKS,
            .address_spaces = [_]AddressSpaceSlot{AddressSpaceSlot{}} ** MAX_TASKS,
        };
    }

    pub fn writeSnapshot(self: *const Runtime, out: *Snapshot) void {
        out.next_task_id = self.next_task_id;
        out.next_process_id = self.next_process_id;
        out.next_address_space_id = self.next_address_space_id;
        out.next_namespace_id = self.next_namespace_id;
        out.next_component_id = self.next_component_id;
        copySlots(IdIndexSlot, out.task_index_slots[0..], self.task_index_slots[0..]);
        copySlots(IdIndexSlot, out.address_space_index_slots[0..], self.address_space_index_slots[0..]);
        copySlots(TaskSlot, out.tasks[0..], self.tasks[0..]);
        copyTaskColdStates(self.tasks[0..], out.task_cold[0..], self.task_cold[0..]);
        bindTaskColdStates(out.tasks[0..], out.task_cold[0..]);
        copySlots(AddressSpaceSlot, out.address_spaces[0..], self.address_spaces[0..]);
    }

    pub fn restoreFromSnapshot(self: *Runtime, state: *const Snapshot) void {
        self.next_task_id = state.next_task_id;
        self.next_process_id = state.next_process_id;
        self.next_address_space_id = state.next_address_space_id;
        self.next_namespace_id = state.next_namespace_id;
        self.next_component_id = state.next_component_id;
        copySlots(IdIndexSlot, self.task_index_slots[0..], state.task_index_slots[0..]);
        copySlots(IdIndexSlot, self.address_space_index_slots[0..], state.address_space_index_slots[0..]);
        copySlots(TaskSlot, self.tasks[0..], state.tasks[0..]);
        copyTaskColdStates(self.tasks[0..], self.task_cold[0..], state.task_cold[0..]);
        bindTaskColdStates(self.tasks[0..], self.task_cold[0..]);
        copySlots(AddressSpaceSlot, self.address_spaces[0..], state.address_spaces[0..]);
    }

    pub fn createTask(self: *Runtime, request: TaskCreateRequest) Error!*TaskRecord {
        const requested_userspace_image = if (request.userspace_image) |image|
            image.*
        else
            ExecutableImageSpec{};
        const userspace_image = if (request.launch.boundary == .userspace_process or requested_userspace_image.isPresent())
            try validateUserspaceImage(requested_userspace_image)
        else
            ExecutableImageSpec{};
        for (&self.tasks, 0..) |*slot, slot_index| {
            if (slot.in_use) continue;
            const task_id = self.next_task_id;
            self.next_task_id += 1;
            const initial_component = makeExecutionComponent(self, defaultInitialComponent(request));
            const host = try allocateHost(
                self,
                request.component_class,
                task_id,
                request.launch.image_id,
                userspace_image,
            );

            slot.in_use = true;
            self.task_cold[slot_index] = zeroTaskCold();
            slot.task = .{
                .id = task_id,
                .process_id = host.process_id,
                .address_space_id = host.address_space_id,
                .namespace_id = host.namespace_id,
                .process_generation = 1,
                .process_class = host.process_class,
                .namespace_class = host.namespace_class,
                .owner = request.owner,
                .state = .active,
                .component_class = request.component_class,
                .execution_component_count = 1,
                .capability_count = 0,
                .budget = request.budget,
                .audit_start = 0,
                .audit_count = 0,
                .ui_surface_id = request.ui_surface_id,
                .resource_class = request.budget.effectiveResourceClass(),
                .background_allowed = request.budget.background_allowed,
                .zero_ambient_authority = true,
                .local_only = request.local_only,
                .launch = makeLaunchProvenance(request.launch),
                .cold_state = &self.task_cold[slot_index],
            };
            self.task_cold[slot_index].userspace_image = userspace_image;
            self.task_cold[slot_index].execution_components[0] = initial_component;
            indexInsert(INDEX_CAPACITY, &self.task_index_slots, task_id, slot_index);
            return &slot.task;
        }
        return error.TaskTableFull;
    }

    pub fn find(self: *Runtime, task_id: u64) ?*TaskRecord {
        if (self.indexedTaskSlot(task_id)) |slot| return &slot.task;
        for (&self.tasks) |*slot| {
            if (slot.in_use and slot.task.id == task_id) return &slot.task;
        }
        return null;
    }

    fn findConst(self: *const Runtime, task_id: u64) ?*const TaskRecord {
        if (self.indexedTaskSlotConst(task_id)) |slot| return &slot.task;
        for (&self.tasks) |*slot| {
            if (slot.in_use and slot.task.id == task_id) return &slot.task;
        }
        return null;
    }

    pub fn findAddressSpace(self: *Runtime, address_space_id: u64) ?*AddressSpaceRecord {
        const slot = findAddressSpaceSlot(self, address_space_id) orelse return null;
        return &slot.address_space;
    }

    pub fn findAddressSpaceConst(self: *const Runtime, address_space_id: u64) ?*const AddressSpaceRecord {
        if (self.indexedAddressSpaceSlotConst(address_space_id)) |slot| return &slot.address_space;
        for (&self.address_spaces) |*slot| {
            if (slot.in_use and slot.address_space.id == address_space_id) return &slot.address_space;
        }
        return null;
    }

    pub fn indexedAddressSpaceSlot(self: *Runtime, address_space_id: u64) ?*AddressSpaceSlot {
        const slot_index = indexLookup(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id) orelse return null;
        const slot = &self.address_spaces[slot_index];
        if (!slot.in_use or slot.address_space.id != address_space_id) return null;
        return slot;
    }

    fn indexedAddressSpaceSlotConst(self: *const Runtime, address_space_id: u64) ?*const AddressSpaceSlot {
        const slot_index = indexLookup(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id) orelse return null;
        const slot = &self.address_spaces[slot_index];
        if (!slot.in_use or slot.address_space.id != address_space_id) return null;
        return slot;
    }

    fn indexedTaskSlot(self: *Runtime, task_id: u64) ?*TaskSlot {
        const slot_index = indexLookup(INDEX_CAPACITY, &self.task_index_slots, task_id) orelse return null;
        const slot = &self.tasks[slot_index];
        if (!slot.in_use or slot.task.id != task_id) return null;
        return slot;
    }

    fn indexedTaskSlotConst(self: *const Runtime, task_id: u64) ?*const TaskSlot {
        const slot_index = indexLookup(INDEX_CAPACITY, &self.task_index_slots, task_id) orelse return null;
        const slot = &self.tasks[slot_index];
        if (!slot.in_use or slot.task.id != task_id) return null;
        return slot;
    }

    pub fn noteAddressSpaceInstalled(self: *Runtime, address_space_id: u64, slot_index: usize) void {
        indexInsert(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id, slot_index);
    }

    pub fn removeAddressSpaceIndex(self: *Runtime, address_space_id: u64) void {
        indexRemove(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id);
    }

    pub fn grantCapability(self: *Runtime, task_id: u64, capability_id: u64) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        const cold = taskCold(task);
        if (taskHasCapability(task, capability_id)) return;
        if (task.capability_count >= MAX_TASK_CAPABILITIES) return error.CapabilityTableFull;
        cold.capability_ids[task.capability_count] = capability_id;
        indexInsert(CAPABILITY_INDEX_CAPACITY, &cold.capability_index_slots, capability_id, task.capability_count);
        task.capability_count += 1;
    }

    pub fn hasCapability(self: *const Runtime, task_id: u64, capability_id: u64) bool {
        const task = self.findConst(task_id) orelse return false;
        return taskHasCapability(task, capability_id);
    }

    pub fn attachComponent(
        self: *Runtime,
        task_id: u64,
        component: ExecutionComponentSpec,
        tick: u64,
    ) Error!ExecutionComponentRecord {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        const cold = taskCold(task);
        if (task.execution_component_count >= MAX_TASK_COMPONENTS) return error.ComponentTableFull;

        const record = makeExecutionComponent(self, component);
        cold.execution_components[task.execution_component_count] = record;
        task.execution_component_count += 1;
        try self.audit(task_id, .{
            .kind = .component_attached,
            .detail = @intFromEnum(record.substrate),
            .tick = tick,
        });
        return record;
    }

    pub fn revokeCapability(self: *Runtime, task_id: u64, capability_id: u64) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        const cold = taskCold(task);
        if (taskCapabilityIndex(task, capability_id)) |index| {
            var tail = index;
            while (tail + 1 < task.capability_count) : (tail += 1) {
                cold.capability_ids[tail] = cold.capability_ids[tail + 1];
            }
            task.capability_count -= 1;
            cold.capability_ids[task.capability_count] = 0;
            rebuildCapabilityIndex(task);
            return true;
        }

        return false;
    }

    pub fn processSeparated(self: *const Runtime, left_task_id: u64, right_task_id: u64) bool {
        const left = self.findConst(left_task_id) orelse return false;
        const right = self.findConst(right_task_id) orelse return false;
        return left.process_id != right.process_id and
            left.address_space_id != right.address_space_id and
            left.namespace_id != right.namespace_id;
    }

    pub fn rehostTask(self: *Runtime, task_id: u64, tick: u64) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.state == .terminated) return false;

        const host = try reassignHost(
            self,
            task.component_class,
            task.id,
            task.launch.image_id,
            task.userspaceImage().*,
            task.address_space_id,
        );
        task.process_id = host.process_id;
        task.address_space_id = host.address_space_id;
        task.namespace_id = host.namespace_id;
        task.process_class = host.process_class;
        task.namespace_class = host.namespace_class;
        task.process_generation += 1;
        try self.audit(task_id, .{
            .kind = .service_restarted,
            .detail = @truncate(task.process_generation),
            .tick = tick,
        });
        return true;
    }

    pub fn audit(self: *Runtime, task_id: u64, event: AuditEvent) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        const cold = taskCold(task);
        if (task.audit_count < MAX_AUDIT_EVENTS) {
            const slot_index = (task.audit_start + task.audit_count) % MAX_AUDIT_EVENTS;
            cold.audit_trail[slot_index] = event;
            task.audit_count += 1;
            return;
        }

        cold.audit_trail[task.audit_start] = event;
        task.audit_start = (task.audit_start + 1) % MAX_AUDIT_EVENTS;
    }

    pub fn canReserveBackgroundWork(
        self: *const Runtime,
        task_id: u64,
        budget: manifest.BackgroundResourceBudget,
    ) bool {
        const task = self.findConst(task_id) orelse return false;
        if (task.state != .active or !task.background_allowed) return false;

        const next_cpu = std.math.add(u64, task.background_cpu_consumed_ticks, budget.cpu_time_ticks) catch return false;
        if (next_cpu > task.budget.cpu_time_ticks) return false;

        const next_memory = std.math.add(usize, task.background_reserved_memory_bytes, budget.memory_bytes) catch return false;
        if (next_memory > task.budget.memory_bytes) return false;

        const next_shared = std.math.add(usize, task.background_reserved_shared_memory_bytes, budget.shared_memory_bytes) catch return false;
        if (next_shared > task.budget.shared_memory_bytes) return false;

        return true;
    }

    pub fn reserveBackgroundWork(
        self: *Runtime,
        task_id: u64,
        budget: manifest.BackgroundResourceBudget,
        network: manifest.BackgroundNetworkMode,
        visibility: manifest.BackgroundVisibility,
        tick: u64,
    ) Error!bool {
        if (!self.canReserveBackgroundWork(task_id, budget)) return false;
        const task = self.find(task_id) orelse return error.TaskNotFound;

        task.background_active_count += 1;
        task.background_cpu_consumed_ticks += budget.cpu_time_ticks;
        task.background_reserved_memory_bytes += budget.memory_bytes;
        task.background_reserved_shared_memory_bytes += budget.shared_memory_bytes;
        task.background_peak_memory_bytes = @max(task.background_peak_memory_bytes, task.background_reserved_memory_bytes);
        task.background_peak_shared_memory_bytes = @max(task.background_peak_shared_memory_bytes, task.background_reserved_shared_memory_bytes);
        task.last_background_network = network;
        task.last_background_visibility = visibility;
        task.last_background_tick = tick;
        return true;
    }

    pub fn releaseBackgroundWork(
        self: *Runtime,
        task_id: u64,
        budget: manifest.BackgroundResourceBudget,
    ) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.background_active_count == 0) return false;

        task.background_active_count -= 1;
        task.background_reserved_memory_bytes = saturatingSub(task.background_reserved_memory_bytes, budget.memory_bytes);
        task.background_reserved_shared_memory_bytes = saturatingSub(task.background_reserved_shared_memory_bytes, budget.shared_memory_bytes);
        return true;
    }

    pub fn terminateTask(self: *Runtime, task_id: u64, tick: u64) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.state == .terminated) return false;

        task.state = .terminated;
        taskCold(task).* = zeroTaskCold();
        task.execution_component_count = 0;
        task.capability_count = 0;
        try self.audit(task_id, .{
            .kind = .terminated,
            .tick = tick,
        });
        return true;
    }
};

fn zeroTask() TaskRecord {
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

fn allocateHost(
    self: *Runtime,
    component_class: ComponentClass,
    owner_task_id: u64,
    image_id: u64,
    userspace_image: ExecutableImageSpec,
) Error!HostAssignment {
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

fn reassignHost(
    self: *Runtime,
    component_class: ComponentClass,
    owner_task_id: u64,
    image_id: u64,
    userspace_image: ExecutableImageSpec,
    replace_address_space_id: u64,
) Error!HostAssignment {
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

fn saturatingSub(current: usize, amount: usize) usize {
    return runtime_host.saturatingSub(current, amount);
}

fn emptyIndexTable(comptime capacity: usize) [capacity]IdIndexSlot {
    return [_]IdIndexSlot{IdIndexSlot{}} ** capacity;
}

fn zeroTaskCold() TaskColdRecord {
    return .{};
}

fn taskCold(task: *TaskRecord) *TaskColdRecord {
    return task.cold_state orelse unreachable;
}

fn taskColdConst(task: *const TaskRecord) *const TaskColdRecord {
    return task.cold_state orelse &detached_task_cold;
}

fn copyTaskColdStates(task_slots: []const TaskSlot, dest: []TaskColdRecord, src: []const TaskColdRecord) void {
    var index: usize = 0;
    while (index < dest.len) : (index += 1) {
        dest[index] = zeroTaskCold();
        if (index >= task_slots.len or !task_slots[index].in_use) continue;
        dest[index] = src[index];
    }
}

fn bindTaskColdStates(task_slots: []TaskSlot, task_cold: []TaskColdRecord) void {
    for (task_slots, 0..) |*slot, slot_index| {
        slot.task.cold_state = if (slot.in_use and slot_index < task_cold.len)
            &task_cold[slot_index]
        else
            null;
    }
}

fn copySlots(comptime T: type, dest: []T, src: []const T) void {
    copyBytes(std.mem.sliceAsBytes(dest), std.mem.sliceAsBytes(src));
}

fn copyBytes(dest: []u8, src: []const u8) void {
    var index: usize = 0;
    while (index < dest.len and index < src.len) : (index += 1) {
        dest[index] = src[index];
    }
}

fn indexLookup(comptime capacity: usize, table: *const [capacity]IdIndexSlot, id: u64) ?usize {
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

fn indexInsert(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64, slot_index: usize) void {
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

fn indexRemove(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64) void {
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

fn indexHash(id: u64, comptime capacity: usize) usize {
    return @as(usize, @intCast((id *% 0x9E37_79B9_7F4A_7C15) % capacity));
}

fn taskCapabilityIndex(task: *const TaskRecord, capability_id: u64) ?usize {
    const cold = taskColdConst(task);
    const slot_index = indexLookup(CAPABILITY_INDEX_CAPACITY, &cold.capability_index_slots, capability_id) orelse return null;
    if (slot_index >= task.capability_count) return null;
    if (cold.capability_ids[slot_index] != capability_id) return null;
    return slot_index;
}

fn taskHasCapability(task: *const TaskRecord, capability_id: u64) bool {
    const cold = taskColdConst(task);
    if (taskCapabilityIndex(task, capability_id) != null) return true;

    var index: usize = 0;
    while (index < task.capability_count) : (index += 1) {
        if (cold.capability_ids[index] == capability_id) return true;
    }
    return false;
}

fn rebuildCapabilityIndex(task: *TaskRecord) void {
    const cold = taskCold(task);
    cold.capability_index_slots = emptyIndexTable(CAPABILITY_INDEX_CAPACITY);
    var index: usize = 0;
    while (index < task.capability_count) : (index += 1) {
        indexInsert(CAPABILITY_INDEX_CAPACITY, &cold.capability_index_slots, cold.capability_ids[index], index);
    }
}

fn zeroAddressSpace() AddressSpaceRecord {
    return runtime_host.zeroAddressSpace(
        AddressSpaceRecord,
        AddressSpaceRegionRecord,
        MAX_EXECUTABLE_SEGMENTS + 1,
    );
}

fn zeroAddressSpaceRegion() AddressSpaceRegionRecord {
    return runtime_host.zeroAddressSpaceRegion(AddressSpaceRegionRecord);
}

fn validateUserspaceImage(image: ExecutableImageSpec) Error!ExecutableImageSpec {
    return launch_helpers.validateUserspaceImage(Error, MAX_EXECUTABLE_SEGMENTS, image);
}

fn installAddressSpace(
    self: *Runtime,
    replace_address_space_id: ?u64,
    address_space: AddressSpaceRecord,
) Error!void {
    return runtime_host.installAddressSpace(Error, self, replace_address_space_id, address_space);
}

fn findAddressSpaceSlot(self: *Runtime, address_space_id: u64) ?*AddressSpaceSlot {
    return runtime_host.findAddressSpaceSlot(self, address_space_id);
}

fn zeroExecutionComponent() ExecutionComponentRecord {
    return launch_helpers.zeroExecutionComponent(ExecutionComponentRecord);
}

fn zeroLaunchProvenance() LaunchProvenanceRecord {
    return launch_helpers.zeroLaunchProvenance(LaunchProvenanceRecord);
}

fn defaultInitialComponent(request: TaskCreateRequest) ExecutionComponentSpec {
    return launch_helpers.defaultInitialComponent(request);
}

fn makeLaunchProvenance(spec: LaunchProvenanceSpec) LaunchProvenanceRecord {
    return launch_helpers.makeLaunchProvenance(LaunchProvenanceRecord, spec);
}

fn makeExecutionComponent(self: *Runtime, component: ExecutionComponentSpec) ExecutionComponentRecord {
    return launch_helpers.makeExecutionComponent(ExecutionComponentRecord, self, component);
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

test "new tasks start with zero ambient authority and no capabilities" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
            .background_allowed = false,
        },
        .ui_surface_id = 7,
        .local_only = true,
    });

    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expect(task.zero_ambient_authority);
    try std.testing.expect(task.local_only);
    try std.testing.expectEqual(@as(?u64, 7), task.ui_surface_id);
    try std.testing.expectEqual(@as(usize, 1), task.execution_component_count);
    try std.testing.expectEqual(ExecutionSubstrate.typed_component_abi, task.executionComponents()[0].substrate);
    try std.testing.expectEqualStrings("session-manager", task.executionComponents()[0].labelSlice());
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.foreground_interactive, task.resourceClass());
    try std.testing.expect(task.hasDedicatedHost());
    try std.testing.expectEqual(ProcessClass.session_host, task.process_class);
    try std.testing.expectEqual(NamespaceClass.session_private, task.namespace_class);
    try std.testing.expect(!task.runsAsUserspaceProcess());
    try std.testing.expect(!task.hasLoadedExecutable());
    try std.testing.expectEqualStrings("", task.launchBundleIdSlice());
}

test "granting and revoking capabilities updates the task table" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 2 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 5_000,
            .memory_bytes = 4096,
            .endpoint_slots = 8,
            .shared_memory_bytes = 8192,
            .background_allowed = true,
        },
    });

    try runtime.grantCapability(task.id, 11);
    try runtime.grantCapability(task.id, 12);
    try std.testing.expectEqual(@as(usize, 2), task.capability_count);
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.background_light, task.resourceClass());

    try std.testing.expect(try runtime.revokeCapability(task.id, 11));
    try std.testing.expectEqual(@as(usize, 1), task.capability_count);
    try std.testing.expectEqual(@as(u64, 12), task.capabilityIds()[0]);
}

test "explicit resource classes override the default task classification" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 500,
            .memory_bytes = 2048,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
            .resource_class = .batch_compute,
            .background_allowed = true,
        },
        .local_only = true,
    });

    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.batch_compute, task.resourceClass());
}

test "userspace launch provenance is recorded for explicit image launches" {
    var runtime = Runtime.init();
    const notes_image = syntheticUserspaceImage("notes", "app.notes");
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 12 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = 2048,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
            .background_allowed = false,
        },
        .local_only = true,
        .initial_component = .{
            .label = "notes",
            .entry = "app.notes",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 44,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.notes",
        },
        .userspace_image = &notes_image,
    });

    try std.testing.expect(task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(u64, 44), task.launch.image_id);
    try std.testing.expect(task.launch.signed);
    try std.testing.expect(task.hasLoadedExecutable());
    try std.testing.expectEqualStrings("app.notes", task.launchBundleIdSlice());
}

test "userspace tasks materialize executable mappings in their address spaces" {
    var runtime = Runtime.init();
    const workspace_storage_image = syntheticUserspaceImage("workspace-storage", "zigos.object.workspace");
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 13 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_500,
            .memory_bytes = 4096,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
        .initial_component = .{
            .label = "workspace-storage",
            .entry = "zigos.object.workspace",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 45,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.storage-object",
        },
        .userspace_image = &workspace_storage_image,
    });

    const address_space = runtime.findAddressSpaceConst(task.address_space_id).?;
    try std.testing.expect(task.hasLoadedExecutable());
    try std.testing.expect(address_space.hasMappedExecutable());
    try std.testing.expectEqual(@as(u64, 45), address_space.image_id);
    try std.testing.expectEqual(task.userspaceImage().entry_point, address_space.instruction_pointer);
    try std.testing.expectEqual(task.userspaceImage().segment_count, address_space.load_segment_count);
    try std.testing.expectEqual(task.userspaceImage().segment_count + 1, address_space.region_count);
    try std.testing.expectEqual(AddressSpaceRegionKind.stack, address_space.regions[address_space.region_count - 1].kind);
}

test "audit trail keeps the most recent events" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 256,
            .endpoint_slots = 2,
            .shared_memory_bytes = 512,
        },
    });

    var index: usize = 0;
    while (index < MAX_AUDIT_EVENTS + 2) : (index += 1) {
        try runtime.audit(task.id, .{
            .kind = .policy_allowed,
            .detail = @intCast(index),
            .tick = index,
        });
    }

    try std.testing.expectEqual(@as(usize, MAX_AUDIT_EVENTS), task.audit_count);
    try std.testing.expectEqual(@as(u32, 2), task.auditEventAt(0).?.detail);
    try std.testing.expectEqual(@as(u32, MAX_AUDIT_EVENTS + 1), task.latestAuditEvent().?.detail);
}

test "tasks can attach execution components while preserving launch substrate" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 6 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 500,
            .memory_bytes = 4096,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .initial_component = .{
            .substrate = .typed_component_abi,
            .label = "notes-ui",
            .entry = "app.notes.ui",
        },
    });

    const helper = try runtime.attachComponent(task.id, .{
        .substrate = .early_elf_runner,
        .label = "notes-sync-helper",
        .entry = "/system/components/notes-sync.elf",
    }, 12);

    try std.testing.expectEqual(@as(usize, 2), task.execution_component_count);
    try std.testing.expectEqualStrings("notes-ui", task.executionComponents()[0].labelSlice());
    try std.testing.expectEqual(ExecutionSubstrate.early_elf_runner, helper.substrate);
    try std.testing.expectEqualStrings("notes-sync-helper", helper.labelSlice());
    try std.testing.expectEqualStrings("/system/components/notes-sync.elf", helper.entrySlice());
    try std.testing.expectEqual(AuditEventKind.component_attached, task.latestAuditEvent().?.kind);
}

test "tasks are isolated in separate process address space and namespace hosts and can be rehosted" {
    var runtime = Runtime.init();
    const service_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 9 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 512,
        },
    });
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 10 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 512,
        },
        .local_only = true,
    });

    const original_process_id = service_task.process_id;
    const original_address_space_id = service_task.address_space_id;
    try std.testing.expect(runtime.processSeparated(service_task.id, app_task.id));
    try std.testing.expectEqual(ProcessClass.service_sandbox, service_task.process_class);
    try std.testing.expectEqual(ProcessClass.app_sandbox, app_task.process_class);

    try std.testing.expect(try runtime.rehostTask(service_task.id, 55));
    try std.testing.expect(service_task.process_id != original_process_id);
    try std.testing.expect(service_task.address_space_id != original_address_space_id);
    try std.testing.expectEqual(@as(u32, 2), service_task.process_generation);
    try std.testing.expectEqual(AuditEventKind.service_restarted, service_task.latestAuditEvent().?.kind);
}

test "rehosting a userspace task rebuilds the mapped executable state" {
    var runtime = Runtime.init();
    const sync_service_image = syntheticUserspaceImage("sync-service", "zigos.sync.workspace");
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 14 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = 4096,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
        .initial_component = .{
            .label = "sync-service",
            .entry = "zigos.sync.workspace",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 46,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.sync-service",
        },
        .userspace_image = &sync_service_image,
    });

    const original_address_space_id = task.address_space_id;
    try std.testing.expect(try runtime.rehostTask(task.id, 77));
    try std.testing.expect(task.address_space_id != original_address_space_id);
    try std.testing.expect(runtime.findAddressSpaceConst(original_address_space_id) == null);

    const address_space = runtime.findAddressSpaceConst(task.address_space_id).?;
    try std.testing.expect(address_space.hasMappedExecutable());
    try std.testing.expectEqual(task.userspaceImage().entry_point, address_space.instruction_pointer);
    try std.testing.expectEqual(task.userspaceImage().segment_count, address_space.load_segment_count);
}

test "terminating a task clears its capabilities and marks the state" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 8 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 512,
        },
    });

    try runtime.grantCapability(task.id, 77);
    try std.testing.expect(try runtime.terminateTask(task.id, 44));
    try std.testing.expectEqual(TaskState.terminated, task.state);
    try std.testing.expectEqual(@as(usize, 0), task.execution_component_count);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expectEqual(AuditEventKind.terminated, task.latestAuditEvent().?.kind);
}
