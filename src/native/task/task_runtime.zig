const accelerator_scheduler = @import("accelerator_scheduler.zig");
const builtin = @import("builtin");
const manifest = @import("../policy/manifest.zig");
const model = @import("task_runtime_model.zig");
const native_util = @import("../core/util.zig");
const std = @import("std");

pub const MAX_TASKS = model.MAX_TASKS;
pub const MAX_TASK_CAPABILITIES = model.MAX_TASK_CAPABILITIES;
pub const MAX_TASK_COMPONENTS = model.MAX_TASK_COMPONENTS;
pub const MAX_AUDIT_EVENTS = model.MAX_AUDIT_EVENTS;
pub const MAX_TASK_BUNDLE_ID_BYTES = model.MAX_TASK_BUNDLE_ID_BYTES;
pub const MAX_EXECUTABLE_SEGMENTS = model.MAX_EXECUTABLE_SEGMENTS;
pub const MAX_IMAGE_HASH_BYTES = model.MAX_IMAGE_HASH_BYTES;
pub const DEFAULT_USER_STACK_TOP = model.DEFAULT_USER_STACK_TOP;
pub const DEFAULT_USER_STACK_SIZE_BYTES = model.DEFAULT_USER_STACK_SIZE_BYTES;
pub const DEFAULT_SYNTHETIC_ENTRY_POINT = model.DEFAULT_SYNTHETIC_ENTRY_POINT;
pub const DEFAULT_SYNTHETIC_IMAGE_BYTES = model.DEFAULT_SYNTHETIC_IMAGE_BYTES;
pub const TaskState = model.TaskState;
pub const ComponentClass = model.ComponentClass;
pub const ProcessClass = model.ProcessClass;
pub const NamespaceClass = model.NamespaceClass;
pub const ExecutionSubstrate = model.ExecutionSubstrate;
pub const LaunchBoundary = model.LaunchBoundary;
pub const SegmentAccess = model.SegmentAccess;
pub const ExecutableSegmentSpec = model.ExecutableSegmentSpec;
pub const ExecutableImageSpec = model.ExecutableImageSpec;
pub const AddressSpaceLoadState = model.AddressSpaceLoadState;
pub const AddressSpaceRegionKind = model.AddressSpaceRegionKind;
pub const AddressSpaceRegionRecord = model.AddressSpaceRegionRecord;
pub const AddressSpaceRecord = model.AddressSpaceRecord;
pub const ExecutionComponentSpec = model.ExecutionComponentSpec;
pub const ExecutionComponentRecord = model.ExecutionComponentRecord;
pub const ResourceBudget = model.ResourceBudget;
pub const AuditEventKind = model.AuditEventKind;
pub const AuditEvent = model.AuditEvent;
pub const LaunchProvenanceSpec = model.LaunchProvenanceSpec;
pub const LaunchProvenanceRecord = model.LaunchProvenanceRecord;
pub const TaskCreateRequest = model.TaskCreateRequest;
pub const TaskRecord = model.TaskRecord;
pub const Error = model.Error;
pub const Snapshot = model.Snapshot;
pub const syntheticUserspaceImage = model.syntheticUserspaceImage;

const INDEX_CAPACITY = model.INDEX_CAPACITY;
const IdIndexSlot = model.IdIndexSlot;
const TaskColdRecord = model.TaskColdRecord;
const TaskSlot = model.TaskSlot;
const AddressSpaceSlot = model.AddressSpaceSlot;
const allocateHost = model.allocateHost;
const reassignHost = model.reassignHost;
const saturatingSub = model.saturatingSub;
const emptyIndexTable = model.emptyIndexTable;
const zeroTaskCold = model.zeroTaskCold;
const resetTaskCold = model.resetTaskCold;
const copyTaskCold = model.copyTaskCold;
const copyTaskColdStates = model.copyTaskColdStates;
const bindTaskColdStates = model.bindTaskColdStates;
const copySlots = model.copySlots;
const indexLookup = model.indexLookup;
const indexInsert = model.indexInsert;
const indexRemove = model.indexRemove;
const taskCold = model.taskCold;
const taskColdConst = model.taskColdConst;
const taskCapabilityIndex = model.taskCapabilityIndex;
const taskHasCapability = model.taskHasCapability;
const rebuildCapabilityIndex = model.rebuildCapabilityIndex;
const validateUserspaceImage = model.validateUserspaceImage;
const findAddressSpaceSlot = model.findAddressSpaceSlot;
const defaultInitialComponent = model.defaultInitialComponent;
const makeLaunchProvenance = model.makeLaunchProvenance;
const makeExecutionComponent = model.makeExecutionComponent;

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
        return Snapshot{};
    }

    pub fn writeSnapshot(self: *const Runtime, out: *Snapshot) void {
        out.next_task_id = self.next_task_id;
        out.next_process_id = self.next_process_id;
        out.next_address_space_id = self.next_address_space_id;
        out.next_namespace_id = self.next_namespace_id;
        out.next_component_id = self.next_component_id;
        out.task_count = 0;
        for (self.tasks, 0..) |slot, slot_index| {
            if (!slot.in_use) continue;
            const dense_index = out.task_count;
            out.tasks[dense_index] = slot;
            copyTaskCold(&out.task_cold[dense_index], &self.task_cold[slot_index]);
            out.task_count += 1;
        }
        bindTaskColdStates(out.tasks[0..out.task_count], out.task_cold[0..out.task_count]);

        out.address_space_count = 0;
        for (self.address_spaces) |slot| {
            if (!slot.in_use) continue;
            out.address_spaces[out.address_space_count] = slot;
            out.address_space_count += 1;
        }
    }

    pub fn restoreFromSnapshot(self: *Runtime, state: *const Snapshot) void {
        self.* = Runtime.init();
        self.next_task_id = state.next_task_id;
        self.next_process_id = state.next_process_id;
        self.next_address_space_id = state.next_address_space_id;
        self.next_namespace_id = state.next_namespace_id;
        self.next_component_id = state.next_component_id;

        var task_index: usize = 0;
        while (task_index < state.task_count) : (task_index += 1) {
            self.tasks[task_index] = state.tasks[task_index];
            copyTaskCold(&self.task_cold[task_index], &state.task_cold[task_index]);
        }

        var address_space_index: usize = 0;
        while (address_space_index < state.address_space_count) : (address_space_index += 1) {
            self.address_spaces[address_space_index] = state.address_spaces[address_space_index];
        }
        self.rebuildIndexes();
        self.debugAssertIndexIntegrity();
    }

    pub fn rebuildIndexes(self: *Runtime) void {
        self.task_index_slots = emptyIndexTable(INDEX_CAPACITY);
        self.address_space_index_slots = emptyIndexTable(INDEX_CAPACITY);

        for (&self.tasks, 0..) |*slot, slot_index| {
            if (!slot.in_use) continue;
            slot.task.cold_state = &self.task_cold[slot_index];
            indexInsert(INDEX_CAPACITY, &self.task_index_slots, slot.task.id, slot_index);
            rebuildCapabilityIndex(&slot.task);
        }

        for (self.address_spaces, 0..) |slot, slot_index| {
            if (!slot.in_use) continue;
            indexInsert(INDEX_CAPACITY, &self.address_space_index_slots, slot.address_space.id, slot_index);
        }
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
            resetTaskCold(&self.task_cold[slot_index]);
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
        self.debugAssertTaskIndexMissAbsent(task_id);
        return null;
    }

    fn findConst(self: *const Runtime, task_id: u64) ?*const TaskRecord {
        if (self.indexedTaskSlotConst(task_id)) |slot| return &slot.task;
        self.debugAssertTaskIndexMissAbsent(task_id);
        return null;
    }

    pub fn findAddressSpace(self: *Runtime, address_space_id: u64) ?*AddressSpaceRecord {
        const slot = findAddressSpaceSlot(self, address_space_id) orelse return null;
        return &slot.address_space;
    }

    pub fn findAddressSpaceConst(self: *const Runtime, address_space_id: u64) ?*const AddressSpaceRecord {
        if (self.indexedAddressSpaceSlotConst(address_space_id)) |slot| return &slot.address_space;
        self.debugAssertAddressSpaceIndexMissAbsent(address_space_id);
        return null;
    }

    pub fn indexedAddressSpaceSlot(self: *Runtime, address_space_id: u64) ?*AddressSpaceSlot {
        const slot_index = indexLookup(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id) orelse {
            self.debugAssertAddressSpaceIndexMissAbsent(address_space_id);
            return null;
        };
        if (slot_index >= self.address_spaces.len) native_util.impossibleByInvariant("address space index points outside slots");
        const slot = &self.address_spaces[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("address space index points at a free slot");
        if (slot.address_space.id != address_space_id) native_util.impossibleByInvariant("address space index points at the wrong slot");
        return slot;
    }

    fn indexedAddressSpaceSlotConst(self: *const Runtime, address_space_id: u64) ?*const AddressSpaceSlot {
        const slot_index = indexLookup(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id) orelse {
            self.debugAssertAddressSpaceIndexMissAbsent(address_space_id);
            return null;
        };
        if (slot_index >= self.address_spaces.len) native_util.impossibleByInvariant("address space index points outside slots");
        const slot = &self.address_spaces[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("address space index points at a free slot");
        if (slot.address_space.id != address_space_id) native_util.impossibleByInvariant("address space index points at the wrong slot");
        return slot;
    }

    fn indexedTaskSlot(self: *Runtime, task_id: u64) ?*TaskSlot {
        const slot_index = indexLookup(INDEX_CAPACITY, &self.task_index_slots, task_id) orelse {
            self.debugAssertTaskIndexMissAbsent(task_id);
            return null;
        };
        if (slot_index >= self.tasks.len) native_util.impossibleByInvariant("task index points outside slots");
        const slot = &self.tasks[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("task index points at a free slot");
        if (slot.task.id != task_id) native_util.impossibleByInvariant("task index points at the wrong slot");
        return slot;
    }

    fn indexedTaskSlotConst(self: *const Runtime, task_id: u64) ?*const TaskSlot {
        const slot_index = indexLookup(INDEX_CAPACITY, &self.task_index_slots, task_id) orelse {
            self.debugAssertTaskIndexMissAbsent(task_id);
            return null;
        };
        if (slot_index >= self.tasks.len) native_util.impossibleByInvariant("task index points outside slots");
        const slot = &self.tasks[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("task index points at a free slot");
        if (slot.task.id != task_id) native_util.impossibleByInvariant("task index points at the wrong slot");
        return slot;
    }

    pub fn noteAddressSpaceInstalled(self: *Runtime, address_space_id: u64, slot_index: usize) void {
        indexInsert(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id, slot_index);
    }

    pub fn removeAddressSpaceIndex(self: *Runtime, address_space_id: u64) void {
        indexRemove(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id);
    }

    fn debugAssertIndexIntegrity(self: *const Runtime) void {
        if (!debugIndexChecksEnabled()) return;
        for (self.tasks) |slot| {
            if (!slot.in_use) continue;
            _ = self.indexedTaskSlotConst(slot.task.id) orelse
                native_util.impossibleByInvariant("task index missing a live task");
            var capability_index: usize = 0;
            while (capability_index < slot.task.capability_count) : (capability_index += 1) {
                const capability_id = slot.task.capabilityIds()[capability_index];
                if (capability_id != 0 and !taskHasCapability(&slot.task, capability_id)) {
                    native_util.impossibleByInvariant("task capability index missing a live capability");
                }
            }
        }
        for (self.address_spaces) |slot| {
            if (!slot.in_use) continue;
            _ = self.indexedAddressSpaceSlotConst(slot.address_space.id) orelse
                native_util.impossibleByInvariant("address space index missing a live address space");
        }
    }

    fn debugAssertTaskIndexMissAbsent(self: *const Runtime, task_id: u64) void {
        if (!debugIndexChecksEnabled()) return;
        for (self.tasks) |slot| {
            if (slot.in_use and slot.task.id == task_id) {
                native_util.impossibleByInvariant("task index missed a live task");
            }
        }
    }

    fn debugAssertAddressSpaceIndexMissAbsent(self: *const Runtime, address_space_id: u64) void {
        if (!debugIndexChecksEnabled()) return;
        for (self.address_spaces) |slot| {
            if (slot.in_use and slot.address_space.id == address_space_id) {
                native_util.impossibleByInvariant("address space index missed a live address space");
            }
        }
    }

    pub fn grantCapability(self: *Runtime, task_id: u64, capability_id: u64) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        const cold = taskCold(task);
        if (taskHasCapability(task, capability_id)) return;
        if (task.capability_count >= MAX_TASK_CAPABILITIES) return error.CapabilityTableFull;
        cold.capability_ids[task.capability_count] = capability_id;
        cold.capability_index.insert(capability_id, task.capability_count);
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
            const last_index = task.capability_count - 1;
            const moved_capability_id = cold.capability_ids[last_index];

            cold.capability_index.remove(capability_id);
            if (index != last_index) {
                cold.capability_ids[index] = moved_capability_id;
                cold.capability_index.insert(moved_capability_id, index);
            }

            task.capability_count -= 1;
            cold.capability_ids[task.capability_count] = 0;
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
        resetTaskCold(taskCold(task));
        task.execution_component_count = 0;
        task.capability_count = 0;
        try self.audit(task_id, .{
            .kind = .terminated,
            .tick = tick,
        });
        return true;
    }
};

fn debugIndexChecksEnabled() bool {
    return builtin.mode == .Debug;
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
    try runtime.grantCapability(task.id, 13);
    try std.testing.expectEqual(@as(usize, 3), task.capability_count);
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.background_light, task.resourceClass());

    try std.testing.expect(try runtime.revokeCapability(task.id, 12));
    try std.testing.expectEqual(@as(usize, 2), task.capability_count);
    try std.testing.expect(runtime.hasCapability(task.id, 11));
    try std.testing.expect(!runtime.hasCapability(task.id, 12));
    try std.testing.expect(runtime.hasCapability(task.id, 13));
    try std.testing.expectEqual(@as(u64, 13), task.capabilityIds()[1]);
    try std.testing.expect(!try runtime.revokeCapability(task.id, 99));
}

test "restoring a snapshot rebuilds authoritative indexes" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 22 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 3_000,
            .memory_bytes = 4096,
            .endpoint_slots = 4,
            .shared_memory_bytes = 8192,
            .background_allowed = true,
        },
    });
    try runtime.grantCapability(task.id, 91);
    const task_id = task.id;
    const address_space_id = task.address_space_id;

    var snapshot = Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);

    var restored = Runtime.init();
    restored.restoreFromSnapshot(&snapshot);

    try std.testing.expect(restored.find(task_id) != null);
    try std.testing.expect(restored.findAddressSpaceConst(address_space_id) != null);
    try std.testing.expect(restored.hasCapability(task_id, 91));
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
