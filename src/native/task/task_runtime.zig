const accelerator_scheduler = @import("accelerator_scheduler.zig");
const builtin = @import("builtin");
const crypto_hash = @import("../core/crypto_hash.zig");
const debug_contract = @import("../security/debug_contract.zig");
const generated_image_fixtures = if (builtin.is_test) @import("generated_image_fixtures.zig") else struct {};
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const model = @import("task_runtime_model.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const std = @import("std");
const units = @import("../core/units.zig");

pub const MAX_TASKS = model.MAX_TASKS;
pub const MAX_TASK_CAPABILITIES = model.MAX_TASK_CAPABILITIES;
pub const MAX_TASK_COMPONENTS = model.MAX_TASK_COMPONENTS;
pub const MAX_AUDIT_EVENTS = model.MAX_AUDIT_EVENTS;
pub const MAX_TASK_PROVENANCE_EVENTS = model.MAX_TASK_PROVENANCE_EVENTS;
pub const MAX_TASK_BUNDLE_ID_BYTES = model.MAX_TASK_BUNDLE_ID_BYTES;
pub const MAX_COMPONENT_LABEL_BYTES = model.MAX_COMPONENT_LABEL_BYTES;
pub const MAX_COMPONENT_ENTRY_BYTES = model.MAX_COMPONENT_ENTRY_BYTES;
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
pub const ProvenanceRecord = model.ProvenanceRecord;
pub const LaunchProvenanceSpec = model.LaunchProvenanceSpec;
pub const LaunchProvenanceRecord = model.LaunchProvenanceRecord;
pub const TaskCreateRequest = model.TaskCreateRequest;
pub const TaskRecord = model.TaskRecord;
pub const Error = model.Error;
pub const Snapshot = model.Snapshot;
pub const syntheticUserspaceImage = model.syntheticUserspaceImage;

const INDEX_CAPACITY = model.INDEX_CAPACITY;
const IdIndexSlot = model.IdIndexSlot;
const TaskArena = model.TaskArena;
pub const TaskHandle = model.TaskHandle;
const TaskOwnerIndex = model.TaskOwnerIndex;
const TaskColdRecord = model.TaskColdRecord;
const TaskSlot = model.TaskSlot;
const AddressSpaceSlot = model.AddressSpaceSlot;
const allocateHost = model.allocateHost;
const reassignHost = model.reassignHost;
const saturatingSub = model.saturatingSub;
const emptyIndexTable = model.emptyIndexTable;
const zeroTaskCold = model.zeroTaskCold;
const resetTaskCold = model.resetTaskCold;
const copyTaskColdForTask = model.copyTaskColdForTask;
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
const taskOwnerIndexKey = model.taskOwnerIndexKey;
const rebuildCapabilityIndex = model.rebuildCapabilityIndex;
const validateUserspaceImage = model.validateUserspaceImage;
const TEST_TASK_MEMORY_BYTES: usize = units.kibibytes(4);
const TEST_MINIMAL_MEMORY_BYTES: usize = 256;
const TEST_MINIMAL_SHARED_MEMORY_BYTES: usize = 512;
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
    address_space_index_slots: [INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(INDEX_CAPACITY),
    tasks: TaskArena = TaskArena.init(),
    task_owner_index: TaskOwnerIndex = TaskOwnerIndex.init(),
    task_cold: [MAX_TASKS]TaskColdRecord = [_]TaskColdRecord{zeroTaskCold()} ** MAX_TASKS,
    address_spaces: [MAX_TASKS]AddressSpaceSlot = [_]AddressSpaceSlot{AddressSpaceSlot{}} ** MAX_TASKS,

    pub fn init() Runtime {
        return Runtime{};
    }

    pub fn initSnapshot() Snapshot {
        return Snapshot{};
    }

    pub fn reset(self: *Runtime) void {
        self.next_task_id = 1;
        self.next_process_id = 1;
        self.next_address_space_id = 1;
        self.next_namespace_id = 1;
        self.next_component_id = 1;
        self.address_space_index_slots = emptyIndexTable(INDEX_CAPACITY);
        self.tasks.reset();
        self.task_owner_index.reset();
        for (&self.task_cold) |*cold| {
            cold.* = zeroTaskCold();
        }
        for (&self.address_spaces) |*slot| {
            slot.* = AddressSpaceSlot{};
        }
    }

    pub fn writeSnapshot(self: *const Runtime, out: *Snapshot) void {
        out.next_task_id = self.next_task_id;
        out.next_process_id = self.next_process_id;
        out.next_address_space_id = self.next_address_space_id;
        out.next_namespace_id = self.next_namespace_id;
        out.next_component_id = self.next_component_id;
        out.task_count = 0;
        var slot_index: usize = 0;
        while (slot_index < MAX_TASKS) : (slot_index += 1) {
            const slot = self.tasks.slotAtConst(slot_index).*;
            if (!slot.in_use) continue;
            const dense_index = out.task_count;
            out.tasks[dense_index] = slot;
            copyTaskColdForTask(&out.task_cold[dense_index], &self.task_cold[slot_index], &slot.task);
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
        self.resetForSnapshotRestore();
        self.next_task_id = state.next_task_id;
        self.next_process_id = state.next_process_id;
        self.next_address_space_id = state.next_address_space_id;
        self.next_namespace_id = state.next_namespace_id;
        self.next_component_id = state.next_component_id;

        var task_index: usize = 0;
        while (task_index < state.task_count) : (task_index += 1) {
            const task_id = state.tasks[task_index].task.id;
            const slot_index = self.tasks.reserveIndexAt(task_id, task_index) orelse {
                native_util.impossibleByInvariant("task snapshot count is bounded by task arena capacity");
            };
            self.tasks.slotAt(slot_index).* = state.tasks[task_index];
            copyTaskColdForTask(&self.task_cold[task_index], &state.task_cold[task_index], &state.tasks[task_index].task);
        }

        var address_space_index: usize = 0;
        while (address_space_index < state.address_space_count) : (address_space_index += 1) {
            self.address_spaces[address_space_index] = state.address_spaces[address_space_index];
        }
        self.rebuildIndexes();
        self.debugAssertIndexIntegrity();
    }

    fn resetForSnapshotRestore(self: *Runtime) void {
        self.next_task_id = 1;
        self.next_process_id = 1;
        self.next_address_space_id = 1;
        self.next_namespace_id = 1;
        self.next_component_id = 1;
        self.address_space_index_slots = emptyIndexTable(INDEX_CAPACITY);
        self.tasks.reset();
        self.task_owner_index.reset();
        for (&self.address_spaces) |*slot| {
            slot.* = AddressSpaceSlot{};
        }
    }

    pub fn rebuildIndexes(self: *Runtime) void {
        self.tasks.rebuildPrimaryIndex();
        self.task_owner_index.reset();
        self.address_space_index_slots = emptyIndexTable(INDEX_CAPACITY);

        var slot_index: usize = 0;
        while (slot_index < MAX_TASKS) : (slot_index += 1) {
            const slot = self.tasks.slotAt(slot_index);
            if (!slot.in_use) continue;
            slot.task.cold_state = &self.task_cold[slot_index];
            if (!self.task_owner_index.append(taskOwnerIndexKey(slot.task.owner), slot_index)) {
                native_util.impossibleByInvariant("task owner index capacity covers task slots");
            }
            rebuildCapabilityIndex(&slot.task);
        }

        for (self.address_spaces, 0..) |slot, address_space_slot_index| {
            if (!slot.in_use) continue;
            indexInsert(INDEX_CAPACITY, &self.address_space_index_slots, slot.address_space.id, address_space_slot_index);
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
        const task_id = self.next_task_id;
        const slot_index = self.tasks.reserveIndex(task_id) orelse return error.TaskTableFull;
        errdefer _ = self.tasks.removeIndex(slot_index);

        const initial_component = makeExecutionComponent(self, defaultInitialComponent(request));
        const host = try allocateHost(
            self,
            request.component_class,
            task_id,
            request.launch.image_id,
            userspace_image,
        );

        self.next_task_id += 1;
        const slot = self.tasks.slotAt(slot_index);
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
            .provenance_start = 0,
            .provenance_count = 0,
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
        appendProvenanceToTask(&slot.task, debug_contract.launchProvenance(
            task_id,
            0,
            request.launch.image_id,
            request.launch.signed,
            @tagName(request.launch.boundary),
            request.launch.bundle_id,
            request.launch.source_identity,
            request.launch.release_transparency_sequence,
            request.launch.release_transparency_root,
            request.launch.release_transparency_log_head,
        ));
        if (!self.task_owner_index.append(taskOwnerIndexKey(slot.task.owner), slot_index)) {
            native_util.impossibleByInvariant("task owner index capacity covers task slots");
        }
        return &slot.task;
    }

    pub fn find(self: *Runtime, task_id: u64) ?*TaskRecord {
        if (self.indexedTaskSlot(task_id)) |slot| return &slot.task;
        self.debugAssertTaskIndexMissAbsent(task_id);
        return null;
    }

    pub fn taskSlotCapacity(self: *const Runtime) usize {
        _ = self;
        return MAX_TASKS;
    }

    pub fn taskCount(self: *const Runtime) usize {
        return self.tasks.countInUse();
    }

    pub fn taskSlotAt(self: *Runtime, slot_index: usize) *TaskSlot {
        return self.tasks.slotAt(slot_index);
    }

    pub fn taskSlotAtConst(self: *const Runtime, slot_index: usize) *const TaskSlot {
        return self.tasks.slotAtConst(slot_index);
    }

    pub fn taskHandle(self: *const Runtime, task_id: u64) ?TaskHandle {
        const slot_index = self.tasks.slotIndexOf(task_id) orelse return null;
        return self.tasks.handleForIndex(slot_index);
    }

    fn findConst(self: *const Runtime, task_id: u64) ?*const TaskRecord {
        if (self.indexedTaskSlotConst(task_id)) |slot| return &slot.task;
        self.debugAssertTaskIndexMissAbsent(task_id);
        return null;
    }

    pub fn findByOwner(self: *const Runtime, owner: principal.PrincipalId) ?*const TaskRecord {
        const key = taskOwnerIndexKey(owner);
        var slot_index = self.task_owner_index.head(key);
        while (slot_index != indexed_arena.no_index) : (slot_index = self.task_owner_index.next(slot_index)) {
            if (slot_index >= MAX_TASKS) native_util.impossibleByInvariant("task owner index points outside task slots");
            const slot = self.tasks.slotAtConst(slot_index);
            if (!slot.in_use) native_util.impossibleByInvariant("task owner index points at a free slot");
            if (slot.task.owner.eql(owner)) return &slot.task;
        }
        self.debugAssertOwnerIndexMissAbsent(owner);
        return null;
    }

    pub fn findAddressSpace(self: *Runtime, address_space_id: u64) ?*AddressSpaceRecord {
        const slot = findAddressSpaceSlot(self, address_space_id) orelse return null;
        return &slot.address_space;
    }

    pub fn allowHostPointerSyscallsForTask(self: *Runtime, task_id: u64) void {
        const task = self.find(task_id).?;
        const address_space = self.findAddressSpace(task.address_space_id).?;
        // Host-side syscall proofs pass pointers from the native test stack.
        address_space.region_count = 0;
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
        return self.tasks.get(task_id);
    }

    fn indexedTaskSlotConst(self: *const Runtime, task_id: u64) ?*const TaskSlot {
        return self.tasks.getConst(task_id);
    }

    pub fn noteAddressSpaceInstalled(self: *Runtime, address_space_id: u64, slot_index: usize) void {
        indexInsert(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id, slot_index);
    }

    pub fn removeAddressSpaceIndex(self: *Runtime, address_space_id: u64) void {
        indexRemove(INDEX_CAPACITY, &self.address_space_index_slots, address_space_id);
    }

    fn debugAssertIndexIntegrity(self: *const Runtime) void {
        if (!debugIndexChecksEnabled()) return;
        var slot_index: usize = 0;
        while (slot_index < MAX_TASKS) : (slot_index += 1) {
            const slot = self.tasks.slotAtConst(slot_index);
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
        var slot_index: usize = 0;
        while (slot_index < MAX_TASKS) : (slot_index += 1) {
            const slot = self.tasks.slotAtConst(slot_index);
            if (slot.in_use and slot.task.id == task_id) {
                native_util.impossibleByInvariant("task index missed a live task");
            }
        }
    }

    fn debugAssertOwnerIndexMissAbsent(self: *const Runtime, owner: principal.PrincipalId) void {
        if (!debugIndexChecksEnabled()) return;
        var slot_index: usize = 0;
        while (slot_index < MAX_TASKS) : (slot_index += 1) {
            const slot = self.tasks.slotAtConst(slot_index);
            if (slot.in_use and slot.task.owner.eql(owner)) {
                native_util.impossibleByInvariant("task owner index missed a live task");
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
        appendProvenanceToTask(task, debug_contract.capabilityGrantProvenance(task_id, capability_id, 0));
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
            appendProvenanceToTask(task, debug_contract.capabilityRevokeProvenance(task_id, capability_id, 0));
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
        appendProvenanceToTask(task, debug_contract.launchProvenance(
            task_id,
            tick,
            task.launch.image_id,
            task.launch.signed,
            "service-restart",
            task.launchBundleIdSlice(),
            task.launchSourceIdentitySlice(),
            task.launch.release_transparency_sequence,
            task.launch.release_transparency_root,
            task.launch.release_transparency_log_head,
        ));
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

    pub fn recordProvenance(self: *Runtime, task_id: u64, event: ProvenanceRecord) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        appendProvenanceToTask(task, event);
    }

    pub fn recordCrashReport(
        self: *Runtime,
        task_id: u64,
        service_id: u64,
        tick: u64,
        crash_code: u32,
        redaction_policy_version: u16,
        reason_fingerprint: u64,
        redacted: bool,
    ) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        appendProvenanceToTask(task, debug_contract.crashReportProvenance(
            task_id,
            service_id,
            tick,
            crash_code,
            redaction_policy_version,
            reason_fingerprint,
            redacted,
        ));
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

fn appendProvenanceToTask(task: *TaskRecord, event: ProvenanceRecord) void {
    const cold = taskCold(task);
    if (task.provenance_count < MAX_TASK_PROVENANCE_EVENTS) {
        const slot_index = (task.provenance_start + task.provenance_count) % MAX_TASK_PROVENANCE_EVENTS;
        cold.provenance_trail[slot_index] = event;
        task.provenance_count += 1;
        return;
    }

    cold.provenance_trail[task.provenance_start] = event;
    task.provenance_start = (task.provenance_start + 1) % MAX_TASK_PROVENANCE_EVENTS;
}

test "new tasks start with zero ambient authority and no capabilities" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
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
    try std.testing.expectEqual(@as(usize, 1), task.provenance_count);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.launch, task.provenanceEventAt(0).?.kind);
    try std.testing.expectEqual(debug_contract.Decision.allowed, task.provenanceEventAt(0).?.decision);
}

test "task runtime crosses the first task slab page with indexed handles" {
    var runtime = Runtime.init();
    var last_task_id: u64 = 0;
    var last_owner = principal.PrincipalId{ .kind = .app, .serial = 0 };

    var index: usize = 0;
    while (index < model.TASK_PAGE_SIZE + 5) : (index += 1) {
        const owner = principal.PrincipalId{ .kind = .app, .serial = @intCast(index + 1) };
        const task = try runtime.createTask(.{
            .owner = owner,
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = units.kibibytes(1),
                .endpoint_slots = 2,
                .shared_memory_bytes = units.kibibytes(1),
            },
        });
        last_task_id = task.id;
        last_owner = owner;
    }

    try std.testing.expectEqual(@as(usize, model.TASK_PAGE_SIZE + 5), runtime.taskCount());
    try std.testing.expect(runtime.find(last_task_id) != null);
    try std.testing.expectEqual(last_task_id, runtime.findByOwner(last_owner).?.id);
    try std.testing.expect(runtime.taskHandle(last_task_id) != null);
}

test "granting and revoking capabilities updates the task table" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 2 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 5_000,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 8,
            .shared_memory_bytes = units.kibibytes(8),
            .background_allowed = true,
        },
    });

    try runtime.grantCapability(task.id, 11);
    try runtime.grantCapability(task.id, 12);
    try runtime.grantCapability(task.id, 13);
    try std.testing.expectEqual(@as(usize, 3), task.capability_count);
    try std.testing.expectEqual(@as(usize, 4), task.provenance_count);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.capability_grant, task.latestProvenanceEvent().?.kind);
    try std.testing.expectEqual(@as(u64, 13), task.latestProvenanceEvent().?.capability_id);
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.background_light, task.resourceClass());

    try std.testing.expect(try runtime.revokeCapability(task.id, 12));
    try std.testing.expectEqual(@as(usize, 2), task.capability_count);
    try std.testing.expect(runtime.hasCapability(task.id, 11));
    try std.testing.expect(!runtime.hasCapability(task.id, 12));
    try std.testing.expect(runtime.hasCapability(task.id, 13));
    try std.testing.expectEqual(@as(u64, 13), task.capabilityIds()[1]);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.capability_revoke, task.latestProvenanceEvent().?.kind);
    try std.testing.expectEqual(@as(u64, 12), task.latestProvenanceEvent().?.capability_id);
    try std.testing.expect(!try runtime.revokeCapability(task.id, 99));
}

test "task runtime records redacted crash report provenance" {
    var runtime = Runtime.init();
    const service_image = try generated_image_fixtures.storageServiceImage();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 30 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 3_000,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(8),
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 51,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.crash-provenance",
        },
        .userspace_image = &service_image,
    });

    try runtime.recordCrashReport(task.id, 704, 77, 0xCA11, 1, 0xFEED, true);
    const latest = task.latestProvenanceEvent().?;
    try std.testing.expectEqual(debug_contract.ProvenanceKind.crash_report, latest.kind);
    try std.testing.expectEqual(@as(u64, 704), latest.service_id);
    try std.testing.expect(std.mem.indexOf(u8, latest.detailSlice(), "redacted=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest.detailSlice(), "reason_fingerprint=0xfeed") != null);
}

test "restoring a snapshot rebuilds authoritative indexes" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 22 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 3_000,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(8),
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

    const restored_task = restored.find(task_id).?;
    try std.testing.expect(restored.findAddressSpaceConst(address_space_id) != null);
    try std.testing.expect(restored.hasCapability(task_id, 91));
    try std.testing.expectEqual(@as(usize, 2), restored_task.provenance_count);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.capability_grant, restored_task.latestProvenanceEvent().?.kind);
    try std.testing.expectEqual(@as(u64, 91), restored_task.latestProvenanceEvent().?.capability_id);
}

test "explicit resource classes override the default task classification" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 500,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
            .resource_class = .batch_compute,
            .background_allowed = true,
        },
        .local_only = true,
    });

    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.batch_compute, task.resourceClass());
}

test "userspace launch provenance is recorded for explicit image launches" {
    var runtime = Runtime.init();
    const notes_image = try generated_image_fixtures.imageByBundleId("app.notes");
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 12 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
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
            .source_identity = "store:zigos/public",
            .release_transparency_sequence = 7,
            .release_transparency_root = crypto_hash.digestFromByte(0x91),
            .release_transparency_log_head = crypto_hash.digestFromByte(0x92),
        },
        .userspace_image = &notes_image,
    });

    try std.testing.expect(task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(u64, 44), task.launch.image_id);
    try std.testing.expect(task.launch.signed);
    try std.testing.expect(task.hasLoadedExecutable());
    try std.testing.expectEqualStrings("app.notes", task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("store:zigos/public", task.launchSourceIdentitySlice());
    try std.testing.expect(task.launch.hasReleaseTransparency());
    try std.testing.expectEqual(@as(u64, 7), task.launch.release_transparency_sequence);
    const expected_root = crypto_hash.digestFromByte(0x91);
    const expected_log_head = crypto_hash.digestFromByte(0x92);
    const expected_root_fingerprint = native_util.fnv1a64(&expected_root);
    const expected_log_head_fingerprint = native_util.fnv1a64(&expected_log_head);
    try std.testing.expect(std.mem.eql(u8, &expected_root, &task.launch.release_transparency_root));
    try std.testing.expect(std.mem.eql(u8, &expected_log_head, &task.launch.release_transparency_log_head));
    try std.testing.expectEqual(debug_contract.ProvenanceKind.launch, task.latestProvenanceEvent().?.kind);
    try std.testing.expectEqual(@as(u64, 44), task.latestProvenanceEvent().?.artifact_id);
    try std.testing.expectEqual(native_util.fnv1a64("store:zigos/public"), task.latestProvenanceEvent().?.source_identity_fingerprint);
    try std.testing.expect(task.latestProvenanceEvent().?.hasReleaseTransparency());
    try std.testing.expectEqual(@as(u64, 7), task.latestProvenanceEvent().?.release_transparency_sequence);
    try std.testing.expectEqual(expected_root_fingerprint, task.latestProvenanceEvent().?.release_transparency_root_fingerprint);
    try std.testing.expectEqual(expected_log_head_fingerprint, task.latestProvenanceEvent().?.release_transparency_log_head_fingerprint);
    try std.testing.expect(std.mem.indexOf(u8, task.latestProvenanceEvent().?.detailSlice(), "source=store:zigos/public") != null);
    try std.testing.expect(std.mem.indexOf(u8, task.latestProvenanceEvent().?.detailSlice(), "seq=7") != null);
    try std.testing.expect(task.latestProvenanceEvent().?.trace_id != 0);
}

test "userspace tasks materialize executable mappings in their address spaces" {
    var runtime = Runtime.init();
    const workspace_storage_image = try generated_image_fixtures.storageServiceImage();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 13 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_500,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
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
            .memory_bytes = TEST_MINIMAL_MEMORY_BYTES,
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
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
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
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
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
    });
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 10 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
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
    const sync_service_image = try generated_image_fixtures.syncServiceImage();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 14 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
        .initial_component = .{
            .label = "sync-service",
            .entry = "zigos.sync.replication",
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
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
    });

    try runtime.grantCapability(task.id, 77);
    try std.testing.expect(try runtime.terminateTask(task.id, 44));
    try std.testing.expectEqual(TaskState.terminated, task.state);
    try std.testing.expectEqual(@as(usize, 0), task.execution_component_count);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expectEqual(AuditEventKind.terminated, task.latestAuditEvent().?.kind);
}
