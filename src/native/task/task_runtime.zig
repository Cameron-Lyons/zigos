const accelerator_scheduler = @import("accelerator_scheduler.zig");
const address_space_retirement = @import("address_space_retirement.zig");
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
const root = @import("root");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

pub const MAX_TASKS = model.MAX_TASKS;
pub const MAX_TASK_CAPABILITIES = model.MAX_TASK_CAPABILITIES;
pub const TASK_CAPABILITY_SCAN_BOUND = model.TASK_CAPABILITY_SCAN_BOUND;
pub const TASK_CAPABILITY_PRIMARY_INDEX_LOOKUPS_PER_OPERATION = model.TASK_CAPABILITY_PRIMARY_INDEX_LOOKUPS_PER_OPERATION;
pub const MAX_TASK_COMPONENTS = model.MAX_TASK_COMPONENTS;
pub const MAX_AUDIT_EVENTS = model.MAX_AUDIT_EVENTS;
pub const MAX_TASK_PROVENANCE_EVENTS = model.MAX_TASK_PROVENANCE_EVENTS;
pub const MAX_TASK_BUNDLE_ID_BYTES = model.MAX_TASK_BUNDLE_ID_BYTES;
pub const MAX_TASK_SOURCE_IDENTITY_BYTES = model.MAX_TASK_SOURCE_IDENTITY_BYTES;
pub const MAX_COMPONENT_LABEL_BYTES = model.MAX_COMPONENT_LABEL_BYTES;
pub const MAX_COMPONENT_ENTRY_BYTES = model.MAX_COMPONENT_ENTRY_BYTES;
pub const MAX_EXECUTABLE_SEGMENTS = model.MAX_EXECUTABLE_SEGMENTS;
pub const ORDERED_EXECUTABLE_SEGMENTS = model.ORDERED_EXECUTABLE_SEGMENTS;
pub const MAX_IMAGE_HASH_BYTES = model.MAX_IMAGE_HASH_BYTES;
pub const DEFAULT_USER_STACK_TOP = model.DEFAULT_USER_STACK_TOP;
pub const DEFAULT_USER_STACK_SIZE_BYTES = model.DEFAULT_USER_STACK_SIZE_BYTES;
pub const DEFAULT_SYNTHETIC_ENTRY_POINT = model.DEFAULT_SYNTHETIC_ENTRY_POINT;
pub const DEFAULT_SYNTHETIC_IMAGE_BYTES = model.DEFAULT_SYNTHETIC_IMAGE_BYTES;
pub const TaskStateCount = u8;
pub const COMPACT_LIFECYCLE_METADATA = true;
pub const SNAPSHOT_RESTORE_REUSES_LIVE_COLD_BACKING = true;
pub const TERMINATION_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const HOST_RUNTIME_SIZE_CEILING_BYTES: usize = 599_664;
pub const FREESTANDING_RUNTIME_SIZE_CEILING_BYTES: usize = 69_624;
pub const RUNTIME_SIZE_CEILING_BYTES: usize = if (builtin.target.os.tag == .freestanding)
    FREESTANDING_RUNTIME_SIZE_CEILING_BYTES
else
    HOST_RUNTIME_SIZE_CEILING_BYTES;
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
pub const AddressSpaceRetirementEvent = address_space_retirement.Event;
pub const AddressSpaceRetirementReason = address_space_retirement.Reason;
pub const AddressSpaceRetirementSink = address_space_retirement.Sink;
pub const ExecutionComponentSpec = model.ExecutionComponentSpec;
pub const ExecutionComponentRecord = model.ExecutionComponentRecord;
pub const ResourceBudget = model.ResourceBudget;
pub const AuditEventKind = model.AuditEventKind;
pub const AuditEvent = model.AuditEvent;
pub const ProvenanceRecord = model.ProvenanceRecord;
pub const TaskProvenanceRecord = model.TaskProvenanceRecord;
pub const LaunchProvenanceSpec = model.LaunchProvenanceSpec;
pub const LaunchProvenanceRecord = model.LaunchProvenanceRecord;
pub const TaskCreateRequest = model.TaskCreateRequest;
pub const TaskRecord = model.TaskRecord;
pub const Error = model.Error;
pub const Snapshot = model.Snapshot;
pub const syntheticUserspaceImage = model.syntheticUserspaceImage;

comptime {
    if (MAX_TASKS > std.math.maxInt(TaskStateCount)) {
        @compileError("task state counts no longer fit in u8");
    }
}

pub const BackgroundWorkReservation = struct {
    task_id: u64,
    expected_active_count: u16,
    expected_cpu_consumed_ticks: u64,
    expected_reserved_memory_bytes: usize,
    expected_reserved_shared_memory_bytes: usize,
    active_count: u16,
    cpu_consumed_ticks: u64,
    reserved_memory_bytes: usize,
    reserved_shared_memory_bytes: usize,
    network: manifest.BackgroundNetworkMode,
    visibility: manifest.BackgroundVisibility,
    tick: u64,
};

const BackgroundCapacity = struct {
    active_count: u16,
    cpu_consumed_ticks: u64,
    reserved_memory_bytes: usize,
    reserved_shared_memory_bytes: usize,
};

pub fn planBackgroundWork(
    task: *const TaskRecord,
    budget: manifest.BackgroundResourceBudget,
    network: manifest.BackgroundNetworkMode,
    visibility: manifest.BackgroundVisibility,
    tick: u64,
) ?BackgroundWorkReservation {
    const capacity = planBackgroundCapacity(task, budget) orelse return null;
    return .{
        .task_id = task.id,
        .expected_active_count = task.background_active_count,
        .expected_cpu_consumed_ticks = task.background_cpu_consumed_ticks,
        .expected_reserved_memory_bytes = task.background_reserved_memory_bytes,
        .expected_reserved_shared_memory_bytes = task.background_reserved_shared_memory_bytes,
        .active_count = capacity.active_count,
        .cpu_consumed_ticks = capacity.cpu_consumed_ticks,
        .reserved_memory_bytes = capacity.reserved_memory_bytes,
        .reserved_shared_memory_bytes = capacity.reserved_shared_memory_bytes,
        .network = network,
        .visibility = visibility,
        .tick = tick,
    };
}

pub fn commitBackgroundWork(task: *TaskRecord, reservation: BackgroundWorkReservation) void {
    if (task.id != reservation.task_id or
        task.background_active_count != reservation.expected_active_count or
        task.background_cpu_consumed_ticks != reservation.expected_cpu_consumed_ticks or
        task.background_reserved_memory_bytes != reservation.expected_reserved_memory_bytes or
        task.background_reserved_shared_memory_bytes != reservation.expected_reserved_shared_memory_bytes)
    {
        native_util.impossibleByInvariant("background reservation must commit to its unchanged task");
    }

    task.background_active_count = reservation.active_count;
    task.background_cpu_consumed_ticks = reservation.cpu_consumed_ticks;
    task.background_reserved_memory_bytes = reservation.reserved_memory_bytes;
    task.background_reserved_shared_memory_bytes = reservation.reserved_shared_memory_bytes;
    task.background_peak_memory_bytes = @max(task.background_peak_memory_bytes, reservation.reserved_memory_bytes);
    task.background_peak_shared_memory_bytes = @max(task.background_peak_shared_memory_bytes, reservation.reserved_shared_memory_bytes);
    task.last_background_network = reservation.network;
    task.last_background_visibility = reservation.visibility;
    task.last_background_tick = reservation.tick;
}

fn planBackgroundCapacity(task: *const TaskRecord, budget: manifest.BackgroundResourceBudget) ?BackgroundCapacity {
    if (task.state != .active or !task.background_allowed) return null;

    const active_count = std.math.add(u16, task.background_active_count, 1) catch return null;
    const cpu_consumed_ticks = std.math.add(u64, task.background_cpu_consumed_ticks, budget.cpu_time_ticks) catch return null;
    if (cpu_consumed_ticks > task.budget.cpu_time_ticks) return null;

    const reserved_memory_bytes = std.math.add(usize, task.background_reserved_memory_bytes, budget.memory_bytes) catch return null;
    if (reserved_memory_bytes > task.budget.memory_bytes) return null;

    const reserved_shared_memory_bytes = std.math.add(usize, task.background_reserved_shared_memory_bytes, budget.shared_memory_bytes) catch return null;
    if (reserved_shared_memory_bytes > task.budget.shared_memory_bytes) return null;

    return .{
        .active_count = active_count,
        .cpu_consumed_ticks = cpu_consumed_ticks,
        .reserved_memory_bytes = reserved_memory_bytes,
        .reserved_shared_memory_bytes = reserved_shared_memory_bytes,
    };
}

const TaskArena = model.TaskArena;
pub const TaskHandle = model.TaskHandle;
const TaskOwnerIndex = model.TaskOwnerIndex;
pub const TaskColdRecord = model.TaskColdRecord;
const TaskSlot = model.TaskSlot;
const AddressSpaceSlot = model.AddressSpaceSlot;
const allocateHost = model.allocateHost;
const reassignHost = model.reassignHost;
const saturatingSub = model.saturatingSub;
const zeroTaskCold = model.zeroTaskCold;
const resetTaskCold = model.resetTaskCold;
const copyTaskColdForTask = model.copyTaskColdForTask;
const copyTaskColdStates = model.copyTaskColdStates;
const bindTaskColdStates = model.bindTaskColdStates;
const taskCold = model.taskCold;
const taskColdConst = model.taskColdConst;
const taskCapabilityIndex = model.taskCapabilityIndex;
const taskOwnerIndexKey = model.taskOwnerIndexKey;
const validateUserspaceImage = model.validateUserspaceImage;
const TEST_TASK_MEMORY_BYTES: usize = units.kibibytes(4);
const TEST_MINIMAL_MEMORY_BYTES: usize = 256;
const TEST_MINIMAL_SHARED_MEMORY_BYTES: usize = 512;
const TASK_STATE_COUNT: usize = @typeInfo(TaskState).@"enum".fields.len;
const TASK_LABEL_INDEX_CAPACITY: usize = MAX_TASKS * 2;
const TaskInitialComponentLabelIndex = indexed_arena.MultimapIndex(MAX_TASKS, MAX_TASKS, TASK_LABEL_INDEX_CAPACITY);
const heap_backed_task_cold = builtin.target.os.tag == .freestanding;
pub const HEAP_BACKED_ADDRESS_SPACE_ARENA_ON_FREESTANDING = true;
const heap_backed_address_spaces = builtin.target.os.tag == .freestanding and HEAP_BACKED_ADDRESS_SPACE_ARENA_ON_FREESTANDING;
const TaskColdRecords = [MAX_TASKS]TaskColdRecord;
const TaskColdBacking = if (heap_backed_task_cold) ?*TaskColdRecords else TaskColdRecords;
const AddressSpaceBacking = if (heap_backed_address_spaces) ?*model.AddressSpaceArena else model.AddressSpaceArena;
const findAddressSpaceSlot = model.findAddressSpaceSlot;
const defaultInitialComponent = model.defaultInitialComponent;
const makeLaunchProvenance = model.makeLaunchProvenance;
const zeroExecutionComponent = model.zeroExecutionComponent;

fn initializeTaskMultimapIndex(index: anytype) void {
    const Index = @TypeOf(index.*);
    const CompactIndex = @FieldType(Index, "free_bucket_head");
    const compact_no_index: CompactIndex = @intCast(@max(index.links.len, index.buckets.len));
    @memset(std.mem.asBytes(index), 0);
    for (&index.links) |*link| link.bucket = compact_no_index;
    index.free_bucket_head = compact_no_index;
}

pub const Runtime = struct {
    pub const AddressSpaceArenaType = model.AddressSpaceArena;
    pub const AddressSpaceSlotType = AddressSpaceSlot;
    pub const AddressSpaceRecordType = AddressSpaceRecord;
    pub const AddressSpaceRegionType = AddressSpaceRegionRecord;

    next_task_id: u64 = 1,
    next_process_id: u64 = 1,
    next_address_space_id: u64 = 1,
    next_namespace_id: u64 = 1,
    next_component_id: u64 = 1,
    tasks: TaskArena = TaskArena.init(),
    task_owner_index: TaskOwnerIndex = TaskOwnerIndex.init(),
    task_initial_component_label_index: TaskInitialComponentLabelIndex = TaskInitialComponentLabelIndex.init(),
    task_state_counts: [TASK_STATE_COUNT]TaskStateCount = [_]TaskStateCount{0} ** TASK_STATE_COUNT,
    task_lifecycle_generation: u64 = 1,
    task_cold: TaskColdBacking = if (heap_backed_task_cold) null else [_]TaskColdRecord{zeroTaskCold()} ** MAX_TASKS,
    address_spaces: AddressSpaceBacking = if (heap_backed_address_spaces) null else model.AddressSpaceArena.init(),
    address_space_retirement_sink: ?AddressSpaceRetirementSink = null,

    comptime {
        if (@sizeOf(@This()) > RUNTIME_SIZE_CEILING_BYTES) {
            @compileError("task runtime exceeded its target-specific compact size ceiling");
        }
    }

    pub fn init() Runtime {
        return Runtime{};
    }

    pub fn initializeAllocated(self: *Runtime) void {
        @memset(std.mem.asBytes(self), 0);
        self.next_task_id = 1;
        self.next_process_id = 1;
        self.next_address_space_id = 1;
        self.next_namespace_id = 1;
        self.next_component_id = 1;
        self.tasks.free_head = indexed_arena.reusableNoIndex(MAX_TASKS);
        initializeTaskMultimapIndex(&self.task_owner_index);
        initializeTaskMultimapIndex(&self.task_initial_component_label_index);
        self.task_lifecycle_generation = 1;
        if (comptime !heap_backed_task_cold) {
            self.task_cold = [_]TaskColdRecord{zeroTaskCold()} ** MAX_TASKS;
        }
        if (comptime !heap_backed_address_spaces) {
            self.address_spaces = model.AddressSpaceArena.init();
        }
    }

    pub fn initSnapshot() Snapshot {
        return Snapshot{};
    }

    pub fn bindAddressSpaceRetirementSink(self: *Runtime, sink: AddressSpaceRetirementSink) bool {
        if (self.address_space_retirement_sink != null) return false;
        self.address_space_retirement_sink = sink;
        return true;
    }

    pub fn unbindAddressSpaceRetirementSink(self: *Runtime, expected: AddressSpaceRetirementSink) bool {
        const current = self.address_space_retirement_sink orelse return false;
        if (!current.eql(expected)) return false;
        self.address_space_retirement_sink = null;
        return true;
    }

    fn taskColdRecords(self: *Runtime) ?*TaskColdRecords {
        if (comptime heap_backed_task_cold) return self.task_cold;
        return &self.task_cold;
    }

    fn taskColdRecordsConst(self: *const Runtime) ?*const TaskColdRecords {
        if (comptime heap_backed_task_cold) return self.task_cold;
        return &self.task_cold;
    }

    fn ensureTaskColdRecords(self: *Runtime) error{NoSpaceLeft}!*TaskColdRecords {
        if (self.taskColdRecords()) |records| return records;
        if (comptime heap_backed_task_cold) {
            const allocation = kernel_memory.kmalloc(@sizeOf(TaskColdRecords)) orelse return error.NoSpaceLeft;
            const records: *TaskColdRecords = @ptrCast(@alignCast(allocation));
            @memset(std.mem.asBytes(records), 0);
            self.task_cold = records;
            return records;
        }
        return &self.task_cold;
    }

    fn clearTaskColdRecords(self: *Runtime, count: usize) void {
        self.clearTaskColdRecordRange(0, count);
    }

    fn clearTaskColdRecordRange(self: *Runtime, first: usize, end: usize) void {
        const records = self.taskColdRecords() orelse return;
        const bounded_first = @min(first, records.len);
        const bounded_end = @min(@max(first, end), records.len);
        for (records[bounded_first..bounded_end]) |*cold| resetTaskCold(cold);
    }

    fn releaseTaskColdRecords(self: *Runtime) void {
        if (comptime heap_backed_task_cold) {
            if (self.task_cold) |records| {
                @memset(std.mem.asBytes(records), 0);
                kernel_memory.kfree(@ptrCast(records));
                self.task_cold = null;
            }
        } else {
            self.clearTaskColdRecords(MAX_TASKS);
        }
    }

    fn addressSpaceArena(self: *Runtime) ?*model.AddressSpaceArena {
        if (comptime heap_backed_address_spaces) return self.address_spaces;
        return &self.address_spaces;
    }

    fn addressSpaceArenaConst(self: *const Runtime) ?*const model.AddressSpaceArena {
        if (comptime heap_backed_address_spaces) return self.address_spaces;
        return &self.address_spaces;
    }

    fn ensureAddressSpaceArena(self: *Runtime) error{NoSpaceLeft}!*model.AddressSpaceArena {
        if (self.addressSpaceArena()) |arena| return arena;
        if (comptime heap_backed_address_spaces) {
            const allocation = kernel_memory.kmalloc(@sizeOf(model.AddressSpaceArena)) orelse return error.NoSpaceLeft;
            const arena: *model.AddressSpaceArena = @ptrCast(@alignCast(allocation));
            @memset(std.mem.asBytes(arena), 0);
            arena.free_head = indexed_arena.reusableNoIndex(MAX_TASKS);
            self.address_spaces = arena;
            return arena;
        }
        return &self.address_spaces;
    }

    fn releaseAddressSpaceArena(self: *Runtime) void {
        if (comptime heap_backed_address_spaces) {
            if (self.address_spaces) |arena| {
                @memset(std.mem.asBytes(arena), 0);
                kernel_memory.kfree(@ptrCast(arena));
                self.address_spaces = null;
            }
        } else {
            self.address_spaces.reset();
        }
    }

    pub fn reset(self: *Runtime) void {
        const retirements = self.captureAddressSpaceRetirements(.runtime_reset);
        self.next_task_id = 1;
        self.next_process_id = 1;
        self.next_address_space_id = 1;
        self.next_namespace_id = 1;
        self.next_component_id = 1;
        self.tasks.reset();
        self.task_owner_index.reset();
        self.task_initial_component_label_index.reset();
        self.task_state_counts = [_]TaskStateCount{0} ** TASK_STATE_COUNT;
        self.releaseTaskColdRecords();
        self.releaseAddressSpaceArena();
        self.advanceTaskLifecycleGeneration();
        self.notifyAddressSpaceRetirements(&retirements);
    }

    pub fn writeSnapshot(self: *const Runtime, out: *Snapshot) void {
        out.next_task_id = self.next_task_id;
        out.next_process_id = self.next_process_id;
        out.next_address_space_id = self.next_address_space_id;
        out.next_namespace_id = self.next_namespace_id;
        out.next_component_id = self.next_component_id;
        out.task_count = 0;
        const task_claimed_count = self.tasks.claimedCount();
        const task_cold = self.taskColdRecordsConst();
        var slot_index: usize = 0;
        while (slot_index < task_claimed_count) : (slot_index += 1) {
            const slot = self.tasks.slotAtConst(slot_index);
            if (!slot.in_use) continue;
            const dense_index = out.task_count;
            out.tasks[dense_index] = slot.*;
            const cold_records = task_cold orelse
                native_util.impossibleByInvariant("live tasks retain cold runtime state");
            copyTaskColdForTask(&out.task_cold[dense_index], &cold_records[slot_index], &slot.task);
            out.task_count += 1;
        }
        bindTaskColdStates(out.tasks[0..out.task_count], out.task_cold[0..out.task_count]);

        out.address_space_count = 0;
        if (self.addressSpaceArenaConst()) |address_spaces| {
            for (address_spaces.slots[0..address_spaces.claimedCount()]) |*slot| {
                if (!slot.in_use) continue;
                out.address_spaces[out.address_space_count] = slot.*;
                out.address_space_count += 1;
            }
        }
    }

    pub fn restoreFromSnapshot(self: *Runtime, state: *const Snapshot) error{NoSpaceLeft}!void {
        const task_cold = if (state.task_count == 0) null else try self.ensureTaskColdRecords();
        const previous_task_claimed_count = self.tasks.claimedCount();
        const restored_address_spaces = if (state.address_space_count == 0) null else try self.ensureAddressSpaceArena();
        const retirements = self.captureAddressSpaceRetirements(.snapshot_restore);
        self.resetForSnapshotRestore();
        if (state.task_count == 0 and heap_backed_task_cold) {
            self.releaseTaskColdRecords();
        } else if (previous_task_claimed_count > state.task_count) {
            self.clearTaskColdRecordRange(state.task_count, previous_task_claimed_count);
        }
        if (state.address_space_count == 0 and heap_backed_address_spaces) {
            self.releaseAddressSpaceArena();
        }
        self.next_task_id = state.next_task_id;
        self.next_process_id = state.next_process_id;
        self.next_address_space_id = state.next_address_space_id;
        self.next_namespace_id = state.next_namespace_id;
        self.next_component_id = state.next_component_id;

        var task_index: usize = 0;
        while (task_index < state.task_count) : (task_index += 1) {
            const snapshot_slot = &state.tasks[task_index];
            if (!snapshot_slot.in_use) {
                native_util.impossibleByInvariant("counted task snapshot records are live");
            }
            const snapshot_task = &snapshot_slot.task;
            const previous_task = &self.tasks.slotAtConst(task_index).task;
            const reuses_cold_backing = task_index < previous_task_claimed_count and
                previous_task.id != 0 and
                previous_task.id == snapshot_task.id and
                previous_task.owner.eql(snapshot_task.owner);
            const cold_records = task_cold orelse
                native_util.impossibleByInvariant("restored tasks retain cold runtime state");
            if (!reuses_cold_backing) resetTaskCold(&cold_records[task_index]);

            const task_id = snapshot_task.id;
            const slot_index = self.tasks.reserveIndexAt(task_id, task_index) orelse {
                native_util.impossibleByInvariant("task snapshot count is bounded by task arena capacity");
            };
            self.tasks.slotAt(slot_index).task = snapshot_task.*;
            copyTaskColdForTask(&cold_records[task_index], &state.task_cold[task_index], snapshot_task);
            self.rebuildTaskDerivedIndexesAt(slot_index);
        }

        var address_space_index: usize = 0;
        while (address_space_index < state.address_space_count) : (address_space_index += 1) {
            if (!state.address_spaces[address_space_index].in_use) {
                native_util.impossibleByInvariant("counted address-space snapshot records are live");
            }
            const address_space_id = state.address_spaces[address_space_index].address_space.id;
            const address_spaces = restored_address_spaces orelse
                native_util.impossibleByInvariant("restored address spaces retain arena backing");
            const slot_index = address_spaces.reserveIndexAt(address_space_id, address_space_index) orelse {
                native_util.impossibleByInvariant("address-space snapshot count is bounded by address-space arena capacity");
            };
            address_spaces.slots[slot_index].address_space = state.address_spaces[address_space_index].address_space;
        }
        self.debugAssertIndexIntegrity();
        self.advanceTaskLifecycleGeneration();
        self.notifyAddressSpaceRetirements(&retirements);
    }

    fn resetForSnapshotRestore(self: *Runtime) void {
        self.next_task_id = 1;
        self.next_process_id = 1;
        self.next_address_space_id = 1;
        self.next_namespace_id = 1;
        self.next_component_id = 1;
        self.tasks.resetRetainingPayloads();
        self.task_owner_index.reset();
        self.task_initial_component_label_index.reset();
        self.task_state_counts = [_]TaskStateCount{0} ** TASK_STATE_COUNT;
        if (self.addressSpaceArena()) |address_spaces| address_spaces.resetRetainingPayloads();
    }

    pub fn rebuildIndexes(self: *Runtime) void {
        self.tasks.rebuildPrimaryIndex();
        self.task_owner_index.reset();
        self.task_initial_component_label_index.reset();
        self.task_state_counts = [_]TaskStateCount{0} ** TASK_STATE_COUNT;
        if (self.addressSpaceArena()) |address_spaces| address_spaces.rebuildPrimaryIndex();

        var slot_index: usize = 0;
        while (slot_index < MAX_TASKS) : (slot_index += 1) {
            const slot = self.tasks.slotAt(slot_index);
            if (!slot.in_use) continue;
            self.rebuildTaskDerivedIndexesAt(slot_index);
        }
    }

    fn rebuildTaskDerivedIndexesAt(self: *Runtime, slot_index: usize) void {
        const slot = self.tasks.slotAt(slot_index);
        const task_cold = self.taskColdRecords() orelse
            native_util.impossibleByInvariant("live tasks retain cold runtime state");
        slot.task.cold_state = &task_cold[slot_index];
        if (!self.task_owner_index.append(taskOwnerIndexKey(slot.task.owner), slot_index)) {
            native_util.impossibleByInvariant("task owner index capacity covers task slots");
        }
        self.task_state_counts[taskStateIndex(slot.task.state)] += 1;
        if (!self.appendInitialComponentLabelIndex(slot_index, &slot.task)) {
            native_util.impossibleByInvariant("task label index capacity covers task slots");
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
        const task_id = self.nextReservableTaskId() orelse return error.TaskTableFull;
        const slot_index = self.tasks.reserveIndex(task_id) orelse return error.TaskTableFull;
        errdefer _ = self.tasks.removeIndex(slot_index);
        const task_cold = try self.ensureTaskColdRecords();

        const initial_component = try self.makeExecutionComponent(defaultInitialComponent(request));
        _ = try self.ensureAddressSpaceArena();
        const host = try allocateHost(
            self,
            request.component_class,
            task_id,
            request.launch.image_id,
            userspace_image,
        );

        const slot = self.tasks.slotAt(slot_index);
        resetTaskCold(&task_cold[slot_index]);
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
            .executable_loaded = userspace_image.isPresent(),
            .launch = makeLaunchProvenance(request.launch),
            .cold_state = &task_cold[slot_index],
        };
        task_cold[slot_index].execution_components[0] = initial_component;
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
        if (!self.appendInitialComponentLabelIndex(slot_index, &slot.task)) {
            native_util.impossibleByInvariant("task label index capacity covers task slots");
        }
        self.task_state_counts[taskStateIndex(slot.task.state)] += 1;
        self.advanceNextComponentIdFrom(initial_component.id);
        self.advanceNextTaskIdFrom(task_id);
        self.advanceTaskLifecycleGeneration();
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

    pub fn countTasksInState(self: *const Runtime, state: TaskState) usize {
        return @intCast(self.task_state_counts[taskStateIndex(state)]);
    }

    pub fn taskLifecycleGeneration(self: *const Runtime) u64 {
        return self.task_lifecycle_generation;
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

    pub fn findByHandle(self: *Runtime, handle: TaskHandle, expected_task_id: u64) ?*TaskRecord {
        const slot = self.tasks.getByHandle(handle) orelse return null;
        if (slot.task.id != expected_task_id) return null;
        return &slot.task;
    }

    pub fn findConstByHandle(self: *const Runtime, handle: TaskHandle, expected_task_id: u64) ?*const TaskRecord {
        const slot = self.tasks.getConstByHandle(handle) orelse return null;
        if (slot.task.id != expected_task_id) return null;
        return &slot.task;
    }

    pub fn findConst(self: *const Runtime, task_id: u64) ?*const TaskRecord {
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

    pub fn findByInitialComponentLabel(self: *Runtime, label: []const u8) ?*TaskRecord {
        var best: ?*TaskRecord = null;
        var slot_index = self.task_initial_component_label_index.head(taskInitialComponentLabelKey(label));
        while (slot_index != indexed_arena.no_index) : (slot_index = self.task_initial_component_label_index.next(slot_index)) {
            if (slot_index >= MAX_TASKS) native_util.impossibleByInvariant("task label index points outside task slots");
            const slot = self.tasks.slotAt(slot_index);
            if (!slot.in_use) native_util.impossibleByInvariant("task label index points at a free slot");
            if (slot.task.execution_component_count == 0) native_util.impossibleByInvariant("task label index points at a task without an initial component");
            if (!std.mem.eql(u8, slot.task.executionComponents()[0].labelSlice(), label)) continue;
            if (best == null or preferTaskLookupMatch(&slot.task, best.?)) {
                best = &slot.task;
            }
        }
        if (best == null) self.debugAssertInitialComponentLabelIndexMissAbsent(label);
        return best;
    }

    pub fn findAddressSpace(self: *Runtime, address_space_id: u64) ?*AddressSpaceRecord {
        const slot = findAddressSpaceSlot(self, address_space_id) orelse return null;
        return &slot.address_space;
    }

    pub fn allowHostPointerSyscallsForTask(self: *Runtime, task_id: u64) void {
        const task = self.find(task_id).?;
        const address_space = self.findAddressSpace(task.address_space_id).?;

        address_space.region_count = 0;
    }

    pub fn findAddressSpaceConst(self: *const Runtime, address_space_id: u64) ?*const AddressSpaceRecord {
        if (self.indexedAddressSpaceSlotConst(address_space_id)) |slot| return &slot.address_space;
        self.debugAssertAddressSpaceIndexMissAbsent(address_space_id);
        return null;
    }

    pub fn indexedAddressSpaceSlot(self: *Runtime, address_space_id: u64) ?*AddressSpaceSlot {
        const address_spaces = self.addressSpaceArena() orelse {
            self.debugAssertAddressSpaceIndexMissAbsent(address_space_id);
            return null;
        };
        return address_spaces.get(address_space_id) orelse {
            self.debugAssertAddressSpaceIndexMissAbsent(address_space_id);
            return null;
        };
    }

    fn indexedAddressSpaceSlotConst(self: *const Runtime, address_space_id: u64) ?*const AddressSpaceSlot {
        const address_spaces = self.addressSpaceArenaConst() orelse {
            self.debugAssertAddressSpaceIndexMissAbsent(address_space_id);
            return null;
        };
        return address_spaces.getConst(address_space_id) orelse {
            self.debugAssertAddressSpaceIndexMissAbsent(address_space_id);
            return null;
        };
    }

    fn indexedTaskSlot(self: *Runtime, task_id: u64) ?*TaskSlot {
        return self.tasks.get(task_id);
    }

    fn indexedTaskSlotConst(self: *const Runtime, task_id: u64) ?*const TaskSlot {
        return self.tasks.getConst(task_id);
    }

    fn nextReservableTaskId(self: *const Runtime) ?u64 {
        if (self.taskCount() >= MAX_TASKS or self.next_task_id == 0) return null;
        if (self.indexedTaskSlotConst(self.next_task_id) != null) {
            native_util.impossibleByInvariant("next task id must be monotonic and unused");
        }
        return self.next_task_id;
    }

    fn advanceNextTaskIdFrom(self: *Runtime, task_id: u64) void {
        self.next_task_id = nextTaskIdAfter(task_id);
    }

    fn makeExecutionComponent(self: *Runtime, component: ExecutionComponentSpec) Error!ExecutionComponentRecord {
        const component_id = self.nextReservableComponentId() orelse return error.ComponentTableFull;
        var record = zeroExecutionComponent();
        record.id = component_id;
        record.substrate = component.substrate;
        record.label_len = @intCast(native_util.copyTextWithReserve(record.label[0..], component.label, 1));
        record.entry_len = @intCast(native_util.copyTextWithReserve(record.entry[0..], component.entry, 1));
        return record;
    }

    fn nextReservableComponentId(self: *const Runtime) ?u64 {
        return if (self.next_component_id == 0) null else self.next_component_id;
    }

    fn advanceNextComponentIdFrom(self: *Runtime, component_id: u64) void {
        self.next_component_id = nextComponentIdAfter(component_id);
    }

    pub fn installAddressSpaceRecord(self: *Runtime, replace_address_space_id: ?u64, address_space: AddressSpaceRecord) bool {
        const address_spaces = self.addressSpaceArena() orelse
            native_util.impossibleByInvariant("address-space installation follows arena allocation");
        if (replace_address_space_id) |old_id| {
            if (address_spaces.slotIndexOf(old_id)) |old_slot_index| {
                _ = address_spaces.removeIndex(old_slot_index);
                const new_slot_index = address_spaces.reserveIndexAt(address_space.id, old_slot_index) orelse {
                    native_util.impossibleByInvariant("removed address-space slot is immediately reusable");
                };
                address_spaces.slots[new_slot_index].address_space = address_space;
                return true;
            }
        }

        const slot = address_spaces.reserve(address_space.id) orelse return false;
        slot.address_space = address_space;
        return true;
    }

    fn debugAssertIndexIntegrity(self: *const Runtime) void {
        if (!debugIndexChecksEnabled()) return;
        var slot_index: usize = 0;
        while (slot_index < MAX_TASKS) : (slot_index += 1) {
            const slot = self.tasks.slotAtConst(slot_index);
            if (!slot.in_use) continue;
            _ = self.indexedTaskSlotConst(slot.task.id) orelse
                native_util.impossibleByInvariant("task index missing a live task");
            if (slot.task.execution_component_count != 0) {
                const key = taskInitialComponentLabelKey(slot.task.executionComponents()[0].labelSlice());
                var found = false;
                var label_slot_index = self.task_initial_component_label_index.head(key);
                while (label_slot_index != indexed_arena.no_index) : (label_slot_index = self.task_initial_component_label_index.next(label_slot_index)) {
                    if (label_slot_index == slot_index) {
                        found = true;
                        break;
                    }
                }
                if (!found) native_util.impossibleByInvariant("task label index missing a live task");
            }
            var capability_index: usize = 0;
            while (capability_index < slot.task.capability_count) : (capability_index += 1) {
                const capability_id = slot.task.capabilityIds()[capability_index];
                if (capability_id == 0 or taskCapabilityIndex(&slot.task, capability_id) != capability_index) {
                    native_util.impossibleByInvariant("live task capabilities are nonzero and unique");
                }
            }
        }
        if (self.addressSpaceArenaConst()) |address_spaces| {
            for (&address_spaces.slots) |*slot| {
                if (!slot.in_use) continue;
                _ = self.indexedAddressSpaceSlotConst(slot.address_space.id) orelse
                    native_util.impossibleByInvariant("address space index missing a live address space");
            }
        }
    }

    fn debugAssertInitialComponentLabelIndexMissAbsent(self: *Runtime, label: []const u8) void {
        if (!debugIndexChecksEnabled()) return;
        var slot_index: usize = 0;
        while (slot_index < MAX_TASKS) : (slot_index += 1) {
            const slot = self.tasks.slotAt(slot_index);
            if (!slot.in_use or slot.task.execution_component_count == 0) continue;
            if (std.mem.eql(u8, slot.task.executionComponents()[0].labelSlice(), label)) {
                native_util.impossibleByInvariant("task label index missed a live task");
            }
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
        const address_spaces = self.addressSpaceArenaConst() orelse return;
        for (&address_spaces.slots) |*slot| {
            if (slot.in_use and slot.address_space.id == address_space_id) {
                native_util.impossibleByInvariant("address space index missed a live address space");
            }
        }
    }

    pub fn grantCapability(self: *Runtime, task_id: u64, capability_id: u64) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        return grantCapabilityToTask(task, capability_id);
    }

    pub fn hasCapability(self: *const Runtime, task_id: u64, capability_id: u64) bool {
        const task = self.findConst(task_id) orelse return false;
        return task.hasCapability(capability_id);
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

        const record = try self.makeExecutionComponent(component);
        cold.execution_components[task.execution_component_count] = record;
        task.execution_component_count += 1;
        try self.audit(task_id, .{
            .kind = .component_attached,
            .detail = @intFromEnum(record.substrate),
            .tick = tick,
        });
        self.advanceNextComponentIdFrom(record.id);
        return record;
    }

    pub fn revokeCapability(self: *Runtime, task_id: u64, capability_id: u64) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        return revokeCapabilityFromTask(task, capability_id);
    }

    pub fn revokeCapabilityEverywhere(self: *Runtime, capability_id: u64) u16 {
        var revoked_count: u16 = 0;
        for (0..self.taskSlotCapacity()) |slot_index| {
            const slot = self.taskSlotAt(slot_index);
            if (!slot.in_use or !slot.task.hasCapability(capability_id)) continue;
            const revoked = revokeCapabilityFromTask(&slot.task, capability_id);
            if (!revoked) {
                native_util.impossibleByInvariant("capability retirement removes every located task attachment");
            }
            revoked_count += 1;
        }
        return revoked_count;
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
        const retired_address_space_id = task.address_space_id;
        const retired_address_space = self.findAddressSpaceConst(retired_address_space_id) orelse
            native_util.impossibleByInvariant("live task references an indexed address space");

        const host = try reassignHost(
            self,
            task.component_class,
            task.id,
            retired_address_space.*,
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
        task.appendAudit(.{
            .kind = .service_restarted,
            .detail = @truncate(task.process_generation),
            .tick = tick,
        });
        self.notifyAddressSpaceRetirement(.{
            .address_space_id = retired_address_space_id,
            .reason = .rehost,
        });
        return true;
    }

    pub fn audit(self: *Runtime, task_id: u64, event: AuditEvent) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        task.appendAudit(event);
    }

    fn captureAddressSpaceRetirements(self: *const Runtime, reason: AddressSpaceRetirementReason) AddressSpaceRetirementBatch {
        var batch = AddressSpaceRetirementBatch{};
        if (self.address_space_retirement_sink == null) return batch;
        const address_spaces = self.addressSpaceArenaConst() orelse return batch;
        for (address_spaces.slots[0..address_spaces.claimedCount()]) |*slot| {
            if (!slot.in_use) continue;
            batch.events[batch.count] = .{
                .address_space_id = slot.address_space.id,
                .reason = reason,
            };
            batch.count += 1;
        }
        return batch;
    }

    fn notifyAddressSpaceRetirements(self: *const Runtime, batch: *const AddressSpaceRetirementBatch) void {
        const sink = self.address_space_retirement_sink orelse return;
        for (batch.events[0..batch.count]) |event| sink.notify(event);
    }

    fn notifyAddressSpaceRetirement(self: *const Runtime, event: AddressSpaceRetirementEvent) void {
        const sink = self.address_space_retirement_sink orelse return;
        if (event.address_space_id == 0) return;
        sink.notify(event);
    }

    fn removeAddressSpaceRecord(self: *Runtime, address_space_id: u64) void {
        const address_spaces = self.addressSpaceArena() orelse return;
        const slot_index = address_spaces.slotIndexOf(address_space_id) orelse return;
        _ = address_spaces.removeIndex(slot_index);
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
        return planBackgroundCapacity(task, budget) != null;
    }

    pub fn reserveBackgroundWork(
        self: *Runtime,
        task_id: u64,
        budget: manifest.BackgroundResourceBudget,
        network: manifest.BackgroundNetworkMode,
        visibility: manifest.BackgroundVisibility,
        tick: u64,
    ) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        const reservation = planBackgroundWork(task, budget, network, visibility, tick) orelse return false;
        commitBackgroundWork(task, reservation);
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
        const handle = self.taskHandle(task_id) orelse return error.TaskNotFound;
        return self.terminateTaskByHandle(handle, task_id, tick);
    }

    pub fn terminateTaskByHandle(self: *Runtime, handle: TaskHandle, task_id: u64, tick: u64) Error!bool {
        const slot = self.tasks.getByHandle(handle) orelse return error.TaskNotFound;
        if (slot.task.id != task_id) return error.TaskNotFound;
        const slot_index = handle.slotIndex();
        const task = &slot.task;
        if (task.state == .terminated) return false;
        const retired_address_space_id = task.address_space_id;

        self.removeInitialComponentLabelIndex(slot_index, task);
        self.setTaskState(task, .terminated);
        clearTerminatedTaskResources(task);
        task.execution_component_count = 0;
        task.capability_count = 0;
        task.appendAudit(.{
            .kind = .terminated,
            .tick = tick,
        });
        self.removeAddressSpaceRecord(retired_address_space_id);
        self.notifyAddressSpaceRetirement(.{
            .address_space_id = retired_address_space_id,
            .reason = .terminate,
        });
        return true;
    }

    pub fn suspendTask(self: *Runtime, task_id: u64, tick: u64) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.state != .active) return false;

        self.setTaskState(task, .suspended);
        try self.audit(task_id, .{
            .kind = .suspended,
            .tick = tick,
        });
        return true;
    }

    pub fn resumeTask(self: *Runtime, task_id: u64, tick: u64) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.state != .suspended) return false;

        self.setTaskState(task, .active);
        try self.audit(task_id, .{
            .kind = .resumed,
            .tick = tick,
        });
        return true;
    }

    fn setTaskState(self: *Runtime, task: *TaskRecord, state: TaskState) void {
        if (task.state == state) return;
        const old_index = taskStateIndex(task.state);
        if (self.task_state_counts[old_index] == 0) {
            native_util.impossibleByInvariant("task state count missing live task state");
        }
        self.task_state_counts[old_index] -= 1;
        task.state = state;
        self.task_state_counts[taskStateIndex(state)] += 1;
        self.advanceTaskLifecycleGeneration();
    }

    fn advanceTaskLifecycleGeneration(self: *Runtime) void {
        self.task_lifecycle_generation +%= 1;
        if (self.task_lifecycle_generation == 0) self.task_lifecycle_generation = 1;
    }

    fn appendInitialComponentLabelIndex(self: *Runtime, slot_index: usize, task: *const TaskRecord) bool {
        if (task.execution_component_count == 0) return true;
        return self.task_initial_component_label_index.append(
            taskInitialComponentLabelKey(task.executionComponents()[0].labelSlice()),
            slot_index,
        );
    }

    fn removeInitialComponentLabelIndex(self: *Runtime, slot_index: usize, task: *const TaskRecord) void {
        if (task.execution_component_count == 0) return;
        if (!self.task_initial_component_label_index.remove(
            taskInitialComponentLabelKey(task.executionComponents()[0].labelSlice()),
            slot_index,
        )) {
            native_util.impossibleByInvariant("task label index missing task being terminated");
        }
    }
};

pub fn grantCapabilityToTask(task: *TaskRecord, capability_id: u64) Error!void {
    const cold = taskCold(task);
    if (capability_id == 0) {
        native_util.impossibleByInvariant("task capability attachments never use the reserved zero id");
    }
    if (task.hasCapability(capability_id)) return;
    if (task.capability_count >= MAX_TASK_CAPABILITIES) return error.CapabilityTableFull;
    cold.capability_ids[task.capability_count] = capability_id;
    task.capability_count += 1;
    advanceTaskCapabilityGeneration(task);
    appendProvenanceToTask(task, debug_contract.capabilityGrantProvenance(task.id, capability_id, 0));
}

pub fn revokeCapabilityFromTask(task: *TaskRecord, capability_id: u64) bool {
    const cold = taskCold(task);
    const index = taskCapabilityIndex(task, capability_id) orelse return false;
    const last_index = task.capability_count - 1;
    const moved_capability_id = cold.capability_ids[last_index];

    if (index != last_index) {
        cold.capability_ids[index] = moved_capability_id;
    }

    task.capability_count -= 1;
    cold.capability_ids[task.capability_count] = 0;
    advanceTaskCapabilityGeneration(task);
    appendProvenanceToTask(task, debug_contract.capabilityRevokeProvenance(task.id, capability_id, 0));
    return true;
}

fn advanceTaskCapabilityGeneration(task: *TaskRecord) void {
    const cold = taskCold(task);
    cold.capability_generation +%= 1;
    if (cold.capability_generation == 0) cold.capability_generation = 1;
}

const AddressSpaceRetirementBatch = struct {
    events: [MAX_TASKS]AddressSpaceRetirementEvent = undefined,
    count: usize = 0,
};

fn nextTaskIdAfter(task_id: u64) u64 {
    return task_id +% 1;
}

fn nextComponentIdAfter(component_id: u64) u64 {
    return component_id +% 1;
}

fn debugIndexChecksEnabled() bool {
    return builtin.mode == .Debug;
}

fn taskStateIndex(state: TaskState) usize {
    return @intFromEnum(state);
}

fn taskInitialComponentLabelKey(label: []const u8) u64 {
    return indexed_arena.nonZeroKey(native_util.fnv1a64(label));
}

fn preferTaskLookupMatch(candidate: *const TaskRecord, current: *const TaskRecord) bool {
    if (candidate.state == .active and current.state != .active) return true;
    if (candidate.state != .active and current.state == .active) return false;
    if (candidate.process_generation != current.process_generation) return candidate.process_generation > current.process_generation;
    return candidate.id > current.id;
}

fn appendProvenanceToTask(task: *TaskRecord, event: ProvenanceRecord) void {
    const cold = taskCold(task);
    if (task.provenance_count < MAX_TASK_PROVENANCE_EVENTS) {
        const slot_index = (task.provenance_start + task.provenance_count) % MAX_TASK_PROVENANCE_EVENTS;
        cold.provenance_trail[slot_index] = TaskProvenanceRecord.from(event);
        task.provenance_count += 1;
        return;
    }

    cold.provenance_trail[task.provenance_start] = TaskProvenanceRecord.from(event);
    task.provenance_start = @intCast((task.provenance_start + 1) % MAX_TASK_PROVENANCE_EVENTS);
}

fn clearTerminatedTaskResources(task: *TaskRecord) void {
    const cold = taskCold(task);
    cold.execution_components = std.mem.zeroes(@TypeOf(cold.execution_components));
    cold.capability_ids = [_]u64{0} ** MAX_TASK_CAPABILITIES;
    cold.capability_generation = 1;
}

fn createTaskIdTestTask(runtime: *Runtime, owner_serial: u64) Error!*TaskRecord {
    return runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = owner_serial },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = TEST_MINIMAL_MEMORY_BYTES,
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });
}

test "allocated runtime initialization preserves empty indexes and id sequences" {
    var runtime: Runtime = undefined;
    runtime.initializeAllocated();

    try std.testing.expectEqual(@as(usize, 0), runtime.taskCount());
    try std.testing.expectEqual(@as(u64, 1), runtime.taskLifecycleGeneration());

    const task = try createTaskIdTestTask(&runtime, 42);
    try std.testing.expectEqual(@as(u64, 1), task.id);
    try std.testing.expectEqual(task.id, runtime.findByOwner(task.owner).?.id);
    const initial_label = task.executionComponents()[0].labelSlice();
    try std.testing.expectEqual(task.id, runtime.findByInitialComponentLabel(initial_label).?.id);

    const lifecycle_generation_before_reset = runtime.taskLifecycleGeneration();
    runtime.reset();
    try std.testing.expectEqual(@as(usize, 0), runtime.taskCount());
    try std.testing.expectEqual(lifecycle_generation_before_reset + 1, runtime.taskLifecycleGeneration());
}

const RetirementRecorder = struct {
    events: [MAX_TASKS * 2]AddressSpaceRetirementEvent = undefined,
    count: usize = 0,
    runtime_to_observe: ?*const Runtime = null,
    required_live_address_space_id: ?u64 = null,
    require_retired_address_space_absent: bool = false,
    commit_observed: bool = true,

    pub fn retireAddressSpace(self: *RetirementRecorder, event: AddressSpaceRetirementEvent) void {
        if (self.count >= self.events.len) @panic("retirement recorder capacity exceeded");
        self.events[self.count] = event;
        self.count += 1;
        const runtime = self.runtime_to_observe orelse return;
        if (self.require_retired_address_space_absent and runtime.findAddressSpaceConst(event.address_space_id) != null) {
            self.commit_observed = false;
        }
        if (self.required_live_address_space_id) |address_space_id| {
            if (runtime.findAddressSpaceConst(address_space_id) == null) self.commit_observed = false;
        }
    }

    fn eventAt(self: *const RetirementRecorder, index: usize) AddressSpaceRetirementEvent {
        return self.events[index];
    }
};

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

test "background work reservations plan and commit against a resolved task" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 2 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
            .background_allowed = true,
        },
    });
    const budget = manifest.BackgroundResourceBudget{
        .cpu_time_ticks = 200,
        .memory_bytes = TEST_MINIMAL_MEMORY_BYTES,
        .shared_memory_bytes = 64,
    };

    const reservation = planBackgroundWork(task, budget, .local_network_only, .status_only, 42).?;
    try std.testing.expectEqual(@as(u16, 0), task.background_active_count);
    try std.testing.expectEqual(@as(u64, 0), task.background_cpu_consumed_ticks);

    commitBackgroundWork(task, reservation);
    try std.testing.expectEqual(@as(u16, 1), task.background_active_count);
    try std.testing.expectEqual(@as(u64, 200), task.background_cpu_consumed_ticks);
    try std.testing.expectEqual(TEST_MINIMAL_MEMORY_BYTES, task.background_reserved_memory_bytes);
    try std.testing.expectEqual(@as(usize, 64), task.background_reserved_shared_memory_bytes);
    try std.testing.expectEqual(manifest.BackgroundNetworkMode.local_network_only, task.last_background_network);
    try std.testing.expectEqual(manifest.BackgroundVisibility.status_only, task.last_background_visibility);
    try std.testing.expectEqual(@as(u64, 42), task.last_background_tick);

    const over_budget = manifest.BackgroundResourceBudget{
        .cpu_time_ticks = 801,
        .memory_bytes = 0,
        .shared_memory_bytes = 0,
    };
    try std.testing.expect(planBackgroundWork(task, over_budget, .none, .audit_only, 43) == null);
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

test "task handles reject stale task records across restore and reuse" {
    var runtime = Runtime.init();
    const first = try createTaskIdTestTask(&runtime, 1);
    const task_id = first.id;
    const first_handle = runtime.taskHandle(task_id).?;

    try std.testing.expectEqual(task_id, runtime.findByHandle(first_handle, task_id).?.id);
    try std.testing.expectEqual(task_id, runtime.findConstByHandle(first_handle, task_id).?.id);
    try std.testing.expect(runtime.findByHandle(first_handle, task_id + 1) == null);

    var snapshot = Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);
    try runtime.restoreFromSnapshot(&snapshot);

    try std.testing.expect(runtime.findByHandle(first_handle, task_id) == null);
    const restored_handle = runtime.taskHandle(task_id).?;
    try std.testing.expect(!restored_handle.eql(first_handle));
    try std.testing.expectEqual(task_id, runtime.findByHandle(restored_handle, task_id).?.id);

    runtime.reset();
    try std.testing.expect(runtime.findByHandle(restored_handle, task_id) == null);
    const replacement = try createTaskIdTestTask(&runtime, 2);
    const replacement_handle = runtime.taskHandle(replacement.id).?;
    try std.testing.expectEqual(task_id, replacement.id);
    try std.testing.expect(!replacement_handle.eql(restored_handle));
    try std.testing.expect(runtime.findByHandle(restored_handle, replacement.id) == null);
    try std.testing.expectEqual(replacement.id, runtime.findByHandle(replacement_handle, replacement.id).?.id);
}

test "task runtime ids are monotonic and exhaust without wrapping" {
    var runtime = Runtime.init();

    runtime.next_task_id = std.math.maxInt(u64);
    const max_task = try createTaskIdTestTask(&runtime, 1);
    try std.testing.expectEqual(std.math.maxInt(u64), max_task.id);
    try std.testing.expectEqual(@as(u64, 0), runtime.next_task_id);
    try std.testing.expect(runtime.find(0) == null);
    try std.testing.expectError(error.TaskTableFull, createTaskIdTestTask(&runtime, 2));
    try std.testing.expectEqual(@as(usize, 1), runtime.taskCount());

    var full_runtime = Runtime.init();
    for (0..MAX_TASKS) |index| {
        _ = try createTaskIdTestTask(&full_runtime, @intCast(index + 10));
    }
    const next_before_full = full_runtime.next_task_id;
    try std.testing.expectError(error.TaskTableFull, createTaskIdTestTask(&full_runtime, 1_000));
    try std.testing.expectEqual(next_before_full, full_runtime.next_task_id);
    try std.testing.expectEqual(MAX_TASKS, full_runtime.taskCount());
}

test "task runtime host ids are monotonic and exhaust without wrapping" {
    var runtime = Runtime.init();

    runtime.next_process_id = std.math.maxInt(u64);
    runtime.next_address_space_id = std.math.maxInt(u64);
    runtime.next_namespace_id = std.math.maxInt(u64);
    const max_host_task = try createTaskIdTestTask(&runtime, 20);
    try std.testing.expectEqual(std.math.maxInt(u64), max_host_task.process_id);
    try std.testing.expectEqual(std.math.maxInt(u64), max_host_task.address_space_id);
    try std.testing.expectEqual(std.math.maxInt(u64), max_host_task.namespace_id);
    try std.testing.expectEqual(@as(u64, 0), runtime.next_process_id);
    try std.testing.expectEqual(@as(u64, 0), runtime.next_address_space_id);
    try std.testing.expectEqual(@as(u64, 0), runtime.next_namespace_id);
    try std.testing.expect(runtime.findAddressSpaceConst(0) == null);
    try std.testing.expectError(error.AddressSpaceTableFull, createTaskIdTestTask(&runtime, 21));
    try std.testing.expectEqual(@as(usize, 1), runtime.taskCount());
    try std.testing.expect(runtime.findAddressSpaceConst(0) == null);
}

test "task runtime host ids do not advance when address space installation fails" {
    var runtime = Runtime.init();
    for (0..runtime.address_spaces.slots.len) |index| {
        const address_space_id: u64 = @intCast(index + 1_000);
        const slot_index = runtime.address_spaces.reserveIndex(address_space_id) orelse unreachable;
        const slot = &runtime.address_spaces.slots[slot_index];
        slot.address_space = model.zeroAddressSpace();
        slot.address_space.id = address_space_id;
    }
    runtime.rebuildIndexes();

    runtime.next_process_id = 80;
    runtime.next_address_space_id = 81;
    runtime.next_namespace_id = 82;
    const next_process_before = runtime.next_process_id;
    const next_address_space_before = runtime.next_address_space_id;
    const next_namespace_before = runtime.next_namespace_id;

    try std.testing.expectError(error.AddressSpaceTableFull, createTaskIdTestTask(&runtime, 23));
    try std.testing.expectEqual(next_process_before, runtime.next_process_id);
    try std.testing.expectEqual(next_address_space_before, runtime.next_address_space_id);
    try std.testing.expectEqual(next_namespace_before, runtime.next_namespace_id);
    try std.testing.expectEqual(@as(usize, 0), runtime.taskCount());
}

test "task runtime component ids are monotonic and exhaust without wrapping" {
    var runtime = Runtime.init();

    runtime.next_component_id = std.math.maxInt(u64);
    const max_component_task = try createTaskIdTestTask(&runtime, 30);
    try std.testing.expectEqual(std.math.maxInt(u64), max_component_task.executionComponents()[0].id);
    try std.testing.expectEqual(@as(u64, 0), runtime.next_component_id);
    try std.testing.expectError(error.ComponentTableFull, createTaskIdTestTask(&runtime, 31));
    try std.testing.expectError(error.ComponentTableFull, runtime.attachComponent(max_component_task.id, .{
        .substrate = .early_elf_runner,
        .label = "component-id-exhausted",
        .entry = "/system/components/component-id-exhausted.elf",
    }, 40));

    try std.testing.expect(max_component_task.executionComponents()[0].id != 0);
    try std.testing.expectEqual(@as(usize, 1), runtime.taskCount());
}

test "task runtime component ids do not advance when host allocation fails" {
    var runtime = Runtime.init();
    for (0..runtime.address_spaces.slots.len) |index| {
        const address_space_id: u64 = @intCast(index + 2_000);
        const slot_index = runtime.address_spaces.reserveIndex(address_space_id) orelse unreachable;
        const slot = &runtime.address_spaces.slots[slot_index];
        slot.address_space = model.zeroAddressSpace();
        slot.address_space.id = address_space_id;
    }
    runtime.rebuildIndexes();

    runtime.next_component_id = 90;
    const next_component_before = runtime.next_component_id;

    try std.testing.expectError(error.AddressSpaceTableFull, createTaskIdTestTask(&runtime, 33));
    try std.testing.expectEqual(next_component_before, runtime.next_component_id);
    try std.testing.expectEqual(@as(usize, 0), runtime.taskCount());
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

    try std.testing.expectEqual(@as(u64, 1), task.capabilityGeneration());
    try runtime.grantCapability(task.id, 11);
    try std.testing.expectEqual(@as(u64, 2), task.capabilityGeneration());
    try runtime.grantCapability(task.id, 12);
    try std.testing.expectEqual(@as(u64, 3), task.capabilityGeneration());
    try runtime.grantCapability(task.id, 13);
    try std.testing.expectEqual(@as(u64, 4), task.capabilityGeneration());
    try runtime.grantCapability(task.id, 13);
    try std.testing.expectEqual(@as(u64, 4), task.capabilityGeneration());
    try std.testing.expectEqual(@as(usize, 3), task.capability_count);
    try std.testing.expectEqual(@as(usize, 4), task.provenance_count);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.capability_grant, task.latestProvenanceEvent().?.kind);
    try std.testing.expectEqual(@as(u64, 13), task.latestProvenanceEvent().?.capability_id);
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.background_light, task.resourceClass());

    try std.testing.expect(try runtime.revokeCapability(task.id, 12));
    try std.testing.expectEqual(@as(u64, 5), task.capabilityGeneration());
    try std.testing.expectEqual(@as(usize, 2), task.capability_count);
    try std.testing.expect(runtime.hasCapability(task.id, 11));
    try std.testing.expect(!runtime.hasCapability(task.id, 12));
    try std.testing.expect(runtime.hasCapability(task.id, 13));
    try std.testing.expectEqual(@as(u64, 13), task.capabilityIds()[1]);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.capability_revoke, task.latestProvenanceEvent().?.kind);
    try std.testing.expectEqual(@as(u64, 12), task.latestProvenanceEvent().?.capability_id);
    try std.testing.expect(!try runtime.revokeCapability(task.id, 99));
    try std.testing.expectEqual(@as(u64, 5), task.capabilityGeneration());

    taskCold(task).capability_generation = std.math.maxInt(u64);
    try runtime.grantCapability(task.id, 14);
    try std.testing.expectEqual(@as(u64, 1), task.capabilityGeneration());

    var snapshot = Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);
    var restored = Runtime.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(@as(u64, 1), restored.find(task.id).?.capabilityGeneration());
}

test "bounded task capability scans preserve full-table and compaction semantics" {
    var runtime = Runtime.init();
    const task = try createTaskIdTestTask(&runtime, 40);

    for (0..MAX_TASK_CAPABILITIES) |capability_index| {
        try runtime.grantCapability(task.id, 1_000 + capability_index);
    }
    try std.testing.expectEqual(MAX_TASK_CAPABILITIES, task.capability_count);
    for (0..MAX_TASK_CAPABILITIES) |capability_index| {
        try std.testing.expect(runtime.hasCapability(task.id, 1_000 + capability_index));
    }

    try runtime.grantCapability(task.id, 1_000 + MAX_TASK_CAPABILITIES - 1);
    try std.testing.expectEqual(MAX_TASK_CAPABILITIES, task.capability_count);
    try std.testing.expectError(error.CapabilityTableFull, runtime.grantCapability(task.id, 2_000));

    try std.testing.expect(try runtime.revokeCapability(task.id, 1_000));
    try std.testing.expect(!runtime.hasCapability(task.id, 1_000));
    try std.testing.expect(runtime.hasCapability(task.id, 1_000 + MAX_TASK_CAPABILITIES - 1));
    try runtime.grantCapability(task.id, 2_000);
    try std.testing.expectEqual(MAX_TASK_CAPABILITIES, task.capability_count);
    try std.testing.expect(runtime.hasCapability(task.id, 2_000));
}

test "capability retirement removes attachments from every task" {
    var runtime = Runtime.init();
    const first = try createTaskIdTestTask(&runtime, 41);
    const second = try createTaskIdTestTask(&runtime, 42);

    try runtime.grantCapability(first.id, 77);
    try runtime.grantCapability(first.id, 88);
    try runtime.grantCapability(second.id, 77);
    try std.testing.expectEqual(@as(u16, 2), runtime.revokeCapabilityEverywhere(77));
    try std.testing.expect(!runtime.hasCapability(first.id, 77));
    try std.testing.expect(!runtime.hasCapability(second.id, 77));
    try std.testing.expect(runtime.hasCapability(first.id, 88));
    try std.testing.expectEqual(@as(u16, 0), runtime.revokeCapabilityEverywhere(77));
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

    try std.testing.expect(try runtime.terminateTask(task.id, 78));
    try std.testing.expectEqual(debug_contract.ProvenanceKind.crash_report, task.latestProvenanceEvent().?.kind);
    try std.testing.expectEqual(model.AuditEventKind.terminated, task.latestAuditEvent().?.kind);
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
    restored.next_task_id = 100;
    restored.next_process_id = 100;
    restored.next_address_space_id = 100;
    restored.next_namespace_id = 100;
    const stale_owner: principal.PrincipalId = .{ .kind = .app, .serial = 99 };
    const stale_task = try restored.createTask(.{
        .owner = stale_owner,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = TEST_MINIMAL_MEMORY_BYTES,
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
        .initial_component = .{
            .label = "stale-service",
            .entry = "zigos.stale.service",
        },
    });
    const stale_task_id = stale_task.id;
    const stale_address_space_id = stale_task.address_space_id;
    try restored.grantCapability(stale_task_id, 92);
    try std.testing.expect(try restored.suspendTask(stale_task_id, 1));

    try restored.restoreFromSnapshot(&snapshot);

    const restored_task = restored.find(task_id).?;
    try std.testing.expect(restored.find(stale_task_id) == null);
    try std.testing.expect(restored.findAddressSpaceConst(stale_address_space_id) == null);
    try std.testing.expect(restored.findByOwner(stale_owner) == null);
    try std.testing.expect(restored.findByInitialComponentLabel("stale-service") == null);
    try std.testing.expect(!restored.hasCapability(stale_task_id, 92));
    try std.testing.expectEqual(@as(usize, 1), restored.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 0), restored.countTasksInState(.suspended));
    try std.testing.expect(restored.findAddressSpaceConst(address_space_id) != null);
    try std.testing.expectEqual(task_id, restored.findByOwner(.{ .kind = .service, .serial = 22 }).?.id);
    try std.testing.expect(restored.hasCapability(task_id, 91));
    try std.testing.expectEqual(@as(usize, 2), restored_task.provenance_count);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.capability_grant, restored_task.latestProvenanceEvent().?.kind);
    try std.testing.expectEqual(@as(u64, 91), restored_task.latestProvenanceEvent().?.capability_id);

    const post_restore_task = try createTaskIdTestTask(&restored, 23);
    try std.testing.expectEqual(snapshot.next_task_id, post_restore_task.id);
    const pre_rehost_address_space_id = restored.find(task_id).?.address_space_id;
    try std.testing.expect(try restored.rehostTask(task_id, 2));
    try std.testing.expect(restored.findAddressSpaceConst(pre_rehost_address_space_id) == null);
}

test "snapshot restore reuses live cold backing and clears only retired records" {
    const source = try std.testing.allocator.create(Runtime);
    defer std.testing.allocator.destroy(source);
    source.* = Runtime.init();
    const restored = try std.testing.allocator.create(Runtime);
    defer std.testing.allocator.destroy(restored);
    restored.* = Runtime.init();
    const snapshot = try std.testing.allocator.create(Snapshot);
    defer std.testing.allocator.destroy(snapshot);
    snapshot.* = Runtime.initSnapshot();

    const source_task = try createTaskIdTestTask(source, 8_001);
    _ = try createTaskIdTestTask(source, 8_010);
    source.writeSnapshot(snapshot);

    _ = try createTaskIdTestTask(restored, 8_001);
    _ = try createTaskIdTestTask(restored, 8_003);
    _ = try createTaskIdTestTask(restored, 8_004);
    const cold_records = restored.taskColdRecords().?;
    cold_records[0].capability_ids[MAX_TASK_CAPABILITIES - 1] = 0xCAFE;
    cold_records[1].capability_ids[MAX_TASK_CAPABILITIES - 1] = 0xBEEF;
    cold_records[1].capability_generation = 99;
    cold_records[2].capability_ids[MAX_TASK_CAPABILITIES - 1] = 0xFACE;
    cold_records[2].capability_generation = 100;

    try restored.restoreFromSnapshot(snapshot);

    const restored_cold = restored.taskColdRecords().?;
    try std.testing.expectEqual(@as(u64, 0xCAFE), restored_cold[0].capability_ids[MAX_TASK_CAPABILITIES - 1]);
    try std.testing.expectEqual(@as(u64, 0), restored_cold[1].capability_ids[MAX_TASK_CAPABILITIES - 1]);
    try std.testing.expectEqual(@as(u64, 1), restored_cold[1].capability_generation);
    try std.testing.expectEqual(@as(u64, 0), restored_cold[2].capability_ids[MAX_TASK_CAPABILITIES - 1]);
    try std.testing.expectEqual(@as(u64, 1), restored_cold[2].capability_generation);

    const live = restored.find(source_task.id).?;
    try std.testing.expectEqual(@as(usize, 0), live.capabilityIds().len);
    try restored.grantCapability(live.id, 0x1234);
    try std.testing.expectEqualSlices(u64, &.{0x1234}, live.capabilityIds());
}

test "snapshot restore preserves compact task denial provenance" {
    var runtime = Runtime.init();
    const task = try createTaskIdTestTask(&runtime, 24);
    const denial = debug_contract.explainDenied(
        .scope_violation,
        "endpoint-send",
        "endpoint_send",
        task.id,
        77,
        .endpoint,
        91,
    );
    try runtime.recordProvenance(task.id, debug_contract.provenance(
        .syscall,
        .denied,
        55,
        task.id,
        0,
        77,
        .endpoint,
        91,
        "endpoint-send",
        "scope=isolated",
        denial,
        0xA11CE,
    ));

    var snapshot = Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);
    var restored = Runtime.init();
    try restored.restoreFromSnapshot(&snapshot);

    const latest = restored.find(task.id).?.latestProvenanceEvent().?;
    try std.testing.expectEqual(debug_contract.Decision.denied, latest.decision);
    try std.testing.expectEqual(denial.reason, latest.denial_reason);
    try std.testing.expectEqual(denial.fingerprint, latest.denial_fingerprint);
    try std.testing.expectEqualStrings("endpoint-send", latest.operationSlice());
    try std.testing.expectEqualStrings("scope=isolated", latest.detailSlice());
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
    try std.testing.expectEqual(workspace_storage_image.entry_point, address_space.instruction_pointer);
    try std.testing.expectEqual(workspace_storage_image.segment_count, address_space.load_segment_count);
    try std.testing.expectEqual(workspace_storage_image.segment_count + 1, address_space.region_count);
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

test "provenance trail keeps the most recent events" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = TEST_MINIMAL_MEMORY_BYTES,
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
    });

    var index: usize = 0;
    while (index < MAX_TASK_PROVENANCE_EVENTS + 2) : (index += 1) {
        try runtime.recordProvenance(task.id, debug_contract.capabilityGrantProvenance(
            task.id,
            100 + index,
            index,
        ));
    }

    try std.testing.expectEqual(@as(usize, MAX_TASK_PROVENANCE_EVENTS), task.provenance_count);
    try std.testing.expectEqual(@as(u64, 102), task.provenanceEventAt(0).?.capability_id);
    try std.testing.expectEqual(@as(u64, 101 + MAX_TASK_PROVENANCE_EVENTS), task.latestProvenanceEvent().?.capability_id);
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
    const original_address_space_count = runtime.address_spaces.countInUse();
    try std.testing.expect(runtime.processSeparated(service_task.id, app_task.id));
    try std.testing.expectEqual(ProcessClass.service_sandbox, service_task.process_class);
    try std.testing.expectEqual(ProcessClass.app_sandbox, app_task.process_class);

    try std.testing.expect(try runtime.rehostTask(service_task.id, 55));
    try std.testing.expect(service_task.process_id != original_process_id);
    try std.testing.expect(service_task.address_space_id != original_address_space_id);
    try std.testing.expect(runtime.address_spaces.get(original_address_space_id) == null);
    try std.testing.expect(runtime.address_spaces.get(service_task.address_space_id) != null);
    try std.testing.expectEqual(original_address_space_count, runtime.address_spaces.countInUse());
    try std.testing.expectEqual(@as(u32, 2), service_task.process_generation);
    try std.testing.expectEqual(AuditEventKind.service_restarted, service_task.latestAuditEvent().?.kind);
}

test "rehosting a restored userspace task clones authoritative mapped state" {
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

    var snapshot = Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);
    var restored = Runtime.init();
    try restored.restoreFromSnapshot(&snapshot);

    const restored_task = restored.find(task.id).?;
    try std.testing.expect(restored_task.hasLoadedExecutable());
    const original_address_space_id = restored_task.address_space_id;
    const original_address_space = restored.findAddressSpaceConst(original_address_space_id).?.*;
    try std.testing.expect(try restored.rehostTask(restored_task.id, 77));
    try std.testing.expect(restored_task.address_space_id != original_address_space_id);
    try std.testing.expect(restored.findAddressSpaceConst(original_address_space_id) == null);

    const address_space = restored.findAddressSpaceConst(restored_task.address_space_id).?;
    try std.testing.expect(address_space.hasMappedExecutable());
    try std.testing.expectEqual(original_address_space.entry_point, address_space.instruction_pointer);
    try std.testing.expectEqual(original_address_space.stack_top, address_space.stack_pointer);
    try std.testing.expectEqual(original_address_space.load_segment_count, address_space.load_segment_count);
    try std.testing.expectEqual(original_address_space.region_count, address_space.region_count);
    try std.testing.expectEqualSlices(
        AddressSpaceRegionRecord,
        original_address_space.regions[0..original_address_space.region_count],
        address_space.regions[0..address_space.region_count],
    );
    try std.testing.expectEqualSlices(u8, &original_address_space.image_sha256, &address_space.image_sha256);
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

test "address-space retirement follows successful rehost and termination exactly once" {
    var runtime = Runtime.init();
    var recorder = RetirementRecorder{
        .runtime_to_observe = &runtime,
        .require_retired_address_space_absent = true,
    };
    try std.testing.expect(runtime.bindAddressSpaceRetirementSink(AddressSpaceRetirementSink.init(RetirementRecorder, &recorder)));
    const task = try createTaskIdTestTask(&runtime, 8_001);
    const task_id = task.id;
    const original_address_space_id = task.address_space_id;

    try std.testing.expectError(error.TaskNotFound, runtime.rehostTask(task_id + 1_000, 1));
    try std.testing.expectEqual(@as(usize, 0), recorder.count);

    try std.testing.expect(try runtime.rehostTask(task_id, 2));
    try std.testing.expectEqual(@as(usize, 1), recorder.count);
    try std.testing.expectEqual(original_address_space_id, recorder.eventAt(0).address_space_id);
    try std.testing.expectEqual(AddressSpaceRetirementReason.rehost, recorder.eventAt(0).reason);
    try std.testing.expect(runtime.findAddressSpaceConst(original_address_space_id) == null);

    const rehosted_address_space_id = runtime.find(task_id).?.address_space_id;
    try std.testing.expect(try runtime.terminateTask(task_id, 3));
    try std.testing.expectEqual(@as(usize, 2), recorder.count);
    try std.testing.expectEqual(rehosted_address_space_id, recorder.eventAt(1).address_space_id);
    try std.testing.expectEqual(AddressSpaceRetirementReason.terminate, recorder.eventAt(1).reason);
    try std.testing.expect(runtime.findAddressSpaceConst(rehosted_address_space_id) == null);
    try std.testing.expect(recorder.commit_observed);

    try std.testing.expect(!(try runtime.terminateTask(task_id, 4)));
    try std.testing.expect(!(try runtime.rehostTask(task_id, 5)));
    runtime.reset();
    try std.testing.expectEqual(@as(usize, 2), recorder.count);
}

test "address-space retirement reset is idempotent and keeps the sink bound" {
    var runtime = Runtime.init();
    const first = try createTaskIdTestTask(&runtime, 8_101);
    const first_address_space_id = first.address_space_id;
    const second = try createTaskIdTestTask(&runtime, 8_102);
    const second_address_space_id = second.address_space_id;
    var recorder = RetirementRecorder{
        .runtime_to_observe = &runtime,
        .require_retired_address_space_absent = true,
    };
    try std.testing.expect(runtime.bindAddressSpaceRetirementSink(AddressSpaceRetirementSink.init(RetirementRecorder, &recorder)));

    runtime.reset();
    try std.testing.expectEqual(@as(usize, 2), recorder.count);
    try std.testing.expectEqual(first_address_space_id, recorder.eventAt(0).address_space_id);
    try std.testing.expectEqual(second_address_space_id, recorder.eventAt(1).address_space_id);
    try std.testing.expectEqual(AddressSpaceRetirementReason.runtime_reset, recorder.eventAt(0).reason);
    try std.testing.expectEqual(AddressSpaceRetirementReason.runtime_reset, recorder.eventAt(1).reason);
    try std.testing.expect(recorder.commit_observed);

    runtime.reset();
    try std.testing.expectEqual(@as(usize, 2), recorder.count);

    const replacement = try createTaskIdTestTask(&runtime, 8_103);
    const replacement_address_space_id = replacement.address_space_id;
    runtime.reset();
    try std.testing.expectEqual(@as(usize, 3), recorder.count);
    try std.testing.expectEqual(replacement_address_space_id, recorder.eventAt(2).address_space_id);
    try std.testing.expectEqual(AddressSpaceRetirementReason.runtime_reset, recorder.eventAt(2).reason);
}

test "sparse checkpoints preserve cross-page slot order and retire only live address spaces" {
    const runtime = try std.testing.allocator.create(Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = Runtime.init();
    const snapshot = try std.testing.allocator.create(Snapshot);
    defer std.testing.allocator.destroy(snapshot);
    snapshot.* = Runtime.initSnapshot();

    const task_count = model.TASK_PAGE_SIZE + 4;
    var task_ids: [task_count]u64 = undefined;
    for (&task_ids, 0..) |*task_id, index| {
        const task = try createTaskIdTestTask(runtime, 8_200 + index);
        task_id.* = task.id;
    }
    const first_task_id = task_ids[0];
    const removed_task_id = task_ids[1];
    const stale_task_handle = runtime.taskHandle(removed_task_id).?;
    const high_task_id = task_ids[task_ids.len - 1];
    try runtime.grantCapability(high_task_id, 0xBEEF);
    try runtime.audit(high_task_id, .{
        .kind = .policy_allowed,
        .detail = 0xA11D,
        .tick = 77,
    });

    var task_index = task_ids.len - 1;
    while (task_index > 1) {
        task_index -= 1;
        const task_id = task_ids[task_index];
        const slot_index = runtime.tasks.slotIndexOf(task_id).?;
        const owner = runtime.tasks.slotAtConst(slot_index).task.owner;
        try std.testing.expect(try runtime.terminateTask(task_id, @intCast(100 + task_index)));
        try std.testing.expect(runtime.task_owner_index.remove(taskOwnerIndexKey(owner), slot_index));
        runtime.task_state_counts[taskStateIndex(.terminated)] -= 1;
        try std.testing.expect(runtime.tasks.removeIndex(slot_index));
    }

    const replacement = try createTaskIdTestTask(runtime, 9_000);
    const replacement_task_id = replacement.id;
    try std.testing.expect(replacement_task_id > high_task_id);
    try std.testing.expectEqual(@as(usize, 1), runtime.tasks.slotIndexOf(replacement_task_id).?);
    try std.testing.expectError(error.TaskNotFound, runtime.terminateTaskByHandle(stale_task_handle, removed_task_id, 200));
    try std.testing.expectEqual(TaskState.active, replacement.state);
    try std.testing.expectEqual(task_count, runtime.tasks.claimedCount());
    try std.testing.expectEqual(task_count, runtime.address_spaces.claimedCount());

    runtime.writeSnapshot(snapshot);
    try std.testing.expectEqual(@as(usize, 3), snapshot.task_count);
    try std.testing.expectEqual(@as(usize, 3), snapshot.address_space_count);
    const expected_task_ids = [_]u64{ first_task_id, replacement_task_id, high_task_id };
    for (expected_task_ids, 0..) |expected_task_id, dense_index| {
        const snapshot_task = &snapshot.tasks[dense_index].task;
        try std.testing.expectEqual(expected_task_id, snapshot_task.id);
        try std.testing.expectEqual(
            snapshot_task.address_space_id,
            snapshot.address_spaces[dense_index].address_space.id,
        );
    }
    const high_snapshot_task = &snapshot.tasks[2].task;
    try std.testing.expectEqualSlices(u64, &.{0xBEEF}, high_snapshot_task.capabilityIds());
    try std.testing.expectEqual(AuditEventKind.policy_allowed, high_snapshot_task.latestAuditEvent().?.kind);
    try std.testing.expectEqual(@as(u64, 77), high_snapshot_task.latestAuditEvent().?.tick);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.launch, high_snapshot_task.provenanceEventAt(0).?.kind);

    var recorder = RetirementRecorder{
        .runtime_to_observe = runtime,
        .require_retired_address_space_absent = true,
    };
    try std.testing.expect(runtime.bindAddressSpaceRetirementSink(AddressSpaceRetirementSink.init(RetirementRecorder, &recorder)));
    const expected_address_space_ids = [_]u64{
        snapshot.tasks[0].task.address_space_id,
        snapshot.tasks[1].task.address_space_id,
        snapshot.tasks[2].task.address_space_id,
    };
    runtime.reset();
    try std.testing.expectEqual(@as(usize, 3), recorder.count);
    for (expected_address_space_ids, 0..) |expected_address_space_id, event_index| {
        try std.testing.expectEqual(expected_address_space_id, recorder.eventAt(event_index).address_space_id);
        try std.testing.expectEqual(AddressSpaceRetirementReason.runtime_reset, recorder.eventAt(event_index).reason);
    }
    try std.testing.expect(recorder.commit_observed);
}

test "address-space retirement binding is exclusive and compare-and-unbind preserves a newer sink" {
    var runtime = Runtime.init();
    var original_recorder = RetirementRecorder{};
    var newer_recorder = RetirementRecorder{};
    const original_sink = AddressSpaceRetirementSink.init(RetirementRecorder, &original_recorder);
    const newer_sink = AddressSpaceRetirementSink.init(RetirementRecorder, &newer_recorder);
    const different_callback_sink = AddressSpaceRetirementSink{
        .context = original_sink.context,
        .notify_fn = struct {
            fn notify(_: *anyopaque, _: AddressSpaceRetirementEvent) void {}
        }.notify,
    };

    try std.testing.expect(original_sink.eql(original_sink));
    try std.testing.expect(!original_sink.eql(newer_sink));
    try std.testing.expect(!original_sink.eql(different_callback_sink));

    try std.testing.expect(runtime.bindAddressSpaceRetirementSink(original_sink));
    try std.testing.expect(!runtime.bindAddressSpaceRetirementSink(original_sink));
    try std.testing.expect(!runtime.bindAddressSpaceRetirementSink(newer_sink));

    _ = try createTaskIdTestTask(&runtime, 8_151);
    runtime.reset();
    try std.testing.expectEqual(@as(usize, 1), original_recorder.count);
    try std.testing.expectEqual(@as(usize, 0), newer_recorder.count);

    try std.testing.expect(runtime.unbindAddressSpaceRetirementSink(original_sink));
    try std.testing.expect(runtime.bindAddressSpaceRetirementSink(newer_sink));
    try std.testing.expect(!runtime.unbindAddressSpaceRetirementSink(original_sink));
    _ = try createTaskIdTestTask(&runtime, 8_152);
    runtime.reset();
    try std.testing.expectEqual(@as(usize, 1), newer_recorder.count);
    try std.testing.expect(runtime.unbindAddressSpaceRetirementSink(newer_sink));
    try std.testing.expect(!runtime.unbindAddressSpaceRetirementSink(newer_sink));
}

test "address-space retirement on snapshot restore replaces only runtime state and never snapshots the sink" {
    const source = try std.testing.allocator.create(Runtime);
    defer std.testing.allocator.destroy(source);
    source.* = Runtime.init();
    const source_task = try createTaskIdTestTask(source, 8_201);
    const source_task_id = source_task.id;
    const source_address_space_id = source_task.address_space_id;
    var source_recorder = RetirementRecorder{};
    try std.testing.expect(source.bindAddressSpaceRetirementSink(AddressSpaceRetirementSink.init(RetirementRecorder, &source_recorder)));
    const snapshot = try std.testing.allocator.create(Snapshot);
    defer std.testing.allocator.destroy(snapshot);
    snapshot.* = Runtime.initSnapshot();
    source.writeSnapshot(snapshot);

    const restored = try std.testing.allocator.create(Runtime);
    defer std.testing.allocator.destroy(restored);
    restored.* = Runtime.init();
    restored.next_address_space_id = 100;
    const replaced_first = try createTaskIdTestTask(restored, 8_202);
    const replaced_first_address_space_id = replaced_first.address_space_id;
    const replaced_second = try createTaskIdTestTask(restored, 8_203);
    const replaced_second_address_space_id = replaced_second.address_space_id;
    var restored_recorder = RetirementRecorder{
        .runtime_to_observe = restored,
        .required_live_address_space_id = source_address_space_id,
        .require_retired_address_space_absent = true,
    };
    const restored_sink = AddressSpaceRetirementSink.init(RetirementRecorder, &restored_recorder);
    try std.testing.expect(restored.bindAddressSpaceRetirementSink(restored_sink));

    try restored.restoreFromSnapshot(snapshot);
    try std.testing.expectEqual(@as(usize, 2), restored_recorder.count);
    try std.testing.expectEqual(replaced_first_address_space_id, restored_recorder.eventAt(0).address_space_id);
    try std.testing.expectEqual(replaced_second_address_space_id, restored_recorder.eventAt(1).address_space_id);
    try std.testing.expectEqual(AddressSpaceRetirementReason.snapshot_restore, restored_recorder.eventAt(0).reason);
    try std.testing.expectEqual(AddressSpaceRetirementReason.snapshot_restore, restored_recorder.eventAt(1).reason);
    try std.testing.expect(restored.findAddressSpaceConst(source_address_space_id) != null);
    try std.testing.expect(restored_recorder.commit_observed);

    restored_recorder.required_live_address_space_id = null;
    try std.testing.expect(try restored.terminateTask(source_task_id, 9));
    try std.testing.expectEqual(@as(usize, 3), restored_recorder.count);
    try std.testing.expectEqual(source_address_space_id, restored_recorder.eventAt(2).address_space_id);
    try std.testing.expectEqual(AddressSpaceRetirementReason.terminate, restored_recorder.eventAt(2).reason);
    try std.testing.expect(restored_recorder.commit_observed);

    try std.testing.expect(restored.unbindAddressSpaceRetirementSink(restored_sink));
    try restored.restoreFromSnapshot(snapshot);
    restored.reset();
    try std.testing.expectEqual(@as(usize, 0), source_recorder.count);
}

test "task state counts track lifecycle transitions and snapshot restore" {
    try std.testing.expect(@FieldType(Runtime, "task_state_counts") == [TASK_STATE_COUNT]TaskStateCount);
    try std.testing.expectEqual(@as(usize, RUNTIME_SIZE_CEILING_BYTES), @sizeOf(Runtime));

    var runtime = Runtime.init();
    try std.testing.expectEqual(@as(u64, 1), runtime.taskLifecycleGeneration());
    const first = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 9 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
    });
    const first_task_id = first.id;
    try std.testing.expectEqual(@as(u64, 2), runtime.taskLifecycleGeneration());
    const second = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 10 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
    });
    const second_task_id = second.id;
    try std.testing.expectEqual(@as(u64, 3), runtime.taskLifecycleGeneration());

    try std.testing.expectEqual(@as(usize, 0), runtime.countTasksInState(.staged));
    try std.testing.expectEqual(@as(usize, 2), runtime.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 0), runtime.countTasksInState(.suspended));
    try std.testing.expectEqual(@as(usize, 0), runtime.countTasksInState(.terminated));

    try std.testing.expect(try runtime.suspendTask(first_task_id, 11));
    try std.testing.expectEqual(@as(u64, 4), runtime.taskLifecycleGeneration());
    try std.testing.expect(!try runtime.suspendTask(first_task_id, 11));
    try std.testing.expectEqual(@as(u64, 4), runtime.taskLifecycleGeneration());
    try std.testing.expectEqual(@as(usize, 1), runtime.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 1), runtime.countTasksInState(.suspended));

    try std.testing.expect(try runtime.resumeTask(first_task_id, 12));
    try std.testing.expectEqual(@as(u64, 5), runtime.taskLifecycleGeneration());
    try std.testing.expectEqual(@as(usize, 2), runtime.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 0), runtime.countTasksInState(.suspended));

    try std.testing.expect(try runtime.terminateTask(second_task_id, 13));
    try std.testing.expectEqual(@as(u64, 6), runtime.taskLifecycleGeneration());
    try std.testing.expect(!try runtime.terminateTask(second_task_id, 13));
    try std.testing.expectEqual(@as(u64, 6), runtime.taskLifecycleGeneration());
    try std.testing.expectEqual(@as(usize, 1), runtime.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 1), runtime.countTasksInState(.terminated));

    var snapshot = Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);
    var restored = Runtime.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(@as(u64, 2), restored.taskLifecycleGeneration());

    try std.testing.expectEqual(@as(usize, 1), restored.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 1), restored.countTasksInState(.terminated));

    restored.reset();
    try std.testing.expectEqual(@as(u64, 3), restored.taskLifecycleGeneration());
    try std.testing.expectEqual(@as(usize, 0), restored.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 0), restored.countTasksInState(.terminated));

    restored.task_lifecycle_generation = std.math.maxInt(u64);
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(@as(u64, 1), restored.taskLifecycleGeneration());
    restored.task_lifecycle_generation = std.math.maxInt(u64);
    restored.reset();
    try std.testing.expectEqual(@as(u64, 1), restored.taskLifecycleGeneration());
}

test "initial component label lookup is indexed across lifecycle and restore" {
    var runtime = Runtime.init();
    const first = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 11 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
        .initial_component = .{
            .label = "indexed-service",
            .entry = "zigos.indexed.first",
        },
    });
    const first_task_id = first.id;
    const second = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 12 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = TEST_MINIMAL_SHARED_MEMORY_BYTES,
        },
        .initial_component = .{
            .label = "indexed-service",
            .entry = "zigos.indexed.second",
        },
    });
    const second_task_id = second.id;

    try std.testing.expectEqual(second_task_id, runtime.findByInitialComponentLabel("indexed-service").?.id);
    try std.testing.expect(runtime.findByInitialComponentLabel("missing-service") == null);

    try std.testing.expect(try runtime.suspendTask(second_task_id, 21));
    try std.testing.expectEqual(first_task_id, runtime.findByInitialComponentLabel("indexed-service").?.id);

    try std.testing.expect(try runtime.resumeTask(second_task_id, 22));
    try std.testing.expectEqual(second_task_id, runtime.findByInitialComponentLabel("indexed-service").?.id);

    var snapshot = Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);
    var restored = Runtime.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(second_task_id, restored.findByInitialComponentLabel("indexed-service").?.id);

    try std.testing.expect(try restored.terminateTask(second_task_id, 23));
    try std.testing.expectEqual(first_task_id, restored.findByInitialComponentLabel("indexed-service").?.id);

    try std.testing.expect(try restored.terminateTask(first_task_id, 24));
    try std.testing.expect(restored.findByInitialComponentLabel("indexed-service") == null);
}
