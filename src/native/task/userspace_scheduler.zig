const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const accelerator_scheduler = @import("accelerator_scheduler.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const syscall_broker = @import("../kernel_api/syscall_broker.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const dispatch_ownership = @import("dispatch_ownership.zig");
const ids = @import("../core/ids.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("task_runtime.zig");
const units = @import("../core/units.zig");
const userspace_executor = @import("userspace_executor.zig");
const userspace_loader = @import("userspace_loader.zig");
const userspace_flags = @import("userspace_flags.zig");
const smp = @import("../../kernel/smp.zig");
const generated_image_fixtures = if (builtin.is_test) @import("generated_image_fixtures.zig") else struct {};
const table_backing = @import("../core/table_backing.zig");
const root = @import("root");
const architecture_proof_enabled = if (@hasDecl(root, "ARCHITECTURE_SMP_PROOF")) root.ARCHITECTURE_SMP_PROOF else false;

// The isolated CPL0 guest binds the production mapping domain and callbacks
// without installing native userspace entry or changing dispatch admission.
pub const ArchitectureProof = if (architecture_proof_enabled) struct {
    pub fn bindDomain(scheduler: *Scheduler, runtime: *task_runtime.Runtime) bool {
        if (!smp.isRuntimeOwner() or scheduler.initialized or scheduler.runtime_ptr != null or scheduler.executor_binding_claimed or
            scheduler.active_dispatch_task_id != 0 or scheduler.active_dispatch_lease != null) return false;
        if (!scheduler.claimRuntimeOwnership(runtime, true)) return false;
        scheduler.runtime_ptr = runtime;
        scheduler.initialized = true;
        return true;
    }
} else struct {};

// These are exactly the diagnostics already retained in the native image.
// One immutable blob and independently stored offsets avoid one object per
// message; the cold selector keeps invariant reporting off the service path.
const SchedulerInvariant = enum(u8) {
    scheduler_deinitialization_follows_active_dispatch_handoff,
    scheduler_deinitialization_follows_every_runtime_execution_lease,
    userspace_runtime_retirement_ownership_changed_while_bound,
    userspace_executor_ownership_has_no_runtime,
    userspace_executor_ownership_changed_while_bound,
    userspace_executor_or_runtime_already_has_an_owner,
    dispatch_accounting_storage_is_available,
    dispatch_accounting_is_allocated_with_its_scheduler_slot,
    syscall_service_claims_only_exact_running_remote_requests,
    syscall_service_retains_its_exact_processing_request,
    syscall_completion_targets_an_admitted_remote_owner,
    scheduler_dispatch_is_owned_by_one_active_task,
    scheduler_dispatch_retains_its_execution_lease,
    scheduler_finishes_its_exact_active_dispatch,
    scheduler_cancels_only_its_unstarted_reservation,
    scheduler_collects_its_exact_quiescent_execution,
    faulted_userspace_dispatch_has_no_exception_record,
    faulted_userspace_task_was_already_terminated,
    accelerator_claim_task_index_points_outside_claim_slots,
    accelerator_claim_task_index_points_at_a_free_slot,
    accelerator_claim_task_index_points_at_the_wrong_task,
    userspace_scheduler_mutation_belongs_to_the_runtime_owner_cpu,
    execution_stop_ipi_target_is_not_an_admitted_remote_cpu,
};

const scheduler_invariant_messages = [_][]const u8{
    "scheduler deinitialization follows active dispatch handoff",
    "scheduler deinitialization follows every runtime execution lease",
    "userspace runtime retirement ownership changed while bound",
    "userspace executor ownership has no runtime",
    "userspace executor ownership changed while bound",
    "userspace executor or runtime already has an owner",
    "dispatch accounting storage is available",
    "dispatch accounting is allocated with its scheduler slot",
    "syscall service claims only exact running remote requests",
    "syscall service retains its exact processing request",
    "syscall completion targets an admitted remote owner",
    "scheduler dispatch is owned by one active task",
    "scheduler dispatch retains its execution lease",
    "scheduler finishes its exact active dispatch",
    "scheduler cancels only its unstarted reservation",
    "scheduler collects its exact quiescent execution",
    "faulted userspace dispatch has no exception record",
    "faulted userspace task was already terminated",
    "accelerator claim task index points outside claim slots",
    "accelerator claim task index points at a free slot",
    "accelerator claim task index points at the wrong task",
    "userspace scheduler mutation belongs to the runtime owner CPU",
    "execution-stop IPI target is not an admitted remote CPU",
};

const scheduler_invariant_message_bytes: []const u8 = blk: {
    if (scheduler_invariant_messages.len != @typeInfo(SchedulerInvariant).@"enum".field_names.len)
        @compileError("scheduler invariant messages must cover every selector");
    var bytes: []const u8 = "";
    for (scheduler_invariant_messages) |message| bytes = bytes ++ message;
    if (bytes.len > std.math.maxInt(u16)) @compileError("scheduler invariant message offsets must fit u16");
    break :blk bytes;
};

const scheduler_invariant_message_offsets = blk: {
    var offsets: [scheduler_invariant_messages.len + 1]u16 = undefined;
    var cursor: usize = 0;
    for (scheduler_invariant_messages, 0..) |message, index| {
        offsets[index] = @intCast(cursor);
        cursor += message.len;
    }
    offsets[scheduler_invariant_messages.len] = @intCast(cursor);
    break :blk offsets;
};

fn schedulerInvariantFailure(selector: SchedulerInvariant) noreturn {
    @branchHint(.cold);
    const index: usize = @backingInt(selector);
    native_util.impossibleByInvariant(scheduler_invariant_message_bytes[scheduler_invariant_message_offsets[index]..scheduler_invariant_message_offsets[index + 1]]);
}

// Shared service mutation remains one nonreentrant BSP operation. Interrupt
// handlers only nudge; this guard also excludes synchronous callback reentry.
var syscall_service_active = false;

const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

// Resource-accounting credits are separate from the hardware timer clock.
const DISPATCH_CPU_TICK_COST: u64 = 1_000;
pub const RESOURCE_CLASS_COUNT: usize = @typeInfo(accelerator_scheduler.ResourceClass).@"enum".field_names.len;
pub const ENGINE_COUNT: usize = @typeInfo(accelerator_scheduler.Engine).@"enum".field_names.len;
pub const UNIFIED_RUNQUEUE = true;
pub const MAX_ACCELERATOR_CLAIMS: usize = task_runtime.MAX_TASKS;
// Aging targets use the canonical timer clock as actual user preemption and wakes.
const EMERGENCY_DEADLINE_DELTA_TICKS = units.millisecondsToTimerTicksCeil(10);
const FOREGROUND_DEADLINE_DELTA_TICKS = units.millisecondsToTimerTicksCeil(50);
const MEDIA_EXPORT_DEADLINE_DELTA_TICKS = units.millisecondsToTimerTicksCeil(200);
const BACKGROUND_DEADLINE_DELTA_TICKS = units.millisecondsToTimerTicksCeil(500);
const BATCH_DEADLINE_DELTA_TICKS = units.millisecondsToTimerTicksCeil(1000);
const USER_EXCEPTION_CRASH_SERVICE_ID: u64 = 0;
const USER_EXCEPTION_REDACTION_POLICY_VERSION: u16 = 1;
const TEST_TASK_MEMORY_BYTES: usize = 1024;
const TEST_TASK_ENDPOINT_SLOTS: u16 = 2;
const TEST_TASK_SHARED_MEMORY_BYTES: usize = 1024;
const TEST_ACCELERATOR_SHARED_MEMORY_BYTES: usize = 4096;
const TEST_ACCELERATOR_DEADLINE_TICKS: u64 = 20;
const MEMORY_BANDWIDTH_UNIT_BYTES: usize = 1024;
const arena_no_index = indexed_arena.no_index;
pub const QueueSlotIndex = u8;
pub const QUEUE_NO_INDEX: QueueSlotIndex = @intCast(task_runtime.MAX_TASKS);
pub const COMPACT_QUEUE_METADATA = true;
pub const SINGLE_RUNTIME_OWNER = true;
pub const PREEMPTS_BATCH_FOR_INTERACTIVE = true;
var bound_preempt_scheduler: ?*Scheduler = null;
pub const STEADY_UI_ELIGIBILITY_CATALOG_LOOKUPS: u8 = 0;
pub const TASK_REGISTRATION_HANDLE_SLOT_RELOOKUPS: u8 = 0;
pub const TASK_WAKE_HANDLE_SLOT_RELOOKUPS: u8 = 0;
pub const FAULT_CONTAINMENT_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const SCHEDULED_TASK_INDEX_LOOKUPS_PER_DISPATCH: u8 = 0;
pub const ACCELERATOR_WAIT_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const TASK_UNREGISTER_SLOT_RELOOKUPS: u8 = 0;
pub const ACCELERATOR_RANK_TASK_INDEX_LOOKUPS_PER_CANDIDATE: u8 = 1;
pub const ACCELERATOR_RANK_BACKING_RELOOKUPS_PER_COMPARISON: u8 = 0;
pub const ACCELERATOR_INSERT_BACKING_RELOOKUPS: u8 = 0;
pub const ACCELERATOR_REMOVE_BACKING_RELOOKUPS: u8 = 0;
pub const ACCELERATOR_ENQUEUE_BACKING_RELOOKUPS: u8 = 0;
pub const ACCELERATOR_WAIT_DISPATCH_REQUEST_DERIVATIONS: u8 = 1;

comptime {
    if (task_runtime.MAX_TASKS > std.math.maxInt(QueueSlotIndex) or
        MAX_ACCELERATOR_CLAIMS > std.math.maxInt(QueueSlotIndex))
    {
        @compileError("userspace scheduler queues no longer fit compact slot indexes");
    }
}

pub const WakeReason = enum(u8) {
    registered,
    ipc_message,
    timer,
    accelerator_available,
    budget_refill,
    external_event,
};

pub const AcceleratorClaimRequest = struct {
    task_id: u64,
    engine: accelerator_scheduler.Engine,
    resource_class: accelerator_scheduler.ResourceClass,
    requested_at_tick: u64,
    deadline_tick: u64 = 0,
    shared_memory_bytes: usize = 0,
};

pub const AcceleratorClaimRecord = struct {
    id: u64,
    task_id: u64,
    engine: accelerator_scheduler.Engine,
    resource_class: accelerator_scheduler.ResourceClass,
    requested_at_tick: u64,
    deadline_tick: u64,
    shared_memory_bytes: usize,
};

const TaskSchedulingRank = struct {
    dispatch_count: u64,
    last_dispatch_tick: u64,
};

const ReadyCandidate = struct {
    slot_index: usize,
    task: ?*task_runtime.TaskRecord = null,
    request: accelerator_scheduler.Request = .{ .class = .foreground_interactive },
    decision: ?accelerator_scheduler.Decision = null,
};

pub const TaskDispatchStats = struct {
    task_id: u64,
    resource_class: accelerator_scheduler.ResourceClass,
    queued_ready: bool,
    dispatch_count: u64,
    event_wait_count: u64,
    ui_state_update_count: u64,
    last_ui_state_revision: u64,
    delayed_dispatch_count: u64,
    denied_dispatch_count: u64,
    missed_deadline_count: u64,
    last_dispatch_tick: u64,
    last_wake_tick: u64,
    wake_event_count: u64,
    cpu_ticks_consumed: u64,
    memory_bandwidth_consumed_units: usize,
    last_dispatch_engine: accelerator_scheduler.Engine,
    last_dispatch_reason: accelerator_scheduler.DecisionReason,
    last_dispatch_degraded: bool,
    last_dispatch_zero_copy: bool,
};

const DispatchAccounting = struct {
    event_wait_count: u64 = 0,
    ui_state_update_count: u64 = 0,
    last_ui_state_revision: u64 = 0,
    last_wake_tick: u64 = 0,
    wake_event_count: u64 = 0,
    cpu_ticks_consumed: u64 = 0,
    memory_bandwidth_consumed_units: usize = 0,
    missed_deadline_count: u64 = 0,
    last_dispatch_engine: accelerator_scheduler.Engine = .cpu,
    last_dispatch_reason: accelerator_scheduler.DecisionReason = .normal,
    last_dispatch_degraded: bool = false,
    last_dispatch_zero_copy: bool = false,
    last_policy_delay_tick: u64 = 0,
    delayed_dispatch_count: u64 = 0,
    denied_dispatch_count: u64 = 0,
};

const DispatchAccountingStorage = [task_runtime.MAX_TASKS]DispatchAccounting;

const Slot = struct {
    in_use: bool = false,
    task_id: u64 = 0,
    task_handle: task_runtime.TaskHandle = .{},
    mapping_handle: userspace_executor.MappingHandle = .{},
    resource_class: accelerator_scheduler.ResourceClass = .foreground_interactive,
    queued_ready: bool = false,
    prev_ready_index: QueueSlotIndex = QUEUE_NO_INDEX,
    next_ready_index: QueueSlotIndex = QUEUE_NO_INDEX,
    dispatch_count: u64 = 0,
    owns_ui_surface: bool = false,
    last_dispatch_tick: u64 = 0,
    cpu_budget_remaining_ticks: u64 = 0,
    deadline_tick: u64 = 0,
    dispatch_request: accelerator_scheduler.Request = .{ .class = .foreground_interactive },
    dispatch_request_configured: bool = false,
    require_accelerator: bool = false,
    pending_accelerator_claim_id: u64 = 0,
    // With no claim id, a non-CPU engine retains a ready waiter whose claim
    // could not be reserved or whose engine is online but policy denies it.
    pending_accelerator_engine: accelerator_scheduler.Engine = .cpu,

    comptime {
        if (@sizeOf(@This()) > SCHEDULER_SLOT_SIZE_CEILING_BYTES) {
            @compileError("userspace scheduler slot exceeds its compact size ceiling");
        }
    }
};

const AcceleratorClaimSlot = struct {
    in_use: bool = false,
    record: AcceleratorClaimRecord = zeroAcceleratorClaim(),
    prev_claim_index: QueueSlotIndex = QUEUE_NO_INDEX,
    next_claim_index: QueueSlotIndex = QUEUE_NO_INDEX,
    prev_deadline_index: QueueSlotIndex = QUEUE_NO_INDEX,
    next_deadline_index: QueueSlotIndex = QUEUE_NO_INDEX,

    comptime {
        if (@sizeOf(@This()) > ACCELERATOR_CLAIM_SLOT_SIZE_CEILING_BYTES) {
            @compileError("userspace accelerator claim slot exceeds its compact size ceiling");
        }
    }
};

const SchedulerSlotArena = indexed_arena.IndexedArenaWithKey(u64, Slot, task_runtime.MAX_TASKS, task_runtime.MAX_TASKS * 2, schedulerSlotTaskId);
const AcceleratorClaimArena = indexed_arena.IndexedArenaWithKey(u64, AcceleratorClaimSlot, MAX_ACCELERATOR_CLAIMS, MAX_ACCELERATOR_CLAIMS * 2, acceleratorClaimSlotId);
const AcceleratorClaimTaskIndex = indexed_arena.MultimapIndex(MAX_ACCELERATOR_CLAIMS, MAX_ACCELERATOR_CLAIMS, MAX_ACCELERATOR_CLAIMS * 2);
const ColdDispatchKind = enum(u8) {
    none = 0,
    completed = 1,
    delayed = 2,
    denied = 3,
};

const ColdDispatchNote = struct {
    active: bool = false,
    kind: ColdDispatchKind = .none,
    slot_index: u16 = 0,
    engine: accelerator_scheduler.Engine = .cpu,
    denial_engine: accelerator_scheduler.Engine = .cpu,
    reason: accelerator_scheduler.DecisionReason = .normal,
    degraded: bool = false,
    zero_copy: bool = false,
    record_decision: bool = false,
    wait_for_event: bool = false,
    missed_deadline: bool = false,
    owns_ui: bool = false,
    bandwidth: usize = 0,
    ui_revision: u64 = 0,
    now_ticks: u64 = 0,
};

const heap_backed_accelerator_claims = builtin.target.os.tag == .freestanding;
pub const SCHEDULER_SLOT_SIZE_CEILING_BYTES: usize = 176;
pub const DISPATCH_ACCOUNTING_IS_COLD = true;
pub const ACCELERATOR_CLAIM_SLOT_SIZE_CEILING_BYTES: usize = 56;
pub const ACCELERATOR_CLAIM_BACKING_SIZE_CEILING_BYTES: usize = 15_888;
pub const SCHEDULER_SIZE_CEILING_BYTES: usize = (if (heap_backed_accelerator_claims) @as(usize, 30_704) else 46_584) + @sizeOf(?dispatch_ownership.Ticket);

pub const AcceleratorClaimBacking = struct {
    claims: AcceleratorClaimArena = AcceleratorClaimArena.init(),
    task_index: AcceleratorClaimTaskIndex = AcceleratorClaimTaskIndex.init(),

    fn init() AcceleratorClaimBacking {
        return .{};
    }

    fn initializeAllocated(self: *AcceleratorClaimBacking) void {
        @memset(std.mem.asBytes(self), 0);
        self.claims.free_head = indexed_arena.reusableNoIndex(MAX_ACCELERATOR_CLAIMS);
        const CompactIndex = @FieldType(AcceleratorClaimTaskIndex, "free_bucket_head");
        const compact_no_index: CompactIndex = @intCast(MAX_ACCELERATOR_CLAIMS);
        for (&self.task_index.links) |*link| link.bucket = compact_no_index;
        self.task_index.free_bucket_head = compact_no_index;
    }

    comptime {
        if (@sizeOf(@This()) > ACCELERATOR_CLAIM_BACKING_SIZE_CEILING_BYTES) {
            @compileError("userspace accelerator claim backing exceeds its compact size ceiling");
        }
    }
};

const AcceleratorClaimBackingStorage = if (heap_backed_accelerator_claims) ?*AcceleratorClaimBacking else AcceleratorClaimBacking;

pub const Scheduler = struct {
    executor: *userspace_executor.Executor,
    executor_binding_claimed: bool = false,
    initialized: bool = false,
    catalog_ptr: ?*userspace_loader.Catalog = null,
    runtime_ptr: ?*task_runtime.Runtime = null,
    capability_table_ptr: ?*const capability.CapabilityTable = null,
    endpoint_table_ptr: ?*const endpoint.Table = null,
    slots: SchedulerSlotArena = SchedulerSlotArena.init(),
    dispatch_accounting: ?*DispatchAccountingStorage = null,
    ready_heads: [RESOURCE_CLASS_COUNT]QueueSlotIndex = @as([RESOURCE_CLASS_COUNT]QueueSlotIndex, @splat(QUEUE_NO_INDEX)),
    ready_tails: [RESOURCE_CLASS_COUNT]QueueSlotIndex = @as([RESOURCE_CLASS_COUNT]QueueSlotIndex, @splat(QUEUE_NO_INDEX)),
    ready_counts: [RESOURCE_CLASS_COUNT]QueueSlotIndex = @as([RESOURCE_CLASS_COUNT]QueueSlotIndex, @splat(0)),
    ready_task_count: QueueSlotIndex = 0,
    accelerator_claim_backing: AcceleratorClaimBackingStorage = if (heap_backed_accelerator_claims) null else AcceleratorClaimBacking.init(),
    accelerator_claim_heads: [ENGINE_COUNT]QueueSlotIndex = @as([ENGINE_COUNT]QueueSlotIndex, @splat(QUEUE_NO_INDEX)),
    accelerator_claim_tails: [ENGINE_COUNT]QueueSlotIndex = @as([ENGINE_COUNT]QueueSlotIndex, @splat(QUEUE_NO_INDEX)),
    accelerator_deadline_heads: [ENGINE_COUNT]QueueSlotIndex = @as([ENGINE_COUNT]QueueSlotIndex, @splat(QUEUE_NO_INDEX)),
    accelerator_deadline_tails: [ENGINE_COUNT]QueueSlotIndex = @as([ENGINE_COUNT]QueueSlotIndex, @splat(QUEUE_NO_INDEX)),
    accelerator_claim_counts: [ENGINE_COUNT]QueueSlotIndex = @as([ENGINE_COUNT]QueueSlotIndex, @splat(0)),
    engine_dispatch_counts: [ENGINE_COUNT]u64 = @as([ENGINE_COUNT]u64, @splat(0)),
    engine_denial_counts: [ENGINE_COUNT]u64 = @as([ENGINE_COUNT]u64, @splat(0)),
    next_accelerator_claim_id: u64 = 1,
    resource_state: accelerator_scheduler.SystemState = .{},
    resource_telemetry_source: accelerator_scheduler.TelemetrySource = .synthetic,
    resource_telemetry_observed_tick: u64 = 0,
    resource_hardware_evidence_complete: bool = false,
    last_dispatch_tick: u64 = 0,
    active_dispatch_task_id: u64 = 0,
    active_dispatch_lease: ?dispatch_ownership.Ticket = null,
    cold_note: ColdDispatchNote = .{},
    ready_marker_printed: bool = false,
    active_marker_printed: bool = false,
    event_wait_marker_printed: bool = false,
    ui_state_marker_printed: bool = false,

    comptime {
        if (@sizeOf(@This()) > SCHEDULER_SIZE_CEILING_BYTES) {
            @compileError("userspace scheduler exceeds its compact resident size ceiling");
        }
    }

    pub fn init(executor: *userspace_executor.Executor) Scheduler {
        return .{ .executor = executor };
    }

    pub fn initializeAllocated(self: *Scheduler, executor: *userspace_executor.Executor) void {
        requireRuntimeOwner();
        @memset(std.mem.asBytes(self), 0);
        self.executor = executor;
        self.slots.free_head = indexed_arena.reusableNoIndex(task_runtime.MAX_TASKS);
        @memset(&self.ready_heads, QUEUE_NO_INDEX);
        @memset(&self.ready_tails, QUEUE_NO_INDEX);
        for (&self.accelerator_claim_heads) |*head| head.* = QUEUE_NO_INDEX;
        for (&self.accelerator_claim_tails) |*tail| tail.* = QUEUE_NO_INDEX;
        for (&self.accelerator_deadline_heads) |*head| head.* = QUEUE_NO_INDEX;
        for (&self.accelerator_deadline_tails) |*tail| tail.* = QUEUE_NO_INDEX;
        if (comptime !heap_backed_accelerator_claims) {
            self.accelerator_claim_backing.initializeAllocated();
        }
        self.next_accelerator_claim_id = 1;
        self.resource_state = .{};
        self.resource_telemetry_source = .synthetic;
    }

    fn acceleratorClaimBacking(self: *Scheduler) ?*AcceleratorClaimBacking {
        if (comptime heap_backed_accelerator_claims) return self.accelerator_claim_backing;
        return &self.accelerator_claim_backing;
    }

    fn acceleratorClaimBackingConst(self: *const Scheduler) ?*const AcceleratorClaimBacking {
        if (comptime heap_backed_accelerator_claims) return self.accelerator_claim_backing;
        return &self.accelerator_claim_backing;
    }

    fn ensureAcceleratorClaimBacking(self: *Scheduler) ?*AcceleratorClaimBacking {
        if (self.acceleratorClaimBacking()) |backing| return backing;
        if (comptime heap_backed_accelerator_claims) {
            const backing = table_backing.alloc(AcceleratorClaimBacking) orelse return null;
            backing.initializeAllocated();
            self.accelerator_claim_backing = backing;
            return backing;
        }
        return &self.accelerator_claim_backing;
    }

    fn releaseAcceleratorClaimBacking(self: *Scheduler) void {
        if (comptime heap_backed_accelerator_claims) {
            if (self.accelerator_claim_backing) |backing| {
                table_backing.free(AcceleratorClaimBacking, backing);
                self.accelerator_claim_backing = null;
            }
        }
    }

    pub fn deinit(self: *Scheduler) void {
        requireRuntimeOwner();
        const x86 = @import("../../arch/x86.zig");
        const restore_if = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_if) x86.sti();
        };
        if (self.active_dispatch_task_id != 0 or self.active_dispatch_lease != null)
            @call(.never_inline, schedulerInvariantFailure, .{.scheduler_deinitialization_follows_active_dispatch_handoff});
        if (self.runtime_ptr) |runtime| {
            if (runtime.execution.hasLeases())
                @call(.never_inline, schedulerInvariantFailure, .{.scheduler_deinitialization_follows_every_runtime_execution_lease});
            if (runtime.lifecycle_transition_active)
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_runtime_retirement_ownership_changed_while_bound});
        }
        const runtime = self.runtime_ptr;
        if (self.executor_binding_claimed) {
            const bound_runtime = runtime orelse
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_ownership_has_no_runtime});
            if (self.executor.binding_owner != @as(*const anyopaque, self) or self.executor.bound_runtime != bound_runtime)
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_ownership_changed_while_bound});
            // All mappings and their shared registrations must drain while the
            // exact domain callback context is still bound. Remote cleanup does
            // not reset another CPU's native entry or registration selection.
            if (!userspace_executor.releaseRegisteredDomain(self, bound_runtime))
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_runtime_retirement_ownership_changed_while_bound});
            if (builtin.target.os.tag == .freestanding or self.ownsRuntimeSinks(bound_runtime)) {
                if (!self.unbindRuntimeSinks(bound_runtime))
                    @call(.never_inline, schedulerInvariantFailure, .{.userspace_runtime_retirement_ownership_changed_while_bound});
            }
        }
        if (bound_preempt_scheduler == self) {
            bound_preempt_scheduler = null;
            userspace_executor.setPreemptCheck(null);
        }
        if (self.executor_binding_claimed) {
            self.executor.deinit();
            const bound_runtime = runtime orelse
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_ownership_has_no_runtime});
            if (!self.executor.releaseRuntimeBinding(self, bound_runtime)) {
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_ownership_changed_while_bound});
            }
        }
        self.executor_binding_claimed = false;
        self.initialized = false;
        self.catalog_ptr = null;
        self.runtime_ptr = null;
        self.capability_table_ptr = null;
        self.endpoint_table_ptr = null;
        self.releaseAcceleratorClaimBacking();
        self.releaseDispatchAccounting();
    }

    pub fn reset(self: *Scheduler) void {
        const executor = self.executor;
        self.deinit();
        self.initializeAllocated(executor);
    }

    pub fn bind(
        self: *Scheduler,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        capability_table: *const capability.CapabilityTable,
    ) void {
        requireRuntimeOwner();
        if (self.initialized or self.runtime_ptr != null) self.reset();
        if (!self.claimRuntimeOwnership(runtime, builtin.target.os.tag == .freestanding))
            @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_or_runtime_already_has_an_owner});
        self.catalog_ptr = catalog;
        self.runtime_ptr = runtime;
        self.capability_table_ptr = capability_table;
        self.initialized = true;
        self.last_dispatch_tick = 0;
        self.executor.init();
        bound_preempt_scheduler = self;
        userspace_executor.setPreemptCheck(preemptCheck);
        if (builtin.target.os.tag == .freestanding and !self.ready_marker_printed) {
            common.printBootMarker(boot_markers.userspace_scheduler_ready);
            self.ready_marker_printed = true;
        }
    }

    fn executionStopSink(self: *Scheduler) task_runtime.ExecutionStopSink {
        return .{ .context = self, .notify = notifyExecutionStop };
    }

    fn addressSpaceRetirementSink(self: *Scheduler) task_runtime.AddressSpaceRetirementSink {
        return task_runtime.AddressSpaceRetirementSink.init(Scheduler, self);
    }

    pub fn retireAddressSpace(self: *Scheduler, event: task_runtime.AddressSpaceRetirementEvent) void {
        requireRuntimeOwner();
        const x86 = @import("../../arch/x86.zig");
        const restore_if = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_if) x86.sti();
        };
        const runtime = self.executor.bound_runtime orelse
            @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_ownership_has_no_runtime});
        if (self.executor.binding_owner != @as(*const anyopaque, self) or (self.runtime_ptr != null and self.runtime_ptr != runtime) or
            !userspace_executor.retireRegisteredAddressSpace(self, runtime, event))
            @call(.never_inline, schedulerInvariantFailure, .{.userspace_runtime_retirement_ownership_changed_while_bound});
    }

    fn ownsRuntimeSinks(self: *Scheduler, runtime: *task_runtime.Runtime) bool {
        const sink = runtime.address_space_retirement_sink orelse return false;
        return sink.eql(self.addressSpaceRetirementSink());
    }

    fn claimRuntimeOwnership(self: *Scheduler, runtime: *task_runtime.Runtime, comptime bind_sinks: bool) bool {
        const x86 = @import("../../arch/x86.zig");
        const restore_if = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_if) x86.sti();
        };
        if (!self.executor.claimRuntimeBinding(self, runtime)) return false;
        if (bind_sinks and !self.executor.claimMappingRegistration(0, self, runtime)) {
            if (!self.executor.releaseRuntimeBinding(self, runtime))
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_ownership_changed_while_bound});
            return false;
        }
        if (bind_sinks and !self.bindRuntimeSinks(runtime)) {
            if (!self.executor.releaseMappingRegistration(0, self, runtime) or
                !self.executor.releaseRuntimeBinding(self, runtime))
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_ownership_changed_while_bound});
            return false;
        }
        self.executor_binding_claimed = true;
        return true;
    }

    fn bindRuntimeSinks(self: *Scheduler, runtime: *task_runtime.Runtime) bool {
        // Rollback is safe only before any owner can start or retain callbacks.
        if (runtime.execution.hasLeases()) return false;
        if (!runtime.bindAddressSpaceRetirementSink(self.addressSpaceRetirementSink())) return false;
        if (!runtime.bindExecutionStopSink(self.executionStopSink())) {
            if (!runtime.unbindAddressSpaceRetirementSink(self.addressSpaceRetirementSink()))
                @call(.never_inline, schedulerInvariantFailure, .{.userspace_runtime_retirement_ownership_changed_while_bound});
            return false;
        }
        if (self.executor.bindMappedObjectLifetime()) return true;
        if (!runtime.unbindExecutionStopSink(self.executionStopSink()) or
            !runtime.unbindAddressSpaceRetirementSink(self.addressSpaceRetirementSink()))
            @call(.never_inline, schedulerInvariantFailure, .{.userspace_runtime_retirement_ownership_changed_while_bound});
        return false;
    }

    fn unbindRuntimeSinks(self: *Scheduler, runtime: *task_runtime.Runtime) bool {
        const x86 = @import("../../arch/x86.zig");
        const restore_if = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_if) x86.sti();
        };
        if (self.executor.binding_owner != @as(*const anyopaque, self) or self.executor.bound_runtime != runtime or
            runtime.execution.hasLeases() or runtime.lifecycle_transition_active) return false;
        const address_sink = runtime.address_space_retirement_sink orelse return false;
        const stop_sink = runtime.execution_stop_sink orelse return false;
        if (!address_sink.eql(self.addressSpaceRetirementSink()) or !stop_sink.eql(self.executionStopSink()) or
            !self.executor.mappedObjectLifetimeIsBound()) return false;
        // Refuse outstanding Table tokens before removing either Runtime sink.
        if (!self.executor.unbindMappedObjectLifetime()) return false;
        if (!runtime.unbindExecutionStopSink(self.executionStopSink())) return false;
        return runtime.unbindAddressSpaceRetirementSink(self.addressSpaceRetirementSink());
    }

    pub fn configureResourceState(self: *Scheduler, state: accelerator_scheduler.SystemState) void {
        requireRuntimeOwner();
        self.resource_state = state;
        self.resource_telemetry_source = .synthetic;
        self.resource_telemetry_observed_tick = 0;
        self.resource_hardware_evidence_complete = false;
    }

    pub fn configureResourceTelemetry(self: *Scheduler, sample: accelerator_scheduler.TelemetrySample) void {
        requireRuntimeOwner();
        if (!accelerator_scheduler.telemetrySampleIsFresh(
            self.resource_telemetry_source,
            self.resource_telemetry_observed_tick,
            sample,
        )) return;
        self.resource_state = sample.toSystemState();
        self.resource_telemetry_source = sample.source;
        self.resource_telemetry_observed_tick = sample.observed_tick;
        self.resource_hardware_evidence_complete = sample.hardwareReaderEvidenceComplete();
    }

    pub fn configureResourceTelemetryFromProvider(
        self: *Scheduler,
        provider: accelerator_scheduler.TelemetryProvider,
    ) void {
        requireRuntimeOwner();
        self.configureResourceTelemetry(provider.read());
    }

    pub fn observedResourceTelemetry(self: *const Scheduler) bool {
        return self.resource_telemetry_source != .synthetic;
    }

    pub fn registerTask(self: *Scheduler, task_id: u64) bool {
        if (!smp.isRuntimeOwner() or !self.initialized) return false;
        return self.registerTaskAt(task_id, registrationTimerTicks());
    }

    pub fn registerTaskAt(self: *Scheduler, task_id: u64, now_ticks: u64) bool {
        if (!smp.isRuntimeOwner()) return false;
        if (!self.initialized) return false;
        if (self.taskHasExecutionLease(task_id)) return false;
        const runtime = self.runtime_ptr orelse return false;
        const task = runtime.find(task_id) orelse return false;
        if (task.state == .terminated) return false;
        const task_handle = runtime.taskHandleForResolved(task);
        const catalog = self.catalog_ptr orelse return false;
        const owns_ui_surface = taskUiPresentationEligible(catalog, task);
        const slot_index = self.slots.reserveIndex(task_id) orelse blk: {
            self.pruneRetiredSlots(runtime);
            break :blk self.slots.reserveIndex(task_id) orelse return false;
        };
        const slot = &self.slots.slots[slot_index];
        slot.task_id = task_id;
        slot.task_handle = task_handle;
        slot.resource_class = task.resourceClass();
        slot.dispatch_request = deriveDispatchRequest(task);
        slot.dispatch_request_configured = false;
        slot.require_accelerator = false;
        slot.owns_ui_surface = owns_ui_surface;
        slot.cpu_budget_remaining_ticks = task.budget.cpu_time_ticks;
        slot.deadline_tick = deadlineFromNow(slot.resource_class, now_ticks);
        self.accountingStorage()[slot_index] = .{};
        self.accountingStorage()[slot_index].last_wake_tick = now_ticks;
        self.accountingStorage()[slot_index].wake_event_count = 1;
        return self.enqueueReadyIndex(slot_index, slot.resource_class);
    }

    pub fn configureTaskDispatchRequest(
        self: *Scheduler,
        task_id: u64,
        request: accelerator_scheduler.Request,
        require_accelerator: bool,
    ) bool {
        if (!smp.isRuntimeOwner()) return false;
        const runtime = self.runtime_ptr orelse return false;
        const task = runtime.find(task_id) orelse return false;
        const slot = self.slots.get(task_id) orelse return false;
        var configured_request = request;
        configured_request.class = task.resourceClass();
        if (require_accelerator and requestedAcceleratorEngine(configured_request) == .cpu) return false;
        slot.dispatch_request = configured_request;
        slot.dispatch_request_configured = true;
        slot.require_accelerator = require_accelerator;
        if (slot.pending_accelerator_claim_id == 0) slot.pending_accelerator_engine = .cpu;
        return true;
    }

    pub fn unregisterTask(self: *Scheduler, task_id: u64) bool {
        if (!smp.isRuntimeOwner()) return false;
        if (self.taskHasExecutionLease(task_id)) return false;
        const slot_index = self.slots.slotIndexOf(task_id) orelse return false;
        return self.unregisterSlotIndex(slot_index);
    }

    pub fn parkTaskUntilEvent(self: *Scheduler, task_id: u64) bool {
        if (!smp.isRuntimeOwner()) return false;
        const slot_index = self.slots.slotIndexOf(task_id) orelse return false;
        if (self.hasPendingIpc(task_id)) return false;
        self.unlinkReadyIndex(slot_index);
        return true;
    }

    pub fn bindEndpointTable(self: *Scheduler, table: *const endpoint.Table) void {
        requireRuntimeOwner();
        self.endpoint_table_ptr = table;
    }

    fn hasPendingIpc(self: *const Scheduler, task_id: u64) bool {
        const table = self.endpoint_table_ptr orelse return false;
        return table.hasPendingForTask(ids.task(task_id));
    }

    pub fn wakeTask(
        self: *Scheduler,
        task_id: u64,
        reason: WakeReason,
        now_ticks: u64,
        deadline_tick: u64,
    ) bool {
        if (!smp.isRuntimeOwner()) return false;
        if (!self.initialized) return false;
        const runtime = self.runtime_ptr orelse return false;
        const slot_index = self.slots.slotIndexOf(task_id) orelse return false;
        const slot = &self.slots.slots[slot_index];
        var task_handle = slot.task_handle;
        // Registered wakes reuse their checked incarnation. Restore can retire
        // that handle while keeping the task ID, so refresh only on a miss.
        const task = runtime.findByHandle(task_handle, task_id) orelse refresh: {
            const resolved = runtime.find(task_id) orelse return false;
            task_handle = runtime.taskHandleForResolved(resolved);
            break :refresh resolved;
        };
        if (task.state != .active) return false;
        const already_ready = slot.queued_ready;
        if (slot.queued_ready and slot.resource_class != task.resourceClass()) {
            self.unlinkReadyIndex(slot_index);
        }
        if (!slot.task_handle.eql(task_handle)) slot.mapping_handle = .{};
        slot.task_handle = task_handle;
        slot.resource_class = task.resourceClass();
        const accounting = self.accountingForSlot(slot);
        accounting.last_wake_tick = now_ticks;
        accounting.wake_event_count += 1;
        const wake_deadline = if (deadline_tick != 0) deadline_tick else deadlineFromNow(slot.resource_class, now_ticks);
        // Coalesced events can tighten a waiting activation's deadline, but
        // cannot postpone its service indefinitely under sustained load.
        slot.deadline_tick = if (already_ready and slot.deadline_tick != 0)
            @min(slot.deadline_tick, wake_deadline)
        else
            wake_deadline;
        // A newly woken task starts an activation with its configured budget.
        // Leftover credit from a previous interaction must not strand this one
        // between reading input and publishing its reply. Coalesced wakes do
        // not refill an already-ready task; explicit refills keep their amount.
        if (!already_ready and reason != .budget_refill) {
            slot.cpu_budget_remaining_ticks = @max(slot.cpu_budget_remaining_ticks, task.budget.cpu_time_ticks);
        }
        return self.enqueueReadyIndex(slot_index, slot.resource_class);
    }

    pub fn refillTaskBudget(self: *Scheduler, task_id: u64, cpu_ticks: u64, now_ticks: u64) bool {
        if (!smp.isRuntimeOwner()) return false;
        const slot = self.slots.get(task_id) orelse return false;
        slot.cpu_budget_remaining_ticks = std.math.add(u64, slot.cpu_budget_remaining_ticks, cpu_ticks) catch std.math.maxInt(u64);
        return self.wakeTask(task_id, .budget_refill, now_ticks, 0);
    }

    pub fn readyQueueDepth(self: *const Scheduler, class: accelerator_scheduler.ResourceClass) usize {
        const queue_index = resourceClassIndex(class);
        return self.ready_counts[queue_index];
    }

    pub fn hasReadyTasks(self: *const Scheduler) bool {
        return self.ready_task_count != 0;
    }

    // Policy-delayed tasks retain their queue position while the owner sleeps.
    // Invalid or exhausted entries remain actionable until runNext removes them.
    pub fn hasDispatchableTasks(self: *const Scheduler, now_ticks: u64) bool {
        if (!self.initialized or !smp.isRuntimeOwner()) return false;
        for (engine_priority_order) |engine| {
            if (self.accelerator_claim_counts[engineIndex(engine)] != 0 and self.physicalEngineAvailable(engine)) return true;
        }
        return self.selectReadyCandidate(now_ticks) != null;
    }

    pub fn taskDispatchStats(self: *const Scheduler, task_id: u64) ?TaskDispatchStats {
        if (!smp.isRuntimeOwner()) return null;
        const slot = self.slots.getConst(task_id) orelse return null;
        const accounting = self.accountingForSlotConst(slot);
        return .{
            .task_id = slot.task_id,
            .resource_class = slot.resource_class,
            .queued_ready = slot.queued_ready,
            .dispatch_count = slot.dispatch_count,
            .event_wait_count = accounting.event_wait_count,
            .ui_state_update_count = accounting.ui_state_update_count,
            .last_ui_state_revision = accounting.last_ui_state_revision,
            .delayed_dispatch_count = accounting.delayed_dispatch_count,
            .denied_dispatch_count = accounting.denied_dispatch_count,
            .missed_deadline_count = accounting.missed_deadline_count,
            .last_dispatch_tick = slot.last_dispatch_tick,
            .last_wake_tick = accounting.last_wake_tick,
            .wake_event_count = accounting.wake_event_count,
            .cpu_ticks_consumed = accounting.cpu_ticks_consumed,
            .memory_bandwidth_consumed_units = accounting.memory_bandwidth_consumed_units,
            .last_dispatch_engine = accounting.last_dispatch_engine,
            .last_dispatch_reason = accounting.last_dispatch_reason,
            .last_dispatch_degraded = accounting.last_dispatch_degraded,
            .last_dispatch_zero_copy = accounting.last_dispatch_zero_copy,
        };
    }

    fn accountingStorage(self: *Scheduler) *DispatchAccountingStorage {
        if (self.dispatch_accounting) |storage| return storage;
        const storage = table_backing.alloc(DispatchAccountingStorage) orelse
            @call(.never_inline, schedulerInvariantFailure, .{.dispatch_accounting_storage_is_available});
        self.dispatch_accounting = storage;
        return storage;
    }

    fn releaseDispatchAccounting(self: *Scheduler) void {
        if (self.dispatch_accounting) |storage| {
            table_backing.free(DispatchAccountingStorage, storage);
            self.dispatch_accounting = null;
        }
    }

    pub fn accountingForSlot(self: *Scheduler, slot: *const Slot) *DispatchAccounting {
        requireRuntimeOwner();
        self.publishColdNote();
        return &self.accountingStorage()[self.accountingIndex(slot)];
    }

    fn accountingForSlotConst(self: *const Scheduler, slot: *const Slot) *const DispatchAccounting {
        requireRuntimeOwner();
        const scheduler = @constCast(self);
        scheduler.publishColdNote();
        const storage = scheduler.dispatch_accounting orelse
            @call(.never_inline, schedulerInvariantFailure, .{.dispatch_accounting_is_allocated_with_its_scheduler_slot});
        return &storage[self.accountingIndex(slot)];
    }

    pub fn taskDispatchAccounting(self: *const Scheduler, task_id: u64) ?*const DispatchAccounting {
        if (!smp.isRuntimeOwner()) return null;
        const slot = self.slots.getConst(task_id) orelse return null;
        return self.accountingForSlotConst(slot);
    }

    fn accountingIndex(self: *const Scheduler, slot: *const Slot) usize {
        const base = @intFromPtr(&self.slots.slots[0]);
        return (@intFromPtr(slot) - base) / @sizeOf(Slot);
    }

    pub fn enqueueAcceleratorClaim(self: *Scheduler, request: AcceleratorClaimRequest) ?u64 {
        if (!smp.isRuntimeOwner()) return null;
        if (!self.initialized or request.engine == .cpu) return null;
        const task_slot = self.slots.get(request.task_id) orelse return null;
        return self.enqueueAcceleratorClaimForSlot(request, task_slot);
    }

    fn enqueueAcceleratorClaimForSlot(
        self: *Scheduler,
        request: AcceleratorClaimRequest,
        task_slot: *Slot,
    ) ?u64 {
        if (builtin.mode == .debug) {
            std.debug.assert(self.initialized);
            std.debug.assert(request.engine != .cpu);
            std.debug.assert(task_slot.in_use and task_slot.task_id == request.task_id);
        }
        const backing = self.ensureAcceleratorClaimBacking() orelse return null;
        if (findAcceleratorClaimForTaskEngine(backing, request.task_id, request.engine)) |claim_id| {
            return claim_id;
        }

        const claim_id = self.nextAcceleratorClaimId(backing) orelse return null;
        const claim_index = backing.claims.reserveIndex(claim_id) orelse return null;
        const slot = &backing.claims.slots[claim_index];
        slot.record = .{
            .id = claim_id,
            .task_id = request.task_id,
            .engine = request.engine,
            .resource_class = request.resource_class,
            .requested_at_tick = request.requested_at_tick,
            .deadline_tick = request.deadline_tick,
            .shared_memory_bytes = request.shared_memory_bytes,
        };
        if (!backing.task_index.append(acceleratorClaimTaskKey(request.task_id), claim_index)) {
            _ = backing.claims.removeIndex(claim_index);
            return null;
        }
        self.insertAcceleratorClaimIndex(backing, request.engine, claim_index);
        self.next_accelerator_claim_id +%= 1;
        if (task_slot.pending_accelerator_claim_id == 0) {
            task_slot.pending_accelerator_claim_id = claim_id;
            task_slot.pending_accelerator_engine = request.engine;
        }
        return claim_id;
    }

    pub fn grantNextAcceleratorClaim(
        self: *Scheduler,
        engine: accelerator_scheduler.Engine,
        now_ticks: u64,
    ) ?AcceleratorClaimRecord {
        if (!smp.isRuntimeOwner()) return null;
        if (!self.physicalEngineAvailable(engine)) return null;
        const backing = self.acceleratorClaimBacking() orelse return null;
        const runtime = self.runtime_ptr orelse return null;
        while (self.popBestAcceleratorClaimIndex(backing, engine, now_ticks)) |claim_index| {
            const record = backing.claims.slots[claim_index].record;
            _ = backing.claims.removeIndex(claim_index);
            if (self.slots.get(record.task_id)) |slot| {
                if (slot.pending_accelerator_claim_id == record.id) {
                    slot.pending_accelerator_claim_id = 0;
                    slot.pending_accelerator_engine = .cpu;
                }
                const task = runtime.findByHandle(slot.task_handle, record.task_id);
                if (task == null or task.?.state == .terminated) {
                    if (!self.taskHasExecutionLease(record.task_id))
                        _ = self.unregisterSlotIndex(self.slots.slotIndexOf(record.task_id).?);
                    continue;
                }
                // Suspended tasks retain their slot; an eventual resume wake
                // replans their engine request without consuming a live grant.
                if (task.?.state != .active) continue;
                _ = self.wakeTask(record.task_id, .accelerator_available, now_ticks, record.deadline_tick);
                return record;
            }
        }
        return null;
    }

    pub fn acceleratorClaimQueueDepth(self: *const Scheduler, engine: accelerator_scheduler.Engine) usize {
        return @intCast(self.accelerator_claim_counts[engineIndex(engine)]);
    }

    pub fn engineDispatchCount(self: *const Scheduler, engine: accelerator_scheduler.Engine) u64 {
        if (!smp.isRuntimeOwner()) return 0;
        const scheduler = @constCast(self);
        scheduler.publishColdNote();
        return scheduler.engine_dispatch_counts[engineIndex(engine)];
    }

    pub fn engineDenialCount(self: *const Scheduler, engine: accelerator_scheduler.Engine) u64 {
        if (!smp.isRuntimeOwner()) return 0;
        const scheduler = @constCast(self);
        scheduler.publishColdNote();
        return scheduler.engine_denial_counts[engineIndex(engine)];
    }

    pub fn executeTask(self: *Scheduler, task_id: u64, now_ticks: u64) userspace_executor.ExecutionOutcome {
        return self.executeTaskWithDispatch(task_id, now_ticks, self).outcome;
    }

    pub fn servicePendingSyscalls(self: *Scheduler, port: *const component_port.KernelPort, now_ticks: u64) u8 {
        if (!smp.isRuntimeOwner() or !self.initialized or syscall_service_active) return 0;
        const runtime = self.runtime_ptr orelse return 0;
        if (port.kernel.runtime != runtime or self.executor.bound_runtime != runtime or self.executor.binding_owner != @as(*const anyopaque, self)) return 0;
        const x86 = @import("../../arch/x86.zig");
        const restore_if = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_if) x86.sti();
        };
        syscall_service_active = true;
        defer syscall_service_active = false;
        var serviced: u8 = 0;
        for (1..dispatch_ownership.CAPACITY) |index| {
            var claim: dispatch_ownership.ClaimedSyscall = undefined;
            runtime.execution.claimSyscallInto(@intCast(index), &claim) catch |err| switch (err) {
                error.NoRequest, error.WrongPhase, error.StopRequested => continue,
                else => @call(.never_inline, schedulerInvariantFailure, .{.syscall_service_claims_only_exact_running_remote_requests}),
            };
            var bound: dispatch_ownership.BoundIdentity = undefined;
            var stopped: bool = undefined;
            runtime.execution.validateClaimInto(&claim, &bound, &stopped) catch
                @call(.never_inline, schedulerInvariantFailure, .{.syscall_service_retains_its_exact_processing_request});
            var copy: syscall_broker.CopySession = undefined;
            if (!stopped and self.executor.prepareSyscallCopySession(&claim, &copy)) {
                syscall_broker.serviceClaim(port, &claim, &copy, now_ticks) catch
                    @call(.never_inline, schedulerInvariantFailure, .{.syscall_service_retains_its_exact_processing_request});
            } else {
                runtime.execution.completeSyscall(claim.key, .{ .status = @intCast(@backingInt(@import("../core/abi.zig").SyscallStatus.unavailable)), .denial_reason = 0, .bytes_written = 0 }) catch
                    @call(.never_inline, schedulerInvariantFailure, .{.syscall_service_retains_its_exact_processing_request});
            }
            if (comptime builtin.target.os.tag == .freestanding) {
                if (!smp.notifySyscallCompletion(@intCast(index)))
                    @call(.never_inline, schedulerInvariantFailure, .{.syscall_completion_targets_an_admitted_remote_owner});
            }
            serviced += 1;
        }
        return serviced;
    }

    fn executeTaskWithDispatch(self: *Scheduler, task_id: u64, now_ticks: u64, dispatcher: anytype) dispatch_ownership.ReturnRecord {
        if (!smp.isRuntimeOwner()) return .{};
        if (!self.initialized or self.active_dispatch_task_id != 0) return .{};
        const runtime = self.runtime_ptr orelse return .{};
        const task = runtime.find(task_id) orelse return .{};
        const ticket = self.beginTaskDispatch(runtime, task, smp.currentCpuIndex()) orelse return .{};
        defer self.finishTaskDispatch(runtime, ticket);
        var uncached_mapping_handle = userspace_executor.MappingHandle{};
        const mapping_handle = if (self.slots.get(task_id)) |slot|
            &slot.mapping_handle
        else
            &uncached_mapping_handle;
        const record = dispatcher.executePreparedTask(task, mapping_handle, now_ticks);
        if (record.outcome == .faulted) self.containUserException(runtime, task, now_ticks, &record);
        return record;
    }

    fn executePreparedTask(
        self: *Scheduler,
        task: *const task_runtime.TaskRecord,
        mapping_handle: *userspace_executor.MappingHandle,
        now_ticks: u64,
    ) dispatch_ownership.ReturnRecord {
        if (!self.initialized) return .{};
        const catalog = self.catalog_ptr orelse return .{};
        const runtime = self.runtime_ptr orelse return .{};
        const capability_table = self.capability_table_ptr orelse return .{};
        const ticket = self.active_dispatch_lease orelse return .{};
        return self.executor.executeTask(catalog, runtime, capability_table, task, mapping_handle, now_ticks, ticket);
    }

    pub fn runNext(self: *Scheduler, now_ticks: u64) bool {
        return self.runNextWithDispatch(now_ticks, self);
    }

    fn runNextWithDispatch(self: *Scheduler, now_ticks: u64, dispatcher: anytype) bool {
        if (!self.initialized or !smp.isRuntimeOwner() or self.active_dispatch_task_id != 0) return false;

        self.wakeAvailableAcceleratorClaims(now_ticks);
        const runtime = self.runtime_ptr orelse return false;

        while (self.ready_task_count != 0) {
            const candidate = self.selectReadyCandidate(now_ticks) orelse {
                if (self.accountBlockedReadyClasses(now_ticks)) {
                    self.last_dispatch_tick = now_ticks;
                }
                break;
            };
            const index = candidate.slot_index;
            const slot = &self.slots.slots[index];
            if (!slot.in_use) continue;

            const task_id = slot.task_id;
            const task = candidate.task orelse {
                self.unlinkReadyIndex(index);
                _ = self.unregisterSlotIndex(index);
                continue;
            };
            if (task.state != .active or !task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) {
                self.unlinkReadyIndex(index);
                if (task.state == .terminated) _ = self.unregisterSlotIndex(index);
                continue;
            }
            if (!hasDispatchBudget(slot, task)) {
                self.unlinkReadyIndex(index);
                self.noteDenied(slot, .cpu_budget, .cpu, .cpu, false);
                continue;
            }

            const dispatch_request = candidate.request;
            const decision = candidate.decision.?;
            if (self.dispatchRequiresUnavailableAccelerator(slot, decision)) {
                self.unlinkReadyIndex(index);
                const requested_engine = requestedAcceleratorEngine(dispatch_request);
                self.noteAcceleratorDenied(slot, decision, requested_engine);
                self.queuePendingAcceleratorWake(
                    index,
                    slot,
                    dispatch_request,
                    now_ticks,
                );
                self.last_dispatch_tick = now_ticks;
                return false;
            }

            // A rejected reservation preserves this activation's exact queue
            // position, accounting and credits for its eventual owner.
            const ticket = self.beginTaskDispatch(runtime, task, smp.currentCpuIndex()) orelse return false;
            defer self.finishTaskDispatch(runtime, ticket);
            self.unlinkReadyIndex(index);
            if (slot.pending_accelerator_claim_id == 0) slot.pending_accelerator_engine = .cpu;

            const dispatch_memory_bandwidth_units = memoryBandwidthUnitsFor(task);
            const missed_deadline = slot.deadline_tick != 0 and now_ticks > slot.deadline_tick;
            const record = dispatcher.executePreparedTask(task, &slot.mapping_handle, now_ticks);
            const outcome = record.outcome;
            const yielded = outcome.handedOff();
            self.last_dispatch_tick = now_ticks;
            slot.dispatch_count += 1;
            if (outcome == .wait_for_event and builtin.target.os.tag == .freestanding and !self.event_wait_marker_printed) {
                common.printBootMarker(boot_markers.userspace_scheduler_event_wait_ready);
                self.event_wait_marker_printed = true;
            }
            const ui_revision = record.ui_revision;
            if (outcome.handedOff() and
                slot.owns_ui_surface and
                ui_revision > self.observedUiRevision(slot) and
                builtin.target.os.tag == .freestanding and
                !self.ui_state_marker_printed)
            {
                common.printBootMarker(boot_markers.userspace_ui_state_ready);
                self.ui_state_marker_printed = true;
            }
            slot.last_dispatch_tick = now_ticks;
            slot.cpu_budget_remaining_ticks -|= DISPATCH_CPU_TICK_COST;
            self.resource_state.cpu_budget_ticks -|= DISPATCH_CPU_TICK_COST;
            self.resource_state.memory_bandwidth_units -|= dispatch_memory_bandwidth_units;
            self.noteCompleted(
                slot,
                decision,
                outcome == .wait_for_event,
                missed_deadline,
                ui_revision,
                dispatch_memory_bandwidth_units,
            );
            if (outcome == .faulted) {
                self.containUserException(runtime, task, now_ticks, &record);
                return true;
            }
            if (builtin.target.os.tag == .freestanding and yielded and !self.active_marker_printed) {
                common.printBootMarker(boot_markers.userspace_scheduler_active);
                self.active_marker_printed = true;
            }
            if (runtime.findByHandle(slot.task_handle, task_id)) |updated_task| {
                if (updated_task.state == .terminated) {
                    return yielded;
                }
                if (!taskEligibleForPostDispatchRequeue(task_id, updated_task, slot)) return yielded;
                slot.resource_class = updated_task.resourceClass();
                if (!slot.dispatch_request_configured) slot.dispatch_request = deriveDispatchRequest(updated_task);
                slot.deadline_tick = deadlineAfterDispatch(slot.resource_class, now_ticks);
                if (executionRemainsReady(outcome) or
                    (outcome == .wait_for_event and self.hasPendingIpc(task_id)))
                {
                    _ = self.enqueueReadyIndex(index, slot.resource_class);
                }
            } else {
                _ = self.unregisterSlotIndex(index);
            }
            return yielded;
        }

        self.last_dispatch_tick = now_ticks;
        return false;
    }

    fn beginTaskDispatch(self: *Scheduler, runtime: *task_runtime.Runtime, task: *const task_runtime.TaskRecord, cpu: u8) ?dispatch_ownership.Ticket {
        if (self.active_dispatch_task_id != 0 or self.active_dispatch_lease != null)
            @call(.never_inline, schedulerInvariantFailure, .{.scheduler_dispatch_is_owned_by_one_active_task});
        var ticket: dispatch_ownership.Ticket = undefined;
        runtime.reserveExecutionInto(task, cpu, &ticket) catch return null;
        // Runtime retains the task pin and exact execution identity through
        // handoff, scheduler accounting and synchronous retirement callbacks.
        self.active_dispatch_task_id = task.id;
        self.active_dispatch_lease = ticket;
        return ticket;
    }

    fn finishTaskDispatch(self: *Scheduler, runtime: *task_runtime.Runtime, ticket: dispatch_ownership.Ticket) void {
        const active = self.active_dispatch_lease orelse
            @call(.never_inline, schedulerInvariantFailure, .{.scheduler_dispatch_retains_its_execution_lease});
        if (active.issuer != ticket.issuer or active.cpu != ticket.cpu or active.epoch != ticket.epoch or self.active_dispatch_task_id == 0)
            @call(.never_inline, schedulerInvariantFailure, .{.scheduler_finishes_its_exact_active_dispatch});
        const task_id = self.active_dispatch_task_id;
        // Model callbacks and failed preparation never start execution. An
        // actual entry may only be collected after its quiescent return ack.
        if (runtime.cancelUnstartedExecution(ticket)) |_| {
            // A canceled prepared command publishes a canonical unavailable
            // receipt. Consume it before collection just like an owner return;
            // a reservation canceled before binding has no prepared receipt.
            var canceled: dispatch_ownership.ReturnRecord = undefined;
            runtime.execution.consumePreparedReturnInto(ticket, &canceled) catch |err| switch (err) {
                error.WrongPurpose => {},
                else => @call(.never_inline, schedulerInvariantFailure, .{.scheduler_cancels_only_its_unstarted_reservation}),
            };
        } else |err| switch (err) {
            error.WrongPhase => switch (runtime.execution.phase(ticket) catch
                @call(.never_inline, schedulerInvariantFailure, .{.scheduler_cancels_only_its_unstarted_reservation})) {
                .returned, .return_consumed => {},
                else => @call(.never_inline, schedulerInvariantFailure, .{.scheduler_cancels_only_its_unstarted_reservation}),
            },
            else => @call(.never_inline, schedulerInvariantFailure, .{.scheduler_cancels_only_its_unstarted_reservation}),
        }
        runtime.collectExecution(ticket) catch
            @call(.never_inline, schedulerInvariantFailure, .{.scheduler_collects_its_exact_quiescent_execution});
        if (!userspace_executor.collectRegisteredRetiredMappings(self, runtime))
            @call(.never_inline, schedulerInvariantFailure, .{.userspace_runtime_retirement_ownership_changed_while_bound});
        self.active_dispatch_lease = null;
        self.active_dispatch_task_id = 0;
        // Collection can run reentrant lifetime callbacks. Do not dereference
        // the old TaskRecord or Slot after releasing their execution pin.
        const task = runtime.find(task_id);
        if (task == null or task.?.state == .terminated) {
            if (self.slots.slotIndexOf(task_id)) |index| _ = self.unregisterSlotIndex(index);
        }
    }

    inline fn taskHasExecutionLease(self: *const Scheduler, task_id: u64) bool {
        if (task_id == self.active_dispatch_task_id) return true;
        const runtime = self.runtime_ptr orelse return false;
        return runtime.execution.hasLeaseForTask(task_id);
    }

    fn containUserException(
        self: *Scheduler,
        runtime: *task_runtime.Runtime,
        task: *task_runtime.TaskRecord,
        now_ticks: u64,
        record: *const dispatch_ownership.ReturnRecord,
    ) void {
        _ = self;
        if (record.outcome != .faulted)
            @call(.never_inline, schedulerInvariantFailure, .{.faulted_userspace_dispatch_has_no_exception_record});
        const exception = userspace_executor.UserException{
            .vector = record.fault_vector,
            .error_code = record.fault_error_code,
            .instruction_pointer = record.fault_instruction_pointer,
            .fault_address = record.fault_address,
        };
        runtime.recordCrashReportForResolved(
            task,
            USER_EXCEPTION_CRASH_SERVICE_ID,
            now_ticks,
            exception.vector,
            USER_EXCEPTION_REDACTION_POLICY_VERSION,
            exception.reasonFingerprint(),
            true,
        );
        const terminated = runtime.terminateResolvedTask(task, now_ticks);
        if (!terminated) @call(.never_inline, schedulerInvariantFailure, .{.faulted_userspace_task_was_already_terminated});
        // The execution lease retains this slot until finishTaskDispatch has
        // collected deferred retirement and returned every lifetime callback.
    }

    fn enqueueReadyIndex(
        self: *Scheduler,
        slot_index: usize,
        class: accelerator_scheduler.ResourceClass,
    ) bool {
        if (slot_index >= self.slots.slots.len) return false;
        const slot = &self.slots.slots[slot_index];
        if (!slot.in_use) return false;
        if (slot.queued_ready) return true;

        const queue_index = resourceClassIndex(class);
        slot.resource_class = class;
        slot.prev_ready_index = self.ready_tails[queue_index];
        slot.next_ready_index = QUEUE_NO_INDEX;
        if (self.ready_tails[queue_index] == QUEUE_NO_INDEX) {
            self.ready_heads[queue_index] = compactQueueIndex(slot_index);
        } else {
            self.slots.slots[self.ready_tails[queue_index]].next_ready_index = compactQueueIndex(slot_index);
        }
        self.ready_tails[queue_index] = compactQueueIndex(slot_index);
        self.ready_counts[queue_index] += 1;
        self.ready_task_count += 1;
        slot.queued_ready = true;
        return true;
    }

    fn unlinkReadyIndex(self: *Scheduler, slot_index: usize) void {
        if (slot_index >= self.slots.slots.len) return;
        const target = &self.slots.slots[slot_index];
        if (!target.in_use or !target.queued_ready) return;

        const queue_index = resourceClassIndex(target.resource_class);
        const previous = target.prev_ready_index;
        const next = target.next_ready_index;

        if (previous == QUEUE_NO_INDEX) {
            self.ready_heads[queue_index] = next;
        } else {
            self.slots.slots[previous].next_ready_index = next;
        }
        if (next == QUEUE_NO_INDEX) {
            self.ready_tails[queue_index] = previous;
        } else {
            self.slots.slots[next].prev_ready_index = previous;
        }

        target.queued_ready = false;
        target.prev_ready_index = QUEUE_NO_INDEX;
        target.next_ready_index = QUEUE_NO_INDEX;
        self.ready_counts[queue_index] -= 1;
        self.ready_task_count -= 1;
    }

    fn selectReadyCandidate(self: *const Scheduler, now_ticks: u64) ?ReadyCandidate {
        var priority_candidate: ?ReadyCandidate = null;
        var deadline_candidate: ?ReadyCandidate = null;
        var deadline_class: ?accelerator_scheduler.ResourceClass = null;
        var earliest_deadline: u64 = std.math.maxInt(u64);
        var selected_dispatch_count: u64 = std.math.maxInt(u64);
        var selected_last_dispatch_tick: u64 = std.math.maxInt(u64);
        for (resource_priority_order) |class| {
            if (!self.resourceClassDispatchable(class)) continue;
            const candidate = self.firstDispatchableCandidate(class) orelse continue;
            if (priority_candidate == null) priority_candidate = candidate;
            const slot = &self.slots.slots[candidate.slot_index];
            const deadline = slot.deadline_tick;
            if (deadline != 0 and
                deadline <= now_ticks and
                expiredReadyCandidateBeats(
                    slot,
                    deadline,
                    deadline_class,
                    earliest_deadline,
                    selected_dispatch_count,
                    selected_last_dispatch_tick,
                ))
            {
                earliest_deadline = deadline;
                selected_dispatch_count = slot.dispatch_count;
                selected_last_dispatch_tick = slot.last_dispatch_tick;
                deadline_class = class;
                deadline_candidate = candidate;
            }
        }
        if (deadline_candidate) |candidate| return candidate;
        return priority_candidate;
    }

    fn firstDispatchableCandidate(self: *const Scheduler, class: accelerator_scheduler.ResourceClass) ?ReadyCandidate {
        const runtime = self.runtime_ptr orelse return null;
        var index = self.ready_heads[resourceClassIndex(class)];
        while (index != QUEUE_NO_INDEX) : (index = self.slots.slots[index].next_ready_index) {
            const slot = &self.slots.slots[index];
            if (self.taskHasExecutionLease(slot.task_id)) continue;
            const task = runtime.findByHandle(slot.task_handle, slot.task_id) orelse
                return .{ .slot_index = index };
            if (task.state != .active or !task.runsAsUserspaceProcess() or
                !task.hasLoadedExecutable() or !hasDispatchBudget(slot, task))
            {
                return .{ .slot_index = index, .task = task };
            }
            const request = self.dispatchRequestFor(slot, task);
            const decision = self.planTaskDispatch(request);
            if (decision.delayed) continue;
            if (slot.pending_accelerator_claim_id == 0 and
                slot.pending_accelerator_engine != .cpu and
                self.dispatchRequiresUnavailableAccelerator(slot, decision)) continue;
            return .{ .slot_index = index, .task = task, .request = request, .decision = decision };
        }
        return null;
    }

    pub fn hasReadyLatencySensitiveWork(self: *const Scheduler) bool {
        if (!smp.isRuntimeOwner()) return false;
        for (resource_priority_order) |class| {
            if (!latencySensitiveClass(class)) continue;
            if (!self.resourceClassDispatchable(class)) continue;
            if (self.firstDispatchableCandidate(class) != null) return true;
        }
        return false;
    }

    pub fn shouldPreemptTask(self: *const Scheduler, task_id: u64) bool {
        if (!smp.isRuntimeOwner()) return false;
        const slot = self.slots.getConst(task_id) orelse return false;
        if (latencySensitiveClass(slot.resource_class)) return false;
        return self.hasReadyLatencySensitiveWork();
    }

    fn resourceClassDispatchable(self: *const Scheduler, class: accelerator_scheduler.ResourceClass) bool {
        return switch (class) {
            .emergency_system_critical => true,
            .batch_compute => self.resource_state.thermal_pressure != .critical and !self.resource_state.battery_saver,
            .background_light => self.resource_state.thermal_pressure != .critical,
            .foreground_interactive, .media_export => true,
        };
    }

    fn accountBlockedReadyClasses(self: *Scheduler, now_ticks: u64) bool {
        var accounted = false;
        for (resource_priority_order) |class| {
            const queue_index = resourceClassIndex(class);
            const slot_index = self.ready_heads[queue_index];
            if (slot_index == QUEUE_NO_INDEX) continue;
            if (slot_index >= self.slots.slots.len) continue;

            const slot = &self.slots.slots[slot_index];
            if (!slot.in_use) continue;
            if (self.taskHasExecutionLease(slot.task_id)) continue;
            const decision = if (!self.resourceClassDispatchable(class))
                self.blockedResourceDecision(class)
            else decision: {
                const runtime = self.runtime_ptr orelse continue;
                const task = runtime.findByHandle(slot.task_handle, slot.task_id) orelse continue;
                break :decision self.planTaskDispatch(self.dispatchRequestFor(slot, task));
            };
            if (!decision.delayed) continue;
            if (self.noteDelayed(slot, decision, now_ticks)) accounted = true;
        }
        return accounted;
    }

    fn blockedResourceDecision(
        self: *const Scheduler,
        class: accelerator_scheduler.ResourceClass,
    ) accelerator_scheduler.Decision {
        const decision = accelerator_scheduler.planWithState(
            self.resource_state,
            self.engineAvailability(),
            .{ .class = class },
        );
        if (decision.delayed) return decision;
        return .{
            .class = class,
            .engine = .cpu,
            .delayed = true,
            .degraded = true,
            .zero_copy_allowed = false,
            .reason = self.blockedResourceReason(),
        };
    }

    fn blockedResourceReason(self: *const Scheduler) accelerator_scheduler.DecisionReason {
        if (self.resource_state.thermal_pressure == .critical) return .thermal_throttle;
        if (self.resource_state.battery_saver) return .battery_preserve;
        return .normal;
    }

    fn planTaskDispatch(
        self: *const Scheduler,
        request: accelerator_scheduler.Request,
    ) accelerator_scheduler.Decision {
        return accelerator_scheduler.planWithState(
            self.resource_state,
            self.engineAvailability(),
            request,
        );
    }

    fn dispatchRequestFor(
        self: *const Scheduler,
        slot: *const Slot,
        task: *const task_runtime.TaskRecord,
    ) accelerator_scheduler.Request {
        _ = self;
        var request = if (slot.dispatch_request_configured)
            slot.dispatch_request
        else
            deriveDispatchRequest(task);
        request.class = slot.resource_class;
        if (request.expected_cpu_ticks == 0) request.expected_cpu_ticks = DISPATCH_CPU_TICK_COST;
        if (request.memory_bandwidth_units == 0) request.memory_bandwidth_units = memoryBandwidthUnitsFor(task);
        if (request.shared_memory_bytes == 0) request.shared_memory_bytes = task.budget.shared_memory_bytes;
        return request;
    }

    fn dispatchRequiresUnavailableAccelerator(
        self: *const Scheduler,
        slot: *const Slot,
        decision: accelerator_scheduler.Decision,
    ) bool {
        _ = self;
        return slot.require_accelerator and decision.engine == .cpu;
    }

    fn observedUiRevision(self: *const Scheduler, slot: *const Slot) u64 {
        const index = self.accountingIndex(slot);
        if (self.cold_note.active and self.cold_note.slot_index == index and self.cold_note.owns_ui) {
            return self.cold_note.ui_revision;
        }
        const storage = self.dispatch_accounting orelse return 0;
        return storage[index].last_ui_state_revision;
    }

    fn noteCompleted(
        self: *Scheduler,
        slot: *Slot,
        decision: accelerator_scheduler.Decision,
        wait_for_event: bool,
        missed_deadline: bool,
        ui_revision: u64,
        bandwidth: usize,
    ) void {
        self.publishColdNote();
        self.cold_note = .{
            .active = true,
            .kind = .completed,
            .slot_index = @intCast(self.accountingIndex(slot)),
            .engine = decision.engine,
            .denial_engine = decision.engine,
            .reason = decision.reason,
            .degraded = decision.degraded,
            .zero_copy = decision.zero_copy_allowed,
            .wait_for_event = wait_for_event,
            .missed_deadline = missed_deadline,
            .owns_ui = slot.owns_ui_surface,
            .bandwidth = bandwidth,
            .ui_revision = ui_revision,
        };
    }

    fn noteDenied(
        self: *Scheduler,
        slot: *Slot,
        reason: accelerator_scheduler.DecisionReason,
        engine: accelerator_scheduler.Engine,
        denial_engine: accelerator_scheduler.Engine,
        record_decision: bool,
    ) void {
        self.publishColdNote();
        self.cold_note = .{
            .active = true,
            .kind = .denied,
            .slot_index = @intCast(self.accountingIndex(slot)),
            .engine = engine,
            .denial_engine = denial_engine,
            .reason = reason,
            .record_decision = record_decision,
        };
    }

    fn noteAcceleratorDenied(
        self: *Scheduler,
        slot: *Slot,
        decision: accelerator_scheduler.Decision,
        denial_engine: accelerator_scheduler.Engine,
    ) void {
        self.publishColdNote();
        self.cold_note = .{
            .active = true,
            .kind = .denied,
            .slot_index = @intCast(self.accountingIndex(slot)),
            .engine = decision.engine,
            .denial_engine = denial_engine,
            .reason = decision.reason,
            .degraded = decision.degraded,
            .zero_copy = decision.zero_copy_allowed,
            .record_decision = true,
        };
    }

    fn noteDelayed(
        self: *Scheduler,
        slot: *Slot,
        decision: accelerator_scheduler.Decision,
        now_ticks: u64,
    ) bool {
        const slot_index: u16 = @intCast(self.accountingIndex(slot));
        if (self.cold_note.active and
            self.cold_note.kind == .delayed and
            self.cold_note.slot_index == slot_index and
            self.cold_note.now_ticks == now_ticks)
        {
            self.cold_note.engine = decision.engine;
            self.cold_note.reason = decision.reason;
            self.cold_note.degraded = decision.degraded;
            self.cold_note.zero_copy = decision.zero_copy_allowed;
            return false;
        }
        self.publishColdNote();
        if (self.accountingStorage()[slot_index].last_policy_delay_tick == now_ticks) {
            const accounting = &self.accountingStorage()[slot_index];
            accounting.last_dispatch_engine = decision.engine;
            accounting.last_dispatch_reason = decision.reason;
            accounting.last_dispatch_degraded = decision.degraded;
            accounting.last_dispatch_zero_copy = decision.zero_copy_allowed;
            return false;
        }
        self.cold_note = .{
            .active = true,
            .kind = .delayed,
            .slot_index = slot_index,
            .engine = decision.engine,
            .denial_engine = decision.engine,
            .reason = decision.reason,
            .degraded = decision.degraded,
            .zero_copy = decision.zero_copy_allowed,
            .now_ticks = now_ticks,
        };
        return true;
    }

    fn publishColdNote(self: *Scheduler) void {
        requireRuntimeOwner();
        if (!self.cold_note.active) return;
        const note = self.cold_note;
        self.cold_note.active = false;
        if (note.slot_index >= self.slots.slots.len) return;
        const slot = &self.slots.slots[note.slot_index];
        const decision = accelerator_scheduler.Decision{
            .class = slot.resource_class,
            .engine = note.engine,
            .delayed = note.kind == .delayed,
            .degraded = note.degraded,
            .zero_copy_allowed = note.zero_copy,
            .reason = note.reason,
        };
        switch (note.kind) {
            .none => {},
            .delayed => self.accountDispatchDelayedAt(slot, decision, note.now_ticks),
            .denied => {
                if (note.record_decision) {
                    const accounting = &self.accountingStorage()[note.slot_index];
                    accounting.last_dispatch_engine = note.engine;
                    accounting.last_dispatch_degraded = note.degraded;
                    accounting.last_dispatch_zero_copy = note.zero_copy;
                }
                self.accountDispatchDenied(slot, note.reason, note.denial_engine);
            },
            .completed => {
                const accounting = &self.accountingStorage()[note.slot_index];
                accounting.last_dispatch_engine = note.engine;
                accounting.last_dispatch_reason = note.reason;
                accounting.last_dispatch_degraded = note.degraded;
                accounting.last_dispatch_zero_copy = note.zero_copy;
                if (note.wait_for_event) accounting.event_wait_count += 1;
                if (note.owns_ui and note.ui_revision > accounting.last_ui_state_revision) {
                    accounting.last_ui_state_revision = note.ui_revision;
                    accounting.ui_state_update_count += 1;
                }
                if (note.missed_deadline) accounting.missed_deadline_count += 1;
                accounting.cpu_ticks_consumed += DISPATCH_CPU_TICK_COST;
                accounting.memory_bandwidth_consumed_units = std.math.add(
                    usize,
                    accounting.memory_bandwidth_consumed_units,
                    note.bandwidth,
                ) catch std.math.maxInt(usize);
                self.engine_dispatch_counts[engineIndex(note.engine)] += 1;
            },
        }
    }

    fn accountDispatchDelayed(self: *Scheduler, slot: *Slot, decision: accelerator_scheduler.Decision) void {
        const accounting = self.accountingForSlot(slot);
        accounting.delayed_dispatch_count += 1;
        accounting.last_dispatch_engine = decision.engine;
        accounting.last_dispatch_reason = decision.reason;
        accounting.last_dispatch_degraded = decision.degraded;
        accounting.last_dispatch_zero_copy = decision.zero_copy_allowed;
    }

    fn accountDispatchDelayedAt(
        self: *Scheduler,
        slot: *Slot,
        decision: accelerator_scheduler.Decision,
        now_ticks: u64,
    ) void {
        const accounting = self.accountingForSlot(slot);
        if (accounting.last_policy_delay_tick == now_ticks) return;
        self.accountDispatchDelayed(slot, decision);
        self.accountingForSlot(slot).last_policy_delay_tick = now_ticks;
    }

    fn accountDispatchDenied(
        self: *Scheduler,
        slot: *Slot,
        reason: accelerator_scheduler.DecisionReason,
        engine: accelerator_scheduler.Engine,
    ) void {
        const accounting = self.accountingForSlot(slot);
        accounting.denied_dispatch_count += 1;
        accounting.last_dispatch_reason = reason;
        self.engine_denial_counts[engineIndex(engine)] += 1;
    }

    fn queuePendingAcceleratorWake(
        self: *Scheduler,
        slot_index: usize,
        slot: *Slot,
        request: accelerator_scheduler.Request,
        now_ticks: u64,
    ) void {
        if (slot.pending_accelerator_claim_id != 0) return;
        const engine = requestedAcceleratorEngine(request);
        if (engine == .cpu) return;
        const has_alternative_engine = request.class == .media_export and request.wants_media_engine and request.wants_gpu;
        if (!has_alternative_engine and !self.physicalEngineAvailable(engine)) {
            if (self.enqueueAcceleratorClaimForSlot(.{
                .task_id = slot.task_id,
                .engine = engine,
                .resource_class = slot.resource_class,
                .requested_at_tick = now_ticks,
                .deadline_tick = slot.deadline_tick,
                .shared_memory_bytes = request.shared_memory_bytes,
            }, slot) != null) {
                self.unlinkReadyIndex(slot_index);
                return;
            }
        }
        // An unreserved or multi-engine wait needs a wake path for any usable
        // engine. An already-online engine instead needs a policy change, so
        // a grant/requeue loop would spin. Recheck eligibility without retries.
        slot.pending_accelerator_engine = engine;
        _ = self.enqueueReadyIndex(slot_index, slot.resource_class);
    }

    fn wakeAvailableAcceleratorClaims(self: *Scheduler, now_ticks: u64) void {
        for (engine_priority_order) |engine| {
            if (!self.physicalEngineAvailable(engine)) continue;
            while (self.accelerator_claim_counts[engineIndex(engine)] != 0) {
                _ = self.grantNextAcceleratorClaim(engine, now_ticks) orelse break;
            }
        }
    }

    fn engineAvailability(self: *const Scheduler) accelerator_scheduler.EngineAvailability {
        return .{
            .gpu = self.engineCurrentlyAvailable(.gpu),
            .npu = self.engineCurrentlyAvailable(.npu),
            .media = self.engineCurrentlyAvailable(.media),
        };
    }

    fn engineCurrentlyAvailable(self: *const Scheduler, engine: accelerator_scheduler.Engine) bool {
        return switch (engine) {
            .cpu => true,
            .gpu => self.physicalEngineAvailable(.gpu) and self.accelerator_claim_counts[engineIndex(.gpu)] == 0,
            .npu => self.physicalEngineAvailable(.npu) and self.accelerator_claim_counts[engineIndex(.npu)] == 0,
            .media => self.physicalEngineAvailable(.media) and self.accelerator_claim_counts[engineIndex(.media)] == 0,
        };
    }

    fn physicalEngineAvailable(self: *const Scheduler, engine: accelerator_scheduler.Engine) bool {
        const telemetry_ready = self.hardwareQueueTelemetryReady();
        return switch (engine) {
            .cpu => true,
            .gpu => telemetry_ready and self.resource_state.gpu_available,
            .npu => telemetry_ready and self.resource_state.npu_available,
            .media => telemetry_ready and self.resource_state.media_available,
        };
    }

    fn hardwareQueueTelemetryReady(self: *const Scheduler) bool {
        if (!self.observedResourceTelemetry()) return false;
        return self.resource_telemetry_source == .hardware and self.resource_hardware_evidence_complete;
    }

    fn unregisterSlotIndex(self: *Scheduler, slot_index: usize) bool {
        if (slot_index >= self.slots.slots.len) return false;
        const slot = &self.slots.slots[slot_index];
        if (!slot.in_use) return false;
        const task_id = slot.task_id;
        if (self.taskHasExecutionLease(task_id)) return false;
        self.unlinkReadyIndex(slot_index);
        self.removeAcceleratorClaimsForTask(task_id, slot);
        if (self.cold_note.active and self.cold_note.slot_index == slot_index) {
            self.cold_note.active = false;
        } else {
            self.publishColdNote();
        }
        if (self.dispatch_accounting) |storage| storage[slot_index] = .{};
        return self.slots.removeIndex(slot_index);
    }

    fn pruneRetiredSlots(self: *Scheduler, runtime: *task_runtime.Runtime) void {
        // Parked tasks are absent from ready queues; registration pressure must
        // also reclaim their terminal slots and any queued accelerator claims.
        for (&self.slots.slots, 0..) |*slot, index| {
            if (!slot.in_use or runtime.execution.hasLeaseForTask(slot.task_id) or slot.task_id == self.active_dispatch_task_id) continue;
            const task = runtime.findByHandle(slot.task_handle, slot.task_id);
            if (task == null or task.?.state == .terminated) _ = self.unregisterSlotIndex(index);
        }
    }

    fn insertAcceleratorClaimIndex(
        self: *Scheduler,
        backing: *AcceleratorClaimBacking,
        engine: accelerator_scheduler.Engine,
        claim_index: usize,
    ) void {
        const queue_index = engineIndex(engine);
        const claim = &backing.claims.slots[claim_index];
        claim.prev_claim_index = QUEUE_NO_INDEX;
        claim.next_claim_index = QUEUE_NO_INDEX;
        claim.prev_deadline_index = QUEUE_NO_INDEX;
        claim.next_deadline_index = QUEUE_NO_INDEX;

        var current = self.accelerator_claim_heads[queue_index];
        while (current != QUEUE_NO_INDEX) : (current = backing.claims.slots[current].next_claim_index) {
            if (self.acceleratorClaimPriorityBeats(&claim.record, &backing.claims.slots[current].record)) {
                self.linkAcceleratorClaimBefore(backing, queue_index, claim_index, @intCast(current));
                self.insertAcceleratorDeadlineIndex(backing, queue_index, claim_index);
                self.accelerator_claim_counts[queue_index] += 1;
                return;
            }
        }

        if (self.accelerator_claim_tails[queue_index] == QUEUE_NO_INDEX) {
            self.accelerator_claim_heads[queue_index] = compactQueueIndex(claim_index);
        } else {
            claim.prev_claim_index = self.accelerator_claim_tails[queue_index];
            backing.claims.slots[self.accelerator_claim_tails[queue_index]].next_claim_index = compactQueueIndex(claim_index);
        }
        self.accelerator_claim_tails[queue_index] = compactQueueIndex(claim_index);
        self.insertAcceleratorDeadlineIndex(backing, queue_index, claim_index);
        self.accelerator_claim_counts[queue_index] += 1;
    }

    fn linkAcceleratorClaimBefore(
        self: *Scheduler,
        backing: *AcceleratorClaimBacking,
        queue_index: usize,
        claim_index: usize,
        before_index: usize,
    ) void {
        const previous = backing.claims.slots[before_index].prev_claim_index;
        backing.claims.slots[claim_index].prev_claim_index = previous;
        backing.claims.slots[claim_index].next_claim_index = compactQueueIndex(before_index);
        backing.claims.slots[before_index].prev_claim_index = compactQueueIndex(claim_index);
        if (previous == QUEUE_NO_INDEX) {
            self.accelerator_claim_heads[queue_index] = compactQueueIndex(claim_index);
        } else {
            backing.claims.slots[previous].next_claim_index = compactQueueIndex(claim_index);
        }
    }

    fn insertAcceleratorDeadlineIndex(
        self: *Scheduler,
        backing: *AcceleratorClaimBacking,
        queue_index: usize,
        claim_index: usize,
    ) void {
        const claim = &backing.claims.slots[claim_index];
        if (claim.record.deadline_tick == 0) return;

        var current = self.accelerator_deadline_heads[queue_index];
        while (current != QUEUE_NO_INDEX) : (current = backing.claims.slots[current].next_deadline_index) {
            if (self.acceleratorClaimDeadlineBeats(&claim.record, &backing.claims.slots[current].record)) {
                self.linkAcceleratorDeadlineBefore(backing, queue_index, claim_index, @intCast(current));
                return;
            }
        }

        if (self.accelerator_deadline_tails[queue_index] == QUEUE_NO_INDEX) {
            self.accelerator_deadline_heads[queue_index] = compactQueueIndex(claim_index);
        } else {
            claim.prev_deadline_index = self.accelerator_deadline_tails[queue_index];
            backing.claims.slots[self.accelerator_deadline_tails[queue_index]].next_deadline_index = compactQueueIndex(claim_index);
        }
        self.accelerator_deadline_tails[queue_index] = compactQueueIndex(claim_index);
    }

    fn linkAcceleratorDeadlineBefore(
        self: *Scheduler,
        backing: *AcceleratorClaimBacking,
        queue_index: usize,
        claim_index: usize,
        before_index: usize,
    ) void {
        const previous = backing.claims.slots[before_index].prev_deadline_index;
        backing.claims.slots[claim_index].prev_deadline_index = previous;
        backing.claims.slots[claim_index].next_deadline_index = compactQueueIndex(before_index);
        backing.claims.slots[before_index].prev_deadline_index = compactQueueIndex(claim_index);
        if (previous == QUEUE_NO_INDEX) {
            self.accelerator_deadline_heads[queue_index] = compactQueueIndex(claim_index);
        } else {
            backing.claims.slots[previous].next_deadline_index = compactQueueIndex(claim_index);
        }
    }

    fn popBestAcceleratorClaimIndex(
        self: *Scheduler,
        backing: *AcceleratorClaimBacking,
        engine: accelerator_scheduler.Engine,
        now_ticks: u64,
    ) ?usize {
        const queue_index = engineIndex(engine);
        const deadline_head = self.accelerator_deadline_heads[queue_index];
        const best = if (deadline_head != QUEUE_NO_INDEX and
            claimDeadlineExpired(backing.claims.slots[deadline_head].record, now_ticks))
            deadline_head
        else
            self.accelerator_claim_heads[queue_index];
        if (best == QUEUE_NO_INDEX or best >= backing.claims.slots.len) return null;

        self.unlinkAcceleratorClaimIndex(backing, engine, @intCast(best));
        self.accelerator_claim_counts[queue_index] -= 1;
        return @intCast(best);
    }

    fn unlinkAcceleratorClaimIndex(
        self: *Scheduler,
        backing: *AcceleratorClaimBacking,
        engine: accelerator_scheduler.Engine,
        claim_index: usize,
    ) void {
        const queue_index = engineIndex(engine);
        const previous = backing.claims.slots[claim_index].prev_claim_index;
        const next = backing.claims.slots[claim_index].next_claim_index;
        if (previous == QUEUE_NO_INDEX) {
            self.accelerator_claim_heads[queue_index] = next;
        } else {
            backing.claims.slots[previous].next_claim_index = next;
        }
        if (next == QUEUE_NO_INDEX) {
            self.accelerator_claim_tails[queue_index] = previous;
        } else {
            backing.claims.slots[next].prev_claim_index = previous;
        }

        const previous_deadline = backing.claims.slots[claim_index].prev_deadline_index;
        const next_deadline = backing.claims.slots[claim_index].next_deadline_index;
        if (backing.claims.slots[claim_index].record.deadline_tick != 0) {
            if (previous_deadline == QUEUE_NO_INDEX) {
                self.accelerator_deadline_heads[queue_index] = next_deadline;
            } else {
                backing.claims.slots[previous_deadline].next_deadline_index = next_deadline;
            }
            if (next_deadline == QUEUE_NO_INDEX) {
                self.accelerator_deadline_tails[queue_index] = previous_deadline;
            } else {
                backing.claims.slots[next_deadline].prev_deadline_index = previous_deadline;
            }
        }

        _ = backing.task_index.remove(
            acceleratorClaimTaskKey(backing.claims.slots[claim_index].record.task_id),
            claim_index,
        );
        backing.claims.slots[claim_index].prev_claim_index = QUEUE_NO_INDEX;
        backing.claims.slots[claim_index].next_claim_index = QUEUE_NO_INDEX;
        backing.claims.slots[claim_index].prev_deadline_index = QUEUE_NO_INDEX;
        backing.claims.slots[claim_index].next_deadline_index = QUEUE_NO_INDEX;
    }

    fn acceleratorClaimPriorityBeats(
        self: *const Scheduler,
        candidate: *const AcceleratorClaimRecord,
        selected: *const AcceleratorClaimRecord,
    ) bool {
        const candidate_priority = resourceClassPriorityRank(candidate.resource_class);
        const selected_priority = resourceClassPriorityRank(selected.resource_class);
        if (candidate_priority < selected_priority) return true;
        if (candidate_priority > selected_priority) return false;

        if (candidate.deadline_tick != 0 and selected.deadline_tick != 0) {
            if (candidate.deadline_tick < selected.deadline_tick) return true;
            if (candidate.deadline_tick > selected.deadline_tick) return false;
        } else if (candidate.deadline_tick != selected.deadline_tick) {
            return candidate.deadline_tick != 0;
        }

        const candidate_rank = self.taskSchedulingRank(candidate.task_id);
        const selected_rank = self.taskSchedulingRank(selected.task_id);
        if (candidate_rank.dispatch_count < selected_rank.dispatch_count) return true;
        if (candidate_rank.dispatch_count > selected_rank.dispatch_count) return false;

        if (candidate_rank.last_dispatch_tick < selected_rank.last_dispatch_tick) return true;
        if (candidate_rank.last_dispatch_tick > selected_rank.last_dispatch_tick) return false;

        return candidate.requested_at_tick < selected.requested_at_tick;
    }

    fn acceleratorClaimDeadlineBeats(
        self: *const Scheduler,
        candidate: *const AcceleratorClaimRecord,
        selected: *const AcceleratorClaimRecord,
    ) bool {
        if (candidate.deadline_tick < selected.deadline_tick) return true;
        if (candidate.deadline_tick > selected.deadline_tick) return false;
        return self.acceleratorClaimPriorityBeats(candidate, selected);
    }

    fn taskSchedulingRank(self: *const Scheduler, task_id: u64) TaskSchedulingRank {
        const slot = self.slots.getConst(task_id) orelse return .{
            .dispatch_count = std.math.maxInt(u64),
            .last_dispatch_tick = std.math.maxInt(u64),
        };
        return .{
            .dispatch_count = slot.dispatch_count,
            .last_dispatch_tick = slot.last_dispatch_tick,
        };
    }

    fn removeAcceleratorClaimsForTask(self: *Scheduler, task_id: u64, task_slot: *Slot) void {
        if (builtin.mode == .debug) {
            std.debug.assert(task_slot.in_use and task_slot.task_id == task_id);
        }
        const backing = self.acceleratorClaimBacking() orelse return;
        const task_key = acceleratorClaimTaskKey(task_id);
        var current = backing.task_index.head(task_key);
        while (current != arena_no_index) {
            if (current >= backing.claims.slots.len) {
                @call(.never_inline, schedulerInvariantFailure, .{.accelerator_claim_task_index_points_outside_claim_slots});
            }
            const next = backing.task_index.next(current);
            const claim_slot = &backing.claims.slots[current];
            if (!claim_slot.in_use) @call(.never_inline, schedulerInvariantFailure, .{.accelerator_claim_task_index_points_at_a_free_slot});
            if (claim_slot.record.task_id != task_id) {
                @call(.never_inline, schedulerInvariantFailure, .{.accelerator_claim_task_index_points_at_the_wrong_task});
            }
            const record = claim_slot.record;
            self.unlinkAcceleratorClaimIndex(backing, record.engine, current);
            self.accelerator_claim_counts[engineIndex(record.engine)] -= 1;
            if (task_slot.pending_accelerator_claim_id == record.id) {
                task_slot.pending_accelerator_claim_id = 0;
                task_slot.pending_accelerator_engine = .cpu;
            }
            _ = backing.claims.removeIndex(current);
            current = next;
        }
    }

    fn findAcceleratorClaimForTaskEngine(
        backing: *const AcceleratorClaimBacking,
        task_id: u64,
        engine: accelerator_scheduler.Engine,
    ) ?u64 {
        const task_key = acceleratorClaimTaskKey(task_id);
        var current = backing.task_index.head(task_key);
        while (current != arena_no_index) : (current = backing.task_index.next(current)) {
            if (current >= backing.claims.slots.len) {
                @call(.never_inline, schedulerInvariantFailure, .{.accelerator_claim_task_index_points_outside_claim_slots});
            }
            const slot = &backing.claims.slots[current];
            if (!slot.in_use) @call(.never_inline, schedulerInvariantFailure, .{.accelerator_claim_task_index_points_at_a_free_slot});
            const record = slot.record;
            if (record.task_id != task_id) @call(.never_inline, schedulerInvariantFailure, .{.accelerator_claim_task_index_points_at_the_wrong_task});
            if (record.task_id == task_id and record.engine == engine) return record.id;
        }
        return null;
    }

    fn nextAcceleratorClaimId(self: *Scheduler, backing: *AcceleratorClaimBacking) ?u64 {
        if (self.next_accelerator_claim_id == 0) return null;
        if (backing.claims.countInUse() >= MAX_ACCELERATOR_CLAIMS) return null;
        if (backing.claims.get(self.next_accelerator_claim_id) != null) return null;
        return self.next_accelerator_claim_id;
    }
};

fn requireRuntimeOwner() void {
    if (!smp.isRuntimeOwner()) {
        @call(.never_inline, schedulerInvariantFailure, .{.userspace_scheduler_mutation_belongs_to_the_runtime_owner_cpu});
    }
}

fn schedulerSlotTaskId(slot: *const Slot) u64 {
    return slot.task_id;
}

fn compactQueueIndex(index: usize) QueueSlotIndex {
    return @intCast(index);
}

fn acceleratorClaimSlotId(slot: *const AcceleratorClaimSlot) u64 {
    return slot.record.id;
}

test "scheduler caches immutable UI presentation eligibility" {
    try std.testing.expect(contractOwnsUiSurface(userspace_flags.FLAG_OWNS_UI_SURFACE));
    try std.testing.expect(contractOwnsUiSurface(userspace_flags.FLAG_OWNS_UI_SURFACE | userspace_flags.FLAG_BACKGROUND_ELIGIBLE));
    try std.testing.expect(!contractOwnsUiSurface(0));
    try std.testing.expect(!contractOwnsUiSurface(userspace_flags.FLAG_BACKGROUND_ELIGIBLE));
    try std.testing.expectEqual(@as(u8, 0), STEADY_UI_ELIGIBILITY_CATALOG_LOOKUPS);
}

fn acceleratorClaimTaskKey(task_id: u64) u64 {
    return task_id;
}

fn hasDispatchBudget(slot: *const Slot, task: *const task_runtime.TaskRecord) bool {
    _ = task;
    return slot.cpu_budget_remaining_ticks >= DISPATCH_CPU_TICK_COST;
}

fn taskEligibleForPostDispatchRequeue(
    expected_task_id: u64,
    task: *const task_runtime.TaskRecord,
    slot: *const Slot,
) bool {
    return task.id == expected_task_id and
        task.state == .active and
        task.runsAsUserspaceProcess() and
        task.hasLoadedExecutable() and
        hasDispatchBudget(slot, task);
}

fn deriveDispatchRequest(task: *const task_runtime.TaskRecord) accelerator_scheduler.Request {
    const class = task.resourceClass();
    var request = accelerator_scheduler.Request{
        .class = class,
        .shared_memory_bytes = task.budget.shared_memory_bytes,
        .expected_cpu_ticks = DISPATCH_CPU_TICK_COST,
        .memory_bandwidth_units = memoryBandwidthUnitsFor(task),
    };
    switch (class) {
        .emergency_system_critical => {},
        .foreground_interactive => request.wants_gpu = task.ui_surface_id != null,
        .background_light => {
            request.estimated_energy_milliwatt_hours = estimatedDispatchEnergyMilliwattHours(task);
        },
        .media_export => {
            request.wants_gpu = true;
            request.wants_media_engine = true;
        },
        .batch_compute => {
            request.wants_npu = true;
            request.estimated_energy_milliwatt_hours = estimatedDispatchEnergyMilliwattHours(task);
        },
    }
    return request;
}

fn estimatedDispatchEnergyMilliwattHours(task: *const task_runtime.TaskRecord) u32 {
    const budget_units = @min(memoryBandwidthUnitsFor(task), std.math.maxInt(u32) - 1);
    return @as(u32, 1) + @as(u32, @intCast(budget_units));
}

fn memoryBandwidthUnitsFor(task: *const task_runtime.TaskRecord) usize {
    const bytes = task.budget.memory_bytes +| task.budget.shared_memory_bytes;
    if (bytes == std.math.maxInt(usize)) return bytes;
    return @max(@as(usize, 1), (bytes +| (MEMORY_BANDWIDTH_UNIT_BYTES - 1)) / MEMORY_BANDWIDTH_UNIT_BYTES);
}

fn requestedAcceleratorEngine(request: accelerator_scheduler.Request) accelerator_scheduler.Engine {
    return switch (request.class) {
        .emergency_system_critical => .cpu,
        .foreground_interactive => if (request.wants_gpu) .gpu else .cpu,
        .media_export => if (request.wants_media_engine) .media else if (request.wants_gpu) .gpu else .cpu,
        .background_light, .batch_compute => if (request.wants_npu) .npu else if (request.wants_gpu) .gpu else .cpu,
    };
}

const resource_priority_order = [_]accelerator_scheduler.ResourceClass{
    .emergency_system_critical,
    .foreground_interactive,
    .media_export,
    .background_light,
    .batch_compute,
};

const engine_priority_order = [_]accelerator_scheduler.Engine{
    .gpu,
    .npu,
    .media,
};

fn resourceClassIndex(class: accelerator_scheduler.ResourceClass) usize {
    return switch (class) {
        .foreground_interactive => 0,
        .background_light => 1,
        .media_export => 2,
        .batch_compute => 3,
        .emergency_system_critical => 4,
    };
}

fn resourceClassPriorityRank(class: accelerator_scheduler.ResourceClass) usize {
    for (resource_priority_order, 0..) |priority_class, priority| {
        if (priority_class == class) return priority;
    }
    return resource_priority_order.len;
}

fn latencySensitiveClass(class: accelerator_scheduler.ResourceClass) bool {
    return switch (class) {
        .emergency_system_critical, .foreground_interactive, .media_export => true,
        .background_light, .batch_compute => false,
    };
}

fn preemptCheck(task_id: u64) bool {
    const scheduler = bound_preempt_scheduler orelse return false;
    return scheduler.shouldPreemptTask(task_id);
}

fn notifyExecutionStop(context: *anyopaque, ticket: dispatch_ownership.Ticket) void {
    const scheduler: *Scheduler = @ptrCast(@alignCast(context));
    const runtime = scheduler.runtime_ptr orelse
        @call(.never_inline, schedulerInvariantFailure, .{.userspace_executor_ownership_has_no_runtime});
    if (ticket.issuer != &runtime.execution or !smp.notifyExecutionStop(ticket.cpu))
        @call(.never_inline, schedulerInvariantFailure, .{.execution_stop_ipi_target_is_not_an_admitted_remote_cpu});
}

fn engineIndex(engine: accelerator_scheduler.Engine) usize {
    return switch (engine) {
        .cpu => 0,
        .gpu => 1,
        .npu => 2,
        .media => 3,
    };
}

fn registrationTimerTicks() u64 {
    if (builtin.target.os.tag != .freestanding) return 0;
    const clock = @import("../../kernel/timer/timer.zig");
    clock.synchronize();
    return clock.getTicks();
}

fn deadlineFromNow(class: accelerator_scheduler.ResourceClass, now_ticks: u64) u64 {
    const delta: u64 = switch (class) {
        .emergency_system_critical => EMERGENCY_DEADLINE_DELTA_TICKS,
        .foreground_interactive => FOREGROUND_DEADLINE_DELTA_TICKS,
        .media_export => MEDIA_EXPORT_DEADLINE_DELTA_TICKS,
        .background_light => BACKGROUND_DEADLINE_DELTA_TICKS,
        .batch_compute => BATCH_DEADLINE_DELTA_TICKS,
    };
    return std.math.add(u64, now_ticks, delta) catch std.math.maxInt(u64);
}

fn deadlineAfterDispatch(class: accelerator_scheduler.ResourceClass, now_ticks: u64) u64 {
    const next_quantum_tick = std.math.add(u64, now_ticks, userspace_executor.DISPATCH_QUANTUM_TICKS) catch std.math.maxInt(u64);
    return deadlineFromNow(class, next_quantum_tick);
}

fn executionRemainsReady(outcome: userspace_executor.ExecutionOutcome) bool {
    return switch (outcome) {
        .unavailable, .yielded => true,
        .wait_for_event, .faulted => false,
    };
}

fn taskUiPresentationEligible(
    catalog: *userspace_loader.Catalog,
    task: *const task_runtime.TaskRecord,
) bool {
    if (task.ui_surface_id != null and isApplicationBundle(task.launchBundleIdSlice())) return true;
    const image = catalog.findById(task.launch.image_id) orelse return false;
    return contractOwnsUiSurface(image.contract_flags);
}

fn isApplicationBundle(bundle_id: []const u8) bool {
    if (bundle_id.len == 0) return false;
    if (std.mem.startsWith(u8, bundle_id, "zigos.") or std.mem.startsWith(u8, bundle_id, "svc.")) return false;
    if (std.mem.startsWith(u8, bundle_id, "compat.") or std.mem.indexOf(u8, bundle_id, ".compat.") != null) return false;
    return true;
}

fn contractOwnsUiSurface(contract_flags: u32) bool {
    return (contract_flags & userspace_flags.FLAG_OWNS_UI_SURFACE) != 0;
}

fn expiredReadyCandidateBeats(
    slot: *const Slot,
    deadline: u64,
    selected_class: ?accelerator_scheduler.ResourceClass,
    selected_deadline: u64,
    selected_dispatch_count: u64,
    selected_last_dispatch_tick: u64,
) bool {
    if (selected_class) |class| {
        const candidate_latency = latencySensitiveClass(slot.resource_class);
        const selected_latency = latencySensitiveClass(class);
        if (candidate_latency != selected_latency) return candidate_latency;
    }
    if (deadline < selected_deadline) return true;
    if (deadline > selected_deadline) return false;
    if (slot.dispatch_count < selected_dispatch_count) return true;
    if (slot.dispatch_count > selected_dispatch_count) return false;
    return slot.last_dispatch_tick < selected_last_dispatch_tick;
}

fn claimDeadlineExpired(record: AcceleratorClaimRecord, now_ticks: u64) bool {
    return record.deadline_tick != 0 and record.deadline_tick <= now_ticks;
}

fn zeroAcceleratorClaim() AcceleratorClaimRecord {
    return .{
        .id = 0,
        .task_id = 0,
        .engine = .cpu,
        .resource_class = .background_light,
        .requested_at_tick = 0,
        .deadline_tick = 0,
        .shared_memory_bytes = 0,
    };
}

fn completeTestHardwareEvidence() accelerator_scheduler.HardwareTelemetryEvidence {
    return .{
        .target_id = "test-hardware-telemetry",
        .reader_generation = 1,
        .observations = .{
            .acpi_observed = true,
            .thermal_observed = true,
            .battery_observed = true,
            .accelerator_observed = true,
            .grid_carbon_observed = true,
        },
    };
}

fn schedulerTestUserspaceImage(service_task: bool) !task_runtime.ExecutableImageSpec {
    if (!builtin.is_test) @compileError("schedulerTestUserspaceImage is test-only");
    return if (service_task)
        try generated_image_fixtures.serviceImage()
    else
        try generated_image_fixtures.appImage();
}

fn createRunnableSchedulerTask(
    runtime: *task_runtime.Runtime,
    serial: u64,
    class: accelerator_scheduler.ResourceClass,
    label: []const u8,
    bundle_id: []const u8,
    ui_surface_id: ?u64,
) !*task_runtime.TaskRecord {
    return createRunnableSchedulerTaskWithBudget(
        runtime,
        serial,
        class,
        label,
        bundle_id,
        ui_surface_id,
        DISPATCH_CPU_TICK_COST,
    );
}

fn createRunnableSchedulerTaskWithBudget(
    runtime: *task_runtime.Runtime,
    serial: u64,
    class: accelerator_scheduler.ResourceClass,
    label: []const u8,
    bundle_id: []const u8,
    ui_surface_id: ?u64,
    cpu_time_ticks: u64,
) !*task_runtime.TaskRecord {
    _ = label;
    const service_task = class == .emergency_system_critical;
    var image = try schedulerTestUserspaceImage(service_task);
    return runtime.createTask(.{
        .owner = .{
            .kind = if (service_task) .service else .app,
            .serial = serial,
        },
        .component_class = if (service_task) .service_component else .app_component,
        .budget = .{
            .cpu_time_ticks = cpu_time_ticks,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = class,
            .background_allowed = class == .background_light or class == .batch_compute,
        },
        .ui_surface_id = ui_surface_id,
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = serial,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = bundle_id,
        },
        .userspace_image = &image,
    });
}

test "allocated scheduler initialization preserves empty queue invariants" {
    var executor = userspace_executor.Executor{};
    var scheduler: Scheduler = undefined;
    scheduler.initializeAllocated(&executor);

    try std.testing.expectEqual(@as(usize, 0), scheduler.slots.countInUse());
    try std.testing.expect(!scheduler.hasReadyTasks());
    try std.testing.expectEqual(@as(u64, 1), scheduler.next_accelerator_claim_id);
    try std.testing.expectEqual(std.math.maxInt(u64), scheduler.resource_state.cpu_budget_ticks);
    try std.testing.expectEqual(std.math.maxInt(usize), scheduler.resource_state.memory_bandwidth_units);
    try std.testing.expect(scheduler.resource_state.gpu_available);
    const slot_index = scheduler.slots.reserveIndex(7).?;
    try std.testing.expectEqual(@as(usize, 0), slot_index);
    try std.testing.expect(scheduler.slots.removeIndex(slot_index));
}

test "all resource classes dispatch and reach idle with application processors online" {
    const previous_cpu_count = smp.setOnlineCpuCountForTest(4);
    defer _ = smp.setOnlineCpuCountForTest(previous_cpu_count);
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();

    var task_ids: [RESOURCE_CLASS_COUNT]u64 = undefined;
    for (resource_priority_order, 0..) |class, index| {
        const task = try createRunnableSchedulerTask(
            &runtime,
            index + 1,
            class,
            "owner-dispatch",
            "app.example.owner-dispatch",
            null,
        );
        task_ids[index] = task.id;
        try std.testing.expect(scheduler.registerTask(task.id));
        try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(class));
    }
    try std.testing.expectEqual(@as(u8, 4), smp.onlineCpuCount());
    for (0..RESOURCE_CLASS_COUNT) |index| {
        _ = scheduler.runNext(index + 1);
    }
    for (task_ids, resource_priority_order) |task_id, class| {
        const stats = scheduler.taskDispatchStats(task_id).?;
        try std.testing.expectEqual(@as(u64, 1), stats.dispatch_count);
        try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(class));
    }
    try std.testing.expect(!scheduler.hasReadyTasks());
    try std.testing.expect(!scheduler.runNext(RESOURCE_CLASS_COUNT + 1));
}

test "application processors cannot mutate or dispatch the shared runtime queues" {
    const previous_cpu_count = smp.setOnlineCpuCountForTest(4);
    defer _ = smp.setOnlineCpuCountForTest(previous_cpu_count);
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();
    const task = try createRunnableSchedulerTask(&runtime, 1, .background_light, "owner", "app.example.owner", null);
    const other = try createRunnableSchedulerTask(&runtime, 2, .batch_compute, "other", "app.example.other", null);
    try std.testing.expect(scheduler.registerTask(task.id));
    const before = scheduler.taskDispatchStats(task.id).?;
    const before_budget = scheduler.slots.getConst(task.id).?.cpu_budget_remaining_ticks;

    {
        const previous_cpu = smp.currentCpuIndex();
        smp.setCurrentCpuIndexForTest(1);
        defer smp.setCurrentCpuIndexForTest(previous_cpu);
        try std.testing.expect(!smp.isRuntimeOwner());
        try std.testing.expect(!scheduler.registerTask(other.id));
        try std.testing.expect(!scheduler.wakeTask(task.id, .external_event, 10, 20));
        try std.testing.expect(!scheduler.refillTaskBudget(task.id, 10_000, 10));
        try std.testing.expect(!scheduler.configureTaskDispatchRequest(task.id, .{ .class = .background_light }, true));
        try std.testing.expect(!scheduler.parkTaskUntilEvent(task.id));
        try std.testing.expect(!scheduler.unregisterTask(task.id));
        try std.testing.expect(scheduler.enqueueAcceleratorClaim(.{
            .task_id = task.id,
            .engine = .gpu,
            .resource_class = .background_light,
            .requested_at_tick = 10,
        }) == null);
        try std.testing.expect(!scheduler.hasDispatchableTasks(10));
        try std.testing.expect(!scheduler.runNext(10));
        try std.testing.expectEqual(userspace_executor.ExecutionOutcome.unavailable, scheduler.executeTask(task.id, 10));
    }

    try std.testing.expectEqualDeep(before, scheduler.taskDispatchStats(task.id).?);
    try std.testing.expectEqual(before_budget, scheduler.slots.getConst(task.id).?.cpu_budget_remaining_ticks);
    try std.testing.expect(scheduler.slots.getConst(other.id) == null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.background_light));
    _ = scheduler.runNext(11);
    try std.testing.expect(!scheduler.hasReadyTasks());
}

test "post-dispatch requeue validates retained task identity and state" {
    var runtime = task_runtime.Runtime.init();
    const task = try createRunnableSchedulerTask(
        &runtime,
        71,
        .foreground_interactive,
        "retained-task",
        "app.retained-task",
        null,
    );
    var slot = Slot{
        .in_use = true,
        .task_id = task.id,
        .cpu_budget_remaining_ticks = DISPATCH_CPU_TICK_COST,
    };

    try std.testing.expect(taskEligibleForPostDispatchRequeue(task.id, task, &slot));
    try std.testing.expect(!taskEligibleForPostDispatchRequeue(task.id + 1, task, &slot));

    try std.testing.expect(try runtime.suspendTask(task.id, 1));
    try std.testing.expect(!taskEligibleForPostDispatchRequeue(task.id, task, &slot));
    try std.testing.expect(try runtime.resumeTask(task.id, 2));
    try std.testing.expect(taskEligibleForPostDispatchRequeue(task.id, task, &slot));

    slot.cpu_budget_remaining_ticks = DISPATCH_CPU_TICK_COST - 1;
    try std.testing.expect(!taskEligibleForPostDispatchRequeue(task.id, task, &slot));
    slot.cpu_budget_remaining_ticks = DISPATCH_CPU_TICK_COST;

    try std.testing.expect(try runtime.terminateTask(task.id, 3));
    try std.testing.expect(!taskEligibleForPostDispatchRequeue(task.id, task, &slot));
    try std.testing.expectEqual(@as(u8, 0), SCHEDULED_TASK_INDEX_LOOKUPS_PER_DISPATCH);
}

test "userspace scheduler registers tasks through indexed arena slots" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const first_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });
    const second_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 2 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });

    try std.testing.expect(scheduler.registerTask(first_task.id));
    try std.testing.expect(scheduler.hasReadyTasks());
    try std.testing.expect(!scheduler.registerTask(first_task.id));
    try std.testing.expectEqual(@as(usize, 1), scheduler.slots.countInUse());

    const first_index = scheduler.slots.slotIndexOf(first_task.id).?;
    const first_handle = scheduler.slots.slots[first_index].task_handle;
    try std.testing.expectEqual(first_task.id, runtime.findByHandle(first_handle, first_task.id).?.id);
    try std.testing.expect(!scheduler.slots.slots[first_index].owns_ui_surface);
    scheduler.slots.slots[first_index].owns_ui_surface = true;
    try std.testing.expect(scheduler.unregisterTask(first_task.id));
    try std.testing.expect(!scheduler.hasReadyTasks());
    try std.testing.expectEqual(@as(usize, 0), scheduler.slots.countInUse());

    try std.testing.expect(scheduler.registerTask(second_task.id));
    try std.testing.expect(scheduler.hasReadyTasks());
    try std.testing.expectEqual(first_index, scheduler.slots.slotIndexOf(second_task.id).?);
    const second_handle = scheduler.slots.slots[first_index].task_handle;
    try std.testing.expect(!second_handle.eql(first_handle));
    try std.testing.expectEqual(second_task.id, runtime.findByHandle(second_handle, second_task.id).?.id);
    try std.testing.expect(!scheduler.slots.slots[first_index].owns_ui_surface);
}

test "userspace scheduler refreshes task handles after runtime restore" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try createRunnableSchedulerTask(
        &runtime,
        72,
        .foreground_interactive,
        "restored-task",
        "app.restored-task",
        null,
    );
    const task_id = task.id;
    try std.testing.expect(scheduler.registerTask(task_id));
    const slot = scheduler.slots.get(task_id).?;
    const original_handle = slot.task_handle;
    slot.mapping_handle = userspace_executor.MappingHandle.fromParts(3, 9);

    var snapshot = task_runtime.Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);
    try runtime.restoreFromSnapshot(&snapshot);
    const restored_handle = runtime.taskHandleForResolved(runtime.find(task_id).?);
    try std.testing.expect(!restored_handle.eql(original_handle));

    try std.testing.expect(scheduler.wakeTask(task_id, .external_event, 1, 0));
    try std.testing.expect(slot.task_handle.eql(restored_handle));
    try std.testing.expect(slot.mapping_handle.isZero());
}

test "userspace scheduler wake checks the task identity of a live cached handle" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try createRunnableSchedulerTask(&runtime, 72, .foreground_interactive, "wake-owner", "app.wake-owner", null);
    const other = try createRunnableSchedulerTask(&runtime, 73, .foreground_interactive, "other-wake-owner", "app.other-wake-owner", null);
    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.registerTask(other.id));
    const slot = scheduler.slots.get(task.id).?;
    const original_handle = slot.task_handle;
    slot.task_handle = runtime.taskHandleForResolved(other);
    slot.mapping_handle = userspace_executor.MappingHandle.fromParts(3, 9);
    const other_wakes = scheduler.taskDispatchStats(other.id).?.wake_event_count;

    try std.testing.expect(scheduler.wakeTask(task.id, .external_event, 10, 20));
    try std.testing.expect(slot.task_handle.eql(original_handle));
    try std.testing.expect(slot.mapping_handle.isZero());
    try std.testing.expectEqual(@as(u64, 2), scheduler.taskDispatchStats(task.id).?.wake_event_count);
    try std.testing.expectEqual(other_wakes, scheduler.taskDispatchStats(other.id).?.wake_event_count);
}

test "userspace scheduler rejects retired task handles after runtime reset" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try createRunnableSchedulerTask(
        &runtime,
        73,
        .foreground_interactive,
        "original-task",
        "app.original-task",
        null,
    );
    const task_id = task.id;
    try std.testing.expect(scheduler.registerTask(task_id));
    const original_handle = scheduler.slots.get(task_id).?.task_handle;

    runtime.reset();
    const replacement = try createRunnableSchedulerTask(
        &runtime,
        74,
        .foreground_interactive,
        "replacement-task",
        "app.replacement-task",
        null,
    );
    try std.testing.expect(replacement.id > task_id);
    try std.testing.expect(runtime.find(task_id) == null);
    try std.testing.expect(!runtime.taskHandleForResolved(replacement).eql(original_handle));

    try std.testing.expect(!scheduler.runNext(1));
    try std.testing.expect(scheduler.slots.get(task_id) == null);
}

test "userspace scheduler unlinks ready queue slots through prev links" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const first_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 11 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });
    const second_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 12 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });
    const third_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 13 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });

    try std.testing.expect(scheduler.registerTask(first_task.id));
    try std.testing.expect(scheduler.registerTask(second_task.id));
    try std.testing.expect(scheduler.registerTask(third_task.id));

    const first_index = scheduler.slots.slotIndexOf(first_task.id).?;
    const second_index = scheduler.slots.slotIndexOf(second_task.id).?;
    const third_index = scheduler.slots.slotIndexOf(third_task.id).?;
    const queue_index = resourceClassIndex(.foreground_interactive);
    try std.testing.expectEqual(compactQueueIndex(first_index), scheduler.ready_heads[queue_index]);
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.ready_tails[queue_index]);
    try std.testing.expectEqual(compactQueueIndex(first_index), scheduler.slots.slots[second_index].prev_ready_index);
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.slots.slots[second_index].next_ready_index);

    try std.testing.expect(scheduler.parkTaskUntilEvent(second_task.id));
    try std.testing.expectEqual(@as(usize, 2), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.slots.slots[first_index].next_ready_index);
    try std.testing.expectEqual(compactQueueIndex(first_index), scheduler.slots.slots[third_index].prev_ready_index);
    try std.testing.expectEqual(QUEUE_NO_INDEX, scheduler.slots.slots[second_index].prev_ready_index);
    try std.testing.expectEqual(QUEUE_NO_INDEX, scheduler.slots.slots[second_index].next_ready_index);

    try std.testing.expect(scheduler.unregisterTask(first_task.id));
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.ready_heads[queue_index]);
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.ready_tails[queue_index]);
    try std.testing.expectEqual(QUEUE_NO_INDEX, scheduler.slots.slots[third_index].prev_ready_index);
}

test "userspace scheduler compact queue indexes cover every task slot" {
    try std.testing.expectEqual(@as(usize, task_runtime.MAX_TASKS), @as(usize, QUEUE_NO_INDEX));
    try std.testing.expectEqual(
        @as(QueueSlotIndex, @intCast(task_runtime.MAX_TASKS - 1)),
        compactQueueIndex(task_runtime.MAX_TASKS - 1),
    );
}

test "userspace scheduler parks only explicit event-wait yields" {
    try std.testing.expect(executionRemainsReady(.unavailable));
    try std.testing.expect(executionRemainsReady(.yielded));
    try std.testing.expect(!executionRemainsReady(.wait_for_event));
    try std.testing.expect(!executionRemainsReady(.faulted));
}

// Hosted dispatch supplies the outcome in place of native entry. The retained
// task, mapping handle, running lease and returned acknowledgement are real.
const EventYieldTestDispatcher = if (builtin.is_test) struct {
    scheduler: *Scheduler,
    runtime: *task_runtime.Runtime,
    action: enum { none, wake, ipc, work } = .none,
    wake_count: usize = 1,
    endpoints: ?*endpoint.Table = null,
    sender_endpoint: ?ids.EndpointId = null,
    sender_task_id: u64 = 0,
    outcome: userspace_executor.ExecutionOutcome = .wait_for_event,
    pending_work: bool = false,
    processed_work: usize = 0,
    calls: usize = 0,

    fn executePreparedTask(self: *@This(), task: *const task_runtime.TaskRecord, mapping: *userspace_executor.MappingHandle, now: u64) dispatch_ownership.ReturnRecord {
        self.execute(task, mapping, now) catch @panic("event yield fixture must preserve exact dispatch ownership");
        return .{ .outcome = self.outcome };
    }

    fn execute(self: *@This(), task: *const task_runtime.TaskRecord, mapping: *userspace_executor.MappingHandle, now: u64) !void {
        const ticket = self.scheduler.active_dispatch_lease.?;
        const slot = self.scheduler.slots.get(task.id).?;
        try std.testing.expectEqual(task.id, self.scheduler.active_dispatch_task_id);
        try std.testing.expectEqual(dispatch_ownership.Phase.reserved, try self.runtime.execution.phase(ticket));
        try std.testing.expectEqual(@as(u8, 1), self.runtime.task_borrow_counts[task.arena_slot_index]);
        try std.testing.expect(self.runtime.findByHandle(slot.task_handle, task.id).? == task);
        try std.testing.expect(mapping == &slot.mapping_handle);
        try std.testing.expect(mapping.eql(self.scheduler.executor.mappingHandle(task.address_space_id).?));
        try std.testing.expect(!slot.queued_ready);
        try self.runtime.execution.bindOwnedRoot(ticket, mapping.value, 0x1000);
        const bound = try self.runtime.execution.start(ticket);
        try std.testing.expectEqual(task.id, bound.identity.task_id);
        try std.testing.expectEqual(mapping.value, bound.mapping_handle);
        try std.testing.expectError(error.WrongPhase, self.runtime.collectExecution(ticket));
        switch (self.action) {
            .none => {},
            .wake => {
                for (0..self.wake_count) |_| {
                    try std.testing.expect(self.scheduler.wakeTask(task.id, .external_event, now, 0));
                    try std.testing.expect(slot.queued_ready);
                    try std.testing.expectEqual(@as(usize, 1), self.scheduler.readyQueueDepth(slot.resource_class));
                }
            },
            .ipc => {
                const table = self.endpoints.?;
                try std.testing.expect(!table.hasPendingForTask(ids.task(task.id)));
                const destination = try table.send(self.sender_endpoint.?, ids.task(self.sender_task_id), 91, "after drain", null, false);
                try std.testing.expectEqual(task.id, destination.raw());
                try std.testing.expect(table.hasPendingForTask(ids.task(task.id)));
                // No wake callback exists in this fixture. The final pending
                // IPC check must recover the arrival after the last drain.
                try std.testing.expect(!slot.queued_ready);
            },
            .work => {
                try std.testing.expect(self.pending_work);
                self.pending_work = false;
                self.processed_work += 1;
            },
        }
        try std.testing.expectEqual(dispatch_ownership.Phase.running, try self.runtime.execution.phase(ticket));
        try std.testing.expect(self.scheduler.active_dispatch_lease.?.issuer == ticket.issuer);
        try self.runtime.execution.acknowledgeOwnedRootReturn(ticket);
        try std.testing.expectEqual(dispatch_ownership.Phase.returned, try self.runtime.execution.phase(ticket));
        try std.testing.expectEqual(@as(u8, 1), self.runtime.task_borrow_counts[task.arena_slot_index]);
        self.calls += 1;
    }
} else struct {};

fn installEventYieldTestMapping(scheduler: *Scheduler, task: *const task_runtime.TaskRecord) !userspace_executor.MappingHandle {
    if (!builtin.is_test) @compileError("event yield mappings are test-only");
    const mappings = &scheduler.executor.mappings;
    const index = mappings.reserveIndex(task.address_space_id) orelse return error.UnavailableMappingSlot;
    mappings.slotAt(index).mapping = .{
        .state = .live,
        .address_space_id = task.address_space_id,
        .dispatch_metadata = .{ .owner_task_id = task.id },
        .resume_valid = true,
        .user_context64 = .{ .instruction_pointer = 0x1234, .stack_pointer = 0x5678 },
    };
    const handle = mappings.handleForIndex(index).?;
    scheduler.slots.get(task.id).?.mapping_handle = handle;
    return handle;
}

test "voluntary event yield parks without a wait syscall and retains task and cached mapping" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    defer runtime.reset();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();
    const task = try createRunnableSchedulerTaskWithBudget(&runtime, 701, .foreground_interactive, "event", "app.event", null, DISPATCH_CPU_TICK_COST * 4);
    const unrelated = try createRunnableSchedulerTask(&runtime, 702, .background_light, "other", "app.other", null);
    try runtime.grantCapability(task.id, 77);
    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.registerTask(unrelated.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(unrelated.id));
    const slot = scheduler.slots.get(task.id).?;
    const task_handle = slot.task_handle;
    const mapping_handle = try installEventYieldTestMapping(&scheduler, task);
    const mapping_before = executor.mappings.getByHandle(mapping_handle).?.mapping;
    const address_space = runtime.findAddressSpaceConst(task.address_space_id).?;
    const task_generation = task.capabilityGeneration();
    const capability_generation = capabilities.mutationGeneration();
    const unrelated_slot = scheduler.slots.get(unrelated.id).?.*;
    const unrelated_accounting = scheduler.taskDispatchAccounting(unrelated.id).?.*;
    var dispatcher = EventYieldTestDispatcher{ .scheduler = &scheduler, .runtime = &runtime };
    try std.testing.expect(scheduler.runNextWithDispatch(10, &dispatcher));
    try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
    try std.testing.expect(!scheduler.hasReadyTasks());
    try std.testing.expect(!runtime.execution.hasLeases());
    try std.testing.expect(scheduler.active_dispatch_lease == null);
    try std.testing.expectEqual(@as(u64, 0), scheduler.active_dispatch_task_id);
    try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[task.arena_slot_index]);
    try std.testing.expectEqual(task_runtime.TaskState.active, task.state);
    try std.testing.expect(runtime.findByHandle(task_handle, task.id).? == task);
    try std.testing.expect(runtime.findAddressSpaceConst(task.address_space_id).? == address_space);
    try std.testing.expect(slot.mapping_handle.eql(mapping_handle));
    try std.testing.expectEqualDeep(mapping_before, executor.mappings.getByHandle(mapping_handle).?.mapping);
    try std.testing.expectEqual(@as(usize, 1), executor.materializedCount());
    try std.testing.expectEqual(@as(u16, 1), task.capability_count);
    try std.testing.expectEqual(@as(u64, 77), task.capabilityIds()[0]);
    try std.testing.expectEqual(task_generation, task.capabilityGeneration());
    try std.testing.expectEqual(capability_generation, capabilities.mutationGeneration());
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchAccounting(task.id).?.event_wait_count);
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST * 3, slot.cpu_budget_remaining_ticks);

    // A later activation restores its configured budget exactly once; further
    // wakes coalesce even after that activation has consumed some credit.
    for (0..8) |_| try std.testing.expect(scheduler.wakeTask(task.id, .external_event, 11, 0));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST * 4, slot.cpu_budget_remaining_ticks);
    slot.cpu_budget_remaining_ticks = DISPATCH_CPU_TICK_COST * 2;
    for (0..8) |_| try std.testing.expect(scheduler.wakeTask(task.id, .external_event, 12, 0));
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST * 2, slot.cpu_budget_remaining_ticks);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expect(scheduler.runNextWithDispatch(13, &dispatcher));
    try std.testing.expect(!scheduler.hasReadyTasks());
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST, slot.cpu_budget_remaining_ticks);
    try std.testing.expectEqual(@as(u64, 2), scheduler.taskDispatchAccounting(task.id).?.event_wait_count);
    try std.testing.expectEqualDeep(unrelated_slot, scheduler.slots.get(unrelated.id).?.*);
    try std.testing.expectEqualDeep(unrelated_accounting, scheduler.taskDispatchAccounting(unrelated.id).?.*);
    try std.testing.expectEqualDeep(mapping_before, executor.mappings.getByHandle(mapping_handle).?.mapping);
}

test "voluntary event yield preserves wakes during exact leased dispatch without duplicate budget" {
    for ([_]usize{ 1, 8 }) |wake_count| {
        var executor = userspace_executor.Executor{};
        var scheduler = Scheduler.init(&executor);
        var catalog = userspace_loader.Catalog.init();
        var runtime = task_runtime.Runtime.init();
        var capabilities = capability.CapabilityTable.init();
        defer runtime.reset();
        scheduler.bind(&catalog, &runtime, &capabilities);
        defer scheduler.deinit();
        const task = try createRunnableSchedulerTaskWithBudget(&runtime, 703, .foreground_interactive, "woken", "app.woken", null, DISPATCH_CPU_TICK_COST * 4);
        const unrelated = try createRunnableSchedulerTask(&runtime, 704, .batch_compute, "other", "app.other", null);
        try std.testing.expect(scheduler.registerTask(task.id));
        try std.testing.expect(scheduler.registerTask(unrelated.id));
        try std.testing.expect(scheduler.parkTaskUntilEvent(unrelated.id));
        const unrelated_slot = scheduler.slots.get(unrelated.id).?.*;
        const unrelated_accounting = scheduler.taskDispatchAccounting(unrelated.id).?.*;
        const slot = scheduler.slots.get(task.id).?;
        const task_handle = slot.task_handle;
        const mapping_handle = try installEventYieldTestMapping(&scheduler, task);
        const initial_wakes = scheduler.taskDispatchAccounting(task.id).?.wake_event_count;
        slot.cpu_budget_remaining_ticks = DISPATCH_CPU_TICK_COST * 2;
        var dispatcher = EventYieldTestDispatcher{ .scheduler = &scheduler, .runtime = &runtime, .action = .wake, .wake_count = wake_count };
        try std.testing.expect(scheduler.runNextWithDispatch(20, &dispatcher));
        try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
        try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
        try std.testing.expect(slot.queued_ready and slot.task_handle.eql(task_handle) and slot.mapping_handle.eql(mapping_handle));
        try std.testing.expectEqual(DISPATCH_CPU_TICK_COST * 3, slot.cpu_budget_remaining_ticks);
        try std.testing.expectEqual(initial_wakes + wake_count, scheduler.taskDispatchAccounting(task.id).?.wake_event_count);
        try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchAccounting(task.id).?.event_wait_count);
        try std.testing.expect(!runtime.execution.hasLeases());
        try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[task.arena_slot_index]);
        dispatcher.action = .none;
        try std.testing.expect(scheduler.runNextWithDispatch(21, &dispatcher));
        try std.testing.expect(!scheduler.hasReadyTasks());
        try std.testing.expectEqual(DISPATCH_CPU_TICK_COST * 2, slot.cpu_budget_remaining_ticks);
        try std.testing.expectEqual(@as(u64, 2), slot.dispatch_count);
        try std.testing.expectEqualDeep(unrelated_slot, scheduler.slots.get(unrelated.id).?.*);
        try std.testing.expectEqualDeep(unrelated_accounting, scheduler.taskDispatchAccounting(unrelated.id).?.*);
    }
}

test "voluntary event yield requeues actual IPC arriving after drain without a wake callback" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    defer endpoints.deinit();
    defer runtime.reset();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();
    scheduler.bindEndpointTable(&endpoints);
    const receiver = try createRunnableSchedulerTaskWithBudget(&runtime, 705, .foreground_interactive, "receiver", "app.receiver", null, DISPATCH_CPU_TICK_COST * 4);
    const sender = try createRunnableSchedulerTask(&runtime, 706, .background_light, "sender", "app.sender", null);
    const receiver_endpoint = try endpoints.create(ids.task(receiver.id), "receiver", .{ .local_only = true });
    const sender_endpoint = try endpoints.create(ids.task(sender.id), "sender", .{ .local_only = true });
    try endpoints.connect(sender_endpoint.id, receiver_endpoint.id);
    try std.testing.expect(scheduler.registerTask(receiver.id));
    const mapping_handle = try installEventYieldTestMapping(&scheduler, receiver);
    const capability_generation = capabilities.mutationGeneration();
    const initial_wakes = scheduler.taskDispatchAccounting(receiver.id).?.wake_event_count;
    var dispatcher = EventYieldTestDispatcher{
        .scheduler = &scheduler,
        .runtime = &runtime,
        .action = .ipc,
        .endpoints = &endpoints,
        .sender_endpoint = sender_endpoint.id,
        .sender_task_id = sender.id,
    };
    try std.testing.expect(scheduler.runNextWithDispatch(30, &dispatcher));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expect(endpoints.hasPendingForTask(ids.task(receiver.id)));
    try std.testing.expectEqual(initial_wakes, scheduler.taskDispatchAccounting(receiver.id).?.wake_event_count);
    try std.testing.expect(!runtime.execution.hasLeases());
    dispatcher.action = .none;
    try std.testing.expect(scheduler.runNextWithDispatch(31, &dispatcher));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try endpoints.recvInto(receiver_endpoint.id, &payload)).?;
    try std.testing.expectEqual(@as(u64, 91), received.correlation_id);
    try std.testing.expectEqualStrings("after drain", payload[0..received.len]);
    try std.testing.expect(!endpoints.hasPendingForTask(ids.task(receiver.id)));
    try std.testing.expect(scheduler.runNextWithDispatch(32, &dispatcher));
    try std.testing.expect(!scheduler.hasReadyTasks());
    try std.testing.expectEqual(@as(usize, 3), dispatcher.calls);
    try std.testing.expectEqual(@as(u64, 3), scheduler.taskDispatchAccounting(receiver.id).?.event_wait_count);
    try std.testing.expectEqual(initial_wakes, scheduler.taskDispatchAccounting(receiver.id).?.wake_event_count);
    try std.testing.expectEqual(capability_generation, capabilities.mutationGeneration());
    try std.testing.expect(scheduler.slots.get(receiver.id).?.mapping_handle.eql(mapping_handle));
    try std.testing.expect(!runtime.execution.hasLeases());
    try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[receiver.arena_slot_index]);
}

test "voluntary event yield preserves interrupted continuation work within one activation credit" {
    for ([_]usize{ 1, 8 }) |wake_count| {
        var executor = userspace_executor.Executor{};
        var scheduler = Scheduler.init(&executor);
        var catalog = userspace_loader.Catalog.init();
        var runtime = task_runtime.Runtime.init();
        var capabilities = capability.CapabilityTable.init();
        defer runtime.reset();
        scheduler.bind(&catalog, &runtime, &capabilities);
        defer scheduler.deinit();
        const task = try createRunnableSchedulerTask(&runtime, 707, .foreground_interactive, "interrupted", "app.interrupted", null);
        const unrelated = try createRunnableSchedulerTask(&runtime, 708, .background_light, "other", "app.other", null);
        try std.testing.expect(scheduler.registerTask(task.id));
        try std.testing.expect(scheduler.registerTask(unrelated.id));
        try std.testing.expect(scheduler.parkTaskUntilEvent(unrelated.id));
        const unrelated_slot = scheduler.slots.get(unrelated.id).?.*;
        const unrelated_accounting = scheduler.taskDispatchAccounting(unrelated.id).?.*;
        const slot = scheduler.slots.get(task.id).?;
        const task_handle = slot.task_handle;
        const mapping_handle = try installEventYieldTestMapping(&scheduler, task);
        const mapping_before = executor.mappings.getByHandle(mapping_handle).?.mapping;
        const initial_wakes = scheduler.taskDispatchAccounting(task.id).?.wake_event_count;
        // Executor's actual IRQ/yield tests verify the stale wait returns to the
        // fresh user loop in place, within the same quantum and running lease.
        // This companion supplies only the final outcomes and a work callback;
        // it exercises real Scheduler queues, credits and Runtime collection.
        var dispatcher = EventYieldTestDispatcher{ .scheduler = &scheduler, .runtime = &runtime, .outcome = .yielded };
        try std.testing.expect(scheduler.runNextWithDispatch(40, &dispatcher));
        try std.testing.expect(!runtime.execution.hasLeases());
        try std.testing.expect(!scheduler.hasReadyTasks());
        try std.testing.expectEqual(@as(u64, 0), slot.cpu_budget_remaining_ticks);
        dispatcher.pending_work = true;
        for (0..wake_count) |_| try std.testing.expect(scheduler.wakeTask(task.id, .external_event, 41, 0));
        try std.testing.expectEqual(DISPATCH_CPU_TICK_COST, slot.cpu_budget_remaining_ticks);
        try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
        try std.testing.expectEqual(@as(u64, 0), scheduler.taskDispatchAccounting(task.id).?.event_wait_count);
        dispatcher.action = .work;
        dispatcher.outcome = .wait_for_event;
        try std.testing.expect(scheduler.runNextWithDispatch(42, &dispatcher));
        try std.testing.expect(!dispatcher.pending_work);
        try std.testing.expectEqual(@as(usize, 1), dispatcher.processed_work);
        try std.testing.expect(!scheduler.hasReadyTasks());
        try std.testing.expectEqual(@as(usize, 2), dispatcher.calls);
        try std.testing.expectEqual(@as(u64, 2), slot.dispatch_count);
        try std.testing.expectEqual(@as(u64, 0), slot.cpu_budget_remaining_ticks);
        try std.testing.expectEqual(initial_wakes + wake_count, scheduler.taskDispatchAccounting(task.id).?.wake_event_count);
        try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchAccounting(task.id).?.event_wait_count);
        try std.testing.expect(!runtime.execution.hasLeases());
        try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[task.arena_slot_index]);
        try std.testing.expect(slot.task_handle.eql(task_handle) and slot.mapping_handle.eql(mapping_handle));
        try std.testing.expectEqualDeep(mapping_before, executor.mappings.getByHandle(mapping_handle).?.mapping);
        try std.testing.expectEqualDeep(unrelated_slot, scheduler.slots.get(unrelated.id).?.*);
        try std.testing.expectEqualDeep(unrelated_accounting, scheduler.taskDispatchAccounting(unrelated.id).?.*);
    }
}

test "userspace scheduler dispatches resource ready queues by priority" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const background_image = try schedulerTestUserspaceImage(false);
    const foreground_image = try schedulerTestUserspaceImage(false);
    const background = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
            .resource_class = .background_light,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 3,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.background",
        },
        .userspace_image = &background_image,
    });
    const foreground = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
            .resource_class = .foreground_interactive,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 4,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.foreground",
        },
        .userspace_image = &foreground_image,
    });

    try std.testing.expect(scheduler.registerTask(background.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.background_light));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));

    try std.testing.expect(scheduler.wakeTask(foreground.id, .timer, 10, 5));
    try std.testing.expect(!scheduler.runNext(10));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(foreground.id).?.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchAccounting(foreground.id).?.missed_deadline_count);
    try std.testing.expectEqual(@as(u64, 0), scheduler.slots.getConst(background.id).?.dispatch_count);
}

test "userspace scheduler keeps compositor-class work ahead of expired log compact" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const compact = try createRunnableSchedulerTask(
        &runtime,
        31,
        .batch_compute,
        "log-compact",
        "sys.storage.log-compact",
        null,
    );
    const compositor = try createRunnableSchedulerTask(
        &runtime,
        32,
        .foreground_interactive,
        "compositor",
        "sys.compositor.session",
        32,
    );

    try std.testing.expect(scheduler.registerTask(compact.id));
    try std.testing.expect(scheduler.registerTask(compositor.id));
    try std.testing.expect(scheduler.wakeTask(compact.id, .timer, 50, 1));
    try std.testing.expect(scheduler.wakeTask(compositor.id, .timer, 50, 2));
    try std.testing.expect(scheduler.shouldPreemptTask(compact.id));
    try std.testing.expect(!scheduler.shouldPreemptTask(compositor.id));
    try std.testing.expect(PREEMPTS_BATCH_FOR_INTERACTIVE);
    try std.testing.expect(!scheduler.runNext(50));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(compositor.id).?.dispatch_count);
    try std.testing.expectEqual(@as(u64, 0), scheduler.slots.getConst(compact.id).?.dispatch_count);
}

test "userspace scheduler uses event wakeups and explicit budget refills" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const image = try schedulerTestUserspaceImage(false);
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 5 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 5,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.wake-budgeted",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(!scheduler.runNext(1));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(task.id).?.dispatch_count);
    try std.testing.expect(!scheduler.runNext(2));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(task.id).?.dispatch_count);

    try std.testing.expect(scheduler.refillTaskBudget(task.id, DISPATCH_CPU_TICK_COST, 3));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expect(!scheduler.runNext(4));
    try std.testing.expectEqual(@as(u64, 2), scheduler.slots.getConst(task.id).?.dispatch_count);
    try std.testing.expectEqual(@as(u64, 2), scheduler.taskDispatchAccounting(task.id).?.wake_event_count);
}

test "userspace scheduler gives new event activations a full budget without accumulating duplicate wakes" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    const image = try schedulerTestUserspaceImage(false);
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 6 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 3, .memory_bytes = TEST_TASK_MEMORY_BYTES, .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS, .shared_memory_bytes = 0 },
        .local_only = true,
        .launch = .{ .boundary = .userspace_process, .image_id = 6, .component_abi_version = 1, .signed = true, .bundle_id = "app.activation-budget" },
        .userspace_image = &image,
    });
    try std.testing.expect(scheduler.registerTask(task.id));
    const index = scheduler.slots.slotIndexOf(task.id).?;
    const slot = &scheduler.slots.slots[index];
    // The first interaction uses two dispatches, then parks with one left.
    _ = scheduler.runNext(1);
    _ = scheduler.runNext(2);
    scheduler.unlinkReadyIndex(index); // Model a userspace event wait on the host.
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST, slot.cpu_budget_remaining_ticks);
    try std.testing.expect(scheduler.wakeTask(task.id, .external_event, 3, 0));
    _ = scheduler.runNext(3); // Read the next interaction.
    for (0..8) |_| try std.testing.expect(scheduler.wakeTask(task.id, .external_event, 3, 0));
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST * 2, slot.cpu_budget_remaining_ticks);
    _ = scheduler.runNext(4); // Publish its reply without waiting for another event.
    try std.testing.expectEqual(@as(u64, 4), slot.dispatch_count);
    try std.testing.expect(slot.queued_ready);
    // Explicit small refills are exact and cannot silently become a full grant.
    _ = scheduler.runNext(5);
    try std.testing.expect(!slot.queued_ready);
    try std.testing.expect(scheduler.refillTaskBudget(task.id, 0, 6));
    _ = scheduler.runNext(6);
    try std.testing.expectEqual(@as(u64, 5), slot.dispatch_count);
    try std.testing.expect(scheduler.refillTaskBudget(task.id, DISPATCH_CPU_TICK_COST / 2, 7));
    _ = scheduler.runNext(7);
    try std.testing.expectEqual(@as(u64, 5), slot.dispatch_count);
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST / 2, slot.cpu_budget_remaining_ticks);
    try std.testing.expect(scheduler.wakeTask(task.id, .ipc_message, 8, 0));
    _ = scheduler.runNext(8);
    _ = scheduler.runNext(9);
    try std.testing.expectEqual(@as(u64, 7), slot.dispatch_count);
}

test "userspace scheduler coalesces wakes at the earliest ready deadline" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    const task = try createRunnableSchedulerTask(&runtime, 7, .background_light, "wake-deadline", "app.wake-deadline", null);
    try std.testing.expect(scheduler.registerTask(task.id));
    const slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expect(scheduler.wakeTask(task.id, .ipc_message, 10, 0));
    try std.testing.expectEqual(BACKGROUND_DEADLINE_DELTA_TICKS, slot.deadline_tick);
    try std.testing.expect(scheduler.wakeTask(task.id, .timer, 11, 20));
    try std.testing.expectEqual(@as(u64, 20), slot.deadline_tick);
    try std.testing.expect(scheduler.wakeTask(task.id, .ipc_message, 12, 80));
    try std.testing.expectEqual(@as(u64, 20), slot.deadline_tick);
    try std.testing.expect(scheduler.parkTaskUntilEvent(task.id));
    try std.testing.expect(scheduler.wakeTask(task.id, .external_event, 90, 0));
    try std.testing.expectEqual(@as(u64, 90) + BACKGROUND_DEADLINE_DELTA_TICKS, slot.deadline_tick);
}

test "userspace scheduler separates accelerator claim queues from cpu ready queues" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 6 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .media_export,
        },
        .local_only = true,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(task.id));
    try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(.media_export));

    const gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 7,
        .deadline_tick = TEST_ACCELERATOR_DEADLINE_TICKS,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    const duplicate_gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 8,
        .deadline_tick = TEST_ACCELERATOR_DEADLINE_TICKS,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    try std.testing.expectEqual(gpu_claim, duplicate_gpu_claim);
    const media_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .media,
        .resource_class = .media_export,
        .requested_at_tick = 8,
        .deadline_tick = TEST_ACCELERATOR_DEADLINE_TICKS,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;

    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expect(scheduler.grantNextAcceleratorClaim(.media, 8) == null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    scheduler.configureResourceTelemetry(.{
        .source = .emulator,
        .observed_tick = 9,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });
    try std.testing.expect(scheduler.grantNextAcceleratorClaim(.media, 9) == null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 10,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    const granted = scheduler.grantNextAcceleratorClaim(.media, 10).?;
    try std.testing.expectEqual(media_claim, granted.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.media_export));
}

test "userspace scheduler indexes accelerator claims by task across grants and unregister" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const task = try createRunnableSchedulerTask(
        &runtime,
        250,
        .media_export,
        "indexed-claim-task",
        "app.example.indexed-claim-task",
        250,
    );

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(task.id));

    const first_gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 1,
        .deadline_tick = 40,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    const duplicate_gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 2,
        .deadline_tick = 30,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    try std.testing.expectEqual(first_gpu_claim, duplicate_gpu_claim);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimBackingConst().?.task_index.count(acceleratorClaimTaskKey(task.id)));

    const granted_gpu = scheduler.grantNextAcceleratorClaim(.gpu, 3).?;
    try std.testing.expectEqual(first_gpu_claim, granted_gpu.id);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimBackingConst().?.task_index.count(acceleratorClaimTaskKey(task.id)));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));

    try std.testing.expect(scheduler.parkTaskUntilEvent(task.id));
    const second_gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 4,
        .deadline_tick = 45,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    try std.testing.expect(first_gpu_claim != second_gpu_claim);
    _ = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .media,
        .resource_class = .media_export,
        .requested_at_tick = 5,
        .deadline_tick = 46,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    try std.testing.expectEqual(@as(usize, 2), scheduler.acceleratorClaimBackingConst().?.task_index.count(acceleratorClaimTaskKey(task.id)));

    try std.testing.expect(scheduler.unregisterTask(task.id));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimBackingConst().?.task_index.count(acceleratorClaimTaskKey(task.id)));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
}

test "userspace scheduler stops accelerator claim ids at exhaustion" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try createRunnableSchedulerTask(
        &runtime,
        251,
        .media_export,
        "final-claim-task",
        "app.example.final-claim-task",
        251,
    );
    try std.testing.expect(scheduler.registerTask(task.id));
    scheduler.next_accelerator_claim_id = std.math.maxInt(u64);

    const final_claim_id = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 1,
    }).?;
    try std.testing.expectEqual(std.math.maxInt(u64), final_claim_id);
    try std.testing.expectEqual(@as(u64, 0), scheduler.next_accelerator_claim_id);
    try std.testing.expect(scheduler.unregisterTask(task.id));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .media,
        .resource_class = .media_export,
        .requested_at_tick = 2,
    }) == null);
    try std.testing.expectEqual(@as(u64, 0), scheduler.next_accelerator_claim_id);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
}

test "userspace scheduler retains accelerator waiters when claim reservation fails" {
    for ([_]bool{ false, true }) |fill_claim_table| {
        var executor = userspace_executor.Executor{};
        var scheduler = Scheduler.init(&executor);
        var catalog = userspace_loader.Catalog.init();
        var runtime = task_runtime.Runtime.init();
        var capabilities = capability.CapabilityTable.init();
        scheduler.bind(&catalog, &runtime, &capabilities);
        scheduler.configureResourceTelemetry(.{
            .source = .hardware,
            .observed_tick = 1,
            .gpu_available = false,
            .npu_available = false,
            .media_available = false,
            .hardware_evidence = completeTestHardwareEvidence(),
        });
        if (fill_claim_table) {
            var claim_count: usize = 0;
            while (claim_count < MAX_ACCELERATOR_CLAIMS) {
                const filler = try createRunnableSchedulerTask(&runtime, @intCast(300 + claim_count), .background_light, "claim-filler", "app.claim-filler", null);
                try std.testing.expect(scheduler.registerTask(filler.id));
                try std.testing.expect(scheduler.parkTaskUntilEvent(filler.id));
                for (engine_priority_order) |engine| {
                    if (claim_count == MAX_ACCELERATOR_CLAIMS) break;
                    try std.testing.expect(scheduler.enqueueAcceleratorClaim(.{
                        .task_id = filler.id,
                        .engine = engine,
                        .resource_class = .background_light,
                        .requested_at_tick = 1,
                    }) != null);
                    claim_count += 1;
                }
            }
        } else {
            scheduler.next_accelerator_claim_id = 0;
        }
        const waiter = try createRunnableSchedulerTask(&runtime, 8, .media_export, "claim-waiter", "app.claim-waiter", null);
        const ordinary = try createRunnableSchedulerTask(&runtime, 9, .media_export, "claim-tail", "app.claim-tail", null);
        try std.testing.expect(scheduler.registerTask(waiter.id));
        try std.testing.expect(scheduler.configureTaskDispatchRequest(waiter.id, .{ .class = .media_export, .wants_gpu = true }, true));
        try std.testing.expect(scheduler.registerTask(ordinary.id));
        try std.testing.expect(scheduler.configureTaskDispatchRequest(ordinary.id, .{ .class = .media_export }, false));
        _ = scheduler.runNext(1);
        try std.testing.expect(scheduler.slots.getConst(waiter.id).?.queued_ready);
        try std.testing.expectEqual(@as(u64, 0), scheduler.slots.getConst(waiter.id).?.pending_accelerator_claim_id);
        try std.testing.expect(scheduler.hasDispatchableTasks(2));
        _ = scheduler.runNext(2);
        try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(ordinary.id).?.dispatch_count);
        try std.testing.expect(!scheduler.hasDispatchableTasks(3));
        for (3..8) |tick| _ = scheduler.runNext(tick);
        try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(waiter.id).?.denied_dispatch_count);
        scheduler.configureResourceTelemetry(.{
            .source = .hardware,
            .observed_tick = 8,
            .gpu_available = true,
            .npu_available = false,
            .media_available = false,
            .hardware_evidence = completeTestHardwareEvidence(),
        });
        try std.testing.expect(scheduler.hasDispatchableTasks(8));
        _ = scheduler.runNext(8);
        const stats = scheduler.taskDispatchStats(waiter.id).?;
        try std.testing.expectEqual(@as(u64, 1), stats.dispatch_count);
        try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, stats.last_dispatch_engine);
    }
}

test "userspace scheduler rejects unsatisfiable accelerator requirements without changing configuration" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    const task = try createRunnableSchedulerTask(&runtime, 11, .media_export, "invalid-accelerator", "app.invalid-accelerator", null);
    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(task.id, .{ .class = .media_export, .wants_gpu = true }, true));
    const slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expect(!scheduler.configureTaskDispatchRequest(task.id, .{ .class = .media_export }, true));
    try std.testing.expect(!scheduler.configureTaskDispatchRequest(task.id, .{ .class = .media_export, .wants_npu = true }, true));
    try std.testing.expect(slot.dispatch_request.wants_gpu);
    try std.testing.expect(slot.require_accelerator);
    try std.testing.expect(slot.queued_ready);
    const service = try createRunnableSchedulerTask(&runtime, 12, .emergency_system_critical, "invalid-service-accelerator", "svc.invalid-accelerator", null);
    try std.testing.expect(scheduler.registerTask(service.id));
    try std.testing.expect(!scheduler.configureTaskDispatchRequest(service.id, .{ .class = .emergency_system_critical, .wants_gpu = true }, true));
    try std.testing.expect(!scheduler.slots.getConst(service.id).?.dispatch_request_configured);
    try std.testing.expect(!scheduler.slots.getConst(service.id).?.require_accelerator);
}

test "userspace scheduler waits on an engine supported by the actual task class" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    const task = try createRunnableSchedulerTask(&runtime, 13, .foreground_interactive, "class-accelerator", "app.class-accelerator", null);
    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(!scheduler.configureTaskDispatchRequest(task.id, .{ .class = .foreground_interactive, .wants_media_engine = true }, true));
    try std.testing.expect(!scheduler.slots.getConst(task.id).?.dispatch_request_configured);
    try std.testing.expect(scheduler.configureTaskDispatchRequest(task.id, .{
        .class = .media_export,
        .wants_media_engine = true,
        .wants_gpu = true,
    }, true));
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.foreground_interactive, scheduler.slots.getConst(task.id).?.dispatch_request.class);
    _ = scheduler.runNext(1);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
}

test "userspace scheduler wakes required media work when only its alternative GPU becomes available" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .gpu_available = false,
        .npu_available = false,
        .media_available = false,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    const task = try createRunnableSchedulerTask(&runtime, 14, .media_export, "alternative-accelerator", "app.alternative-accelerator", null);
    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(task.id, .{
        .class = .media_export,
        .wants_media_engine = true,
        .wants_gpu = true,
    }, true));
    _ = scheduler.runNext(1);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expect(!scheduler.hasDispatchableTasks(2));
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 2,
        .gpu_available = true,
        .npu_available = false,
        .media_available = false,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    try std.testing.expect(scheduler.hasDispatchableTasks(2));
    _ = scheduler.runNext(2);
    const stats = scheduler.taskDispatchStats(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), stats.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, stats.last_dispatch_engine);
}

test "userspace scheduler idles required accelerators denied by policy until policy or request changes" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .privacy_mode = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    const waiter = try createRunnableSchedulerTaskWithBudget(&runtime, 10, .background_light, "policy-waiter", "app.policy-waiter", null, DISPATCH_CPU_TICK_COST * 2);
    try std.testing.expect(scheduler.registerTask(waiter.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(waiter.id, .{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    }, true));
    _ = scheduler.runNext(1);
    try std.testing.expect(scheduler.slots.getConst(waiter.id).?.queued_ready);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.npu));
    try std.testing.expect(!scheduler.hasDispatchableTasks(2));
    for (2..8) |tick| _ = scheduler.runNext(tick);
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(waiter.id).?.denied_dispatch_count);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 8,
        .privacy_mode = false,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    try std.testing.expect(scheduler.hasDispatchableTasks(8));
    _ = scheduler.runNext(8);
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(waiter.id).?.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, scheduler.taskDispatchStats(waiter.id).?.last_dispatch_engine);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 9,
        .privacy_mode = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    _ = scheduler.runNext(9);
    try std.testing.expect(!scheduler.hasDispatchableTasks(10));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(waiter.id, .{ .class = .background_light }, false));
    try std.testing.expect(scheduler.hasDispatchableTasks(10));
    _ = scheduler.runNext(10);
    try std.testing.expectEqual(@as(u64, 2), scheduler.taskDispatchStats(waiter.id).?.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.cpu, scheduler.taskDispatchStats(waiter.id).?.last_dispatch_engine);
}

test "userspace scheduler grants expired high-priority accelerator claims before older batch claims" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const batch = try createRunnableSchedulerTask(
        &runtime,
        260,
        .batch_compute,
        "queued-batch-gpu",
        "app.example.queued-batch-gpu",
        null,
    );
    const foreground = try createRunnableSchedulerTask(
        &runtime,
        261,
        .foreground_interactive,
        "urgent-foreground-gpu",
        "app.example.urgent-foreground-gpu",
        261,
    );

    try std.testing.expect(scheduler.registerTask(batch.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(batch.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(foreground.id));

    const batch_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = batch.id,
        .engine = .gpu,
        .resource_class = .batch_compute,
        .requested_at_tick = 1,
        .deadline_tick = 200,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    const foreground_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = foreground.id,
        .engine = .gpu,
        .resource_class = .foreground_interactive,
        .requested_at_tick = 2,
        .deadline_tick = 20,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;

    try std.testing.expectEqual(@as(usize, 2), scheduler.acceleratorClaimQueueDepth(.gpu));
    const granted_foreground = scheduler.grantNextAcceleratorClaim(.gpu, 20).?;
    try std.testing.expectEqual(foreground_claim, granted_foreground.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(.batch_compute));
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));

    const granted_batch = scheduler.grantNextAcceleratorClaim(.gpu, 21).?;
    try std.testing.expectEqual(batch_claim, granted_batch.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.batch_compute));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));
}

test "userspace scheduler grants expired accelerator deadlines before unexpired foreground claims" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const batch = try createRunnableSchedulerTask(
        &runtime,
        262,
        .batch_compute,
        "expired-batch-gpu",
        "app.example.expired-batch-gpu",
        null,
    );
    const foreground = try createRunnableSchedulerTask(
        &runtime,
        263,
        .foreground_interactive,
        "unexpired-foreground-gpu",
        "app.example.unexpired-foreground-gpu",
        263,
    );

    try std.testing.expect(scheduler.registerTask(batch.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(batch.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(foreground.id));

    const foreground_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = foreground.id,
        .engine = .gpu,
        .resource_class = .foreground_interactive,
        .requested_at_tick = 1,
        .deadline_tick = 200,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    const batch_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = batch.id,
        .engine = .gpu,
        .resource_class = .batch_compute,
        .requested_at_tick = 2,
        .deadline_tick = 20,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;

    try std.testing.expectEqual(@as(usize, 2), scheduler.acceleratorClaimQueueDepth(.gpu));
    const granted_batch = scheduler.grantNextAcceleratorClaim(.gpu, 20).?;
    try std.testing.expectEqual(batch_claim, granted_batch.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.batch_compute));
    try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(.foreground_interactive));

    const granted_foreground = scheduler.grantNextAcceleratorClaim(.gpu, 21).?;
    try std.testing.expectEqual(foreground_claim, granted_foreground.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));
}

test "userspace scheduler requires complete hardware telemetry before waking hardware queues" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceState(.{
        .gpu_available = false,
        .media_available = false,
    });

    const image = try schedulerTestUserspaceImage(false);
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 20 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 2,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .media_export,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 20,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.media-required",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(task.id, .{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }, true));

    try std.testing.expect(!scheduler.runNext(1));
    const denied_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), denied_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), scheduler.accountingForSlot(denied_slot).denied_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.accelerator_unavailable, scheduler.accountingForSlot(denied_slot).last_dispatch_reason);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDenialCount(.media));
    try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(.media_export));
    try std.testing.expect(!scheduler.hasDispatchableTasks(1));

    scheduler.configureResourceState(.{ .media_available = true });
    try std.testing.expect(!scheduler.runNext(2));
    const synthetic_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), synthetic_slot.dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDenialCount(.media));

    scheduler.configureResourceTelemetry(.{
        .source = .emulator,
        .observed_tick = 1,
        .media_available = true,
    });
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expect(!scheduler.runNext(2));
    const emulator_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), emulator_slot.dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 2,
        .media_available = true,
    });
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expect(!scheduler.resource_hardware_evidence_complete);
    try std.testing.expect(!scheduler.runNext(2));
    const partial_hardware_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), partial_hardware_slot.dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    var provider = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(2, 20, 3, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(512),
        .status = .{
            .gpu_driver_online = false,
            .npu_driver_online = false,
        },
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expect(scheduler.hasDispatchableTasks(3));
    try std.testing.expect(!scheduler.runNext(3));
    const dispatched_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, scheduler.accountingForSlot(dispatched_slot).last_dispatch_engine);
    try std.testing.expect(scheduler.accountingForSlot(dispatched_slot).last_dispatch_zero_copy);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDispatchCount(.media));
}

test "userspace scheduler ignores stale observed telemetry samples" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 10,
        .gpu_available = false,
        .npu_available = false,
        .media_available = false,
        .grid_carbon_intensity_grams_per_kwh = 500,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 9,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .grid_carbon_intensity_grams_per_kwh = 100,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    try std.testing.expectEqual(@as(u64, 10), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(!scheduler.resource_state.gpu_available);
    try std.testing.expect(!scheduler.resource_state.npu_available);
    try std.testing.expectEqual(@as(u16, 500), scheduler.resource_state.grid_carbon_intensity_grams_per_kwh);

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 11,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .grid_carbon_intensity_grams_per_kwh = 100,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    try std.testing.expectEqual(@as(u64, 11), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(scheduler.resource_state.gpu_available);
    try std.testing.expectEqual(@as(u16, 100), scheduler.resource_state.grid_carbon_intensity_grams_per_kwh);
}

test "userspace scheduler delays on memory bandwidth before npu dispatch" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceState(.{
        .memory_bandwidth_units = 1,
        .npu_available = true,
    });

    const image = try schedulerTestUserspaceImage(false);
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 21 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 2,
            .memory_bytes = units.kibibytes(128),
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .batch_compute,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 21,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.npu-batch",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(task.id, .{
        .class = .batch_compute,
        .wants_npu = true,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
        .memory_bandwidth_units = 256,
    }, false));

    try std.testing.expect(!scheduler.runNext(1));
    const delayed_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), delayed_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), scheduler.accountingForSlot(delayed_slot).delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.memory_bandwidth, scheduler.accountingForSlot(delayed_slot).last_dispatch_reason);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.batch_compute));

    var provider = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(3, 21, 2, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.mebibytes(1),
        .status = .{
            .gpu_driver_online = false,
            .media_driver_online = false,
        },
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expect(!scheduler.runNext(2));
    const dispatched_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, scheduler.accountingForSlot(dispatched_slot).last_dispatch_engine);
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDispatchCount(.npu));
}

test "userspace scheduler does not defer batch tasks for carbon intensity" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceState(.{
        .npu_available = true,
        .grid_carbon_intensity_grams_per_kwh = 620,
    });

    const task = try createRunnableSchedulerTask(
        &runtime,
        221,
        .batch_compute,
        "carbon-batch",
        "app.example.carbon-batch",
        null,
    );
    try std.testing.expect(scheduler.registerTask(task.id));

    try std.testing.expect(!scheduler.runNext(1));
    const dispatched_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 0), scheduler.accountingForSlot(dispatched_slot).delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.cpu, scheduler.accountingForSlot(dispatched_slot).last_dispatch_engine);
}

test "userspace scheduler applies thermal and battery decisions to live dispatch" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    const foreground_image = try schedulerTestUserspaceImage(false);
    const foreground = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 22 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .foreground_interactive,
        },
        .ui_surface_id = 4,
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 22,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.thermal-ui",
        },
        .userspace_image = &foreground_image,
    });
    try std.testing.expect(scheduler.registerTask(foreground.id));
    var provider = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(22, 220, 101, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(512),
        .thermal_milli_celsius = 91_000,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expectEqual(accelerator_scheduler.TelemetrySource.hardware, scheduler.resource_telemetry_source);
    try std.testing.expectEqual(@as(u64, 101), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(!scheduler.runNext(1));
    const foreground_slot = scheduler.slots.getConst(foreground.id).?;
    try std.testing.expectEqual(@as(u64, 1), foreground_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, scheduler.accountingForSlot(foreground_slot).last_dispatch_engine);
    try std.testing.expect(scheduler.accountingForSlot(foreground_slot).last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, scheduler.accountingForSlot(foreground_slot).last_dispatch_reason);

    const media_image = try schedulerTestUserspaceImage(false);
    const media_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 23 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 2,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .media_export,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 23,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.battery-media",
        },
        .userspace_image = &media_image,
    });
    try std.testing.expect(scheduler.registerTask(media_task.id));
    try provider.observeLive(220, 102, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(512),
        .thermal_milli_celsius = 45_000,
        .battery_percent = 15,
        .status = .{ .battery_charging = false },
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expectEqual(@as(u64, 102), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(!scheduler.runNext(2));
    const media_slot = scheduler.slots.getConst(media_task.id).?;
    try std.testing.expectEqual(@as(u64, 1), media_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, scheduler.accountingForSlot(media_slot).last_dispatch_engine);
    try std.testing.expect(scheduler.accountingForSlot(media_slot).last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.battery_preserve, scheduler.accountingForSlot(media_slot).last_dispatch_reason);
}

test "userspace scheduler applies booted live telemetry across every resource class" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const critical = try createRunnableSchedulerTask(&runtime, 30, .emergency_system_critical, "critical", "svc.example.critical", null);
    const foreground = try createRunnableSchedulerTask(&runtime, 31, .foreground_interactive, "foreground", "app.example.foreground-live", 31);
    const media = try createRunnableSchedulerTask(&runtime, 32, .media_export, "media", "app.example.media-live", null);
    const background = try createRunnableSchedulerTask(&runtime, 33, .background_light, "background", "app.example.background-live", null);
    const batch = try createRunnableSchedulerTask(&runtime, 34, .batch_compute, "batch", "app.example.batch-live", null);

    const task_ids = [_]u64{ critical.id, foreground.id, media.id, background.id, batch.id };
    for (task_ids) |task_id| {
        try std.testing.expect(scheduler.registerTask(task_id));
    }
    try std.testing.expect(scheduler.configureTaskDispatchRequest(background.id, .{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }, false));

    var provider = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(30, 300, 10, .{
        .total_cpu_budget_ticks = 20_000,
        .memory_capacity_bytes = units.mebibytes(1),
        .thermal_milli_celsius = 91_000,
        .battery_percent = 80,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());

    try std.testing.expect(!scheduler.runNext(10));
    const critical_slot = scheduler.slots.getConst(critical.id).?;
    try std.testing.expectEqual(@as(u64, 1), critical_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.normal, scheduler.accountingForSlot(critical_slot).last_dispatch_reason);

    try std.testing.expect(!scheduler.runNext(11));
    const foreground_slot = scheduler.slots.getConst(foreground.id).?;
    try std.testing.expectEqual(@as(u64, 1), foreground_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, scheduler.accountingForSlot(foreground_slot).last_dispatch_engine);
    try std.testing.expect(scheduler.accountingForSlot(foreground_slot).last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, scheduler.accountingForSlot(foreground_slot).last_dispatch_reason);

    try std.testing.expect(!scheduler.runNext(12));
    const media_slot = scheduler.slots.getConst(media.id).?;
    try std.testing.expectEqual(@as(u64, 1), media_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, scheduler.accountingForSlot(media_slot).last_dispatch_engine);
    try std.testing.expect(scheduler.accountingForSlot(media_slot).last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, scheduler.accountingForSlot(media_slot).last_dispatch_reason);

    try std.testing.expect(!scheduler.runNext(13));
    const thermally_blocked_background = scheduler.slots.getConst(background.id).?;
    const thermally_blocked_batch = scheduler.slots.getConst(batch.id).?;
    try std.testing.expectEqual(@as(u64, 0), thermally_blocked_background.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), scheduler.accountingForSlot(thermally_blocked_background).delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, scheduler.accountingForSlot(thermally_blocked_background).last_dispatch_reason);
    try std.testing.expectEqual(@as(u64, 0), thermally_blocked_batch.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), scheduler.accountingForSlot(thermally_blocked_batch).delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, scheduler.accountingForSlot(thermally_blocked_batch).last_dispatch_reason);

    try provider.observeLive(300, 14, .{
        .total_cpu_budget_ticks = 20_000,
        .memory_capacity_bytes = units.mebibytes(1),
        .thermal_milli_celsius = 45_000,
        .battery_percent = 12,
        .status = .{
            .battery_charging = false,
            .privacy_sensitive_task_present = true,
        },
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());

    try std.testing.expect(!scheduler.runNext(14));
    const privacy_limited_background = scheduler.slots.getConst(background.id).?;
    try std.testing.expectEqual(@as(u64, 1), privacy_limited_background.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.cpu, scheduler.accountingForSlot(privacy_limited_background).last_dispatch_engine);
    try std.testing.expect(scheduler.accountingForSlot(privacy_limited_background).last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.privacy_mode, scheduler.accountingForSlot(privacy_limited_background).last_dispatch_reason);

    try std.testing.expect(!scheduler.runNext(15));
    const battery_blocked_batch = scheduler.slots.getConst(batch.id).?;
    try std.testing.expectEqual(@as(u64, 0), battery_blocked_batch.dispatch_count);
    try std.testing.expectEqual(@as(u64, 2), scheduler.accountingForSlot(battery_blocked_batch).delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.battery_preserve, scheduler.accountingForSlot(battery_blocked_batch).last_dispatch_reason);

    try provider.observeLive(300, 16, .{
        .total_cpu_budget_ticks = 20_000,
        .memory_capacity_bytes = units.mebibytes(1),
        .thermal_milli_celsius = 45_000,
        .battery_percent = 80,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());

    try std.testing.expect(!scheduler.runNext(16));
    const batch_slot = scheduler.slots.getConst(batch.id).?;
    try std.testing.expectEqual(@as(u64, 1), batch_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, scheduler.accountingForSlot(batch_slot).last_dispatch_engine);
}

test "userspace scheduler sustained load gate bounds background and batch starvation" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .cpu_budget_ticks = DISPATCH_CPU_TICK_COST * 256,
        .memory_bandwidth_units = 1024,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const foreground = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        240,
        .foreground_interactive,
        "sustained-foreground",
        "app.example.sustained-foreground",
        240,
        DISPATCH_CPU_TICK_COST * 160,
    );
    const background = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        241,
        .background_light,
        "sustained-background",
        "app.example.sustained-background",
        null,
        DISPATCH_CPU_TICK_COST * 8,
    );
    const batch = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        242,
        .batch_compute,
        "sustained-batch",
        "app.example.sustained-batch",
        null,
        DISPATCH_CPU_TICK_COST * 8,
    );

    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.registerTask(background.id));
    try std.testing.expect(scheduler.registerTask(batch.id));

    var first_background_dispatch_tick: u64 = 0;
    var first_batch_dispatch_tick: u64 = 0;
    var now_ticks: u64 = userspace_executor.DISPATCH_QUANTUM_TICKS;
    while (now_ticks <= BATCH_DEADLINE_DELTA_TICKS + userspace_executor.DISPATCH_QUANTUM_TICKS * 2) : (now_ticks += userspace_executor.DISPATCH_QUANTUM_TICKS) {
        _ = scheduler.runNext(now_ticks);
        const background_stats = scheduler.taskDispatchStats(background.id).?;
        const batch_stats = scheduler.taskDispatchStats(batch.id).?;
        if (first_background_dispatch_tick == 0 and background_stats.dispatch_count != 0) {
            first_background_dispatch_tick = background_stats.last_dispatch_tick;
        }
        if (first_batch_dispatch_tick == 0 and batch_stats.dispatch_count != 0) {
            first_batch_dispatch_tick = batch_stats.last_dispatch_tick;
        }
    }

    const foreground_stats = scheduler.taskDispatchStats(foreground.id).?;
    const background_stats = scheduler.taskDispatchStats(background.id).?;
    const batch_stats = scheduler.taskDispatchStats(batch.id).?;
    try std.testing.expect(foreground_stats.dispatch_count > background_stats.dispatch_count);
    try std.testing.expect(background_stats.dispatch_count > 0);
    try std.testing.expect(batch_stats.dispatch_count > 0);
    try std.testing.expect(first_background_dispatch_tick <= BACKGROUND_DEADLINE_DELTA_TICKS);
    try std.testing.expect(first_batch_dispatch_tick <= BATCH_DEADLINE_DELTA_TICKS + userspace_executor.DISPATCH_QUANTUM_TICKS);
    try std.testing.expectEqual(@as(u64, 0), background_stats.missed_deadline_count);
    try std.testing.expectEqual(@as(u64, 0), batch_stats.missed_deadline_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, batch_stats.last_dispatch_engine);
}

test "userspace scheduler bounds lower class starvation despite coalesced wakes" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .cpu_budget_ticks = DISPATCH_CPU_TICK_COST * 256,
        .memory_bandwidth_units = 1024,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    const foreground = try createRunnableSchedulerTaskWithBudget(&runtime, 243, .foreground_interactive, "coalesced-foreground", "app.coalesced-foreground", 243, DISPATCH_CPU_TICK_COST * 160);
    const background = try createRunnableSchedulerTask(&runtime, 244, .background_light, "coalesced-background", "app.coalesced-background", null);
    const batch = try createRunnableSchedulerTask(&runtime, 245, .batch_compute, "coalesced-batch", "app.coalesced-batch", null);
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.registerTask(background.id));
    try std.testing.expect(scheduler.registerTask(batch.id));
    var first_background_dispatch_tick: u64 = 0;
    var first_batch_dispatch_tick: u64 = 0;
    var now_ticks: u64 = userspace_executor.DISPATCH_QUANTUM_TICKS;
    while (now_ticks <= BATCH_DEADLINE_DELTA_TICKS + userspace_executor.DISPATCH_QUANTUM_TICKS * 2) : (now_ticks += userspace_executor.DISPATCH_QUANTUM_TICKS) {
        if (first_background_dispatch_tick == 0) try std.testing.expect(scheduler.wakeTask(background.id, .ipc_message, now_ticks, 0));
        if (first_batch_dispatch_tick == 0) try std.testing.expect(scheduler.wakeTask(batch.id, .ipc_message, now_ticks, 0));
        _ = scheduler.runNext(now_ticks);
        const background_stats = scheduler.taskDispatchStats(background.id).?;
        const batch_stats = scheduler.taskDispatchStats(batch.id).?;
        if (first_background_dispatch_tick == 0 and background_stats.dispatch_count != 0) first_background_dispatch_tick = background_stats.last_dispatch_tick;
        if (first_batch_dispatch_tick == 0 and batch_stats.dispatch_count != 0) first_batch_dispatch_tick = batch_stats.last_dispatch_tick;
    }
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(background.id).?.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(batch.id).?.dispatch_count);
    try std.testing.expect(first_background_dispatch_tick <= BACKGROUND_DEADLINE_DELTA_TICKS);
    try std.testing.expect(first_batch_dispatch_tick <= BATCH_DEADLINE_DELTA_TICKS + userspace_executor.DISPATCH_QUANTUM_TICKS);
}

test "userspace scheduler foreground wall-time deadline bounds an expired lower-class backlog" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .cpu_budget_ticks = DISPATCH_CPU_TICK_COST * 64,
        .memory_bandwidth_units = 1024,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    var lower_ids: [4]u64 = undefined;
    for (&lower_ids, 0..) |*task_id, index| {
        const class: accelerator_scheduler.ResourceClass = if (index < 2) .background_light else .batch_compute;
        const task = try createRunnableSchedulerTaskWithBudget(&runtime, 260 + index, class, "expired-lower", "app.expired-lower", null, DISPATCH_CPU_TICK_COST * 2);
        task_id.* = task.id;
        try std.testing.expect(scheduler.registerTaskAt(task.id, 0));
    }
    const foreground = try createRunnableSchedulerTaskWithBudget(&runtime, 264, .foreground_interactive, "new-foreground", "app.new-foreground", 264, DISPATCH_CPU_TICK_COST * 16);
    const start: u64 = 1000;
    try std.testing.expect(scheduler.registerTaskAt(foreground.id, start));
    try std.testing.expect(scheduler.parkTaskUntilEvent(foreground.id));
    try std.testing.expect(scheduler.wakeTask(foreground.id, .ipc_message, start, 0));
    const quantum = userspace_executor.DISPATCH_QUANTUM_TICKS;
    var first_foreground: ?u64 = null;
    var now = start;
    while (now <= start + quantum * 8) : (now += quantum) {
        _ = scheduler.runNext(now);
        const foreground_stats = scheduler.taskDispatchStats(foreground.id).?;
        if (first_foreground == null and foreground_stats.dispatch_count != 0) first_foreground = foreground_stats.last_dispatch_tick;
    }
    try std.testing.expect(first_foreground != null);
    try std.testing.expect(first_foreground.? - start <= units.millisecondsToTimerTicksCeil(50) + quantum);
    // Foreground urgency does not discard the already-aged lower work.
    for (lower_ids) |task_id| try std.testing.expect(scheduler.taskDispatchStats(task_id).?.dispatch_count != 0);
}

test "userspace scheduler aging deadlines use timer units and saturate" {
    try std.testing.expectEqual(@as(u64, 1), deadlineFromNow(.emergency_system_critical, 0));
    try std.testing.expectEqual(@as(u64, 5), deadlineFromNow(.foreground_interactive, 0));
    try std.testing.expectEqual(@as(u64, 20), deadlineFromNow(.media_export, 0));
    try std.testing.expectEqual(@as(u64, 50), deadlineFromNow(.background_light, 0));
    try std.testing.expectEqual(@as(u64, 100), deadlineFromNow(.batch_compute, 0));
    try std.testing.expectEqual(@as(u64, 152), deadlineAfterDispatch(.background_light, 100));
    inline for (std.enums.values(accelerator_scheduler.ResourceClass)) |class| {
        try std.testing.expectEqual(std.math.maxInt(u64), deadlineFromNow(class, std.math.maxInt(u64) - 1));
        try std.testing.expectEqual(std.math.maxInt(u64), deadlineAfterDispatch(class, std.math.maxInt(u64) - 1));
    }
}

test "userspace scheduler late registration ages from the current timer tick" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    const task = try createRunnableSchedulerTask(&runtime, 256, .background_light, "late-background", "app.late-background", null);
    const now: u64 = 100_000;
    try std.testing.expect(scheduler.registerTaskAt(task.id, now));
    const slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(now + 50, slot.deadline_tick);
    try std.testing.expectEqual(now, scheduler.taskDispatchStats(task.id).?.last_wake_tick);
    try std.testing.expect(scheduler.wakeTask(task.id, .ipc_message, now + 1, 0));
    try std.testing.expectEqual(now + 50, slot.deadline_tick);
    try std.testing.expect(scheduler.parkTaskUntilEvent(task.id));
    try std.testing.expect(scheduler.unregisterTask(task.id));
    try std.testing.expect(scheduler.registerTaskAt(task.id, std.math.maxInt(u64) - 1));
    try std.testing.expectEqual(std.math.maxInt(u64), scheduler.slots.getConst(task.id).?.deadline_tick);
}

test "userspace scheduler wall-time aging bounds initial and repeated lower-class service" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .cpu_budget_ticks = DISPATCH_CPU_TICK_COST * 512,
        .memory_bandwidth_units = 4096,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    const foreground = try createRunnableSchedulerTaskWithBudget(&runtime, 253, .foreground_interactive, "wall-time-foreground", "app.wall-time-foreground", 253, DISPATCH_CPU_TICK_COST * 512);
    const background = try createRunnableSchedulerTaskWithBudget(&runtime, 254, .background_light, "wall-time-background", "app.wall-time-background", null, DISPATCH_CPU_TICK_COST * 16);
    const batch = try createRunnableSchedulerTaskWithBudget(&runtime, 255, .batch_compute, "wall-time-batch", "app.wall-time-batch", null, DISPATCH_CPU_TICK_COST * 16);
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.registerTask(background.id));
    try std.testing.expect(scheduler.registerTask(batch.id));

    const quantum = userspace_executor.DISPATCH_QUANTUM_TICKS;
    const background_wait = units.millisecondsToTimerTicksCeil(500);
    const batch_wait = units.millisecondsToTimerTicksCeil(1000);
    var first_background: u64 = 0;
    var first_batch: u64 = 0;
    var previous_background: u64 = 0;
    var previous_batch: u64 = 0;
    var max_background_gap: u64 = 0;
    var max_batch_gap: u64 = 0;
    var now: u64 = quantum;
    while (now <= units.millisecondsToTimerTicksCeil(3000)) : (now += quantum) {
        // Foreground traffic stays ready. Lower classes receive coalesced
        // wakes before their first service, then remain ready without new
        // events: their requeue deadlines must age in wall time too.
        try std.testing.expect(scheduler.wakeTask(foreground.id, .ipc_message, now, 0));
        if (first_background == 0) try std.testing.expect(scheduler.wakeTask(background.id, .ipc_message, now, 0));
        if (first_batch == 0) try std.testing.expect(scheduler.wakeTask(batch.id, .ipc_message, now, 0));
        _ = scheduler.runNext(now);
        const background_tick = scheduler.taskDispatchStats(background.id).?.last_dispatch_tick;
        const batch_tick = scheduler.taskDispatchStats(batch.id).?.last_dispatch_tick;
        if (background_tick != previous_background) {
            if (first_background == 0) first_background = background_tick;
            if (previous_background != 0) max_background_gap = @max(max_background_gap, background_tick - previous_background);
            previous_background = background_tick;
        }
        if (batch_tick != previous_batch) {
            if (first_batch == 0) first_batch = batch_tick;
            if (previous_batch != 0) max_batch_gap = @max(max_batch_gap, batch_tick - previous_batch);
            previous_batch = batch_tick;
        }
    }
    try std.testing.expect(first_background != 0);
    try std.testing.expect(first_batch != 0);
    try std.testing.expect(first_background <= background_wait + quantum);
    try std.testing.expect(first_batch <= batch_wait + quantum * 2);
    try std.testing.expect(scheduler.taskDispatchStats(background.id).?.dispatch_count >= 4);
    try std.testing.expect(scheduler.taskDispatchStats(batch.id).?.dispatch_count >= 2);
    // A completed quantum receives one quantum of slack before aging again;
    // another expired class can take one quantum before this one is selected.
    try std.testing.expect(max_background_gap <= background_wait + quantum * 3);
    try std.testing.expect(max_batch_gap <= batch_wait + quantum * 3);
    try std.testing.expect(scheduler.taskDispatchStats(foreground.id).?.dispatch_count > scheduler.taskDispatchStats(background.id).?.dispatch_count);
}

test "userspace scheduler breaks expired lower-class ties by service debt" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .npu_available = true,
        .cpu_budget_ticks = DISPATCH_CPU_TICK_COST * 16,
        .memory_bandwidth_units = 1024,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const background = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        250,
        .background_light,
        "tie-background",
        "app.example.tie-background",
        null,
        DISPATCH_CPU_TICK_COST * 2,
    );
    const batch = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        251,
        .batch_compute,
        "tie-batch",
        "app.example.tie-batch",
        null,
        DISPATCH_CPU_TICK_COST * 2,
    );

    try std.testing.expect(scheduler.registerTask(background.id));
    try std.testing.expect(scheduler.registerTask(batch.id));
    try std.testing.expect(scheduler.wakeTask(background.id, .timer, 10, 20));
    try std.testing.expect(scheduler.wakeTask(batch.id, .timer, 10, 100));

    try std.testing.expect(!scheduler.runNext(20));
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(background.id).?.dispatch_count);
    try std.testing.expectEqual(@as(u64, 0), scheduler.taskDispatchStats(batch.id).?.dispatch_count);

    try std.testing.expect(scheduler.wakeTask(background.id, .timer, 21, 30));
    try std.testing.expect(scheduler.wakeTask(batch.id, .timer, 21, 30));
    try std.testing.expect(!scheduler.runNext(30));

    const background_stats = scheduler.taskDispatchStats(background.id).?;
    const batch_stats = scheduler.taskDispatchStats(batch.id).?;
    try std.testing.expectEqual(@as(u64, 1), background_stats.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), batch_stats.dispatch_count);
    try std.testing.expectEqual(@as(u64, 0), batch_stats.missed_deadline_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, batch_stats.last_dispatch_engine);
}

test "userspace scheduler thermal pressure gates batch queues without scanning task slots" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const image = try schedulerTestUserspaceImage(false);
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 7 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
            .resource_class = .batch_compute,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 7,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.batch",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    scheduler.configureResourceState(.{ .thermal_pressure = .critical });
    try std.testing.expect(!scheduler.runNext(10));
    try std.testing.expectEqual(@as(u64, 0), scheduler.slots.getConst(task.id).?.dispatch_count);

    scheduler.configureResourceState(.{ .thermal_pressure = .nominal });
    try std.testing.expect(!scheduler.runNext(11));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(task.id).?.dispatch_count);
}

test "userspace scheduler stops dispatching tasks after their cpu budget is consumed" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const image = try schedulerTestUserspaceImage(false);
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 1,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.budgeted",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(!scheduler.runNext(1));
    const slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), slot.dispatch_count);
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST, scheduler.accountingForSlot(slot).cpu_ticks_consumed);

    try std.testing.expect(!scheduler.runNext(2));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(task.id).?.dispatch_count);
}

test "policy blocked queues can idle and become dispatchable when policy changes" {
    for ([_]accelerator_scheduler.ResourceClass{ .batch_compute, .background_light }) |class| {
        var executor = userspace_executor.Executor{};
        var scheduler = Scheduler.init(&executor);
        defer scheduler.deinit();
        var catalog = userspace_loader.Catalog.init();
        var runtime = task_runtime.Runtime.init();
        var capabilities = capability.CapabilityTable.init();
        scheduler.bind(&catalog, &runtime, &capabilities);
        const task = try createRunnableSchedulerTask(&runtime, 601, class, "deferred", "app.example.deferred", null);
        try std.testing.expect(scheduler.registerTask(task.id));
        try std.testing.expect(scheduler.hasDispatchableTasks(1));
        scheduler.configureResourceState(if (class == .batch_compute)
            .{ .battery_saver = true }
        else
            .{ .thermal_pressure = .critical });

        try std.testing.expect(scheduler.hasReadyTasks());
        try std.testing.expect(!scheduler.hasDispatchableTasks(10));
        try std.testing.expect(!scheduler.runNext(10));
        const deadline = scheduler.slots.getConst(task.id).?.deadline_tick;
        try std.testing.expect(!scheduler.hasDispatchableTasks(deadline + 1));
        try std.testing.expect(!scheduler.runNext(deadline + 1));
        try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(class));
        try std.testing.expectEqual(@as(u64, 0), scheduler.taskDispatchStats(task.id).?.dispatch_count);

        scheduler.configureResourceState(.{});
        try std.testing.expect(scheduler.hasDispatchableTasks(deadline + 2));
        _ = scheduler.runNext(deadline + 2);
        try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(task.id).?.dispatch_count);
        _ = scheduler.runNext(deadline + 3);
        try std.testing.expect(!scheduler.hasReadyTasks());
        try std.testing.expect(!scheduler.hasDispatchableTasks(deadline + 3));
    }
}

test "request delayed heads preserve their place without blocking runnable tasks or idle" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    const deferred = try createRunnableSchedulerTask(&runtime, 611, .foreground_interactive, "deferred", "app.example.deferred", null);
    const foreground = try createRunnableSchedulerTask(&runtime, 612, .foreground_interactive, "foreground", "app.example.foreground", null);
    const media = try createRunnableSchedulerTask(&runtime, 613, .media_export, "media", "app.example.media", null);
    for ([_]u64{ deferred.id, foreground.id, media.id }) |id| try std.testing.expect(scheduler.registerTask(id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(deferred.id, .{
        .class = .foreground_interactive,
        .expected_cpu_ticks = 8_000,
    }, false));
    scheduler.configureResourceState(.{ .cpu_budget_ticks = 4_000 });
    const original_head = scheduler.ready_heads[resourceClassIndex(.foreground_interactive)];

    try std.testing.expect(scheduler.hasDispatchableTasks(1));
    _ = scheduler.runNext(1);
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(foreground.id).?.dispatch_count);
    try std.testing.expectEqual(original_head, scheduler.ready_heads[resourceClassIndex(.foreground_interactive)]);
    _ = scheduler.runNext(2);
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(media.id).?.dispatch_count);
    _ = scheduler.runNext(3);
    try std.testing.expect(scheduler.hasReadyTasks());
    try std.testing.expect(!scheduler.hasDispatchableTasks(3));
    try std.testing.expect(!scheduler.hasReadyLatencySensitiveWork());
    try std.testing.expectEqual(@as(u64, 0), scheduler.taskDispatchStats(deferred.id).?.dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));

    scheduler.configureResourceState(.{ .cpu_budget_ticks = 8_000 });
    try std.testing.expect(scheduler.hasDispatchableTasks(4));
    _ = scheduler.runNext(4);
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(deferred.id).?.dispatch_count);
}

test "task reclamation scheduler pressure releases parked slots and accelerator claims" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer runtime.reset();
    defer scheduler.deinit();
    var first_id: u64 = 0;
    for (0..task_runtime.MAX_TASKS * 3) |index| {
        const task = try createRunnableSchedulerTask(&runtime, @intCast(index + 1), .background_light, "churn", "app.churn", null);
        const task_id = task.id;
        if (index == 0) first_id = task_id;
        try std.testing.expect(scheduler.registerTask(task_id));
        try std.testing.expect(scheduler.parkTaskUntilEvent(task_id));
        try std.testing.expect(scheduler.enqueueAcceleratorClaim(.{
            .task_id = task_id,
            .engine = .gpu,
            .resource_class = .background_light,
            .requested_at_tick = @intCast(index),
        }) != null);
        try std.testing.expect(runtime.terminateResolvedTask(task, @intCast(index)));
        try std.testing.expect(scheduler.slots.countInUse() <= task_runtime.MAX_TASKS);
        try std.testing.expect(scheduler.acceleratorClaimQueueDepth(.gpu) <= task_runtime.MAX_TASKS);
    }
    try std.testing.expect(runtime.find(first_id) == null);
    try std.testing.expect(scheduler.taskDispatchStats(first_id) == null);
    const live = try createRunnableSchedulerTask(&runtime, 1001, .background_light, "live", "app.live", null);
    try std.testing.expect(scheduler.registerTask(live.id));
    try std.testing.expectEqual(@as(usize, 1), scheduler.slots.countInUse());
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.background_light));
}

test "task reclamation scheduler skips terminal accelerator claims before granting live work" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer runtime.reset();
    defer scheduler.deinit();
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    const terminal = try createRunnableSchedulerTask(&runtime, 1, .foreground_interactive, "terminal", "app.terminal", null);
    const terminal_id = terminal.id;
    const live = try createRunnableSchedulerTask(&runtime, 2, .background_light, "live", "app.live", null);
    try std.testing.expect(scheduler.registerTask(terminal_id));
    try std.testing.expect(scheduler.registerTask(live.id));
    _ = scheduler.enqueueAcceleratorClaim(.{ .task_id = terminal_id, .engine = .gpu, .resource_class = .foreground_interactive, .requested_at_tick = 1 }).?;
    const live_claim = scheduler.enqueueAcceleratorClaim(.{ .task_id = live.id, .engine = .gpu, .resource_class = .background_light, .requested_at_tick = 2 }).?;
    try std.testing.expect(runtime.terminateResolvedTask(terminal, 3));
    const granted = scheduler.grantNextAcceleratorClaim(.gpu, 4).?;
    try std.testing.expectEqual(live_claim, granted.id);
    try std.testing.expectEqual(live.id, granted.task_id);
    try std.testing.expect(scheduler.taskDispatchStats(terminal_id) == null);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));
}

test "task reclamation scheduler dispatch callbacks preserve slot through reentrant registration and handoff" {
    const Dispatcher = struct {
        scheduler: *Scheduler,
        runtime: *task_runtime.Runtime,
        task_ids: *const [task_runtime.MAX_TASKS]u64,
        calls: usize = 0,

        fn executePreparedTask(self: *@This(), task: *const task_runtime.TaskRecord, mapping_handle: *userspace_executor.MappingHandle, _: u64) dispatch_ownership.ReturnRecord {
            const task_id = task.id;
            const task_handle = self.runtime.taskHandleForResolved(task);
            const slot = self.scheduler.slots.get(task_id).?;
            const original_mapping = mapping_handle.*;
            if (!(self.runtime.terminateTask(task_id, 0) catch false)) @panic("task reclamation fixture invariant failed");
            if (!(!self.scheduler.unregisterTask(task_id))) @panic("task reclamation fixture invariant failed");
            if (!(!self.scheduler.registerTask(task_id))) @panic("task reclamation fixture invariant failed");
            if (!(!self.scheduler.runNext(0))) @panic("task reclamation fixture invariant failed");
            if (!(self.scheduler.executeTask(self.task_ids[1], 0) == .unavailable)) @panic("task reclamation fixture invariant failed");
            for (self.task_ids[1..], 1..) |id, index| if (!(self.runtime.terminateTask(id, @intCast(index)) catch false)) @panic("task reclamation fixture invariant failed");
            for (0..task_runtime.MAX_TASKS + 3) |index| {
                const replacement = createRunnableSchedulerTask(self.runtime, @intCast(index + 1000), .background_light, "replacement", "app.replacement", null) catch @panic("dispatch callback retains launch capacity");
                if (!(self.scheduler.registerTask(replacement.id))) @panic("task reclamation fixture invariant failed");
                if (!(self.runtime.terminateResolvedTask(replacement, @intCast(index + 1000)))) @panic("task reclamation fixture invariant failed");
                if (!(self.scheduler.slots.get(task_id).? == slot)) @panic("task reclamation fixture invariant failed");
                if (!(&self.scheduler.slots.get(task_id).?.mapping_handle == mapping_handle)) @panic("task reclamation fixture invariant failed");
                if (!(mapping_handle.eql(original_mapping))) @panic("task reclamation fixture invariant failed");
                if (!(self.runtime.findByHandle(task_handle, task_id).? == task)) @panic("task reclamation fixture invariant failed");
            }
            self.calls += 1;
            return .{ .outcome = .yielded };
        }
    };
    for ([_]bool{ false, true }) |direct| {
        var executor = userspace_executor.Executor{};
        var scheduler = Scheduler.init(&executor);
        var catalog = userspace_loader.Catalog.init();
        var runtime = task_runtime.Runtime.init();
        var capabilities = capability.CapabilityTable.init();
        scheduler.bind(&catalog, &runtime, &capabilities);
        defer runtime.reset();
        defer scheduler.deinit();
        var task_ids: [task_runtime.MAX_TASKS]u64 = undefined;
        for (&task_ids, 0..) |*id, index| {
            const task = try createRunnableSchedulerTask(&runtime, @intCast(index + 1), .background_light, "dispatch", "app.dispatch", null);
            id.* = task.id;
            try std.testing.expect(scheduler.registerTask(task.id));
        }
        const task = runtime.find(task_ids[0]).?;
        const handle = runtime.taskHandleForResolved(task);
        var dispatcher = Dispatcher{ .scheduler = &scheduler, .runtime = &runtime, .task_ids = &task_ids };
        if (direct) {
            try std.testing.expectEqual(userspace_executor.ExecutionOutcome.yielded, scheduler.executeTaskWithDispatch(task_ids[0], 1, &dispatcher).outcome);
        } else {
            try std.testing.expect(scheduler.runNextWithDispatch(1, &dispatcher));
        }
        try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
        try std.testing.expectEqual(@as(u64, 0), scheduler.active_dispatch_task_id);
        try std.testing.expect(scheduler.slots.get(task_ids[0]) == null);
        _ = try createRunnableSchedulerTask(&runtime, 9999, .background_light, "after-handoff", "app.after-handoff", null);
        try std.testing.expect(runtime.findByHandle(handle, task_ids[0]) == null);
    }
}

test "userspace quantum bounds every class and direct unregistered dispatch through actual callbacks" {
    const Dispatcher = struct {
        scheduler: *Scheduler,
        calls: usize = 0,
        fn executePreparedTask(self: *@This(), task: *const task_runtime.TaskRecord, _: *userspace_executor.MappingHandle, now: u64) dispatch_ownership.ReturnRecord {
            const quantum = userspace_executor.DispatchQuantum.begin(task.id, now);
            if (quantum.expired(task.id, now + userspace_executor.DISPATCH_QUANTUM_TICKS - 1))
                @panic("dispatch quantum must preserve its bounded interval");
            if (!quantum.expired(task.id, now + userspace_executor.DISPATCH_QUANTUM_TICKS))
                @panic("every user dispatch must return to deferred device work");
            if (self.scheduler.shouldPreemptTask(task.id))
                @panic("a solitary task has no earlier priority preemption");
            self.calls += 1;
            return .{ .outcome = .yielded };
        }
    };
    for (resource_priority_order) |class| {
        for ([_]bool{ false, true }) |direct| {
            var executor = userspace_executor.Executor{};
            var scheduler = Scheduler.init(&executor);
            var catalog = userspace_loader.Catalog.init();
            var runtime = task_runtime.Runtime.init();
            var capabilities = capability.CapabilityTable.init();
            scheduler.bind(&catalog, &runtime, &capabilities);
            defer runtime.reset();
            defer scheduler.deinit();
            const task = try createRunnableSchedulerTask(&runtime, 1, class, "bounded", "app.bounded", null);
            var dispatcher = Dispatcher{ .scheduler = &scheduler };
            if (direct) {
                try std.testing.expectEqual(userspace_executor.ExecutionOutcome.yielded, scheduler.executeTaskWithDispatch(task.id, 100, &dispatcher).outcome);
                try std.testing.expect(scheduler.slots.get(task.id) == null);
            } else {
                try std.testing.expect(scheduler.registerTask(task.id));
                try std.testing.expect(scheduler.runNextWithDispatch(100, &dispatcher));
            }
            try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
            try std.testing.expectEqual(@as(u64, 0), scheduler.active_dispatch_task_id);
        }
    }
}

test "scheduler production runtime sink binding rolls back exact ownership before publication" {
    const cpu_identity = @import("../../kernel/cpu_identity.zig");
    const shared_memory = @import("../kernel_api/shared_memory.zig");
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    var executor = userspace_executor.Executor{};
    var foreign_executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var foreign = Scheduler.init(&foreign_executor);
    const ForeignLifetime = struct {
        fn register(_: *anyopaque, _: *shared_memory.Table, _: shared_memory.FreestandingMappingDescriptor, _: bool, _: bool) ?u64 {
            return null;
        }
        fn unregister(_: *anyopaque, _: *shared_memory.Table, _: u64, _: shared_memory.FreestandingMappingDescriptor) bool {
            return false;
        }
    };
    const foreign_lifetime = shared_memory.MappingLifetime{ .context = &foreign, .register = ForeignLifetime.register, .unregister = ForeignLifetime.unregister };
    try std.testing.expect(shared_memory.bindMappedObjectLifetime(foreign_lifetime));
    try std.testing.expect(!scheduler.claimRuntimeOwnership(runtime, true));
    try std.testing.expect(executor.binding_owner == null and executor.bound_runtime == null and executor.registration_cpu == null);
    try std.testing.expect(runtime.address_space_retirement_sink == null and runtime.execution_stop_sink == null);
    try std.testing.expect(shared_memory.mappedObjectLifetimeIsBound(foreign_lifetime));
    try std.testing.expect(shared_memory.unbindMappedObjectLifetime(foreign_lifetime));
    try std.testing.expect(runtime.bindExecutionStopSink(foreign.executionStopSink()));
    // The same production claim path releases only the ownership it acquired;
    // an existing unrelated stop sink survives the failed address-sink claim.
    try std.testing.expect(!scheduler.claimRuntimeOwnership(runtime, true));
    try std.testing.expect(executor.binding_owner == null and executor.bound_runtime == null);
    try std.testing.expect(!scheduler.executor_binding_claimed and !scheduler.initialized);
    try std.testing.expect(runtime.address_space_retirement_sink == null);
    try std.testing.expect(runtime.execution_stop_sink.?.eql(foreign.executionStopSink()));
    try std.testing.expect(runtime.unbindExecutionStopSink(foreign.executionStopSink()));
    try std.testing.expect(scheduler.claimRuntimeOwnership(runtime, true));
    const address_sink = runtime.address_space_retirement_sink.?;
    const stop_sink = runtime.execution_stop_sink.?;
    try std.testing.expect(address_sink.eql(scheduler.addressSpaceRetirementSink()));
    try std.testing.expect(address_sink.context == @as(*anyopaque, &scheduler));
    try std.testing.expect(executor.mappedObjectLifetimeIsBound());
    try std.testing.expect(!foreign.unbindRuntimeSinks(runtime));
    try std.testing.expect(!scheduler.claimRuntimeOwnership(runtime, true));
    try std.testing.expect(runtime.address_space_retirement_sink.?.eql(address_sink));
    try std.testing.expect(runtime.execution_stop_sink.?.eql(stop_sink));
    try std.testing.expect(executor.binding_owner == @as(*const anyopaque, &scheduler) and executor.bound_runtime == runtime);
    executor.binding_owner = &foreign;
    try std.testing.expect(!scheduler.unbindRuntimeSinks(runtime));
    try std.testing.expect(executor.mappedObjectLifetimeIsBound());
    try std.testing.expect(runtime.address_space_retirement_sink.?.eql(address_sink));
    try std.testing.expect(runtime.execution_stop_sink.?.eql(stop_sink));
    executor.binding_owner = &scheduler;
    executor.bound_runtime = null;
    try std.testing.expect(!scheduler.unbindRuntimeSinks(runtime));
    try std.testing.expect(executor.mappedObjectLifetimeIsBound());
    executor.bound_runtime = runtime;
    const ticket = try runtime.execution.prepare(1, .{ .task_handle = 1, .task_id = 7, .process_generation = 1, .address_space_id = 42 });
    try std.testing.expect(!scheduler.unbindRuntimeSinks(runtime));
    try std.testing.expect(!foreign.claimRuntimeOwnership(runtime, true));
    try std.testing.expect(foreign_executor.binding_owner == null and foreign_executor.bound_runtime == null);
    try std.testing.expect(runtime.address_space_retirement_sink.?.eql(address_sink));
    try std.testing.expect(runtime.execution_stop_sink.?.eql(stop_sink));
    try runtime.execution.cancelUnstarted(ticket);
    _ = try runtime.execution.beginCollect(ticket);
    try runtime.execution.finishCollect(ticket);
    runtime.lifecycle_transition_active = true;
    try std.testing.expect(!scheduler.unbindRuntimeSinks(runtime));
    try std.testing.expect(runtime.address_space_retirement_sink.?.eql(address_sink));
    try std.testing.expect(runtime.execution_stop_sink.?.eql(stop_sink));
    runtime.lifecycle_transition_active = false;
    try std.testing.expect(scheduler.unbindRuntimeSinks(runtime));
    try std.testing.expect(runtime.address_space_retirement_sink == null and runtime.execution_stop_sink == null);
    try std.testing.expect(!executor.mappedObjectLifetimeIsBound());
    try std.testing.expect(executor.releaseMappingRegistration(0, &scheduler, runtime));
    try std.testing.expect(executor.releaseRuntimeBinding(&scheduler, runtime));
    scheduler.executor_binding_claimed = false;
}

test "scheduler retirement domain isolates all CPU arenas and preflights complete teardown" {
    const cpu_identity = @import("../../kernel/cpu_identity.zig");
    const native_entry = @import("../../arch/x86_64/native_entry_state.zig");
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    const foreign_runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(foreign_runtime);
    foreign_runtime.* = .{};
    const executors = try std.testing.allocator.alloc(userspace_executor.Executor, cpu_identity.MAX_CPUS);
    defer std.testing.allocator.free(executors);
    for (executors) |*executor| executor.* = .{};
    var scheduler = Scheduler.init(&executors[0]);
    var foreign = Scheduler.init(&executors[14]);
    try std.testing.expect(scheduler.claimRuntimeOwnership(runtime, true));
    scheduler.runtime_ptr = runtime;
    scheduler.initialized = true;
    var domain_active = true;
    defer if (domain_active) scheduler.deinit();
    for (1..executors.len) |index| {
        const owner: *const anyopaque = if (index == 14) &foreign else &scheduler;
        const selected_runtime = if (index == 15) foreign_runtime else runtime;
        try std.testing.expect(executors[index].claimRuntimeBinding(owner, selected_runtime));
        try std.testing.expect(executors[index].claimMappingRegistration(@intCast(index), owner, selected_runtime));
    }
    defer {
        if (!userspace_executor.releaseRegisteredDomain(&foreign, runtime) or
            !userspace_executor.releaseRegisteredDomain(&scheduler, foreign_runtime)) @panic("foreign test domains release their own backing");
    }
    const MappingFixture = struct {
        fn install(executor: *userspace_executor.Executor, address_space_id: u64) !void {
            const index = executor.mappings.reserveIndexAt(address_space_id, 0) orelse return error.UnavailableMappingSlot;
            executor.mappings.slotAt(index).mapping = .{
                .state = .live,
                .address_space_id = address_space_id,
                .dispatch_metadata = .{ .owner_task_id = address_space_id + 1 },
            };
        }
    };
    for (executors) |*executor| try MappingFixture.install(executor, 777);
    var previous_states: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    var canaries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&previous_states, &canaries, 0..) |*previous, *canary, index| {
        const state = native_entry.stateForCpu(@intCast(index));
        previous.* = state.*;
        state.userspace_xstate = 0x1000 + index;
        state.kernel_xstate = 0x2000 + index;
        state.resume_rsp = 0x3000 + index;
        state.resume_rip = 0x4000 + index;
        state.resume_requested = @intCast(index + 1);
        canary.* = state.*;
    }
    defer {
        for (previous_states, 0..) |state, index| native_entry.stateForCpu(@intCast(index)).* = state;
    }
    const ticket = try runtime.execution.prepare(13, .{ .task_handle = 1, .task_id = 2, .process_generation = 1, .address_space_id = 777 });
    try std.testing.expect(!userspace_executor.releaseRegisteredDomain(&scheduler, runtime));
    for (executors) |*executor| try std.testing.expectEqual(@as(usize, 1), executor.materializedCount());
    try std.testing.expect(executors[0].mappedObjectLifetimeIsBound());
    try runtime.execution.cancelUnstarted(ticket);
    _ = try runtime.execution.beginCollect(ticket);
    try runtime.execution.finishCollect(ticket);
    // Equal ASIDs and slot handles in unrelated bindings are intentional. Only
    // the exact Scheduler and Runtime pair may receive this callback.
    scheduler.addressSpaceRetirementSink().notify(.{ .address_space_id = 777, .reason = .terminate });
    for (executors, 0..) |*executor, index| {
        try std.testing.expectEqual(@as(usize, if (index < 14) 0 else 1), executor.materializedCount());
        try std.testing.expectEqualDeep(canaries[index], native_entry.stateForCpu(@intCast(index)).*);
    }
    try MappingFixture.install(&executors[13], 888);
    scheduler.deinit();
    domain_active = false;
    try std.testing.expect(runtime.address_space_retirement_sink == null and runtime.execution_stop_sink == null);
    for (executors, 0..) |*executor, index| {
        if (index < 14) {
            try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
            try std.testing.expect(executor.registration_cpu == null and executor.binding_owner == null and executor.bound_runtime == null);
        } else {
            try std.testing.expectEqual(@as(usize, 1), executor.materializedCount());
            try std.testing.expectEqual(@as(u8, @intCast(index)), executor.registration_cpu.?);
        }
        if (index != 0) try std.testing.expectEqualDeep(canaries[index], native_entry.stateForCpu(@intCast(index)).*);
    }
}

test "scheduler execution leases protect all CPU task slots across scheduler owners" {
    const Dispatcher = struct {
        calls: usize = 0,
        fn executePreparedTask(self: *@This(), _: *const task_runtime.TaskRecord, _: *userspace_executor.MappingHandle, _: u64) dispatch_ownership.ReturnRecord {
            self.calls += 1;
            return .{ .outcome = .yielded };
        }
    };
    const previous_cpu = smp.currentCpuIndex();
    defer smp.setCurrentCpuIndexForTest(previous_cpu);
    smp.setCurrentCpuIndexForTest(0);
    var executor = userspace_executor.Executor{};
    var peer_executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var peer = Scheduler.init(&peer_executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    defer runtime.reset();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();
    peer.bind(&catalog, &runtime, &capabilities);
    defer peer.deinit();
    var tickets: [dispatch_ownership.CAPACITY]dispatch_ownership.Ticket = undefined;
    var reserved_count: usize = 0;
    defer for (tickets[0..reserved_count]) |ticket| {
        if ((runtime.execution.phase(ticket) catch continue) != .idle) {
            runtime.cancelUnstartedExecution(ticket) catch {};
            runtime.collectExecution(ticket) catch {};
        }
    };
    var task_ids: [dispatch_ownership.CAPACITY]u64 = undefined;
    var before_slots: [dispatch_ownership.CAPACITY]Slot = undefined;
    var before_accounting: [dispatch_ownership.CAPACITY]DispatchAccounting = undefined;
    for (&tickets, &task_ids, 0..) |*ticket, *task_id, index| {
        const task = try createRunnableSchedulerTask(&runtime, index + 1, .background_light, "leased", "app.leased", null);
        task_id.* = task.id;
        try std.testing.expect(scheduler.registerTask(task.id));
        try std.testing.expect(peer.registerTask(task.id));
        ticket.* = try runtime.reserveExecution(task, @intCast(index));
        reserved_count += 1;
    }
    for (task_ids, &before_slots, &before_accounting) |task_id, *slot_snapshot, *accounting_snapshot| {
        slot_snapshot.* = scheduler.slots.get(task_id).?.*;
        accounting_snapshot.* = scheduler.taskDispatchAccounting(task_id).?.*;
    }
    // A policy-blocked class must not flush a note or remove a remotely leased
    // activation merely because selection cannot dispatch it.
    scheduler.configureResourceState(.{ .thermal_pressure = .critical });
    const resource_before = scheduler.resource_state;
    var dispatcher = Dispatcher{};
    try std.testing.expect(!scheduler.runNextWithDispatch(10, &dispatcher));
    try std.testing.expect(!peer.runNextWithDispatch(10, &dispatcher));
    for (tickets, task_ids, before_slots, before_accounting) |ticket, task_id, slot_snapshot, accounting_snapshot| {
        const task = runtime.find(task_id).?;
        try std.testing.expect(!scheduler.registerTask(task_id));
        try std.testing.expect(!peer.registerTask(task_id));
        try std.testing.expect(!scheduler.unregisterTask(task_id));
        try std.testing.expect(!peer.unregisterTask(task_id));
        try std.testing.expect(!scheduler.unregisterSlotIndex(scheduler.slots.slotIndexOf(task_id).?));
        try std.testing.expect(!peer.unregisterSlotIndex(peer.slots.slotIndexOf(task_id).?));
        try std.testing.expectEqual(userspace_executor.ExecutionOutcome.unavailable, scheduler.executeTaskWithDispatch(task_id, 11, &dispatcher).outcome);
        try std.testing.expectEqual(userspace_executor.ExecutionOutcome.unavailable, peer.executeTaskWithDispatch(task_id, 11, &dispatcher).outcome);
        try std.testing.expectEqual(@as(u8, 1), runtime.task_borrow_counts[task.arena_slot_index]);
        try std.testing.expectEqualDeep(slot_snapshot, scheduler.slots.get(task_id).?.*);
        try std.testing.expectEqualDeep(accounting_snapshot, scheduler.taskDispatchAccounting(task_id).?.*);
        try std.testing.expectEqual(ticket.epoch, runtime.execution.taskTicket(task_id).?.epoch);
    }
    try std.testing.expectEqual(@as(usize, 0), dispatcher.calls);
    try std.testing.expectEqualDeep(resource_before, scheduler.resource_state);
    try std.testing.expectEqual(@as(usize, dispatch_ownership.CAPACITY), scheduler.readyQueueDepth(.background_light));
    for (tickets) |ticket| {
        try runtime.cancelUnstartedExecution(ticket);
        try runtime.collectExecution(ticket);
    }
    scheduler.configureResourceState(.{});
    try std.testing.expect(scheduler.runNextWithDispatch(12, &dispatcher));
    try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
    try std.testing.expect(!runtime.execution.hasLeases());
    try std.testing.expect(scheduler.active_dispatch_lease == null);
}

test "scheduler execution reservation failure preserves exact ready queue and accounting" {
    const Dispatcher = struct {
        fn executePreparedTask(_: @This(), _: *const task_runtime.TaskRecord, _: *userspace_executor.MappingHandle, _: u64) dispatch_ownership.ReturnRecord {
            @panic("a busy execution CPU must not reach dispatch");
        }
    };
    const previous_cpu = smp.currentCpuIndex();
    defer smp.setCurrentCpuIndexForTest(previous_cpu);
    smp.setCurrentCpuIndexForTest(0);
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    defer runtime.reset();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();
    const first = try createRunnableSchedulerTask(&runtime, 1, .foreground_interactive, "first", "app.first", null);
    const second = try createRunnableSchedulerTask(&runtime, 2, .foreground_interactive, "second", "app.second", null);
    const occupied = try createRunnableSchedulerTask(&runtime, 3, .background_light, "occupied", "app.occupied", null);
    try std.testing.expect(scheduler.registerTask(first.id));
    try std.testing.expect(scheduler.registerTask(second.id));
    const ticket = try runtime.reserveExecution(occupied, 0);
    defer if (runtime.execution.hasLeases()) {
        runtime.cancelUnstartedExecution(ticket) catch {};
        runtime.collectExecution(ticket) catch {};
    };
    const slots_before = scheduler.slots.slots;
    const accounting_before = scheduler.accountingStorage().*;
    const heads_before = scheduler.ready_heads;
    const tails_before = scheduler.ready_tails;
    const counts_before = scheduler.ready_counts;
    const resource_before = scheduler.resource_state;
    const note_before = scheduler.cold_note;
    try std.testing.expect(!scheduler.runNextWithDispatch(20, Dispatcher{}));
    try std.testing.expectEqual(userspace_executor.ExecutionOutcome.unavailable, scheduler.executeTaskWithDispatch(first.id, 20, Dispatcher{}).outcome);
    try std.testing.expectEqualDeep(slots_before, scheduler.slots.slots);
    try std.testing.expectEqualDeep(accounting_before, scheduler.accountingStorage().*);
    try std.testing.expectEqual(heads_before, scheduler.ready_heads);
    try std.testing.expectEqual(tails_before, scheduler.ready_tails);
    try std.testing.expectEqual(counts_before, scheduler.ready_counts);
    try std.testing.expectEqualDeep(resource_before, scheduler.resource_state);
    try std.testing.expectEqualDeep(note_before, scheduler.cold_note);
    try std.testing.expectEqual(@as(u64, 0), scheduler.last_dispatch_tick);
    try std.testing.expectEqual(@as(u64, 0), scheduler.active_dispatch_task_id);
    try std.testing.expect(scheduler.active_dispatch_lease == null);
    try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[first.arena_slot_index]);
    try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[second.arena_slot_index]);
    try std.testing.expectEqual(@as(u8, 1), runtime.task_borrow_counts[occupied.arena_slot_index]);
    try runtime.cancelUnstartedExecution(ticket);
    try runtime.collectExecution(ticket);
}

// Entry is replaced by a supplied record, but preparation, owner start,
// publication, once-only BSP consumption and Runtime pin collection are real.
const PreparedReturnTestDispatcher = if (builtin.is_test) struct {
    scheduler: *Scheduler,
    runtime: *task_runtime.Runtime,
    record: dispatch_ownership.ReturnRecord,
    calls: usize = 0,

    fn executePreparedTask(self: *@This(), task: *const task_runtime.TaskRecord, _: *userspace_executor.MappingHandle, _: u64) dispatch_ownership.ReturnRecord {
        return self.execute(task) catch @panic("prepared return fixture retains exact dispatch ownership");
    }

    fn execute(self: *@This(), task: *const task_runtime.TaskRecord) !dispatch_ownership.ReturnRecord {
        const ticket = self.scheduler.active_dispatch_lease.?;
        try self.runtime.execution.bindPrepared(ticket, 1, 0x1000);
        var bound: dispatch_ownership.BoundIdentity = undefined;
        try self.runtime.execution.startPreparedInto(ticket, &bound);
        try std.testing.expectEqual(task.id, bound.identity.task_id);
        try std.testing.expectEqual(@as(u8, 1), self.runtime.task_borrow_counts[task.arena_slot_index]);
        try self.runtime.execution.ackPreparedReturn(ticket, self.record);
        try std.testing.expectError(error.WrongPhase, self.runtime.collectExecution(ticket));
        var consumed: dispatch_ownership.ReturnRecord = undefined;
        try self.runtime.execution.consumePreparedReturnInto(ticket, &consumed);
        try std.testing.expectEqualDeep(self.record, consumed);
        try std.testing.expectError(error.WrongPhase, self.runtime.execution.consumePreparedReturnInto(ticket, &consumed));
        try std.testing.expectEqualDeep(self.record, consumed);
        try std.testing.expect(!self.scheduler.unregisterTask(task.id));
        self.calls += 1;
        return consumed;
    }
} else struct {};

test "scheduler prepared return drives UI accounting instead of anchor observations" {
    const previous_cpu = smp.currentCpuIndex();
    defer smp.setCurrentCpuIndexForTest(previous_cpu);
    smp.setCurrentCpuIndexForTest(0);
    for ([_]dispatch_ownership.Outcome{ .yielded, .wait_for_event }) |outcome| {
        var executor = userspace_executor.Executor{};
        var scheduler = Scheduler.init(&executor);
        var catalog = userspace_loader.Catalog.init();
        var runtime = task_runtime.Runtime.init();
        var capabilities = capability.CapabilityTable.init();
        defer runtime.reset();
        scheduler.bind(&catalog, &runtime, &capabilities);
        defer scheduler.deinit();
        const task = try createRunnableSchedulerTask(&runtime, 41, .foreground_interactive, "return-ui", "app.return-ui", 41);
        try std.testing.expect(scheduler.registerTask(task.id));
        executor.last_yield_ui_revision = 999;
        var dispatcher = PreparedReturnTestDispatcher{
            .scheduler = &scheduler,
            .runtime = &runtime,
            .record = .{ .outcome = outcome, .ui_revision = 17 },
        };
        try std.testing.expect(scheduler.runNextWithDispatch(50, &dispatcher));
        const accounting = scheduler.taskDispatchAccounting(task.id).?;
        try std.testing.expectEqual(@as(u64, 17), accounting.last_ui_state_revision);
        try std.testing.expectEqual(@as(u64, @intFromBool(outcome == .wait_for_event)), accounting.event_wait_count);
        try std.testing.expectEqual(DISPATCH_CPU_TICK_COST, accounting.cpu_ticks_consumed);
        try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
        try std.testing.expectEqual(@as(u64, 999), executor.last_yield_ui_revision);
        try std.testing.expect(!runtime.execution.hasLeases());
        try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[task.arena_slot_index]);
    }
}

test "scheduler prepared return contains the exact fault receipt before collection" {
    const previous_cpu = smp.currentCpuIndex();
    defer smp.setCurrentCpuIndexForTest(previous_cpu);
    smp.setCurrentCpuIndexForTest(0);
    for ([_]bool{ false, true }) |direct| {
        var executor = userspace_executor.Executor{};
        var scheduler = Scheduler.init(&executor);
        var catalog = userspace_loader.Catalog.init();
        var runtime = task_runtime.Runtime.init();
        var capabilities = capability.CapabilityTable.init();
        defer runtime.reset();
        scheduler.bind(&catalog, &runtime, &capabilities);
        defer scheduler.deinit();
        const task = try createRunnableSchedulerTask(&runtime, 42, .background_light, "return-fault", "app.return-fault", null);
        const task_id = task.id;
        try std.testing.expect(scheduler.registerTask(task_id));
        const anchor_exception = userspace_executor.UserException{ .vector = 6, .error_code = 0, .instruction_pointer = 0x5000 };
        executor.last_user_exception = anchor_exception;
        const exception = userspace_executor.UserException{
            .vector = 14,
            .error_code = 0x15,
            .instruction_pointer = 0x4000_100a,
            .fault_address = 0x4000_3000,
        };
        var dispatcher = PreparedReturnTestDispatcher{
            .scheduler = &scheduler,
            .runtime = &runtime,
            .record = .{
                .outcome = .faulted,
                .fault_vector = exception.vector,
                .fault_error_code = exception.error_code,
                .fault_instruction_pointer = exception.instruction_pointer,
                .fault_address = exception.fault_address,
            },
        };
        if (direct) {
            const record = scheduler.executeTaskWithDispatch(task_id, 51, &dispatcher);
            try std.testing.expectEqualDeep(dispatcher.record, record);
        } else {
            try std.testing.expect(scheduler.runNextWithDispatch(51, &dispatcher));
        }
        const terminal = runtime.find(task_id).?;
        try std.testing.expectEqual(task_runtime.TaskState.terminated, terminal.state);
        const provenance = terminal.latestProvenanceEvent().?;
        try std.testing.expectEqual(@as(u64, 51), provenance.tick);
        var expected: [64]u8 = undefined;
        const fingerprint = try std.fmt.bufPrint(&expected, "reason_fingerprint=0x{x}", .{exception.reasonFingerprint()});
        try std.testing.expect(std.mem.indexOf(u8, provenance.detailSlice(), fingerprint) != null);
        try std.testing.expectEqualDeep(anchor_exception, executor.last_user_exception.?);
        try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
        try std.testing.expect(scheduler.slots.get(task_id) == null);
        try std.testing.expect(!runtime.execution.hasLeases());
    }
}

test "scheduler selected prepared owners retain pins until receipt consumption and collect cancellations" {
    const previous_cpu = smp.currentCpuIndex();
    defer smp.setCurrentCpuIndexForTest(previous_cpu);
    smp.setCurrentCpuIndexForTest(0);
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    defer runtime.reset();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();
    const task = try createRunnableSchedulerTask(&runtime, 43, .foreground_interactive, "selected", "app.selected", null);
    const neighbor = try createRunnableSchedulerTask(&runtime, 44, .background_light, "neighbor", "app.neighbor", null);
    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.registerTask(neighbor.id));
    const slot_before = scheduler.slots.get(task.id).?.*;
    const accounting_before = scheduler.taskDispatchAccounting(task.id).?.*;
    const resources_before = scheduler.resource_state;
    var foreign: dispatch_ownership.Coordinator = .{};
    for (0..dispatch_ownership.CAPACITY) |index| {
        const cpu: u8 = @intCast(index);
        const neighbor_ticket = try runtime.reserveExecution(neighbor, @intCast((index + 1) % dispatch_ownership.CAPACITY));
        const ticket = scheduler.beginTaskDispatch(&runtime, task, cpu).?;
        try runtime.execution.bindPrepared(ticket, 1, 0x1000);
        smp.setCurrentCpuIndexForTest(neighbor_ticket.cpu);
        var bound: dispatch_ownership.BoundIdentity = undefined;
        try std.testing.expectError(error.WrongCpu, runtime.execution.startPreparedInto(ticket, &bound));
        smp.setCurrentCpuIndexForTest(cpu);
        try runtime.execution.startPreparedInto(ticket, &bound);
        try std.testing.expectEqual(task.id, bound.identity.task_id);
        const record = dispatch_ownership.ReturnRecord{ .outcome = .wait_for_event, .ui_revision = 100 + index };
        var wrong_issuer = ticket;
        wrong_issuer.issuer = &foreign;
        try std.testing.expectError(error.WrongCoordinator, runtime.execution.ackPreparedReturn(wrong_issuer, record));
        try runtime.execution.ackPreparedReturn(ticket, record);
        smp.setCurrentCpuIndexForTest(0);
        try std.testing.expectError(error.WrongPhase, runtime.collectExecution(ticket));
        try std.testing.expectEqual(@as(u8, 1), runtime.task_borrow_counts[task.arena_slot_index]);
        var consumed = dispatch_ownership.ReturnRecord{ .ui_revision = 999 };
        const canary = consumed;
        var stale = ticket;
        stale.epoch += 1;
        try std.testing.expectError(error.StaleTicket, runtime.execution.consumePreparedReturnInto(stale, &consumed));
        try std.testing.expectEqualDeep(canary, consumed);
        try runtime.execution.consumePreparedReturnInto(ticket, &consumed);
        try std.testing.expectEqualDeep(record, consumed);
        scheduler.finishTaskDispatch(&runtime, ticket);
        try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[task.arena_slot_index]);
        try std.testing.expectEqual(@as(u8, 1), runtime.task_borrow_counts[neighbor.arena_slot_index]);
        try std.testing.expectEqual(neighbor_ticket.epoch, runtime.execution.taskTicket(neighbor.id).?.epoch);
        // The same Scheduler finish path handles both unpublished reservations
        // and ready commands canceled before any owner starts. No AP entry runs.
        for ([_]bool{ false, true }) |prepared| {
            const canceled = scheduler.beginTaskDispatch(&runtime, task, cpu).?;
            if (prepared) try runtime.execution.bindPrepared(canceled, 1, 0x1000);
            scheduler.finishTaskDispatch(&runtime, canceled);
            try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[task.arena_slot_index]);
            try std.testing.expectEqual(@as(u8, 1), runtime.task_borrow_counts[neighbor.arena_slot_index]);
        }
        try runtime.cancelUnstartedExecution(neighbor_ticket);
        try runtime.collectExecution(neighbor_ticket);
        try std.testing.expect(!runtime.execution.hasLeases());
        try std.testing.expectEqualDeep(slot_before, scheduler.slots.get(task.id).?.*);
        try std.testing.expectEqualDeep(accounting_before, scheduler.taskDispatchAccounting(task.id).?.*);
        try std.testing.expectEqualDeep(resources_before, scheduler.resource_state);
    }
}

test "scheduler execution collection retains active identity through lifetime callbacks" {
    const Callback = struct {
        scheduler: *Scheduler,
        peer: *Scheduler,
        runtime: *task_runtime.Runtime,
        task: *task_runtime.TaskRecord,
        task_id: u64,
        address_space_id: u64,
        slot: *Slot,
        notifications: usize = 0,

        fn check(self: *@This()) void {
            const ticket = self.scheduler.active_dispatch_lease orelse @panic("collecting scheduler retains lease");
            std.testing.expectEqual(self.task_id, self.scheduler.active_dispatch_task_id) catch @panic("collecting scheduler retains active task");
            std.testing.expectEqual(dispatch_ownership.Phase.collecting, self.runtime.execution.phase(ticket) catch @panic("collecting ticket remains valid")) catch @panic("callbacks run while collecting");
            std.testing.expectEqual(@as(u8, 1), self.runtime.task_borrow_counts[self.task.arena_slot_index]) catch @panic("callbacks retain task pin");
            if (self.scheduler.slots.get(self.task_id).? != self.slot) @panic("callbacks retain scheduling slot");
            if (self.scheduler.registerTask(self.task_id) or self.peer.registerTask(self.task_id) or
                self.scheduler.unregisterTask(self.task_id) or self.peer.unregisterTask(self.task_id)) @panic("callbacks cannot replace leased slots");
            self.scheduler.pruneRetiredSlots(self.runtime);
            self.peer.pruneRetiredSlots(self.runtime);
            if (self.scheduler.slots.get(self.task_id).? != self.slot) @panic("pruning preserves collecting slot");
            if (self.scheduler.executeTask(self.task_id, 100) != .unavailable or
                self.peer.executeTask(self.task_id, 100) != .unavailable) @panic("callbacks cannot dispatch collecting incarnation");
            self.notifications += 1;
        }

        fn retire(context: *anyopaque, event: task_runtime.TaskRetirement) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (event.task_id != self.task_id) return;
            if (event.capability_ids.len != 1 or event.capability_ids[0] != 77 or event.now_ticks != 29) @panic("retirement retains exact deferred resources");
            self.check();
            if (event.capability_ids[0] != 77) @panic("callback retains attachment slice");
        }

        pub fn retireAddressSpace(self: *@This(), event: task_runtime.AddressSpaceRetirementEvent) void {
            if (event.address_space_id != self.address_space_id) return;
            if (self.runtime.findAddressSpaceConst(self.address_space_id) != null) @panic("address metadata detached before notification");
            self.check();
        }
    };
    const Dispatcher = struct {
        callback: *Callback,
        fn executePreparedTask(self: @This(), task: *const task_runtime.TaskRecord, _: *userspace_executor.MappingHandle, _: u64) dispatch_ownership.ReturnRecord {
            const callback = self.callback;
            const ticket = callback.scheduler.active_dispatch_lease.?;
            callback.runtime.execution.bindPrepared(ticket, 1, 0x1000) catch @panic("model binds exact execution");
            var bound: dispatch_ownership.BoundIdentity = undefined;
            callback.runtime.execution.startPreparedInto(ticket, &bound) catch @panic("model starts exact execution");
            if (bound.identity.task_id != task.id) @panic("model consumes exact task identity");
            if (!callback.runtime.terminateResolvedTask(callback.task, 29)) @panic("model requests deferred termination");
            if (task.capability_count != 1 or callback.runtime.findAddressSpaceConst(callback.address_space_id) == null or callback.notifications != 0) @panic("running termination retains resources");
            std.testing.expectError(error.WrongPhase, callback.runtime.collectExecution(ticket)) catch @panic("running lease cannot be collected");
            _ = callback.runtime.execution.requestStop(ticket) catch @panic("model requests generation-bound stop");
            if (!callback.runtime.execution.stopRequested(ticket)) @panic("owner observes matching stop");
            callback.runtime.execution.ackPreparedReturn(ticket, .{ .outcome = .yielded }) catch @panic("model publishes completed return");
            if (callback.notifications != 0 or callback.scheduler.unregisterTask(task.id)) @panic("return ack retains scheduler lifetime until collection");
            std.testing.expectError(error.WrongPhase, callback.runtime.collectExecution(ticket)) catch @panic("prepared return requires consumption before collection");
            var record: dispatch_ownership.ReturnRecord = undefined;
            callback.runtime.execution.consumePreparedReturnInto(ticket, &record) catch @panic("model consumes its exact prepared return");
            return record;
        }
    };
    const previous_cpu = smp.currentCpuIndex();
    defer smp.setCurrentCpuIndexForTest(previous_cpu);
    smp.setCurrentCpuIndexForTest(0);
    var executor = userspace_executor.Executor{};
    var peer_executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var peer = Scheduler.init(&peer_executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    defer runtime.reset();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();
    peer.bind(&catalog, &runtime, &capabilities);
    defer peer.deinit();
    const task = try createRunnableSchedulerTask(&runtime, 1, .background_light, "collect", "app.collect", null);
    const task_id = task.id;
    try runtime.grantCapability(task.id, 77);
    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(peer.registerTask(task.id));
    var callback = Callback{ .scheduler = &scheduler, .peer = &peer, .runtime = &runtime, .task = task, .task_id = task.id, .address_space_id = task.address_space_id, .slot = scheduler.slots.get(task.id).? };
    const task_sink = task_runtime.TaskRetirementSink{ .context = &callback, .retire = Callback.retire };
    const address_sink = task_runtime.AddressSpaceRetirementSink.init(Callback, &callback);
    try std.testing.expect(runtime.bindTaskRetirementSink(task_sink));
    try std.testing.expect(runtime.bindAddressSpaceRetirementSink(address_sink));
    try std.testing.expect(scheduler.runNextWithDispatch(1, Dispatcher{ .callback = &callback }));
    try std.testing.expectEqual(@as(usize, 2), callback.notifications);
    try std.testing.expectEqual(@as(u64, 0), scheduler.active_dispatch_task_id);
    try std.testing.expect(scheduler.active_dispatch_lease == null);
    try std.testing.expect(!runtime.execution.hasLeases());
    try std.testing.expectEqual(@as(u16, 0), task.capability_count);
    try std.testing.expectEqual(@as(u8, 0), runtime.task_borrow_counts[task.arena_slot_index]);
    try std.testing.expect(scheduler.slots.get(task_id) == null);
    try std.testing.expect(peer.unregisterTask(task_id));
    try std.testing.expect(runtime.unbindTaskRetirementSink(task_sink));
    try std.testing.expect(runtime.unbindAddressSpaceRetirementSink(address_sink));
}

test "scheduler foreign readers preserve pending accounting and avoid runtime priority scans" {
    const previous_cpu = smp.currentCpuIndex();
    defer smp.setCurrentCpuIndexForTest(previous_cpu);
    smp.setCurrentCpuIndexForTest(0);
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    defer runtime.reset();
    scheduler.bind(&catalog, &runtime, &capabilities);
    defer scheduler.deinit();
    const batch = try createRunnableSchedulerTask(&runtime, 1, .batch_compute, "batch", "app.batch", null);
    const foreground = try createRunnableSchedulerTask(&runtime, 2, .foreground_interactive, "foreground", "app.foreground", null);
    try std.testing.expect(scheduler.registerTask(batch.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    scheduler.noteDenied(scheduler.slots.get(batch.id).?, .cpu_budget, .cpu, .cpu, false);
    const note = scheduler.cold_note;
    const accounting = scheduler.accountingStorage().*;
    const dispatched = scheduler.engine_dispatch_counts;
    const denied = scheduler.engine_denial_counts;
    for (1..dispatch_ownership.CAPACITY) |cpu| {
        smp.setCurrentCpuIndexForTest(@intCast(cpu));
        defer smp.setCurrentCpuIndexForTest(0);
        try std.testing.expect(scheduler.taskDispatchStats(batch.id) == null);
        try std.testing.expect(scheduler.taskDispatchAccounting(batch.id) == null);
        try std.testing.expectEqual(@as(u64, 0), scheduler.engineDispatchCount(.cpu));
        try std.testing.expectEqual(@as(u64, 0), scheduler.engineDenialCount(.cpu));
        try std.testing.expect(!scheduler.hasReadyLatencySensitiveWork());
        try std.testing.expect(!scheduler.shouldPreemptTask(batch.id));
        try std.testing.expectEqualDeep(note, scheduler.cold_note);
        try std.testing.expectEqualDeep(accounting, scheduler.dispatch_accounting.?.*);
        try std.testing.expectEqual(dispatched, scheduler.engine_dispatch_counts);
        try std.testing.expectEqual(denied, scheduler.engine_denial_counts);
    }
    smp.setCurrentCpuIndexForTest(0);
    try std.testing.expect(scheduler.shouldPreemptTask(batch.id));
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDenialCount(.cpu));
    try std.testing.expect(!scheduler.cold_note.active);
}
