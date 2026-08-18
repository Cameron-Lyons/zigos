const accelerator_scheduler = @import("accelerator_scheduler.zig");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const debug_contract = @import("../security/debug_contract.zig");
const launch_helpers = @import("task_runtime_launch.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const runtime_host = @import("task_runtime_host.zig");
const root = @import("root");
const std = @import("std");
const units = @import("../core/units.zig");
const native_util = @import("../core/util.zig");

pub const TASK_PAGE_SIZE: usize = 32;
pub const TASK_PAGE_COUNT: usize = 4;
pub const MAX_TASKS: usize = TASK_PAGE_SIZE * TASK_PAGE_COUNT;
pub const MAX_TASK_CAPABILITIES: usize = 24;
pub const MAX_TASK_COMPONENTS: usize = 8;
pub const MAX_AUDIT_EVENTS: usize = 16;

pub const MAX_TASK_PROVENANCE_EVENTS: usize = if (includesVerificationEvidence()) 24 else 8;
pub const MAX_TASK_BUNDLE_ID_BYTES: usize = 64;
pub const MAX_TASK_SOURCE_IDENTITY_BYTES: usize = 96;
pub const MAX_COMPONENT_LABEL_BYTES: usize = 48;
pub const MAX_COMPONENT_ENTRY_BYTES: usize = 64;
pub const MAX_EXECUTABLE_SEGMENTS: usize = 8;
pub const MAX_IMAGE_HASH_BYTES: usize = crypto_hash.digest_bytes;
pub const INDEX_CAPACITY: usize = MAX_TASKS * 2;
pub const TASK_OWNER_INDEX_CAPACITY: usize = MAX_TASKS * 2;
pub const TASK_CAPABILITY_SCAN_BOUND: usize = MAX_TASK_CAPABILITIES;
pub const TASK_CAPABILITY_PRIMARY_INDEX_LOOKUPS_PER_OPERATION: u8 = 0;
pub const DEFAULT_USER_STACK_TOP: u64 = 0xBFFF_F000;
pub const DEFAULT_USER_STACK_SIZE_BYTES: usize = units.kibibytes(64);
pub const USER_PAGE_SIZE: u64 = launch_helpers.USER_PAGE_SIZE;
pub const USER_VIRTUAL_ADDRESS_MIN: u64 = launch_helpers.USER_VIRTUAL_ADDRESS_MIN;
pub const USER_IMAGE_ADDRESS_MAX_EXCLUSIVE: u64 = launch_helpers.USER_IMAGE_ADDRESS_MAX_EXCLUSIVE;
pub const USER_STACK_ADDRESS_MIN: u64 = launch_helpers.USER_STACK_ADDRESS_MIN;
pub const USER_VIRTUAL_ADDRESS_MAX_EXCLUSIVE: u64 = launch_helpers.USER_VIRTUAL_ADDRESS_MAX_EXCLUSIVE;
pub const DEFAULT_SYNTHETIC_ENTRY_POINT: u64 = USER_VIRTUAL_ADDRESS_MIN;
pub const DEFAULT_SYNTHETIC_IMAGE_BYTES: usize = units.kibibytes(8);

fn includesVerificationEvidence() bool {
    if (!@hasDecl(root, "includes_verification_evidence")) return false;
    return root.includes_verification_evidence;
}

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
    bootstrap_mailbox_address: u64 = 0,
    stack_top: u64 = DEFAULT_USER_STACK_TOP,
    stack_size_bytes: usize = DEFAULT_USER_STACK_SIZE_BYTES,
    file_size_bytes: usize = 0,
    file_sha256: crypto_hash.Digest = crypto_hash.zero_digest,
    segment_count: usize = 0,
    segments: [MAX_EXECUTABLE_SEGMENTS]ExecutableSegmentSpec = [_]ExecutableSegmentSpec{ExecutableSegmentSpec{}} ** MAX_EXECUTABLE_SEGMENTS,

    pub fn isPresent(self: *const ExecutableImageSpec) bool {
        return self.entry_point != 0 and self.segment_count != 0;
    }

    pub fn eql(self: *const ExecutableImageSpec, other: *const ExecutableImageSpec) bool {
        if (self.entry_point != other.entry_point) return false;
        if (self.bootstrap_mailbox_address != other.bootstrap_mailbox_address) return false;
        if (self.stack_top != other.stack_top) return false;
        if (self.stack_size_bytes != other.stack_size_bytes) return false;
        if (self.file_size_bytes != other.file_size_bytes) return false;
        if (!std.mem.eql(u8, &self.file_sha256, &other.file_sha256)) return false;
        if (self.segment_count != other.segment_count) return false;
        if (self.segment_count > self.segments.len) return false;

        for (self.segments[0..self.segment_count], other.segments[0..other.segment_count]) |left, right| {
            if (left.virtual_address != right.virtual_address) return false;
            if (left.file_offset != right.file_offset) return false;
            if (left.file_size != right.file_size) return false;
            if (left.memory_size != right.memory_size) return false;
            if (left.alignment != right.alignment) return false;
            if (left.access.read != right.access.read) return false;
            if (left.access.write != right.access.write) return false;
            if (left.access.execute != right.access.execute) return false;
        }

        return true;
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
    label: [MAX_COMPONENT_LABEL_BYTES]u8,
    entry_len: usize,
    entry: [MAX_COMPONENT_ENTRY_BYTES]u8,

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
    suspended,
    resumed,
    terminated,
    capability_granted,
    capability_revoked,
    component_attached,
    permission_prompted,
    permission_reviewed,
    policy_allowed,
    policy_denied,
    background_dispatched,
    background_expired,
    service_connected,
    service_restarted,
};

pub const AuditEvent = struct {
    kind: AuditEventKind,
    capability_id: u64 = 0,
    detail: u32 = 0,
    tick: u64 = 0,
};

pub const ProvenanceRecord = debug_contract.ProvenanceRecord;

comptime {
    if (debug_contract.MAX_LABEL_BYTES > std.math.maxInt(u8) or
        debug_contract.MAX_DETAIL_BYTES > std.math.maxInt(u8))
    {
        @compileError("compact task provenance text lengths require wider counters");
    }
}

pub const TaskProvenanceRecord = struct {
    trace_id: u64 = 0,
    parent_trace_id: u64 = 0,
    task_id: u64 = 0,
    artifact_id: u64 = 0,
    service_id: u64 = 0,
    capability_id: u64 = 0,
    target_id: u64 = 0,
    tick: u64 = 0,
    source_identity_fingerprint: u64 = 0,
    release_transparency_sequence: u64 = 0,
    release_transparency_root_fingerprint: u64 = 0,
    release_transparency_log_head_fingerprint: u64 = 0,
    denial_fingerprint: u64 = 0,
    operation: [debug_contract.MAX_LABEL_BYTES]u8 = [_]u8{0} ** debug_contract.MAX_LABEL_BYTES,
    detail: [debug_contract.MAX_DETAIL_BYTES]u8 = [_]u8{0} ** debug_contract.MAX_DETAIL_BYTES,
    kind: debug_contract.ProvenanceKind = .none,
    decision: debug_contract.Decision = .allowed,
    target_kind: ?capability.CapabilityTargetKind = null,
    denial_reason: abi.DenialReason = .none,
    operation_len: u8 = 0,
    detail_len: u8 = 0,

    pub fn from(record: ProvenanceRecord) TaskProvenanceRecord {
        const operation_len = @min(record.operation_len, record.operation.len);
        const detail_len = @min(record.detail_len, record.detail.len);
        var compact = TaskProvenanceRecord{
            .trace_id = record.trace_id,
            .parent_trace_id = record.parent_trace_id,
            .task_id = record.task_id,
            .artifact_id = record.artifact_id,
            .service_id = record.service_id,
            .capability_id = record.capability_id,
            .target_id = record.target_id,
            .tick = record.tick,
            .source_identity_fingerprint = record.source_identity_fingerprint,
            .release_transparency_sequence = record.release_transparency_sequence,
            .release_transparency_root_fingerprint = record.release_transparency_root_fingerprint,
            .release_transparency_log_head_fingerprint = record.release_transparency_log_head_fingerprint,
            .denial_fingerprint = record.denial.fingerprint,
            .kind = record.kind,
            .decision = record.decision,
            .target_kind = record.target_kind,
            .denial_reason = record.denial.reason,
            .operation_len = @intCast(operation_len),
            .detail_len = @intCast(detail_len),
        };
        @memcpy(compact.operation[0..operation_len], record.operation[0..operation_len]);
        @memcpy(compact.detail[0..detail_len], record.detail[0..detail_len]);
        return compact;
    }

    pub fn operationSlice(self: *const TaskProvenanceRecord) []const u8 {
        return self.operation[0..self.operation_len];
    }

    pub fn detailSlice(self: *const TaskProvenanceRecord) []const u8 {
        return self.detail[0..self.detail_len];
    }

    pub fn hasReleaseTransparency(self: *const TaskProvenanceRecord) bool {
        return self.release_transparency_sequence != 0 and
            self.release_transparency_root_fingerprint != 0 and
            self.release_transparency_log_head_fingerprint != 0;
    }
};

test "task provenance compacts recovery traces without losing diagnostic identity" {
    const denial = debug_contract.explainDenied(
        .policy_denied,
        "open-camera",
        "camera",
        9,
        17,
        .device,
        3,
    );
    const source = debug_contract.provenance(
        .syscall,
        .denied,
        44,
        9,
        22,
        17,
        .device,
        3,
        "open-camera",
        "redacted=yes",
        denial,
        0xA11CE,
    );
    const compact = TaskProvenanceRecord.from(source);

    try std.testing.expect(@sizeOf(TaskProvenanceRecord) < @sizeOf(ProvenanceRecord));
    try std.testing.expectEqual(source.trace_id, compact.trace_id);
    try std.testing.expectEqual(source.parent_trace_id, compact.parent_trace_id);
    try std.testing.expectEqual(source.kind, compact.kind);
    try std.testing.expectEqual(source.decision, compact.decision);
    try std.testing.expectEqual(source.target_kind, compact.target_kind);
    try std.testing.expectEqual(source.denial.reason, compact.denial_reason);
    try std.testing.expectEqual(source.denial.fingerprint, compact.denial_fingerprint);
    try std.testing.expectEqualStrings(source.operationSlice(), compact.operationSlice());
    try std.testing.expectEqualStrings(source.detailSlice(), compact.detailSlice());
}

test "task provenance clamps untrusted text lengths to compact storage" {
    var source = ProvenanceRecord{};
    @memset(&source.operation, 'o');
    @memset(&source.detail, 'd');
    source.operation_len = std.math.maxInt(usize);
    source.detail_len = std.math.maxInt(usize);

    const compact = TaskProvenanceRecord.from(source);
    try std.testing.expectEqual(@as(usize, debug_contract.MAX_LABEL_BYTES), compact.operationSlice().len);
    try std.testing.expectEqual(@as(usize, debug_contract.MAX_DETAIL_BYTES), compact.detailSlice().len);
    try std.testing.expect(std.mem.allEqual(u8, compact.operationSlice(), 'o'));
    try std.testing.expect(std.mem.allEqual(u8, compact.detailSlice(), 'd'));
}

pub const LaunchProvenanceSpec = struct {
    boundary: LaunchBoundary = .direct_request,
    image_id: u64 = 0,
    component_abi_version: u16 = 0,
    signed: bool = false,
    bundle_id: []const u8 = "",
    source_identity: []const u8 = "",
    release_transparency_sequence: u64 = 0,
    release_transparency_root: crypto_hash.Digest = crypto_hash.zero_digest,
    release_transparency_log_head: crypto_hash.Digest = crypto_hash.zero_digest,
};

pub const LaunchProvenanceRecord = struct {
    boundary: LaunchBoundary,
    image_id: u64,
    component_abi_version: u16,
    signed: bool,
    bundle_id_len: usize,
    bundle_id: [MAX_TASK_BUNDLE_ID_BYTES]u8,
    source_identity_len: usize,
    source_identity: [MAX_TASK_SOURCE_IDENTITY_BYTES]u8,
    release_transparency_sequence: u64,
    release_transparency_root: crypto_hash.Digest,
    release_transparency_log_head: crypto_hash.Digest,

    pub fn bundleIdSlice(self: *const LaunchProvenanceRecord) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn sourceIdentitySlice(self: *const LaunchProvenanceRecord) []const u8 {
        return self.source_identity[0..self.source_identity_len];
    }

    pub fn hasReleaseTransparency(self: *const LaunchProvenanceRecord) bool {
        return self.release_transparency_sequence != 0 and
            !std.mem.eql(u8, &self.release_transparency_root, &crypto_hash.zero_digest) and
            !std.mem.eql(u8, &self.release_transparency_log_head, &crypto_hash.zero_digest);
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

pub const TaskColdRecord = struct {
    execution_components: [MAX_TASK_COMPONENTS]ExecutionComponentRecord = [_]ExecutionComponentRecord{zeroExecutionComponent()} ** MAX_TASK_COMPONENTS,
    capability_ids: [MAX_TASK_CAPABILITIES]u64 = [_]u64{0} ** MAX_TASK_CAPABILITIES,
    capability_generation: u64 = 1,
    audit_trail: [MAX_AUDIT_EVENTS]AuditEvent = [_]AuditEvent{AuditEvent{ .kind = .created }} ** MAX_AUDIT_EVENTS,
    provenance_trail: [MAX_TASK_PROVENANCE_EVENTS]TaskProvenanceRecord = [_]TaskProvenanceRecord{TaskProvenanceRecord{}} ** MAX_TASK_PROVENANCE_EVENTS,
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
    provenance_start: usize,
    provenance_count: usize,
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
    executable_loaded: bool,
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

    pub fn launchSourceIdentitySlice(self: *const TaskRecord) []const u8 {
        return self.launch.sourceIdentitySlice();
    }

    pub fn executionComponents(self: *const TaskRecord) []const ExecutionComponentRecord {
        return taskColdConst(self).execution_components[0..self.execution_component_count];
    }

    pub fn capabilityIds(self: *const TaskRecord) []const u64 {
        if (self.capability_count > TASK_CAPABILITY_SCAN_BOUND) {
            native_util.impossibleByInvariant("task capabilities stay within their fixed scan bound");
        }
        return taskColdConst(self).capability_ids[0..self.capability_count];
    }

    pub fn capabilityGeneration(self: *const TaskRecord) u64 {
        return taskColdConst(self).capability_generation;
    }

    pub fn hasLoadedExecutable(self: *const TaskRecord) bool {
        return self.executable_loaded;
    }

    pub fn auditEventAt(self: *const TaskRecord, index: usize) ?AuditEvent {
        if (index >= self.audit_count) return null;
        return taskColdConst(self).audit_trail[(self.audit_start + index) % MAX_AUDIT_EVENTS];
    }

    pub fn latestAuditEvent(self: *const TaskRecord) ?AuditEvent {
        if (self.audit_count == 0) return null;
        return self.auditEventAt(self.audit_count - 1);
    }

    pub fn appendAudit(self: *TaskRecord, event: AuditEvent) void {
        const cold = taskCold(self);
        if (self.audit_count < MAX_AUDIT_EVENTS) {
            const slot_index = (self.audit_start + self.audit_count) % MAX_AUDIT_EVENTS;
            cold.audit_trail[slot_index] = event;
            self.audit_count += 1;
            return;
        }

        cold.audit_trail[self.audit_start] = event;
        self.audit_start = (self.audit_start + 1) % MAX_AUDIT_EVENTS;
    }

    pub fn provenanceEventAt(self: *const TaskRecord, index: usize) ?TaskProvenanceRecord {
        if (index >= self.provenance_count) return null;
        return taskColdConst(self).provenance_trail[(self.provenance_start + index) % MAX_TASK_PROVENANCE_EVENTS];
    }

    pub fn latestProvenanceEvent(self: *const TaskRecord) ?TaskProvenanceRecord {
        if (self.provenance_count == 0) return null;
        return self.provenanceEventAt(self.provenance_count - 1);
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

fn taskSlotId(slot: *const TaskSlot) u64 {
    return slot.task.id;
}

pub const TaskArena = indexed_arena.PagedIndexedArena(TaskSlot, TASK_PAGE_SIZE, TASK_PAGE_COUNT, INDEX_CAPACITY, taskSlotId);
pub const TaskHandle = TaskArena.Handle;
pub const TaskOwnerIndex = indexed_arena.MultimapIndex(MAX_TASKS, MAX_TASKS, TASK_OWNER_INDEX_CAPACITY);

pub fn taskOwnerIndexKey(owner: principal.PrincipalId) u64 {
    const kind_bits = @as(u64, @intFromEnum(owner.kind)) + 1;
    return indexed_arena.nonZeroKey((owner.serial *% 0x100) ^ kind_bits);
}

pub const AddressSpaceSlot = struct {
    in_use: bool = false,
    address_space: AddressSpaceRecord = zeroAddressSpace(),
};

fn addressSpaceSlotId(slot: *const AddressSpaceSlot) u64 {
    return slot.address_space.id;
}

pub const AddressSpaceArena = indexed_arena.IndexedArenaWithKey(u64, AddressSpaceSlot, MAX_TASKS, INDEX_CAPACITY, addressSpaceSlotId);

pub const Snapshot = struct {
    next_task_id: u64 = 1,
    next_process_id: u64 = 1,
    next_address_space_id: u64 = 1,
    next_namespace_id: u64 = 1,
    next_component_id: u64 = 1,
    task_count: usize = 0,
    tasks: [MAX_TASKS]TaskSlot = [_]TaskSlot{TaskSlot{}} ** MAX_TASKS,
    task_cold: [MAX_TASKS]TaskColdRecord = [_]TaskColdRecord{zeroTaskCold()} ** MAX_TASKS,
    address_space_count: usize = 0,
    address_spaces: [MAX_TASKS]AddressSpaceSlot = [_]AddressSpaceSlot{AddressSpaceSlot{}} ** MAX_TASKS,
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
        .provenance_start = 0,
        .provenance_count = 0,
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
        .executable_loaded = false,
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
    address_space: AddressSpaceRecord,
    replace_address_space_id: u64,
) Error!runtime_host.HostAssignment(ProcessClass, NamespaceClass) {
    return runtime_host.reassignHost(
        Error,
        ProcessClass,
        NamespaceClass,
        self,
        component_class,
        owner_task_id,
        address_space,
        replace_address_space_id,
    );
}

pub fn saturatingSub(current: usize, amount: usize) usize {
    return runtime_host.saturatingSub(current, amount);
}

pub fn zeroTaskCold() TaskColdRecord {
    return .{};
}

pub fn resetTaskCold(dest: *TaskColdRecord) void {
    zeroBytes(std.mem.asBytes(dest));
    dest.capability_generation = 1;
}

pub fn copyTaskColdForTask(dest: *TaskColdRecord, src: *const TaskColdRecord, task: *const TaskRecord) void {
    copySlots(ExecutionComponentRecord, dest.execution_components[0..task.execution_component_count], src.execution_components[0..task.execution_component_count]);
    copySlots(u64, dest.capability_ids[0..task.capability_count], src.capability_ids[0..task.capability_count]);
    dest.capability_generation = src.capability_generation;
    copyAuditTrailForTask(dest, src, task);
    copyProvenanceTrailForTask(dest, src, task);
}

fn copyAuditTrailForTask(dest: *TaskColdRecord, src: *const TaskColdRecord, task: *const TaskRecord) void {
    var index: usize = 0;
    while (index < task.audit_count) : (index += 1) {
        const slot_index = (task.audit_start + index) % MAX_AUDIT_EVENTS;
        dest.audit_trail[slot_index] = src.audit_trail[slot_index];
    }
}

fn copyProvenanceTrailForTask(dest: *TaskColdRecord, src: *const TaskColdRecord, task: *const TaskRecord) void {
    var index: usize = 0;
    while (index < task.provenance_count) : (index += 1) {
        const slot_index = (task.provenance_start + index) % MAX_TASK_PROVENANCE_EVENTS;
        dest.provenance_trail[slot_index] = src.provenance_trail[slot_index];
    }
}

pub fn taskCold(task: *TaskRecord) *TaskColdRecord {
    return task.cold_state orelse native_util.impossibleByInvariant("active task records are bound to cold state storage");
}

pub fn taskColdConst(task: *const TaskRecord) *const TaskColdRecord {
    return task.cold_state orelse &detached_task_cold;
}

pub fn copyTaskColdStates(task_slots: []const TaskSlot, dest: []TaskColdRecord, src: []const TaskColdRecord) void {
    var index: usize = 0;
    while (index < dest.len) : (index += 1) {
        resetTaskCold(&dest[index]);
        if (index >= task_slots.len or !task_slots[index].in_use) continue;
        copyTaskColdForTask(&dest[index], &src[index], &task_slots[index].task);
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
    const len = @min(dest.len, src.len);
    var index: usize = 0;
    while (index < len) : (index += 1) {
        dest[index] = src[index];
    }
}

pub fn zeroBytes(dest: []u8) void {
    var index: usize = 0;
    while (index < dest.len) : (index += 1) {
        dest[index] = 0;
    }
}

pub fn taskCapabilityIndex(task: *const TaskRecord, capability_id: u64) ?usize {
    if (capability_id == 0) return null;
    for (task.capabilityIds(), 0..) |attached_capability_id, capability_index| {
        if (attached_capability_id == capability_id) return capability_index;
    }
    return null;
}

pub fn taskHasCapability(task: *const TaskRecord, capability_id: u64) bool {
    return taskCapabilityIndex(task, capability_id) != null;
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

pub fn findAddressSpaceSlot(self: anytype, address_space_id: u64) ?*AddressSpaceSlot {
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

fn expectInvalidUserspaceImage(image: ExecutableImageSpec) !void {
    try std.testing.expectError(error.InvalidUserspaceImage, validateUserspaceImage(image));
}

test "userspace image validation accepts a bounded executable layout" {
    const image = syntheticUserspaceImage("layout-test", "layout-test.entry");
    const validated = try validateUserspaceImage(image);

    try std.testing.expectEqual(DEFAULT_SYNTHETIC_ENTRY_POINT, validated.entry_point);
    try std.testing.expectEqual(
        DEFAULT_SYNTHETIC_ENTRY_POINT + launch_helpers.SYNTHETIC_SEGMENT_ALIGNMENT,
        validated.bootstrap_mailbox_address,
    );
}

test "executable image equality compares metadata and active segments" {
    const image = syntheticUserspaceImage("equality-test", "equality-test.entry");
    var other = image;
    try std.testing.expect(image.eql(&other));

    other.segments[0].file_size += 1;
    try std.testing.expect(!image.eql(&other));

    other = image;
    other.segments[image.segment_count].file_size = 1;
    try std.testing.expect(image.eql(&other));

    other.segment_count = other.segments.len + 1;
    try std.testing.expect(!image.eql(&other));
}

test "userspace image validation rejects addresses outside the user interval" {
    const valid = syntheticUserspaceImage("layout-test", "layout-test.entry");

    var below_floor = valid;
    below_floor.entry_point = USER_VIRTUAL_ADDRESS_MIN - USER_PAGE_SIZE;
    below_floor.segments[0].virtual_address = below_floor.entry_point;
    try expectInvalidUserspaceImage(below_floor);

    var segment_overflow = valid;
    segment_overflow.bootstrap_mailbox_address = 0;
    segment_overflow.segments[1].virtual_address = std.math.maxInt(u64) - (USER_PAGE_SIZE - 1);
    try expectInvalidUserspaceImage(segment_overflow);

    var stack_below_floor = valid;
    stack_below_floor.stack_top = USER_STACK_ADDRESS_MIN;
    try expectInvalidUserspaceImage(stack_below_floor);

    var segment_in_shared_window = valid;
    segment_in_shared_window.bootstrap_mailbox_address = 0;
    segment_in_shared_window.segments[1].virtual_address = USER_IMAGE_ADDRESS_MAX_EXCLUSIVE;
    try expectInvalidUserspaceImage(segment_in_shared_window);
}

test "userspace image validation rejects malformed rounded mappings" {
    const valid = syntheticUserspaceImage("layout-test", "layout-test.entry");

    var unaligned_segment = valid;
    unaligned_segment.bootstrap_mailbox_address = 0;
    unaligned_segment.segments[1].virtual_address += 1;
    try expectInvalidUserspaceImage(unaligned_segment);

    var invalid_alignment = valid;
    invalid_alignment.segments[0].alignment = 0x1800;
    try expectInvalidUserspaceImage(invalid_alignment);

    var address_misaligned_for_segment = valid;
    address_misaligned_for_segment.segments[1].alignment = USER_PAGE_SIZE * 2;
    try expectInvalidUserspaceImage(address_misaligned_for_segment);

    var overlapping_segments = valid;
    overlapping_segments.bootstrap_mailbox_address = 0;
    overlapping_segments.segments[1].virtual_address = overlapping_segments.segments[0].virtual_address;
    overlapping_segments.segments[1].file_offset = 0;
    try expectInvalidUserspaceImage(overlapping_segments);

    var stack_collision = valid;
    stack_collision.stack_size_bytes = USER_PAGE_SIZE;
    stack_collision.stack_top = valid.segments[1].virtual_address + USER_PAGE_SIZE;
    try expectInvalidUserspaceImage(stack_collision);
}

test "userspace image validation rejects invalid file and execution extents" {
    const valid = syntheticUserspaceImage("layout-test", "layout-test.entry");

    var file_extent = valid;
    file_extent.segments[1].file_offset = DEFAULT_SYNTHETIC_IMAGE_BYTES;
    try expectInvalidUserspaceImage(file_extent);

    var entry_in_writable_segment = valid;
    entry_in_writable_segment.entry_point = entry_in_writable_segment.segments[1].virtual_address;
    try expectInvalidUserspaceImage(entry_in_writable_segment);

    var entry_in_rounded_padding = valid;
    entry_in_rounded_padding.segments[0].memory_size = 1;
    entry_in_rounded_padding.segments[0].file_size = 1;
    entry_in_rounded_padding.entry_point = entry_in_rounded_padding.segments[0].virtual_address + 1;
    try expectInvalidUserspaceImage(entry_in_rounded_padding);

    var writable_executable = valid;
    writable_executable.segments[0].access.write = true;
    try expectInvalidUserspaceImage(writable_executable);
}

test "userspace image validation requires the mailbox to fit writable memory" {
    const valid = syntheticUserspaceImage("layout-test", "layout-test.entry");

    var missing_mailbox = valid;
    missing_mailbox.bootstrap_mailbox_address = 0;
    try expectInvalidUserspaceImage(missing_mailbox);

    var mailbox_in_executable_memory = valid;
    mailbox_in_executable_memory.bootstrap_mailbox_address = mailbox_in_executable_memory.segments[0].virtual_address;
    try expectInvalidUserspaceImage(mailbox_in_executable_memory);

    var mailbox_straddles_segment = valid;
    mailbox_straddles_segment.bootstrap_mailbox_address =
        mailbox_straddles_segment.segments[1].virtual_address + SYNTHETIC_MAILBOX_STRADDLE_OFFSET;
    try expectInvalidUserspaceImage(mailbox_straddles_segment);

    var misaligned_mailbox = valid;
    misaligned_mailbox.bootstrap_mailbox_address += 1;
    try expectInvalidUserspaceImage(misaligned_mailbox);
}

test "userspace image validation binds exact region boundaries" {
    const valid = syntheticUserspaceImage("layout-test", "layout-test.entry");

    var image_at_upper_bound = valid;
    image_at_upper_bound.segments[1].virtual_address = USER_IMAGE_ADDRESS_MAX_EXCLUSIVE - USER_PAGE_SIZE;
    image_at_upper_bound.bootstrap_mailbox_address = image_at_upper_bound.segments[1].virtual_address;
    _ = try validateUserspaceImage(image_at_upper_bound);

    var image_crossing_upper_bound = image_at_upper_bound;
    image_crossing_upper_bound.segments[1].memory_size = @intCast(USER_PAGE_SIZE + 1);
    try expectInvalidUserspaceImage(image_crossing_upper_bound);

    var stack_at_upper_bound = valid;
    stack_at_upper_bound.stack_top = USER_VIRTUAL_ADDRESS_MAX_EXCLUSIVE;
    stack_at_upper_bound.stack_size_bytes = USER_PAGE_SIZE;
    _ = try validateUserspaceImage(stack_at_upper_bound);

    var stack_crossing_upper_bound = stack_at_upper_bound;
    stack_crossing_upper_bound.stack_top += USER_PAGE_SIZE;
    try expectInvalidUserspaceImage(stack_crossing_upper_bound);
}

const SYNTHETIC_MAILBOX_STRADDLE_OFFSET: u64 =
    launch_helpers.SYNTHETIC_SEGMENT_BYTES - 8;
