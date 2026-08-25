const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const debug_contract = @import("../security/debug_contract.zig");
const device_broker = @import("device_broker.zig");
const endpoint = @import("endpoint.zig");
const ids = @import("../core/ids.zig");
const kernel_access = @import("native_kernel_access.zig");
const kernel_descriptors = @import("native_kernel_descriptors.zig");
const operation_metadata = @import("operation_metadata.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("../task/generated_image_fixtures.zig") else struct {};
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const shared_memory = @import("shared_memory.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");

pub const EndpointCreateResult = struct {
    endpoint: abi.EndpointDescriptor,
    capability: abi.CapabilityDescriptor,
    capability_id: u64,
};

pub const EndpointReceiveResult = struct {
    message: abi.EndpointMessageDescriptor,
    attached_capability: ?abi.CapabilityDescriptor = null,
};

pub const SharedMemoryCreateResult = struct {
    object: abi.SharedMemoryDescriptor,
    capability: abi.CapabilityDescriptor,
    capability_id: u64,
};

pub const FocusedInputReceiver = struct {
    context: *anyopaque,
    poll: *const fn (context: *anyopaque, task_id: u64) ?abi.InputEventDescriptor,
};

pub const SurfacePresentStatus = enum(u8) {
    accepted,
    duplicate,
    stale,
    invalid_surface,
    full,
};

pub const SurfacePresentationReceiver = struct {
    context: *anyopaque,
    present: *const fn (
        context: *anyopaque,
        task: *const task_runtime.TaskRecord,
        presentation: *const abi.SurfacePresentation,
    ) SurfacePresentStatus,
};

pub const AuthorityGraphEdge = debug_contract.AuthorityGraphEdge;

pub const KernelTarget = union(enum) {
    none,
    task: u64,
    endpoint: u64,
    service: u64,
    shared_memory: u64,
    capability: u64,
    device: u64,
    policy: u64,
};

pub const KernelCallContext = struct {
    caller_task_id: u64,
    presented_capability_id: u64,
    target: KernelTarget,
};
pub const TYPED_METHOD_DERIVES_KERNEL_OPERATION = true;
pub const KERNEL_CALL_CONTEXT_SIZE_CEILING_BYTES: usize = 32;
pub const AUTHORIZATION_TASK_INDEX_LOOKUPS_PER_CALL: usize = 1;
pub const RESOLVED_TASK_BUDGET_RELOOKUPS_PER_CALL: usize = 0;
pub const GRANT_PLAN_TASK_INDEX_LOOKUPS_PER_UNIQUE_TASK: usize = 1;
pub const GRANT_ATTACHMENT_TASK_INDEX_LOOKUPS_PER_ENTRY: usize = 0;
pub const RESOLVED_TASK_REVOCATION_INDEX_LOOKUPS_PER_ENTRY: usize = 0;
pub const SUBJECT_TASK_INDEX_RELOOKUPS_PER_CALL: usize = 0;
pub const SINGLE_AUTO_GRANT_TASK_INDEX_RELOOKUPS: usize = 0;
pub const SCOPED_MINT_TASK_INDEX_RELOOKUPS: usize = 0;
pub const CAPABILITY_PASS_QUERY_RELOOKUPS: usize = 0;
pub const TASK_CREATE_AUDIT_INDEX_RELOOKUPS: usize = 0;
pub const SELF_TARGET_TASK_INDEX_RELOOKUPS_PER_CALL: usize = 0;

comptime {
    if (@sizeOf(KernelCallContext) > KERNEL_CALL_CONTEXT_SIZE_CEILING_BYTES) {
        @compileError("kernel call context exceeds its compact size ceiling");
    }
}

const AuthorizationInput = struct {
    request_task_id: ?u64 = null,
    request_local_only: ?bool = null,
    target_capability: ?*const capability.Capability = null,
};

const AuthorizationResult = struct {
    resolved_capability: capability.ResolvedCapability,
    subject_task: ?*task_runtime.TaskRecord,
};

const SubjectTaskAuthorization = struct {
    capability: *const capability.Capability,
    task: *task_runtime.TaskRecord,
};

pub const Error = task_runtime.Error || capability.Error || device_broker.Error || endpoint.Error || shared_memory.Error || error{
    InvalidCapabilityTarget,
    InvalidUserspaceImage,
    PermissionDenied,
    ResourceBudgetExceeded,
    ScopeViolation,
    SubjectTaskMismatch,
    UserspaceLaunchRequired,
    InvalidSurfacePresentation,
    StaleSurfacePresentation,
    SurfacePresentationUnavailable,
};

pub const Kernel = struct {
    policy_authority: principal.PrincipalId,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    endpoint_table: *endpoint.Table,
    shared_memory_table: *shared_memory.Table,
    focused_input_receiver: ?FocusedInputReceiver = null,
    surface_presentation_receiver: ?SurfacePresentationReceiver = null,
    pub fn init(
        policy_authority: principal.PrincipalId,
        runtime: *task_runtime.Runtime,
        capability_table: *capability.CapabilityTable,
        endpoint_table: *endpoint.Table,
        shared_memory_table: *shared_memory.Table,
    ) Kernel {
        return .{
            .policy_authority = policy_authority,
            .runtime = runtime,
            .capability_table = capability_table,
            .endpoint_table = endpoint_table,
            .shared_memory_table = shared_memory_table,
        };
    }

    pub fn bindFocusedInputReceiver(self: *Kernel, receiver: FocusedInputReceiver) void {
        self.focused_input_receiver = receiver;
    }

    pub fn clearFocusedInputReceiver(self: *Kernel) void {
        self.focused_input_receiver = null;
    }

    pub fn bindSurfacePresentationReceiver(self: *Kernel, receiver: SurfacePresentationReceiver) void {
        self.surface_presentation_receiver = receiver;
    }

    pub fn clearSurfacePresentationReceiver(self: *Kernel) void {
        self.surface_presentation_receiver = null;
    }

    pub fn taskCreate(
        self: *Kernel,
        context: KernelCallContext,
        request: task_runtime.TaskCreateRequest,
        now_ticks: u64,
    ) Error!abi.TaskDescriptor {
        _ = try self.authorizeOperation(.task_create, context, now_ticks, .{
            .request_local_only = request.local_only,
        });
        try validateTaskCreateRequest(request);

        const task = try self.runtime.createTask(request);
        task.appendAudit(.{
            .kind = .created,
            .tick = now_ticks,
        });
        return taskDescriptor(task);
    }

    pub fn taskTerminate(self: *Kernel, context: KernelCallContext, now_ticks: u64) Error!bool {
        const task_capability = try self.authorizeOperation(.task_terminate, context, now_ticks, .{});
        const task_id = task_capability.target.id;
        const task_handle = self.runtime.taskHandle(task_id) orelse return error.TaskNotFound;
        const task = self.runtime.findByHandle(task_handle, task_id) orelse return error.TaskNotFound;
        var held_capability_ids: [task_runtime.MAX_TASK_CAPABILITIES]u64 = undefined;
        const held_capability_count = task.capability_count;
        @memcpy(held_capability_ids[0..held_capability_count], task.capabilityIds());
        const terminated = try self.runtime.terminateTaskByHandle(task_handle, task_id, now_ticks);
        if (!terminated) return false;
        _ = self.capability_table.retireHeldTaskAuthority(task_id, held_capability_ids[0..held_capability_count]);
        self.retireCapabilityTarget(.{ .kind = .task, .id = task_id });
        const retired_endpoints = self.endpoint_table.retireTask(ids.task(task_id));
        for (retired_endpoints.retiredEndpointIds()) |endpoint_id| {
            self.retireCapabilityTarget(.{ .kind = .endpoint, .id = endpoint_id.raw() });
        }
        const retired_shared_memory = self.shared_memory_table.retireTask(ids.task(task_id));
        for (retired_shared_memory.revokedObjectIds()) |object_id| {
            self.retireCapabilityTarget(.{ .kind = .shared_memory, .id = object_id.raw() });
        }
        return true;
    }

    pub fn endpointCreate(
        self: *Kernel,
        context: KernelCallContext,
        owner_task_id: u64,
        label: []const u8,
        flags: endpoint.EndpointFlags,
        now_ticks: u64,
    ) Error!EndpointCreateResult {
        const authorization = try self.authorizeOperationWithSubject(.endpoint_create, context, now_ticks, .{
            .request_task_id = owner_task_id,
            .request_local_only = flags.local_only,
        });

        const task = try self.taskForAuthorizedRequest(authorization, owner_task_id);
        try self.validateEndpointBudget(task);
        const created = try self.endpoint_table.create(ids.task(owner_task_id), label, flags);
        const endpoint_capability = try self.applySingleAutoGrant(
            .endpoint_create,
            .created_endpoint_owner,
            task,
            .{ .kind = .endpoint, .id = created.id.raw() },
            flags.local_only,
            now_ticks,
        );

        return .{
            .endpoint = try self.endpoint_table.descriptor(created.id),
            .capability = capabilityDescriptor(&endpoint_capability),
            .capability_id = endpoint_capability.id,
        };
    }

    pub fn endpointConnect(
        self: *Kernel,
        context: KernelCallContext,
        peer_endpoint_capability_id: u64,
        peer_endpoint_id: u64,
        now_ticks: u64,
    ) Error!abi.EndpointDescriptor {
        const endpoint_capability = try self.authorizeOperation(.endpoint_connect, context, now_ticks, .{});
        const peer_capability = try self.requirePeerEndpointCapability(
            peer_endpoint_capability_id,
            peer_endpoint_id,
            now_ticks,
        );
        if (endpoint_capability.scope.local_only != peer_capability.scope.local_only) return error.ScopeViolation;
        try self.endpoint_table.connect(ids.endpoint(endpoint_capability.target.id), ids.endpoint(peer_endpoint_id));
        return self.endpoint_table.descriptor(ids.endpoint(endpoint_capability.target.id));
    }

    pub fn endpointSend(
        self: *Kernel,
        context: KernelCallContext,
        correlation_id: u64,
        payload: []const u8,
        attached_capability_id: ?u64,
        move_attached_capability: bool,
        now_ticks: u64,
    ) Error!void {
        const endpoint_capability = try self.authorizeOperation(.endpoint_send, context, now_ticks, .{});
        if (attached_capability_id) |capability_id| {
            const attached = if (context.caller_task_id != 0)
                try self.requireTaskCapability(context.caller_task_id, capability_id, now_ticks)
            else
                try self.capability_table.requireUsable(capability_id, now_ticks);
            if (!attached.rights.has(.capability_pass)) return error.PermissionDenied;
            if (attached.scope.task_id != endpoint_capability.scope.task_id) return error.ScopeViolation;
        }

        try self.endpoint_table.send(
            ids.endpoint(endpoint_capability.target.id),
            ids.task(endpoint_capability.scope.task_id orelse 0),
            correlation_id,
            payload,
            if (attached_capability_id) |id| ids.capability(id) else null,
            move_attached_capability,
        );
    }

    pub fn endpointRecv(
        self: *Kernel,
        context: KernelCallContext,
        receiver_task_id: u64,
        payload_out: []u8,
        now_ticks: u64,
    ) Error!?EndpointReceiveResult {
        const authorization = try self.authorizeSubjectTaskOperation(.endpoint_recv, context, receiver_task_id, now_ticks, .{
            .request_task_id = receiver_task_id,
        });
        const endpoint_capability = authorization.capability;

        const message = (try self.endpoint_table.recvInto(
            ids.endpoint(endpoint_capability.target.id),
            payload_out,
        )) orelse return null;
        var result = EndpointReceiveResult{
            .message = .{
                .endpoint_id = endpoint_capability.target.id,
                .sender_task_id = message.sender_task_id.raw(),
                .correlation_id = message.correlation_id,
                .attached_capability_id = if (message.attached_capability_id) |id| id.raw() else 0,
                .payload_len = @intCast(message.len),
                .flags = @bitCast(message.flags),
            },
        };

        if (message.attached_capability_id) |attached_capability_id| {
            const receiver = authorization.task;
            try validateRuntimeGrantForTask(receiver, 1);
            const resolved_original = try self.capability_table.resolveUsable(attached_capability_id.raw(), now_ticks);
            const original = resolved_original.capability.*;
            const passed = try self.capability_table.passResolved(.{
                .capability_id = attached_capability_id.raw(),
                .new_holder = receiver.owner,
                .now_ticks = now_ticks,
                .revoke_source = message.move_attached_capability,
                .allow_task_retarget = true,
                .scope = retargetTaskScope(original.scope, receiver_task_id),
                .audit = .{
                    .policy_generation = original.audit.policy_generation,
                    .source_task_id = message.sender_task_id.raw(),
                    .broker_service_id = original.audit.broker_service_id,
                },
            }, resolved_original);
            errdefer self.capability_table.rollbackGrant(&.{passed});
            try task_runtime.grantCapabilityToTask(receiver, passed.id);

            if (message.move_attached_capability) {
                if (original.scope.task_id) |source_task_id| {
                    _ = try self.runtime.revokeCapability(source_task_id, original.id);
                }
            }

            result.attached_capability = capabilityDescriptor(&passed);
        }

        return result;
    }

    pub fn capabilityMint(
        self: *Kernel,
        context: KernelCallContext,
        request: capability.MintRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        const authorization = try self.authorizeOperationWithSubject(.capability_mint, context, now_ticks, .{
            .request_task_id = request.scope.task_id,
        });
        const target_task = if (request.scope.task_id) |task_id| blk: {
            const task = try self.taskForAuthorizedRequest(authorization, task_id);
            if (!task.owner.eql(request.holder)) return error.PermissionDenied;
            break :blk task;
        } else null;

        var plan = capability.GrantPlan{};
        if (request.scope.task_id) |task_id| {
            try plan.addMint(task_id, request);
        } else {
            try plan.addMint(0, request);
        }
        var minted_buffer: [capability.MAX_GRANT_PLAN_ENTRIES]capability.Capability = undefined;
        const minted = (try self.applyGrantPlan(&plan, &minted_buffer, target_task))[0];
        return capabilityDescriptor(&minted);
    }

    fn applyGrantPlan(
        self: *Kernel,
        plan: *const capability.GrantPlan,
        output: []capability.Capability,
        first_task: ?*task_runtime.TaskRecord,
    ) Error![]capability.Capability {
        var runtime_tasks = [_]?*task_runtime.TaskRecord{null} ** capability.MAX_GRANT_PLAN_ENTRIES;
        runtime_tasks[0] = first_task;
        try self.validateRuntimeGrantPlan(plan, &runtime_tasks);
        const minted = try self.capability_table.applyGrantPlan(plan, output);
        var attached_count: usize = 0;
        errdefer {
            var revoke_index: usize = 0;
            while (revoke_index < attached_count) : (revoke_index += 1) {
                const entry = plan.entries[revoke_index];
                if (entry.task_id != 0) {
                    if (!task_runtime.revokeCapabilityFromTask(runtime_tasks[revoke_index].?, minted[revoke_index].id)) {
                        native_util.impossibleByInvariant("rollback revokes capabilities attached earlier in this kernel grant transaction");
                    }
                }
            }
            self.capability_table.rollbackGrant(minted);
        }
        for (plan.slice(), minted, 0..) |entry, granted_capability, entry_index| {
            if (entry.task_id != 0) {
                try task_runtime.grantCapabilityToTask(runtime_tasks[entry_index].?, granted_capability.id);
            }
            attached_count += 1;
        }
        return minted;
    }

    fn applySingleGrantPlan(
        self: *Kernel,
        task: *task_runtime.TaskRecord,
        request: capability.MintRequest,
    ) Error!struct { capability: capability.Capability } {
        var plan = capability.GrantPlan{};
        try plan.addMint(task.id, request);
        var minted_buffer: [1]capability.Capability = undefined;
        const minted = try self.applyGrantPlan(&plan, &minted_buffer, task);
        return .{ .capability = minted[0] };
    }

    fn applySingleAutoGrant(
        self: *Kernel,
        comptime operation: abi.NativeOperation,
        comptime grant_kind: operation_metadata.AutoGrantKind,
        task: *task_runtime.TaskRecord,
        target: capability.CapabilityTarget,
        request_local_only: bool,
        now_ticks: u64,
    ) Error!capability.Capability {
        const grant = operation_metadata.autoGrantFor(operation, grant_kind);
        const scoped_task_id: ?u64 = if (grant.task_scoped) task.id else null;
        const local_only = switch (grant.locality) {
            .request => request_local_only,
            .always_local => true,
        };
        return (try self.applySingleGrantPlan(task, .{
            .holder = task.owner,
            .issuer = self.policy_authority,
            .target = target,
            .rights = grant.rights,
            .scope = .{
                .task_id = scoped_task_id,
                .local_only = local_only,
                .broker_only = grant.broker_only,
            },
            .lease = .{
                .issued_at_ticks = now_ticks,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = grant.renewable,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = task.id,
            },
        })).capability;
    }

    pub fn capabilityDerive(self: *Kernel, context: KernelCallContext, request: capability.DeriveRequest) Error!abi.CapabilityDescriptor {
        const authorization = try self.authorizeOperationWithSubject(.capability_derive, context, request.lease.issued_at_ticks, .{
            .request_task_id = request.scope.task_id,
        });
        const target_task = if (request.scope.task_id) |task_id| blk: {
            const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
            if (!task.owner.eql(request.holder)) return error.PermissionDenied;
            try validateRuntimeGrantForTask(task, 1);
            break :blk task;
        } else null;
        const derived = try self.capability_table.deriveResolved(request, authorization.resolved_capability);
        errdefer self.capability_table.rollbackGrant(&.{derived});
        if (target_task) |task| {
            try task_runtime.grantCapabilityToTask(task, derived.id);
        }
        return capabilityDescriptor(&derived);
    }

    pub fn capabilityPass(
        self: *Kernel,
        context: KernelCallContext,
        receiver_task_id: u64,
        now_ticks: u64,
        revoke_source: bool,
    ) Error!abi.CapabilityDescriptor {
        const capability_id = context.presented_capability_id;
        const authorization = try self.authorizeOperationWithSubject(.capability_pass, context, now_ticks, .{});
        const original = authorization.resolved_capability.capability.*;
        const receiver = self.runtime.find(receiver_task_id) orelse return error.TaskNotFound;
        try validateRuntimeGrantForTask(receiver, 1);
        const passed = try self.capability_table.passResolved(.{
            .capability_id = capability_id,
            .new_holder = receiver.owner,
            .now_ticks = now_ticks,
            .revoke_source = revoke_source,
            .allow_task_retarget = true,
            .scope = retargetTaskScope(original.scope, receiver_task_id),
            .audit = .{
                .policy_generation = original.audit.policy_generation,
                .source_task_id = original.scope.task_id orelse 0,
                .broker_service_id = original.audit.broker_service_id,
            },
        }, authorization.resolved_capability);
        errdefer self.capability_table.rollbackGrant(&.{passed});
        try task_runtime.grantCapabilityToTask(receiver, passed.id);
        if (revoke_source) {
            if (original.scope.task_id) |source_task_id| {
                _ = try self.runtime.revokeCapability(source_task_id, original.id);
            }
        }
        return capabilityDescriptor(&passed);
    }

    pub fn capabilityRevoke(self: *Kernel, context: KernelCallContext, capability_id: u64, now_ticks: u64) Error!void {
        const resolved_revoked = self.capability_table.resolve(capability_id) orelse return error.CapabilityNotFound;
        const revoked = resolved_revoked.capability.*;
        _ = try self.authorizeOperation(.capability_revoke, context, now_ticks, .{
            .target_capability = &revoked,
        });
        try self.capability_table.revokeTargetAuthorityResolved(capability_id, resolved_revoked);
        if (revoked.scope.task_id) |task_id| {
            _ = try self.runtime.revokeCapability(task_id, capability_id);
        }
    }

    pub fn capabilityQuery(
        self: *Kernel,
        context: KernelCallContext,
        capability_id: u64,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        const queried = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        _ = try self.authorizeOperation(.capability_query, context, now_ticks, .{
            .target_capability = &queried,
        });
        return capabilityDescriptor(&queried);
    }

    pub fn sharedMemoryCreate(
        self: *Kernel,
        context: KernelCallContext,
        owner_task_id: u64,
        size_bytes: usize,
        now_ticks: u64,
    ) Error!SharedMemoryCreateResult {
        const authorization = try self.authorizeOperationWithSubject(.shared_memory_create, context, now_ticks, .{
            .request_task_id = owner_task_id,
        });

        const task = try self.taskForAuthorizedRequest(authorization, owner_task_id);
        try self.validateSharedMemoryCreateBudget(task, size_bytes);
        const object = try self.shared_memory_table.create(ids.task(owner_task_id), size_bytes);
        const object_capability = try self.applySingleAutoGrant(
            .shared_memory_create,
            .created_shared_memory_owner,
            task,
            .{ .kind = .shared_memory, .id = object.id.raw() },
            true,
            now_ticks,
        );

        return .{
            .object = try self.shared_memory_table.descriptor(object.id),
            .capability = capabilityDescriptor(&object_capability),
            .capability_id = object_capability.id,
        };
    }

    pub fn sharedMemoryMap(
        self: *Kernel,
        context: KernelCallContext,
        task_id: u64,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        const authorization = try self.authorizeSubjectTaskOperation(.shared_memory_map, context, task_id, now_ticks, .{
            .request_task_id = task_id,
        });
        const object_capability = authorization.capability;
        const object_id = ids.sharedMemory(object_capability.target.id);
        if (!self.shared_memory_table.hasMapping(object_id, ids.task(task_id))) {
            const object_size = try self.shared_memory_table.objectSize(object_id);
            try self.validateSharedMemoryMapBudget(authorization.task, object_size);
        }
        try self.shared_memory_table.map(object_id, ids.task(task_id));
        return self.shared_memory_table.descriptor(object_id);
    }

    pub fn sharedMemoryUnmap(
        self: *Kernel,
        context: KernelCallContext,
        task_id: u64,
        now_ticks: u64,
    ) Error!bool {
        const authorization = try self.authorizeSubjectTaskOperation(.shared_memory_unmap, context, task_id, now_ticks, .{
            .request_task_id = task_id,
        });
        return self.shared_memory_table.unmap(ids.sharedMemory(authorization.capability.target.id), ids.task(task_id));
    }

    pub fn sharedMemoryRevoke(
        self: *Kernel,
        context: KernelCallContext,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        const object_capability = try self.authorizeOperation(.shared_memory_revoke, context, now_ticks, .{});
        const target = object_capability.target;
        const descriptor = try self.shared_memory_table.revoke(ids.sharedMemory(target.id));
        self.retireCapabilityTarget(target);
        return descriptor;
    }

    pub fn timeQuery(self: *Kernel, context: KernelCallContext, now_ticks: u64) Error!u64 {
        _ = try self.authorizeOperation(.time_query, context, now_ticks, .{});
        return now_ticks;
    }

    pub fn resourceQuery(
        self: *Kernel,
        context: KernelCallContext,
        task_id: u64,
        now_ticks: u64,
    ) Error!abi.ResourceDescriptor {
        const authorization = try self.authorizeOperationWithSubject(.resource_query, context, now_ticks, .{
            .request_task_id = task_id,
        });
        const task = try self.taskForAuthorizedRequest(authorization, task_id);
        return .{
            .task_id = task.id,
            .state = @intFromEnum(task.state),
            .capability_count = @intCast(task.capability_count),
            .endpoint_count = self.endpoint_table.activeForTask(ids.task(task_id)),
            .flags = taskFlags(task),
            .cpu_time_ticks = task.budget.cpu_time_ticks,
            .memory_bytes = task.budget.memory_bytes,
            .shared_memory_bytes = task.budget.shared_memory_bytes,
        };
    }

    pub fn accountingQuery(
        self: *Kernel,
        context: KernelCallContext,
        task_id: u64,
        now_ticks: u64,
    ) Error!abi.AccountingDescriptor {
        const authorization = try self.authorizeOperationWithSubject(.accounting_query, context, now_ticks, .{
            .request_task_id = task_id,
        });
        const task = try self.taskForAuthorizedRequest(authorization, task_id);
        return .{
            .task_id = task.id,
            .audit_event_count = @intCast(task.audit_count),
            .capability_count = @intCast(task.capability_count),
            .component_count = @intCast(task.execution_component_count),
            .endpoint_count = self.endpoint_table.activeForTask(ids.task(task_id)),
            .shared_memory_mappings = self.shared_memory_table.mappingsForTask(ids.task(task_id)),
            .ui_surface_id = task.ui_surface_id orelse 0,
        };
    }

    pub fn inputRecv(
        self: *Kernel,
        context: KernelCallContext,
        receiver_task_id: u64,
        now_ticks: u64,
    ) Error!?abi.InputEventDescriptor {
        _ = try self.authorizeSubjectTaskOperation(.input_recv, context, receiver_task_id, now_ticks, .{
            .request_task_id = receiver_task_id,
        });
        const receiver = self.focused_input_receiver orelse return null;
        const event = receiver.poll(receiver.context, receiver_task_id) orelse return null;
        if (event.task_id != receiver_task_id) return error.ScopeViolation;
        return event;
    }

    pub fn surfacePresent(
        self: *Kernel,
        context: KernelCallContext,
        presenter_task_id: u64,
        presentation: *const abi.SurfacePresentation,
        now_ticks: u64,
    ) Error!bool {
        const authorization = try self.authorizeSubjectTaskOperation(.surface_present, context, presenter_task_id, now_ticks, .{
            .request_task_id = presenter_task_id,
        });
        const task = authorization.task;
        if (task.state != .active) return error.InvalidSurfacePresentation;
        if (task.ui_surface_id == null or task.ui_surface_id.? != presentation.surface_id) return error.ScopeViolation;
        if (!abi.isCanonicalSurfacePresentation(presentation)) return error.InvalidSurfacePresentation;
        const receiver = self.surface_presentation_receiver orelse return error.SurfacePresentationUnavailable;
        return switch (receiver.present(receiver.context, task, presentation)) {
            .accepted, .duplicate => true,
            .stale => error.StaleSurfacePresentation,
            .invalid_surface => error.InvalidSurfacePresentation,
            .full => error.ResourceBudgetExceeded,
        };
    }

    pub fn deviceDescribe(
        self: *Kernel,
        context: KernelCallContext,
        now_ticks: u64,
    ) Error!abi.DeviceDescriptor {
        const device_capability = try self.authorizeOperation(.device_describe, context, now_ticks, .{});
        return deviceDescriptor(try device_broker.describe(device_capability.target.id));
    }

    pub fn deviceMmioWindow(
        self: *Kernel,
        context: KernelCallContext,
        window_index: u8,
        now_ticks: u64,
    ) Error!abi.DeviceMmioWindowDescriptor {
        const device_capability = try self.authorizeOperation(.device_mmio_window, context, now_ticks, .{});
        return mmioWindowDescriptor(try device_broker.mmioWindow(device_capability.target.id, window_index));
    }

    pub fn requireTaskCapability(
        self: *Kernel,
        task_id: u64,
        capability_id: u64,
        now_ticks: u64,
    ) Error!*const capability.Capability {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        const owned = try self.capability_table.requireUsable(capability_id, now_ticks);
        if (!task.hasCapability(capability_id)) return error.CapabilityNotFound;
        if (!task.owner.eql(owned.holder)) return error.PermissionDenied;
        if (owned.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != task_id) return error.ScopeViolation;
        }
        return owned;
    }

    pub fn taskAuthorityGraph(
        self: *Kernel,
        task_id: u64,
        now_ticks: u64,
        output: []AuthorityGraphEdge,
    ) Error![]AuthorityGraphEdge {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        var count: usize = 0;
        for (task.capabilityIds()) |capability_id| {
            if (count >= output.len) break;
            const inspected = self.capability_table.inspect(capability_id, now_ticks) orelse continue;
            output[count] = debug_contract.authorityGraphEdge(task_id, inspected.capability.*, inspected.usable);
            count += 1;
        }
        return output[0..count];
    }

    fn authorizeOperation(
        self: *Kernel,
        comptime expected_operation: abi.NativeOperation,
        context: KernelCallContext,
        now_ticks: u64,
        input: AuthorizationInput,
    ) Error!*const capability.Capability {
        return (try self.authorizeOperationWithSubject(expected_operation, context, now_ticks, input)).resolved_capability.capability;
    }

    fn authorizeSubjectTaskOperation(
        self: *Kernel,
        comptime expected_operation: abi.NativeOperation,
        context: KernelCallContext,
        task_id: u64,
        now_ticks: u64,
        input: AuthorizationInput,
    ) Error!SubjectTaskAuthorization {
        if (context.caller_task_id != 0 and context.caller_task_id != task_id) return error.SubjectTaskMismatch;
        const authorization = try self.authorizeOperationWithSubject(expected_operation, context, now_ticks, input);
        const task = authorization.subject_task orelse self.runtime.find(task_id) orelse return error.TaskNotFound;
        return .{ .capability = authorization.resolved_capability.capability, .task = task };
    }

    fn taskForAuthorizedRequest(
        self: *Kernel,
        authorization: AuthorizationResult,
        task_id: u64,
    ) Error!*task_runtime.TaskRecord {
        if (authorization.subject_task) |subject_task| {
            if (subject_task.id == task_id) return subject_task;
        }
        return self.runtime.find(task_id) orelse error.TaskNotFound;
    }

    fn authorizeOperationWithSubject(
        self: *Kernel,
        comptime expected_operation: abi.NativeOperation,
        context: KernelCallContext,
        now_ticks: u64,
        input: AuthorizationInput,
    ) Error!AuthorizationResult {
        const descriptor = operation_metadata.declarationFor(expected_operation);

        const subject_task = if (context.caller_task_id != 0)
            (self.runtime.find(context.caller_task_id) orelse return error.TaskNotFound)
        else
            null;

        const resolved = try self.capability_table.resolveUsable(context.presented_capability_id, now_ticks);
        const owned = resolved.capability;

        if (subject_task) |task| {
            if (!task.hasCapability(context.presented_capability_id)) return error.CapabilityNotFound;
            if (!task.owner.eql(owned.holder)) return error.PermissionDenied;
            if (owned.scope.task_id) |scoped_task_id| {
                if (scoped_task_id != context.caller_task_id) return error.ScopeViolation;
            }
        }

        const base_rights = capability.CapabilityRights.single(descriptor.required_right);
        switch (descriptor.target_kind) {
            .none => {
                if (!owned.rights.containsAll(base_rights)) return error.PermissionDenied;
            },
            .fixed => |target_kind| {
                if (!owned.rights.containsAll(base_rights)) return error.PermissionDenied;
                if (owned.target.kind != target_kind) return error.InvalidCapabilityTarget;
                try validateContextTarget(context.target, owned.target);
            },
            .same_as_target_capability => {
                const target_capability = input.target_capability orelse return error.InvalidCapabilityTarget;
                if (!owned.rights.containsAll(base_rights.retarget(target_capability.target.kind))) return error.PermissionDenied;
                if (owned.target.kind != target_capability.target.kind) return error.InvalidCapabilityTarget;
                if (!owned.target.eql(target_capability.target)) return error.InvalidCapabilityTarget;
                try validateContextTarget(context.target, target_capability.target);
            },
        }
        try validateOperationScope(descriptor.scope_rule, owned.scope, input);
        return .{ .resolved_capability = resolved, .subject_task = subject_task };
    }

    fn requireTargetedCapability(
        self: *Kernel,
        capability_id: u64,
        now_ticks: u64,
        needed_rights: capability.CapabilityRights,
        target_kind: capability.CapabilityTargetKind,
    ) Error!*const capability.Capability {
        return kernel_access.requireTargetedCapability(
            Error,
            self,
            capability_id,
            now_ticks,
            needed_rights,
            target_kind,
        );
    }

    fn requirePeerEndpointCapability(
        self: *Kernel,
        peer_endpoint_capability_id: u64,
        peer_endpoint_id: u64,
        now_ticks: u64,
    ) Error!*const capability.Capability {
        const peer = try self.requireTargetedCapability(
            peer_endpoint_capability_id,
            now_ticks,
            .{ .endpoint = .{ .ipc_peer = true } },
            .endpoint,
        );
        if (peer.target.id != peer_endpoint_id) return error.InvalidCapabilityTarget;
        return peer;
    }

    fn validateRuntimeGrantPlan(
        self: *Kernel,
        plan: *const capability.GrantPlan,
        tasks: *[capability.MAX_GRANT_PLAN_ENTRIES]?*task_runtime.TaskRecord,
    ) Error!void {
        for (plan.slice(), 0..) |entry, index| {
            if (entry.task_id == 0) continue;
            var planned_for_task: usize = 1;
            var task = tasks[index];
            if (task) |resolved_task| {
                if (resolved_task.id != entry.task_id) {
                    native_util.impossibleByInvariant("pre-resolved grant task matches its transaction entry");
                }
            }
            for (plan.entries[0..index], 0..) |candidate, candidate_index| {
                if (candidate.task_id == entry.task_id) {
                    planned_for_task += 1;
                    if (task == null) task = tasks[candidate_index];
                }
            }
            const resolved_task = task orelse self.runtime.find(entry.task_id) orelse return error.TaskNotFound;
            try validateRuntimeGrantForTask(resolved_task, planned_for_task);
            tasks[index] = resolved_task;
        }
    }

    fn retireCapabilityTarget(self: *Kernel, target: capability.CapabilityTarget) void {
        var retired_buffer: [capability.MAX_CAPABILITIES]capability.RetiredAuthority = undefined;
        const retired_count = self.capability_table.retireTargetAuthorityInto(target, &retired_buffer);
        if (retired_count > retired_buffer.len) {
            native_util.impossibleByInvariant("capability retirement output covers the capability table");
        }
        for (retired_buffer[0..retired_count]) |retired| {
            if (retired.scoped_task_id) |task_id| {
                if (self.runtime.find(task_id)) |task| {
                    _ = task_runtime.revokeCapabilityFromTask(task, retired.capability_id);
                }
            } else {
                _ = self.runtime.revokeCapabilityEverywhere(retired.capability_id);
            }
        }
    }

    fn validateEndpointBudget(self: *Kernel, task: *const task_runtime.TaskRecord) Error!void {
        if (self.endpoint_table.activeForTask(ids.task(task.id)) >= task.budget.endpoint_slots) {
            return error.ResourceBudgetExceeded;
        }
    }

    fn validateSharedMemoryCreateBudget(self: *Kernel, task: *const task_runtime.TaskRecord, size_bytes: usize) Error!void {
        const allocated = self.shared_memory_table.liveOwnedBytesForTask(ids.task(task.id));
        const next_allocated = std.math.add(usize, allocated, size_bytes) catch return error.ResourceBudgetExceeded;
        if (next_allocated > task.budget.shared_memory_bytes) return error.ResourceBudgetExceeded;
    }

    fn validateSharedMemoryMapBudget(self: *Kernel, task: *const task_runtime.TaskRecord, size_bytes: usize) Error!void {
        const mapped = self.shared_memory_table.liveMappedBytesForTask(ids.task(task.id));
        const next_mapped = std.math.add(usize, mapped, size_bytes) catch return error.ResourceBudgetExceeded;
        if (next_mapped > task.budget.shared_memory_bytes) return error.ResourceBudgetExceeded;
    }
};

fn validateRuntimeGrantForTask(task: *const task_runtime.TaskRecord, additional_count: usize) Error!void {
    if (task.capability_count + additional_count > task_runtime.MAX_TASK_CAPABILITIES) {
        return error.CapabilityTableFull;
    }
}

fn taskDescriptor(task: *const task_runtime.TaskRecord) abi.TaskDescriptor {
    return kernel_descriptors.taskDescriptor(task);
}

fn taskFlags(task: *const task_runtime.TaskRecord) u16 {
    return kernel_descriptors.taskFlags(task);
}

fn validateTaskCreateRequest(request: task_runtime.TaskCreateRequest) Error!void {
    return kernel_access.validateTaskCreateRequest(Error, request);
}

fn capabilityDescriptor(owned: *const capability.Capability) abi.CapabilityDescriptor {
    return kernel_descriptors.capabilityDescriptor(owned);
}

fn deviceDescriptor(descriptor: device_broker.ControllerDescriptor) abi.DeviceDescriptor {
    return kernel_descriptors.deviceDescriptor(descriptor);
}

fn mmioWindowDescriptor(window: device_broker.MmioWindow) abi.DeviceMmioWindowDescriptor {
    return kernel_descriptors.mmioWindowDescriptor(window);
}

fn retargetTaskScope(original: capability.CapabilityScope, receiver_task_id: u64) capability.CapabilityScope {
    return kernel_access.retargetTaskScope(original, receiver_task_id);
}

fn validateOperationScope(
    rule: operation_metadata.ScopeRule,
    scope: capability.CapabilityScope,
    input: AuthorizationInput,
) Error!void {
    if (rule.task_scope_matches_request_task) {
        if (scope.task_id) |scoped_task_id| {
            if (input.request_task_id == null or input.request_task_id.? != scoped_task_id) return error.ScopeViolation;
        }
    }
    if (rule.local_scope_requires_request_local and scope.local_only) {
        if (input.request_local_only != true) return error.ScopeViolation;
    }
}

fn validateContextTarget(context_target: KernelTarget, capability_target: capability.CapabilityTarget) Error!void {
    const matches = switch (context_target) {
        .none => true,
        .task => |id| capability_target.kind == .task and capability_target.id == id,
        .endpoint => |id| capability_target.kind == .endpoint and capability_target.id == id,
        .service => |id| capability_target.kind == .service and capability_target.id == id,
        .shared_memory => |id| capability_target.kind == .shared_memory and capability_target.id == id,
        .capability => true,
        .device => |id| capability_target.kind == .device and capability_target.id == id,
        .policy => |id| capability_target.kind == .policy and capability_target.id == id,
    };
    if (!matches) return error.InvalidCapabilityTarget;
}

fn testContext(operation: abi.NativeOperation, capability_id: u64, target: KernelTarget) KernelCallContext {
    _ = operation;
    return .{
        .caller_task_id = 0,
        .presented_capability_id = capability_id,
        .target = target,
    };
}

const test_policy_authority: principal.PrincipalId = .{ .kind = .policy_authority, .serial = 1 };

const TestKernelHarness = struct {
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    shared: shared_memory.Table = shared_memory.Table.init(),

    fn kernel(self: *TestKernelHarness) Kernel {
        return Kernel.init(
            test_policy_authority,
            &self.runtime,
            &self.capabilities,
            &self.endpoints,
            &self.shared,
        );
    }

    fn createSessionTask(self: *TestKernelHarness) task_runtime.Error!*task_runtime.TaskRecord {
        return self.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = 2 },
            .component_class = .session_manager,
            .budget = .{
                .cpu_time_ticks = 10_000,
                .memory_bytes = shared_memory.PAGE_SIZE,
                .endpoint_slots = 8,
                .shared_memory_bytes = shared_memory.PAGE_SIZE,
            },
            .local_only = true,
        });
    }

    fn mintSessionServiceAuthority(
        self: *TestKernelHarness,
        session_task: *const task_runtime.TaskRecord,
        rights: capability.CapabilityRights,
    ) capability.Error!capability.Capability {
        return self.capabilities.mintBootRoot(.{
            .holder = session_task.owner,
            .issuer = test_policy_authority,
            .target = .{ .kind = .service, .id = 42 },
            .rights = rights,
            .scope = .{ .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
        });
    }
};

test "moving a capability removes its source task attachment" {
    var harness = TestKernelHarness{};
    var kernel = harness.kernel();
    const source_task = try harness.createSessionTask();
    const receiver_task = try harness.runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = shared_memory.PAGE_SIZE,
            .endpoint_slots = 2,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
        },
        .local_only = true,
    });
    const source_capability = try harness.capabilities.mintBootRoot(.{
        .holder = source_task.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{ .service = .{ .capability_pass = true } },
        .scope = .{ .task_id = source_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    try harness.runtime.grantCapability(source_task.id, source_capability.id);

    var context = testContext(.capability_pass, source_capability.id, .none);
    context.caller_task_id = source_task.id;
    const passed = try kernel.capabilityPass(context, receiver_task.id, 10, true);

    try std.testing.expect(harness.capabilities.query(source_capability.id) == null);
    try std.testing.expect(!source_task.hasCapability(source_capability.id));
    try std.testing.expect(receiver_task.hasCapability(passed.capability_id));
}

test "capability derivation is bound to its authorized source" {
    var harness = TestKernelHarness{};
    var kernel = harness.kernel();
    const source_task = try harness.createSessionTask();
    const receiver_task = try harness.runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = shared_memory.PAGE_SIZE,
            .endpoint_slots = 2,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
        },
        .local_only = true,
    });
    const rights = capability.CapabilityRights{ .service = .{
        .capability_derive = true,
        .time_query = true,
    } };
    const authorized_source = try harness.mintSessionServiceAuthority(source_task, rights);
    const other_source = try harness.mintSessionServiceAuthority(source_task, rights);
    try harness.runtime.grantCapability(source_task.id, authorized_source.id);
    try harness.runtime.grantCapability(source_task.id, other_source.id);

    var request = capability.DeriveRequest{
        .parent_capability_id = other_source.id,
        .holder = receiver_task.owner,
        .rights = .{ .service = .{ .time_query = true } },
        .scope = .{ .task_id = receiver_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 100 },
    };
    var context = testContext(.capability_derive, authorized_source.id, .none);
    context.caller_task_id = source_task.id;
    try std.testing.expectError(error.CapabilityNotFound, kernel.capabilityDerive(context, request));

    request.parent_capability_id = authorized_source.id;
    const derived = try kernel.capabilityDerive(context, request);
    try std.testing.expect(receiver_task.hasCapability(derived.capability_id));
}

test "native kernel creates tasks endpoints and shared memory without owning service discovery" {
    var harness = TestKernelHarness{};
    var kernel = harness.kernel();
    const session_task = try harness.createSessionTask();
    const authority_capability = try harness.mintSessionServiceAuthority(session_task, .{ .service = .{
        .task_create = true,
        .endpoint_create = true,
        .endpoint_connect = true,
        .endpoint_send = true,
        .endpoint_recv = true,
        .shared_memory_create = true,
        .shared_memory_map = true,
        .shared_memory_unmap = true,
        .shared_memory_revoke = true,
        .resource_query = true,
        .accounting_query = true,
        .time_query = true,
        .ipc_peer = true,
        .capability_query = true,
    } });
    try task_runtime.grantCapabilityToTask(session_task, authority_capability.id);

    const workspace_storage_image = try generated_image_fixtures.workspaceStorageImage();
    const example_client_image = try generated_image_fixtures.serviceClientImage();
    const service_task_desc = try kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .service, .serial = 3 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
            .resource_class = .emergency_system_critical,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 10,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.service.object-store",
        },
        .userspace_image = &workspace_storage_image,
    }, 5);
    const app_task_desc = try kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
            .resource_class = .batch_compute,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 11,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.client",
        },
        .userspace_image = &example_client_image,
    }, 6);
    try std.testing.expect(abi.taskFlagsHas(service_task_desc.flags, abi.TASK_FLAG_LOCAL_ONLY));
    try std.testing.expect(abi.taskFlagsHas(service_task_desc.flags, abi.TASK_FLAG_ZERO_AMBIENT_AUTHORITY));
    try std.testing.expect(abi.taskFlagsHas(service_task_desc.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(abi.taskFlagsHas(service_task_desc.flags, abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED));
    try std.testing.expectEqual(@as(u8, @intFromEnum(accelerator_scheduler.ResourceClass.emergency_system_critical)), abi.taskFlagsResourceClass(service_task_desc.flags));
    try std.testing.expectEqual(@as(u8, @intFromEnum(accelerator_scheduler.ResourceClass.batch_compute)), abi.taskFlagsResourceClass(app_task_desc.flags));

    const service_endpoint = try kernel.endpointCreate(testContext(.endpoint_create, authority_capability.id, .{ .task = service_task_desc.task_id }), service_task_desc.task_id, "zigos.object.workspace", .{
        .local_only = true,
        .service_port = true,
    }, 7);

    const app_endpoint = try kernel.endpointCreate(testContext(.endpoint_create, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, "app.endpoint", .{
        .local_only = true,
    }, 8);
    _ = try kernel.endpointConnect(testContext(.endpoint_connect, app_endpoint.capability_id, .none), service_endpoint.capability_id, service_endpoint.endpoint.endpoint_id, 8);

    const shared_result = try kernel.sharedMemoryCreate(testContext(.shared_memory_create, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, shared_memory.PAGE_SIZE, 9);
    try kernel.endpointSend(testContext(.endpoint_send, app_endpoint.capability_id, .none), 11, "sync-open", shared_result.capability_id, false, 9);
    var received_payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try kernel.endpointRecv(testContext(.endpoint_recv, service_endpoint.capability_id, .none), service_task_desc.task_id, &received_payload, 10)).?;
    try std.testing.expectEqualStrings("sync-open", received_payload[0..received.message.payload_len]);
    try std.testing.expect(received.attached_capability != null);

    _ = try kernel.sharedMemoryMap(testContext(.shared_memory_map, shared_result.capability_id, .none), app_task_desc.task_id, 10);
    const resources = try kernel.resourceQuery(testContext(.resource_query, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, 10);
    const accounting = try kernel.accountingQuery(testContext(.accounting_query, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, 10);
    try std.testing.expectEqual(@as(u16, 1), resources.endpoint_count);
    try std.testing.expect(accounting.audit_event_count >= 1);
    try std.testing.expectEqual(@as(u8, @intFromEnum(accelerator_scheduler.ResourceClass.batch_compute)), abi.taskFlagsResourceClass(resources.flags));

    var self_resource_context = testContext(.resource_query, authority_capability.id, .{ .task = session_task.id });
    self_resource_context.caller_task_id = session_task.id;
    const self_resources = try kernel.resourceQuery(self_resource_context, session_task.id, 10);
    var self_accounting_context = testContext(.accounting_query, authority_capability.id, .{ .task = session_task.id });
    self_accounting_context.caller_task_id = session_task.id;
    const self_accounting = try kernel.accountingQuery(self_accounting_context, session_task.id, 10);
    try std.testing.expectEqual(session_task.id, self_resources.task_id);
    try std.testing.expectEqual(session_task.id, self_accounting.task_id);

    try std.testing.expectEqual(@as(u64, 10), try kernel.timeQuery(testContext(.time_query, authority_capability.id, .none), 10));
}

test "native kernel descriptor authorization enforces request task scope" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );

    const scoped_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 7 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
    });
    const other_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 8 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
    });
    const authority = try capabilities.mintBootRoot(.{
        .holder = scoped_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 77 },
        .rights = .{ .service = .{ .resource_query = true } },
        .scope = .{ .task_id = scoped_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    });
    try runtime.grantCapability(scoped_task.id, authority.id);

    var context = testContext(.resource_query, authority.id, .{ .task = scoped_task.id });
    context.caller_task_id = scoped_task.id;
    _ = try kernel.resourceQuery(context, scoped_task.id, 10);

    context.target = .{ .task = other_task.id };
    try std.testing.expectError(error.ScopeViolation, kernel.resourceQuery(context, other_task.id, 10));
}

test "native kernel rejects app and service launches without signed userspace image provenance" {
    var harness = TestKernelHarness{};
    var kernel = harness.kernel();
    const session_task = try harness.createSessionTask();
    const authority_capability = try harness.mintSessionServiceAuthority(session_task, .{ .service = .{
        .task_create = true,
    } });
    const unsigned_app_image = try generated_image_fixtures.appImage();
    const missing_bundle_image = try generated_image_fixtures.serviceImage();

    try std.testing.expectError(error.UserspaceLaunchRequired, kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
    }, 5));
    try std.testing.expectError(error.InvalidUserspaceImage, kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .service, .serial = 5 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 0,
            .component_abi_version = 1,
            .signed = true,
        },
    }, 6));
    try std.testing.expectError(error.InvalidUserspaceImage, kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .app, .serial = 6 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 16,
            .component_abi_version = 1,
            .signed = false,
            .bundle_id = "app.unsigned",
        },
        .userspace_image = &unsigned_app_image,
    }, 7));
    try std.testing.expectError(error.InvalidUserspaceImage, kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .service, .serial = 7 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 17,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "",
        },
        .userspace_image = &missing_bundle_image,
    }, 8));
}

test "native kernel leaves typed service registration outside the TCB" {
    var harness = TestKernelHarness{};
    var kernel = harness.kernel();
    const session_task = try harness.createSessionTask();
    const authority_capability = try harness.mintSessionServiceAuthority(session_task, .{ .service = .{
        .endpoint_create = true,
        .endpoint_connect = true,
        .ipc_peer = true,
    } });

    const direct_service_task = try harness.runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 7 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
        .initial_component = .{
            .label = "direct-service",
            .entry = "zigos.direct.service",
        },
    });
    _ = try kernel.endpointCreate(testContext(.endpoint_create, authority_capability.id, .{ .task = direct_service_task.id }), direct_service_task.id, "zigos.direct.service", .{
        .local_only = true,
        .service_port = true,
    }, 5);
    try std.testing.expect(!@hasDecl(Kernel, "serviceRegister"));
    try std.testing.expect(!@hasDecl(Kernel, "serviceConnect"));
}

test "capability mint query revoke and task termination are exposed by the native kernel" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );

    const target_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 7 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
    });
    const admin_capability = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .policy_authority, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .policy, .id = 1 },
        .rights = .{ .policy = .{
            .capability_mint = true,
            .capability_query = true,
            .capability_revoke = true,
            .task_terminate = true,
        } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });
    const task_capability = try capabilities.mintBootRoot(.{
        .holder = target_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = target_task.id },
        .rights = .{ .task = .{ .task_terminate = true } },
        .scope = .{ .task_id = target_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
    });
    try runtime.grantCapability(target_task.id, task_capability.id);
    const external_task_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .policy_authority, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = target_task.id },
        .rights = .{ .task = .{ .task_terminate = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
    });
    const task_endpoint = try endpoints.create(ids.task(target_task.id), "terminated-task", .{});
    try std.testing.expectEqual(@as(u16, 1), endpoints.activeForTask(ids.task(target_task.id)));
    const owned_shared = try shared.create(ids.task(target_task.id), shared_memory.PAGE_SIZE);
    const peer_shared = try shared.create(ids.task(999), shared_memory.PAGE_SIZE);
    try shared.map(owned_shared.id, ids.task(target_task.id));
    try shared.map(owned_shared.id, ids.task(999));
    try shared.map(peer_shared.id, ids.task(target_task.id));
    try shared.map(peer_shared.id, ids.task(999));
    try std.testing.expectEqual(@as(u16, 2), shared.mappingsForTask(ids.task(target_task.id)));
    const external_endpoint_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .policy_authority, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .endpoint, .id = task_endpoint.id.raw() },
        .rights = .{ .endpoint = .{ .endpoint_connect = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
    });
    const external_owned_shared_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .policy_authority, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .shared_memory, .id = owned_shared.id.raw() },
        .rights = .{ .shared_memory = .{ .shared_memory_map = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
    });
    const external_peer_shared_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .policy_authority, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .shared_memory, .id = peer_shared.id.raw() },
        .rights = .{ .shared_memory = .{ .shared_memory_map = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
    });

    const minted = try kernel.capabilityMint(testContext(.capability_mint, admin_capability.id, .{ .policy = 1 }), .{
        .holder = target_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .object, .id = 55 },
        .rights = .{ .object = .{
            .object_read = true,
            .capability_query = true,
            .capability_revoke = true,
        } },
        .scope = .{ .task_id = target_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    }, 10);
    try std.testing.expectEqual(@as(u64, 55), minted.target_id);

    var graph_edges: [4]AuthorityGraphEdge = undefined;
    const graph = try kernel.taskAuthorityGraph(target_task.id, 10, &graph_edges);
    try std.testing.expectEqual(@as(usize, 2), graph.len);
    var found_minted = false;
    for (graph) |edge| {
        if (edge.capability_id == minted.capability_id) {
            found_minted = true;
            try std.testing.expectEqual(capability.CapabilityTargetKind.object, edge.target_kind);
            try std.testing.expectEqual(@as(u64, 55), edge.target_id);
            try std.testing.expect(edge.trace_id != 0);
            try std.testing.expect(edge.usable);
        }
    }
    try std.testing.expect(found_minted);

    var unowned_query = testContext(.capability_query, admin_capability.id, .{ .capability = minted.capability_id });
    unowned_query.caller_task_id = target_task.id;
    try std.testing.expectError(error.CapabilityNotFound, kernel.capabilityQuery(unowned_query, minted.capability_id, 10));

    try std.testing.expectError(error.InvalidCapabilityTarget, kernel.capabilityQuery(testContext(.capability_query, admin_capability.id, .{ .capability = minted.capability_id }), minted.capability_id, 10));
    _ = try kernel.capabilityQuery(testContext(.capability_query, minted.capability_id, .{ .capability = minted.capability_id }), minted.capability_id, 10);
    try std.testing.expectError(error.InvalidCapabilityTarget, kernel.capabilityRevoke(testContext(.capability_revoke, admin_capability.id, .{ .capability = minted.capability_id }), minted.capability_id, 10));
    try kernel.capabilityRevoke(testContext(.capability_revoke, minted.capability_id, .{ .capability = minted.capability_id }), minted.capability_id, 10);
    try std.testing.expect(capabilities.query(minted.capability_id) == null);
    try std.testing.expect(try kernel.taskTerminate(testContext(.task_terminate, task_capability.id, .none), 11));
    try std.testing.expect(capabilities.query(task_capability.id) == null);
    try std.testing.expect(capabilities.query(external_task_authority.id) == null);
    try std.testing.expect(capabilities.query(external_endpoint_authority.id) == null);
    try std.testing.expect(capabilities.query(external_owned_shared_authority.id) == null);
    try std.testing.expect(capabilities.query(external_peer_shared_authority.id) != null);
    try std.testing.expect(capabilities.query(admin_capability.id) != null);
    try std.testing.expectEqual(@as(u16, 0), endpoints.activeForTask(ids.task(target_task.id)));
    try std.testing.expectError(error.EndpointNotFound, endpoints.descriptor(task_endpoint.id));
    try std.testing.expectEqual(@as(u16, 0), shared.mappingsForTask(ids.task(target_task.id)));
    try std.testing.expectError(error.SharedMemoryNotFound, shared.descriptor(owned_shared.id));
    try std.testing.expectEqual(@as(u16, 0), (try shared.descriptor(peer_shared.id)).flags);
    try std.testing.expect(!shared.hasMapping(peer_shared.id, ids.task(target_task.id)));
    try std.testing.expect(shared.hasMapping(peer_shared.id, ids.task(999)));
}

test "task authority graph marks target-revoked capabilities unusable" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );

    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 77 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
    });
    const authority = try capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .object, .id = 900 },
        .rights = .{ .object = .{
            .capability_derive = true,
            .object_read = true,
        } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    });
    const derived = try capabilities.derive(.{
        .parent_capability_id = authority.id,
        .holder = task.owner,
        .rights = .{ .object = .{ .object_read = true } },
        .scope = authority.scope,
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 90, .renewable = false },
    });
    try runtime.grantCapability(task.id, derived.id);
    try capabilities.revokeTargetAuthority(authority.id);
    try std.testing.expectError(error.CapabilityRevoked, kernel.requireTaskCapability(task.id, derived.id, 10));

    var graph_edges: [2]AuthorityGraphEdge = undefined;
    const graph = try kernel.taskAuthorityGraph(task.id, 10, &graph_edges);
    try std.testing.expectEqual(@as(usize, 1), graph.len);
    try std.testing.expectEqual(derived.id, graph[0].capability_id);
    try std.testing.expect(!graph[0].usable);
}

test "capability grant plan does not mint when runtime attachment cannot fit" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );

    const target_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 7 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
    });
    const admin_capability = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .policy_authority, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .policy, .id = 1 },
        .rights = .{ .policy = .{ .capability_mint = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });

    var index: usize = 0;
    while (index < task_runtime.MAX_TASK_CAPABILITIES) : (index += 1) {
        const existing = try capabilities.mintBootRoot(.{
            .holder = target_task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .object, .id = 1000 + index },
            .rights = .{ .object = .{ .object_read = true } },
            .scope = .{ .task_id = target_task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
        });
        try runtime.grantCapability(target_task.id, existing.id);
    }

    const capability_count = capabilities.activeCount();
    const capability_mutation_generation = capabilities.mutationGeneration();
    try std.testing.expectError(error.CapabilityTableFull, kernel.capabilityMint(testContext(.capability_mint, admin_capability.id, .{ .policy = 1 }), .{
        .holder = target_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .object, .id = 55 },
        .rights = .{ .object = .{ .object_read = true } },
        .scope = .{ .task_id = target_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    }, 10));
    try std.testing.expectEqual(capability_count, capabilities.activeCount());
    try std.testing.expectEqual(capability_mutation_generation, capabilities.mutationGeneration());
}

test "native kernel brokers device metadata and port io through device capabilities" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );

    const storage_driver_test_image = try generated_image_fixtures.storageDriverImage();
    const driver_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 4 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 40,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.storage-driver",
        },
        .userspace_image = &storage_driver_test_image,
    });
    const device_capability = try capabilities.mintBootRoot(.{
        .holder = driver_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .device, .id = 0x1F001 },
        .rights = .{ .device = .{ .device_use = true } },
        .scope = .{
            .task_id = driver_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 12,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
    });
    try runtime.grantCapability(driver_task.id, device_capability.id);

    device_broker.reset();
    defer device_broker.reset();
    try std.testing.expect(device_broker.publishPciController(0x1F001));

    const descriptor = try kernel.deviceDescribe(testContext(.device_describe, device_capability.id, .none), 12);
    try std.testing.expectEqual(@as(u64, 0x1F001), descriptor.device_id);
    try std.testing.expectEqual(@as(u8, 0), descriptor.mmio_window_count);
    try std.testing.expectError(error.UnsupportedMmioWindow, kernel.deviceMmioWindow(testContext(.device_mmio_window, device_capability.id, .none), 0, 12));
}
