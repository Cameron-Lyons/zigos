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
        text: ?*const abi.SurfaceText,
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
pub const CAPABILITY_MUTATION_SELF_TASK_INDEX_RELOOKUPS: usize = 0;
pub const CAPABILITY_PASS_SOURCE_TASK_INDEX_RELOOKUPS: usize = 0;
pub const ATTACHED_CAPABILITY_TASK_INDEX_RELOOKUPS_PER_SEND: usize = 0;
pub const MOVED_CAPABILITY_RECEIVE_TASK_INDEX_RELOOKUPS: usize = 0;
pub const TASK_TERMINATE_PREVIEW_SLOT_LOOKUPS: usize = 0;
pub const TASK_TERMINATE_HANDLE_DERIVATIONS: usize = 0;

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

pub const EndpointWakeSink = struct {
    context: *anyopaque,
    wake: *const fn (context: *anyopaque, receiver_task_id: u64, now_ticks: u64) void,
};

pub const Kernel = struct {
    policy_authority: principal.PrincipalId,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    endpoint_table: *endpoint.Table,
    shared_memory_table: *shared_memory.Table,
    focused_input_receiver: ?FocusedInputReceiver = null,
    surface_presentation_receiver: ?SurfacePresentationReceiver = null,
    endpoint_wake_sink: ?EndpointWakeSink = null,
    // The runtime retains this address until deinit; initialize only in stable
    // storage, and unbind before either this kernel or its runtime is released.
    pub fn initInPlace(
        self: *Kernel,
        policy_authority: principal.PrincipalId,
        runtime: *task_runtime.Runtime,
        capability_table: *capability.CapabilityTable,
        endpoint_table: *endpoint.Table,
        shared_memory_table: *shared_memory.Table,
    ) void {
        self.* = .{
            .policy_authority = policy_authority,
            .runtime = runtime,
            .capability_table = capability_table,
            .endpoint_table = endpoint_table,
            .shared_memory_table = shared_memory_table,
        };
        if (!runtime.bindTaskRetirementSink(self.retirementSink())) {
            native_util.impossibleByInvariant("a task runtime has exactly one live kernel resource owner");
        }
    }

    pub fn deinit(self: *Kernel) void {
        const current = self.runtime.task_retirement_sink orelse return;
        const expected = self.retirementSink();
        if (current.eql(expected) and !self.runtime.unbindTaskRetirementSink(expected))
            native_util.impossibleByInvariant("kernel resource owner outlives every execution lease");
    }

    fn retirementSink(self: *Kernel) task_runtime.TaskRetirementSink {
        return .{ .context = self, .retire = retireTaskForRuntime };
    }

    pub fn bindFocusedInputReceiver(self: *Kernel, receiver: FocusedInputReceiver) void {
        self.focused_input_receiver = receiver;
    }

    pub fn bindEndpointWakeSink(self: *Kernel, sink: EndpointWakeSink) void {
        self.endpoint_wake_sink = sink;
    }

    pub fn clearEndpointWakeSink(self: *Kernel) void {
        self.endpoint_wake_sink = null;
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
        const authorization = try self.authorizeOperationWithSubject(.task_terminate, context, now_ticks, .{});
        const task_id = authorization.resolved_capability.capability.target.id;
        const task = try self.taskForAuthorizedRequest(authorization, task_id);
        return self.runtime.terminateResolvedTask(task, now_ticks);
    }

    fn retireTaskResources(self: *Kernel, retirement: task_runtime.TaskRetirement) void {
        const task_id = retirement.task_id;
        _ = self.capability_table.retireHeldTaskAuthority(task_id, retirement.capability_ids);
        self.retireCapabilityTarget(.{ .kind = .task, .id = task_id });
        const retired_endpoints = self.endpoint_table.retireTask(ids.task(task_id), .{
            .context = self.capability_table,
            .release = releaseQueuedMove,
        });
        const retired_shared_memory = self.shared_memory_table.retireTask(ids.task(task_id));
        for (retired_shared_memory.revokedObjectIds()) |object_id| {
            self.retireCapabilityTarget(.{ .kind = .shared_memory, .id = object_id.raw() });
        }
        self.completeEndpointRetirement(&retired_endpoints, retirement.now_ticks);
    }

    fn completeEndpointRetirement(self: *Kernel, retired: *const endpoint.Retirement, now_ticks: u64) void {
        for (retired.retiredEndpointIds()) |endpoint_id| {
            self.retireCapabilityTarget(.{ .kind = .endpoint, .id = endpoint_id.raw() });
        }
        if (self.endpoint_wake_sink) |sink| {
            for (retired.disconnectedTaskIds()) |task_id| sink.wake(sink.context, task_id.raw(), now_ticks);
        }
    }

    pub fn endpointClose(self: *Kernel, context: KernelCallContext, now_ticks: u64) Error!void {
        const authorized = try self.authorizeOperation(.endpoint_close, context, now_ticks, .{});
        try self.retireEndpoint(ids.endpoint(authorized.target.id), now_ticks);
    }

    // Trusted channel owners retain generational endpoint ids for teardown,
    // including after policy revokes the endpoint's userspace grants.
    pub fn retireEndpoint(self: *Kernel, endpoint_id: ids.EndpointId, now_ticks: u64) endpoint.Error!void {
        const retired = try self.endpoint_table.close(endpoint_id, .{
            .context = self.capability_table,
            .release = releaseQueuedMove,
        });
        self.completeEndpointRetirement(&retired, now_ticks);
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
        try validateRuntimeGrantForTask(task, 1);
        const created = try self.endpoint_table.create(ids.task(owner_task_id), label, flags);
        errdefer self.endpoint_table.rollbackCreate(created.id);
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
        if (context.caller_task_id == 0) try self.requireCallerZeroCapabilityAdmission(peer_capability);
        if (endpoint_capability.scope.local_only != peer_capability.scope.local_only) return error.ScopeViolation;
        try self.requireEndpointOwnerAdmission(endpoint_capability.target.id);
        try self.requireEndpointOwnerAdmission(peer_endpoint_id);
        try self.endpoint_table.connect(ids.endpoint(endpoint_capability.target.id), ids.endpoint(peer_endpoint_id));
        return self.endpoint_table.descriptor(ids.endpoint(endpoint_capability.target.id));
    }

    pub fn endpointSend(
        self: *Kernel,
        context: KernelCallContext,
        correlation_id: u64,
        payload: []const u8,
        reply_endpoint_id: u64,
        attached_capability_id: ?u64,
        move_attached_capability: bool,
        now_ticks: u64,
    ) Error!void {
        const authorization = try self.authorizeOperationWithSubject(.endpoint_send, context, now_ticks, .{});
        const endpoint_capability = authorization.resolved_capability.capability;
        // Either endpoint can remain physically owned by a stopped dispatch,
        // even when a live task holds its delegated grant.
        const source = try self.endpoint_table.routing(ids.endpoint(endpoint_capability.target.id));
        try self.requireEndpointTaskAdmission(source.owner_task_id.raw(), authorization.subject_task);
        const destination = if (reply_endpoint_id != 0) reply_endpoint_id else source.peer_endpoint_id.raw();
        if (destination != 0) try self.requireEndpointOwnerAdmission(destination);
        var move_source_task: ?*task_runtime.TaskRecord = null;
        var moved_attachment: ?capability.ResolvedCapability = null;
        if (attached_capability_id) |capability_id| {
            const attached = if (authorization.subject_task) |caller_task|
                try self.requireResolvedTaskCapability(caller_task, capability_id, now_ticks)
            else blk: {
                const owned = try self.capability_table.requireUsable(capability_id, now_ticks);
                try self.requireCallerZeroCapabilityAdmission(owned);
                break :blk owned;
            };
            if (!attached.rights.has(.capability_pass)) return error.PermissionDenied;
            if (attached.scope.task_id != endpoint_capability.scope.task_id) return error.ScopeViolation;
            if (move_attached_capability) {
                moved_attachment = self.capability_table.resolve(capability_id) orelse
                    native_util.impossibleByInvariant("freshly resolved capability remains in its slot");
                if (attached.scope.task_id) |source_task_id| {
                    move_source_task = try self.taskForAuthorizedRequest(authorization, source_task_id);
                }
            }
        }

        const sender_task_id = if (authorization.subject_task) |task| task.id else endpoint_capability.scope.task_id orelse 0;
        const receiver_task_id = if (reply_endpoint_id != 0)
            try self.endpoint_table.reply(
                ids.endpoint(endpoint_capability.target.id),
                ids.endpoint(reply_endpoint_id),
                ids.task(sender_task_id),
                correlation_id,
                payload,
                if (attached_capability_id) |id| ids.capability(id) else null,
                move_attached_capability,
            )
        else
            try self.endpoint_table.send(
                ids.endpoint(endpoint_capability.target.id),
                ids.task(sender_task_id),
                correlation_id,
                payload,
                if (attached_capability_id) |id| ids.capability(id) else null,
                move_attached_capability,
            );
        if (moved_attachment) |resolved| {
            // Enqueue and this ownership commit are one serialized BSP
            // transaction. No callback can observe a queued usable gift.
            self.capability_table.commitQueuedMoveResolved(resolved, attached_capability_id.?);
            if (move_source_task) |source_task| {
                _ = task_runtime.revokeCapabilityFromTask(source_task, attached_capability_id.?);
            } else {
                _ = self.runtime.revokeCapabilityEverywhere(attached_capability_id.?);
            }
        }
        if (self.endpoint_wake_sink) |sink| {
            sink.wake(sink.context, receiver_task_id.raw(), now_ticks);
        }
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
                .sender_endpoint_id = message.sender_endpoint_id.raw(),
                .sender_task_id = message.sender_task_id.raw(),
                .correlation_id = message.correlation_id,
                .attached_capability_id = if (message.attached_capability_id) |id| id.raw() else 0,
                .payload_len = @intCast(message.len),
                .flags = @bitCast(message.flags),
            },
        };

        if (message.attached_capability_id) |attached_capability_id| {
            // Dequeue transfers responsibility for an in-flight move here.
            // A failed receive must release it if no recipient was attached.
            errdefer if (message.move_attached_capability) releaseQueuedMove(self.capability_table, attached_capability_id);
            const receiver = authorization.task;
            try validateRuntimeGrantForTask(receiver, 1);
            const resolved_original = if (message.move_attached_capability)
                self.capability_table.resolve(attached_capability_id.raw()) orelse return error.CapabilityNotFound
            else
                try self.capability_table.resolveUsable(attached_capability_id.raw(), now_ticks);
            const original = resolved_original.capability.*;
            const pass_request = capability.PassRequest{
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
            };
            const passed = if (message.move_attached_capability)
                try self.capability_table.passQueuedMove(pass_request)
            else
                try self.capability_table.passResolved(pass_request, resolved_original);
            errdefer self.capability_table.rollbackGrant(&.{passed});
            try task_runtime.grantCapabilityToTask(receiver, passed.id);

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

        var plan = capability.SingleGrantPlan{};
        if (request.scope.task_id) |task_id| {
            try plan.addMint(task_id, request);
        } else {
            try plan.addMint(0, request);
        }
        var minted_buffer: [1]capability.Capability = undefined;
        const minted = (try self.applyGrantPlan(&plan, &minted_buffer, target_task))[0];
        return capabilityDescriptor(&minted);
    }

    fn applyGrantPlan(
        self: *Kernel,
        plan: anytype,
        output: []capability.Capability,
        first_task: ?*task_runtime.TaskRecord,
    ) Error![]capability.Capability {
        const capacity = @typeInfo(@TypeOf(plan.entries)).array.len;
        var runtime_tasks = @as([capacity]?*task_runtime.TaskRecord, @splat(null));
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

    fn applySingleGrant(
        self: *Kernel,
        task: *task_runtime.TaskRecord,
        request: capability.MintRequest,
    ) Error!capability.Capability {
        try validateRuntimeGrantForTask(task, 1);
        const minted = try self.capability_table.mintSingle(request);
        errdefer self.capability_table.rollbackSingleGrant(minted.id);
        try task_runtime.grantCapabilityToTask(task, minted.id);
        return minted;
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
        return self.applySingleGrant(task, .{
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
        });
    }

    pub fn capabilityDerive(self: *Kernel, context: KernelCallContext, request: capability.DeriveRequest, now_ticks: u64) Error!abi.CapabilityDescriptor {
        const authorization = try self.authorizeOperationWithSubject(.capability_derive, context, now_ticks, .{
            .request_task_id = request.scope.task_id,
        });
        const target_task = if (request.scope.task_id) |task_id| blk: {
            const task = try self.taskForAuthorizedRequest(authorization, task_id);
            if (!task.owner.eql(request.holder)) return error.PermissionDenied;
            try validateRuntimeGrantForTask(task, 1);
            break :blk task;
        } else null;
        const derived = try self.capability_table.deriveResolved(request, authorization.resolved_capability, now_ticks);
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
        const receiver = try self.taskForAuthorizedRequest(authorization, receiver_task_id);
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
                _ = try self.revokeCapabilityFromAuthorizedTask(authorization, source_task_id, original.id);
            } else {
                _ = self.runtime.revokeCapabilityEverywhere(original.id);
            }
        }
        return capabilityDescriptor(&passed);
    }

    pub fn capabilityRevoke(self: *Kernel, context: KernelCallContext, capability_id: u64, now_ticks: u64) Error!void {
        const resolved_revoked = self.capability_table.resolve(capability_id) orelse return error.CapabilityNotFound;
        const revoked = resolved_revoked.capability.*;
        const authorization = try self.authorizeOperationWithSubject(.capability_revoke, context, now_ticks, .{
            .target_capability = &revoked,
        });
        try self.capability_table.revokeTargetAuthorityResolved(capability_id, resolved_revoked);
        if (revoked.scope.task_id) |task_id| {
            _ = try self.revokeCapabilityFromAuthorizedTask(authorization, task_id, capability_id);
        } else {
            _ = self.runtime.revokeCapabilityEverywhere(capability_id);
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
        try validateRuntimeGrantForTask(task, 1);
        const object = try self.shared_memory_table.create(ids.task(owner_task_id), size_bytes);
        errdefer self.shared_memory_table.rollbackCreate(object.id);
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
            .state = @backingInt(task.state),
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
        text: ?*const abi.SurfaceText,
        now_ticks: u64,
    ) Error!bool {
        const authorization = try self.authorizeSubjectTaskOperation(.surface_present, context, presenter_task_id, now_ticks, .{
            .request_task_id = presenter_task_id,
        });
        const task = authorization.task;
        if (task.state != .active) return error.InvalidSurfacePresentation;
        if (task.ui_surface_id == null or task.ui_surface_id.? != presentation.surface_id) return error.ScopeViolation;
        if (!abi.isCanonicalSurfacePresentation(presentation)) return error.InvalidSurfacePresentation;
        if (text) |content| if (!content.isCanonical()) return error.InvalidSurfacePresentation;
        const receiver = self.surface_presentation_receiver orelse return error.SurfacePresentationUnavailable;
        var borrow = self.runtime.borrowResolvedTask(task);
        defer borrow.release();
        return switch (receiver.present(receiver.context, task, presentation, text)) {
            .accepted, .duplicate => if (task.state == .active) true else error.InvalidSurfacePresentation,
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
        return self.requireResolvedTaskCapability(task, capability_id, now_ticks);
    }

    fn requireResolvedTaskCapability(
        self: *Kernel,
        task: *const task_runtime.TaskRecord,
        capability_id: u64,
        now_ticks: u64,
    ) Error!*const capability.Capability {
        try requireTaskAdmission(task);
        const owned = try self.capability_table.requireUsable(capability_id, now_ticks);
        if (!task.hasCapability(capability_id)) return error.CapabilityNotFound;
        if (!task.owner.eql(owned.holder)) return error.PermissionDenied;
        if (owned.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != task.id) return error.ScopeViolation;
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
        const task = try self.taskForAuthorizedRequest(authorization, task_id);
        return .{ .capability = authorization.resolved_capability.capability, .task = task };
    }

    fn taskForAuthorizedRequest(
        self: *Kernel,
        authorization: AuthorizationResult,
        task_id: u64,
    ) Error!*task_runtime.TaskRecord {
        const task = if (authorization.subject_task) |subject_task|
            if (subject_task.id == task_id) subject_task else self.runtime.find(task_id) orelse return error.TaskNotFound
        else
            self.runtime.find(task_id) orelse return error.TaskNotFound;
        try requireTaskAdmission(task);
        return task;
    }

    fn revokeCapabilityFromAuthorizedTask(
        self: *Kernel,
        authorization: AuthorizationResult,
        task_id: u64,
        capability_id: u64,
    ) Error!bool {
        const task = try self.taskForAuthorizedRequest(authorization, task_id);
        return task_runtime.revokeCapabilityFromTask(task, capability_id);
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

        if (subject_task) |task| try requireTaskAdmission(task);

        const resolved = try self.capability_table.resolveUsable(context.presented_capability_id, now_ticks);
        const owned = resolved.capability;

        // Caller zero identifies a trusted kernel caller, rather than a bypass
        // for the authority retained while its scoped task awaits collection.
        if (subject_task == null) try self.requireCallerZeroCapabilityAdmission(owned);

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

    inline fn requireCallerZeroCapabilityAdmission(self: *Kernel, owned: *const capability.Capability) Error!void {
        if (owned.scope.task_id) |task_id| {
            if (self.runtime.findConst(task_id)) |task| try requireTaskAdmission(task);
        } else if (self.runtime.hasTerminatedCapabilityHolder(owned.id, owned.holder)) return error.TaskNotFound;
    }

    fn requireEndpointOwnerAdmission(self: *Kernel, endpoint_id: u64) Error!void {
        const route = try self.endpoint_table.routing(ids.endpoint(endpoint_id));
        try self.requireEndpointTaskAdmission(route.owner_task_id.raw(), null);
    }

    fn requireEndpointTaskAdmission(self: *Kernel, task_id: u64, subject_task: ?*const task_runtime.TaskRecord) Error!void {
        // Routing and authority admission have no callbacks. Reuse the live
        // caller when it owns the source; delegated owners still resolve here.
        const task = if (subject_task) |subject|
            if (subject.id == task_id) subject else self.runtime.findConst(task_id)
        else
            self.runtime.findConst(task_id);
        if (task) |owner| try requireTaskAdmission(owner);
    }

    fn validateRuntimeGrantPlan(
        self: *Kernel,
        plan: anytype,
        tasks: anytype,
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

fn releaseQueuedMove(context: *anyopaque, capability_id: ids.CapabilityId) void {
    const table: *capability.CapabilityTable = @ptrCast(@alignCast(context));
    _ = table.disposeQueuedMove(capability_id.raw());
}

fn retireTaskForRuntime(context: *anyopaque, retirement: task_runtime.TaskRetirement) void {
    const kernel: *Kernel = @ptrCast(@alignCast(context));
    kernel.retireTaskResources(retirement);
}

fn validateRuntimeGrantForTask(task: *const task_runtime.TaskRecord, additional_count: usize) Error!void {
    try requireTaskAdmission(task);
    if (task.capability_count + additional_count > task_runtime.MAX_TASK_CAPABILITIES) {
        return error.CapabilityTableFull;
    }
}

inline fn requireTaskAdmission(task: *const task_runtime.TaskRecord) error{TaskNotFound}!void {
    if (task.state == .terminated) return error.TaskNotFound;
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

const DeadTaskAdmissionProbe = struct {
    kernel: *Kernel,
    task: *task_runtime.TaskRecord,
    creator: u64,
    mint_authority: u64,
    gift: u64,
    mapping_authority: u64,
    retained_authority: u64,
    retained_unscoped_authority: u64,
    live_peer_id: u64,
    callbacks: usize = 0,

    fn check(self: *@This(), before_collection: bool) !void {
        const kernel = self.kernel;
        const grants = kernel.capability_table.activeCount();
        const mutation = kernel.capability_table.mutationGeneration();
        const endpoints = kernel.endpoint_table.activeCount();
        const objects = kernel.shared_memory_table.activeCount();
        const mappings = kernel.shared_memory_table.mappingsForTask(ids.task(self.task.id));
        const owned_bytes = kernel.shared_memory_table.liveOwnedBytesForTask(ids.task(self.task.id));
        const attachments = std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(self.task.capabilityIds()));
        const capability_generation = self.task.capabilityGeneration();
        const components = self.task.execution_component_count;
        const component_cursor = kernel.runtime.next_component_id;
        const audit_count = self.task.audit_count;
        const live_peer = kernel.runtime.find(self.live_peer_id).?;
        const live_attachments = std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(live_peer.capabilityIds()));
        const live_generation = live_peer.capabilityGeneration();
        const request = capability.MintRequest{
            .holder = self.task.owner,
            .issuer = test_policy_authority,
            .target = .{ .kind = .service, .id = 55 },
            .rights = .{ .service = .{ .time_query = true } },
            .scope = .{ .task_id = self.task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 12, .expires_at_ticks = 100 },
        };
        const creator_context = testContext(.endpoint_create, self.creator, .none);
        try std.testing.expectError(error.TaskNotFound, kernel.endpointCreate(creator_context, self.task.id, "stopped", .{ .local_only = true }, 12));
        try std.testing.expectError(error.TaskNotFound, kernel.sharedMemoryCreate(creator_context, self.task.id, shared_memory.PAGE_SIZE, 12));
        try std.testing.expectError(error.TaskNotFound, kernel.sharedMemoryMap(testContext(.shared_memory_map, self.mapping_authority, .none), self.task.id, 12));
        try std.testing.expectError(error.TaskNotFound, kernel.capabilityMint(testContext(.capability_mint, self.mint_authority, .none), request, 12));
        try std.testing.expectError(error.TaskNotFound, kernel.capabilityPass(testContext(.capability_pass, self.gift, .none), self.task.id, 12, true));
        try std.testing.expectError(error.TaskNotFound, kernel.capabilityDerive(testContext(.capability_derive, self.gift, .none), .{
            .parent_capability_id = self.gift,
            .holder = request.holder,
            .rights = request.rights,
            .scope = request.scope,
            .lease = request.lease,
        }, 12));
        var caller_context = testContext(.time_query, self.retained_authority, .none);
        caller_context.caller_task_id = self.task.id;
        try std.testing.expectError(error.TaskNotFound, kernel.timeQuery(caller_context, 12));
        if (before_collection) {
            try std.testing.expect(kernel.capability_table.query(self.retained_authority) != null);
            try std.testing.expectError(error.TaskNotFound, kernel.timeQuery(testContext(.time_query, self.retained_authority, .none), 12));
        }
        try std.testing.expectError(error.TaskNotFound, kernel.timeQuery(testContext(.time_query, self.retained_unscoped_authority, .none), 12));
        try std.testing.expectEqual(@as(u64, 12), try kernel.timeQuery(.{ .caller_task_id = self.live_peer_id, .presented_capability_id = self.retained_unscoped_authority, .target = .none }, 12));
        try std.testing.expectError(error.TaskNotFound, kernel.runtime.grantCapability(self.task.id, 777));
        try std.testing.expectError(error.TaskNotFound, kernel.runtime.attachComponent(self.task.id, .{ .label = "stopped", .entry = "stopped" }, 12));
        var plan = capability.GrantPlan{};
        try plan.addMint(self.task.id, request);
        var output: [1]capability.Capability = undefined;
        @memset(std.mem.asBytes(&output), 0xa5);
        try std.testing.expectError(error.TaskNotFound, kernel.applyGrantPlan(&plan, &output, null));
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&output), 0xa5));
        try std.testing.expectEqual(grants, kernel.capability_table.activeCount());
        try std.testing.expectEqual(mutation, kernel.capability_table.mutationGeneration());
        try std.testing.expectEqual(endpoints, kernel.endpoint_table.activeCount());
        try std.testing.expectEqual(objects, kernel.shared_memory_table.activeCount());
        try std.testing.expectEqual(mappings, kernel.shared_memory_table.mappingsForTask(ids.task(self.task.id)));
        try std.testing.expectEqual(owned_bytes, kernel.shared_memory_table.liveOwnedBytesForTask(ids.task(self.task.id)));
        try std.testing.expectEqual(attachments, std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(self.task.capabilityIds())));
        try std.testing.expectEqual(capability_generation, self.task.capabilityGeneration());
        try std.testing.expectEqual(components, self.task.execution_component_count);
        try std.testing.expectEqual(component_cursor, kernel.runtime.next_component_id);
        try std.testing.expectEqual(audit_count, self.task.audit_count);
        try std.testing.expectEqual(live_attachments, std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(live_peer.capabilityIds())));
        try std.testing.expectEqual(live_generation, live_peer.capabilityGeneration());
    }

    fn wake(context: *anyopaque, _: u64, _: u64) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        std.testing.expect(self.kernel.runtime.execution.hasLeaseForTask(self.task.id)) catch @panic("retirement retains its collecting lease");
        self.check(false) catch @panic("reentrant cleanup cannot recreate stopped resources");
        self.callbacks += 1;
    }
};

const TestKernelHarness = struct {
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    shared: shared_memory.Table = shared_memory.Table.init(),

    fn initKernel(self: *TestKernelHarness, kernel: *Kernel) void {
        kernel.initInPlace(
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
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
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

test "surface presentation retains the presenter across reentrant termination and churn" {
    const Receiver = struct {
        harness: *TestKernelHarness,
        kernel: *Kernel,
        context: KernelCallContext,
        task_id: u64,
        handle: task_runtime.TaskHandle,
        status: SurfacePresentStatus,
        calls: usize = 0,
        record_retained: bool = true,

        fn createApp(runtime: *task_runtime.Runtime, owner_serial: u64) task_runtime.Error!*task_runtime.TaskRecord {
            return runtime.createTask(.{
                .owner = .{ .kind = .app, .serial = owner_serial },
                .component_class = .app_component,
                .budget = .{
                    .cpu_time_ticks = 100,
                    .memory_bytes = shared_memory.PAGE_SIZE,
                    .endpoint_slots = 2,
                    .shared_memory_bytes = 0,
                },
                .local_only = true,
                .ui_surface_id = 7,
            });
        }

        fn present(
            opaque_context: *anyopaque,
            task: *const task_runtime.TaskRecord,
            _: *const abi.SurfacePresentation,
            _: ?*const abi.SurfaceText,
        ) SurfacePresentStatus {
            const self: *@This() = @ptrCast(@alignCast(opaque_context));
            const terminated = self.kernel.taskTerminate(self.context, 0) catch @panic("receiver can terminate its presenter");
            if (!terminated) @panic("presenter terminates once");
            for (0..task_runtime.MAX_TASKS + 3) |index| {
                const child = createApp(&self.harness.runtime, @intCast(index + 1000)) catch @panic("receiver churn retains task capacity");
                if (!self.harness.runtime.terminateResolvedTask(child, @intCast(index + 1000)))
                    @panic("receiver retires each churn task");
                self.record_retained = self.record_retained and task.id == self.task_id and
                    task.state == .terminated and
                    self.harness.runtime.findConstByHandle(self.handle, self.task_id) == task;
            }
            self.calls += 1;
            return self.status;
        }
    };

    for ([_]SurfacePresentStatus{ .accepted, .duplicate, .stale, .invalid_surface, .full }) |status| {
        const harness = try std.testing.allocator.create(TestKernelHarness);
        defer std.testing.allocator.destroy(harness);
        harness.* = .{};
        defer harness.runtime.reset();
        var kernel: Kernel = undefined;
        harness.initKernel(&kernel);
        defer kernel.deinit();
        const presenter = try Receiver.createApp(&harness.runtime, 7);
        const task_id = presenter.id;
        const address_space_id = presenter.address_space_id;
        const handle = harness.runtime.taskHandleForResolved(presenter);
        const slot_index = presenter.arena_slot_index;
        const authority = try harness.capabilities.mintBootRoot(.{
            .holder = presenter.owner,
            .issuer = test_policy_authority,
            .target = .{ .kind = .task, .id = task_id },
            .rights = .{ .task = .{ .surface_present = true, .task_terminate = true } },
            .scope = .{ .task_id = task_id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try harness.runtime.grantCapability(task_id, authority.id);
        const context = KernelCallContext{
            .caller_task_id = task_id,
            .presented_capability_id = authority.id,
            .target = .{ .task = task_id },
        };
        var receiver = Receiver{ .harness = harness, .kernel = &kernel, .context = context, .task_id = task_id, .handle = handle, .status = status };
        kernel.bindSurfacePresentationReceiver(.{ .context = &receiver, .present = Receiver.present });
        const presentation = abi.SurfacePresentation{
            .surface_id = 7,
            .revision = 1,
            .buffer_object_id = 1,
            .buffer_offset = 0,
            .buffer_bytes = 8,
        };
        const result = kernel.surfacePresent(context, task_id, &presentation, null, 0);
        try std.testing.expectEqual(@as(usize, 1), receiver.calls);
        try std.testing.expect(receiver.record_retained);
        switch (status) {
            .accepted, .duplicate, .invalid_surface => try std.testing.expectError(error.InvalidSurfacePresentation, result),
            .stale => try std.testing.expectError(error.StaleSurfacePresentation, result),
            .full => try std.testing.expectError(error.ResourceBudgetExceeded, result),
        }
        try std.testing.expectEqual(@as(u8, 0), harness.runtime.task_borrow_counts[slot_index]);
        try std.testing.expect(harness.runtime.findAddressSpaceConst(address_space_id) == null);
        try std.testing.expect(harness.capabilities.query(authority.id) == null);
        try std.testing.expectEqual(presenter, harness.runtime.findByHandle(handle, task_id).?);

        const replacement = try Receiver.createApp(&harness.runtime, 9999);
        try std.testing.expectEqual(slot_index, replacement.arena_slot_index);
        try std.testing.expect(harness.runtime.findByHandle(handle, task_id) == null);
        try std.testing.expect(harness.runtime.find(task_id) == null);
        try std.testing.expect(harness.runtime.terminateResolvedTask(replacement, 9999));
    }
}

const UndeliveredCase = enum { terminate, runtime_terminate, leased_terminate, restore, endpoint_close, receiver_full, grants_full, expired };

fn expectCreationRollback(shared_object: bool, task_full: bool) !void {
    var harness = TestKernelHarness{};
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
    const task = try harness.createSessionTask();
    task.budget.shared_memory_bytes = 2 * shared_memory.PAGE_SIZE;
    const authority = try harness.mintSessionServiceAuthority(task, .{ .service = .{
        .endpoint_create = true,
        .shared_memory_create = true,
    } });
    try harness.runtime.grantCapability(task.id, authority.id);
    const context = KernelCallContext{ .caller_task_id = task.id, .presented_capability_id = authority.id, .target = .none };
    const existing_endpoint = try kernel.endpointCreate(context, task.id, "existing", .{ .local_only = true }, 1);
    const existing_object = try kernel.sharedMemoryCreate(context, task.id, shared_memory.PAGE_SIZE, 1);
    const peer = try harness.endpoints.create(ids.task(900), "peer", .{});
    try harness.endpoints.connect(ids.endpoint(existing_endpoint.endpoint.endpoint_id), peer.id);
    _ = try harness.endpoints.send(peer.id, peer.owner_task_id, 1, "preserved", null, false);
    const filler_request = capability.MintRequest{
        .holder = task.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .service, .id = 901 },
        .rights = .{ .service = .{ .time_query = true } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    };
    var last_filler: u64 = 0;
    while (if (task_full) task.capability_count < task_runtime.MAX_TASK_CAPABILITIES else harness.capabilities.activeCount() < capability.MAX_CAPABILITIES) {
        const filler = try harness.capabilities.mintBootRoot(filler_request);
        last_filler = filler.id;
        if (task_full) try harness.runtime.grantCapability(task.id, filler.id);
    }
    const grants_before = harness.capabilities.activeCount();
    const attached_before = task.capability_count;
    // Failed retries must not exhaust the object arena or the owner's budget.
    for (0..endpoint.MAX_ENDPOINTS * 2) |_| {
        const expected = if (task_full) error.CapabilityTableFull else error.TableFull;
        if (shared_object) {
            try std.testing.expectError(expected, kernel.sharedMemoryCreate(context, task.id, shared_memory.PAGE_SIZE, 2));
        } else {
            try std.testing.expectError(expected, kernel.endpointCreate(context, task.id, "rejected", .{ .local_only = true }, 2));
        }
        try std.testing.expectEqual(@as(usize, 2), harness.endpoints.activeCount());
        try std.testing.expectEqual(@as(u16, 1), harness.endpoints.activeForTask(ids.task(task.id)));
        try std.testing.expectEqual(@as(usize, 1), harness.shared.activeCount());
        try std.testing.expectEqual(shared_memory.PAGE_SIZE, harness.shared.liveOwnedBytesForTask(ids.task(task.id)));
        try std.testing.expectEqual(grants_before, harness.capabilities.activeCount());
        try std.testing.expectEqual(attached_before, task.capability_count);
    }
    var payload: [32]u8 = undefined;
    const received = (try harness.endpoints.recvInto(ids.endpoint(existing_endpoint.endpoint.endpoint_id), &payload)).?;
    try std.testing.expectEqualStrings("preserved", payload[0..received.len]);
    try std.testing.expectEqual(existing_object.object.object_id, (try harness.shared.descriptor(ids.sharedMemory(existing_object.object.object_id))).object_id);
    if (task_full) _ = try harness.runtime.revokeCapability(task.id, last_filler);
    try harness.capabilities.revokeGrant(last_filler);
    if (shared_object) {
        _ = try kernel.sharedMemoryCreate(context, task.id, shared_memory.PAGE_SIZE, 3);
        try std.testing.expectEqual(2 * shared_memory.PAGE_SIZE, harness.shared.liveOwnedBytesForTask(ids.task(task.id)));
    } else {
        _ = try kernel.endpointCreate(context, task.id, "retry", .{ .local_only = true }, 3);
        try std.testing.expectEqual(@as(u16, 2), harness.endpoints.activeForTask(ids.task(task.id)));
    }
    try std.testing.expectEqual(grants_before, harness.capabilities.activeCount());
}

test "endpoint creation rolls back object and budget when its grant cannot be attached" {
    for ([_]bool{ false, true }) |task_full| try expectCreationRollback(false, task_full);
}

test "shared memory creation rolls back object and budget when its grant cannot be attached" {
    for ([_]bool{ false, true }) |task_full| try expectCreationRollback(true, task_full);
}

fn expectUndeliveredCleanup(case: UndeliveredCase, moved: bool) !void {
    const cpu_identity = @import("../../kernel/cpu_identity.zig");
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    var harness = TestKernelHarness{};
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
    defer if (case == .leased_terminate) {
        kernel.clearEndpointWakeSink();
        harness.runtime.reset();
        harness.endpoints.deinit();
        harness.shared.deinit();
    };
    const sender = try harness.createSessionTask();
    const checkpoint = if (case == .restore) try std.testing.allocator.create(task_runtime.Snapshot) else null;
    defer if (checkpoint) |state| std.testing.allocator.destroy(state);
    if (checkpoint) |state| {
        state.* = task_runtime.Runtime.initSnapshot();
        harness.runtime.writeSnapshot(state);
    }
    const receiver = try harness.runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 3 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 4096, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .local_only = true,
    });
    const source = try harness.endpoints.create(ids.task(sender.id), "source", .{ .local_only = true });
    const destination = try harness.endpoints.create(ids.task(receiver.id), "destination", .{ .local_only = true });
    try harness.endpoints.connect(source.id, destination.id);
    const sending = try harness.capabilities.mintBootRoot(.{
        .holder = sender.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .endpoint, .id = source.id.raw() },
        .rights = .{ .endpoint = .{ .endpoint_send = true } },
        .scope = .{ .task_id = sender.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    const receiving = try harness.capabilities.mintBootRoot(.{
        .holder = receiver.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .endpoint, .id = destination.id.raw() },
        .rights = .{ .endpoint = .{ .endpoint_recv = true, .endpoint_close = true } },
        .scope = .{ .task_id = receiver.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    const gift_request = capability.MintRequest{
        .holder = sender.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .service, .id = 900 },
        .rights = .{ .service = .{ .capability_pass = true, .time_query = true } },
        .scope = .{ .task_id = sender.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    };
    const gift = try harness.capabilities.mintBootRoot(gift_request);
    const termination = try harness.capabilities.mintBootRoot(.{
        .holder = receiver.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .task, .id = receiver.id },
        .rights = .{ .task = .{ .task_terminate = true } },
        .scope = .{ .task_id = receiver.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    const peer_grant = if (case == .restore) try harness.capabilities.mintBootRoot(.{
        .holder = sender.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .endpoint, .id = destination.id.raw() },
        .rights = .{ .endpoint = .{ .endpoint_connect = true } },
        .scope = .{ .task_id = sender.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    }) else null;
    if (peer_grant) |grant| try harness.runtime.grantCapability(sender.id, grant.id);
    try harness.runtime.grantCapability(sender.id, sending.id);
    try harness.runtime.grantCapability(sender.id, gift.id);
    try harness.runtime.grantCapability(receiver.id, receiving.id);
    try harness.runtime.grantCapability(receiver.id, termination.id);
    const delegated_sending = if (case == .leased_terminate) blk: {
        const owned = try harness.capabilities.mintBootRoot(.{
            .holder = receiver.owner,
            .issuer = test_policy_authority,
            .target = .{ .kind = .endpoint, .id = destination.id.raw() },
            .rights = .{ .endpoint = .{ .endpoint_send = true, .capability_pass = true } },
            .scope = .{ .task_id = receiver.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try harness.runtime.grantCapability(receiver.id, owned.id);
        break :blk try kernel.capabilityPass(.{ .caller_task_id = receiver.id, .presented_capability_id = owned.id, .target = .none }, sender.id, 1, false);
    } else null;
    const delegated_gift = if (case == .leased_terminate) blk: {
        const owned = try harness.capabilities.mintBootRoot(gift_request);
        try harness.runtime.grantCapability(sender.id, owned.id);
        break :blk owned;
    } else null;
    try kernel.endpointSend(.{ .caller_task_id = sender.id, .presented_capability_id = sending.id, .target = .{ .endpoint = source.id.raw() } }, 1, "in flight", 0, gift.id, moved, 10);
    try std.testing.expectEqual(!moved, sender.hasCapability(gift.id));
    var wake_probe = TestEndpointWakeProbe{};
    kernel.bindEndpointWakeSink(.{ .context = &wake_probe, .wake = TestEndpointWakeProbe.wake });
    if (case == .terminate) {
        try std.testing.expect(try kernel.taskTerminate(.{ .caller_task_id = receiver.id, .presented_capability_id = termination.id, .target = .{ .task = receiver.id } }, 11));
    } else if (case == .leased_terminate) {
        const address_space_id = receiver.address_space_id;
        const attachments = receiver.capability_count;
        const grants = harness.capabilities.activeCount();
        const ticket = try harness.runtime.reserveExecution(receiver, 3);
        try harness.runtime.execution.bindOwnedRoot(ticket, 1, 0x1000);
        cpu_identity.setIndexForTest(3);
        _ = try harness.runtime.execution.start(ticket);
        cpu_identity.setIndexForTest(0);
        try std.testing.expect(try harness.runtime.terminateTask(receiver.id, 11));
        try std.testing.expect(!try harness.runtime.terminateTask(receiver.id, 12));
        try std.testing.expectEqual(task_runtime.TaskState.terminated, receiver.state);
        try std.testing.expectEqual(attachments, receiver.capability_count);
        try std.testing.expectEqual(grants, harness.capabilities.activeCount());
        try std.testing.expect(harness.runtime.findAddressSpaceConst(address_space_id) != null);
        try std.testing.expectEqual(@as(u16, 1), (try harness.endpoints.descriptor(destination.id)).queued_messages);
        try std.testing.expect(harness.capabilities.query(gift.id) != null);
        try std.testing.expectEqual(@as(usize, 0), wake_probe.count);
        var receive_output: [abi.ENDPOINT_INLINE_BYTES]u8 = @splat(0xa5);
        try std.testing.expectError(error.TaskNotFound, kernel.endpointRecv(.{ .caller_task_id = receiver.id, .presented_capability_id = receiving.id, .target = .none }, receiver.id, &receive_output, 12));
        try std.testing.expect(std.mem.allEqual(u8, &receive_output, 0xa5));
        const destination_slot = harness.endpoints.arena.getByHandle(.{ .value = destination.id.raw() }).?;
        const ring_hash = std.hash.Wyhash.hash(0, destination_slot.endpoint.data_ring);
        const sender_generation = sender.capabilityGeneration();
        try std.testing.expectError(error.TaskNotFound, kernel.endpointSend(.{ .caller_task_id = sender.id, .presented_capability_id = sending.id, .target = .none }, 2, "rejected", 0, gift.id, true, 12));
        try std.testing.expectEqual(ring_hash, std.hash.Wyhash.hash(0, destination_slot.endpoint.data_ring));
        try std.testing.expectEqual(sender_generation, sender.capabilityGeneration());
        try std.testing.expectEqual(grants, harness.capabilities.activeCount());
        try std.testing.expectEqual(!moved, sender.hasCapability(gift.id));
        try std.testing.expectEqual(@as(u16, 1), (try harness.endpoints.descriptor(destination.id)).queued_messages);
        // This source endpoint belongs to the stopped receiver, but its grant
        // was legitimately passed and retargeted to the still-live sender.
        const live_peer = harness.endpoints.arena.getByHandle(.{ .value = source.id.raw() }).?;
        const peer_ring_before = try std.testing.allocator.dupe(u8, live_peer.endpoint.data_ring);
        defer std.testing.allocator.free(peer_ring_before);
        const destination_ring_before = try std.testing.allocator.dupe(u8, destination_slot.endpoint.data_ring);
        defer std.testing.allocator.free(destination_ring_before);
        const source_before = try harness.endpoints.descriptor(source.id);
        const destination_before = try harness.endpoints.descriptor(destination.id);
        const mutation = harness.capabilities.mutationGeneration();
        const sender_count = sender.capability_count;
        const receiver_generation = receiver.capabilityGeneration();
        var sender_attachments: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0);
        var receiver_attachments: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0);
        @memcpy(sender_attachments[0..sender.capability_count], sender.capabilityIds());
        @memcpy(receiver_attachments[0..receiver.capability_count], receiver.capabilityIds());
        for ([_]bool{ false, true }) |move_gift| {
            try std.testing.expectError(error.TaskNotFound, kernel.endpointSend(.{
                .caller_task_id = sender.id,
                .presented_capability_id = delegated_sending.?.capability_id,
                .target = .{ .endpoint = destination.id.raw() },
            }, 3, "rejected delegated source", 0, delegated_gift.?.id, move_gift, 12));
            try std.testing.expectEqualDeep(source_before, try harness.endpoints.descriptor(source.id));
            try std.testing.expectEqualDeep(destination_before, try harness.endpoints.descriptor(destination.id));
            try std.testing.expectEqualSlices(u8, peer_ring_before, live_peer.endpoint.data_ring);
            try std.testing.expectEqualSlices(u8, destination_ring_before, destination_slot.endpoint.data_ring);
            try std.testing.expectEqual(mutation, harness.capabilities.mutationGeneration());
            try std.testing.expectEqual(grants, harness.capabilities.activeCount());
            try std.testing.expectEqual(sender_generation, sender.capabilityGeneration());
            try std.testing.expectEqual(receiver_generation, receiver.capabilityGeneration());
            try std.testing.expectEqual(sender_count, sender.capability_count);
            try std.testing.expectEqual(attachments, receiver.capability_count);
            try std.testing.expectEqualSlices(u64, sender_attachments[0..sender.capability_count], sender.capabilityIds());
            try std.testing.expectEqualSlices(u64, receiver_attachments[0..receiver.capability_count], receiver.capabilityIds());
            try std.testing.expectEqualDeep(delegated_gift.?, harness.capabilities.query(delegated_gift.?.id).?);
            try std.testing.expectEqual(@as(usize, 0), wake_probe.count);
        }
        try std.testing.expectError(error.WrongPhase, harness.runtime.collectExecution(ticket));
        try std.testing.expectError(error.WrongPhase, harness.runtime.cancelUnstartedExecution(ticket));
        cpu_identity.setIndexForTest(2);
        try std.testing.expectError(error.WrongCpu, harness.runtime.execution.acknowledgeOwnedRootReturn(ticket));
        cpu_identity.setIndexForTest(3);
        try std.testing.expect(harness.runtime.execution.stopRequested(ticket));
        try harness.runtime.execution.acknowledgeOwnedRootReturn(ticket);
        try std.testing.expectError(error.WrongCpu, harness.runtime.collectExecution(ticket));
        cpu_identity.setIndexForTest(0);
        try harness.runtime.collectExecution(ticket);
        try std.testing.expect(harness.runtime.findAddressSpaceConst(address_space_id) == null);
        try std.testing.expectError(error.StaleTicket, harness.runtime.collectExecution(ticket));
    } else if (case == .runtime_terminate) {
        try std.testing.expect(try harness.runtime.terminateTask(receiver.id, 11));
    } else if (case == .restore) {
        const receiver_id = receiver.id;
        try harness.runtime.restoreFromSnapshot(checkpoint.?);
        try std.testing.expect(harness.runtime.find(receiver_id) == null);
        try std.testing.expectEqual(@as(u16, 0), harness.endpoints.activeForTask(ids.task(receiver_id)));
        try std.testing.expect(harness.capabilities.query(receiving.id) == null);
        try std.testing.expect(harness.capabilities.query(termination.id) == null);
        try std.testing.expect(harness.capabilities.query(sending.id) != null);
        try std.testing.expect(sender.hasCapability(sending.id));
        try std.testing.expect(!sender.hasCapability(peer_grant.?.id));
        try std.testing.expect(harness.capabilities.query(peer_grant.?.id) == null);
        try std.testing.expectEqual(@as(u16, 1), harness.endpoints.activeForTask(ids.task(sender.id)));
    } else if (case == .endpoint_close) {
        try kernel.endpointClose(.{ .caller_task_id = receiver.id, .presented_capability_id = receiving.id, .target = .none }, 11);
        try std.testing.expectEqual(task_runtime.TaskState.active, receiver.state);
        try std.testing.expect(harness.capabilities.query(receiving.id) == null);
        try std.testing.expect(harness.capabilities.query(termination.id) != null);
        try std.testing.expectEqual(@as(u16, 0), harness.endpoints.activeForTask(ids.task(receiver.id)));
    } else {
        if (case == .receiver_full) {
            var receiver_grant = gift_request;
            receiver_grant.holder = receiver.owner;
            receiver_grant.scope.task_id = receiver.id;
            while (receiver.capability_count < task_runtime.MAX_TASK_CAPABILITIES) {
                const filler = try harness.capabilities.mintBootRoot(receiver_grant);
                try harness.runtime.grantCapability(receiver.id, filler.id);
            }
        }
        if (case == .grants_full) {
            while (harness.capabilities.activeCount() < capability.MAX_CAPABILITIES) _ = try harness.capabilities.mintBootRoot(gift_request);
        }
        const count = harness.capabilities.activeCount();
        var payload: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        const expected_error = switch (case) {
            .receiver_full => error.CapabilityTableFull,
            .grants_full => error.TableFull,
            .expired => error.CapabilityRevoked,
            .terminate, .runtime_terminate, .leased_terminate, .restore, .endpoint_close => unreachable,
        };
        try std.testing.expectError(expected_error, kernel.endpointRecv(.{ .caller_task_id = receiver.id, .presented_capability_id = receiving.id, .target = .{ .endpoint = destination.id.raw() } }, receiver.id, &payload, if (case == .expired) 101 else 11));
        try std.testing.expectEqual(count - @intFromBool(moved), harness.capabilities.activeCount());
        try std.testing.expectEqual(@as(u16, 0), (try harness.endpoints.descriptor(destination.id)).queued_messages);
    }
    if (case == .terminate or case == .runtime_terminate or case == .leased_terminate) {
        try std.testing.expectEqual(@as(u16, 0), harness.endpoints.activeForTask(ids.task(receiver.id)));
        try std.testing.expect(harness.capabilities.query(receiving.id) == null);
        try std.testing.expect(harness.capabilities.query(termination.id) == null);
        try std.testing.expectEqual(@as(u16, 0), receiver.capability_count);
        try std.testing.expect(!try harness.runtime.terminateTask(receiver.id, 12));
    }
    try std.testing.expectEqual(!moved, harness.capabilities.query(gift.id) != null);
    try std.testing.expectEqual(!moved, sender.hasCapability(gift.id));
    if (case == .terminate or case == .runtime_terminate or case == .leased_terminate or case == .restore or case == .endpoint_close) {
        try std.testing.expectEqual(@as(usize, 1), wake_probe.count);
        try std.testing.expectEqual(sender.id, wake_probe.tasks[0]);
    }
}

test "endpoint retirement disposes unread moves while preserving sender-owned copies" {
    for ([_]bool{ false, true }) |moved| try expectUndeliveredCleanup(.terminate, moved);
}

test "direct runtime termination disposes unread moves and endpoint resources" {
    for ([_]bool{ false, true }) |moved| try expectUndeliveredCleanup(.runtime_terminate, moved);
}

test "execution retirement retains unread moves and copies until owner return is collected" {
    for ([_]bool{ false, true }) |moved| try expectUndeliveredCleanup(.leased_terminate, moved);
}

test "endpoint queued MOVE survives source retirement but not receiver or target retirement" {
    const Retirement = enum { source, receiver, target };
    for ([_]bool{ false, true }) |unscoped| {
        for (std.enums.values(Retirement)) |retirement| {
            var harness = TestKernelHarness{};
            var kernel: Kernel = undefined;
            harness.initKernel(&kernel);
            defer kernel.deinit();
            defer {
                harness.runtime.reset();
                harness.endpoints.deinit();
                harness.shared.deinit();
            }
            const sender = try harness.createSessionTask();
            const sender_id = sender.id;
            const receiver = try harness.runtime.createTask(.{
                .owner = .{ .kind = .app, .serial = 3 },
                .component_class = .app_component,
                .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 4096, .endpoint_slots = 2, .shared_memory_bytes = 0 },
                .local_only = true,
            });
            const receiver_id = receiver.id;
            const target_id = if (retirement == .target) (try harness.createSessionTask()).id else 0;
            const source = try harness.endpoints.create(ids.task(sender_id), "move source", .{});
            const destination = try harness.endpoints.create(ids.task(receiver.id), "move receiver", .{});
            try harness.endpoints.connect(source.id, destination.id);
            const sending = try harness.capabilities.mintBootRoot(.{
                .holder = sender.owner,
                .issuer = test_policy_authority,
                .target = .{ .kind = .endpoint, .id = source.id.raw() },
                .rights = .{ .endpoint = .{ .endpoint_send = true } },
                .scope = .{ .task_id = if (unscoped) null else sender_id },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
            });
            const receiving = try harness.capabilities.mintBootRoot(.{
                .holder = receiver.owner,
                .issuer = test_policy_authority,
                .target = .{ .kind = .endpoint, .id = destination.id.raw() },
                .rights = .{ .endpoint = .{ .endpoint_recv = true } },
                .scope = .{ .task_id = receiver.id },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
            });
            const gift = try harness.capabilities.mintBootRoot(.{
                .holder = sender.owner,
                .issuer = test_policy_authority,
                .target = if (target_id != 0) .{ .kind = .task, .id = target_id } else .{ .kind = .service, .id = 900 },
                .rights = if (target_id != 0) .{ .task = .{ .capability_pass = true, .time_query = true } } else .{ .service = .{ .capability_pass = true, .time_query = true } },
                .scope = .{ .task_id = if (unscoped) null else sender_id },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
            });
            var sibling_request = capability.MintRequest{
                .holder = sender.owner,
                .issuer = test_policy_authority,
                .target = gift.target,
                .rights = gift.rights,
                .scope = .{},
                .lease = gift.lease,
            };
            sibling_request.holder.serial = 90;
            const sibling = try harness.capabilities.mintBootRoot(sibling_request);
            try harness.runtime.grantCapability(sender_id, sending.id);
            try harness.runtime.grantCapability(sender_id, gift.id);
            try harness.runtime.grantCapability(receiver.id, receiving.id);
            try kernel.endpointSend(.{ .caller_task_id = sender_id, .presented_capability_id = sending.id, .target = .none }, 9, "owned", 0, gift.id, true, 10);
            try std.testing.expect(!sender.hasCapability(gift.id));
            try std.testing.expectError(error.CapabilityRevoked, harness.capabilities.requireUsable(gift.id, 11));
            if (retirement == .target) {
                // Ordinary policy-authorized target retirement also invalidates
                // authority already held by an unrelated endpoint queue.
                const termination = try harness.capabilities.mintBootRoot(.{
                    .holder = sender.owner,
                    .issuer = test_policy_authority,
                    .target = .{ .kind = .task, .id = target_id },
                    .rights = .{ .task = .{ .task_terminate = true } },
                    .scope = .{ .task_id = sender_id },
                    .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
                });
                try harness.runtime.grantCapability(sender_id, termination.id);
                try std.testing.expect(try kernel.taskTerminate(.{ .caller_task_id = sender_id, .presented_capability_id = termination.id, .target = .{ .task = target_id } }, 11));
                try std.testing.expectEqual(task_runtime.TaskState.terminated, harness.runtime.find(target_id).?.state);
                try std.testing.expect(harness.capabilities.query(gift.id) == null);
                try std.testing.expect(harness.capabilities.query(sibling.id) == null);
                try std.testing.expect(!harness.capabilities.disposeQueuedMove(gift.id));
                try std.testing.expectEqual(@as(u16, 1), (try harness.endpoints.descriptor(destination.id)).queued_messages);
                var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = @splat(0xa5);
                try std.testing.expectError(error.CapabilityNotFound, kernel.endpointRecv(.{ .caller_task_id = receiver_id, .presented_capability_id = receiving.id, .target = .none }, receiver_id, &payload, 12));
                try std.testing.expectEqual(@as(u16, 0), (try harness.endpoints.descriptor(destination.id)).queued_messages);
                try std.testing.expectEqual(@as(u16, 1), receiver.capability_count);
                _ = try harness.capabilities.requireUsable(sending.id, 12);
                _ = try harness.capabilities.requireUsable(receiving.id, 12);
                continue;
            }
            try std.testing.expect(try harness.runtime.terminateTask(if (retirement == .source) sender_id else receiver_id, 11));
            _ = try harness.capabilities.requireUsable(sibling.id, 12);
            if (retirement == .source) {
                try std.testing.expectEqual(task_runtime.TaskState.terminated, harness.runtime.find(sender_id).?.state);
                try std.testing.expectEqual(@as(u16, 0), sender.capability_count);
                try std.testing.expectEqual(@as(u16, 0), harness.endpoints.activeForTask(ids.task(sender_id)));
                try std.testing.expect(harness.capabilities.query(gift.id) != null);
                try std.testing.expectEqual(@as(u16, 1), (try harness.endpoints.descriptor(destination.id)).queued_messages);
                var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = @splat(0xa5);
                const received = (try kernel.endpointRecv(.{ .caller_task_id = receiver_id, .presented_capability_id = receiving.id, .target = .none }, receiver_id, &payload, 12)).?;
                try std.testing.expectEqualStrings("owned", payload[0..received.message.payload_len]);
                try std.testing.expectEqual(sender_id, received.message.sender_task_id);
                const delivered = received.attached_capability.?.capability_id;
                try std.testing.expect(delivered != gift.id and receiver.hasCapability(delivered));
                _ = try kernel.timeQuery(.{ .caller_task_id = receiver_id, .presented_capability_id = delivered, .target = .none }, 12);
                try std.testing.expect(harness.capabilities.query(gift.id) == null);
                try std.testing.expect(!harness.capabilities.disposeQueuedMove(gift.id));
                try std.testing.expectEqual(@as(u16, 0), (try harness.endpoints.descriptor(destination.id)).queued_messages);
            } else {
                try std.testing.expectEqual(task_runtime.TaskState.terminated, harness.runtime.find(receiver_id).?.state);
                try std.testing.expectEqual(@as(u16, 0), harness.endpoints.activeForTask(ids.task(receiver_id)));
                try std.testing.expect(harness.capabilities.query(gift.id) == null);
                try std.testing.expect(!harness.capabilities.disposeQueuedMove(gift.id));
                try std.testing.expect(!sender.hasCapability(gift.id));
                _ = try harness.capabilities.requireUsable(sending.id, 12);
            }
            try std.testing.expectEqualDeep(sibling, harness.capabilities.query(sibling.id).?);
        }
    }
}

test "endpoint execution rejects caller zero retained gifts and peer proofs but admits explicit live holders" {
    const cpu_identity = @import("../../kernel/cpu_identity.zig");
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    var harness = TestKernelHarness{};
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
    var retained_ticket: ?task_runtime.ExecutionTicket = null;
    defer {
        kernel.clearEndpointWakeSink();
        if (retained_ticket) |ticket| {
            harness.runtime.cancelUnstartedExecution(ticket) catch {};
            harness.runtime.collectExecution(ticket) catch {};
        }
        harness.runtime.reset();
        harness.endpoints.deinit();
        harness.shared.deinit();
    }
    const stopped = try harness.createSessionTask();
    const caller = try harness.runtime.createTask(.{
        .owner = stopped.owner,
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 4096, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .local_only = true,
    });
    const receiver = try harness.runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 3 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 4096, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .local_only = true,
    });
    const source = try harness.endpoints.create(ids.task(caller.id), "live source", .{ .local_only = true });
    const destination = try harness.endpoints.create(ids.task(receiver.id), "live destination", .{ .local_only = true });
    try harness.endpoints.connect(source.id, destination.id);
    const connect_source = try harness.endpoints.create(ids.task(caller.id), "unconnected source", .{ .local_only = true });
    const connect_destination = try harness.endpoints.create(ids.task(receiver.id), "unconnected destination", .{ .local_only = true });
    const sending = try harness.capabilities.mintBootRoot(.{
        .holder = caller.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .endpoint, .id = source.id.raw() },
        .rights = .{ .endpoint = .{ .endpoint_send = true } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    const connecting = try harness.capabilities.mintBootRoot(.{
        .holder = caller.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .endpoint, .id = connect_source.id.raw() },
        .rights = .{ .endpoint = .{ .endpoint_connect = true } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    const peer = try harness.capabilities.mintBootRoot(.{
        .holder = stopped.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .endpoint, .id = connect_destination.id.raw() },
        .rights = .{ .endpoint = .{ .ipc_peer = true } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    const gift = try harness.capabilities.mintBootRoot(.{
        .holder = stopped.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .service, .id = 900 },
        .rights = .{ .service = .{ .capability_pass = true, .time_query = true } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    const receiving = try harness.capabilities.mintBootRoot(.{
        .holder = receiver.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .endpoint, .id = destination.id.raw() },
        .rights = .{ .endpoint = .{ .endpoint_recv = true } },
        .scope = .{ .task_id = receiver.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    for ([_]u64{ sending.id, connecting.id, peer.id, gift.id }) |id| try harness.runtime.grantCapability(caller.id, id);
    for ([_]u64{ peer.id, gift.id }) |id| try harness.runtime.grantCapability(stopped.id, id);
    try harness.runtime.grantCapability(receiver.id, receiving.id);
    // A preexisting record makes queue/ring preservation observable, while all
    // supplied primary endpoint authority still belongs to live tasks.
    const send_context = KernelCallContext{ .caller_task_id = 0, .presented_capability_id = sending.id, .target = .none };
    try kernel.endpointSend(send_context, 1, "preserved", 0, null, false, 10);
    retained_ticket = try harness.runtime.reserveExecution(stopped, 3);
    try std.testing.expect(try harness.runtime.terminateTask(stopped.id, 11));
    var wake_probe = TestEndpointWakeProbe{};
    kernel.bindEndpointWakeSink(.{ .context = &wake_probe, .wake = TestEndpointWakeProbe.wake });
    const source_slot = harness.endpoints.arena.getByHandle(.{ .value = source.id.raw() }).?;
    const destination_slot = harness.endpoints.arena.getByHandle(.{ .value = destination.id.raw() }).?;
    const source_ring = try std.testing.allocator.dupe(u8, source_slot.endpoint.data_ring);
    defer std.testing.allocator.free(source_ring);
    const destination_ring = try std.testing.allocator.dupe(u8, destination_slot.endpoint.data_ring);
    defer std.testing.allocator.free(destination_ring);
    const source_before = try harness.endpoints.descriptor(source.id);
    const destination_before = try harness.endpoints.descriptor(destination.id);
    const connect_source_before = try harness.endpoints.descriptor(connect_source.id);
    const connect_destination_before = try harness.endpoints.descriptor(connect_destination.id);
    const grants = harness.capabilities.activeCount();
    const mutation = harness.capabilities.mutationGeneration();
    const stopped_generation = stopped.capabilityGeneration();
    const caller_generation = caller.capabilityGeneration();
    const receiver_generation = receiver.capabilityGeneration();
    var stopped_ids: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0);
    var caller_ids: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0);
    var receiver_ids: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0);
    const stopped_count = stopped.capability_count;
    const caller_count = caller.capability_count;
    const receiver_count = receiver.capability_count;
    @memcpy(stopped_ids[0..stopped_count], stopped.capabilityIds());
    @memcpy(caller_ids[0..caller_count], caller.capabilityIds());
    @memcpy(receiver_ids[0..receiver_count], receiver.capabilityIds());
    for ([_]bool{ false, true }) |move_gift| {
        try std.testing.expectError(error.TaskNotFound, kernel.endpointSend(send_context, 2, "retained gift", 0, gift.id, move_gift, 12));
    }
    const connect_context = KernelCallContext{ .caller_task_id = 0, .presented_capability_id = connecting.id, .target = .none };
    try std.testing.expectError(error.TaskNotFound, kernel.endpointConnect(connect_context, peer.id, connect_destination.id.raw(), 12));
    try std.testing.expectEqualDeep(source_before, try harness.endpoints.descriptor(source.id));
    try std.testing.expectEqualDeep(destination_before, try harness.endpoints.descriptor(destination.id));
    try std.testing.expectEqualDeep(connect_source_before, try harness.endpoints.descriptor(connect_source.id));
    try std.testing.expectEqualDeep(connect_destination_before, try harness.endpoints.descriptor(connect_destination.id));
    try std.testing.expectEqualSlices(u8, source_ring, source_slot.endpoint.data_ring);
    try std.testing.expectEqualSlices(u8, destination_ring, destination_slot.endpoint.data_ring);
    try std.testing.expectEqual(@as(usize, 0), harness.endpoints.arena.getByHandle(.{ .value = connect_source.id.raw() }).?.endpoint.data_ring.len);
    try std.testing.expectEqual(@as(usize, 0), harness.endpoints.arena.getByHandle(.{ .value = connect_destination.id.raw() }).?.endpoint.data_ring.len);
    try std.testing.expectEqual(grants, harness.capabilities.activeCount());
    try std.testing.expectEqual(mutation, harness.capabilities.mutationGeneration());
    try std.testing.expectEqualDeep(gift, harness.capabilities.query(gift.id).?);
    try std.testing.expectEqualDeep(peer, harness.capabilities.query(peer.id).?);
    try std.testing.expectEqual(stopped_generation, stopped.capabilityGeneration());
    try std.testing.expectEqual(caller_generation, caller.capabilityGeneration());
    try std.testing.expectEqual(receiver_generation, receiver.capabilityGeneration());
    try std.testing.expectEqual(stopped_count, stopped.capability_count);
    try std.testing.expectEqual(caller_count, caller.capability_count);
    try std.testing.expectEqual(receiver_count, receiver.capability_count);
    try std.testing.expectEqualSlices(u64, stopped_ids[0..stopped_count], stopped.capabilityIds());
    try std.testing.expectEqualSlices(u64, caller_ids[0..caller_count], caller.capabilityIds());
    try std.testing.expectEqualSlices(u64, receiver_ids[0..receiver_count], receiver.capabilityIds());
    try std.testing.expectEqual(@as(usize, 0), wake_probe.count);
    // The exact live holder remains unambiguous. It may use these same grants
    // through the task-bound path while the stopped holder awaits collection.
    var live_send_context = send_context;
    live_send_context.caller_task_id = caller.id;
    try kernel.endpointSend(live_send_context, 3, "live peer", 0, gift.id, false, 13);
    var live_connect_context = connect_context;
    live_connect_context.caller_task_id = caller.id;
    _ = try kernel.endpointConnect(live_connect_context, peer.id, connect_destination.id.raw(), 13);
    var output: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const receive_context = KernelCallContext{ .caller_task_id = receiver.id, .presented_capability_id = receiving.id, .target = .none };
    const first = (try kernel.endpointRecv(receive_context, receiver.id, &output, 14)).?;
    try std.testing.expectEqualStrings("preserved", output[0..first.message.payload_len]);
    const second = (try kernel.endpointRecv(receive_context, receiver.id, &output, 14)).?;
    try std.testing.expectEqualStrings("live peer", output[0..second.message.payload_len]);
    try std.testing.expect(receiver.hasCapability(second.attached_capability.?.capability_id));
    try std.testing.expect(caller.hasCapability(gift.id));
    try std.testing.expect(stopped.hasCapability(gift.id));
    try std.testing.expectEqual(@as(u16, 0), (try harness.endpoints.descriptor(destination.id)).queued_messages);
}

test "checkpoint restore disposes removed receivers moves and retains live sender authority" {
    for ([_]bool{ false, true }) |moved| try expectUndeliveredCleanup(.restore, moved);
}

test "endpoint close releases unread moves without terminating either task" {
    for ([_]bool{ false, true }) |moved| try expectUndeliveredCleanup(.endpoint_close, moved);
}

test "failed capability receipts dispose moves after quota allocation and expiry failures" {
    for ([_]UndeliveredCase{ .receiver_full, .grants_full, .expired }) |case| {
        for ([_]bool{ false, true }) |moved| try expectUndeliveredCleanup(case, moved);
    }
}

test "capability derivation is bound to its authorized source" {
    var harness = TestKernelHarness{};
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
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
    try std.testing.expectError(error.CapabilityNotFound, kernel.capabilityDerive(context, request, 10));

    request.parent_capability_id = authorized_source.id;
    const derived = try kernel.capabilityDerive(context, request, 10);
    try std.testing.expect(receiver_task.hasCapability(derived.capability_id));
}

test "capability scalar derive uses trusted syscall time and preserves grants attachments and output on denial" {
    const scalar = @import("capability_wire.zig");
    const handlers = @import("capability_syscalls.zig");
    const port_module = @import("component_port.zig");
    const dispatch = @import("syscall_dispatch.zig");
    var harness = TestKernelHarness{};
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer {
        harness.runtime.reset();
        harness.endpoints.deinit();
        harness.shared.deinit();
        kernel.deinit();
    }
    const source = try harness.createSessionTask();
    const receiver = try harness.createSessionTask();
    const parent = try harness.capabilities.mintBootRoot(.{
        .holder = source.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{ .service = .{ .capability_derive = true, .time_query = true } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 50 },
    });
    try harness.runtime.grantCapability(source.id, parent.id);
    const request = capability.DeriveRequest{
        .parent_capability_id = parent.id,
        .holder = receiver.owner,
        .rights = .{ .service = .{ .time_query = true } },
        .scope = .{ .task_id = receiver.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 40 },
    };
    var encoded: abi.CapabilityDeriveWireRequest = undefined;
    scalar.deriveToWireInto(port_module.makeHeader(.capability_derive, source.id), request, &encoded);
    var port = port_module.KernelPort.init(&kernel);
    port.syscall_caller_task_id = 999;
    const memory = dispatch.UserMemoryContext{ .address_space = null, .caller_task_id = source.id };
    var output: abi.CapabilityDescriptor = undefined;
    @memset(std.mem.asBytes(&output), 0xa5);
    const output_before = std.mem.toBytes(output);
    const table_before = harness.capabilities;
    const source_before = source.*;
    const receiver_before = receiver.*;
    for ([_]u64{ 9, 51, 100 }) |now_ticks| {
        const result = handlers.dispatchCapabilityDerive(&port, memory, now_ticks, @intFromPtr(&encoded), @intFromPtr(&output), @sizeOf(@TypeOf(output)));
        try std.testing.expectEqual(abi.SyscallStatus.denied, result.status);
        try std.testing.expectEqual(abi.DenialReason.capability_revoked, result.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
        try std.testing.expectEqualDeep(table_before, harness.capabilities);
        try std.testing.expectEqualDeep(source_before, source.*);
        try std.testing.expectEqualDeep(receiver_before, receiver.*);
        try std.testing.expectEqualSlices(u8, &output_before, std.mem.asBytes(&output));
        try std.testing.expectEqual(@as(u64, 999), port.syscall_caller_task_id);
    }
    const result = handlers.dispatchCapabilityDerive(&port, memory, 20, @intFromPtr(&encoded), @intFromPtr(&output), @sizeOf(@TypeOf(output)));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, @sizeOf(abi.CapabilityDescriptor)), result.bytes_written);
    try std.testing.expect(receiver.hasCapability(output.capability_id));
    try std.testing.expect(source.hasCapability(parent.id));
    try std.testing.expectEqual(table_before.activeCount() + 1, harness.capabilities.activeCount());
    try std.testing.expectEqual(@as(u64, 999), port.syscall_caller_task_id);
}

test "self-target capability mutations reuse the authorized task" {
    var harness = TestKernelHarness{};
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
    const task = try harness.createSessionTask();
    const authority = try harness.capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = test_policy_authority,
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{ .service = .{
            .capability_derive = true,
            .capability_pass = true,
            .capability_revoke = true,
            .time_query = true,
        } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    try task_runtime.grantCapabilityToTask(task, authority.id);

    var derive_context = testContext(.capability_derive, authority.id, .none);
    derive_context.caller_task_id = task.id;
    const derived = try kernel.capabilityDerive(derive_context, .{
        .parent_capability_id = authority.id,
        .holder = task.owner,
        .rights = .{ .service = .{ .time_query = true } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 90 },
    }, 10);
    try std.testing.expect(task.hasCapability(derived.capability_id));

    var pass_context = testContext(.capability_pass, authority.id, .none);
    pass_context.caller_task_id = task.id;
    const passed = try kernel.capabilityPass(pass_context, task.id, 10, true);
    try std.testing.expect(!task.hasCapability(authority.id));
    try std.testing.expect(task.hasCapability(passed.capability_id));

    var revoke_context = testContext(.capability_revoke, passed.capability_id, .{ .capability = derived.capability_id });
    revoke_context.caller_task_id = task.id;
    try kernel.capabilityRevoke(revoke_context, derived.capability_id, 10);
    try std.testing.expect(!task.hasCapability(derived.capability_id));
}

const TestEndpointWakeProbe = struct {
    tasks: [16]u64 = undefined,
    count: usize = 0,
    move_source: ?*const task_runtime.TaskRecord = null,
    moved_capability_id: u64 = 0,
    source_retained_capability_at_wake: bool = false,

    fn wake(context: *anyopaque, receiver_task_id: u64, _: u64) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.tasks[self.count] = receiver_task_id;
        self.count += 1;
        if (self.move_source) |source| {
            self.source_retained_capability_at_wake = source.hasCapability(self.moved_capability_id);
        }
    }
};

test "native kernel creates tasks endpoints and shared memory without owning service discovery" {
    var harness = TestKernelHarness{};
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
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
    try std.testing.expectEqual(@as(u8, @backingInt(accelerator_scheduler.ResourceClass.emergency_system_critical)), abi.taskFlagsResourceClass(service_task_desc.flags));
    try std.testing.expectEqual(@as(u8, @backingInt(accelerator_scheduler.ResourceClass.batch_compute)), abi.taskFlagsResourceClass(app_task_desc.flags));

    const service_endpoint = try kernel.endpointCreate(testContext(.endpoint_create, authority_capability.id, .{ .task = service_task_desc.task_id }), service_task_desc.task_id, "zigos.object.workspace", .{
        .local_only = true,
        .service_port = true,
    }, 7);

    const app_endpoint = try kernel.endpointCreate(testContext(.endpoint_create, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, "app.endpoint", .{
        .local_only = true,
    }, 8);
    _ = try kernel.endpointConnect(testContext(.endpoint_connect, app_endpoint.capability_id, .none), service_endpoint.capability_id, service_endpoint.endpoint.endpoint_id, 8);

    const shared_result = try kernel.sharedMemoryCreate(testContext(.shared_memory_create, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, shared_memory.PAGE_SIZE, 9);
    var send_context = testContext(.endpoint_send, app_endpoint.capability_id, .none);
    send_context.caller_task_id = app_task_desc.task_id;
    var wake_probe = TestEndpointWakeProbe{};
    kernel.bindEndpointWakeSink(.{ .context = &wake_probe, .wake = TestEndpointWakeProbe.wake });
    try kernel.endpointSend(send_context, 11, "sync-open", 0, shared_result.capability_id, false, 9);
    const other_endpoint = try kernel.endpointCreate(testContext(.endpoint_create, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, "app.second-request", .{
        .local_only = true,
    }, 9);
    _ = try kernel.endpointConnect(testContext(.endpoint_connect, other_endpoint.capability_id, .none), service_endpoint.capability_id, service_endpoint.endpoint.endpoint_id, 9);
    var other_context = testContext(.endpoint_send, other_endpoint.capability_id, .none);
    other_context.caller_task_id = app_task_desc.task_id;
    try kernel.endpointSend(other_context, 11, "second request", 0, null, false, 9);
    try std.testing.expectEqualSlices(u64, &.{ service_task_desc.task_id, service_task_desc.task_id }, wake_probe.tasks[0..wake_probe.count]);
    var received_payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try kernel.endpointRecv(testContext(.endpoint_recv, service_endpoint.capability_id, .none), service_task_desc.task_id, &received_payload, 10)).?;
    try std.testing.expectEqualStrings("sync-open", received_payload[0..received.message.payload_len]);
    try std.testing.expect(received.attached_capability != null);
    try std.testing.expectEqual(app_endpoint.endpoint.endpoint_id, received.message.sender_endpoint_id);
    const other_request = (try kernel.endpointRecv(testContext(.endpoint_recv, service_endpoint.capability_id, .none), service_task_desc.task_id, &received_payload, 10)).?;
    try std.testing.expectEqual(other_endpoint.endpoint.endpoint_id, other_request.message.sender_endpoint_id);

    const service_task = harness.runtime.find(service_task_desc.task_id).?;
    const copied_capability_id = received.attached_capability.?.capability_id;
    try std.testing.expect(service_task.hasCapability(copied_capability_id));
    wake_probe.move_source = service_task;
    wake_probe.moved_capability_id = copied_capability_id;
    var move_context = testContext(.endpoint_send, service_endpoint.capability_id, .none);
    move_context.caller_task_id = service_task.id;
    // A denied reply must not consume an attached capability or fall back to
    // the first connected client. Even clients in one task have distinct routes.
    try std.testing.expectError(error.ScopeViolation, kernel.endpointSend(move_context, 12, "invalid", service_endpoint.endpoint.endpoint_id, copied_capability_id, true, 10));
    try std.testing.expectEqual(@as(usize, 2), wake_probe.count);
    try std.testing.expect(service_task.hasCapability(copied_capability_id));
    try kernel.endpointSend(move_context, 11, "second reply", other_request.message.sender_endpoint_id, null, false, 10);
    try std.testing.expectEqual(@as(u16, 0), (try harness.endpoints.descriptor(ids.endpoint(app_endpoint.endpoint.endpoint_id))).queued_messages);
    try kernel.endpointSend(move_context, 12, "move-back", received.message.sender_endpoint_id, copied_capability_id, true, 10);
    try std.testing.expect(!service_task.hasCapability(copied_capability_id));
    try std.testing.expect(!wake_probe.source_retained_capability_at_wake);
    try std.testing.expectEqualSlices(u64, &.{ app_task_desc.task_id, app_task_desc.task_id }, wake_probe.tasks[2..wake_probe.count]);

    var moved_payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    var moved_receive_context = testContext(.endpoint_recv, app_endpoint.capability_id, .none);
    moved_receive_context.caller_task_id = app_task_desc.task_id;
    const moved = (try kernel.endpointRecv(moved_receive_context, app_task_desc.task_id, &moved_payload, 10)).?;
    try std.testing.expectEqualStrings("move-back", moved_payload[0..moved.message.payload_len]);
    try std.testing.expect(harness.capabilities.query(copied_capability_id) == null);
    try std.testing.expect(harness.runtime.find(app_task_desc.task_id).?.hasCapability(moved.attached_capability.?.capability_id));
    try std.testing.expectEqual(service_endpoint.endpoint.endpoint_id, moved.message.sender_endpoint_id);
    var other_receive_context = testContext(.endpoint_recv, other_endpoint.capability_id, .none);
    other_receive_context.caller_task_id = app_task_desc.task_id;
    const other_response = (try kernel.endpointRecv(other_receive_context, app_task_desc.task_id, &moved_payload, 10)).?;
    try std.testing.expectEqualStrings("second reply", moved_payload[0..other_response.message.payload_len]);

    _ = try kernel.sharedMemoryMap(testContext(.shared_memory_map, shared_result.capability_id, .none), app_task_desc.task_id, 10);
    const resources = try kernel.resourceQuery(testContext(.resource_query, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, 10);
    const accounting = try kernel.accountingQuery(testContext(.accounting_query, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, 10);
    try std.testing.expectEqual(@as(u16, 2), resources.endpoint_count);
    try std.testing.expect(accounting.audit_event_count >= 1);
    try std.testing.expectEqual(@as(u8, @backingInt(accelerator_scheduler.ResourceClass.batch_compute)), abi.taskFlagsResourceClass(resources.flags));

    var self_resource_context = testContext(.resource_query, authority_capability.id, .{ .task = session_task.id });
    self_resource_context.caller_task_id = session_task.id;
    const self_resources = try kernel.resourceQuery(self_resource_context, session_task.id, 10);
    var self_accounting_context = testContext(.accounting_query, authority_capability.id, .{ .task = session_task.id });
    self_accounting_context.caller_task_id = session_task.id;
    const self_accounting = try kernel.accountingQuery(self_accounting_context, session_task.id, 10);
    try std.testing.expectEqual(session_task.id, self_resources.task_id);
    try std.testing.expectEqual(session_task.id, self_accounting.task_id);

    try std.testing.expectEqual(@as(u64, 10), try kernel.timeQuery(testContext(.time_query, authority_capability.id, .none), 10));
    for (0..endpoint.MAX_ENDPOINT_QUEUE) |index| {
        try kernel.endpointSend(send_context, index, "pending", 0, null, false, 11);
    }
    const wake_count = wake_probe.count;
    try std.testing.expectError(error.RingFull, kernel.endpointSend(send_context, 99, "overflow", 0, null, false, 11));
    try std.testing.expectEqual(wake_count, wake_probe.count);
}

test "native kernel descriptor authorization enforces request task scope" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel: Kernel = undefined;
    kernel.initInPlace(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    defer kernel.deinit();

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
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
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
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
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
    try expectNativeCapabilityLifecycle(.syscall);
}

test "direct runtime termination retires owned memory and all authority for dead objects" {
    try expectNativeCapabilityLifecycle(.terminate);
}

test "execution retirement retains shared backing and grants until acknowledged collection" {
    try expectNativeCapabilityLifecycle(.leased_terminate);
}

test "execution resource owner deinit preserves a replacement and tolerates prior unbinding" {
    var harness = TestKernelHarness{};
    defer harness.runtime.reset();
    var first: Kernel = undefined;
    var replacement: Kernel = undefined;
    harness.initKernel(&first);
    first.deinit();
    first.deinit();
    harness.initKernel(&replacement);
    defer replacement.deinit();
    first.deinit();
    try std.testing.expect(harness.runtime.task_retirement_sink.?.eql(replacement.retirementSink()));
    const task = try harness.createSessionTask();
    const ticket = try harness.runtime.reserveExecution(task, 0);
    try std.testing.expect(!harness.runtime.unbindTaskRetirementSink(replacement.retirementSink()));
    try harness.runtime.cancelUnstartedExecution(ticket);
    try harness.runtime.collectExecution(ticket);
    try std.testing.expect(harness.runtime.task_retirement_sink.?.eql(replacement.retirementSink()));
}

test "execution admission preserves active and suspended task resource operations" {
    var harness = TestKernelHarness{};
    var kernel: Kernel = undefined;
    harness.initKernel(&kernel);
    defer kernel.deinit();
    defer {
        harness.runtime.reset();
        harness.endpoints.deinit();
        harness.shared.deinit();
    }
    for ([_]bool{ false, true }) |suspended| {
        const task = try harness.createSessionTask();
        const authority = try harness.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = test_policy_authority,
            .target = .{ .kind = .service, .id = 42 },
            .rights = .{ .service = .{ .time_query = true, .endpoint_create = true, .shared_memory_create = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try harness.runtime.grantCapability(task.id, authority.id);
        if (suspended) try std.testing.expect(harness.runtime.suspendResolvedTask(task, 0));
        var context = testContext(.time_query, authority.id, .none);
        context.caller_task_id = task.id;
        try std.testing.expectEqual(@as(u64, 1), try kernel.timeQuery(context, 1));
        try std.testing.expectEqual(@as(u64, 1), try kernel.timeQuery(testContext(.time_query, authority.id, .none), 1));
        const created_endpoint = try kernel.endpointCreate(context, task.id, "admitted", .{ .local_only = true }, 1);
        const created_shared = try kernel.sharedMemoryCreate(context, task.id, shared_memory.PAGE_SIZE, 1);
        const map_context = KernelCallContext{ .caller_task_id = task.id, .presented_capability_id = created_shared.capability_id, .target = .none };
        _ = try kernel.sharedMemoryMap(map_context, task.id, 1);
        try std.testing.expectEqual(@as(u16, 1), harness.shared.mappingsForTask(ids.task(task.id)));
        try std.testing.expectEqual(created_endpoint.endpoint.endpoint_id, (try harness.endpoints.descriptor(ids.endpoint(created_endpoint.endpoint.endpoint_id))).endpoint_id);
        try harness.runtime.grantCapability(task.id, 777);
        _ = try harness.runtime.attachComponent(task.id, .{ .label = "admitted", .entry = "admitted" }, 1);
        try std.testing.expectEqual(if (suspended) task_runtime.TaskState.suspended else task_runtime.TaskState.active, task.state);
    }
}

test "runtime reset retires owned memory endpoints and authority" {
    try expectNativeCapabilityLifecycle(.reset);
}

test "checkpoint restore retires removed tasks and their kernel resources" {
    try expectNativeCapabilityLifecycle(.restore);
}

fn expectNativeCapabilityLifecycle(action: enum { syscall, terminate, leased_terminate, reset, restore }) !void {
    const cpu_identity = @import("../../kernel/cpu_identity.zig");
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel: Kernel = undefined;
    kernel.initInPlace(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    defer kernel.deinit();
    defer if (action == .leased_terminate) {
        runtime.reset();
        endpoints.deinit();
        shared.deinit();
    };

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
    const target_task_id = target_task.id;
    switch (action) {
        .leased_terminate => {
            const creator = try capabilities.mintBootRoot(.{
                .holder = test_policy_authority,
                .issuer = test_policy_authority,
                .target = .{ .kind = .service, .id = 42 },
                .rights = .{ .service = .{ .endpoint_create = true, .shared_memory_create = true } },
                .scope = .{ .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
            });
            const gift = try capabilities.mintBootRoot(.{
                .holder = test_policy_authority,
                .issuer = test_policy_authority,
                .target = .{ .kind = .service, .id = 43 },
                .rights = .{ .service = .{ .capability_pass = true, .capability_derive = true, .time_query = true } },
                .scope = .{ .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
            });
            const retained = try capabilities.mintBootRoot(.{
                .holder = target_task.owner,
                .issuer = test_policy_authority,
                .target = .{ .kind = .service, .id = 44 },
                .rights = .{ .service = .{ .time_query = true } },
                .scope = .{ .task_id = target_task.id, .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
            });
            try runtime.grantCapability(target_task.id, retained.id);
            try std.testing.expectEqual(@as(u64, 10), try kernel.timeQuery(testContext(.time_query, retained.id, .none), 10));
            const peer_task = try runtime.createTask(.{
                .owner = target_task.owner,
                .component_class = .app_component,
                .budget = .{ .cpu_time_ticks = 100, .memory_bytes = shared_memory.PAGE_SIZE, .endpoint_slots = 2, .shared_memory_bytes = shared_memory.PAGE_SIZE },
                .local_only = true,
            });
            const retained_unscoped = try capabilities.mintBootRoot(.{
                .holder = target_task.owner,
                .issuer = test_policy_authority,
                .target = .{ .kind = .service, .id = 45 },
                .rights = .{ .service = .{ .time_query = true } },
                .scope = .{ .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
            });
            try runtime.grantCapability(target_task.id, retained_unscoped.id);
            try runtime.grantCapability(peer_task.id, retained_unscoped.id);
            try std.testing.expectEqual(@as(u64, 10), try kernel.timeQuery(testContext(.time_query, retained_unscoped.id, .none), 10));
            const peer_endpoint = try endpoints.create(ids.task(peer_task.id), "live-peer", .{});
            try endpoints.connect(task_endpoint.id, peer_endpoint.id);
            var admission_probe = DeadTaskAdmissionProbe{
                .kernel = &kernel,
                .task = target_task,
                .creator = creator.id,
                .mint_authority = admin_capability.id,
                .gift = gift.id,
                .mapping_authority = external_peer_shared_authority.id,
                .retained_authority = retained.id,
                .retained_unscoped_authority = retained_unscoped.id,
                .live_peer_id = peer_task.id,
            };
            kernel.bindEndpointWakeSink(.{ .context = &admission_probe, .wake = DeadTaskAdmissionProbe.wake });
            defer kernel.clearEndpointWakeSink();
            const ticket = try runtime.reserveExecution(target_task, 15);
            try runtime.execution.bindOwnedRoot(ticket, 1, 0x1000);
            cpu_identity.setIndexForTest(15);
            _ = try runtime.execution.start(ticket);
            cpu_identity.setIndexForTest(0);
            const grants = capabilities.activeCount();
            const attached = target_task.capability_count;
            const address_space_id = target_task.address_space_id;
            try std.testing.expect(try runtime.terminateTask(target_task_id, 11));
            try std.testing.expectEqual(grants, capabilities.activeCount());
            try std.testing.expectEqual(attached, target_task.capability_count);
            try std.testing.expect(runtime.findAddressSpaceConst(address_space_id) != null);
            try std.testing.expectEqual(@as(u16, 1), endpoints.activeForTask(ids.task(target_task_id)));
            try std.testing.expectEqual(@as(u16, 2), shared.mappingsForTask(ids.task(target_task_id)));
            try std.testing.expect(shared.hasMapping(owned_shared.id, ids.task(999)));
            try admission_probe.check(true);
            try std.testing.expectError(error.WrongPhase, runtime.collectExecution(ticket));
            cpu_identity.setIndexForTest(15);
            try runtime.execution.acknowledgeOwnedRootReturn(ticket);
            cpu_identity.setIndexForTest(0);
            try runtime.collectExecution(ticket);
            try std.testing.expectEqual(@as(usize, 1), admission_probe.callbacks);
            try std.testing.expect(runtime.findAddressSpaceConst(address_space_id) == null);
        },
        .terminate => try std.testing.expect(try runtime.terminateTask(target_task_id, 11)),
        .syscall => try std.testing.expect(try kernel.taskTerminate(testContext(.task_terminate, task_capability.id, .none), 11)),
        .reset => {
            runtime.reset();
            runtime.reset();
        },
        .restore => {
            const empty = try std.testing.allocator.create(task_runtime.Snapshot);
            defer std.testing.allocator.destroy(empty);
            empty.* = task_runtime.Runtime.initSnapshot();
            try runtime.restoreFromSnapshot(empty);
            try runtime.restoreFromSnapshot(empty);
        },
    }
    try std.testing.expect(capabilities.query(task_capability.id) == null);
    try std.testing.expect(capabilities.query(external_task_authority.id) == null);
    try std.testing.expect(capabilities.query(external_endpoint_authority.id) == null);
    try std.testing.expect(capabilities.query(external_owned_shared_authority.id) == null);
    try std.testing.expect(capabilities.query(external_peer_shared_authority.id) != null);
    try std.testing.expect(capabilities.query(admin_capability.id) != null);
    try std.testing.expectEqual(@as(u16, 0), endpoints.activeForTask(ids.task(target_task_id)));
    try std.testing.expectError(error.EndpointNotFound, endpoints.descriptor(task_endpoint.id));
    try std.testing.expectEqual(@as(u16, 0), shared.mappingsForTask(ids.task(target_task_id)));
    try std.testing.expectError(error.SharedMemoryNotFound, shared.descriptor(owned_shared.id));
    try std.testing.expectEqual(@as(u16, 0), (try shared.descriptor(peer_shared.id)).flags);
    try std.testing.expect(!shared.hasMapping(peer_shared.id, ids.task(target_task_id)));
    try std.testing.expect(shared.hasMapping(peer_shared.id, ids.task(999)));
}

test "task authority graph marks target-revoked capabilities unusable" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel: Kernel = undefined;
    kernel.initInPlace(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    defer kernel.deinit();

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
    }, 1);
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
    var kernel: Kernel = undefined;
    kernel.initInPlace(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    defer kernel.deinit();

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
    var kernel: Kernel = undefined;
    kernel.initInPlace(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    defer kernel.deinit();

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
    try device_broker.registerMmioWindows(0x1F001, &.{.{
        .base = 0,
        .physical_base = 0xF000_0000,
        .length = 4096,
        .writable = true,
    }});

    const descriptor = try kernel.deviceDescribe(testContext(.device_describe, device_capability.id, .none), 12);
    try std.testing.expectEqual(@as(u64, 0x1F001), descriptor.device_id);
    try std.testing.expectEqual(@as(u8, 1), descriptor.mmio_window_count);
    const window = try kernel.deviceMmioWindow(testContext(.device_mmio_window, device_capability.id, .none), 0, 12);
    try std.testing.expectEqual(@as(u64, 4096), window.length);
    try std.testing.expect((window.flags & abi.MMIO_WINDOW_FLAG_WRITABLE) != 0);
}
