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
    payload_len: usize,
    payload: [endpoint.MAX_MESSAGE_BYTES]u8,
    attached_capability: ?abi.CapabilityDescriptor = null,
};

pub const SharedMemoryCreateResult = struct {
    object: abi.SharedMemoryDescriptor,
    capability: abi.CapabilityDescriptor,
    capability_id: u64,
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
    operation: abi.NativeOperation,
    target: KernelTarget,
};

const AuthorizationInput = struct {
    request_task_id: ?u64 = null,
    request_local_only: ?bool = null,
    target_capability: ?*const capability.Capability = null,
};

pub const Error = task_runtime.Error || capability.Error || device_broker.Error || endpoint.Error || shared_memory.Error || error{
    InvalidCapabilityTarget,
    InvalidUserspaceImage,
    PermissionDenied,
    ResourceBudgetExceeded,
    ScopeViolation,
    UnexpectedOperation,
    UserspaceLaunchRequired,
};

pub const Kernel = struct {
    policy_authority: principal.PrincipalId,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    endpoint_table: *endpoint.Table,
    shared_memory_table: *shared_memory.Table,
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
        try self.runtime.audit(task.id, .{
            .kind = .created,
            .tick = now_ticks,
        });
        return taskDescriptor(task);
    }

    pub fn taskTerminate(self: *Kernel, context: KernelCallContext, now_ticks: u64) Error!bool {
        const task_capability = try self.authorizeOperation(.task_terminate, context, now_ticks, .{});
        return self.runtime.terminateTask(task_capability.target.id, now_ticks);
    }

    pub fn endpointCreate(
        self: *Kernel,
        context: KernelCallContext,
        owner_task_id: u64,
        label: []const u8,
        flags: endpoint.EndpointFlags,
        now_ticks: u64,
    ) Error!EndpointCreateResult {
        _ = try self.authorizeOperation(.endpoint_create, context, now_ticks, .{
            .request_task_id = owner_task_id,
            .request_local_only = flags.local_only,
        });

        const task = self.runtime.find(owner_task_id) orelse return error.TaskNotFound;
        try self.validateEndpointBudget(owner_task_id);
        const created = try self.endpoint_table.create(ids.task(owner_task_id), label, flags);
        const endpoint_capability = try self.applySingleAutoGrant(
            .endpoint_create,
            .created_endpoint_owner,
            owner_task_id,
            task.owner,
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
        now_ticks: u64,
    ) Error!?EndpointReceiveResult {
        const endpoint_capability = try self.authorizeOperation(.endpoint_recv, context, now_ticks, .{
            .request_task_id = receiver_task_id,
        });

        const message = (try self.endpoint_table.recv(ids.endpoint(endpoint_capability.target.id))) orelse return null;
        var result = EndpointReceiveResult{
            .message = .{
                .endpoint_id = endpoint_capability.target.id,
                .sender_task_id = message.sender_task_id.raw(),
                .correlation_id = message.correlation_id,
                .attached_capability_id = if (message.attached_capability_id) |id| id.raw() else 0,
                .payload_len = @intCast(message.len),
                .flags = @bitCast(message.flags),
            },
            .payload_len = message.len,
            .payload = [_]u8{0} ** endpoint.MAX_MESSAGE_BYTES,
        };
        @memcpy(result.payload[0..message.len], message.payload());

        if (message.attached_capability_id) |attached_capability_id| {
            const receiver = self.runtime.find(receiver_task_id) orelse return error.TaskNotFound;
            try self.validateRuntimeGrant(receiver_task_id, 1);
            const original = self.capability_table.query(attached_capability_id.raw()) orelse return error.CapabilityNotFound;
            const passed = try self.capability_table.pass(.{
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
            });
            errdefer self.capability_table.rollbackGrant(&.{passed});
            try self.runtime.grantCapability(receiver_task_id, passed.id);

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
        _ = try self.authorizeOperation(.capability_mint, context, now_ticks, .{
            .request_task_id = request.scope.task_id,
        });
        if (request.scope.task_id) |task_id| {
            const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
            if (!task.owner.eql(request.holder)) return error.PermissionDenied;
        }

        var plan = capability.GrantPlan{};
        if (request.scope.task_id) |task_id| {
            try plan.addMint(task_id, request);
        } else {
            try plan.addMint(0, request);
        }
        var minted_buffer: [capability.MAX_GRANT_PLAN_ENTRIES]capability.Capability = undefined;
        const minted = (try self.applyGrantPlan(&plan, &minted_buffer))[0];
        return capabilityDescriptor(&minted);
    }

    pub fn applyGrantPlan(
        self: *Kernel,
        plan: *const capability.GrantPlan,
        output: []capability.Capability,
    ) Error![]capability.Capability {
        try self.validateRuntimeGrantPlan(plan);
        const minted = try self.capability_table.applyGrantPlan(plan, output);
        var attached_count: usize = 0;
        errdefer {
            var revoke_index: usize = 0;
            while (revoke_index < attached_count) : (revoke_index += 1) {
                const entry = plan.entries[revoke_index];
                if (entry.task_id != 0) {
                    _ = self.runtime.revokeCapability(entry.task_id, minted[revoke_index].id) catch |err|
                        native_util.impossibleByInvariantError("rollback revokes capabilities attached earlier in this kernel grant transaction", err);
                }
            }
            self.capability_table.rollbackGrant(minted);
        }
        for (plan.slice(), minted) |entry, granted_capability| {
            if (entry.task_id != 0) {
                try self.runtime.grantCapability(entry.task_id, granted_capability.id);
            }
            attached_count += 1;
        }
        return minted;
    }

    fn applySingleGrantPlan(
        self: *Kernel,
        task_id: u64,
        request: capability.MintRequest,
    ) Error!struct { capability: capability.Capability } {
        var plan = capability.GrantPlan{};
        try plan.addMint(task_id, request);
        var minted_buffer: [1]capability.Capability = undefined;
        const minted = try self.applyGrantPlan(&plan, &minted_buffer);
        return .{ .capability = minted[0] };
    }

    fn applySingleAutoGrant(
        self: *Kernel,
        comptime operation: abi.NativeOperation,
        comptime grant_kind: operation_metadata.AutoGrantKind,
        task_id: u64,
        holder: principal.PrincipalId,
        target: capability.CapabilityTarget,
        request_local_only: bool,
        now_ticks: u64,
    ) Error!capability.Capability {
        const grant = operation_metadata.autoGrantFor(operation, grant_kind);
        const scoped_task_id: ?u64 = if (grant.task_scoped) task_id else null;
        const local_only = switch (grant.locality) {
            .request => request_local_only,
            .always_local => true,
        };
        return (try self.applySingleGrantPlan(task_id, .{
            .holder = holder,
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
                .source_task_id = task_id,
            },
        })).capability;
    }

    pub fn capabilityDerive(self: *Kernel, context: KernelCallContext, request: capability.DeriveRequest) Error!abi.CapabilityDescriptor {
        _ = try self.authorizeOperation(.capability_derive, context, request.lease.issued_at_ticks, .{
            .request_task_id = request.scope.task_id,
        });
        if (request.scope.task_id) |task_id| {
            const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
            if (!task.owner.eql(request.holder)) return error.PermissionDenied;
            try self.validateRuntimeGrant(task_id, 1);
        }
        const derived = try self.capability_table.derive(request);
        errdefer self.capability_table.rollbackGrant(&.{derived.*});
        if (request.scope.task_id) |task_id| {
            try self.runtime.grantCapability(task_id, derived.id);
        }
        return capabilityDescriptor(derived);
    }

    pub fn capabilityPass(
        self: *Kernel,
        context: KernelCallContext,
        receiver_task_id: u64,
        now_ticks: u64,
        revoke_source: bool,
    ) Error!abi.CapabilityDescriptor {
        const capability_id = context.presented_capability_id;
        _ = try self.authorizeOperation(.capability_pass, context, now_ticks, .{});
        const receiver = self.runtime.find(receiver_task_id) orelse return error.TaskNotFound;
        try self.validateRuntimeGrant(receiver_task_id, 1);
        const original = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        const passed = try self.capability_table.pass(.{
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
        });
        errdefer self.capability_table.rollbackGrant(&.{passed});
        try self.runtime.grantCapability(receiver_task_id, passed.id);
        if (revoke_source) {
            if (original.scope.task_id) |source_task_id| {
                _ = try self.runtime.revokeCapability(source_task_id, original.id);
            }
        }
        return capabilityDescriptor(&passed);
    }

    pub fn capabilityRevoke(self: *Kernel, context: KernelCallContext, capability_id: u64, now_ticks: u64) Error!void {
        const revoked = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        _ = try self.authorizeOperation(.capability_revoke, context, now_ticks, .{
            .target_capability = &revoked,
        });
        try self.capability_table.revokeTargetAuthority(capability_id);
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
        _ = try self.authorizeOperation(.shared_memory_create, context, now_ticks, .{
            .request_task_id = owner_task_id,
        });

        const task = self.runtime.find(owner_task_id) orelse return error.TaskNotFound;
        try self.validateSharedMemoryCreateBudget(owner_task_id, size_bytes);
        const object = try self.shared_memory_table.create(ids.task(owner_task_id), size_bytes);
        const object_capability = try self.applySingleAutoGrant(
            .shared_memory_create,
            .created_shared_memory_owner,
            owner_task_id,
            task.owner,
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
        const object_capability = try self.authorizeOperation(.shared_memory_map, context, now_ticks, .{
            .request_task_id = task_id,
        });
        const object_id = ids.sharedMemory(object_capability.target.id);
        if (!self.shared_memory_table.hasMapping(object_id, ids.task(task_id))) {
            const object_size = try self.shared_memory_table.objectSize(object_id);
            try self.validateSharedMemoryMapBudget(task_id, object_size);
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
        const object_capability = try self.authorizeOperation(.shared_memory_unmap, context, now_ticks, .{
            .request_task_id = task_id,
        });
        return self.shared_memory_table.unmap(ids.sharedMemory(object_capability.target.id), ids.task(task_id));
    }

    pub fn sharedMemoryRevoke(
        self: *Kernel,
        context: KernelCallContext,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        const object_capability = try self.authorizeOperation(.shared_memory_revoke, context, now_ticks, .{});
        try self.shared_memory_table.revoke(ids.sharedMemory(object_capability.target.id));
        return self.shared_memory_table.descriptor(ids.sharedMemory(object_capability.target.id));
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
        _ = try self.authorizeOperation(.resource_query, context, now_ticks, .{
            .request_task_id = task_id,
        });
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
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
        _ = try self.authorizeOperation(.accounting_query, context, now_ticks, .{
            .request_task_id = task_id,
        });
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
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

    pub fn devicePortRead(
        self: *Kernel,
        context: KernelCallContext,
        port: u16,
        width: abi.DevicePortWidth,
        now_ticks: u64,
    ) Error!u32 {
        const device_capability = try self.authorizeOperation(.device_port_read, context, now_ticks, .{});
        return device_broker.readPort(device_capability.target.id, port, width);
    }

    pub fn devicePortWrite(
        self: *Kernel,
        context: KernelCallContext,
        port: u16,
        width: abi.DevicePortWidth,
        value: u32,
        now_ticks: u64,
    ) Error!void {
        const device_capability = try self.authorizeOperation(.device_port_write, context, now_ticks, .{});
        return device_broker.writePort(device_capability.target.id, port, width, value);
    }

    pub fn requireTaskCapability(
        self: *Kernel,
        task_id: u64,
        capability_id: u64,
        now_ticks: u64,
    ) Error!*const capability.Capability {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        const owned = try self.capability_table.requireUsable(capability_id, now_ticks);
        if (!self.runtime.hasCapability(task_id, capability_id)) return error.CapabilityNotFound;
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
        const descriptor = operation_metadata.declarationFor(expected_operation);
        if (context.operation != descriptor.operation) return error.UnexpectedOperation;

        // Resolve the calling task first when authenticated, preserving the
        // original TaskNotFound-before-capability error ordering.
        const subject_task = if (context.caller_task_id != 0)
            (self.runtime.find(context.caller_task_id) orelse return error.TaskNotFound)
        else
            null;

        // Resolve live table membership, lease state, and target generation in
        // one indexed lookup. Callers consume the immutable record before any
        // capability-table mutation, so authorization never needs to copy the
        // full capability record.
        const owned = try self.capability_table.requireUsable(context.presented_capability_id, now_ticks);

        if (subject_task) |task| {
            if (!self.runtime.hasCapability(context.caller_task_id, context.presented_capability_id)) return error.CapabilityNotFound;
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
        return owned;
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

    fn validateRuntimeGrantPlan(self: *Kernel, plan: *const capability.GrantPlan) Error!void {
        for (plan.slice(), 0..) |entry, index| {
            if (entry.task_id == 0) continue;
            var planned_for_task: usize = 0;
            for (plan.entries[0 .. index + 1]) |candidate| {
                if (candidate.task_id == entry.task_id) planned_for_task += 1;
            }
            try self.validateRuntimeGrant(entry.task_id, planned_for_task);
        }
    }

    fn validateRuntimeGrant(self: *Kernel, task_id: u64, additional_count: usize) Error!void {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        if (task.capability_count + additional_count > task_runtime.MAX_TASK_CAPABILITIES) {
            return error.CapabilityTableFull;
        }
    }

    fn validateEndpointBudget(self: *Kernel, task_id: u64) Error!void {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        if (self.endpoint_table.activeForTask(ids.task(task_id)) >= task.budget.endpoint_slots) {
            return error.ResourceBudgetExceeded;
        }
    }

    fn validateSharedMemoryCreateBudget(self: *Kernel, task_id: u64, size_bytes: usize) Error!void {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        const allocated = self.shared_memory_table.liveOwnedBytesForTask(ids.task(task_id));
        const next_allocated = std.math.add(usize, allocated, size_bytes) catch return error.ResourceBudgetExceeded;
        if (next_allocated > task.budget.shared_memory_bytes) return error.ResourceBudgetExceeded;
    }

    fn validateSharedMemoryMapBudget(self: *Kernel, task_id: u64, size_bytes: usize) Error!void {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        const mapped = self.shared_memory_table.liveMappedBytesForTask(ids.task(task_id));
        const next_mapped = std.math.add(usize, mapped, size_bytes) catch return error.ResourceBudgetExceeded;
        if (next_mapped > task.budget.shared_memory_bytes) return error.ResourceBudgetExceeded;
    }
};

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
    return .{
        .caller_task_id = 0,
        .presented_capability_id = capability_id,
        .operation = operation,
        .target = target,
    };
}

const test_policy_authority: principal.PrincipalId = .{ .kind = .policy_authority, .serial = 1 };
const TEST_ATA_SECTOR_COUNT: u64 = 4096;

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
    const received = (try kernel.endpointRecv(testContext(.endpoint_recv, service_endpoint.capability_id, .none), service_task_desc.task_id, 10)).?;
    try std.testing.expectEqualStrings("sync-open", received.payload[0..received.payload_len]);
    try std.testing.expect(received.attached_capability != null);

    _ = try kernel.sharedMemoryMap(testContext(.shared_memory_map, shared_result.capability_id, .none), app_task_desc.task_id, 10);
    const resources = try kernel.resourceQuery(testContext(.resource_query, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, 10);
    const accounting = try kernel.accountingQuery(testContext(.accounting_query, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, 10);
    try std.testing.expectEqual(@as(u16, 1), resources.endpoint_count);
    try std.testing.expect(accounting.audit_event_count >= 1);
    try std.testing.expectEqual(@as(u8, @intFromEnum(accelerator_scheduler.ResourceClass.batch_compute)), abi.taskFlagsResourceClass(resources.flags));
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

    const next_capability_id = capabilities.next_capability_id;
    try std.testing.expectError(error.CapabilityTableFull, kernel.capabilityMint(testContext(.capability_mint, admin_capability.id, .{ .policy = 1 }), .{
        .holder = target_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .object, .id = 55 },
        .rights = .{ .object = .{ .object_read = true } },
        .scope = .{ .task_id = target_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    }, 10));
    try std.testing.expectEqual(next_capability_id, capabilities.next_capability_id);
    try std.testing.expect(capabilities.query(next_capability_id) == null);
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
    try std.testing.expect(device_broker.publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = TEST_ATA_SECTOR_COUNT,
    }));

    const descriptor = try kernel.deviceDescribe(testContext(.device_describe, device_capability.id, .none), 12);
    try std.testing.expectEqual(@as(u64, 0x1F001), descriptor.device_id);
    try std.testing.expectEqual(@as(u16, 0x1F0), descriptor.base_port);
    try std.testing.expectEqual(@as(u16, abi.DEVICE_DESCRIPTOR_FLAG_ATA_MASTER), descriptor.flags);

    try kernel.devicePortWrite(testContext(.device_port_write, device_capability.id, .none), 0x1F0 + 7, .u8, 0xA5, 12);
    try std.testing.expectEqual(@as(u32, 0xA5), try kernel.devicePortRead(testContext(.device_port_read, device_capability.id, .none), 0x1F0 + 7, .u8, 12));
    try std.testing.expectError(error.UnsupportedMmioWindow, kernel.deviceMmioWindow(testContext(.device_mmio_window, device_capability.id, .none), 0, 12));
}
