const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const device_broker = @import("device_broker.zig");
const endpoint = @import("endpoint.zig");
const kernel_access = @import("native_kernel_access.zig");
const kernel_descriptors = @import("native_kernel_descriptors.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const shared_memory = @import("shared_memory.zig");
const task_runtime = @import("../task/task_runtime.zig");

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

pub const Error = task_runtime.Error || capability.Error || device_broker.Error || endpoint.Error || shared_memory.Error || error{
    InvalidCapabilityTarget,
    InvalidUserspaceImage,
    PermissionDenied,
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
        const auth = try self.requireOperationCapability(context, .task_create, now_ticks, capability.CapabilityRights.single(.task_create));
        if (auth.scope.local_only and !request.local_only) return error.ScopeViolation;
        try validateTaskCreateRequest(request);

        const task = try self.runtime.createTask(request);
        try self.runtime.audit(task.id, .{
            .kind = .created,
            .tick = now_ticks,
        });
        return taskDescriptor(task);
    }

    pub fn taskTerminate(self: *Kernel, context: KernelCallContext, now_ticks: u64) Error!bool {
        const task_capability = try self.requireTargetedOperationCapability(
            context,
            .task_terminate,
            now_ticks,
            capability.CapabilityRights.single(.task_terminate),
            .task,
        );
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
        const auth = try self.requireOperationCapability(context, .endpoint_create, now_ticks, capability.CapabilityRights.single(.endpoint_create));
        if (auth.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != owner_task_id) return error.ScopeViolation;
        }
        if (auth.scope.local_only and !flags.local_only) return error.ScopeViolation;

        const task = self.runtime.find(owner_task_id) orelse return error.TaskNotFound;
        const created = try self.endpoint_table.create(owner_task_id, label, flags);
        const endpoint_capability = (try self.applySingleGrantPlan(owner_task_id, .{
            .holder = task.owner,
            .issuer = self.policy_authority,
            .target = .{ .kind = .endpoint, .id = created.id },
            .rights = .{ .endpoint = .{
                .endpoint_connect = true,
                .endpoint_send = true,
                .endpoint_recv = true,
                .capability_query = true,
                .ipc_peer = true,
            } },
            .scope = .{
                .task_id = owner_task_id,
                .local_only = flags.local_only,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = now_ticks,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = owner_task_id,
            },
        })).capability;

        return .{
            .endpoint = try self.endpoint_table.descriptor(created.id),
            .capability = capabilityDescriptor(endpoint_capability),
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
        const endpoint_capability = try self.requireTargetedOperationCapability(
            context,
            .endpoint_connect,
            now_ticks,
            capability.CapabilityRights.single(.endpoint_connect),
            .endpoint,
        );
        const peer_capability = try self.requirePeerEndpointCapability(
            peer_endpoint_capability_id,
            peer_endpoint_id,
            now_ticks,
        );
        if (endpoint_capability.scope.local_only != peer_capability.scope.local_only) return error.ScopeViolation;
        try self.endpoint_table.connect(endpoint_capability.target.id, peer_endpoint_id);
        return self.endpoint_table.descriptor(endpoint_capability.target.id);
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
        const endpoint_capability = try self.requireTargetedOperationCapability(
            context,
            .endpoint_send,
            now_ticks,
            capability.CapabilityRights.single(.endpoint_send),
            .endpoint,
        );
        if (attached_capability_id) |capability_id| {
            if (context.caller_task_id != 0) {
                try self.requireTaskCapability(context.caller_task_id, capability_id, now_ticks);
            }
            const attached = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
            if (!self.capability_table.isUsable(attached, now_ticks)) return error.CapabilityRevoked;
            if (!attached.rights.has(.capability_pass)) return error.PermissionDenied;
            if (attached.scope.task_id != endpoint_capability.scope.task_id) return error.ScopeViolation;
        }

        try self.endpoint_table.send(
            endpoint_capability.target.id,
            endpoint_capability.scope.task_id orelse 0,
            correlation_id,
            payload,
            attached_capability_id,
            move_attached_capability,
        );
    }

    pub fn endpointRecv(
        self: *Kernel,
        context: KernelCallContext,
        receiver_task_id: u64,
        now_ticks: u64,
    ) Error!?EndpointReceiveResult {
        const endpoint_capability = try self.requireTargetedOperationCapability(
            context,
            .endpoint_recv,
            now_ticks,
            capability.CapabilityRights.single(.endpoint_recv),
            .endpoint,
        );
        if (endpoint_capability.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != receiver_task_id) return error.ScopeViolation;
        }

        const message = (try self.endpoint_table.recv(endpoint_capability.target.id)) orelse return null;
        var result = EndpointReceiveResult{
            .message = .{
                .endpoint_id = endpoint_capability.target.id,
                .sender_task_id = message.sender_task_id,
                .correlation_id = message.correlation_id,
                .attached_capability_id = message.attached_capability_id orelse 0,
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
            const original = self.capability_table.query(attached_capability_id) orelse return error.CapabilityNotFound;
            const passed = try self.capability_table.pass(.{
                .capability_id = attached_capability_id,
                .new_holder = receiver.owner,
                .now_ticks = now_ticks,
                .revoke_source = message.move_attached_capability,
                .allow_task_retarget = true,
                .scope = retargetTaskScope(original.scope, receiver_task_id),
                .audit = .{
                    .policy_generation = original.audit.policy_generation,
                    .source_task_id = message.sender_task_id,
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

            result.attached_capability = capabilityDescriptor(passed);
        }

        return result;
    }

    pub fn capabilityMint(
        self: *Kernel,
        context: KernelCallContext,
        request: capability.MintRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        try self.requireCallSubject(context, .capability_mint, now_ticks);
        _ = try self.requireTargetedCapability(context.presented_capability_id, now_ticks, .{ .policy = .{
            .capability_mint = true,
        } }, .policy);
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
        return capabilityDescriptor(minted);
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

    pub fn capabilityDerive(self: *Kernel, context: KernelCallContext, request: capability.DeriveRequest) Error!abi.CapabilityDescriptor {
        _ = try self.requireOperationCapability(context, .capability_derive, request.lease.issued_at_ticks, capability.CapabilityRights.single(.capability_derive));
        if (request.scope.task_id) |task_id| {
            const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
            if (!task.owner.eql(request.holder)) return error.PermissionDenied;
            try self.validateRuntimeGrant(task_id, 1);
        }
        const derived = try self.capability_table.derive(request);
        errdefer self.capability_table.rollbackGrant(&.{derived});
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
        _ = try self.requireOperationCapability(context, .capability_pass, now_ticks, capability.CapabilityRights.single(.capability_pass));
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
        return capabilityDescriptor(passed);
    }

    pub fn capabilityRevoke(self: *Kernel, context: KernelCallContext, capability_id: u64, now_ticks: u64) Error!void {
        const revoked = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        _ = try self.requireCapabilityOperationAuthority(context, .capability_revoke, now_ticks, revoked, .capability_revoke);
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
        _ = try self.requireCapabilityOperationAuthority(context, .capability_query, now_ticks, queried, .capability_query);
        return capabilityDescriptor(queried);
    }

    pub fn sharedMemoryCreate(
        self: *Kernel,
        context: KernelCallContext,
        owner_task_id: u64,
        size_bytes: usize,
        now_ticks: u64,
    ) Error!SharedMemoryCreateResult {
        const auth = try self.requireOperationCapability(context, .shared_memory_create, now_ticks, .{ .shared_memory = .{
            .shared_memory_create = true,
        } });
        if (auth.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != owner_task_id) return error.ScopeViolation;
        }

        const task = self.runtime.find(owner_task_id) orelse return error.TaskNotFound;
        const object = try self.shared_memory_table.create(owner_task_id, size_bytes);
        const object_capability = (try self.applySingleGrantPlan(owner_task_id, .{
            .holder = task.owner,
            .issuer = self.policy_authority,
            .target = .{ .kind = .shared_memory, .id = object.id },
            .rights = .{ .shared_memory = .{
                .shared_memory_map = true,
                .shared_memory_unmap = true,
                .shared_memory_revoke = true,
                .capability_pass = true,
                .capability_query = true,
            } },
            .scope = .{
                .task_id = owner_task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = now_ticks,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = owner_task_id,
            },
        })).capability;

        return .{
            .object = try self.shared_memory_table.descriptor(object.id),
            .capability = capabilityDescriptor(object_capability),
            .capability_id = object_capability.id,
        };
    }

    pub fn sharedMemoryMap(
        self: *Kernel,
        context: KernelCallContext,
        task_id: u64,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        const object_capability = try self.requireTargetedOperationCapability(
            context,
            .shared_memory_map,
            now_ticks,
            capability.CapabilityRights.single(.shared_memory_map),
            .shared_memory,
        );
        if (object_capability.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != task_id) return error.ScopeViolation;
        }
        try self.shared_memory_table.map(object_capability.target.id, task_id);
        return self.shared_memory_table.descriptor(object_capability.target.id);
    }

    pub fn sharedMemoryUnmap(
        self: *Kernel,
        context: KernelCallContext,
        task_id: u64,
        now_ticks: u64,
    ) Error!bool {
        const object_capability = try self.requireTargetedOperationCapability(
            context,
            .shared_memory_unmap,
            now_ticks,
            capability.CapabilityRights.single(.shared_memory_unmap),
            .shared_memory,
        );
        if (object_capability.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != task_id) return error.ScopeViolation;
        }
        return self.shared_memory_table.unmap(object_capability.target.id, task_id);
    }

    pub fn sharedMemoryRevoke(
        self: *Kernel,
        context: KernelCallContext,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        const object_capability = try self.requireTargetedOperationCapability(
            context,
            .shared_memory_revoke,
            now_ticks,
            capability.CapabilityRights.single(.shared_memory_revoke),
            .shared_memory,
        );
        try self.shared_memory_table.revoke(object_capability.target.id);
        return self.shared_memory_table.descriptor(object_capability.target.id);
    }

    pub fn timeQuery(self: *Kernel, context: KernelCallContext, now_ticks: u64) Error!u64 {
        _ = try self.requireOperationCapability(context, .time_query, now_ticks, capability.CapabilityRights.single(.time_query));
        return now_ticks;
    }

    pub fn resourceQuery(
        self: *Kernel,
        context: KernelCallContext,
        task_id: u64,
        now_ticks: u64,
    ) Error!abi.ResourceDescriptor {
        _ = try self.requireOperationCapability(context, .resource_query, now_ticks, capability.CapabilityRights.single(.resource_query));
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        return .{
            .task_id = task.id,
            .state = @intFromEnum(task.state),
            .capability_count = @intCast(task.capability_count),
            .endpoint_count = self.endpoint_table.activeForTask(task_id),
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
        _ = try self.requireOperationCapability(context, .accounting_query, now_ticks, capability.CapabilityRights.single(.accounting_query));
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        return .{
            .task_id = task.id,
            .audit_event_count = @intCast(task.audit_count),
            .capability_count = @intCast(task.capability_count),
            .component_count = @intCast(task.execution_component_count),
            .endpoint_count = self.endpoint_table.activeForTask(task_id),
            .shared_memory_mappings = self.shared_memory_table.mappingsForTask(task_id),
            .ui_surface_id = task.ui_surface_id orelse 0,
        };
    }

    pub fn deviceDescribe(
        self: *Kernel,
        context: KernelCallContext,
        now_ticks: u64,
    ) Error!abi.DeviceDescriptor {
        const device_capability = try self.requireTargetedOperationCapability(
            context,
            .device_describe,
            now_ticks,
            capability.CapabilityRights.single(.device_use),
            .device,
        );
        return deviceDescriptor(try device_broker.describe(device_capability.target.id));
    }

    pub fn deviceMmioWindow(
        self: *Kernel,
        context: KernelCallContext,
        window_index: u8,
        now_ticks: u64,
    ) Error!abi.DeviceMmioWindowDescriptor {
        const device_capability = try self.requireTargetedOperationCapability(
            context,
            .device_mmio_window,
            now_ticks,
            capability.CapabilityRights.single(.device_use),
            .device,
        );
        return mmioWindowDescriptor(try device_broker.mmioWindow(device_capability.target.id, window_index));
    }

    pub fn devicePortRead(
        self: *Kernel,
        context: KernelCallContext,
        port: u16,
        width: abi.DevicePortWidth,
        now_ticks: u64,
    ) Error!u32 {
        const device_capability = try self.requireTargetedOperationCapability(
            context,
            .device_port_read,
            now_ticks,
            capability.CapabilityRights.single(.device_use),
            .device,
        );
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
        const device_capability = try self.requireTargetedOperationCapability(
            context,
            .device_port_write,
            now_ticks,
            capability.CapabilityRights.single(.device_use),
            .device,
        );
        return device_broker.writePort(device_capability.target.id, port, width, value);
    }

    pub fn requireTaskCapability(
        self: *Kernel,
        task_id: u64,
        capability_id: u64,
        now_ticks: u64,
    ) Error!void {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        const owned = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        if (!self.capability_table.isUsable(owned, now_ticks)) return error.CapabilityRevoked;
        if (!self.runtime.hasCapability(task_id, capability_id)) return error.CapabilityNotFound;
        if (!task.owner.eql(owned.holder)) return error.PermissionDenied;
        if (owned.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != task_id) return error.ScopeViolation;
        }
    }

    fn requireCapability(
        self: *Kernel,
        capability_id: u64,
        now_ticks: u64,
        needed_rights: capability.CapabilityRights,
    ) Error!capability.Capability {
        return kernel_access.requireCapability(Error, self, capability_id, now_ticks, needed_rights);
    }

    fn requireOperationCapability(
        self: *Kernel,
        context: KernelCallContext,
        expected_operation: abi.NativeOperation,
        now_ticks: u64,
        needed_rights: capability.CapabilityRights,
    ) Error!capability.Capability {
        try self.requireCallSubject(context, expected_operation, now_ticks);
        return self.requireCapability(context.presented_capability_id, now_ticks, needed_rights);
    }

    fn requireTargetedCapability(
        self: *Kernel,
        capability_id: u64,
        now_ticks: u64,
        needed_rights: capability.CapabilityRights,
        target_kind: capability.CapabilityTargetKind,
    ) Error!capability.Capability {
        return kernel_access.requireTargetedCapability(
            Error,
            self,
            capability_id,
            now_ticks,
            needed_rights,
            target_kind,
        );
    }

    fn requireTargetedOperationCapability(
        self: *Kernel,
        context: KernelCallContext,
        expected_operation: abi.NativeOperation,
        now_ticks: u64,
        needed_rights: capability.CapabilityRights,
        target_kind: capability.CapabilityTargetKind,
    ) Error!capability.Capability {
        try self.requireCallSubject(context, expected_operation, now_ticks);
        const owned = try self.requireTargetedCapability(
            context.presented_capability_id,
            now_ticks,
            needed_rights,
            target_kind,
        );
        try validateContextTarget(context.target, owned.target);
        return owned;
    }

    fn requirePeerEndpointCapability(
        self: *Kernel,
        peer_endpoint_capability_id: u64,
        peer_endpoint_id: u64,
        now_ticks: u64,
    ) Error!capability.Capability {
        const peer = try self.requireTargetedCapability(
            peer_endpoint_capability_id,
            now_ticks,
            .{ .endpoint = .{ .ipc_peer = true } },
            .endpoint,
        );
        if (peer.target.id != peer_endpoint_id) return error.InvalidCapabilityTarget;
        return peer;
    }

    fn requireCapabilityOperationAuthority(
        self: *Kernel,
        context: KernelCallContext,
        expected_operation: abi.NativeOperation,
        now_ticks: u64,
        target_capability: capability.Capability,
        right: capability.CapabilityRight,
    ) Error!capability.Capability {
        try self.requireCallSubject(context, expected_operation, now_ticks);
        const authority = try self.requireTargetedCapability(
            context.presented_capability_id,
            now_ticks,
            capability.CapabilityRights.single(right).retarget(target_capability.target.kind),
            target_capability.target.kind,
        );
        if (!authority.target.eql(target_capability.target)) return error.InvalidCapabilityTarget;
        try validateContextTarget(context.target, target_capability.target);
        return authority;
    }

    fn requireCallSubject(
        self: *Kernel,
        context: KernelCallContext,
        expected_operation: abi.NativeOperation,
        now_ticks: u64,
    ) Error!void {
        if (context.operation != expected_operation) return error.UnexpectedOperation;
        if (context.caller_task_id != 0) {
            try self.requireTaskCapability(context.caller_task_id, context.presented_capability_id, now_ticks);
        }
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

fn capabilityDescriptor(owned: capability.Capability) abi.CapabilityDescriptor {
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

test "native kernel creates tasks endpoints and shared memory without owning service discovery" {
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

    const session_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 2 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 10_000,
            .memory_bytes = 4096,
            .endpoint_slots = 8,
            .shared_memory_bytes = 4096,
        },
        .local_only = true,
    });
    const authority_capability = try capabilities.mintBootRoot(.{
        .holder = session_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{ .service = .{
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
        } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });

    const workspace_storage_image = task_runtime.syntheticUserspaceImage("workspace-storage", "zigos.object.workspace");
    const example_client_image = task_runtime.syntheticUserspaceImage("example-client", "app.example.client");
    const service_task_desc = try kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .service, .serial = 3 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
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
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
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

    const shared_result = try kernel.sharedMemoryCreate(testContext(.shared_memory_create, authority_capability.id, .{ .task = app_task_desc.task_id }), app_task_desc.task_id, 4096, 9);
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

test "native kernel rejects app and service launches without userspace image provenance" {
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

    const session_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 2 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 10_000,
            .memory_bytes = 4096,
            .endpoint_slots = 8,
            .shared_memory_bytes = 4096,
        },
        .local_only = true,
    });
    const authority_capability = try capabilities.mintBootRoot(.{
        .holder = session_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{ .service = .{
            .task_create = true,
        } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });

    try std.testing.expectError(error.UserspaceLaunchRequired, kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
        },
        .local_only = true,
    }, 5));
    try std.testing.expectError(error.InvalidUserspaceImage, kernel.taskCreate(testContext(.task_create, authority_capability.id, .{ .task = 0 }), .{
        .owner = .{ .kind = .service, .serial = 5 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 0,
            .component_abi_version = 1,
            .signed = true,
        },
    }, 6));
}

test "native kernel leaves typed service registration outside the TCB" {
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

    const session_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 2 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 10_000,
            .memory_bytes = 4096,
            .endpoint_slots = 8,
            .shared_memory_bytes = 4096,
        },
        .local_only = true,
    });
    const authority_capability = try capabilities.mintBootRoot(.{
        .holder = session_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{ .service = .{
            .endpoint_create = true,
            .endpoint_connect = true,
            .ipc_peer = true,
        } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });

    const direct_service_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 7 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
        },
        .local_only = true,
        .initial_component = .{
            .label = "legacy-service",
            .entry = "zigos.legacy.service",
        },
    });
    _ = try kernel.endpointCreate(testContext(.endpoint_create, authority_capability.id, .{ .task = direct_service_task.id }), direct_service_task.id, "zigos.legacy.service", .{
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
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
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
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
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

    const storage_driver_test_image = task_runtime.syntheticUserspaceImage(
        "storage-driver-test",
        "zigos.system.storage-driver",
    );
    const driver_task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 4 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
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
        .sector_count = 4096,
    }));

    const descriptor = try kernel.deviceDescribe(testContext(.device_describe, device_capability.id, .none), 12);
    try std.testing.expectEqual(@as(u64, 0x1F001), descriptor.device_id);
    try std.testing.expectEqual(@as(u16, 0x1F0), descriptor.base_port);
    try std.testing.expectEqual(@as(u16, abi.DEVICE_DESCRIPTOR_FLAG_ATA_MASTER), descriptor.flags);

    try kernel.devicePortWrite(testContext(.device_port_write, device_capability.id, .none), 0x1F0 + 7, .u8, 0xA5, 12);
    try std.testing.expectEqual(@as(u32, 0xA5), try kernel.devicePortRead(testContext(.device_port_read, device_capability.id, .none), 0x1F0 + 7, .u8, 12));
    try std.testing.expectError(error.UnsupportedMmioWindow, kernel.deviceMmioWindow(testContext(.device_mmio_window, device_capability.id, .none), 0, 12));
}
