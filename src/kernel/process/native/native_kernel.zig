const std = @import("std");
const abi = @import("abi.zig");
const capability = @import("capability.zig");
const endpoint = @import("endpoint.zig");
const manifest = @import("manifest.zig");
const principal = @import("principal.zig");
const service_registry = @import("service_registry.zig");
const shared_memory = @import("shared_memory.zig");
const task_runtime = @import("task_runtime.zig");

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

pub const Error = task_runtime.Error || capability.Error || endpoint.Error || shared_memory.Error || service_registry.Error || error{
    InvalidCapabilityTarget,
    PermissionDenied,
    ScopeViolation,
};

pub const Kernel = struct {
    policy_authority: principal.PrincipalId,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    endpoint_table: *endpoint.Table,
    shared_memory_table: *shared_memory.Table,
    service_registry: *service_registry.Registry,

    pub fn init(
        policy_authority: principal.PrincipalId,
        runtime: *task_runtime.Runtime,
        capability_table: *capability.CapabilityTable,
        endpoint_table: *endpoint.Table,
        shared_memory_table: *shared_memory.Table,
        service_registry_table: *service_registry.Registry,
    ) Kernel {
        return .{
            .policy_authority = policy_authority,
            .runtime = runtime,
            .capability_table = capability_table,
            .endpoint_table = endpoint_table,
            .shared_memory_table = shared_memory_table,
            .service_registry = service_registry_table,
        };
    }

    pub fn taskCreate(
        self: *Kernel,
        authority_capability_id: u64,
        request: task_runtime.TaskCreateRequest,
        now_ticks: u64,
    ) Error!abi.TaskDescriptor {
        const auth = try self.requireCapability(authority_capability_id, now_ticks, .{ .task_create = true });
        if (auth.scope.local_only and !request.local_only) return error.ScopeViolation;

        const task = try self.runtime.createTask(request);
        try self.runtime.audit(task.id, .{
            .kind = .created,
            .tick = now_ticks,
        });
        return taskDescriptor(task);
    }

    pub fn taskTerminate(self: *Kernel, task_capability_id: u64, now_ticks: u64) Error!bool {
        const task_capability = try self.requireTargetedCapability(
            task_capability_id,
            now_ticks,
            .{ .task_terminate = true },
            .task,
        );
        return self.runtime.terminateTask(task_capability.target.id, now_ticks);
    }

    pub fn endpointCreate(
        self: *Kernel,
        authority_capability_id: u64,
        owner_task_id: u64,
        label: []const u8,
        flags: endpoint.EndpointFlags,
        now_ticks: u64,
    ) Error!EndpointCreateResult {
        const auth = try self.requireCapability(authority_capability_id, now_ticks, .{ .endpoint_create = true });
        if (auth.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != owner_task_id) return error.ScopeViolation;
        }
        if (auth.scope.local_only and !flags.local_only) return error.ScopeViolation;

        const task = self.runtime.find(owner_task_id) orelse return error.TaskNotFound;
        const created = try self.endpoint_table.create(owner_task_id, label, flags);
        const endpoint_capability = try self.capability_table.mint(.{
            .holder = task.owner,
            .issuer = self.policy_authority,
            .target = .{ .kind = .endpoint, .id = created.id },
            .rights = .{
                .endpoint_connect = true,
                .endpoint_send = true,
                .endpoint_recv = true,
                .capability_query = true,
            },
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
        });
        try self.runtime.grantCapability(owner_task_id, endpoint_capability.id);

        return .{
            .endpoint = try self.endpoint_table.descriptor(created.id),
            .capability = capabilityDescriptor(endpoint_capability),
            .capability_id = endpoint_capability.id,
        };
    }

    pub fn endpointConnect(
        self: *Kernel,
        endpoint_capability_id: u64,
        peer_endpoint_id: u64,
        now_ticks: u64,
    ) Error!abi.EndpointDescriptor {
        const endpoint_capability = try self.requireTargetedCapability(
            endpoint_capability_id,
            now_ticks,
            .{ .endpoint_connect = true },
            .endpoint,
        );
        try self.endpoint_table.connect(endpoint_capability.target.id, peer_endpoint_id);
        return self.endpoint_table.descriptor(endpoint_capability.target.id);
    }

    pub fn endpointSend(
        self: *Kernel,
        endpoint_capability_id: u64,
        correlation_id: u64,
        payload: []const u8,
        attached_capability_id: ?u64,
        move_attached_capability: bool,
        now_ticks: u64,
    ) Error!void {
        const endpoint_capability = try self.requireTargetedCapability(
            endpoint_capability_id,
            now_ticks,
            .{ .endpoint_send = true },
            .endpoint,
        );
        if (attached_capability_id) |capability_id| {
            const attached = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
            if (!self.capability_table.isUsable(attached, now_ticks)) return error.CapabilityRevoked;
            if (!attached.rights.capability_pass) return error.PermissionDenied;
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
        endpoint_capability_id: u64,
        receiver_task_id: u64,
        now_ticks: u64,
    ) Error!?EndpointReceiveResult {
        const endpoint_capability = try self.requireTargetedCapability(
            endpoint_capability_id,
            now_ticks,
            .{ .endpoint_recv = true },
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
            const original = self.capability_table.query(attached_capability_id) orelse return error.CapabilityNotFound;
            const passed = try self.capability_table.pass(.{
                .capability_id = attached_capability_id,
                .new_holder = receiver.owner,
                .now_ticks = now_ticks,
                .revoke_source = message.move_attached_capability,
                .scope = retargetTaskScope(original.scope, receiver_task_id),
                .audit = .{
                    .policy_generation = original.audit.policy_generation,
                    .source_task_id = message.sender_task_id,
                    .broker_service_id = original.audit.broker_service_id,
                },
            });
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
        policy_capability_id: u64,
        request: capability.MintRequest,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        const policy_capability = try self.requireCapability(policy_capability_id, now_ticks, .{
            .capability_mint = true,
        });
        if (policy_capability.holder.kind != .policy_authority) return error.PermissionDenied;

        const minted = try self.capability_table.mint(request);
        if (request.scope.task_id) |task_id| {
            try self.runtime.grantCapability(task_id, minted.id);
        }
        return capabilityDescriptor(minted);
    }

    pub fn capabilityDerive(self: *Kernel, request: capability.DeriveRequest) Error!abi.CapabilityDescriptor {
        const derived = try self.capability_table.derive(request);
        if (request.scope.task_id) |task_id| {
            try self.runtime.grantCapability(task_id, derived.id);
        }
        return capabilityDescriptor(derived);
    }

    pub fn capabilityPass(
        self: *Kernel,
        capability_id: u64,
        receiver_task_id: u64,
        now_ticks: u64,
        revoke_source: bool,
    ) Error!abi.CapabilityDescriptor {
        const receiver = self.runtime.find(receiver_task_id) orelse return error.TaskNotFound;
        const original = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        const passed = try self.capability_table.pass(.{
            .capability_id = capability_id,
            .new_holder = receiver.owner,
            .now_ticks = now_ticks,
            .revoke_source = revoke_source,
            .scope = retargetTaskScope(original.scope, receiver_task_id),
            .audit = .{
                .policy_generation = original.audit.policy_generation,
                .source_task_id = original.scope.task_id orelse 0,
                .broker_service_id = original.audit.broker_service_id,
            },
        });
        try self.runtime.grantCapability(receiver_task_id, passed.id);
        if (revoke_source) {
            if (original.scope.task_id) |source_task_id| {
                _ = try self.runtime.revokeCapability(source_task_id, original.id);
            }
        }
        return capabilityDescriptor(passed);
    }

    pub fn capabilityRevoke(self: *Kernel, authority_capability_id: u64, capability_id: u64, now_ticks: u64) Error!void {
        _ = try self.requireCapability(authority_capability_id, now_ticks, .{ .capability_revoke = true });
        const revoked = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        try self.capability_table.revoke(capability_id);
        if (revoked.scope.task_id) |task_id| {
            _ = try self.runtime.revokeCapability(task_id, capability_id);
        }
    }

    pub fn capabilityQuery(
        self: *Kernel,
        authority_capability_id: u64,
        capability_id: u64,
        now_ticks: u64,
    ) Error!abi.CapabilityDescriptor {
        _ = try self.requireCapability(authority_capability_id, now_ticks, .{ .capability_query = true });
        const queried = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        return capabilityDescriptor(queried);
    }

    pub fn sharedMemoryCreate(
        self: *Kernel,
        authority_capability_id: u64,
        owner_task_id: u64,
        size_bytes: usize,
        now_ticks: u64,
    ) Error!SharedMemoryCreateResult {
        const auth = try self.requireCapability(authority_capability_id, now_ticks, .{
            .shared_memory_create = true,
        });
        if (auth.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != owner_task_id) return error.ScopeViolation;
        }

        const task = self.runtime.find(owner_task_id) orelse return error.TaskNotFound;
        const object = try self.shared_memory_table.create(owner_task_id, size_bytes);
        const object_capability = try self.capability_table.mint(.{
            .holder = task.owner,
            .issuer = self.policy_authority,
            .target = .{ .kind = .shared_memory, .id = object.id },
            .rights = .{
                .shared_memory_map = true,
                .shared_memory_unmap = true,
                .shared_memory_revoke = true,
                .capability_pass = true,
                .capability_query = true,
            },
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
        });
        try self.runtime.grantCapability(owner_task_id, object_capability.id);

        return .{
            .object = try self.shared_memory_table.descriptor(object.id),
            .capability = capabilityDescriptor(object_capability),
            .capability_id = object_capability.id,
        };
    }

    pub fn sharedMemoryMap(
        self: *Kernel,
        shared_memory_capability_id: u64,
        task_id: u64,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        const object_capability = try self.requireTargetedCapability(
            shared_memory_capability_id,
            now_ticks,
            .{ .shared_memory_map = true },
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
        shared_memory_capability_id: u64,
        task_id: u64,
        now_ticks: u64,
    ) Error!bool {
        const object_capability = try self.requireTargetedCapability(
            shared_memory_capability_id,
            now_ticks,
            .{ .shared_memory_unmap = true },
            .shared_memory,
        );
        if (object_capability.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != task_id) return error.ScopeViolation;
        }
        return self.shared_memory_table.unmap(object_capability.target.id, task_id);
    }

    pub fn sharedMemoryRevoke(
        self: *Kernel,
        shared_memory_capability_id: u64,
        now_ticks: u64,
    ) Error!abi.SharedMemoryDescriptor {
        const object_capability = try self.requireTargetedCapability(
            shared_memory_capability_id,
            now_ticks,
            .{ .shared_memory_revoke = true },
            .shared_memory,
        );
        try self.shared_memory_table.revoke(object_capability.target.id);
        return self.shared_memory_table.descriptor(object_capability.target.id);
    }

    pub fn timeQuery(self: *Kernel, authority_capability_id: u64, now_ticks: u64) Error!u64 {
        _ = try self.requireCapability(authority_capability_id, now_ticks, .{ .time_query = true });
        return now_ticks;
    }

    pub fn resourceQuery(
        self: *Kernel,
        authority_capability_id: u64,
        task_id: u64,
        now_ticks: u64,
    ) Error!abi.ResourceDescriptor {
        _ = try self.requireCapability(authority_capability_id, now_ticks, .{ .resource_query = true });
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
        authority_capability_id: u64,
        task_id: u64,
        now_ticks: u64,
    ) Error!abi.AccountingDescriptor {
        _ = try self.requireCapability(authority_capability_id, now_ticks, .{ .accounting_query = true });
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

    pub fn serviceRegister(
        self: *Kernel,
        authority_capability_id: u64,
        service_id: u64,
        owner_task_id: u64,
        endpoint_capability_id: u64,
        interface: manifest.InterfaceDecl,
        now_ticks: u64,
    ) Error!void {
        const auth = try self.requireCapability(authority_capability_id, now_ticks, .{
            .endpoint_connect = true,
            .ipc_peer = true,
        });
        _ = auth;
        const endpoint_capability = try self.requireTargetedCapability(
            endpoint_capability_id,
            now_ticks,
            .{ .endpoint_connect = true },
            .endpoint,
        );
        if (endpoint_capability.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != owner_task_id) return error.ScopeViolation;
        }
        try self.service_registry.register(service_id, owner_task_id, endpoint_capability.target.id, interface);
    }

    pub fn serviceConnect(
        self: *Kernel,
        authority_capability_id: u64,
        endpoint_capability_id: u64,
        interface: manifest.InterfaceDecl,
        now_ticks: u64,
    ) Error!abi.ServiceConnectionDescriptor {
        _ = try self.requireCapability(authority_capability_id, now_ticks, .{
            .endpoint_connect = true,
            .ipc_peer = true,
        });
        const endpoint_capability = try self.requireTargetedCapability(
            endpoint_capability_id,
            now_ticks,
            .{ .endpoint_connect = true },
            .endpoint,
        );
        const connection = try self.service_registry.connect(interface);
        try self.endpoint_table.connect(endpoint_capability.target.id, connection.endpoint_id);
        if (endpoint_capability.scope.task_id) |task_id| {
            try self.runtime.audit(task_id, .{
                .kind = .service_connected,
                .detail = @truncate(connection.service_id),
                .tick = now_ticks,
            });
        }
        return connection;
    }

    fn requireCapability(
        self: *Kernel,
        capability_id: u64,
        now_ticks: u64,
        needed_rights: capability.CapabilityRights,
    ) Error!capability.Capability {
        const owned = self.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
        if (!self.capability_table.isUsable(owned, now_ticks)) return error.CapabilityRevoked;
        if (!owned.rights.containsAll(needed_rights)) return error.PermissionDenied;
        return owned;
    }

    fn requireTargetedCapability(
        self: *Kernel,
        capability_id: u64,
        now_ticks: u64,
        needed_rights: capability.CapabilityRights,
        target_kind: capability.CapabilityTargetKind,
    ) Error!capability.Capability {
        const owned = try self.requireCapability(capability_id, now_ticks, needed_rights);
        if (owned.target.kind != target_kind) return error.InvalidCapabilityTarget;
        return owned;
    }
};

fn taskDescriptor(task: *const task_runtime.TaskRecord) abi.TaskDescriptor {
    return .{
        .task_id = task.id,
        .owner_serial = task.owner.serial,
        .owner_kind = @intFromEnum(task.owner.kind),
        .component_class = @intFromEnum(task.component_class),
        .state = @intFromEnum(task.state),
        .flags = taskFlags(task),
        .ui_surface_id = task.ui_surface_id orelse 0,
    };
}

fn taskFlags(task: *const task_runtime.TaskRecord) u16 {
    var flags: u16 = 0;
    if (task.local_only) flags |= 1;
    if (task.zero_ambient_authority) flags |= 1 << 1;
    if (task.background_allowed) flags |= 1 << 2;
    return flags;
}

fn capabilityDescriptor(owned: capability.Capability) abi.CapabilityDescriptor {
    const flags = abi.ScopeFlags{
        .local_only = owned.scope.local_only,
        .broker_only = owned.scope.broker_only,
        .task_scoped = owned.scope.task_id != null,
        .workspace_scoped = owned.scope.workspace_id != null,
        .ephemeral = !owned.lease.renewable,
    };
    return .{
        .capability_id = owned.id,
        .target_id = owned.target.id,
        .rights = @bitCast(owned.rights),
        .revocation_generation = owned.revocation_generation,
        .expires_at_ticks = owned.lease.expires_at_ticks,
        .scope_task_id = owned.scope.task_id orelse 0,
        .scope_workspace_id = owned.scope.workspace_id orelse 0,
        .scope_flags = @bitCast(flags),
    };
}

fn retargetTaskScope(original: capability.CapabilityScope, receiver_task_id: u64) capability.CapabilityScope {
    var next = original;
    if (original.task_id != null) {
        next.task_id = receiver_task_id;
    }
    return next;
}

test "native kernel creates tasks endpoints shared memory and typed service connections" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var registry = service_registry.Registry.init();
    var kernel = Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
        &registry,
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
    const authority_capability = try capabilities.mint(.{
        .holder = session_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{
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
        },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });

    const service_task_desc = try kernel.taskCreate(authority_capability.id, .{
        .owner = .{ .kind = .service, .serial = 3 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
        },
        .local_only = true,
    }, 5);
    const app_task_desc = try kernel.taskCreate(authority_capability.id, .{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
        },
        .local_only = true,
    }, 6);

    const service_endpoint = try kernel.endpointCreate(authority_capability.id, service_task_desc.task_id, "zigos.object.workspace", .{
        .local_only = true,
        .service_port = true,
    }, 7);
    try kernel.serviceRegister(authority_capability.id, 900, service_task_desc.task_id, service_endpoint.capability_id, .{
        .name = "zigos.object.workspace",
    }, 7);

    const app_endpoint = try kernel.endpointCreate(authority_capability.id, app_task_desc.task_id, "app.endpoint", .{
        .local_only = true,
    }, 8);
    const connection = try kernel.serviceConnect(authority_capability.id, app_endpoint.capability_id, .{
        .name = "zigos.object.workspace",
    }, 8);
    try std.testing.expectEqual(@as(u64, 900), connection.service_id);

    const shared_result = try kernel.sharedMemoryCreate(authority_capability.id, app_task_desc.task_id, 4096, 9);
    try kernel.endpointSend(app_endpoint.capability_id, 11, "sync-open", shared_result.capability_id, false, 9);
    const received = (try kernel.endpointRecv(service_endpoint.capability_id, service_task_desc.task_id, 10)).?;
    try std.testing.expectEqualStrings("sync-open", received.payload[0..received.payload_len]);
    try std.testing.expect(received.attached_capability != null);

    _ = try kernel.sharedMemoryMap(shared_result.capability_id, app_task_desc.task_id, 10);
    const resources = try kernel.resourceQuery(authority_capability.id, app_task_desc.task_id, 10);
    const accounting = try kernel.accountingQuery(authority_capability.id, app_task_desc.task_id, 10);
    try std.testing.expectEqual(@as(u16, 1), resources.endpoint_count);
    try std.testing.expect(accounting.audit_event_count >= 1);
    try std.testing.expectEqual(@as(u64, 10), try kernel.timeQuery(authority_capability.id, 10));
}

test "capability mint query revoke and task termination are exposed by the native kernel" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var registry = service_registry.Registry.init();
    var kernel = Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
        &registry,
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
    const admin_capability = try capabilities.mint(.{
        .holder = .{ .kind = .policy_authority, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .policy, .id = 1 },
        .rights = .{
            .capability_mint = true,
            .capability_query = true,
            .capability_revoke = true,
            .task_terminate = true,
        },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
    });
    const task_capability = try capabilities.mint(.{
        .holder = target_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = target_task.id },
        .rights = .{ .task_terminate = true },
        .scope = .{ .task_id = target_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
    });
    try runtime.grantCapability(target_task.id, task_capability.id);

    const minted = try kernel.capabilityMint(admin_capability.id, .{
        .holder = target_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .object, .id = 55 },
        .rights = .{
            .object_read = true,
            .capability_query = true,
        },
        .scope = .{ .task_id = target_task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    }, 10);
    try std.testing.expectEqual(@as(u64, 55), minted.target_id);
    _ = try kernel.capabilityQuery(admin_capability.id, minted.capability_id, 10);
    try kernel.capabilityRevoke(admin_capability.id, minted.capability_id, 10);
    try std.testing.expect(capabilities.query(minted.capability_id) == null);
    try std.testing.expect(try kernel.taskTerminate(task_capability.id, 11));
}
