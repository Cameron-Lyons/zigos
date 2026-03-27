const std = @import("std");
const principal = @import("principal.zig");

pub const MAX_CAPABILITIES: usize = 128;
pub const MAX_TARGET_GENERATIONS: usize = 64;

pub const CapabilityTargetKind = enum(u8) {
    task,
    endpoint,
    service,
    shared_memory,
    object,
    workspace,
    device,
    policy,
};

pub const CapabilityTarget = struct {
    kind: CapabilityTargetKind,
    id: u64,

    pub fn eql(self: CapabilityTarget, other: CapabilityTarget) bool {
        return self.kind == other.kind and self.id == other.id;
    }
};

pub const CapabilityRights = packed struct(u32) {
    task_create: bool = false,
    task_terminate: bool = false,
    endpoint_create: bool = false,
    endpoint_connect: bool = false,
    endpoint_send: bool = false,
    endpoint_recv: bool = false,
    capability_mint: bool = false,
    capability_derive: bool = false,
    capability_pass: bool = false,
    capability_revoke: bool = false,
    capability_query: bool = false,
    shared_memory_create: bool = false,
    shared_memory_map: bool = false,
    shared_memory_unmap: bool = false,
    shared_memory_revoke: bool = false,
    time_query: bool = false,
    resource_query: bool = false,
    accounting_query: bool = false,
    object_read: bool = false,
    object_write: bool = false,
    device_use: bool = false,
    clipboard_read: bool = false,
    clipboard_write: bool = false,
    sensor_read: bool = false,
    background_run: bool = false,
    network_local: bool = false,
    network_remote: bool = false,
    ipc_peer: bool = false,
    location_read: bool = false,
    contacts_read: bool = false,
    screen_capture: bool = false,
    notification_post: bool = false,

    pub fn containsAll(self: CapabilityRights, requested: CapabilityRights) bool {
        const owned: u32 = @bitCast(self);
        const needed: u32 = @bitCast(requested);
        return (owned & needed) == needed;
    }
};

pub const CapabilityScope = struct {
    task_id: ?u64 = null,
    workspace_id: ?u64 = null,
    local_only: bool = false,
    broker_only: bool = false,

    pub fn isSubsetOf(self: CapabilityScope, parent: CapabilityScope) bool {
        if (parent.task_id) |task_id| {
            if (self.task_id == null or self.task_id.? != task_id) return false;
        }
        if (parent.workspace_id) |workspace_id| {
            if (self.workspace_id == null or self.workspace_id.? != workspace_id) return false;
        }
        if (parent.local_only and !self.local_only) return false;
        if (parent.broker_only and !self.broker_only) return false;
        return true;
    }
};

pub const CapabilityLease = struct {
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    renewable: bool = false,

    pub fn isActive(self: CapabilityLease, now_ticks: u64) bool {
        return now_ticks >= self.issued_at_ticks and now_ticks <= self.expires_at_ticks;
    }

    pub fn isSubsetOf(self: CapabilityLease, parent: CapabilityLease) bool {
        return self.issued_at_ticks >= parent.issued_at_ticks and self.expires_at_ticks <= parent.expires_at_ticks;
    }
};

pub const AuditMetadata = struct {
    policy_generation: u32 = 0,
    source_task_id: u64 = 0,
    broker_service_id: u64 = 0,
};

pub const Capability = struct {
    id: u64,
    holder: principal.PrincipalId,
    issuer: principal.PrincipalId,
    target: CapabilityTarget,
    rights: CapabilityRights,
    scope: CapabilityScope,
    lease: CapabilityLease,
    revocation_generation: u32,
    audit: AuditMetadata,
};

pub const MintRequest = struct {
    holder: principal.PrincipalId,
    issuer: principal.PrincipalId,
    target: CapabilityTarget,
    rights: CapabilityRights,
    scope: CapabilityScope,
    lease: CapabilityLease,
    audit: AuditMetadata = .{},
};

pub const DeriveRequest = struct {
    parent_capability_id: u64,
    holder: principal.PrincipalId,
    rights: CapabilityRights,
    scope: CapabilityScope,
    lease: CapabilityLease,
    audit: AuditMetadata = .{},
};

pub const PassRequest = struct {
    capability_id: u64,
    new_holder: principal.PrincipalId,
    now_ticks: u64,
    revoke_source: bool = false,
    scope: ?CapabilityScope = null,
    audit: AuditMetadata = .{},
};

pub const Error = error{
    CapabilityNotFound,
    CapabilityRevoked,
    LeaseEscalation,
    RightsEscalation,
    ScopeEscalation,
    TableFull,
    TargetTableFull,
};

const CapabilitySlot = struct {
    in_use: bool = false,
    capability: Capability = zeroCapability(),
};

const TargetGeneration = struct {
    in_use: bool = false,
    target: CapabilityTarget = .{ .kind = .task, .id = 0 },
    generation: u32 = 1,
};

pub const CapabilityTable = struct {
    next_capability_id: u64 = 1,
    slots: [MAX_CAPABILITIES]CapabilitySlot = [_]CapabilitySlot{CapabilitySlot{}} ** MAX_CAPABILITIES,
    target_generations: [MAX_TARGET_GENERATIONS]TargetGeneration = [_]TargetGeneration{TargetGeneration{}} ** MAX_TARGET_GENERATIONS,

    pub fn init() CapabilityTable {
        return CapabilityTable{};
    }

    pub fn mint(self: *CapabilityTable, request: MintRequest) Error!Capability {
        const generation = try self.ensureTargetGeneration(request.target);
        return self.insert(.{
            .id = self.allocateCapabilityId(),
            .holder = request.holder,
            .issuer = request.issuer,
            .target = request.target,
            .rights = request.rights,
            .scope = request.scope,
            .lease = request.lease,
            .revocation_generation = generation,
            .audit = request.audit,
        });
    }

    pub fn derive(self: *CapabilityTable, request: DeriveRequest) Error!Capability {
        const parent = self.query(request.parent_capability_id) orelse return error.CapabilityNotFound;
        if (!self.isUsable(parent, request.lease.issued_at_ticks)) return error.CapabilityRevoked;
        if (!parent.rights.capability_derive) return error.RightsEscalation;
        if (!parent.rights.containsAll(request.rights)) return error.RightsEscalation;
        if (!request.scope.isSubsetOf(parent.scope)) return error.ScopeEscalation;
        if (!request.lease.isSubsetOf(parent.lease)) return error.LeaseEscalation;

        return self.insert(.{
            .id = self.allocateCapabilityId(),
            .holder = request.holder,
            .issuer = parent.holder,
            .target = parent.target,
            .rights = request.rights,
            .scope = request.scope,
            .lease = request.lease,
            .revocation_generation = parent.revocation_generation,
            .audit = request.audit,
        });
    }

    pub fn pass(self: *CapabilityTable, request: PassRequest) Error!Capability {
        const original = self.query(request.capability_id) orelse return error.CapabilityNotFound;
        if (!self.isUsable(original, request.now_ticks)) return error.CapabilityRevoked;
        if (!original.rights.capability_pass) return error.RightsEscalation;
        const next_scope = request.scope orelse original.scope;
        if (!scopeIsPassCompatible(next_scope, original.scope)) return error.ScopeEscalation;

        const passed = try self.insert(.{
            .id = self.allocateCapabilityId(),
            .holder = request.new_holder,
            .issuer = original.issuer,
            .target = original.target,
            .rights = original.rights,
            .scope = next_scope,
            .lease = original.lease,
            .revocation_generation = original.revocation_generation,
            .audit = request.audit,
        });

        if (request.revoke_source) {
            const source_slot = self.findSlot(request.capability_id) orelse return error.CapabilityNotFound;
            source_slot.in_use = false;
        }

        return passed;
    }

    pub fn revoke(self: *CapabilityTable, capability_id: u64) Error!void {
        const slot = self.findSlot(capability_id) orelse return error.CapabilityNotFound;
        const target = slot.capability.target;
        slot.in_use = false;
        try self.bumpTargetGeneration(target);
    }

    pub fn query(self: *const CapabilityTable, capability_id: u64) ?Capability {
        for (self.slots) |slot| {
            if (slot.in_use and slot.capability.id == capability_id) {
                return slot.capability;
            }
        }
        return null;
    }

    pub fn isUsable(self: *const CapabilityTable, capability: Capability, now_ticks: u64) bool {
        return capability.lease.isActive(now_ticks) and self.currentTargetGeneration(capability.target) == capability.revocation_generation;
    }

    fn allocateCapabilityId(self: *CapabilityTable) u64 {
        defer self.next_capability_id += 1;
        return self.next_capability_id;
    }

    fn insert(self: *CapabilityTable, capability: Capability) Error!Capability {
        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.capability = capability;
            return capability;
        }
        return error.TableFull;
    }

    fn findSlot(self: *CapabilityTable, capability_id: u64) ?*CapabilitySlot {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.capability.id == capability_id) return slot;
        }
        return null;
    }

    fn ensureTargetGeneration(self: *CapabilityTable, target: CapabilityTarget) Error!u32 {
        for (&self.target_generations) |*entry| {
            if (entry.in_use and entry.target.eql(target)) return entry.generation;
        }

        for (&self.target_generations) |*entry| {
            if (entry.in_use) continue;
            entry.in_use = true;
            entry.target = target;
            entry.generation = 1;
            return entry.generation;
        }

        return error.TargetTableFull;
    }

    fn bumpTargetGeneration(self: *CapabilityTable, target: CapabilityTarget) Error!void {
        for (&self.target_generations) |*entry| {
            if (entry.in_use and entry.target.eql(target)) {
                entry.generation += 1;
                return;
            }
        }
        return error.TargetTableFull;
    }

    fn currentTargetGeneration(self: *const CapabilityTable, target: CapabilityTarget) u32 {
        for (self.target_generations) |entry| {
            if (entry.in_use and entry.target.eql(target)) return entry.generation;
        }
        return 1;
    }
};

fn zeroCapability() Capability {
    return .{
        .id = 0,
        .holder = .{ .kind = .service, .serial = 0 },
        .issuer = .{ .kind = .service, .serial = 0 },
        .target = .{ .kind = .service, .id = 0 },
        .rights = .{},
        .scope = .{},
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 0,
            .renewable = false,
        },
        .revocation_generation = 0,
        .audit = .{},
    };
}

fn scopeIsPassCompatible(next_scope: CapabilityScope, original_scope: CapabilityScope) bool {
    if (original_scope.workspace_id) |workspace_id| {
        if (next_scope.workspace_id == null or next_scope.workspace_id.? != workspace_id) return false;
    }
    if (original_scope.local_only and !next_scope.local_only) return false;
    if (original_scope.broker_only and !next_scope.broker_only) return false;
    return true;
}

fn fullSessionRights() CapabilityRights {
    return .{
        .endpoint_create = true,
        .endpoint_connect = true,
        .endpoint_send = true,
        .endpoint_recv = true,
        .capability_derive = true,
        .capability_pass = true,
        .capability_query = true,
        .time_query = true,
        .resource_query = true,
        .accounting_query = true,
    };
}

test "capabilities derive narrower rights and are invalidated by target revocation" {
    var table = CapabilityTable.init();
    const policy = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const session = principal.PrincipalId{ .kind = .service, .serial = 2 };
    const task = principal.PrincipalId{ .kind = .user, .serial = 9 };

    const parent = try table.mint(.{
        .holder = session,
        .issuer = policy,
        .target = .{ .kind = .service, .id = 42 },
        .rights = fullSessionRights(),
        .scope = .{ .task_id = 100, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
        .audit = .{ .policy_generation = 1, .source_task_id = 100, .broker_service_id = 42 },
    });

    const derived = try table.derive(.{
        .parent_capability_id = parent.id,
        .holder = task,
        .rights = .{
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_query = true,
        },
        .scope = .{ .task_id = 100, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 5, .expires_at_ticks = 500, .renewable = false },
        .audit = .{ .policy_generation = 1, .source_task_id = 100, .broker_service_id = 42 },
    });

    try std.testing.expect(table.isUsable(parent, 10));
    try std.testing.expect(table.isUsable(derived, 10));

    try table.revoke(parent.id);
    try std.testing.expect(!table.isUsable(derived, 10));
}

test "derive rejects rights and scope escalation" {
    var table = CapabilityTable.init();
    const issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const holder = principal.PrincipalId{ .kind = .service, .serial = 7 };

    const parent = try table.mint(.{
        .holder = holder,
        .issuer = issuer,
        .target = .{ .kind = .workspace, .id = 3 },
        .rights = .{
            .capability_derive = true,
            .capability_query = true,
            .resource_query = true,
        },
        .scope = .{ .workspace_id = 3, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 50, .renewable = false },
    });

    try std.testing.expectError(error.RightsEscalation, table.derive(.{
        .parent_capability_id = parent.id,
        .holder = holder,
        .rights = .{
            .capability_derive = true,
            .capability_query = true,
            .resource_query = true,
            .time_query = true,
        },
        .scope = .{ .workspace_id = 3, .local_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10, .renewable = false },
    }));

    try std.testing.expectError(error.ScopeEscalation, table.derive(.{
        .parent_capability_id = parent.id,
        .holder = holder,
        .rights = .{
            .capability_query = true,
        },
        .scope = .{ .workspace_id = 3, .local_only = false },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10, .renewable = false },
    }));
}

test "passing capabilities duplicates or transfers authority based on request flags" {
    var table = CapabilityTable.init();
    const issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const source = principal.PrincipalId{ .kind = .service, .serial = 7 };
    const target = principal.PrincipalId{ .kind = .app, .serial = 3 };

    const original = try table.mint(.{
        .holder = source,
        .issuer = issuer,
        .target = .{ .kind = .endpoint, .id = 99 },
        .rights = .{
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_pass = true,
        },
        .scope = .{ .task_id = 11, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    });

    const duplicated = try table.pass(.{
        .capability_id = original.id,
        .new_holder = target,
        .now_ticks = 10,
        .scope = .{ .task_id = 11, .local_only = true },
    });
    try std.testing.expectEqual(target, duplicated.holder);
    try std.testing.expect(table.query(original.id) != null);

    _ = try table.pass(.{
        .capability_id = original.id,
        .new_holder = target,
        .now_ticks = 10,
        .revoke_source = true,
        .scope = .{ .task_id = 11, .local_only = true },
    });
    try std.testing.expect(table.query(original.id) == null);
}

test "expired capabilities are no longer usable" {
    var table = CapabilityTable.init();
    const capability = try table.mint(.{
        .holder = .{ .kind = .service, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .endpoint, .id = 99 },
        .rights = .{ .endpoint_connect = true, .endpoint_recv = true },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 20, .renewable = false },
    });

    try std.testing.expect(!table.isUsable(capability, 9));
    try std.testing.expect(table.isUsable(capability, 15));
    try std.testing.expect(!table.isUsable(capability, 21));
}
