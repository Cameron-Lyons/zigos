const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const checkpoint = @import("../storage/storage_service_checkpoint.zig");
const component_port = @import("../kernel_api/component_port.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const ids = @import("../core/ids.zig");
const policy = @import("../policy/policy_object.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const principal = @import("../core/principal.zig");
const storage_service = @import("../storage/storage_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");
const workspace = @import("../storage/workspace.zig");

pub const MAX_LEASE_TICKS: u64 = 15 * 60 * units.TIMER_FREQUENCY_HZ;

// This native broker is called only after the trusted permission view approves
// the displayed document. Its receipt never enters the userspace syscall ABI.
pub const Authorization = struct {
    policies: *const policy.Directory,
    subjects: policy.SubjectSet,
    owner: principal.PrincipalId,
    expires_at_ticks: u64,
};

pub const PreparedIdentity = struct {
    task_handle: task_runtime.TaskHandle,
    task_id: u64,
    process_generation: u32,
    image_id: u64,
    image_sha256: crypto_hash.Digest,

    pub fn capture(runtime: *const task_runtime.Runtime, task_id: u64) !PreparedIdentity {
        const task = runtime.findConst(task_id) orelse return error.TaskNotPrepared;
        const address_space = try preparedAddressSpace(runtime, task);
        if (task.state != .active) return error.TaskNotPrepared;
        return .{
            .task_handle = runtime.taskHandleForResolved(task),
            .task_id = task.id,
            .process_generation = task.process_generation,
            .image_id = task.launch.image_id,
            .image_sha256 = address_space.image_sha256,
        };
    }
};

pub const Approval = struct {
    prepared: PreparedIdentity,
    workspace_id: u64,
    object_id: u64,
    path: []const u8,
    user_grant: policy_mediation.UserGrant,
};

// The manager retains at most four grants. All text is owned by ShareGrant;
// cancellation never borrows a permission view or a mutable directory entry.
pub const Grant = struct {
    prepared: PreparedIdentity,
    workspace_id: u64,
    capability_id: u64,
    share: workspace.ShareGrant,
};

pub fn grant(kernel: *component_port.KernelPort, storage: *storage_service.Service, authorization: Authorization, approval: Approval, now_ticks: u64) !Grant {
    const runtime = kernel.kernel.runtime;
    const table = kernel.kernel.capability_table;
    const task = resolvePrepared(runtime, approval.prepared) orelse return error.TaskNotPrepared;
    if (task.state != .active) return error.TaskNotPrepared;
    var borrow = runtime.borrowResolvedTask(task);
    defer borrow.release();
    if (authorization.owner.kind != .user or authorization.subjects.user_id != authorization.owner.serial or
        authorization.expires_at_ticks <= now_ticks or authorization.expires_at_ticks == std.math.maxInt(u64)) return error.PermissionDenied;
    const receipt = approval.user_grant;
    const receipt_expiry = receipt.expires_at_ticks orelse return error.PermissionDenied;
    if (approval.workspace_id == 0 or approval.object_id == 0 or approval.path.len == 0 or
        approval.path.len > workspace.MAX_ENTRY_PATH_BYTES or receipt.kind != .object_access or
        !receipt.allow or !receipt.local_only or !std.mem.eql(u8, receipt.resource, approval.path) or
        receipt_expiry <= now_ticks or receipt_expiry == std.math.maxInt(u64)) return error.PermissionDenied;
    const record = storage.findWorkspaceRecordConst(approval.workspace_id) orelse return error.WorkspaceNotFound;
    if (!record.owner.eql(authorization.owner)) return error.PermissionDenied;
    var subjects = authorization.subjects;
    subjects.workspace_id = approval.workspace_id;
    if (!authorization.policies.permissionKindDecision(subjects, .object_access).allowed) return error.PermissionDenied;
    const entry = try storage.resolve(approval.workspace_id, approval.path);
    if (entry.object_id.raw() != approval.object_id or entry.object_type != .document) return error.DocumentChanged;
    if (storage.findShareGrant(approval.workspace_id, task.owner) != null) return error.DocumentGrantAlreadyPresent;
    const expiry = @min(@min(receipt_expiry, authorization.expires_at_ticks), now_ticks +| MAX_LEASE_TICKS);
    const share = try (workspace.ShareGrant{
        .principal_id = task.owner,
        .expires_at_ticks = expiry,
        .can_read = true,
        .can_write = true,
        .network_scope = .local_only,
        .reshare_policy = .owner_only,
        .audit_visibility = .owner_only,
    }).withObjectScope(entry.object_id, approval.path);
    // One native policy mint creates no intermediate ambient object grant.
    const minted = try table.mintBootRoot(.{
        .holder = task.owner,
        .issuer = kernel.kernel.policy_authority,
        .target = .{ .kind = .workspace, .id = approval.workspace_id },
        .rights = .{ .workspace = .{ .object_read = true, .object_write = true } },
        .scope = .{ .task_id = task.id, .workspace_id = approval.workspace_id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = now_ticks, .expires_at_ticks = expiry },
        .audit = .{ .source_task_id = task.id, .broker_service_id = storage.service_id, .user_visible_entitlement = true },
    });
    errdefer table.rollbackSingleGrant(minted.id);
    try task_runtime.grantCapabilityToTask(task, minted.id);
    errdefer _ = task_runtime.revokeCapabilityFromTask(task, minted.id);
    try storage.workspaces.share(ids.workspace(approval.workspace_id), share);
    // Do not yield to storage midway through approval publication or cleanup.
    checkpoint.noteMutation(storage, false);
    task.appendAudit(.{ .kind = .policy_allowed, .capability_id = minted.id, .tick = now_ticks });
    return .{ .prepared = approval.prepared, .workspace_id = approval.workspace_id, .capability_id = minted.id, .share = share };
}

pub fn revoke(kernel: *component_port.KernelPort, storage: *storage_service.Service, granted: Grant, now_ticks: u64) void {
    if (kernel.kernel.runtime.findByHandle(granted.prepared.task_handle, granted.prepared.task_id)) |task| {
        if (task.process_generation == granted.prepared.process_generation and task.owner.eql(granted.share.principal_id)) {
            _ = task_runtime.revokeCapabilityFromTask(task, granted.capability_id);
            task.appendAudit(.{ .kind = .capability_revoked, .capability_id = granted.capability_id, .tick = now_ticks });
        }
    }
    kernel.kernel.capability_table.revokeGrant(granted.capability_id) catch {};
    const removed = storage.workspaces.removeShare(ids.workspace(granted.workspace_id), granted.share) catch false;
    if (removed) checkpoint.noteMutation(storage, false);
}

pub fn live(kernel: *const component_port.KernelPort, storage: *const storage_service.Service, granted: Grant, now_ticks: u64) bool {
    const task = resolvePrepared(kernel.kernel.runtime, granted.prepared) orelse return false;
    if (!task.owner.eql(granted.share.principal_id) or !task.hasCapability(granted.capability_id)) return false;
    const authority = kernel.kernel.capability_table.requireUsable(granted.capability_id, now_ticks) catch return false;
    if (authority.target.kind != .workspace or authority.target.id != granted.workspace_id or
        !authority.holder.eql(task.owner) or authority.scope.task_id != task.id or authority.scope.workspace_id != granted.workspace_id or
        !authority.scope.local_only or !authority.scope.broker_only or !authority.rights.has(.object_read) or !authority.rights.has(.object_write)) return false;
    const share = storage.findShareGrant(granted.workspace_id, task.owner) orelse return false;
    if (!std.meta.eql(share, granted.share) or !share.isActive(now_ticks)) return false;
    const entry = storage.resolve(granted.workspace_id, share.scopePathSlice()) catch return false;
    return entry.object_id.eql(share.scope_object_id) and entry.object_type == .document;
}

fn resolvePrepared(runtime: *const task_runtime.Runtime, identity: PreparedIdentity) ?*task_runtime.TaskRecord {
    const task = @constCast(runtime.findConstByHandle(identity.task_handle, identity.task_id) orelse return null);
    const address_space = preparedAddressSpace(runtime, task) catch return null;
    if (task.process_generation != identity.process_generation or task.launch.image_id != identity.image_id or
        !std.mem.eql(u8, &address_space.image_sha256, &identity.image_sha256)) return null;
    return task;
}

fn preparedAddressSpace(runtime: *const task_runtime.Runtime, task: *const task_runtime.TaskRecord) !*const task_runtime.AddressSpaceRecord {
    if (task.state == .terminated or task.component_class != .app_component or !task.runsAsUserspaceProcess() or
        !task.hasLoadedExecutable() or !task.launch.signed or task.launch.image_id == 0 or
        !std.mem.eql(u8, task.launchBundleIdSlice(), "app.notes")) return error.TaskNotPrepared;
    const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return error.TaskNotPrepared;
    if (!address_space.hasMappedExecutable() or address_space.owner_task_id != task.id or
        address_space.image_id != task.launch.image_id or std.mem.allEqual(u8, &address_space.image_sha256, 0)) return error.TaskNotPrepared;
    return address_space;
}

const TestFixture = if (@import("builtin").is_test) struct {
    const endpoint = @import("../kernel_api/endpoint.zig");
    const shared_memory = @import("../kernel_api/shared_memory.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const signing = @import("../core/signing.zig");
    const object_store = @import("../storage/object_store.zig");
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    runtime: task_runtime.Runtime = .init(),
    capabilities: capability.CapabilityTable = .init(),
    endpoints: endpoint.Table = .init(),
    shared: shared_memory.Table = .init(),
    policies: policy.Directory = .init(),
    checkpoint_store: storage_service.CheckpointStore = .{},
    storage: storage_service.Service = undefined,
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    prepared: PreparedIdentity = undefined,
    workspace_id: u64 = 0,

    fn init(self: *@This()) !void {
        self.* = .{};
        self.storage = storage_service.Service.bindPrepared(&self.checkpoint_store, 7, 8, .{ .kind = .service, .serial = 9 }, false);
        self.storage.checkpoint_enabled = false;
        self.storage.capability_table = &self.capabilities;
        self.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 10 }, &self.runtime, &self.capabilities, &self.endpoints, &self.shared);
        self.port = component_port.KernelPort.init(&self.kernel);
        const task = try self.createNotes(2);
        self.prepared = try PreparedIdentity.capture(&self.runtime, task.id);
        self.workspace_id = (try self.storage.createWorkspace(.{ .owner = owner, .label = "Notes" })).id.raw();
        const signer = signing.SignerIdentity{ .label = "document grant fixture", .seed = @splat(0x47) };
        _ = try self.policies.create(.{ .scope = .user, .subject_id = owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 10 }, .label = "Notes policy" }, signer);
        try self.storage.beginTransaction(self.workspace_id);
        for ([_]u64{ 11, 12 }) |object_id| {
            const path = if (object_id == 11) "notes.md" else "sibling.md";
            const result = try self.storage.putVersion(.{
                .preferred_object_id = ids.object(object_id),
                .object_type = .document,
                .payload = "text",
                .metadata = try object_store.signMetadata(signer, path, "text/plain", .document, "text", 10),
            });
            try self.storage.stagePut(self.workspace_id, path, result.object_id, result.version_id, .document);
        }
        _ = try self.storage.commit(self.workspace_id, 10);
    }

    fn deinit(self: *@This()) void {
        self.kernel.deinit();
        self.runtime.reset();
        if (!self.checkpoint_store.resetPersistent()) @panic("document grant fixture cleanup was refused");
    }

    fn createNotes(self: *@This(), serial: u64) !*task_runtime.TaskRecord {
        const image = try @import("../task/generated_image_fixtures.zig").appImage();
        return self.runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = serial },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 2000, .memory_bytes = units.mebibytes(2), .endpoint_slots = 4, .shared_memory_bytes = units.kibibytes(4) },
            .local_only = true,
            .launch = .{ .boundary = .userspace_process, .image_id = 1, .component_abi_version = 1, .signed = true, .bundle_id = "app.notes", .source_identity = "store:zigos/public" },
            .userspace_image = &image,
        });
    }

    fn authorization(self: *@This()) Authorization {
        return .{ .policies = &self.policies, .subjects = .{ .user_id = owner.serial }, .owner = owner, .expires_at_ticks = 80 };
    }

    fn approval(self: *@This()) Approval {
        return .{ .prepared = self.prepared, .workspace_id = self.workspace_id, .object_id = 11, .path = "notes.md", .user_grant = .{ .kind = .object_access, .resource = "notes.md", .allow = true, .local_only = true, .expires_at_ticks = 100 } };
    }

    fn authority(self: *@This(), granted: Grant, now_ticks: u64) storage_service.AuthorityContext {
        _ = self;
        return .{ .task_id = granted.prepared.task_id, .principal = granted.share.principal_id, .capability_id = granted.capability_id, .now_ticks = now_ticks };
    }
} else struct {};

test "document grant binds real StoragePort to task object path and finite session lease" {
    var fixture = TestFixture{};
    try fixture.init();
    defer fixture.deinit();
    const granted = try grant(&fixture.port, &fixture.storage, fixture.authorization(), fixture.approval(), 10);
    try std.testing.expectEqual(@as(u64, 80), granted.share.expires_at_ticks);
    const cap = try fixture.capabilities.requireUsable(granted.capability_id, 10);
    try std.testing.expectEqual(capability.CapabilityTargetKind.workspace, cap.target.kind);
    try std.testing.expectEqual(@as(?u64, granted.prepared.task_id), cap.scope.task_id);
    try std.testing.expect(cap.scope.local_only and cap.scope.broker_only);
    try std.testing.expect(!cap.rights.has(.capability_derive));
    try std.testing.expect(live(&fixture.port, &fixture.storage, granted, 80));
    var storage = storage_service.StoragePort.init(&fixture.storage, &fixture.capabilities);
    const authority = fixture.authority(granted, 10);
    _ = try storage.openEntry(authority, fixture.workspace_id, "notes.md", .read);
    _ = try storage.openEntry(authority, fixture.workspace_id, "notes.md", .write);
    try std.testing.expectError(error.PermissionDenied, storage.openEntry(authority, fixture.workspace_id, "sibling.md", .read));
    var foreign = authority;
    foreign.task_id += 1;
    try std.testing.expectError(error.PermissionDenied, storage.openEntry(foreign, fixture.workspace_id, "notes.md", .write));
    foreign = authority;
    foreign.now_ticks = 81;
    try std.testing.expectError(error.CapabilityRevoked, storage.openEntry(foreign, fixture.workspace_id, "notes.md", .read));
    try std.testing.expect(!live(&fixture.port, &fixture.storage, granted, 81));
    revoke(&fixture.port, &fixture.storage, granted, 81);
    try std.testing.expect(fixture.capabilities.query(granted.capability_id) == null);
    try std.testing.expect(fixture.storage.findShareGrant(fixture.workspace_id, granted.share.principal_id) == null);
    try std.testing.expect(!fixture.runtime.find(granted.prepared.task_id).?.hasCapability(granted.capability_id));
}

test "document grant denies unapproved expired foreign owner and changed objects before mint" {
    var fixture = TestFixture{};
    try fixture.init();
    defer fixture.deinit();
    var approval = fixture.approval();
    approval.user_grant.allow = false;
    try std.testing.expectError(error.PermissionDenied, grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 10));
    approval = fixture.approval();
    approval.user_grant.local_only = false;
    try std.testing.expectError(error.PermissionDenied, grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 10));
    approval = fixture.approval();
    approval.user_grant.resource = "sibling.md";
    try std.testing.expectError(error.PermissionDenied, grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 10));
    approval = fixture.approval();
    approval.user_grant.expires_at_ticks = 9;
    try std.testing.expectError(error.PermissionDenied, grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 10));
    approval = fixture.approval();
    approval.object_id = 12;
    try std.testing.expectError(error.DocumentChanged, grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 10));
    var authorization = fixture.authorization();
    authorization.owner.serial = 99;
    authorization.subjects.user_id = 99;
    try std.testing.expectError(error.PermissionDenied, grant(&fixture.port, &fixture.storage, authorization, fixture.approval(), 10));
    try std.testing.expectEqual(@as(usize, 0), fixture.capabilities.activeCount());
    try std.testing.expectEqual(@as(u8, 0), fixture.runtime.find(fixture.prepared.task_id).?.capability_count);
}

test "document grant bounds long approval to sign in lifetime and rejects forever authority" {
    var fixture = TestFixture{};
    try fixture.init();
    defer fixture.deinit();
    var authorization = fixture.authorization();
    authorization.expires_at_ticks = 200_000;
    var approval = fixture.approval();
    approval.user_grant.expires_at_ticks = 300_000;
    const granted = try grant(&fixture.port, &fixture.storage, authorization, approval, 10);
    try std.testing.expectEqual(@as(u64, 90_010), granted.share.expires_at_ticks);
    try std.testing.expectEqual(granted.share.expires_at_ticks, (try fixture.capabilities.requireUsable(granted.capability_id, 10)).lease.expires_at_ticks);
    revoke(&fixture.port, &fixture.storage, granted, 11);
    authorization.expires_at_ticks = std.math.maxInt(u64);
    try std.testing.expectError(error.PermissionDenied, grant(&fixture.port, &fixture.storage, authorization, approval, 12));
    authorization = fixture.authorization();
    approval.user_grant.expires_at_ticks = std.math.maxInt(u64);
    try std.testing.expectError(error.PermissionDenied, grant(&fixture.port, &fixture.storage, authorization, approval, 12));
    try std.testing.expectEqual(@as(usize, 0), fixture.capabilities.activeCount());
}

test "document grant rejects unsigned policy and stale measured prepared incarnation" {
    var fixture = TestFixture{};
    try fixture.init();
    defer fixture.deinit();
    const current_policy = fixture.policies.activeForScope(.user, TestFixture.owner.serial).?;
    current_policy.signature.value[0] ^= 1;
    try std.testing.expectError(error.PermissionDenied, grant(&fixture.port, &fixture.storage, fixture.authorization(), fixture.approval(), 10));
    current_policy.signature.value[0] ^= 1;
    var approval = fixture.approval();
    approval.prepared.image_sha256[0] ^= 1;
    try std.testing.expectError(error.TaskNotPrepared, grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 10));
    approval = fixture.approval();
    approval.prepared.process_generation += 1;
    try std.testing.expectError(error.TaskNotPrepared, grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 10));
    try std.testing.expect(try fixture.runtime.terminateTask(fixture.prepared.task_id, 11));
    try std.testing.expectError(error.TaskNotPrepared, grant(&fixture.port, &fixture.storage, fixture.authorization(), fixture.approval(), 12));
    const replacement = try fixture.createNotes(3);
    approval = fixture.approval();
    approval.prepared.task_id = replacement.id;
    try std.testing.expectError(error.TaskNotPrepared, grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 12));
    try std.testing.expectEqual(@as(usize, 0), fixture.capabilities.activeCount());
}

test "document grant rolls back mint when task attachment or share publication is full" {
    var fixture = TestFixture{};
    try fixture.init();
    defer fixture.deinit();
    const task = fixture.runtime.find(fixture.prepared.task_id).?;
    var existing_capabilities: [task_runtime.MAX_TASK_CAPABILITIES]u64 = undefined;
    for (&existing_capabilities) |*id| {
        const existing = try fixture.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = fixture.kernel.policy_authority,
            .target = .{ .kind = .service, .id = fixture.storage.service_id },
            .rights = .{ .service = .{ .object_read = true } },
            .scope = .{ .task_id = task.id, .local_only = true, .broker_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        });
        id.* = existing.id;
        try task_runtime.grantCapabilityToTask(task, existing.id);
    }
    try std.testing.expectError(error.CapabilityTableFull, grant(&fixture.port, &fixture.storage, fixture.authorization(), fixture.approval(), 10));
    try std.testing.expectEqual(task_runtime.MAX_TASK_CAPABILITIES, fixture.capabilities.activeCount());
    try std.testing.expect(fixture.storage.findShareGrant(fixture.workspace_id, task.owner) == null);
    for (existing_capabilities) |id| {
        try std.testing.expect(task_runtime.revokeCapabilityFromTask(task, id));
        try fixture.capabilities.revokeGrant(id);
    }
    for (0..workspace.MAX_SHARE_GRANTS) |index| try fixture.storage.workspaces.share(ids.workspace(fixture.workspace_id), .{ .principal_id = .{ .kind = .app, .serial = 100 + index } });
    try std.testing.expectError(error.ShareTableFull, grant(&fixture.port, &fixture.storage, fixture.authorization(), fixture.approval(), 10));
    try std.testing.expectEqual(@as(usize, 0), fixture.capabilities.activeCount());
    try std.testing.expectEqual(@as(u8, 0), task.capability_count);
}

test "document grant cancellation preserves renewed share and can recycle four sessions" {
    var fixture = TestFixture{};
    try fixture.init();
    defer fixture.deinit();
    const granted = try grant(&fixture.port, &fixture.storage, fixture.authorization(), fixture.approval(), 10);
    var renewed = granted.share;
    renewed.expires_at_ticks += 1;
    try fixture.storage.workspaces.share(ids.workspace(fixture.workspace_id), renewed);
    revoke(&fixture.port, &fixture.storage, granted, 11);
    try std.testing.expect(fixture.capabilities.query(granted.capability_id) == null);
    try std.testing.expectEqual(@as(u64, 81), fixture.storage.findShareGrant(fixture.workspace_id, renewed.principal_id).?.expires_at_ticks);
    try std.testing.expectError(error.DocumentGrantAlreadyPresent, grant(&fixture.port, &fixture.storage, fixture.authorization(), fixture.approval(), 12));
    try std.testing.expect(try fixture.storage.workspaces.removeShare(ids.workspace(fixture.workspace_id), renewed));
    for (0..4) |index| {
        const task = try fixture.createNotes(20 + index);
        var approval = fixture.approval();
        approval.prepared = try PreparedIdentity.capture(&fixture.runtime, task.id);
        const current = try grant(&fixture.port, &fixture.storage, fixture.authorization(), approval, 12);
        try std.testing.expect(live(&fixture.port, &fixture.storage, current, 12));
        revoke(&fixture.port, &fixture.storage, current, 13);
        revoke(&fixture.port, &fixture.storage, current, 13);
        try std.testing.expect(!live(&fixture.port, &fixture.storage, current, 13));
    }
    try std.testing.expectEqual(@as(usize, 0), fixture.capabilities.activeCount());
    try std.testing.expectEqual(@as(u8, 0), fixture.storage.findWorkspaceRecord(fixture.workspace_id).?.counts.share_grant_count);
}
