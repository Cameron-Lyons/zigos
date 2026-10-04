//! Native manager plumbing for a prepared, measured Notes process. Browsing
//! prepares no authority; approval supplies one document and transient channel
//! construction authority, which is retired before the process can run.
const std = @import("std");
const hash = @import("../core/crypto_hash.zig");
const principal = @import("../core/principal.zig");
const unlock = @import("../platform/unlock_context.zig");
const launch = @import("../task/userspace_launch.zig");
const executor = @import("../task/userspace_executor.zig");
const tasks = @import("../task/task_runtime.zig");
const grants = @import("document_grants.zig");
const workspace = @import("../storage/workspace.zig");
const signer_mod = @import("../storage/sealed_object_signer.zig");

pub fn prepare(manager: anytype, binding: unlock.Binding, now: u64) !*tasks.TaskRecord {
    const owner = manager.identity_owner orelse return error.IdentityUnavailable;
    const access = owner.document_access(owner.context, now) orelse return error.IdentityUnavailable;
    if (!binding.valid() or !std.meta.eql(access.binding, binding)) return error.IdentityUnavailable;
    const runtime = manager.runtimePtr();
    const storage = manager.storageServicePtr();
    if (runtime.next_task_id == 0) return error.TaskIdentityExhausted;
    // Task IDs restart across boots; fresh session entropy and collision checks
    // keep old persisted shares from recognizing a newly prepared process.
    const attempts = workspace.MAX_WORKSPACES * workspace.MAX_SHARE_GRANTS + tasks.MAX_TASKS + 1;
    for (0..attempts) |attempt| {
        var digest = hash.init();
        hash.updateBytes(&digest, "native-notes-principal", &binding.boot_instance);
        hash.updateBytes(&digest, "session", &binding.session_nonce);
        hash.updateInt(&digest, "task", runtime.next_task_id);
        hash.updateInt(&digest, "probe", attempt);
        const bytes = hash.finalize(&digest);
        const serial = std.mem.readInt(u64, bytes[0..8], .little);
        const candidate = principal.PrincipalId{ .kind = .app, .serial = serial };
        if (serial == 0 or runtime.findByOwner(candidate) != null or manager.compositorSessionPtr().surfacePresentation(serial) != null) continue;
        var collision = false;
        for (storage.workspaces.workspaces.slots[0..storage.workspaces.workspaces.next_unclaimed_index]) |*slot| {
            if (!slot.in_use or slot.workspace.counts.share_grant_count == 0) continue;
            for (slot.workspace.share_table.dataConst().share_grants[0..slot.workspace.counts.share_grant_count]) |share| {
                if (share.principal_id.eql(candidate)) {
                    collision = true;
                    break;
                }
            }
            if (collision) break;
        }
        if (collision) continue;
        for (0..runtime.taskSlotCapacity()) |index| {
            const slot = runtime.taskSlotAtConst(index);
            if (slot.in_use and slot.task.ui_surface_id == serial) {
                collision = true;
                break;
            }
        }
        if (collision) continue;
        return launch.prepareRegisteredDirect(manager.userspaceCatalogPtr(), runtime, "app.notes", .{
            .owner = candidate,
            .budget = .{ .cpu_time_ticks = grants.MAX_LEASE_TICKS, .memory_bytes = 256 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 },
            .ui_surface_id = serial,
            .component_label = "Notes",
        });
    }
    return error.TaskIdentityExhausted;
}

pub fn grant(manager: anytype, task_id: u64, workspace_id: u64, object_id: u64, path: []const u8, expiry: u64, now: u64) !grants.Grant {
    const owner = manager.identity_owner orelse return error.IdentityUnavailable;
    const access = owner.document_access(owner.context, now) orelse return error.IdentityUnavailable;
    if (expiry <= now or expiry > access.expires_at_ticks) return error.PermissionDenied;
    return grants.grant(manager.kernelPort() orelse return error.KernelUnavailable, manager.storageServicePtr(), access.authorization, .{
        .prepared = try grants.PreparedIdentity.capture(manager.runtimePtr(), task_id),
        .workspace_id = workspace_id,
        .object_id = object_id,
        .path = path,
        .user_grant = .{ .kind = .object_access, .resource = path, .allow = true, .local_only = true, .expires_at_ticks = expiry },
    }, now);
}

pub fn activate(manager: anytype, approved: grants.Grant, signer: signer_mod.Signer, now: u64) !@TypeOf(manager.*).DocumentTask {
    const kernel = manager.kernelPort() orelse return error.KernelUnavailable;
    const storage = manager.storageServicePtr();
    if (!grants.live(kernel, storage, approved, now)) return error.PermissionDenied;
    const task = manager.runtimePtr().findByHandle(approved.prepared.task_handle, approved.prepared.task_id) orelse return error.TaskNotPrepared;
    const service = manager.runtimePtr().find(storage.task_id) orelse return error.TaskNotFound;
    const server_authority = executor.resolveMailboxAuthorities(service, manager.capabilityTablePtr(), now).bootstrap_capability_id;
    if (server_authority == 0) return error.StorageUnavailable;
    const temporary = try manager.capabilityTablePtr().mintBootRoot(.{
        .holder = task.owner,
        .issuer = kernel.kernel.policy_authority,
        .target = .{ .kind = .service, .id = storage.service_id },
        .rights = .{ .service = .{ .endpoint_create = true } },
        .scope = .{ .task_id = task.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = now, .expires_at_ticks = approved.share.expires_at_ticks },
        .audit = .{ .source_task_id = task.id, .broker_service_id = storage.service_id },
    });
    defer manager.capabilityTablePtr().rollbackSingleGrant(temporary.id);
    try tasks.grantCapabilityToTask(task, temporary.id);
    defer _ = tasks.revokeCapabilityFromTask(task, temporary.id);
    return manager.activateDocumentTask(.{
        .authority = .{ .principal = task.owner, .task_id = task.id, .capability_id = approved.capability_id, .now_ticks = now },
        .client_bootstrap_capability_id = temporary.id,
        .server_bootstrap_capability_id = server_authority,
        .workspace_id = approved.workspace_id,
        .path = approved.share.scopePathSlice(),
        .signer = signer,
    }, now);
}

// Factory unit fixture, not a sign-in proof: only the read-only authenticated
// session envelope is supplied. Catalog validation, task/address-space creation,
// policy evaluation, StoragePort checks, and compositor state are real modules.
const FactoryFixture = if (@import("builtin").is_test) struct {
    const storage_mod = @import("../storage/storage_service.zig");
    const loader = @import("../task/userspace_loader.zig");
    const capability = @import("../kernel_api/capability.zig");
    const component = @import("../kernel_api/component_port.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const policy = @import("../policy/policy_object.zig");
    const ids = @import("../core/ids.zig");
    const signing = @import("../core/signing.zig");
    const objects = @import("../storage/object_store.zig");
    const user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const OwnerEnvelope = struct {
        context: *anyopaque,
        document_access: *const fn (*anyopaque, u64) ?Access,
    };
    const Access = struct {
        binding: unlock.Binding,
        expires_at_ticks: u64,
        authorization: grants.Authorization,
    };

    runtime: tasks.Runtime = .init(),
    catalog: loader.Catalog = .init(),
    compositor: @import("../platform/compositor_session.zig").Session = .init(),
    capabilities: capability.CapabilityTable = .init(),
    endpoints: @import("../kernel_api/endpoint.zig").Table = .init(),
    shared: @import("../kernel_api/shared_memory.zig").Table = .init(),
    policies: policy.Directory = .init(),
    checkpoint_store: storage_mod.CheckpointStore = .{},
    storage: storage_mod.Service = undefined,
    kernel: native_kernel.Kernel = undefined,
    port: component.KernelPort = undefined,
    identity_owner: ?OwnerEnvelope = null,
    binding: unlock.Binding = .{ .boot_instance = @splat(1), .session_nonce = @splat(2) },
    session_active: bool = true,
    expiry: u64 = 100,
    workspace_id: u64 = 0,
    execution: executor.Executor = .{},
    scheduler: @import("../task/userspace_scheduler.zig").Scheduler = undefined,

    fn create() !*@This() {
        const self = try std.testing.allocator.create(@This());
        self.* = .{};
        self.storage = storage_mod.Service.bindPrepared(&self.checkpoint_store, 7, 8, .{ .kind = .service, .serial = 9 }, false);
        self.storage.checkpoint_enabled = false;
        self.storage.capability_table = &self.capabilities;
        self.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 10 }, &self.runtime, &self.capabilities, &self.endpoints, &self.shared);
        self.port = component.KernelPort.init(&self.kernel);
        self.scheduler = .init(&self.execution);
        self.scheduler.bind(&self.catalog, &self.runtime, &self.capabilities);
        self.identity_owner = .{ .context = self, .document_access = documentAccess };
        errdefer self.destroy();
        self.workspace_id = (try self.storage.createWorkspace(.{ .owner = user, .label = "Notes" })).id.raw();
        const signer = signing.SignerIdentity{ .label = "Notes factory policy fixture", .seed = @splat(0x39) };
        _ = try self.policies.create(.{ .scope = .user, .subject_id = user.serial, .issuer = self.kernel.policy_authority, .label = "Notes policy" }, signer);
        try self.storage.beginTransaction(self.workspace_id);
        for ([_]u64{ 11, 12 }) |object_id| {
            const path = if (object_id == 11) "notes.md" else "sibling.md";
            const result = try self.storage.putVersion(.{ .preferred_object_id = ids.object(object_id), .object_type = .document, .payload = "text", .metadata = try objects.signMetadata(signer, path, "text/markdown", .document, "text", 10) });
            try self.storage.stagePut(self.workspace_id, path, result.object_id, result.version_id, .document);
        }
        _ = try self.storage.commit(self.workspace_id, 10);
        return self;
    }
    fn destroy(self: *@This()) void {
        self.scheduler.deinit();
        self.execution.deinit();
        self.compositor.deinit();
        self.kernel.deinit();
        self.runtime.reset();
        if (!self.checkpoint_store.resetPersistent()) @panic("Notes factory fixture cleanup was refused");
        std.testing.allocator.destroy(self);
    }
    fn documentAccess(context: *anyopaque, now: u64) ?Access {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (!self.session_active or now >= self.expiry) return null;
        return .{ .binding = self.binding, .expires_at_ticks = self.expiry, .authorization = .{ .policies = &self.policies, .subjects = .{ .user_id = user.serial }, .owner = user, .expires_at_ticks = self.expiry } };
    }
    pub fn runtimePtr(self: *@This()) *tasks.Runtime {
        return &self.runtime;
    }
    pub fn storageServicePtr(self: *@This()) *storage_mod.Service {
        return &self.storage;
    }
    pub fn userspaceCatalogPtr(self: *@This()) *loader.Catalog {
        return &self.catalog;
    }
    pub fn compositorSessionPtr(self: *@This()) *@import("../platform/compositor_session.zig").Session {
        return &self.compositor;
    }
    pub fn kernelPort(self: *@This()) ?*component.KernelPort {
        return &self.port;
    }
    fn shareWith(self: *@This(), owner: principal.PrincipalId) !void {
        try self.storage.workspaces.share(ids.workspace(self.workspace_id), try (workspace.ShareGrant{ .principal_id = owner, .expires_at_ticks = 90, .can_read = true, .can_write = true }).withObjectScope(ids.object(11), "notes.md"));
    }
    fn filler(self: *@This(), owner: principal.PrincipalId, surface: ?u64) !*tasks.TaskRecord {
        return self.runtime.createTask(.{ .owner = owner, .component_class = .app_component, .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 64 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 }, .ui_surface_id = surface, .local_only = true });
    }
    fn rebootRuntime(self: *@This()) void {
        self.scheduler.reset();
        self.runtime.reset();
        // A new boot owns a new runtime lifetime. Ordinary reset intentionally
        // preserves issuance cursors and therefore cannot model ID recycling.
        self.runtime = .init();
        self.scheduler.bind(&self.catalog, &self.runtime, &self.capabilities);
    }
} else struct {};

test "Notes factory rejects absent inactive invalid and mismatched session bindings before creating a task" {
    const f = try FactoryFixture.create();
    defer f.destroy();
    const owner = f.identity_owner;
    f.identity_owner = null;
    try std.testing.expectError(error.IdentityUnavailable, prepare(f, f.binding, 10));
    f.identity_owner = owner;
    f.session_active = false;
    try std.testing.expectError(error.IdentityUnavailable, prepare(f, f.binding, 10));
    f.session_active = true;
    try std.testing.expectError(error.IdentityUnavailable, prepare(f, .{}, 10));
    var mismatch = f.binding;
    mismatch.session_nonce[0] ^= 1;
    try std.testing.expectError(error.IdentityUnavailable, prepare(f, mismatch, 10));
    mismatch = f.binding;
    mismatch.boot_instance[0] ^= 1;
    try std.testing.expectError(error.IdentityUnavailable, prepare(f, mismatch, 10));
    try std.testing.expectError(error.IdentityUnavailable, prepare(f, f.binding, 100));
    try std.testing.expectEqual(@as(u64, 1), f.runtime.next_task_id);
    try std.testing.expectEqual(@as(usize, 0), f.runtime.countTasksInState(.active));
    try std.testing.expectEqual(@as(usize, 0), f.catalog.imageCount());
    try std.testing.expectEqual(@as(usize, 0), f.capabilities.activeCount());
}

test "Notes factory prepares the registered measured signed image with zero authority and no scheduler publication" {
    const f = try FactoryFixture.create();
    defer f.destroy();
    const task = try prepare(f, f.binding, 10);
    const image = f.catalog.findById(task.launch.image_id).?;
    const space = f.runtime.findAddressSpaceConst(task.address_space_id).?;
    try std.testing.expectEqualStrings("app.notes", task.launchBundleIdSlice());
    try std.testing.expect(task.launch.signed and image.bundle_signed and image.embedsElf());
    try std.testing.expect(task.runsAsUserspaceProcess() and task.hasLoadedExecutable() and space.hasMappedExecutable());
    try std.testing.expectEqual(task.id, space.owner_task_id);
    try std.testing.expectEqualSlices(u8, &image.file_sha256, &space.image_sha256);
    try std.testing.expect(!std.mem.allEqual(u8, &space.image_sha256, 0));
    try std.testing.expectEqual(@as(u8, 0), task.capability_count);
    try std.testing.expectEqual(@as(usize, 0), f.capabilities.activeCount());
    try std.testing.expectEqual(task.owner.serial, task.ui_surface_id.?);
    try std.testing.expect(f.scheduler.taskDispatchStats(task.id) == null);
    try std.testing.expect(!f.scheduler.runNext(10));
    try std.testing.expect(f.scheduler.taskDispatchStats(task.id) == null);
    try std.testing.expectEqual(@as(usize, 0), f.execution.materializedCount());
    try std.testing.expectEqual(@as(usize, 0), f.compositor.window_count);
}

test "Notes factory fresh session and boot domains prevent old persisted shares from recognizing recycled task IDs" {
    for ([_]bool{ false, true }) |new_boot| {
        const f = try FactoryFixture.create();
        defer f.destroy();
        const first = try prepare(f, f.binding, 10);
        const old_owner = first.owner;
        const old_id = first.id;
        try f.shareWith(old_owner);
        f.rebootRuntime();
        if (new_boot) f.binding.boot_instance = @splat(3) else f.binding.session_nonce = @splat(4);
        const replacement = try prepare(f, f.binding, 10);
        try std.testing.expectEqual(old_id, replacement.id);
        try std.testing.expect(!replacement.owner.eql(old_owner));
        try std.testing.expect(f.storage.findShareGrant(f.workspace_id, old_owner) != null);
        try std.testing.expect(f.storage.findShareGrant(f.workspace_id, replacement.owner) == null);
        try std.testing.expectEqual(@as(u8, 0), replacement.capability_count);
        var port = FactoryFixture.storage_mod.StoragePort.init(&f.storage, &f.capabilities);
        try std.testing.expectError(error.CapabilityNotFound, port.openEntry(.{ .task_id = replacement.id, .principal = replacement.owner, .capability_id = 0, .now_ticks = 10 }, f.workspace_id, "notes.md", .read));
    }
}

test "Notes factory probes another principal when the exact binding and recycled task ID collide with a persisted share" {
    const f = try FactoryFixture.create();
    defer f.destroy();
    const first = try prepare(f, f.binding, 10);
    const old_owner = first.owner;
    const old_id = first.id;
    try f.shareWith(old_owner);
    f.rebootRuntime(); // Deliberately repeat the entire public hash input.
    const replacement = try prepare(f, f.binding, 10);
    try std.testing.expectEqual(old_id, replacement.id);
    try std.testing.expect(!replacement.owner.eql(old_owner));
    try std.testing.expect(f.storage.findShareGrant(f.workspace_id, replacement.owner) == null);
    try std.testing.expect(f.storage.findShareGrant(f.workspace_id, old_owner) != null);
    try std.testing.expectEqual(@as(u8, 0), replacement.capability_count);
}

test "Notes factory skips principal and UI surface identities already used by live tasks" {
    const preview = try FactoryFixture.create();
    defer preview.destroy();
    _ = try preview.filler(.{ .kind = .app, .serial = 81 }, null);
    const candidate = (try prepare(preview, preview.binding, 10)).owner;
    for ([_]bool{ false, true }) |surface_collision| {
        const f = try FactoryFixture.create();
        defer f.destroy();
        const blocker = try f.filler(if (surface_collision) .{ .kind = .app, .serial = 82 } else candidate, if (surface_collision) candidate.serial else null);
        const task = try prepare(f, f.binding, 10);
        try std.testing.expectEqual(@as(u64, 2), task.id);
        try std.testing.expect(!task.owner.eql(candidate) and task.ui_surface_id.? != candidate.serial);
        try std.testing.expect(f.runtime.find(blocker.id).? == blocker);
        try std.testing.expectEqual(@as(usize, 2), f.runtime.countTasksInState(.active));
    }
}

test "Notes factory does not reuse a compositor surface retained after runtime retirement" {
    const f = try FactoryFixture.create();
    defer f.destroy();
    const first = try prepare(f, f.binding, 10);
    const candidate = first.owner;
    var presentation = std.mem.zeroes(@import("../core/abi.zig").SurfacePresentation);
    presentation.surface_id = candidate.serial;
    presentation.revision = 1;
    presentation.buffer_object_id = 71;
    presentation.buffer_bytes = 4096;
    _ = try f.compositor.presentSurface(first, &presentation);
    f.rebootRuntime();
    try std.testing.expect(f.compositor.surfacePresentation(candidate.serial) != null);
    const replacement = try prepare(f, f.binding, 10);
    try std.testing.expect(!replacement.owner.eql(candidate));
    try std.testing.expectEqual(@as(usize, 1), f.compositor.presentedSurfaceCount());
    try std.testing.expectEqual(@as(u8, 0), replacement.capability_count);
}

test "Notes factory approval grants one real object path and revocation clears attached authority without ambient inheritance" {
    const f = try FactoryFixture.create();
    defer f.destroy();
    const task = try prepare(f, f.binding, 10);
    try std.testing.expectError(error.PermissionDenied, grant(f, task.id, f.workspace_id, 11, "notes.md", 101, 10));
    try std.testing.expectError(error.DocumentChanged, grant(f, task.id, f.workspace_id, 12, "notes.md", 80, 10));
    f.session_active = false;
    try std.testing.expectError(error.IdentityUnavailable, grant(f, task.id, f.workspace_id, 11, "notes.md", 80, 10));
    f.session_active = true;
    try std.testing.expectEqual(@as(usize, 0), f.capabilities.activeCount());
    try std.testing.expectEqual(@as(u8, 0), task.capability_count);
    const approved = try grant(f, task.id, f.workspace_id, 11, "notes.md", 80, 10);
    try std.testing.expect(grants.live(&f.port, &f.storage, approved, 10));
    var port = FactoryFixture.storage_mod.StoragePort.init(&f.storage, &f.capabilities);
    const authority = FactoryFixture.storage_mod.AuthorityContext{ .task_id = task.id, .principal = task.owner, .capability_id = approved.capability_id, .now_ticks = 10 };
    _ = try port.openEntry(authority, f.workspace_id, "notes.md", .read);
    _ = try port.openEntry(authority, f.workspace_id, "notes.md", .write);
    try std.testing.expectError(error.PermissionDenied, port.openEntry(authority, f.workspace_id, "sibling.md", .read));
    grants.revoke(&f.port, &f.storage, approved, 11);
    try std.testing.expectEqual(@as(usize, 0), f.capabilities.activeCount());
    try std.testing.expectEqual(@as(u8, 0), task.capability_count);
    try std.testing.expect(f.storage.findShareGrant(f.workspace_id, task.owner) == null);
    try std.testing.expect(f.scheduler.taskDispatchStats(task.id) == null);
    try std.testing.expect(try f.runtime.terminateTask(task.id, 11));
}

test "Notes bridge hosted mailbox refusal unwinds real document clipboard window task and temporary construction authority" {
    if (@import("builtin").target.os.tag == .freestanding) return error.SkipZigTest;
    const manager_mod = @import("session_manager.zig");
    const ids = @import("../core/ids.zig");
    const signing = @import("../core/signing.zig");
    const signer_fixture = @import("../../tests/fixtures/document_signer.zig");
    const manager = try std.testing.allocator.create(manager_mod.SessionManager);
    defer std.testing.allocator.destroy(manager);
    manager.* = .init();
    defer manager.reset();
    manager.boot();
    try std.testing.expect(manager.isInitialized());
    const runtime = manager.runtimePtr();
    const storage = manager.storageServicePtr();
    const kernel = manager.kernelPort().?;
    const user = principal.PrincipalId{ .kind = .user, .serial = 901 };
    const identity = signing.SignerIdentity{ .label = "Notes activation fixture", .seed = @splat(0x41) };
    var signing_fixture = signer_fixture.Fixture{};
    const signer = try signing_fixture.initWithClipboard(user, storage.owner, storage.task_id, identity, true);
    const record = try storage.createWorkspace(.{ .owner = user, .label = "Notes activation" });
    const version = try storage.putVersion(.{ .object_type = .document, .payload = "draft", .metadata = try signer.signMetadata("notes.md", "draft", 10) });
    try storage.beginTransaction(record.id);
    try storage.stagePut(record.id, "notes.md", version.object_id, version.version_id, .document);
    _ = try storage.commit(record.id, 10);
    const task = try launch.prepareRegisteredDirect(manager.userspaceCatalogPtr(), runtime, "app.notes", .{
        .owner = .{ .kind = .app, .serial = 0xD0C4A7 },
        .budget = .{ .cpu_time_ticks = grants.MAX_LEASE_TICKS, .memory_bytes = 256 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .ui_surface_id = 0xD0C4A7,
    });
    const task_id = task.id;
    const space_id = task.address_space_id;
    const caps_before = manager.capabilityTablePtr().activeCount();
    const endpoints_before = kernel.kernel.endpoint_table.activeCount();
    const shared_before = kernel.kernel.shared_memory_table.activeCount();
    const windows_before = manager.compositorSessionPtr().window_count;
    const approved = try grants.grant(kernel, storage, .{ .policies = &signing_fixture.policies, .subjects = .{ .user_id = user.serial }, .owner = user, .expires_at_ticks = 100 }, .{
        .prepared = try grants.PreparedIdentity.capture(runtime, task_id),
        .workspace_id = record.id.raw(),
        .object_id = version.object_id.raw(),
        .path = "notes.md",
        .user_grant = .{ .kind = .object_access, .resource = "notes.md", .allow = true, .local_only = true, .expires_at_ticks = 80 },
    }, 10);
    // The actual hosted executor deliberately refuses initial mailbox mapping.
    // Reaching this error proves both real channels were constructed first;
    // no fake scheduler or simulated successful userspace launch is involved.
    try std.testing.expectError(error.DocumentLaunchUnavailable, activate(manager, approved, signer, 10));
    try std.testing.expectEqual(tasks.TaskState.terminated, runtime.find(task_id).?.state);
    try std.testing.expect(runtime.findAddressSpaceConst(space_id) == null);
    try std.testing.expect(manager.userspaceSchedulerPtr().taskDispatchStats(task_id) == null);
    try std.testing.expectEqual(caps_before, manager.capabilityTablePtr().activeCount());
    try std.testing.expectEqual(endpoints_before, kernel.kernel.endpoint_table.activeCount());
    try std.testing.expectEqual(shared_before, kernel.kernel.shared_memory_table.activeCount());
    try std.testing.expectEqual(windows_before, manager.compositorSessionPtr().window_count);
    try std.testing.expectEqual(@as(u8, 0), runtime.find(task_id).?.capability_count);
    try std.testing.expect(!manager.documents.hasLiveDocument(task_id, approved.capability_id, approved.workspace_id, approved.share.scope_object_id.raw(), "notes.md"));
    try std.testing.expect(!manager.clipboard.transferPendingForTask(task_id));
    // The outer approved-operation owner performs exact share cancellation.
    manager.revokeApprovedDocument(approved, 11);
    try std.testing.expect(storage.findShareGrant(record.id, approved.share.principal_id) == null);
    try std.testing.expect(!grants.live(kernel, storage, approved, 11));
    _ = ids;
}
