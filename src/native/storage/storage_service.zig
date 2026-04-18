const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const file_bridge = @import("file_bridge.zig");
const object_store = @import("object_store.zig");
const checkpoint_support = @import("storage_service_checkpoint.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_volume = @import("storage_volume.zig");
const workspace = @import("workspace.zig");

pub const CheckpointStore = checkpoint_support.CheckpointStore;

pub const Service = struct {
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    loaded_from_volume: bool = false,
    checkpoint_enabled: bool = true,
    deferred_checkpoint_count: usize = 0,
    checkpoint_store: *CheckpointStore,
    store: *object_store.Store,
    workspaces: *workspace.Directory,

    pub fn initWithStore(
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        checkpoint_store: *CheckpointStore,
    ) Service {
        const loaded_from_volume = checkpoint_store.preparePersistentState();
        return checkpoint_support.makeService(Service, checkpoint_store, service_id, task_id, owner, loaded_from_volume);
    }

    pub fn bootstrapWithStore(
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        checkpoint_store: *CheckpointStore,
    ) Service {
        const loaded_from_volume = checkpoint_store.preparePersistentState();
        return checkpoint_support.makeService(Service, checkpoint_store, service_id, task_id, owner, loaded_from_volume);
    }

    pub fn bindPrepared(
        checkpoint_store: *CheckpointStore,
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        loaded_from_volume: bool,
    ) Service {
        return checkpoint_support.makeService(Service, checkpoint_store, service_id, task_id, owner, loaded_from_volume);
    }

    pub fn reloadFromAttachedVolume(
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        checkpoint_store: *CheckpointStore,
    ) Service {
        checkpoint_store.resetPreparedState();
        const loaded_from_volume = checkpoint_store.loadPreparedStateFromAttachedVolume();
        return checkpoint_support.makeService(Service, checkpoint_store, service_id, task_id, owner, loaded_from_volume);
    }

    pub fn checkpoint(self: *const Service) void {
        self.flushCheckpoint();
    }

    pub fn putVersion(self: *Service, request: object_store.PutRequest) object_store.Error!object_store.PutResult {
        return self.putVersionRef(&request);
    }

    pub fn putVersionRef(self: *Service, request: *const object_store.PutRequest) object_store.Error!object_store.PutResult {
        const result = try self.store.putVersionRef(request);
        self.noteMutation(true);
        return result;
    }

    pub fn createWorkspace(self: *Service, request: workspace.CreateRequest) workspace.Error!*workspace.WorkspaceRecord {
        return self.createWorkspaceRef(&request);
    }

    pub fn createWorkspaceRef(self: *Service, request: *const workspace.CreateRequest) workspace.Error!*workspace.WorkspaceRecord {
        const record = try self.workspaces.createRef(request);
        self.noteMutation(true);
        return record;
    }

    pub fn beginTransaction(self: *Service, workspace_id: u64) workspace.Error!void {
        try self.workspaces.beginTransaction(workspace_id);
        self.deferred_checkpoint_count += 1;
        self.noteMutation(false);
    }

    pub fn stagePut(
        self: *Service,
        workspace_id: u64,
        path: []const u8,
        object_id: u64,
        version_id: u64,
        object_type: object_store.ObjectType,
    ) workspace.Error!void {
        try self.workspaces.stagePut(workspace_id, path, object_id, version_id, object_type);
        self.noteMutation(false);
    }

    pub fn stageDelete(self: *Service, workspace_id: u64, path: []const u8) workspace.Error!void {
        try self.workspaces.stageDelete(workspace_id, path);
        self.noteMutation(false);
    }

    pub fn commit(self: *Service, workspace_id: u64, tick: u64) workspace.Error!u32 {
        const generation = try self.workspaces.commit(workspace_id, tick);
        if (self.deferred_checkpoint_count != 0) self.deferred_checkpoint_count -= 1;
        self.noteMutation(true);
        return generation;
    }

    pub fn snapshot(
        self: *Service,
        workspace_id: u64,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) workspace.Error!*workspace.SnapshotRecord {
        const snapshot_record = try self.workspaces.snapshot(workspace_id, label, identity);
        self.noteMutation(true);
        return snapshot_record;
    }

    pub fn restore(self: *Service, workspace_id: u64, snapshot_id: u64, tick: u64) workspace.Error!u32 {
        const generation = try self.workspaces.restore(workspace_id, snapshot_id, tick);
        self.noteMutation(true);
        return generation;
    }

    pub fn restoreFromExportPackage(
        self: *Service,
        workspace_id: u64,
        package: *const workspace.ExportPackage,
        tick: u64,
    ) workspace.Error!u32 {
        const generation = try self.workspaces.restoreFromExportPackage(workspace_id, package, tick);
        self.noteMutation(true);
        return generation;
    }

    pub fn recoverDeleted(self: *Service, workspace_id: u64, path: []const u8, tick: u64) workspace.Error!bool {
        const recovered = try self.workspaces.recoverDeleted(workspace_id, path, tick);
        if (recovered) self.noteMutation(true);
        return recovered;
    }

    pub fn exportSnapshot(
        self: *Service,
        workspace_id: u64,
        snapshot_id: u64,
        identity: signing.SignerIdentity,
    ) workspace.Error!workspace.ExportPackage {
        return self.workspaces.exportSnapshot(workspace_id, snapshot_id, identity);
    }

    pub fn exportSnapshotInto(
        self: *Service,
        workspace_id: u64,
        snapshot_id: u64,
        identity: signing.SignerIdentity,
        out: *workspace.ExportPackage,
    ) workspace.Error!void {
        return self.workspaces.exportSnapshotInto(workspace_id, snapshot_id, identity, out);
    }

    pub fn importWorkspace(
        self: *Service,
        owner: principal.PrincipalId,
        label: []const u8,
        package: workspace.ExportPackage,
        tick: u64,
    ) workspace.Error!*workspace.WorkspaceRecord {
        const record = try self.workspaces.importWorkspace(owner, label, package, tick);
        self.noteMutation(true);
        return record;
    }

    pub fn importWorkspaceFromPackage(
        self: *Service,
        owner: principal.PrincipalId,
        label: []const u8,
        package: *const workspace.ExportPackage,
        tick: u64,
    ) workspace.Error!*workspace.WorkspaceRecord {
        const record = try self.workspaces.importWorkspaceFromPackage(owner, label, package, tick);
        self.noteMutation(true);
        return record;
    }

    pub fn shareWorkspace(self: *Service, workspace_id: u64, request: workspace.ShareRequest) workspace.Error!void {
        try self.workspaces.share(workspace_id, request);
        self.noteMutation(true);
    }

    pub fn resolve(self: *const Service, workspace_id: u64, path: []const u8) workspace.Error!workspace.Entry {
        return self.workspaces.resolve(workspace_id, path);
    }

    pub fn entries(self: *const Service, workspace_id: u64) workspace.Error![]const workspace.Entry {
        return self.workspaces.entries(workspace_id);
    }

    pub fn findWorkspace(self: *Service, owner: principal.PrincipalId, label: []const u8) ?*workspace.WorkspaceRecord {
        return self.workspaces.findOwned(owner, label);
    }

    pub fn findWorkspaceByLabel(self: *Service, label: []const u8) ?*workspace.WorkspaceRecord {
        return self.workspaces.findByLabel(label);
    }

    pub fn findSnapshot(self: *Service, workspace_id: u64, label: []const u8) ?*workspace.SnapshotRecord {
        return self.workspaces.findSnapshotByLabel(workspace_id, label);
    }

    pub fn bridge(self: *Service) file_bridge.Bridge {
        return file_bridge.Bridge.init(self, bridgeResolveEntry, bridgeHasVersion);
    }

    pub fn bridgeResolve(
        self: *Service,
        request: file_bridge.ResolveRequest,
        authority: capability.Capability,
        now_ticks: u64,
    ) file_bridge.Error!file_bridge.View {
        var compat_bridge = self.bridge();
        return compat_bridge.resolve(request, authority, now_ticks);
    }

    pub fn object(self: *const Service, object_id: u64) ?*const object_store.ObjectRecord {
        return self.store.object(object_id);
    }

    pub fn version(self: *const Service, version_id: u64) ?*const object_store.VersionRecord {
        return self.store.version(version_id);
    }

    pub fn latestVersion(self: *const Service, object_id: u64) ?*const object_store.VersionRecord {
        return self.store.latestVersion(object_id);
    }

    pub fn latestInsertedVersion(self: *const Service) ?*const object_store.VersionRecord {
        var latest: ?*const object_store.VersionRecord = null;
        for (&self.store.versions) |*slot| {
            if (!slot.in_use) continue;
            if (latest == null or slot.version.id > latest.?.id) {
                latest = &slot.version;
            }
        }
        return latest;
    }

    pub fn objectCount(self: *const Service) usize {
        return self.store.objectCount();
    }

    pub fn versionCount(self: *const Service) usize {
        return self.store.versionCount();
    }

    pub fn findWorkspaceRecord(self: *Service, workspace_id: u64) ?*workspace.WorkspaceRecord {
        return self.workspaces.find(workspace_id);
    }

    pub fn findWorkspaceRecordConst(self: *const Service, workspace_id: u64) ?*const workspace.WorkspaceRecord {
        return self.workspaces.findConst(workspace_id);
    }

    pub fn findShareGrant(self: *const Service, workspace_id: u64, principal_id: principal.PrincipalId) ?workspace.ShareGrant {
        return self.workspaces.findShareGrant(workspace_id, principal_id);
    }

    pub fn workspaceHasAccess(self: *const Service, workspace_id: u64, request: workspace.AccessRequest) bool {
        return self.workspaces.hasAccess(workspace_id, request);
    }

    pub fn workspaceCanReshare(
        self: *const Service,
        workspace_id: u64,
        principal_id: principal.PrincipalId,
        network_scope: workspace.ShareNetworkScope,
        now_ticks: u64,
    ) bool {
        return self.workspaces.canReshare(workspace_id, principal_id, network_scope, now_ticks);
    }

    pub fn hasAnySnapshots(self: *const Service) bool {
        for (self.workspaces.snapshots) |slot| {
            if (slot.in_use) return true;
        }
        return false;
    }

    pub fn hasAnyWorkspaceRecords(self: *const Service) bool {
        for (self.workspaces.workspaces) |slot| {
            if (slot.in_use) return true;
        }
        return false;
    }

    fn noteMutation(self: *const Service, durable_boundary: bool) void {
        checkpoint_support.noteMutation(self, durable_boundary);
    }

    fn flushCheckpoint(self: *const Service) void {
        checkpoint_support.flushCheckpoint(self);
    }
};

fn bridgeResolveEntry(context: *const anyopaque, workspace_id: u64, path: []const u8) workspace.Error!workspace.Entry {
    const service: *const Service = @ptrCast(@alignCast(context));
    return service.resolve(workspace_id, path);
}

fn bridgeHasVersion(context: *const anyopaque, version_id: u64) bool {
    const service: *const Service = @ptrCast(@alignCast(context));
    return service.version(version_id) != null;
}

test "storage service retains authoritative object and workspace state across restart" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 44 };
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA4} ** 32,
    };

    var first = Service.initWithStore(700, 17, owner, &checkpoint_store);
    const object = try first.putVersion(.{
        .preferred_object_id = 950,
        .object_type = .document,
        .payload = "workspace hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "workspace hello", 10),
    });
    const notes = try first.createWorkspace(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try first.shareWorkspace(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 70 },
        .can_read = true,
        .can_write = true,
        .can_admin = true,
        .can_export = true,
        .expires_at_ticks = 90,
        .network_scope = .trusted_overlay,
        .reshare_policy = .admin_only,
        .audit_visibility = .shared_participants,
    });
    try first.beginTransaction(notes.id);
    try first.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    _ = try first.commit(notes.id, 11);

    var restarted = Service.initWithStore(700, 18, owner, &checkpoint_store);
    const resolved = try restarted.resolve(notes.id, "documents/notes.md");
    const entries = try restarted.entries(notes.id);
    const grant = restarted.findShareGrant(notes.id, .{ .kind = .app, .serial = 70 }).?;
    try std.testing.expectEqual(object.object_id, resolved.object_id);
    try std.testing.expectEqual(object.version_id, resolved.version_id);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(?*object_store.Store, &checkpoint_store.store), restarted.store);
    try std.testing.expectEqual(@as(?*workspace.Directory, &checkpoint_store.workspaces), restarted.workspaces);
    try std.testing.expectEqual(workspace.ShareNetworkScope.trusted_overlay, grant.network_scope);
    try std.testing.expectEqual(workspace.ResharePolicy.admin_only, grant.reshare_policy);
    try std.testing.expectEqual(workspace.AuditVisibility.shared_participants, grant.audit_visibility);
    try std.testing.expect(restarted.workspaceHasAccess(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 70 },
        .wants_write = true,
        .wants_export = true,
        .wants_admin = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 50,
    }));
    try std.testing.expect(restarted.workspaceCanReshare(notes.id, .{ .kind = .app, .serial = 70 }, .trusted_overlay, 50));

    checkpoint_store.resetPersistent();
}

test "storage service reloads authoritative state from the attached volume after a cold start" {
    const FakeBackend = struct {
        var image: []u8 = &.{};

        fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            const buffer = buffer_ptr[0..buffer_len];
            const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
            const end = start + buffer.len;
            if (end > image.len) return false;
            @memcpy(buffer, image[start..end]);
            return true;
        }

        fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
            const buffer = buffer_ptr[0..buffer_len];
            const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
            const end = start + buffer.len;
            if (end > image.len) return false;
            @memcpy(image[start..end], buffer);
            return true;
        }
    };

    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    var image = [_]u8{0} ** storage_volume.image_bytes;
    FakeBackend.image = &image;
    storage_volume.attachBackend(.{
        .sector_count = storage_volume.required_device_sectors,
        .read = FakeBackend.read,
        .write = FakeBackend.write,
    });

    const owner = principal.PrincipalId{ .kind = .service, .serial = 45 };
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA5} ** 32,
    };

    var first = Service.initWithStore(701, 17, owner, &checkpoint_store);
    const object = try first.putVersion(.{
        .preferred_object_id = 951,
        .object_type = .document,
        .payload = "cold-start hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "cold-start hello", 10),
    });
    const notes = try first.createWorkspace(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .label = "cold-notes",
    });
    try first.shareWorkspace(notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 88 },
        .can_read = true,
        .can_write = false,
        .can_export = true,
        .expires_at_ticks = 80,
        .network_scope = .relay_assisted,
        .reshare_policy = .owner_only,
        .audit_visibility = .organization_policy,
    });
    try first.beginTransaction(notes.id);
    try first.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    _ = try first.commit(notes.id, 11);

    checkpoint_store.resetPreparedState();

    var reloaded = Service.initWithStore(701, 18, owner, &checkpoint_store);
    const resolved = try reloaded.resolve(notes.id, "documents/notes.md");
    const grant = reloaded.findShareGrant(notes.id, .{ .kind = .device, .serial = 88 }).?;
    try std.testing.expect(reloaded.loaded_from_volume);
    try std.testing.expectEqual(object.object_id, resolved.object_id);
    try std.testing.expectEqual(object.version_id, resolved.version_id);
    try std.testing.expectEqual(workspace.ShareNetworkScope.relay_assisted, grant.network_scope);
    try std.testing.expectEqual(workspace.AuditVisibility.organization_policy, grant.audit_visibility);
    try std.testing.expect(reloaded.workspaceHasAccess(notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 88 },
        .wants_export = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 40,
    }));
    try std.testing.expect(!reloaded.workspaceHasAccess(notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 88 },
        .network_scope = .relay_assisted,
        .now_ticks = 120,
    }));
}
