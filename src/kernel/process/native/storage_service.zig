const std = @import("std");
const capability = @import("capability.zig");
const file_bridge = @import("file_bridge.zig");
const object_store = @import("object_store.zig");
const principal = @import("principal.zig");
const signing = @import("signing.zig");
const storage_volume = @import("storage_volume.zig");
const workspace = @import("workspace.zig");

var persisted_store = object_store.Store.init();
var persisted_workspaces = workspace.Directory.init();
var has_persisted_state = false;

pub const Service = struct {
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    loaded_from_volume: bool = false,
    checkpoint_enabled: bool = true,
    store: *object_store.Store,
    workspaces: *workspace.Directory,

    pub fn init(service_id: u64, task_id: u64, owner: principal.PrincipalId) Service {
        const loaded_from_volume = preparePersistentState();
        return makeService(service_id, task_id, owner, loaded_from_volume);
    }

    pub fn bootstrap(service_id: u64, task_id: u64, owner: principal.PrincipalId) Service {
        const loaded_from_volume = preparePersistentState();
        return makeService(service_id, task_id, owner, loaded_from_volume);
    }

    pub fn bindPrepared(service_id: u64, task_id: u64, owner: principal.PrincipalId, loaded_from_volume: bool) Service {
        return makeService(service_id, task_id, owner, loaded_from_volume);
    }

    pub fn hasCachedPersistentState() bool {
        return has_persisted_state;
    }

    pub fn resetPreparedState() void {
        persisted_store.reset();
        persisted_workspaces.reset();
        has_persisted_state = false;
    }

    pub fn loadPreparedStateFromAttachedVolume() bool {
        if (!storage_volume.hasAttachedDevice()) return false;
        if (storage_volume.loadFromVolume(&persisted_store, &persisted_workspaces)) {
            has_persisted_state = true;
            return true;
        }
        return false;
    }

    pub fn resetPersistentState() void {
        persisted_store.reset();
        persisted_workspaces.reset();
        has_persisted_state = false;
        storage_volume.clearAttachedVolume();
        storage_volume.clearAttachedBackend();
    }

    pub fn reloadFromAttachedVolume(service_id: u64, task_id: u64, owner: principal.PrincipalId) Service {
        Service.resetPreparedState();
        const loaded_from_volume = Service.loadPreparedStateFromAttachedVolume();
        return makeService(service_id, task_id, owner, loaded_from_volume);
    }

    pub fn checkpoint(self: *const Service) void {
        _ = self;
        has_persisted_state = true;
        _ = storage_volume.saveToVolume(&persisted_store, &persisted_workspaces) catch null;
    }

    pub fn putVersion(self: *Service, request: object_store.PutRequest) object_store.Error!object_store.PutResult {
        return self.putVersionRef(&request);
    }

    pub fn putVersionRef(self: *Service, request: *const object_store.PutRequest) object_store.Error!object_store.PutResult {
        const result = try self.store.putVersionRef(request);
        if (self.checkpoint_enabled) self.checkpoint();
        return result;
    }

    pub fn createWorkspace(self: *Service, request: workspace.CreateRequest) workspace.Error!*workspace.WorkspaceRecord {
        return self.createWorkspaceRef(&request);
    }

    pub fn createWorkspaceRef(self: *Service, request: *const workspace.CreateRequest) workspace.Error!*workspace.WorkspaceRecord {
        const record = try self.workspaces.createRef(request);
        if (self.checkpoint_enabled) self.checkpoint();
        return record;
    }

    pub fn beginTransaction(self: *Service, workspace_id: u64) workspace.Error!void {
        try self.workspaces.beginTransaction(workspace_id);
        if (self.checkpoint_enabled) self.checkpoint();
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
        if (self.checkpoint_enabled) self.checkpoint();
    }

    pub fn stageDelete(self: *Service, workspace_id: u64, path: []const u8) workspace.Error!void {
        try self.workspaces.stageDelete(workspace_id, path);
        if (self.checkpoint_enabled) self.checkpoint();
    }

    pub fn commit(self: *Service, workspace_id: u64, tick: u64) workspace.Error!u32 {
        const generation = try self.workspaces.commit(workspace_id, tick);
        if (self.checkpoint_enabled) self.checkpoint();
        return generation;
    }

    pub fn snapshot(
        self: *Service,
        workspace_id: u64,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) workspace.Error!*workspace.SnapshotRecord {
        const snapshot_record = try self.workspaces.snapshot(workspace_id, label, identity);
        if (self.checkpoint_enabled) self.checkpoint();
        return snapshot_record;
    }

    pub fn restore(self: *Service, workspace_id: u64, snapshot_id: u64, tick: u64) workspace.Error!u32 {
        const generation = try self.workspaces.restore(workspace_id, snapshot_id, tick);
        if (self.checkpoint_enabled) self.checkpoint();
        return generation;
    }

    pub fn restoreFromExportPackage(
        self: *Service,
        workspace_id: u64,
        package: *const workspace.ExportPackage,
        tick: u64,
    ) workspace.Error!u32 {
        const generation = try self.workspaces.restoreFromExportPackage(workspace_id, package, tick);
        if (self.checkpoint_enabled) self.checkpoint();
        return generation;
    }

    pub fn recoverDeleted(self: *Service, workspace_id: u64, path: []const u8, tick: u64) workspace.Error!bool {
        const recovered = try self.workspaces.recoverDeleted(workspace_id, path, tick);
        if (self.checkpoint_enabled) self.checkpoint();
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
        if (self.checkpoint_enabled) self.checkpoint();
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
        if (self.checkpoint_enabled) self.checkpoint();
        return record;
    }

    pub fn shareWorkspace(self: *Service, workspace_id: u64, request: workspace.ShareRequest) workspace.Error!void {
        try self.workspaces.share(workspace_id, request);
        if (self.checkpoint_enabled) self.checkpoint();
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
        return file_bridge.Bridge.init(self.store, self.workspaces);
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
};

fn makeService(service_id: u64, task_id: u64, owner: principal.PrincipalId, loaded_from_volume: bool) Service {
    return .{
        .service_id = service_id,
        .task_id = task_id,
        .owner = owner,
        .loaded_from_volume = loaded_from_volume,
        .checkpoint_enabled = true,
        .store = &persisted_store,
        .workspaces = &persisted_workspaces,
    };
}

fn preparePersistentState() bool {
    if (has_persisted_state) return false;
    Service.resetPreparedState();
    return Service.loadPreparedStateFromAttachedVolume();
}

test "storage service retains authoritative object and workspace state across restart" {
    Service.resetPersistentState();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 44 };
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA4} ** 32,
    };

    var first = Service.init(700, 17, owner);
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

    var restarted = Service.init(700, 18, owner);
    const resolved = try restarted.resolve(notes.id, "documents/notes.md");
    const entries = try restarted.entries(notes.id);
    const grant = restarted.workspaces.findShareGrant(notes.id, .{ .kind = .app, .serial = 70 }).?;
    try std.testing.expectEqual(object.object_id, resolved.object_id);
    try std.testing.expectEqual(object.version_id, resolved.version_id);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(?*object_store.Store, &persisted_store), restarted.store);
    try std.testing.expectEqual(@as(?*workspace.Directory, &persisted_workspaces), restarted.workspaces);
    try std.testing.expectEqual(workspace.ShareNetworkScope.trusted_overlay, grant.network_scope);
    try std.testing.expectEqual(workspace.ResharePolicy.admin_only, grant.reshare_policy);
    try std.testing.expectEqual(workspace.AuditVisibility.shared_participants, grant.audit_visibility);
    try std.testing.expect(restarted.workspaces.hasAccess(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 70 },
        .wants_write = true,
        .wants_export = true,
        .wants_admin = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 50,
    }));
    try std.testing.expect(restarted.workspaces.canReshare(notes.id, .{ .kind = .app, .serial = 70 }, .trusted_overlay, 50));

    Service.resetPersistentState();
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

    Service.resetPersistentState();
    defer Service.resetPersistentState();

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

    var first = Service.init(701, 17, owner);
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

    persisted_store.reset();
    persisted_workspaces.reset();
    has_persisted_state = false;

    var reloaded = Service.init(701, 18, owner);
    const resolved = try reloaded.resolve(notes.id, "documents/notes.md");
    const grant = reloaded.workspaces.findShareGrant(notes.id, .{ .kind = .device, .serial = 88 }).?;
    try std.testing.expect(reloaded.loaded_from_volume);
    try std.testing.expectEqual(object.object_id, resolved.object_id);
    try std.testing.expectEqual(object.version_id, resolved.version_id);
    try std.testing.expectEqual(workspace.ShareNetworkScope.relay_assisted, grant.network_scope);
    try std.testing.expectEqual(workspace.AuditVisibility.organization_policy, grant.audit_visibility);
    try std.testing.expect(reloaded.workspaces.hasAccess(notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 88 },
        .wants_export = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 40,
    }));
    try std.testing.expect(!reloaded.workspaces.hasAccess(notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 88 },
        .network_scope = .relay_assisted,
        .now_ticks = 120,
    }));
}
