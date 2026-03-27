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
    store: *object_store.Store,
    workspaces: *workspace.Directory,

    pub fn init(service_id: u64, task_id: u64, owner: principal.PrincipalId) Service {
        if (!has_persisted_state) {
            persisted_store.reset();
            persisted_workspaces.reset();
        }
        return .{
            .service_id = service_id,
            .task_id = task_id,
            .owner = owner,
            .loaded_from_volume = false,
            .store = &persisted_store,
            .workspaces = &persisted_workspaces,
        };
    }

    pub fn bootstrap(service_id: u64, task_id: u64, owner: principal.PrincipalId) Service {
        return .{
            .service_id = service_id,
            .task_id = task_id,
            .owner = owner,
            .loaded_from_volume = false,
            .store = &persisted_store,
            .workspaces = &persisted_workspaces,
        };
    }

    pub fn resetPersistentState() void {
        persisted_store.reset();
        persisted_workspaces.reset();
        has_persisted_state = false;
        storage_volume.clearAttachedVolume();
    }

    pub fn checkpoint(self: *const Service) void {
        _ = self;
        has_persisted_state = true;
        _ = storage_volume.saveToVolume(&persisted_store, &persisted_workspaces) catch null;
    }

    pub fn putVersion(self: *Service, request: object_store.PutRequest) object_store.Error!object_store.PutResult {
        const result = try self.store.putVersion(request);
        self.checkpoint();
        return result;
    }

    pub fn createWorkspace(self: *Service, request: workspace.CreateRequest) workspace.Error!*workspace.WorkspaceRecord {
        const record = try self.workspaces.create(request);
        self.checkpoint();
        return record;
    }

    pub fn beginTransaction(self: *Service, workspace_id: u64) workspace.Error!void {
        try self.workspaces.beginTransaction(workspace_id);
        self.checkpoint();
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
        self.checkpoint();
    }

    pub fn stageDelete(self: *Service, workspace_id: u64, path: []const u8) workspace.Error!void {
        try self.workspaces.stageDelete(workspace_id, path);
        self.checkpoint();
    }

    pub fn commit(self: *Service, workspace_id: u64, tick: u64) workspace.Error!u32 {
        const generation = try self.workspaces.commit(workspace_id, tick);
        self.checkpoint();
        return generation;
    }

    pub fn snapshot(
        self: *Service,
        workspace_id: u64,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) workspace.Error!*workspace.SnapshotRecord {
        const snapshot_record = try self.workspaces.snapshot(workspace_id, label, identity);
        self.checkpoint();
        return snapshot_record;
    }

    pub fn restore(self: *Service, workspace_id: u64, snapshot_id: u64, tick: u64) workspace.Error!u32 {
        const generation = try self.workspaces.restore(workspace_id, snapshot_id, tick);
        self.checkpoint();
        return generation;
    }

    pub fn recoverDeleted(self: *Service, workspace_id: u64, path: []const u8, tick: u64) workspace.Error!bool {
        const recovered = try self.workspaces.recoverDeleted(workspace_id, path, tick);
        self.checkpoint();
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

    pub fn importWorkspace(
        self: *Service,
        owner: principal.PrincipalId,
        label: []const u8,
        package: workspace.ExportPackage,
        tick: u64,
    ) workspace.Error!*workspace.WorkspaceRecord {
        const record = try self.workspaces.importWorkspace(owner, label, package, tick);
        self.checkpoint();
        return record;
    }

    pub fn shareWorkspace(self: *Service, workspace_id: u64, request: workspace.ShareRequest) workspace.Error!void {
        try self.workspaces.share(workspace_id, request);
        self.checkpoint();
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
    try first.beginTransaction(notes.id);
    try first.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    _ = try first.commit(notes.id, 11);

    var restarted = Service.init(700, 18, owner);
    const resolved = try restarted.resolve(notes.id, "documents/notes.md");
    const entries = try restarted.entries(notes.id);
    try std.testing.expectEqual(object.object_id, resolved.object_id);
    try std.testing.expectEqual(object.version_id, resolved.version_id);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(?*object_store.Store, &persisted_store), restarted.store);
    try std.testing.expectEqual(@as(?*workspace.Directory, &persisted_workspaces), restarted.workspaces);

    Service.resetPersistentState();
}
