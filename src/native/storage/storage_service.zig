const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const file_bridge = @import("file_bridge.zig");
const object_store = @import("object_store.zig");
const checkpoint_support = @import("storage_service_checkpoint.zig");
const ids = @import("../core/ids.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const signing = @import("../core/signing.zig");
const storage_volume = @import("storage_volume.zig");
const workspace = @import("workspace.zig");

pub const CheckpointStore = checkpoint_support.CheckpointStore;

pub const SharedPayloadTransfer = struct {
    table: *const shared_memory.Table,
    object_id: ids.SharedMemoryId,
    producer_task_id: ids.TaskId,
    storage_task_id: ids.TaskId,
    bytes: []const u8,
};

pub const SharedPayloadReadTransfer = struct {
    table: *const shared_memory.Table,
    object_id: ids.SharedMemoryId,
    consumer_task_id: ids.TaskId,
    storage_task_id: ids.TaskId,
    bytes: []u8,
};

pub const SharedPayloadError = object_store.Error || shared_memory.Error || error{
    PermissionDenied,
    SharedMemoryNotMapped,
    SharedMemorySizeMismatch,
};

pub const AuthorityContext = struct {
    task_id: u64,
    principal: principal.PrincipalId,
    capability_id: u64,
    now_ticks: u64,
};

pub const AuthorityError = file_bridge.Error;

pub const StorageCore = struct {
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    capability_table: ?*const capability.CapabilityTable = null,
    loaded_from_volume: bool = false,
    checkpoint_enabled: bool = true,
    deferred_checkpoint_count: usize = 0,
    checkpoint_batch_depth: usize = 0,
    checkpoint_store: *CheckpointStore,
    store: *object_store.Store,
    workspaces: *workspace.Directory,

    pub fn initWithStore(
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        checkpoint_store: *CheckpointStore,
    ) StorageCore {
        const loaded_from_volume = checkpoint_store.preparePersistentState();
        return checkpoint_support.makeService(StorageCore, checkpoint_store, service_id, task_id, owner, loaded_from_volume);
    }

    pub fn bootstrapWithStore(
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        checkpoint_store: *CheckpointStore,
    ) StorageCore {
        const loaded_from_volume = checkpoint_store.preparePersistentState();
        return checkpoint_support.makeService(StorageCore, checkpoint_store, service_id, task_id, owner, loaded_from_volume);
    }

    pub fn bindPrepared(
        checkpoint_store: *CheckpointStore,
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        loaded_from_volume: bool,
    ) StorageCore {
        return checkpoint_support.makeService(StorageCore, checkpoint_store, service_id, task_id, owner, loaded_from_volume);
    }

    pub fn reloadFromAttachedVolume(
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        checkpoint_store: *CheckpointStore,
    ) StorageCore {
        checkpoint_store.resetPreparedState();
        const loaded_from_volume = checkpoint_store.loadPreparedStateFromAttachedVolume();
        return checkpoint_support.makeService(StorageCore, checkpoint_store, service_id, task_id, owner, loaded_from_volume);
    }

    pub fn checkpoint(self: *const Service) void {
        self.flushCheckpoint();
    }

    pub fn beginCheckpointBatch(self: *Service) void {
        self.checkpoint_batch_depth += 1;
    }

    pub fn flushCheckpointBatch(self: *Service) void {
        if (self.checkpoint_batch_depth != 0) self.checkpoint_batch_depth -= 1;
        if (self.checkpoint_batch_depth == 0) self.flushCheckpoint();
    }

    pub fn pendingCheckpointMutations(self: *const Service) bool {
        return self.checkpoint_store.dirty;
    }

    pub fn bindCapabilityTable(self: *Service, capability_table: *const capability.CapabilityTable) void {
        self.capability_table = capability_table;
    }

    pub fn putVersion(self: *Service, request: object_store.PutRequest) object_store.Error!object_store.PutResult {
        return self.putVersionRef(&request);
    }

    pub fn putVersionRef(self: *Service, request: *const object_store.PutRequest) object_store.Error!object_store.PutResult {
        const result = try self.store.putVersionRef(request);
        self.noteMutation(true);
        return result;
    }

    pub fn putVersionFromSharedMemory(
        self: *Service,
        request: object_store.PutRequest,
        transfer: SharedPayloadTransfer,
    ) SharedPayloadError!object_store.PutResult {
        return self.putVersionFromSharedMemoryRef(&request, transfer);
    }

    pub fn putVersionFromSharedMemoryRef(
        self: *Service,
        request: *const object_store.PutRequest,
        transfer: SharedPayloadTransfer,
    ) SharedPayloadError!object_store.PutResult {
        const descriptor = try transfer.table.descriptor(transfer.object_id);
        if (descriptor.flags != 0) return error.Revoked;
        if (descriptor.size_bytes != transfer.bytes.len) return error.SharedMemorySizeMismatch;
        if (descriptor.owner_task_id != transfer.producer_task_id.raw()) return error.PermissionDenied;
        if (!transfer.table.hasMapping(transfer.object_id, transfer.producer_task_id)) return error.SharedMemoryNotMapped;
        if (!transfer.table.hasMapping(transfer.object_id, transfer.storage_task_id)) return error.SharedMemoryNotMapped;

        var shared_request = request.*;
        shared_request.payload = transfer.bytes;
        return self.putVersionRef(&shared_request);
    }

    pub fn createWorkspace(self: *Service, request: workspace.CreateRequest) workspace.Error!*workspace.WorkspaceRecord {
        return self.createWorkspaceRef(&request);
    }

    pub fn createWorkspaceRef(self: *Service, request: *const workspace.CreateRequest) workspace.Error!*workspace.WorkspaceRecord {
        const record = try self.workspaces.createRef(request);
        self.noteMutation(true);
        return record;
    }

    pub fn beginTransaction(self: *Service, workspace_id: anytype) workspace.Error!void {
        const key = workspaceId(workspace_id);
        try self.workspaces.beginTransaction(key);
        self.deferred_checkpoint_count += 1;
        self.noteMutation(false);
    }

    pub fn stagePut(
        self: *Service,
        workspace_id: anytype,
        path: []const u8,
        object_id: anytype,
        version_id: anytype,
        object_type: object_store.ObjectType,
    ) workspace.Error!void {
        try self.workspaces.stagePut(workspaceId(workspace_id), path, objectId(object_id), versionId(version_id), object_type);
        self.noteMutation(false);
    }

    pub fn stageDelete(self: *Service, workspace_id: anytype, path: []const u8) workspace.Error!void {
        try self.workspaces.stageDelete(workspaceId(workspace_id), path);
        self.noteMutation(false);
    }

    pub fn commit(self: *Service, workspace_id: anytype, tick: u64) workspace.Error!u32 {
        const generation = try self.workspaces.commit(workspaceId(workspace_id), tick);
        if (self.deferred_checkpoint_count != 0) self.deferred_checkpoint_count -= 1;
        self.noteMutation(true);
        return generation;
    }

    pub fn snapshot(
        self: *Service,
        workspace_id: anytype,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) workspace.Error!*workspace.SnapshotRecord {
        const snapshot_record = try self.workspaces.snapshot(workspaceId(workspace_id), label, identity);
        self.noteMutation(true);
        return snapshot_record;
    }

    pub fn restore(self: *Service, workspace_id: anytype, snapshot_id: anytype, tick: u64) workspace.Error!u32 {
        const generation = try self.workspaces.restore(workspaceId(workspace_id), snapshotId(snapshot_id), tick);
        self.noteMutation(true);
        return generation;
    }

    pub fn restoreFromExportPackage(
        self: *Service,
        workspace_id: anytype,
        package: *const workspace.ExportPackage,
        tick: u64,
    ) workspace.Error!u32 {
        const generation = try self.workspaces.restoreFromExportPackage(workspaceId(workspace_id), package, tick);
        self.noteMutation(true);
        return generation;
    }

    pub fn recoverDeleted(self: *Service, workspace_id: anytype, path: []const u8, tick: u64) workspace.Error!bool {
        const recovered = try self.workspaces.recoverDeleted(workspaceId(workspace_id), path, tick);
        if (recovered) self.noteMutation(true);
        return recovered;
    }

    pub fn exportSnapshot(
        self: *Service,
        workspace_id: anytype,
        snapshot_id: anytype,
        identity: signing.SignerIdentity,
    ) workspace.Error!workspace.ExportPackage {
        return self.workspaces.exportSnapshot(workspaceId(workspace_id), snapshotId(snapshot_id), identity);
    }

    pub fn exportSnapshotInto(
        self: *Service,
        workspace_id: anytype,
        snapshot_id: anytype,
        identity: signing.SignerIdentity,
        out: *workspace.ExportPackage,
    ) workspace.Error!void {
        return self.workspaces.exportSnapshotInto(workspaceId(workspace_id), snapshotId(snapshot_id), identity, out);
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

    pub fn shareWorkspace(self: *Service, workspace_id: anytype, request: workspace.ShareRequest) workspace.Error!void {
        try self.workspaces.share(workspaceId(workspace_id), request);
        self.noteMutation(true);
    }

    pub fn resolve(self: *const Service, workspace_id: anytype, path: []const u8) workspace.Error!workspace.Entry {
        return self.workspaces.resolve(workspaceId(workspace_id), path);
    }

    pub fn entries(self: *const Service, workspace_id: anytype) workspace.Error![]const workspace.Entry {
        return self.workspaces.entries(workspaceId(workspace_id));
    }

    pub fn entryChangesSince(self: *const Service, workspace_id: anytype, generation: u32) workspace.Error![]const workspace.EntryMutation {
        return self.workspaces.entryChangesSince(workspaceId(workspace_id), generation);
    }

    pub fn findWorkspace(self: *Service, owner: principal.PrincipalId, label: []const u8) ?*workspace.WorkspaceRecord {
        return self.workspaces.findOwned(owner, label);
    }

    pub fn findWorkspaceByLabel(self: *Service, label: []const u8) ?*workspace.WorkspaceRecord {
        return self.workspaces.findByLabel(label);
    }

    pub fn findSnapshot(self: *Service, workspace_id: anytype, label: []const u8) ?*workspace.SnapshotRecord {
        return self.workspaces.findSnapshotByLabel(workspaceId(workspace_id), label);
    }

    pub fn bridge(self: *Service) ?file_bridge.Bridge {
        const capability_table = self.capability_table orelse return null;
        return file_bridge.Bridge.init(self, capability_table, bridgeResolveEntry, bridgeHasVersion);
    }

    pub fn bridgeResolve(
        self: *StorageCore,
        request: file_bridge.ResolveRequest,
        authority: AuthorityContext,
    ) file_bridge.Error!file_bridge.View {
        const capability_table = self.capability_table orelse return error.CapabilityRequired;
        var port = StoragePort.init(self, capability_table);
        return port.resolve(authority, request) catch |err| switch (err) {
            error.CapabilityNotFound => return error.CapabilityNotFound,
            error.CapabilityRequired => return error.CapabilityRequired,
            error.CapabilityRevoked => return error.CapabilityRevoked,
            error.ObjectMissing => return error.ObjectMissing,
            error.PermissionDenied => return error.PermissionDenied,
            error.WorkspaceScopeViolation => return error.WorkspaceScopeViolation,
            else => return error.PathNotFound,
        };
    }

    pub fn object(self: *const Service, object_id: anytype) ?*const object_store.ObjectRecord {
        return self.store.object(objectId(object_id));
    }

    pub fn version(self: *const Service, version_id: anytype) ?*const object_store.VersionRecord {
        return self.store.version(versionId(version_id));
    }

    pub fn versionPayload(self: *const Service, version_record: *const object_store.VersionRecord) object_store.Error![]const u8 {
        return self.store.versionPayload(version_record);
    }

    pub fn versionPayloadInto(
        self: *const Service,
        version_record: *const object_store.VersionRecord,
        out: []u8,
    ) object_store.Error![]const u8 {
        return self.store.versionPayloadInto(version_record, out);
    }

    pub fn versionChunkCursor(
        self: *const Service,
        version_record: *const object_store.VersionRecord,
    ) object_store.Error!object_store.Store.VersionChunkCursor {
        return self.store.versionChunkCursor(version_record);
    }

    pub fn transferVersionPayload(
        self: *const Service,
        version_record: *const object_store.VersionRecord,
        out: []u8,
    ) object_store.Error!object_store.PayloadTransferSummary {
        return self.store.transferVersionPayload(version_record, out);
    }

    pub fn versionPayloadIntoSharedMemory(
        self: *const Service,
        version_record: *const object_store.VersionRecord,
        transfer: SharedPayloadReadTransfer,
    ) SharedPayloadError!object_store.PayloadTransferSummary {
        const descriptor = try transfer.table.descriptor(transfer.object_id);
        if (descriptor.flags != 0) return error.Revoked;
        if (descriptor.size_bytes != transfer.bytes.len or transfer.bytes.len < version_record.payload_len) {
            return error.SharedMemorySizeMismatch;
        }
        if (descriptor.owner_task_id != transfer.consumer_task_id.raw()) return error.PermissionDenied;
        if (!transfer.table.hasMapping(transfer.object_id, transfer.consumer_task_id)) return error.SharedMemoryNotMapped;
        if (!transfer.table.hasMapping(transfer.object_id, transfer.storage_task_id)) return error.SharedMemoryNotMapped;
        return self.transferVersionPayload(version_record, transfer.bytes);
    }

    pub fn latestVersion(self: *const Service, object_id: anytype) ?*const object_store.VersionRecord {
        return self.store.latestVersion(objectId(object_id));
    }

    pub fn latestInsertedVersion(self: *const Service) ?*const object_store.VersionRecord {
        var latest: ?*const object_store.VersionRecord = null;
        for (&self.store.versions.slots) |*slot| {
            if (!slot.in_use) continue;
            if (latest == null or slot.version.id.raw() > latest.?.id.raw()) {
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

    pub fn findWorkspaceRecord(self: *Service, workspace_id: anytype) ?*workspace.WorkspaceRecord {
        return self.workspaces.find(workspaceId(workspace_id));
    }

    pub fn findWorkspaceRecordConst(self: *const Service, workspace_id: anytype) ?*const workspace.WorkspaceRecord {
        return self.workspaces.findConst(workspaceId(workspace_id));
    }

    pub fn findShareGrant(self: *const Service, workspace_id: anytype, principal_id: principal.PrincipalId) ?workspace.ShareGrant {
        return self.workspaces.findShareGrant(workspaceId(workspace_id), principal_id);
    }

    pub fn workspaceHasAccess(self: *const Service, workspace_id: anytype, request: workspace.AccessRequest) bool {
        return self.workspaces.hasAccess(workspaceId(workspace_id), request);
    }

    pub fn workspaceCanReshare(
        self: *const Service,
        workspace_id: anytype,
        principal_id: principal.PrincipalId,
        network_scope: workspace.ShareNetworkScope,
        now_ticks: u64,
    ) bool {
        return self.workspaces.canReshare(workspaceId(workspace_id), principal_id, network_scope, now_ticks);
    }

    pub fn hasAnySnapshots(self: *const Service) bool {
        for (self.workspaces.snapshots.slots) |slot| {
            if (slot.in_use) return true;
        }
        return false;
    }

    pub fn hasAnyWorkspaceRecords(self: *const Service) bool {
        for (self.workspaces.workspaces.slots) |slot| {
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

pub const Service = StorageCore;

pub const StoragePort = struct {
    core: *StorageCore,
    capability_table: *const capability.CapabilityTable,

    pub fn init(core: *StorageCore, capability_table: *const capability.CapabilityTable) StoragePort {
        core.bindCapabilityTable(capability_table);
        return .{
            .core = core,
            .capability_table = capability_table,
        };
    }

    pub fn putVersion(self: *StoragePort, authority: AuthorityContext, request: object_store.PutRequest) (AuthorityError || object_store.Error)!object_store.PutResult {
        _ = try self.requireStorageAuthority(authority, null, .write);
        return self.core.putVersion(request);
    }

    pub fn putVersionRef(self: *StoragePort, authority: AuthorityContext, request: *const object_store.PutRequest) (AuthorityError || object_store.Error)!object_store.PutResult {
        _ = try self.requireStorageAuthority(authority, null, .write);
        return self.core.putVersionRef(request);
    }

    pub fn putVersionFromSharedMemoryRef(
        self: *StoragePort,
        authority: AuthorityContext,
        request: *const object_store.PutRequest,
        transfer: SharedPayloadTransfer,
    ) (AuthorityError || SharedPayloadError)!object_store.PutResult {
        _ = try self.requireStorageAuthority(authority, null, .write);
        return self.core.putVersionFromSharedMemoryRef(request, transfer);
    }

    pub fn versionPayloadIntoSharedMemory(
        self: *StoragePort,
        authority: AuthorityContext,
        version_record: *const object_store.VersionRecord,
        transfer: SharedPayloadReadTransfer,
    ) (AuthorityError || SharedPayloadError)!object_store.PayloadTransferSummary {
        _ = try self.requireStorageAuthority(authority, null, .read);
        return self.core.versionPayloadIntoSharedMemory(version_record, transfer);
    }

    pub fn createWorkspace(self: *StoragePort, authority: AuthorityContext, request: workspace.CreateRequest) (AuthorityError || workspace.Error)!*workspace.WorkspaceRecord {
        _ = try self.requireStorageAuthority(authority, null, .write);
        return self.core.createWorkspace(request);
    }

    pub fn createWorkspaceRef(self: *StoragePort, authority: AuthorityContext, request: *const workspace.CreateRequest) (AuthorityError || workspace.Error)!*workspace.WorkspaceRecord {
        _ = try self.requireStorageAuthority(authority, null, .write);
        return self.core.createWorkspaceRef(request);
    }

    pub fn beginTransaction(self: *StoragePort, authority: AuthorityContext, workspace_id: anytype) (AuthorityError || workspace.Error)!void {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .write);
        return self.core.beginTransaction(key);
    }

    pub fn stagePut(
        self: *StoragePort,
        authority: AuthorityContext,
        workspace_id: anytype,
        path: []const u8,
        object_id: anytype,
        version_id: anytype,
        object_type: object_store.ObjectType,
    ) (AuthorityError || workspace.Error)!void {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .write);
        return self.core.stagePut(key, path, objectId(object_id), versionId(version_id), object_type);
    }

    pub fn stageDelete(self: *StoragePort, authority: AuthorityContext, workspace_id: anytype, path: []const u8) (AuthorityError || workspace.Error)!void {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .write);
        return self.core.stageDelete(key, path);
    }

    pub fn commit(self: *StoragePort, authority: AuthorityContext, workspace_id: anytype) (AuthorityError || workspace.Error)!u32 {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .write);
        return self.core.commit(key, authority.now_ticks);
    }

    pub fn snapshot(
        self: *StoragePort,
        authority: AuthorityContext,
        workspace_id: anytype,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) (AuthorityError || workspace.Error)!*workspace.SnapshotRecord {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .read);
        return self.core.snapshot(key, label, identity);
    }

    pub fn restore(self: *StoragePort, authority: AuthorityContext, workspace_id: anytype, snapshot_id: anytype) (AuthorityError || workspace.Error)!u32 {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .write);
        return self.core.restore(key, snapshotId(snapshot_id), authority.now_ticks);
    }

    pub fn restoreFromExportPackage(
        self: *StoragePort,
        authority: AuthorityContext,
        workspace_id: anytype,
        package: *const workspace.ExportPackage,
    ) (AuthorityError || workspace.Error)!u32 {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .write);
        return self.core.restoreFromExportPackage(key, package, authority.now_ticks);
    }

    pub fn recoverDeleted(self: *StoragePort, authority: AuthorityContext, workspace_id: anytype, path: []const u8) (AuthorityError || workspace.Error)!bool {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .write);
        return self.core.recoverDeleted(key, path, authority.now_ticks);
    }

    pub fn importWorkspace(
        self: *StoragePort,
        authority: AuthorityContext,
        owner: principal.PrincipalId,
        label: []const u8,
        package: workspace.ExportPackage,
    ) (AuthorityError || workspace.Error)!*workspace.WorkspaceRecord {
        _ = try self.requireStorageAuthority(authority, null, .write);
        return self.core.importWorkspace(owner, label, package, authority.now_ticks);
    }

    pub fn importWorkspaceFromPackage(
        self: *StoragePort,
        authority: AuthorityContext,
        owner: principal.PrincipalId,
        label: []const u8,
        package: *const workspace.ExportPackage,
    ) (AuthorityError || workspace.Error)!*workspace.WorkspaceRecord {
        _ = try self.requireStorageAuthority(authority, null, .write);
        return self.core.importWorkspaceFromPackage(owner, label, package, authority.now_ticks);
    }

    pub fn shareWorkspace(self: *StoragePort, authority: AuthorityContext, workspace_id: anytype, request: workspace.ShareRequest) (AuthorityError || workspace.Error)!void {
        const key = workspaceId(workspace_id);
        _ = try self.requireStorageAuthority(authority, key, .write);
        return self.core.shareWorkspace(key, request);
    }

    pub fn resolve(self: *StoragePort, authority: AuthorityContext, request: file_bridge.ResolveRequest) (AuthorityError || workspace.Error)!file_bridge.View {
        _ = try self.requireStorageAuthority(authority, ids.workspace(request.workspace_id), request.access);
        var bridge = file_bridge.Bridge.init(self.core, self.capability_table, bridgeResolveEntry, bridgeHasVersion);
        return bridge.resolve(request, authority.principal, authority.capability_id, authority.now_ticks);
    }

    fn requireStorageAuthority(
        self: *const StoragePort,
        authority_context: AuthorityContext,
        workspace_id: ?ids.WorkspaceId,
        access: file_bridge.AccessMode,
    ) AuthorityError!*const capability.Capability {
        const authority = self.capability_table.requireUsable(authority_context.capability_id, authority_context.now_ticks) catch |err| switch (err) {
            error.CapabilityNotFound => return error.CapabilityNotFound,
            error.CapabilityRevoked => return error.CapabilityRevoked,
            else => native_util.impossibleByInvariantError("storage authority lookup only reports not-found or revoked capabilities", err),
        };
        if (!authority.holder.eql(authority_context.principal)) return error.PermissionDenied;
        if (authority.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != authority_context.task_id) return error.PermissionDenied;
        }
        if (workspace_id) |requested_workspace_id| {
            if (authority.scope.workspace_id) |scoped_workspace_id| {
                if (scoped_workspace_id != requested_workspace_id.raw()) return error.WorkspaceScopeViolation;
            }
        }
        switch (authority.target.kind) {
            .service => if (authority.target.id != self.core.service_id) return error.CapabilityRequired,
            .workspace => if (workspace_id == null or authority.target.id != workspace_id.?.raw()) return error.WorkspaceScopeViolation,
            .object => if (access == .write) return error.PermissionDenied,
            else => return error.CapabilityRequired,
        }
        if (access == .write and !authority.rights.has(.object_write)) return error.PermissionDenied;
        if (access == .read and !authority.rights.has(.object_read)) return error.PermissionDenied;
        return authority;
    }
};

fn bridgeResolveEntry(context: *const anyopaque, workspace_id: u64, path: []const u8) workspace.Error!workspace.Entry {
    const service: *const StorageCore = @ptrCast(@alignCast(context));
    return service.resolve(ids.workspace(workspace_id), path);
}

fn bridgeHasVersion(context: *const anyopaque, version_id: u64) bool {
    const service: *const StorageCore = @ptrCast(@alignCast(context));
    return service.version(ids.version(version_id)) != null;
}

fn workspaceId(value: anytype) ids.WorkspaceId {
    return ids.coerce(ids.WorkspaceId, value);
}

fn objectId(value: anytype) ids.ObjectId {
    return ids.coerce(ids.ObjectId, value);
}

fn versionId(value: anytype) ids.VersionId {
    return ids.coerce(ids.VersionId, value);
}

fn snapshotId(value: anytype) ids.SnapshotId {
    return ids.coerce(ids.SnapshotId, value);
}

test "storage port requires authority context for protected mutations" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 47 };
    const actor = principal.PrincipalId{ .kind = .user, .serial = 7 };
    var core = StorageCore.initWithStore(703, 20, owner, &checkpoint_store);
    var capabilities = capability.CapabilityTable.init();
    var port = StoragePort.init(&core, &capabilities);

    const read_only = try capabilities.mintBootRoot(.{
        .holder = actor,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = core.service_id },
        .rights = .{ .service = .{ .object_read = true } },
        .scope = .{ .task_id = 20, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const writer = try capabilities.mintBootRoot(.{
        .holder = actor,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = core.service_id },
        .rights = .{ .service = .{ .object_read = true, .object_write = true } },
        .scope = .{ .task_id = 20, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA7} ** 32,
    };
    const request = object_store.PutRequest{
        .preferred_object_id = ids.object(953),
        .object_type = .document,
        .payload = "authorized",
        .metadata = try object_store.signMetadata(signer, "authorized", "text/plain", .document, "authorized", 10),
    };

    try std.testing.expectError(error.PermissionDenied, port.putVersion(.{
        .task_id = 20,
        .principal = actor,
        .capability_id = read_only.id,
        .now_ticks = 10,
    }, request));

    const result = try port.putVersion(.{
        .task_id = 20,
        .principal = actor,
        .capability_id = writer.id,
        .now_ticks = 10,
    }, request);
    try std.testing.expectEqual(ids.object(953), result.object_id);

    try std.testing.expectError(error.PermissionDenied, port.createWorkspace(.{
        .task_id = 21,
        .principal = actor,
        .capability_id = writer.id,
        .now_ticks = 10,
    }, .{
        .owner = actor,
        .label = "denied-task",
    }));
}

test "storage service accepts large object payloads through mapped shared memory transfer" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 48 };
    const producer_task_id = ids.task(200);
    const storage_task_id = ids.task(201);
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA8} ** 32,
    };

    var payload: [object_store.PAGE_SIZE_BYTES * 2 + 33]u8 = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @intCast((index * 17) & 0xFF);
    }

    var shared = shared_memory.Table.init();
    const transfer_object = try shared.create(producer_task_id, payload.len);
    try shared.map(transfer_object.id, producer_task_id);
    try shared.map(transfer_object.id, storage_task_id);

    var service = Service.initWithStore(704, storage_task_id.raw(), owner, &checkpoint_store);
    const request = object_store.PutRequest{
        .preferred_object_id = ids.object(954),
        .object_type = .media_asset,
        .payload = &.{},
        .metadata = try object_store.signMetadata(signer, "large", "application/octet-stream", .media_asset, &payload, 12),
    };
    const result = try service.putVersionFromSharedMemoryRef(&request, .{
        .table = &shared,
        .object_id = transfer_object.id,
        .producer_task_id = producer_task_id,
        .storage_task_id = storage_task_id,
        .bytes = &payload,
    });

    const loaded = try service.versionPayload(service.version(result.version_id).?);
    try std.testing.expectEqualSlices(u8, &payload, loaded);

    const consumer_task_id = ids.task(202);
    var read_buffer: [payload.len]u8 = undefined;
    const read_object = try shared.create(consumer_task_id, payload.len);
    try shared.map(read_object.id, consumer_task_id);
    try shared.map(read_object.id, storage_task_id);
    const read_summary = try service.versionPayloadIntoSharedMemory(service.version(result.version_id).?, .{
        .table = &shared,
        .object_id = read_object.id,
        .consumer_task_id = consumer_task_id,
        .storage_task_id = storage_task_id,
        .bytes = &read_buffer,
    });
    try std.testing.expectEqual(payload.len, read_summary.bytes_transferred);
    try std.testing.expectEqualSlices(u8, &payload, read_buffer[0..read_summary.bytes_transferred]);

    const wrong_size = payload[0 .. payload.len - 1];
    try std.testing.expectError(error.SharedMemorySizeMismatch, service.putVersionFromSharedMemoryRef(&request, .{
        .table = &shared,
        .object_id = transfer_object.id,
        .producer_task_id = producer_task_id,
        .storage_task_id = storage_task_id,
        .bytes = wrong_size,
    }));
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
        .preferred_object_id = ids.object(950),
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
        .preferred_object_id = ids.object(951),
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

test "storage service coalesces checkpoint writes across an explicit batch" {
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
    defer storage_volume.clearAttachedBackend();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 48 };
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA8} ** 32,
    };

    var service = Service.initWithStore(704, 21, owner, &checkpoint_store);
    service.beginCheckpointBatch();
    const object = try service.putVersion(.{
        .preferred_object_id = ids.object(954),
        .object_type = .document,
        .payload = "batched checkpoint",
        .metadata = try object_store.signMetadata(signer, "batched", "text/plain", .document, "batched checkpoint", 10),
    });
    const notes = try service.createWorkspace(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .label = "batched-notes",
    });
    try service.beginTransaction(notes.id);
    try service.stagePut(notes.id, "documents/batched.md", object.object_id, object.version_id, .document);
    _ = try service.commit(notes.id, 11);

    try std.testing.expect(service.pendingCheckpointMutations());
    try std.testing.expectEqual(@as(u64, 0), checkpoint_store.last_checkpoint_generation);

    service.flushCheckpointBatch();
    try std.testing.expect(!service.pendingCheckpointMutations());
    try std.testing.expectEqual(@as(u64, 1), checkpoint_store.last_checkpoint_generation);

    checkpoint_store.resetPreparedState();
    var reloaded = Service.initWithStore(704, 22, owner, &checkpoint_store);
    try std.testing.expect(reloaded.loaded_from_volume);
    const resolved = try reloaded.resolve(notes.id, "documents/batched.md");
    try std.testing.expectEqual(object.version_id, resolved.version_id);
}

test "storage service records checkpoint flush failures" {
    const FailingBackend = struct {
        fn read(_: u64, _: [*]u8, _: usize) callconv(.c) bool {
            return false;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return false;
        }
    };

    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();
    storage_volume.attachBackend(.{
        .sector_count = storage_volume.required_device_sectors,
        .read = FailingBackend.read,
        .write = FailingBackend.write,
    });
    defer storage_volume.clearAttachedBackend();

    var service = Service.initWithStore(702, 19, .{ .kind = .service, .serial = 46 }, &checkpoint_store);
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA6} ** 32,
    };
    _ = try service.putVersion(.{
        .preferred_object_id = ids.object(952),
        .object_type = .document,
        .payload = "checkpoint failure",
        .metadata = try object_store.signMetadata(signer, "failure", "text/plain", .document, "checkpoint failure", 10),
    });

    try std.testing.expect(checkpoint_store.dirty);
    try std.testing.expect(!checkpoint_store.checkpointHealthy());
    try std.testing.expectEqual(storage_volume.Error.CorruptImage, checkpoint_store.last_checkpoint_error.?);
}
