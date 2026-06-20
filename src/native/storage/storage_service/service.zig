const abi = @import("../../core/abi.zig");
const capability = @import("../../kernel_api/capability.zig");
const debug_contract = @import("../../security/debug_contract.zig");
const file_bridge = @import("../file_bridge.zig");
const object_store = @import("../object_store.zig");
const checkpoint_support = @import("../storage_service_checkpoint.zig");
const ids = @import("../../core/ids.zig");
const native_util = @import("../../core/util.zig");
const principal = @import("../../core/principal.zig");
const service_authority = @import("../../services/service_authority.zig");
const shared_memory = @import("../../kernel_api/shared_memory.zig");
const signing = @import("../../core/signing.zig");
const workspace = @import("../workspace.zig");

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

pub const AuthorityContext = service_authority.Context;

pub const AuthorityError = file_bridge.Error;

pub const SharedWorkspaceGrant = struct {
    grant: workspace.ShareGrant,
    capability: capability.Capability,
};

pub const ShareCapabilityError = AuthorityError || workspace.Error || capability.Error;

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
            error.PathAuthorityRejected => return error.PathAuthorityRejected,
            error.PathSyntaxInvalid => return error.PathSyntaxInvalid,
            error.PathTooLong => return error.PathTooLong,
            error.PermissionDenied => return error.PermissionDenied,
            error.WorkspaceScopeViolation => return error.WorkspaceScopeViolation,
            else => return error.PathNotFound,
        };
    }

    pub fn object(self: *const Service, object_id: anytype) ?*const object_store.ObjectRecord {
        return self.store.objectConst(objectId(object_id));
    }

    pub fn version(self: *const Service, version_id: anytype) ?*const object_store.VersionRecord {
        return self.store.versionConst(versionId(version_id));
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
        return self.store.latestVersionConst(objectId(object_id));
    }

    pub fn queryObjects(
        self: *const Service,
        query: object_store.ObjectQuery,
        output: []object_store.ObjectQueryResult,
    ) []const object_store.ObjectQueryResult {
        return self.store.queryObjects(query, output);
    }

    pub fn objectHistory(
        self: *const Service,
        object_id: anytype,
        output: []object_store.ObjectHistoryEntry,
    ) object_store.Error![]const object_store.ObjectHistoryEntry {
        return self.store.objectHistory(objectId(object_id), output);
    }

    pub fn objectOperatingModel(
        self: *const Service,
        object_id: anytype,
    ) object_store.Error!object_store.ObjectOperatingModel {
        return self.store.objectOperatingModel(objectId(object_id));
    }

    pub fn findEntryForObject(self: *const Service, workspace_id: anytype, object_id: anytype) workspace.Error!workspace.Entry {
        const entries_slice = try self.entries(workspace_id);
        const key = objectId(object_id);
        for (entries_slice) |entry| {
            if (entry.object_id.eql(key)) return entry;
        }
        return error.EntryNotFound;
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

    pub fn workspaceHasAnyAccess(self: *const Service, workspace_id: anytype, request: workspace.AccessRequest) bool {
        return self.workspaces.hasAnyAccess(workspaceId(workspace_id), request);
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
        for (&self.workspaces.snapshots.slots) |*slot| {
            if (slot.in_use) return true;
        }
        return false;
    }

    pub fn hasAnyWorkspaceRecords(self: *const Service) bool {
        for (&self.workspaces.workspaces.slots) |*slot| {
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
        const authority_capability = try self.requireStorageAuthority(authority, key, .write);
        if (authority_capability.target.kind != .workspace or authority_capability.target.id != key.raw()) return error.WorkspaceScopeViolation;
        if (!authority_capability.rights.has(.capability_derive)) return error.PermissionDenied;

        const record = self.core.findWorkspaceRecordConst(key) orelse return error.WorkspaceNotFound;
        if (!shareSlotAvailable(record, request.principal_id)) return error.ShareTableFull;

        var effective_grant = request;
        effective_grant.expires_at_ticks = boundedGrantExpiry(
            request.expires_at_ticks,
            authority_capability.lease.expires_at_ticks,
        );
        try self.validateShareActor(record, authority.principal, effective_grant, authority.now_ticks);
        return self.core.shareWorkspace(key, effective_grant);
    }

    pub fn grantWorkspaceShare(
        self: *StoragePort,
        capability_table: *capability.CapabilityTable,
        authority_context: AuthorityContext,
        workspace_id: anytype,
        request: workspace.ShareRequest,
    ) ShareCapabilityError!SharedWorkspaceGrant {
        const key = workspaceId(workspace_id);
        const authority = try self.requireStorageAuthority(authority_context, key, .write);
        if (authority.target.kind != .workspace or authority.target.id != key.raw()) return error.WorkspaceScopeViolation;
        if (!authority.rights.has(.capability_derive)) return error.PermissionDenied;

        const record = self.core.findWorkspaceRecordConst(key) orelse return error.WorkspaceNotFound;
        if (!shareSlotAvailable(record, request.principal_id)) return error.ShareTableFull;

        var effective_grant = request;
        effective_grant.expires_at_ticks = boundedGrantExpiry(
            request.expires_at_ticks,
            authority.lease.expires_at_ticks,
        );
        try self.validateShareActor(record, authority_context.principal, effective_grant, authority_context.now_ticks);

        const derived = try capability_table.derive(.{
            .parent_capability_id = authority.id,
            .holder = effective_grant.principal_id,
            .rights = workspaceRightsForGrant(effective_grant),
            .scope = .{
                .workspace_id = key.raw(),
                .local_only = effective_grant.network_scope == .local_only,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = authority_context.now_ticks,
                .expires_at_ticks = effective_grant.expires_at_ticks,
            },
            .audit = .{
                .policy_generation = shareAuditGeneration(record, effective_grant.principal_id),
                .source_task_id = authority_context.task_id,
                .broker_service_id = self.core.service_id,
            },
        });
        errdefer capability_table.revokeGrant(derived.id) catch {};

        try self.core.shareWorkspace(key, effective_grant);
        return .{
            .grant = effective_grant,
            .capability = derived,
        };
    }

    pub fn grantObjectShare(
        self: *StoragePort,
        capability_table: *capability.CapabilityTable,
        authority_context: AuthorityContext,
        workspace_id: anytype,
        object_id: anytype,
        request: workspace.ShareRequest,
    ) ShareCapabilityError!SharedWorkspaceGrant {
        const workspace_key = workspaceId(workspace_id);
        const object_key = objectId(object_id);
        const authority = try self.requireStorageAuthority(authority_context, workspace_key, .write);
        if (authority.target.kind != .workspace or authority.target.id != workspace_key.raw()) return error.WorkspaceScopeViolation;
        if (!authority.rights.has(.capability_derive)) return error.PermissionDenied;

        const record = self.core.findWorkspaceRecordConst(workspace_key) orelse return error.WorkspaceNotFound;
        if (!shareSlotAvailable(record, request.principal_id)) return error.ShareTableFull;
        const entry = try self.core.findEntryForObject(workspace_key, object_key);

        var effective_grant = try request.withObjectScope(object_key, entry.pathSlice());
        effective_grant.expires_at_ticks = boundedGrantExpiry(
            request.expires_at_ticks,
            authority.lease.expires_at_ticks,
        );
        try self.validateShareActor(record, authority_context.principal, effective_grant, authority_context.now_ticks);

        const derived = try capability_table.mintBootRoot(.{
            .holder = effective_grant.principal_id,
            .issuer = authority_context.principal,
            .target = .{ .kind = .object, .id = object_key.raw() },
            .rights = objectRightsForGrant(effective_grant),
            .scope = .{
                .workspace_id = workspace_key.raw(),
                .local_only = effective_grant.network_scope == .local_only,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = authority_context.now_ticks,
                .expires_at_ticks = effective_grant.expires_at_ticks,
            },
            .audit = .{
                .policy_generation = shareAuditGeneration(record, effective_grant.principal_id),
                .source_task_id = authority_context.task_id,
                .broker_service_id = self.core.service_id,
                .parent_trace_id = authority.traceId(),
            },
        });
        errdefer capability_table.revokeGrant(derived.id) catch {};

        try self.core.shareWorkspace(workspace_key, effective_grant);
        return .{
            .grant = effective_grant,
            .capability = derived,
        };
    }

    pub fn queryObjects(
        self: *StoragePort,
        authority: AuthorityContext,
        query: object_store.ObjectQuery,
        output: []object_store.ObjectQueryResult,
    ) AuthorityError![]const object_store.ObjectQueryResult {
        _ = try self.requireStorageAuthority(authority, null, .read);
        return self.core.queryObjects(query, output);
    }

    pub fn objectHistory(
        self: *StoragePort,
        authority: AuthorityContext,
        object_id: anytype,
        output: []object_store.ObjectHistoryEntry,
    ) (AuthorityError || object_store.Error)![]const object_store.ObjectHistoryEntry {
        _ = try self.requireObjectAuthority(authority, objectId(object_id), .read);
        return self.core.objectHistory(object_id, output);
    }

    pub fn objectOperatingModel(
        self: *StoragePort,
        authority: AuthorityContext,
        object_id: anytype,
    ) (AuthorityError || object_store.Error)!object_store.ObjectOperatingModel {
        _ = try self.requireObjectAuthority(authority, objectId(object_id), .read);
        return self.core.objectOperatingModel(object_id);
    }

    pub fn resolve(self: *StoragePort, authority: AuthorityContext, request: file_bridge.ResolveRequest) (AuthorityError || workspace.Error)!file_bridge.View {
        const workspace_id = ids.workspace(request.workspace_id);
        _ = try file_bridge.validateBridgePath(request.path);
        const storage_authority = try self.requireStorageAuthority(authority, workspace_id, request.access);
        if (storage_authority.target.kind == .workspace) {
            try self.requireGrantScopeForResolve(authority, request);
        }
        var bridge = file_bridge.Bridge.init(self.core, self.capability_table, bridgeResolveEntry, bridgeHasVersion);
        return bridge.resolve(request, authority.principal, authority.capability_id, authority.now_ticks);
    }

    fn requireGrantScopeForResolve(
        self: *const StoragePort,
        authority: AuthorityContext,
        request: file_bridge.ResolveRequest,
    ) (AuthorityError || workspace.Error)!void {
        const workspace_id = ids.workspace(request.workspace_id);
        const record = self.core.findWorkspaceRecordConst(workspace_id) orelse return error.WorkspaceNotFound;
        if (record.owner.eql(authority.principal)) return;

        const path = try file_bridge.validateBridgePath(request.path);
        const entry = try self.core.resolve(workspace_id, path);
        if (!self.core.workspaceHasAccess(workspace_id, .{
            .principal_id = authority.principal,
            .object_id = entry.object_id,
            .path = entry.pathSlice(),
            .wants_write = request.access == .write,
            .network_scope = .local_only,
            .now_ticks = authority.now_ticks,
        })) return error.PermissionDenied;
    }

    fn requireObjectAuthority(
        self: *const StoragePort,
        authority_context: AuthorityContext,
        object_id: ids.ObjectId,
        access: file_bridge.AccessMode,
    ) AuthorityError!*const capability.Capability {
        const authority = try self.requireStorageAuthority(authority_context, null, access);
        if (authority.target.kind == .object and authority.target.id != object_id.raw()) return error.PermissionDenied;
        if (authority.target.kind != .object and authority.target.kind != .service) return error.CapabilityRequired;
        return authority;
    }

    fn requireStorageAuthority(
        self: *const StoragePort,
        authority_context: AuthorityContext,
        workspace_id: ?ids.WorkspaceId,
        access: file_bridge.AccessMode,
    ) AuthorityError!*const capability.Capability {
        const required_right: capability.CapabilityRight = if (access == .write) .object_write else .object_read;
        const authority = try self.requireUsableStorageCapability(authority_context, required_right);
        if (!authority.holder.eql(authority_context.principal)) {
            return self.denyStorageAuthorityTarget(
                authority_context,
                required_right,
                authority,
                .policy_denied,
                error.PermissionDenied,
            );
        }
        if (authority.scope.task_id) |scoped_task_id| {
            if (scoped_task_id != authority_context.task_id) {
                return self.denyStorageAuthorityTarget(
                    authority_context,
                    required_right,
                    authority,
                    .scope_violation,
                    error.PermissionDenied,
                );
            }
        }
        if (workspace_id) |requested_workspace_id| {
            if (authority.scope.workspace_id) |scoped_workspace_id| {
                if (scoped_workspace_id != requested_workspace_id.raw()) {
                    return self.denyStorageAuthority(
                        authority_context,
                        required_right,
                        .workspace,
                        requested_workspace_id.raw(),
                        .scope_violation,
                        error.WorkspaceScopeViolation,
                    );
                }
            }
        }
        switch (authority.target.kind) {
            .service => if (authority.target.id != self.core.service_id) {
                return self.denyStorageAuthorityTarget(
                    authority_context,
                    required_right,
                    authority,
                    .invalid_target,
                    error.CapabilityRequired,
                );
            },
            .workspace => {
                const requested_workspace_id = workspace_id orelse {
                    return self.denyStorageAuthorityTarget(
                        authority_context,
                        required_right,
                        authority,
                        .scope_violation,
                        error.WorkspaceScopeViolation,
                    );
                };
                if (authority.target.id != requested_workspace_id.raw()) {
                    return self.denyStorageAuthorityTarget(
                        authority_context,
                        required_right,
                        authority,
                        .scope_violation,
                        error.WorkspaceScopeViolation,
                    );
                }
            },
            .object => if (access == .write) {
                return self.denyStorageAuthorityTarget(
                    authority_context,
                    required_right,
                    authority,
                    .policy_denied,
                    error.PermissionDenied,
                );
            },
            else => {
                return self.denyStorageAuthorityTarget(
                    authority_context,
                    required_right,
                    authority,
                    .invalid_target,
                    error.CapabilityRequired,
                );
            },
        }
        if (access == .write and !authority.rights.has(.object_write)) {
            return self.denyStorageAuthorityTarget(
                authority_context,
                required_right,
                authority,
                .policy_denied,
                error.PermissionDenied,
            );
        }
        if (access == .read and !authority.rights.has(.object_read)) {
            return self.denyStorageAuthorityTarget(
                authority_context,
                required_right,
                authority,
                .policy_denied,
                error.PermissionDenied,
            );
        }
        writeStorageTrace(
            authority_context,
            self.core.service_id,
            required_right,
            authority.target.kind,
            authority.target.id,
            .allowed,
            .none,
        );
        return authority;
    }

    fn requireUsableStorageCapability(
        self: *const StoragePort,
        authority_context: AuthorityContext,
        required_right: capability.CapabilityRight,
    ) AuthorityError!*const capability.Capability {
        return self.capability_table.requireUsable(authority_context.capability_id, authority_context.now_ticks) catch |err| switch (err) {
            error.CapabilityNotFound => {
                return self.denyStorageAuthority(
                    authority_context,
                    required_right,
                    null,
                    0,
                    .capability_missing,
                    error.CapabilityNotFound,
                );
            },
            error.CapabilityRevoked => {
                return self.denyStorageAuthority(
                    authority_context,
                    required_right,
                    null,
                    0,
                    .capability_revoked,
                    error.CapabilityRevoked,
                );
            },
            else => native_util.impossibleByInvariantError("storage authority lookup only reports not-found or revoked capabilities", err),
        };
    }

    fn denyStorageAuthorityTarget(
        self: *const StoragePort,
        authority_context: AuthorityContext,
        required_right: capability.CapabilityRight,
        authority: *const capability.Capability,
        reason: abi.DenialReason,
        err: AuthorityError,
    ) AuthorityError {
        return self.denyStorageAuthority(
            authority_context,
            required_right,
            authority.target.kind,
            authority.target.id,
            reason,
            err,
        );
    }

    fn denyStorageAuthority(
        self: *const StoragePort,
        authority_context: AuthorityContext,
        required_right: capability.CapabilityRight,
        target_kind: ?capability.CapabilityTargetKind,
        target_id: u64,
        reason: abi.DenialReason,
        err: AuthorityError,
    ) AuthorityError {
        writeStorageTrace(
            authority_context,
            self.core.service_id,
            required_right,
            target_kind,
            target_id,
            .denied,
            reason,
        );
        return err;
    }

    fn validateShareActor(
        self: *const StoragePort,
        record: *const workspace.WorkspaceRecord,
        actor: principal.PrincipalId,
        request: workspace.ShareGrant,
        now_ticks: u64,
    ) AuthorityError!void {
        _ = self;
        if (record.owner.eql(actor)) return;

        const actor_grant = findGrantInRecord(record, actor) orelse return error.PermissionDenied;
        if (!actor_grant.isActive(now_ticks)) return error.PermissionDenied;
        if (!actor_grant.allowsNetworkScope(request.network_scope)) return error.PermissionDenied;
        if (!actorMayReshare(actor_grant)) return error.PermissionDenied;
        if (shareGrantEscalates(actor_grant, request)) return error.PermissionDenied;
    }
};

fn writeStorageTrace(
    authority_context: AuthorityContext,
    service_id: u64,
    required_right: capability.CapabilityRight,
    target_kind: ?capability.CapabilityTargetKind,
    target_id: u64,
    decision: debug_contract.Decision,
    reason: abi.DenialReason,
) void {
    if (authority_context.trace) |trace| {
        const explanation = if (decision == .denied)
            debug_contract.explainDenied(
                reason,
                authority_context.operation,
                @tagName(required_right),
                authority_context.task_id,
                authority_context.capability_id,
                target_kind,
                target_id,
            )
        else
            debug_contract.DenialExplanation{};
        trace.* = debug_contract.provenance(
            .service_call,
            decision,
            authority_context.now_ticks,
            authority_context.task_id,
            service_id,
            authority_context.capability_id,
            target_kind,
            target_id,
            authority_context.operation,
            @tagName(required_right),
            explanation,
            0,
        );
    }
}

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

fn shareSlotAvailable(record: *const workspace.WorkspaceRecord, principal_id: principal.PrincipalId) bool {
    for (record.share_table.share_grants[0..record.share_table.share_grant_count]) |grant| {
        if (grant.principal_id.eql(principal_id)) return true;
    }
    return record.share_table.share_grant_count < workspace.MAX_SHARE_GRANTS;
}

fn findGrantInRecord(record: *const workspace.WorkspaceRecord, principal_id: principal.PrincipalId) ?workspace.ShareGrant {
    for (record.share_table.share_grants[0..record.share_table.share_grant_count]) |grant| {
        if (grant.principal_id.eql(principal_id)) return grant;
    }
    return null;
}

fn boundedGrantExpiry(requested_expiry: u64, authority_expiry: u64) u64 {
    if (requested_expiry == 0) return authority_expiry;
    return @min(requested_expiry, authority_expiry);
}

fn workspaceRightsForGrant(grant: workspace.ShareGrant) capability.CapabilityRights {
    return .{ .workspace = .{
        .object_read = grant.can_read or grant.can_write or grant.can_admin or grant.can_export,
        .object_write = grant.can_write,
        .capability_derive = grant.can_admin or grant.reshare_policy != .owner_only,
        .capability_query = grant.audit_visibility != .owner_only,
    } };
}

fn objectRightsForGrant(grant: workspace.ShareGrant) capability.CapabilityRights {
    return .{ .object = .{
        .object_read = grant.can_read or grant.can_write or grant.can_admin or grant.can_export,
        .object_write = grant.can_write,
        .capability_derive = grant.can_admin or grant.reshare_policy != .owner_only,
        .capability_query = grant.audit_visibility != .owner_only,
        .capability_pass = grant.reshare_policy == .grantee_allowed,
    } };
}

fn actorMayReshare(grant: workspace.ShareGrant) bool {
    return switch (grant.reshare_policy) {
        .owner_only => false,
        .admin_only => grant.can_admin,
        .grantee_allowed => true,
    };
}

fn shareGrantEscalates(actor: workspace.ShareGrant, requested: workspace.ShareGrant) bool {
    if (requested.can_read and !actor.can_read) return true;
    if (requested.can_write and !actor.can_write) return true;
    if (requested.can_admin and !actor.can_admin) return true;
    if (requested.can_export and !actor.can_export) return true;
    if (actor.expires_at_ticks != 0 and
        (requested.expires_at_ticks == 0 or requested.expires_at_ticks > actor.expires_at_ticks))
    {
        return true;
    }
    if (resharePolicyRank(requested.reshare_policy) > resharePolicyRank(actor.reshare_policy)) return true;
    if (auditVisibilityRank(requested.audit_visibility) > auditVisibilityRank(actor.audit_visibility)) return true;
    return false;
}

fn resharePolicyRank(policy: workspace.ResharePolicy) u8 {
    return switch (policy) {
        .owner_only => 0,
        .admin_only => 1,
        .grantee_allowed => 2,
    };
}

fn auditVisibilityRank(visibility: workspace.AuditVisibility) u8 {
    return switch (visibility) {
        .owner_only => 0,
        .shared_participants => 1,
        .organization_policy => 2,
    };
}

fn shareAuditGeneration(record: *const workspace.WorkspaceRecord, principal_id: principal.PrincipalId) u32 {
    for (record.share_table.share_grants[0..record.share_table.share_grant_count], 0..) |grant, index| {
        if (grant.principal_id.eql(principal_id)) return @intCast(index + 1);
    }
    return @intCast(record.share_table.share_grant_count + 1);
}
