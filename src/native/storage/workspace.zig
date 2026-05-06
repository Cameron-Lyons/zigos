const std = @import("std");
const binary_cursor = @import("../core/binary_cursor.zig");
const id_index = @import("../core/id_index.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_WORKSPACES: usize = 8;
pub const MAX_WORKSPACE_ENTRIES: usize = 96;
pub const MAX_WORKSPACE_ENTRY_MUTATIONS: usize = MAX_WORKSPACE_ENTRIES * 2;
pub const MAX_SNAPSHOTS: usize = 16;
pub const MAX_RECOVERABLE_DELETES: usize = 24;
pub const MAX_ENTRY_PATH_BYTES: usize = 96;
pub const MAX_SHARE_GRANTS: usize = 8;
const WORKSPACE_INDEX_CAPACITY: usize = MAX_WORKSPACES * 2;
const SNAPSHOT_INDEX_CAPACITY: usize = MAX_SNAPSHOTS * 2;
const ENTRY_INDEX_CAPACITY: usize = MAX_WORKSPACE_ENTRIES * 2;

pub const Entry = struct {
    path_len: usize = 0,
    path: [MAX_ENTRY_PATH_BYTES]u8 = [_]u8{0} ** MAX_ENTRY_PATH_BYTES,
    object_id: ids.ObjectId = ids.ObjectId.zero,
    version_id: ids.VersionId = ids.VersionId.zero,
    object_type: object_store.ObjectType = .blob,

    pub fn init(path: []const u8, object_id: ids.ObjectId, version_id: ids.VersionId, object_type: object_store.ObjectType) Error!Entry {
        var entry = Entry{
            .object_id = object_id,
            .version_id = version_id,
            .object_type = object_type,
        };
        entry.path_len = native_util.copyTextExact(&entry.path, path) catch return error.PathTooLong;
        return entry;
    }

    pub fn pathSlice(self: *const Entry) []const u8 {
        return self.path[0..@min(self.path_len, self.path.len)];
    }

    pub fn pathHash(self: *const Entry) u64 {
        return native_util.fnv1a64(self.pathSlice());
    }
};

pub const EntryMutation = struct {
    generation: u32 = 0,
    entry: Entry = .{},
};

pub const CreateRequest = struct {
    owner: principal.PrincipalId,
    label: []const u8,
};

pub const ShareNetworkScope = enum(u8) {
    local_only,
    trusted_overlay,
    relay_assisted,
    unrestricted,
};

pub const ResharePolicy = enum(u8) {
    owner_only,
    admin_only,
    grantee_allowed,
};

pub const AuditVisibility = enum(u8) {
    owner_only,
    shared_participants,
    organization_policy,
};

pub const ShareGrant = struct {
    principal_id: principal.PrincipalId,
    can_read: bool = true,
    can_write: bool = false,
    can_admin: bool = false,
    can_export: bool = false,
    expires_at_ticks: u64 = 0,
    network_scope: ShareNetworkScope = .local_only,
    reshare_policy: ResharePolicy = .owner_only,
    audit_visibility: AuditVisibility = .owner_only,

    pub fn isActive(self: ShareGrant, now_ticks: u64) bool {
        return self.expires_at_ticks == 0 or now_ticks <= self.expires_at_ticks;
    }

    pub fn allowsNetworkScope(self: ShareGrant, requested: ShareNetworkScope) bool {
        return shareNetworkScopeRank(requested) <= shareNetworkScopeRank(self.network_scope);
    }
};

pub const ShareRequest = ShareGrant;

pub const AccessRequest = struct {
    principal_id: principal.PrincipalId,
    wants_write: bool = false,
    wants_export: bool = false,
    wants_admin: bool = false,
    network_scope: ShareNetworkScope = .local_only,
    now_ticks: u64 = 0,
};

pub const SnapshotRecord = struct {
    id: ids.SnapshotId,
    workspace_id: ids.WorkspaceId,
    generation: u32,
    label_len: usize,
    label: [48]u8,
    signature: manifest.Signature = .{},
    entry_count: usize,
    entries: [MAX_WORKSPACE_ENTRIES]Entry,

    pub fn labelSlice(self: *const SnapshotRecord) []const u8 {
        return self.label[0..@min(self.label_len, self.label.len)];
    }

    pub fn signerSlice(self: *const SnapshotRecord) []const u8 {
        return self.signature.signer;
    }
};

pub const ExportPackage = struct {
    workspace_id: ids.WorkspaceId,
    snapshot_id: ids.SnapshotId,
    generation: u32,
    label_len: usize,
    label: [48]u8,
    signature: manifest.Signature = .{},
    signature_format_len: usize = 0,
    signature_format_storage: [16]u8 = [_]u8{0} ** 16,
    signature_signer_len: usize = 0,
    signature_signer_storage: [48]u8 = [_]u8{0} ** 48,
    entry_count: usize,
    entries: [MAX_WORKSPACE_ENTRIES]Entry,

    pub fn labelSlice(self: *const ExportPackage) []const u8 {
        return self.label[0..@min(self.label_len, self.label.len)];
    }

    pub fn signerSlice(self: *const ExportPackage) []const u8 {
        return exportPackageSignature(self).signer;
    }
};

pub const WorkspaceRecord = struct {
    id: ids.WorkspaceId,
    owner: principal.PrincipalId,
    label_len: usize,
    label: [48]u8,
    generation: u32,
    entry_count: usize,
    entries: [MAX_WORKSPACE_ENTRIES]Entry,
    entry_index_slots: [ENTRY_INDEX_CAPACITY]EntryIndexSlot,
    entry_mutation_count: usize,
    entry_mutations: [MAX_WORKSPACE_ENTRY_MUTATIONS]EntryMutation,
    share_grant_count: usize,
    share_grants: [MAX_SHARE_GRANTS]ShareGrant,
    transaction_open: bool,
    staged_entry_count: usize,
    staged_entries: [MAX_WORKSPACE_ENTRIES]Entry,
    staged_entry_index_slots: [ENTRY_INDEX_CAPACITY]EntryIndexSlot,
    staged_effective_entry_count: usize,
    deleted_count: usize,
    deleted_entries: [MAX_RECOVERABLE_DELETES]Entry,

    pub fn labelSlice(self: *const WorkspaceRecord) []const u8 {
        return self.label[0..@min(self.label_len, self.label.len)];
    }
};

pub const Error = error{
    DuplicatePath,
    EntryNotFound,
    EntryTableFull,
    NoActiveTransaction,
    PathTooLong,
    ShareTableFull,
    SnapshotNotFound,
    SnapshotTableFull,
    TransactionAlreadyOpen,
    InvalidSignature,
    LabelTooLong,
    SignatureFormatTooLong,
    SignatureSignerTooLong,
    UnsignedExport,
    UnsignedSnapshot,
    WorkspaceNotFound,
    WorkspaceTableFull,
};

const WorkspaceSlot = struct {
    in_use: bool = false,
    workspace: WorkspaceRecord = zeroWorkspace(),
};

const SnapshotSlot = struct {
    in_use: bool = false,
    snapshot: SnapshotRecord = zeroSnapshot(),
};

const WorkspaceLookup = struct {
    owner: principal.PrincipalId,
    label: []const u8,
};

const SnapshotLookup = struct {
    workspace_id: ids.WorkspaceId,
    label: []const u8,
};

const EntryIndexSlot = struct {
    state: id_index.State = .empty,
    path_hash: u64 = 0,
    slot_index: usize = 0,
};

fn workspaceSlotMatchesOwnerLabel(context: WorkspaceLookup, slot: *const WorkspaceSlot) bool {
    return slot.workspace.owner.eql(context.owner) and
        std.mem.eql(u8, slot.workspace.labelSlice(), context.label);
}

fn workspaceSlotMatchesLabel(label: []const u8, slot: *const WorkspaceSlot) bool {
    return std.mem.eql(u8, slot.workspace.labelSlice(), label);
}

fn workspaceSlotId(slot: *const WorkspaceSlot) ids.WorkspaceId {
    return slot.workspace.id;
}

fn snapshotSlotMatchesWorkspaceLabel(context: SnapshotLookup, slot: *const SnapshotSlot) bool {
    return slot.snapshot.workspace_id.eql(context.workspace_id) and
        std.mem.eql(u8, slot.snapshot.labelSlice(), context.label);
}

fn snapshotSlotId(slot: *const SnapshotSlot) ids.SnapshotId {
    return slot.snapshot.id;
}

const WorkspaceArena = indexed_arena.IndexedArenaWithKey(ids.WorkspaceId, WorkspaceSlot, MAX_WORKSPACES, WORKSPACE_INDEX_CAPACITY, workspaceSlotId);
const SnapshotArena = indexed_arena.IndexedArenaWithKey(ids.SnapshotId, SnapshotSlot, MAX_SNAPSHOTS, SNAPSHOT_INDEX_CAPACITY, snapshotSlotId);

pub const Directory = struct {
    next_workspace_id: u64 = 1,
    next_snapshot_id: u64 = 1,
    workspaces: WorkspaceArena = WorkspaceArena.init(),
    snapshots: SnapshotArena = SnapshotArena.init(),

    pub fn init() Directory {
        return .{};
    }

    pub fn reset(self: *Directory) void {
        self.next_workspace_id = 1;
        self.next_snapshot_id = 1;
        self.workspaces.reset();
        self.snapshots.reset();
    }

    pub fn rebuildIndexes(self: *Directory) void {
        self.workspaces.rebuildPrimaryIndex();
        self.snapshots.rebuildPrimaryIndex();

        for (&self.workspaces.slots) |*slot| {
            if (!slot.in_use) continue;
            rebuildWorkspaceIndexes(&slot.workspace);
        }
    }

    pub fn create(self: *Directory, request: CreateRequest) Error!*WorkspaceRecord {
        return self.createRef(&request);
    }

    pub fn createRef(self: *Directory, request: *const CreateRequest) Error!*WorkspaceRecord {
        var label: [48]u8 = [_]u8{0} ** 48;
        const label_len = native_util.copyTextExact(&label, request.label) catch return error.LabelTooLong;
        const workspace_id = ids.workspace(self.next_workspace_id);
        const slot = self.workspaces.reserve(workspace_id) orelse return error.WorkspaceTableFull;
        self.next_workspace_id += 1;
        slot.workspace = zeroWorkspace();
        slot.workspace.id = workspace_id;
        slot.workspace.owner = request.owner;
        slot.workspace.label = label;
        slot.workspace.label_len = label_len;
        return &slot.workspace;
    }

    pub fn find(self: *Directory, workspace_id: ids.WorkspaceId) ?*WorkspaceRecord {
        const slot = self.workspaces.get(workspace_id) orelse return null;
        return &slot.workspace;
    }

    pub fn findConst(self: *const Directory, workspace_id: ids.WorkspaceId) ?*const WorkspaceRecord {
        return self.lookupConst(workspace_id);
    }

    pub fn findOwned(self: *Directory, owner: principal.PrincipalId, label: []const u8) ?*WorkspaceRecord {
        const slot = self.workspaces.findMatching(WorkspaceLookup{
            .owner = owner,
            .label = label,
        }, workspaceSlotMatchesOwnerLabel) orelse return null;
        return &slot.workspace;
    }

    pub fn findOwnedConst(self: *const Directory, owner: principal.PrincipalId, label: []const u8) ?*const WorkspaceRecord {
        const slot = self.workspaces.findConstMatching(WorkspaceLookup{
            .owner = owner,
            .label = label,
        }, workspaceSlotMatchesOwnerLabel) orelse return null;
        return &slot.workspace;
    }

    pub fn findByLabel(self: *Directory, label: []const u8) ?*WorkspaceRecord {
        const slot = self.workspaces.findMatching(label, workspaceSlotMatchesLabel) orelse return null;
        return &slot.workspace;
    }

    pub fn findSnapshotByLabel(self: *Directory, workspace_id: ids.WorkspaceId, label: []const u8) ?*SnapshotRecord {
        const slot = self.snapshots.findMatching(SnapshotLookup{
            .workspace_id = workspace_id,
            .label = label,
        }, snapshotSlotMatchesWorkspaceLabel) orelse return null;
        return &slot.snapshot;
    }

    pub fn findSnapshotByLabelConst(self: *const Directory, workspace_id: ids.WorkspaceId, label: []const u8) ?*const SnapshotRecord {
        const slot = self.snapshots.findConstMatching(SnapshotLookup{
            .workspace_id = workspace_id,
            .label = label,
        }, snapshotSlotMatchesWorkspaceLabel) orelse return null;
        return &slot.snapshot;
    }

    pub fn beginTransaction(self: *Directory, workspace_id: ids.WorkspaceId) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (workspace.transaction_open) return error.TransactionAlreadyOpen;
        workspace.transaction_open = true;
        workspace.staged_entry_count = 0;
        workspace.staged_effective_entry_count = workspace.entry_count;
        workspace.staged_entry_index_slots = emptyEntryIndexTable();
        clearEntries(&workspace.staged_entries);
    }

    pub fn stagePut(
        self: *Directory,
        workspace_id: ids.WorkspaceId,
        path: []const u8,
        object_id: ids.ObjectId,
        version_id: ids.VersionId,
        object_type: object_store.ObjectType,
    ) Error!void {
        if (path.len > MAX_ENTRY_PATH_BYTES) return error.PathTooLong;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.transaction_open) return error.NoActiveTransaction;

        if (findStagedEntryIndex(workspace, path)) |index| {
            if (isDeleteTombstone(workspace.staged_entries[index])) {
                workspace.staged_effective_entry_count += 1;
            }
            workspace.staged_entries[index] = try Entry.init(path, object_id, version_id, object_type);
            return;
        }
        if (findWorkspaceEntryIndex(workspace, path) == null) {
            if (workspace.staged_effective_entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;
            workspace.staged_effective_entry_count += 1;
        }
        if (workspace.staged_entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;

        try insertSortedEntry(&workspace.staged_entries, &workspace.staged_entry_count, try Entry.init(path, object_id, version_id, object_type));
    }

    pub fn stageDelete(self: *Directory, workspace_id: ids.WorkspaceId, path: []const u8) Error!void {
        if (path.len > MAX_ENTRY_PATH_BYTES) return error.PathTooLong;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.transaction_open) return error.NoActiveTransaction;
        const base_exists = findWorkspaceEntryIndex(workspace, path) != null;

        if (findStagedEntryIndex(workspace, path)) |index| {
            if (isDeleteTombstone(workspace.staged_entries[index])) return error.EntryNotFound;

            workspace.staged_effective_entry_count -= 1;
            if (base_exists) {
                workspace.staged_entries[index] = try deleteTombstone(path);
            } else {
                removeEntry(&workspace.staged_entries, &workspace.staged_entry_count, index);
                rebuildStagedEntryIndex(workspace);
            }
            return;
        }

        if (!base_exists) return error.EntryNotFound;
        if (workspace.staged_entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;

        try insertSortedEntry(&workspace.staged_entries, &workspace.staged_entry_count, try deleteTombstone(path));
        workspace.staged_effective_entry_count -= 1;
    }

    pub fn commit(self: *Directory, workspace_id: ids.WorkspaceId, tick: u64) Error!u32 {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.transaction_open) return error.NoActiveTransaction;

        try applyTransactionDelta(workspace);
        clearTransactionState(workspace);
        self.markWorkspaceDirty(workspace_id);
        return workspace.generation;
    }

    pub fn share(self: *Directory, workspace_id: ids.WorkspaceId, request: ShareRequest) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        for (workspace.share_grants[0..workspace.share_grant_count]) |*grant| {
            if (!grant.principal_id.eql(request.principal_id)) continue;
            grant.* = request;
            self.markWorkspaceDirty(workspace_id);
            return;
        }
        if (workspace.share_grant_count >= MAX_SHARE_GRANTS) return error.ShareTableFull;
        workspace.share_grants[workspace.share_grant_count] = request;
        workspace.share_grant_count += 1;
        self.markWorkspaceDirty(workspace_id);
    }

    pub fn findShareGrant(
        self: *const Directory,
        workspace_id: ids.WorkspaceId,
        principal_id: principal.PrincipalId,
    ) ?ShareGrant {
        const workspace = self.lookupConst(workspace_id) orelse return null;
        for (workspace.share_grants[0..workspace.share_grant_count]) |grant| {
            if (grant.principal_id.eql(principal_id)) return grant;
        }
        return null;
    }

    pub fn hasAccess(self: *const Directory, workspace_id: ids.WorkspaceId, request: AccessRequest) bool {
        const workspace = self.lookupConst(workspace_id) orelse return false;
        if (workspace.owner.eql(request.principal_id)) return true;

        const grant = self.findShareGrant(workspace_id, request.principal_id) orelse return false;
        if (!grant.isActive(request.now_ticks)) return false;
        if (!grant.allowsNetworkScope(request.network_scope)) return false;
        if (request.wants_admin and !grant.can_admin) return false;
        if (request.wants_write and !grant.can_write) return false;
        if (request.wants_export and !grant.can_export) return false;
        if (!request.wants_write and !request.wants_admin and !grant.can_read) return false;
        return true;
    }

    pub fn canReshare(
        self: *const Directory,
        workspace_id: ids.WorkspaceId,
        principal_id: principal.PrincipalId,
        network_scope: ShareNetworkScope,
        now_ticks: u64,
    ) bool {
        const workspace = self.lookupConst(workspace_id) orelse return false;
        if (workspace.owner.eql(principal_id)) return true;

        const grant = self.findShareGrant(workspace_id, principal_id) orelse return false;
        if (!grant.isActive(now_ticks)) return false;
        if (!grant.allowsNetworkScope(network_scope)) return false;
        return switch (grant.reshare_policy) {
            .owner_only => false,
            .admin_only => grant.can_admin,
            .grantee_allowed => true,
        };
    }

    pub fn resolve(self: *const Directory, workspace_id: ids.WorkspaceId, path: []const u8) Error!Entry {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        const index = findWorkspaceEntryIndex(workspace, path) orelse return error.EntryNotFound;
        return workspace.entries[index];
    }

    pub fn entries(self: *const Directory, workspace_id: ids.WorkspaceId) Error![]const Entry {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        return workspace.entries[0..workspace.entry_count];
    }

    pub fn snapshot(
        self: *Directory,
        workspace_id: ids.WorkspaceId,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) Error!*SnapshotRecord {
        if (identity.label.len == 0) return error.UnsignedSnapshot;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        var label_copy: [48]u8 = [_]u8{0} ** 48;
        const label_len = native_util.copyTextExact(&label_copy, label) catch return error.LabelTooLong;

        const snapshot_id = ids.snapshot(self.next_snapshot_id);
        var snapshot_record = zeroSnapshot();
        snapshot_record.id = snapshot_id;
        snapshot_record.workspace_id = workspace.id;
        snapshot_record.generation = workspace.generation;
        snapshot_record.label = label_copy;
        snapshot_record.label_len = label_len;
        var snapshot_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        snapshot_record.entry_count = try materializeEntriesAtGeneration(workspace, snapshot_record.generation, &snapshot_entries);
        signSnapshotRecord(&snapshot_record, snapshot_entries[0..snapshot_record.entry_count], identity) catch return error.InvalidSignature;

        const slot = self.snapshots.reserve(snapshot_id) orelse return error.SnapshotTableFull;
        self.next_snapshot_id += 1;
        slot.snapshot = snapshot_record;
        return &slot.snapshot;
    }

    pub fn restore(self: *Directory, workspace_id: ids.WorkspaceId, snapshot_id: ids.SnapshotId, tick: u64) Error!u32 {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        const snapshot_record = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;
        if (!snapshot_record.workspace_id.eql(workspace_id)) return error.SnapshotNotFound;
        var snapshot_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        const snapshot_entry_count = try materializeEntriesAtGeneration(workspace, snapshot_record.generation, &snapshot_entries);
        if (snapshot_entry_count != snapshot_record.entry_count) return error.InvalidSignature;
        if (!verifySnapshotRecord(snapshot_record, snapshot_entries[0..snapshot_entry_count])) return error.InvalidSignature;

        try replaceCurrentEntriesWith(workspace, snapshot_entries[0..snapshot_entry_count]);
        clearTransactionState(workspace);
        self.markWorkspaceDirty(workspace_id);
        return workspace.generation;
    }

    pub fn recoverDeleted(self: *Directory, workspace_id: ids.WorkspaceId, path: []const u8, tick: u64) Error!bool {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (findEntryIndex(workspace.entries[0..workspace.entry_count], path) != null) return false;

        var index = workspace.deleted_count;
        while (index > 0) {
            index -= 1;
            const entry = workspace.deleted_entries[index];
            if (!std.mem.eql(u8, entry.pathSlice(), path)) continue;
            if (workspace.entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;
            if (workspace.entry_mutation_count >= MAX_WORKSPACE_ENTRY_MUTATIONS) return error.EntryTableFull;

            workspace.generation += 1;
            try appendEntryMutation(workspace, workspace.generation, entry);
            try insertSortedEntry(&workspace.entries, &workspace.entry_count, entry);
            self.markWorkspaceDirty(workspace_id);
            return true;
        }

        return false;
    }

    pub fn exportSnapshot(
        self: *Directory,
        workspace_id: ids.WorkspaceId,
        snapshot_id: ids.SnapshotId,
        identity: signing.SignerIdentity,
    ) Error!ExportPackage {
        var package = zeroExportPackage();
        try self.exportSnapshotInto(workspace_id, snapshot_id, identity, &package);
        return package;
    }

    pub fn exportSnapshotInto(
        self: *Directory,
        workspace_id: ids.WorkspaceId,
        snapshot_id: ids.SnapshotId,
        identity: signing.SignerIdentity,
        out: *ExportPackage,
    ) Error!void {
        if (identity.label.len == 0) return error.UnsignedExport;
        const snapshot_record = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;
        if (!snapshot_record.workspace_id.eql(workspace_id)) return error.SnapshotNotFound;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        var snapshot_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        const snapshot_entry_count = try materializeEntriesAtGeneration(workspace, snapshot_record.generation, &snapshot_entries);
        if (snapshot_entry_count != snapshot_record.entry_count) return error.InvalidSignature;
        if (!verifySnapshotRecord(snapshot_record, snapshot_entries[0..snapshot_entry_count])) return error.InvalidSignature;

        out.* = zeroExportPackage();
        out.workspace_id = workspace_id;
        out.snapshot_id = snapshot_id;
        out.generation = snapshot_record.generation;
        out.entry_count = snapshot_entry_count;
        out.label_len = native_util.copyTextExact(&out.label, snapshot_record.labelSlice()) catch return error.LabelTooLong;
        copyEntries(out.entries[0..snapshot_entry_count], snapshot_entries[0..snapshot_entry_count]);
        signExportPackage(out, identity) catch return error.InvalidSignature;
    }

    pub fn importWorkspace(
        self: *Directory,
        owner: principal.PrincipalId,
        label: []const u8,
        package: ExportPackage,
        tick: u64,
    ) Error!*WorkspaceRecord {
        return self.importWorkspaceFromPackage(owner, label, &package, tick);
    }

    pub fn importWorkspaceFromPackage(
        self: *Directory,
        owner: principal.PrincipalId,
        label: []const u8,
        package: *const ExportPackage,
        tick: u64,
    ) Error!*WorkspaceRecord {
        _ = tick;
        if (!exportPackageSignature(package).isPresent()) return error.UnsignedExport;
        if (package.entry_count > MAX_WORKSPACE_ENTRIES) return error.InvalidSignature;
        if (!verifyExportPackage(package)) return error.InvalidSignature;
        const workspace = try self.create(.{
            .owner = owner,
            .label = label,
        });
        workspace.generation = package.generation;
        try seedWorkspaceEntries(workspace, package.entries[0..package.entry_count], workspace.generation);
        self.markWorkspaceDirty(workspace.id);
        return workspace;
    }

    pub fn restoreFromExportPackage(
        self: *Directory,
        workspace_id: ids.WorkspaceId,
        package: *const ExportPackage,
        tick: u64,
    ) Error!u32 {
        _ = tick;
        if (!exportPackageSignature(package).isPresent()) return error.UnsignedExport;
        if (package.entry_count > MAX_WORKSPACE_ENTRIES) return error.InvalidSignature;
        if (!verifyExportPackage(package)) return error.InvalidSignature;
        if (!package.workspace_id.eql(workspace_id)) return error.SnapshotNotFound;

        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        try replaceCurrentEntriesWith(workspace, package.entries[0..package.entry_count]);
        clearTransactionState(workspace);
        self.markWorkspaceDirty(workspace_id);
        return workspace.generation;
    }

    pub fn dirtyWorkspaceIds(self: *const Directory) []const ids.WorkspaceId {
        return self.workspaces.dirtyIds();
    }

    pub fn dirtySnapshotIds(self: *const Directory) []const ids.SnapshotId {
        return self.snapshots.dirtyIds();
    }

    pub fn clearDirty(self: *Directory) void {
        self.workspaces.clearDirty();
        self.snapshots.clearDirty();
    }

    fn lookupConst(self: *const Directory, workspace_id: ids.WorkspaceId) ?*const WorkspaceRecord {
        const slot = self.workspaces.getConst(workspace_id) orelse return null;
        return &slot.workspace;
    }

    fn findSnapshot(self: *Directory, snapshot_id: ids.SnapshotId) ?*SnapshotRecord {
        const slot = self.snapshots.get(snapshot_id) orelse return null;
        return &slot.snapshot;
    }

    fn markWorkspaceDirty(self: *Directory, workspace_id: ids.WorkspaceId) void {
        self.workspaces.markDirty(workspace_id);
    }

    fn markSnapshotDirty(self: *Directory, snapshot_id: ids.SnapshotId) void {
        self.snapshots.markDirty(snapshot_id);
    }
};

fn zeroWorkspace() WorkspaceRecord {
    return .{
        .id = ids.WorkspaceId.zero,
        .owner = .{ .kind = .service, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .generation = 0,
        .entry_count = 0,
        .entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
        .entry_index_slots = emptyEntryIndexTable(),
        .entry_mutation_count = 0,
        .entry_mutations = [_]EntryMutation{EntryMutation{}} ** MAX_WORKSPACE_ENTRY_MUTATIONS,
        .share_grant_count = 0,
        .share_grants = [_]ShareGrant{ShareGrant{
            .principal_id = .{ .kind = .service, .serial = 0 },
        }} ** MAX_SHARE_GRANTS,
        .transaction_open = false,
        .staged_entry_count = 0,
        .staged_entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
        .staged_entry_index_slots = emptyEntryIndexTable(),
        .staged_effective_entry_count = 0,
        .deleted_count = 0,
        .deleted_entries = [_]Entry{Entry{}} ** MAX_RECOVERABLE_DELETES,
    };
}

pub fn emptyWorkspaceRecord() WorkspaceRecord {
    return zeroWorkspace();
}

pub fn pathHash(path: []const u8) u64 {
    return native_util.fnv1a64(path);
}

fn shareNetworkScopeRank(scope: ShareNetworkScope) u8 {
    return switch (scope) {
        .local_only => 0,
        .trusted_overlay => 1,
        .relay_assisted => 2,
        .unrestricted => 3,
    };
}

fn zeroSnapshot() SnapshotRecord {
    return .{
        .id = ids.SnapshotId.zero,
        .workspace_id = ids.WorkspaceId.zero,
        .generation = 0,
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .signature = .{},
        .entry_count = 0,
        .entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
    };
}

pub fn emptySnapshotRecord() SnapshotRecord {
    return zeroSnapshot();
}

fn zeroExportPackage() ExportPackage {
    return .{
        .workspace_id = ids.WorkspaceId.zero,
        .snapshot_id = ids.SnapshotId.zero,
        .generation = 0,
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .signature = .{},
        .signature_format_len = 0,
        .signature_format_storage = [_]u8{0} ** 16,
        .signature_signer_len = 0,
        .signature_signer_storage = [_]u8{0} ** 48,
        .entry_count = 0,
        .entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
    };
}

pub fn emptyExportPackage() ExportPackage {
    return zeroExportPackage();
}

fn emptyEntryIndexTable() [ENTRY_INDEX_CAPACITY]EntryIndexSlot {
    return [_]EntryIndexSlot{EntryIndexSlot{}} ** ENTRY_INDEX_CAPACITY;
}

fn copyEntries(dest: []Entry, src: []const Entry) void {
    for (src, 0..) |entry, index| {
        dest[index] = entry;
    }
}

fn clearEntries(entries: *[MAX_WORKSPACE_ENTRIES]Entry) void {
    for (entries) |*entry| {
        entry.* = Entry{};
    }
}

fn signSnapshotRecord(snapshot: *SnapshotRecord, entries: []const Entry, identity: signing.SignerIdentity) !void {
    var message_buffer: [4096]u8 = undefined;
    const message = try snapshotMessage(
        &message_buffer,
        "snapshot",
        snapshot.workspace_id,
        snapshot.generation,
        snapshot.labelSlice(),
        entries,
    );
    snapshot.signature = try signing.sign(identity, message);
}

fn verifySnapshotRecord(snapshot: *const SnapshotRecord, entries: []const Entry) bool {
    if (!snapshot.signature.isPresent()) return false;
    var message_buffer: [4096]u8 = undefined;
    const message = snapshotMessage(
        &message_buffer,
        "snapshot",
        snapshot.workspace_id,
        snapshot.generation,
        snapshot.labelSlice(),
        entries,
    ) catch return false;
    return signing.verify(snapshot.signature, message);
}

fn signExportPackage(package: *ExportPackage, identity: signing.SignerIdentity) !void {
    var message_buffer: [4096]u8 = undefined;
    const message = try snapshotMessage(
        &message_buffer,
        "export",
        package.workspace_id,
        package.generation,
        package.labelSlice(),
        package.entries[0..package.entry_count],
    );
    package.signature = try signing.sign(identity, message);
    try persistExportPackageSignature(package);
}

fn verifyExportPackage(package: *const ExportPackage) bool {
    const signature = exportPackageSignature(package);
    if (!signature.isPresent()) return false;
    var message_buffer: [4096]u8 = undefined;
    const message = snapshotMessage(
        &message_buffer,
        "export",
        package.workspace_id,
        package.generation,
        package.labelSlice(),
        package.entries[0..package.entry_count],
    ) catch return false;
    return signing.verify(signature, message);
}

fn persistExportPackageSignature(package: *ExportPackage) Error!void {
    package.signature_format_len = native_util.copyTextExact(&package.signature_format_storage, package.signature.format) catch return error.SignatureFormatTooLong;
    package.signature_signer_len = native_util.copyTextExact(&package.signature_signer_storage, package.signature.signer) catch return error.SignatureSignerTooLong;
    package.signature.format = package.signature_format_storage[0..package.signature_format_len];
    package.signature.signer = package.signature_signer_storage[0..package.signature_signer_len];
}

fn exportPackageSignature(package: *const ExportPackage) manifest.Signature {
    var signature = package.signature;
    if (package.signature_format_len != 0) {
        signature.format = package.signature_format_storage[0..package.signature_format_len];
    }
    if (package.signature_signer_len != 0) {
        signature.signer = package.signature_signer_storage[0..package.signature_signer_len];
    }
    return signature;
}

fn snapshotMessage(
    buffer: []u8,
    tag: []const u8,
    workspace_id: ids.WorkspaceId,
    generation: u32,
    label: []const u8,
    entries: []const Entry,
) error{NoSpaceLeft}![]const u8 {
    var writer = BinaryWriter{ .buffer = buffer };
    try writer.writeBytes("zigos.workspace.snapshot.v2");
    try writeLengthPrefixed(&writer, tag);
    try writer.writeU64(workspace_id.raw());
    try writer.writeU32(generation);
    try writeLengthPrefixed(&writer, label);
    try writer.writeU16(@intCast(entries.len));
    for (entries) |entry| {
        try writeLengthPrefixed(&writer, entry.pathSlice());
        try writer.writeU64(entry.object_id.raw());
        try writer.writeU64(entry.version_id.raw());
        try writer.writeByte(@intFromEnum(entry.object_type));
    }
    return buffer[0..writer.offset];
}

const BinaryWriter = binary_cursor.Writer(error{NoSpaceLeft}, error.NoSpaceLeft);

fn writeLengthPrefixed(writer: *BinaryWriter, bytes: []const u8) error{NoSpaceLeft}!void {
    if (bytes.len > std.math.maxInt(u16)) return error.NoSpaceLeft;
    try writer.writeU16(@intCast(bytes.len));
    try writer.writeBytes(bytes);
}

fn rebuildWorkspaceIndexes(workspace: *WorkspaceRecord) void {
    rebuildWorkspaceEntryIndex(workspace);
    rebuildStagedEntryIndex(workspace);
}

fn rebuildWorkspaceEntryIndex(workspace: *WorkspaceRecord) void {
    sortEntries(workspace.entries[0..workspace.entry_count]);
    workspace.entry_index_slots = emptyEntryIndexTable();
}

fn rebuildStagedEntryIndex(workspace: *WorkspaceRecord) void {
    sortEntries(workspace.staged_entries[0..workspace.staged_entry_count]);
    workspace.staged_entry_index_slots = emptyEntryIndexTable();
}

fn findWorkspaceEntryIndex(workspace: *const WorkspaceRecord, path: []const u8) ?usize {
    return findEntryIndex(workspace.entries[0..workspace.entry_count], path);
}

fn findStagedEntryIndex(workspace: *const WorkspaceRecord, path: []const u8) ?usize {
    return findEntryIndex(workspace.staged_entries[0..workspace.staged_entry_count], path);
}

fn deleteTombstone(path: []const u8) Error!Entry {
    return Entry.init(path, ids.ObjectId.zero, ids.VersionId.zero, .blob);
}

fn isDeleteTombstone(entry: Entry) bool {
    return entry.object_id.isZero() and entry.version_id.isZero();
}

fn findEntryIndex(entries: []const Entry, path: []const u8) ?usize {
    const index = lowerBoundEntry(entries, path);
    if (index < entries.len and compareEntryPath(entries[index].pathSlice(), path) == .eq) return index;
    return null;
}

fn removeEntry(entries: *[MAX_WORKSPACE_ENTRIES]Entry, count: *usize, index: usize) void {
    var cursor = index;
    while (cursor + 1 < count.*) : (cursor += 1) {
        entries[cursor] = entries[cursor + 1];
    }
    count.* -= 1;
    entries[count.*] = Entry{};
}

fn insertSortedEntry(entries: *[MAX_WORKSPACE_ENTRIES]Entry, count: *usize, entry: Entry) Error!void {
    if (count.* >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;
    const insert_index = lowerBoundEntry(entries[0..count.*], entry.pathSlice());
    if (insert_index < count.* and compareEntryPath(entries[insert_index].pathSlice(), entry.pathSlice()) == .eq) {
        entries[insert_index] = entry;
        return;
    }

    var cursor = count.*;
    while (cursor > insert_index) : (cursor -= 1) {
        entries[cursor] = entries[cursor - 1];
    }
    entries[insert_index] = entry;
    count.* += 1;
}

fn sortEntries(entries: []Entry) void {
    std.sort.insertion(Entry, entries, {}, entryLessThan);
}

fn entryLessThan(_: void, left: Entry, right: Entry) bool {
    return compareEntryPath(left.pathSlice(), right.pathSlice()) == .lt;
}

fn lowerBoundEntry(entries: []const Entry, path: []const u8) usize {
    var left: usize = 0;
    var right: usize = entries.len;
    while (left < right) {
        const mid = left + (right - left) / 2;
        if (compareEntryPath(entries[mid].pathSlice(), path) == .lt) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return left;
}

fn compareEntryPath(left: []const u8, right: []const u8) std.math.Order {
    return std.mem.order(u8, left, right);
}

fn entryContentEql(left: Entry, right: Entry) bool {
    return left.object_id.eql(right.object_id) and
        left.version_id.eql(right.version_id) and
        left.object_type == right.object_type;
}

fn appendDeleted(workspace: *WorkspaceRecord, entry: Entry) void {
    if (workspace.deleted_count < MAX_RECOVERABLE_DELETES) {
        workspace.deleted_entries[workspace.deleted_count] = entry;
        workspace.deleted_count += 1;
        return;
    }

    var index: usize = 1;
    while (index < MAX_RECOVERABLE_DELETES) : (index += 1) {
        workspace.deleted_entries[index - 1] = workspace.deleted_entries[index];
    }
    workspace.deleted_entries[MAX_RECOVERABLE_DELETES - 1] = entry;
}

fn appendEntryMutation(workspace: *WorkspaceRecord, generation: u32, entry: Entry) Error!void {
    if (workspace.entry_mutation_count >= MAX_WORKSPACE_ENTRY_MUTATIONS) return error.EntryTableFull;
    workspace.entry_mutations[workspace.entry_mutation_count] = .{
        .generation = generation,
        .entry = entry,
    };
    workspace.entry_mutation_count += 1;
}

fn seedWorkspaceEntries(workspace: *WorkspaceRecord, source_entries: []const Entry, generation: u32) Error!void {
    workspace.entry_count = 0;
    workspace.entry_mutation_count = 0;
    workspace.entry_index_slots = emptyEntryIndexTable();
    clearEntries(&workspace.entries);
    for (&workspace.entry_mutations) |*mutation| {
        mutation.* = EntryMutation{};
    }

    for (source_entries) |entry| {
        if (isDeleteTombstone(entry)) continue;
        try insertSortedEntry(&workspace.entries, &workspace.entry_count, entry);
        try appendEntryMutation(workspace, generation, entry);
    }
}

fn materializeEntriesAtGeneration(
    workspace: *const WorkspaceRecord,
    generation: u32,
    out: *[MAX_WORKSPACE_ENTRIES]Entry,
) Error!usize {
    clearEntries(out);
    var out_count: usize = 0;
    for (workspace.entry_mutations[0..workspace.entry_mutation_count]) |mutation| {
        if (mutation.generation > generation) continue;

        if (isDeleteTombstone(mutation.entry)) {
            const index = findEntryIndex(out[0..out_count], mutation.entry.pathSlice()) orelse return error.EntryNotFound;
            removeEntry(out, &out_count, index);
            continue;
        }

        try insertSortedEntry(out, &out_count, mutation.entry);
    }
    return out_count;
}

fn replaceCurrentEntriesWith(workspace: *WorkspaceRecord, source_entries: []const Entry) Error!void {
    var target_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
    var target_count: usize = 0;
    for (source_entries) |entry| {
        if (isDeleteTombstone(entry)) continue;
        try insertSortedEntry(&target_entries, &target_count, entry);
    }

    var mutation_count_needed: usize = 0;
    var current_index: usize = 0;
    var target_index: usize = 0;
    while (current_index < workspace.entry_count or target_index < target_count) {
        if (current_index >= workspace.entry_count) {
            mutation_count_needed += 1;
            target_index += 1;
            continue;
        }
        if (target_index >= target_count) {
            mutation_count_needed += 1;
            current_index += 1;
            continue;
        }

        switch (compareEntryPath(workspace.entries[current_index].pathSlice(), target_entries[target_index].pathSlice())) {
            .lt => {
                mutation_count_needed += 1;
                current_index += 1;
            },
            .gt => {
                mutation_count_needed += 1;
                target_index += 1;
            },
            .eq => {
                if (!entryContentEql(workspace.entries[current_index], target_entries[target_index])) {
                    mutation_count_needed += 1;
                }
                current_index += 1;
                target_index += 1;
            },
        }
    }
    if (workspace.entry_mutation_count + mutation_count_needed > MAX_WORKSPACE_ENTRY_MUTATIONS) return error.EntryTableFull;

    const next_generation = workspace.generation + 1;
    current_index = 0;
    target_index = 0;
    while (current_index < workspace.entry_count or target_index < target_count) {
        if (current_index >= workspace.entry_count) {
            const target_entry = target_entries[target_index];
            try insertSortedEntry(&workspace.entries, &workspace.entry_count, target_entry);
            try appendEntryMutation(workspace, next_generation, target_entry);
            current_index += 1;
            target_index += 1;
            continue;
        }
        if (target_index >= target_count) {
            const deleted_entry = workspace.entries[current_index];
            appendDeleted(workspace, deleted_entry);
            try appendEntryMutation(workspace, next_generation, try deleteTombstone(deleted_entry.pathSlice()));
            removeEntry(&workspace.entries, &workspace.entry_count, current_index);
            continue;
        }

        const current_entry = workspace.entries[current_index];
        const target_entry = target_entries[target_index];
        switch (compareEntryPath(current_entry.pathSlice(), target_entry.pathSlice())) {
            .lt => {
                appendDeleted(workspace, current_entry);
                try appendEntryMutation(workspace, next_generation, try deleteTombstone(current_entry.pathSlice()));
                removeEntry(&workspace.entries, &workspace.entry_count, current_index);
            },
            .gt => {
                try insertSortedEntry(&workspace.entries, &workspace.entry_count, target_entry);
                try appendEntryMutation(workspace, next_generation, target_entry);
                current_index += 1;
                target_index += 1;
            },
            .eq => {
                if (!entryContentEql(current_entry, target_entry)) {
                    workspace.entries[current_index] = target_entry;
                    try appendEntryMutation(workspace, next_generation, target_entry);
                }
                current_index += 1;
                target_index += 1;
            },
        }
    }
    workspace.generation = next_generation;
    rebuildWorkspaceEntryIndex(workspace);
}

fn applyTransactionDelta(workspace: *WorkspaceRecord) Error!void {
    if (workspace.entry_mutation_count + workspace.staged_entry_count > MAX_WORKSPACE_ENTRY_MUTATIONS) return error.EntryTableFull;
    const next_generation = workspace.generation + 1;
    for (workspace.staged_entries[0..workspace.staged_entry_count]) |staged_entry| {
        if (isDeleteTombstone(staged_entry)) {
            const existing_index = findWorkspaceEntryIndex(workspace, staged_entry.pathSlice()) orelse return error.EntryNotFound;
            appendDeleted(workspace, workspace.entries[existing_index]);
            removeEntry(&workspace.entries, &workspace.entry_count, existing_index);
            try appendEntryMutation(workspace, next_generation, staged_entry);
            continue;
        }

        if (findWorkspaceEntryIndex(workspace, staged_entry.pathSlice())) |existing_index| {
            workspace.entries[existing_index] = staged_entry;
        } else {
            try insertSortedEntry(&workspace.entries, &workspace.entry_count, staged_entry);
        }
        try appendEntryMutation(workspace, next_generation, staged_entry);
    }
    workspace.generation = next_generation;
    rebuildWorkspaceEntryIndex(workspace);
}

fn clearTransactionState(workspace: *WorkspaceRecord) void {
    workspace.transaction_open = false;
    workspace.staged_entry_count = 0;
    workspace.staged_effective_entry_count = 0;
    workspace.staged_entry_index_slots = emptyEntryIndexTable();
    clearEntries(&workspace.staged_entries);
}

test "workspace transactions, snapshot restore, delete recovery, and signed export import work" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x61} ** 32,
    };
    const first = try store.putVersion(.{
        .preferred_object_id = ids.object(900),
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello", 10),
    });
    const second = try store.putVersion(.{
        .preferred_object_id = ids.object(900),
        .object_type = .document,
        .payload = "hello, world",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello, world", 11),
        .parent_version_id = first.version_id,
    });

    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/notes.md", first.object_id, first.version_id, .document);
    try std.testing.expectEqual(@as(u32, 1), try directory.commit(workspace.id, 20));

    const snapshot_identity = signing.SignerIdentity{
        .label = "zigos-workspace-key",
        .seed = [_]u8{0x62} ** 32,
    };
    const export_identity = signing.SignerIdentity{
        .label = "zigos-export-key",
        .seed = [_]u8{0x63} ** 32,
    };
    const baseline = try directory.snapshot(workspace.id, "baseline", snapshot_identity);
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/notes.md", second.object_id, second.version_id, .document);
    try std.testing.expectEqual(@as(u32, 2), try directory.commit(workspace.id, 21));
    try std.testing.expectEqual(second.version_id, (try directory.resolve(workspace.id, "documents/notes.md")).version_id);

    try std.testing.expectEqual(@as(u32, 3), try directory.restore(workspace.id, baseline.id, 22));
    try std.testing.expectEqual(first.version_id, (try directory.resolve(workspace.id, "documents/notes.md")).version_id);

    try directory.beginTransaction(workspace.id);
    try directory.stageDelete(workspace.id, "documents/notes.md");
    try std.testing.expectEqual(@as(u32, 4), try directory.commit(workspace.id, 23));
    try std.testing.expectError(error.EntryNotFound, directory.resolve(workspace.id, "documents/notes.md"));
    try std.testing.expect(try directory.recoverDeleted(workspace.id, "documents/notes.md", 24));
    try std.testing.expectEqual(first.version_id, (try directory.resolve(workspace.id, "documents/notes.md")).version_id);

    const package = try directory.exportSnapshot(workspace.id, baseline.id, export_identity);
    const imported = try directory.importWorkspace(.{ .kind = .service, .serial = 9 }, "imported-notes", package, 25);
    try std.testing.expectEqualStrings("imported-notes", imported.labelSlice());
    try std.testing.expectEqual(first.version_id, (try directory.resolve(imported.id, "documents/notes.md")).version_id);
}

test "workspace paths reject overlong values instead of truncating" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 44 },
        .label = "notes",
    });

    try std.testing.expectError(
        error.PathTooLong,
        directory.stagePut(
            workspace.id,
            "documents/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.md",
            ids.object(10),
            ids.version(20),
            .document,
        ),
    );
}

test "workspace can restore the original workspace from a signed export package" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x64} ** 32,
    };
    const export_signer = signing.SignerIdentity{
        .label = "zigos-export-key",
        .seed = [_]u8{0x65} ** 32,
    };

    const first = try store.putVersion(.{
        .preferred_object_id = ids.object(901),
        .object_type = .document,
        .payload = "baseline",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "baseline", 30),
    });
    const second = try store.putVersion(.{
        .preferred_object_id = ids.object(901),
        .object_type = .document,
        .payload = "drifted",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "drifted", 31),
        .parent_version_id = first.version_id,
    });

    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .label = "notes-restore",
    });
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try directory.commit(workspace.id, 32);

    const snapshot = try directory.snapshot(workspace.id, "baseline", signer);
    const package = try directory.exportSnapshot(workspace.id, snapshot.id, export_signer);

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/notes.md", second.object_id, second.version_id, .document);
    _ = try directory.commit(workspace.id, 33);
    try std.testing.expectEqual(second.version_id, (try directory.resolve(workspace.id, "documents/notes.md")).version_id);

    _ = try directory.restoreFromExportPackage(workspace.id, &package, 34);
    try std.testing.expectEqual(first.version_id, (try directory.resolve(workspace.id, "documents/notes.md")).version_id);
}

test "workspace overlay transactions can cancel staged additions before commit" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 4 },
        .label = "overlay-cancel",
    });

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/draft.md", ids.object(10), ids.version(20), .document);
    try directory.stageDelete(workspace.id, "documents/draft.md");
    try std.testing.expectEqual(@as(u32, 1), try directory.commit(workspace.id, 40));
    try std.testing.expectEqual(@as(usize, 0), (try directory.entries(workspace.id)).len);
    try std.testing.expectError(error.EntryNotFound, directory.resolve(workspace.id, "documents/draft.md"));
}

test "workspace commit applies multiple staged deletions with one rebuilt index" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 7 },
        .label = "multi-delete",
    });

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "a.md", ids.object(10), ids.version(100), .document);
    try directory.stagePut(workspace.id, "b.md", ids.object(11), ids.version(101), .document);
    try directory.stagePut(workspace.id, "c.md", ids.object(12), ids.version(102), .document);
    try directory.stagePut(workspace.id, "d.md", ids.object(13), ids.version(103), .document);
    _ = try directory.commit(workspace.id, 41);

    try directory.beginTransaction(workspace.id);
    try directory.stageDelete(workspace.id, "a.md");
    try directory.stageDelete(workspace.id, "b.md");
    try directory.stageDelete(workspace.id, "c.md");
    try directory.stagePut(workspace.id, "d.md", ids.object(14), ids.version(104), .document);
    try directory.stagePut(workspace.id, "e.md", ids.object(15), ids.version(105), .document);
    _ = try directory.commit(workspace.id, 42);

    const entries_after_delete = try directory.entries(workspace.id);
    try std.testing.expectEqual(@as(usize, 2), entries_after_delete.len);
    try std.testing.expectError(error.EntryNotFound, directory.resolve(workspace.id, "a.md"));
    try std.testing.expectError(error.EntryNotFound, directory.resolve(workspace.id, "b.md"));
    try std.testing.expectError(error.EntryNotFound, directory.resolve(workspace.id, "c.md"));
    try std.testing.expectEqual(ids.version(104), (try directory.resolve(workspace.id, "d.md")).version_id);
    try std.testing.expectEqual(ids.version(105), (try directory.resolve(workspace.id, "e.md")).version_id);

    const record = directory.find(workspace.id).?;
    try std.testing.expectEqual(@as(usize, 3), record.deleted_count);
}

test "workspace snapshots and exports must stay signed" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .label = "unsigned",
    });
    try std.testing.expectError(error.UnsignedSnapshot, directory.snapshot(workspace.id, "baseline", .{
        .label = "",
        .seed = [_]u8{0} ** 32,
    }));

    const package = ExportPackage{
        .workspace_id = workspace.id,
        .snapshot_id = ids.SnapshotId.zero,
        .generation = 0,
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .signature = .{},
        .entry_count = 0,
        .entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
    };
    try std.testing.expectError(error.UnsignedExport, directory.importWorkspace(.{ .kind = .service, .serial = 10 }, "import", package, 0));
}

test "export packages keep self-contained signature state across copies" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x66} ** 32,
    };
    const export_signer = signing.SignerIdentity{
        .label = "zigos-export-key",
        .seed = [_]u8{0x67} ** 32,
    };

    const first = try store.putVersion(.{
        .preferred_object_id = ids.object(902),
        .object_type = .document,
        .payload = "archived",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "archived", 35),
    });

    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 4 },
        .label = "archive-test",
    });
    try directory.beginTransaction(workspace.id);
    _ = try directory.stagePut(workspace.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try directory.commit(workspace.id, 36);

    const snapshot = try directory.snapshot(workspace.id, "baseline", signer);
    var package = try directory.exportSnapshot(workspace.id, snapshot.id, export_signer);
    const copied = package;
    package = copied;

    try std.testing.expect(exportPackageSignature(&package).isPresent());
    const imported = try directory.importWorkspace(.{ .kind = .service, .serial = 11 }, "archive-import", package, 37);
    try std.testing.expectEqual(first.version_id, (try directory.resolve(imported.id, "documents/notes.md")).version_id);
}

test "workspace sharing acts as a mutable policy container" {
    var directory = Directory.init();
    const notes = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try directory.share(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 7 },
        .can_read = true,
        .can_write = true,
        .can_admin = true,
        .can_export = true,
        .expires_at_ticks = 40,
        .network_scope = .trusted_overlay,
        .reshare_policy = .admin_only,
        .audit_visibility = .shared_participants,
    });
    const initial = directory.findShareGrant(notes.id, .{ .kind = .app, .serial = 7 }).?;
    try std.testing.expectEqual(ShareNetworkScope.trusted_overlay, initial.network_scope);
    try std.testing.expectEqual(ResharePolicy.admin_only, initial.reshare_policy);
    try std.testing.expectEqual(AuditVisibility.shared_participants, initial.audit_visibility);
    try std.testing.expect(directory.hasAccess(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 7 },
        .wants_write = true,
        .wants_export = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 20,
    }));
    try std.testing.expect(!directory.hasAccess(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 7 },
        .wants_write = true,
        .network_scope = .unrestricted,
        .now_ticks = 20,
    }));
    try std.testing.expect(directory.canReshare(notes.id, .{ .kind = .app, .serial = 7 }, .trusted_overlay, 20));

    try directory.share(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 7 },
        .can_read = true,
        .can_write = false,
        .can_admin = false,
        .can_export = false,
        .expires_at_ticks = 15,
        .network_scope = .local_only,
        .reshare_policy = .owner_only,
        .audit_visibility = .organization_policy,
    });
    const updated = directory.findShareGrant(notes.id, .{ .kind = .app, .serial = 7 }).?;
    try std.testing.expectEqual(ShareNetworkScope.local_only, updated.network_scope);
    try std.testing.expectEqual(ResharePolicy.owner_only, updated.reshare_policy);
    try std.testing.expectEqual(AuditVisibility.organization_policy, updated.audit_visibility);
    try std.testing.expect(!directory.hasAccess(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 7 },
        .network_scope = .local_only,
        .now_ticks = 20,
    }));
    try std.testing.expect(!directory.canReshare(notes.id, .{ .kind = .app, .serial = 7 }, .local_only, 20));
}

test "workspace restore rejects tampered signed snapshots" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x64} ** 32,
    };
    const object = try store.putVersion(.{
        .preferred_object_id = ids.object(901),
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello", 10),
    });

    var directory = Directory.init();
    const notes = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try directory.beginTransaction(notes.id);
    try directory.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    _ = try directory.commit(notes.id, 11);

    const snapshot = try directory.snapshot(notes.id, "baseline", .{
        .label = "zigos-workspace-key",
        .seed = [_]u8{0x65} ** 32,
    });
    snapshot.generation += 1;
    try std.testing.expectError(error.InvalidSignature, directory.restore(notes.id, snapshot.id, 12));
}
