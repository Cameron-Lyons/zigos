const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const copyText = native_util.copyText;

pub const MAX_WORKSPACES: usize = 8;
pub const MAX_WORKSPACE_ENTRIES: usize = 96;
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
    object_id: u64 = 0,
    version_id: u64 = 0,
    object_type: object_store.ObjectType = .blob,

    pub fn init(path: []const u8, object_id: u64, version_id: u64, object_type: object_store.ObjectType) Entry {
        var entry = Entry{
            .object_id = object_id,
            .version_id = version_id,
            .object_type = object_type,
        };
        entry.path_len = copyText(&entry.path, path);
        return entry;
    }

    pub fn pathSlice(self: *const Entry) []const u8 {
        return self.path[0..@min(self.path_len, self.path.len)];
    }
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
    id: u64,
    workspace_id: u64,
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
    workspace_id: u64,
    snapshot_id: u64,
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
    id: u64,
    owner: principal.PrincipalId,
    label_len: usize,
    label: [48]u8,
    generation: u32,
    entry_count: usize,
    entries: [MAX_WORKSPACE_ENTRIES]Entry,
    entry_index_slots: [ENTRY_INDEX_CAPACITY]EntryIndexSlot,
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

const IndexState = enum(u8) {
    empty,
    filled,
    tombstone,
};

const IdIndexSlot = struct {
    state: IndexState = .empty,
    id: u64 = 0,
    slot_index: usize = 0,
};

const EntryIndexSlot = struct {
    state: IndexState = .empty,
    path_hash: u64 = 0,
    slot_index: usize = 0,
};

pub const Directory = struct {
    next_workspace_id: u64 = 1,
    next_snapshot_id: u64 = 1,
    workspace_index_slots: [WORKSPACE_INDEX_CAPACITY]IdIndexSlot = emptyIdIndexTable(WORKSPACE_INDEX_CAPACITY),
    snapshot_index_slots: [SNAPSHOT_INDEX_CAPACITY]IdIndexSlot = emptyIdIndexTable(SNAPSHOT_INDEX_CAPACITY),
    workspaces: [MAX_WORKSPACES]WorkspaceSlot = [_]WorkspaceSlot{WorkspaceSlot{}} ** MAX_WORKSPACES,
    snapshots: [MAX_SNAPSHOTS]SnapshotSlot = [_]SnapshotSlot{SnapshotSlot{}} ** MAX_SNAPSHOTS,

    pub fn init() Directory {
        return .{};
    }

    pub fn reset(self: *Directory) void {
        self.next_workspace_id = 1;
        self.next_snapshot_id = 1;
        self.workspace_index_slots = emptyIdIndexTable(WORKSPACE_INDEX_CAPACITY);
        self.snapshot_index_slots = emptyIdIndexTable(SNAPSHOT_INDEX_CAPACITY);
        for (&self.workspaces) |*slot| {
            if (!slot.in_use) continue;
            slot.* = .{};
        }
        for (&self.snapshots) |*slot| {
            if (!slot.in_use) continue;
            slot.* = .{};
        }
    }

    pub fn rebuildIndexes(self: *Directory) void {
        self.workspace_index_slots = emptyIdIndexTable(WORKSPACE_INDEX_CAPACITY);
        self.snapshot_index_slots = emptyIdIndexTable(SNAPSHOT_INDEX_CAPACITY);

        for (&self.workspaces, 0..) |*slot, slot_index| {
            if (!slot.in_use) continue;
            rebuildWorkspaceIndexes(&slot.workspace);
            indexInsert(WORKSPACE_INDEX_CAPACITY, &self.workspace_index_slots, slot.workspace.id, slot_index);
        }
        for (self.snapshots, 0..) |slot, slot_index| {
            if (!slot.in_use) continue;
            indexInsert(SNAPSHOT_INDEX_CAPACITY, &self.snapshot_index_slots, slot.snapshot.id, slot_index);
        }
    }

    pub fn create(self: *Directory, request: CreateRequest) Error!*WorkspaceRecord {
        return self.createRef(&request);
    }

    pub fn createRef(self: *Directory, request: *const CreateRequest) Error!*WorkspaceRecord {
        for (&self.workspaces, 0..) |*slot, slot_index| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.workspace = zeroWorkspace();
            slot.workspace.id = self.nextWorkspaceId();
            slot.workspace.owner = request.owner;
            slot.workspace.label_len = copyText(&slot.workspace.label, request.label);
            indexInsert(WORKSPACE_INDEX_CAPACITY, &self.workspace_index_slots, slot.workspace.id, slot_index);
            return &slot.workspace;
        }
        return error.WorkspaceTableFull;
    }

    pub fn find(self: *Directory, workspace_id: u64) ?*WorkspaceRecord {
        if (self.indexedWorkspaceSlot(workspace_id)) |slot| return &slot.workspace;
        for (&self.workspaces) |*slot| {
            if (slot.in_use and slot.workspace.id == workspace_id) return &slot.workspace;
        }
        return null;
    }

    pub fn findConst(self: *const Directory, workspace_id: u64) ?*const WorkspaceRecord {
        return self.lookupConst(workspace_id);
    }

    pub fn findOwned(self: *Directory, owner: principal.PrincipalId, label: []const u8) ?*WorkspaceRecord {
        for (&self.workspaces) |*slot| {
            if (!slot.in_use) continue;
            if (!slot.workspace.owner.eql(owner)) continue;
            if (!std.mem.eql(u8, slot.workspace.labelSlice(), label)) continue;
            return &slot.workspace;
        }
        return null;
    }

    pub fn findOwnedConst(self: *const Directory, owner: principal.PrincipalId, label: []const u8) ?*const WorkspaceRecord {
        for (&self.workspaces) |*slot| {
            if (!slot.in_use) continue;
            if (!slot.workspace.owner.eql(owner)) continue;
            if (!std.mem.eql(u8, slot.workspace.labelSlice(), label)) continue;
            return &slot.workspace;
        }
        return null;
    }

    pub fn findByLabel(self: *Directory, label: []const u8) ?*WorkspaceRecord {
        for (&self.workspaces) |*slot| {
            if (!slot.in_use) continue;
            if (!std.mem.eql(u8, slot.workspace.labelSlice(), label)) continue;
            return &slot.workspace;
        }
        return null;
    }

    pub fn findSnapshotByLabel(self: *Directory, workspace_id: u64, label: []const u8) ?*SnapshotRecord {
        for (&self.snapshots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.snapshot.workspace_id != workspace_id) continue;
            if (!std.mem.eql(u8, slot.snapshot.labelSlice(), label)) continue;
            return &slot.snapshot;
        }
        return null;
    }

    pub fn findSnapshotByLabelConst(self: *const Directory, workspace_id: u64, label: []const u8) ?*const SnapshotRecord {
        for (&self.snapshots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.snapshot.workspace_id != workspace_id) continue;
            if (!std.mem.eql(u8, slot.snapshot.labelSlice(), label)) continue;
            return &slot.snapshot;
        }
        return null;
    }

    pub fn beginTransaction(self: *Directory, workspace_id: u64) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (workspace.transaction_open) return error.TransactionAlreadyOpen;
        workspace.transaction_open = true;
        workspace.staged_entry_count = 0;
        workspace.staged_effective_entry_count = workspace.entry_count;
        workspace.staged_entry_index_slots = emptyEntryIndexTable();
    }

    pub fn stagePut(
        self: *Directory,
        workspace_id: u64,
        path: []const u8,
        object_id: u64,
        version_id: u64,
        object_type: object_store.ObjectType,
    ) Error!void {
        if (path.len > MAX_ENTRY_PATH_BYTES) return error.PathTooLong;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.transaction_open) return error.NoActiveTransaction;

        if (findStagedEntryIndex(workspace, path)) |index| {
            if (isDeleteTombstone(workspace.staged_entries[index])) {
                workspace.staged_effective_entry_count += 1;
            }
            workspace.staged_entries[index] = Entry.init(path, object_id, version_id, object_type);
            return;
        }
        if (findWorkspaceEntryIndex(workspace, path) == null) {
            if (workspace.staged_effective_entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;
            workspace.staged_effective_entry_count += 1;
        }
        if (workspace.staged_entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;

        workspace.staged_entries[workspace.staged_entry_count] = Entry.init(path, object_id, version_id, object_type);
        entryIndexInsert(
            &workspace.staged_entry_index_slots,
            workspace.staged_entries[workspace.staged_entry_count].pathSlice(),
            workspace.staged_entry_count,
        );
        workspace.staged_entry_count += 1;
    }

    pub fn stageDelete(self: *Directory, workspace_id: u64, path: []const u8) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.transaction_open) return error.NoActiveTransaction;
        const base_exists = findWorkspaceEntryIndex(workspace, path) != null;

        if (findStagedEntryIndex(workspace, path)) |index| {
            if (isDeleteTombstone(workspace.staged_entries[index])) return error.EntryNotFound;

            workspace.staged_effective_entry_count -= 1;
            if (base_exists) {
                workspace.staged_entries[index] = deleteTombstone(path);
            } else {
                removeEntry(&workspace.staged_entries, &workspace.staged_entry_count, index);
                rebuildStagedEntryIndex(workspace);
            }
            return;
        }

        if (!base_exists) return error.EntryNotFound;
        if (workspace.staged_entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;

        workspace.staged_entries[workspace.staged_entry_count] = deleteTombstone(path);
        entryIndexInsert(
            &workspace.staged_entry_index_slots,
            workspace.staged_entries[workspace.staged_entry_count].pathSlice(),
            workspace.staged_entry_count,
        );
        workspace.staged_entry_count += 1;
        workspace.staged_effective_entry_count -= 1;
    }

    pub fn commit(self: *Directory, workspace_id: u64, tick: u64) Error!u32 {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.transaction_open) return error.NoActiveTransaction;

        applyTransactionDelta(workspace);
        clearTransactionState(workspace);
        workspace.generation += 1;
        return workspace.generation;
    }

    pub fn share(self: *Directory, workspace_id: u64, request: ShareRequest) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        for (workspace.share_grants[0..workspace.share_grant_count]) |*grant| {
            if (!grant.principal_id.eql(request.principal_id)) continue;
            grant.* = request;
            return;
        }
        if (workspace.share_grant_count >= MAX_SHARE_GRANTS) return error.ShareTableFull;
        workspace.share_grants[workspace.share_grant_count] = request;
        workspace.share_grant_count += 1;
    }

    pub fn findShareGrant(
        self: *const Directory,
        workspace_id: u64,
        principal_id: principal.PrincipalId,
    ) ?ShareGrant {
        const workspace = self.lookupConst(workspace_id) orelse return null;
        for (workspace.share_grants[0..workspace.share_grant_count]) |grant| {
            if (grant.principal_id.eql(principal_id)) return grant;
        }
        return null;
    }

    pub fn hasAccess(self: *const Directory, workspace_id: u64, request: AccessRequest) bool {
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
        workspace_id: u64,
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

    pub fn resolve(self: *const Directory, workspace_id: u64, path: []const u8) Error!Entry {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        const index = findWorkspaceEntryIndex(workspace, path) orelse return error.EntryNotFound;
        return workspace.entries[index];
    }

    pub fn entries(self: *const Directory, workspace_id: u64) Error![]const Entry {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        return workspace.entries[0..workspace.entry_count];
    }

    pub fn snapshot(
        self: *Directory,
        workspace_id: u64,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) Error!*SnapshotRecord {
        if (identity.label.len == 0) return error.UnsignedSnapshot;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;

        for (&self.snapshots, 0..) |*slot, slot_index| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.snapshot = zeroSnapshot();
            slot.snapshot.id = self.nextSnapshotId();
            slot.snapshot.workspace_id = workspace.id;
            slot.snapshot.generation = workspace.generation;
            slot.snapshot.label_len = copyText(&slot.snapshot.label, label);
            slot.snapshot.entry_count = workspace.entry_count;
            copyEntries(
                slot.snapshot.entries[0..workspace.entry_count],
                workspace.entries[0..workspace.entry_count],
            );
            signSnapshotRecord(&slot.snapshot, identity) catch return error.InvalidSignature;
            indexInsert(SNAPSHOT_INDEX_CAPACITY, &self.snapshot_index_slots, slot.snapshot.id, slot_index);
            return &slot.snapshot;
        }

        return error.SnapshotTableFull;
    }

    pub fn restore(self: *Directory, workspace_id: u64, snapshot_id: u64, tick: u64) Error!u32 {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        const snapshot_record = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;
        if (snapshot_record.workspace_id != workspace_id) return error.SnapshotNotFound;
        if (!verifySnapshotRecord(snapshot_record)) return error.InvalidSignature;

        var restore_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        clearEntries(&restore_entries);
        copyEntries(restore_entries[0..snapshot_record.entry_count], snapshot_record.entries[0..snapshot_record.entry_count]);
        recordDeletedEntriesAgainst(workspace, restore_entries[0..snapshot_record.entry_count]);

        clearEntries(&workspace.entries);
        workspace.entry_count = snapshot_record.entry_count;
        copyEntries(
            workspace.entries[0..snapshot_record.entry_count],
            snapshot_record.entries[0..snapshot_record.entry_count],
        );
        clearTransactionState(workspace);
        rebuildWorkspaceEntryIndex(workspace);
        workspace.generation += 1;
        return workspace.generation;
    }

    pub fn recoverDeleted(self: *Directory, workspace_id: u64, path: []const u8, tick: u64) Error!bool {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (findEntryIndex(workspace.entries[0..workspace.entry_count], path) != null) return false;

        var index = workspace.deleted_count;
        while (index > 0) {
            index -= 1;
            const entry = workspace.deleted_entries[index];
            if (!std.mem.eql(u8, entry.pathSlice(), path)) continue;
            if (workspace.entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;

            workspace.entries[workspace.entry_count] = entry;
            entryIndexInsert(&workspace.entry_index_slots, entry.pathSlice(), workspace.entry_count);
            workspace.entry_count += 1;
            workspace.generation += 1;
            return true;
        }

        return false;
    }

    pub fn exportSnapshot(
        self: *Directory,
        workspace_id: u64,
        snapshot_id: u64,
        identity: signing.SignerIdentity,
    ) Error!ExportPackage {
        var package = zeroExportPackage();
        try self.exportSnapshotInto(workspace_id, snapshot_id, identity, &package);
        return package;
    }

    pub fn exportSnapshotInto(
        self: *Directory,
        workspace_id: u64,
        snapshot_id: u64,
        identity: signing.SignerIdentity,
        out: *ExportPackage,
    ) Error!void {
        if (identity.label.len == 0) return error.UnsignedExport;
        const snapshot_record = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;
        if (snapshot_record.workspace_id != workspace_id) return error.SnapshotNotFound;
        if (!verifySnapshotRecord(snapshot_record)) return error.InvalidSignature;

        out.* = zeroExportPackage();
        out.workspace_id = workspace_id;
        out.snapshot_id = snapshot_id;
        out.generation = snapshot_record.generation;
        out.entry_count = snapshot_record.entry_count;
        out.label_len = copyText(&out.label, snapshot_record.labelSlice());
        copyEntries(out.entries[0..snapshot_record.entry_count], snapshot_record.entries[0..snapshot_record.entry_count]);
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
        if (!verifyExportPackage(package)) return error.InvalidSignature;
        const workspace = try self.create(.{
            .owner = owner,
            .label = label,
        });
        workspace.generation = package.generation;
        workspace.entry_count = package.entry_count;
        copyEntries(workspace.entries[0..package.entry_count], package.entries[0..package.entry_count]);
        rebuildWorkspaceEntryIndex(workspace);
        return workspace;
    }

    pub fn restoreFromExportPackage(
        self: *Directory,
        workspace_id: u64,
        package: *const ExportPackage,
        tick: u64,
    ) Error!u32 {
        _ = tick;
        if (!exportPackageSignature(package).isPresent()) return error.UnsignedExport;
        if (!verifyExportPackage(package)) return error.InvalidSignature;
        if (package.workspace_id != workspace_id) return error.SnapshotNotFound;

        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        recordDeletedEntriesAgainst(workspace, package.entries[0..package.entry_count]);
        clearEntries(&workspace.entries);
        workspace.entry_count = package.entry_count;
        copyEntries(workspace.entries[0..package.entry_count], package.entries[0..package.entry_count]);
        clearTransactionState(workspace);
        rebuildWorkspaceEntryIndex(workspace);
        workspace.generation += 1;
        return workspace.generation;
    }

    fn lookupConst(self: *const Directory, workspace_id: u64) ?*const WorkspaceRecord {
        if (self.indexedWorkspaceSlotConst(workspace_id)) |slot| return &slot.workspace;
        for (&self.workspaces) |*slot| {
            if (slot.in_use and slot.workspace.id == workspace_id) return &slot.workspace;
        }
        return null;
    }

    fn findSnapshot(self: *Directory, snapshot_id: u64) ?*SnapshotRecord {
        if (self.indexedSnapshotSlot(snapshot_id)) |slot| return &slot.snapshot;
        for (&self.snapshots) |*slot| {
            if (slot.in_use and slot.snapshot.id == snapshot_id) return &slot.snapshot;
        }
        return null;
    }

    fn indexedWorkspaceSlot(self: *Directory, workspace_id: u64) ?*WorkspaceSlot {
        const slot_index = indexLookup(WORKSPACE_INDEX_CAPACITY, &self.workspace_index_slots, workspace_id) orelse return null;
        const slot = &self.workspaces[slot_index];
        if (!slot.in_use or slot.workspace.id != workspace_id) return null;
        return slot;
    }

    fn indexedWorkspaceSlotConst(self: *const Directory, workspace_id: u64) ?*const WorkspaceSlot {
        const slot_index = indexLookup(WORKSPACE_INDEX_CAPACITY, &self.workspace_index_slots, workspace_id) orelse return null;
        const slot = &self.workspaces[slot_index];
        if (!slot.in_use or slot.workspace.id != workspace_id) return null;
        return slot;
    }

    fn indexedSnapshotSlot(self: *Directory, snapshot_id: u64) ?*SnapshotSlot {
        const slot_index = indexLookup(SNAPSHOT_INDEX_CAPACITY, &self.snapshot_index_slots, snapshot_id) orelse return null;
        const slot = &self.snapshots[slot_index];
        if (!slot.in_use or slot.snapshot.id != snapshot_id) return null;
        return slot;
    }

    fn nextWorkspaceId(self: *Directory) u64 {
        defer self.next_workspace_id += 1;
        return self.next_workspace_id;
    }

    fn nextSnapshotId(self: *Directory) u64 {
        defer self.next_snapshot_id += 1;
        return self.next_snapshot_id;
    }
};

fn zeroWorkspace() WorkspaceRecord {
    return .{
        .id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .generation = 0,
        .entry_count = 0,
        .entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
        .entry_index_slots = emptyEntryIndexTable(),
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
        .id = 0,
        .workspace_id = 0,
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
        .workspace_id = 0,
        .snapshot_id = 0,
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

fn emptyIdIndexTable(comptime capacity: usize) [capacity]IdIndexSlot {
    return [_]IdIndexSlot{IdIndexSlot{}} ** capacity;
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

fn signSnapshotRecord(snapshot: *SnapshotRecord, identity: signing.SignerIdentity) !void {
    var message_buffer: [4096]u8 = undefined;
    const message = try snapshotMessage(
        &message_buffer,
        "snapshot",
        snapshot.workspace_id,
        snapshot.generation,
        snapshot.labelSlice(),
        snapshot.entries[0..snapshot.entry_count],
    );
    snapshot.signature = try signing.sign(identity, message);
}

fn verifySnapshotRecord(snapshot: *const SnapshotRecord) bool {
    if (!snapshot.signature.isPresent()) return false;
    var message_buffer: [4096]u8 = undefined;
    const message = snapshotMessage(
        &message_buffer,
        "snapshot",
        snapshot.workspace_id,
        snapshot.generation,
        snapshot.labelSlice(),
        snapshot.entries[0..snapshot.entry_count],
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
    persistExportPackageSignature(package);
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

fn persistExportPackageSignature(package: *ExportPackage) void {
    package.signature_format_len = copyText(&package.signature_format_storage, package.signature.format);
    package.signature_signer_len = copyText(&package.signature_signer_storage, package.signature.signer);
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
    workspace_id: u64,
    generation: u32,
    label: []const u8,
    entries: []const Entry,
) error{NoSpaceLeft}![]const u8 {
    var used: usize = 0;
    used = try appendFormat(
        buffer,
        used,
        "{s}:{d}:{d}:{s}",
        .{ tag, workspace_id, generation, label },
    );
    for (entries) |entry| {
        used = try appendFormat(
            buffer,
            used,
            "\n{s}|{d}|{d}|{s}",
            .{ entry.pathSlice(), entry.object_id, entry.version_id, objectTypeName(entry.object_type) },
        );
    }
    return buffer[0..used];
}

fn objectTypeName(object_type: object_store.ObjectType) []const u8 {
    return switch (object_type) {
        .blob => "blob",
        .document => "document",
        .collection => "collection",
        .secret => "secret",
        .media_asset => "media_asset",
        .model_artifact => "model_artifact",
        .event_stream => "event_stream",
    };
}

fn appendFormat(buffer: []u8, offset: usize, comptime fmt: []const u8, args: anytype) error{NoSpaceLeft}!usize {
    const text = std.fmt.bufPrint(buffer[offset..], fmt, args) catch return error.NoSpaceLeft;
    return offset + text.len;
}

fn rebuildWorkspaceIndexes(workspace: *WorkspaceRecord) void {
    rebuildWorkspaceEntryIndex(workspace);
    rebuildStagedEntryIndex(workspace);
}

fn rebuildWorkspaceEntryIndex(workspace: *WorkspaceRecord) void {
    rebuildEntryIndex(&workspace.entry_index_slots, workspace.entries[0..workspace.entry_count]);
}

fn rebuildStagedEntryIndex(workspace: *WorkspaceRecord) void {
    rebuildEntryIndex(&workspace.staged_entry_index_slots, workspace.staged_entries[0..workspace.staged_entry_count]);
}

fn rebuildEntryIndex(table: *[ENTRY_INDEX_CAPACITY]EntryIndexSlot, entries: []const Entry) void {
    table.* = emptyEntryIndexTable();
    for (entries, 0..) |entry, slot_index| {
        entryIndexInsert(table, entry.pathSlice(), slot_index);
    }
}

fn findWorkspaceEntryIndex(workspace: *const WorkspaceRecord, path: []const u8) ?usize {
    return entryIndexLookup(&workspace.entry_index_slots, workspace.entries[0..workspace.entry_count], path);
}

fn findStagedEntryIndex(workspace: *const WorkspaceRecord, path: []const u8) ?usize {
    return entryIndexLookup(&workspace.staged_entry_index_slots, workspace.staged_entries[0..workspace.staged_entry_count], path);
}

fn deleteTombstone(path: []const u8) Entry {
    return Entry.init(path, 0, 0, .blob);
}

fn isDeleteTombstone(entry: Entry) bool {
    return entry.object_id == 0 and entry.version_id == 0;
}

fn findEntryIndex(entries: []const Entry, path: []const u8) ?usize {
    for (entries, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.pathSlice(), path)) return index;
    }
    return null;
}

fn entryIndexLookup(table: *const [ENTRY_INDEX_CAPACITY]EntryIndexSlot, entries: []const Entry, path: []const u8) ?usize {
    const path_hash = hashPath(path);
    var index = path_hash % ENTRY_INDEX_CAPACITY;
    var attempts: usize = 0;
    while (attempts < ENTRY_INDEX_CAPACITY) : (attempts += 1) {
        const slot = table[index];
        switch (slot.state) {
            .empty => return null,
            .filled => {
                if (slot.path_hash == path_hash and slot.slot_index < entries.len and std.mem.eql(u8, entries[slot.slot_index].pathSlice(), path)) {
                    return slot.slot_index;
                }
            },
            .tombstone => {},
        }
        index = (index + 1) % ENTRY_INDEX_CAPACITY;
    }
    return null;
}

fn entryIndexInsert(table: *[ENTRY_INDEX_CAPACITY]EntryIndexSlot, path: []const u8, slot_index: usize) void {
    const path_hash = hashPath(path);
    var index = path_hash % ENTRY_INDEX_CAPACITY;
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < ENTRY_INDEX_CAPACITY) : (attempts += 1) {
        switch (table[index].state) {
            .empty => {
                const insert_index = first_tombstone orelse index;
                table[insert_index] = .{
                    .state = .filled,
                    .path_hash = path_hash,
                    .slot_index = slot_index,
                };
                return;
            },
            .filled => {},
            .tombstone => {
                if (first_tombstone == null) first_tombstone = index;
            },
        }
        index = (index + 1) % ENTRY_INDEX_CAPACITY;
    }

    native_util.impossibleByInvariant("entry index capacity covers all workspace entry slots");
}

fn indexLookup(comptime capacity: usize, table: *const [capacity]IdIndexSlot, id: u64) ?usize {
    if (id == 0) return null;

    var index = indexHash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry = table[index];
        switch (entry.state) {
            .empty => return null,
            .filled => if (entry.id == id) return entry.slot_index,
            .tombstone => {},
        }
        index = (index + 1) % capacity;
    }
    return null;
}

fn indexInsert(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64, slot_index: usize) void {
    if (id == 0) native_util.impossibleByInvariant("id indexes never store the reserved zero id");

    var index = indexHash(id, capacity);
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table[index].state) {
            .empty => {
                const insert_index = first_tombstone orelse index;
                table[insert_index] = .{
                    .state = .filled,
                    .id = id,
                    .slot_index = slot_index,
                };
                return;
            },
            .filled => {
                if (table[index].id == id) {
                    table[index].slot_index = slot_index;
                    return;
                }
            },
            .tombstone => {
                if (first_tombstone == null) first_tombstone = index;
            },
        }
        index = (index + 1) % capacity;
    }

    native_util.impossibleByInvariant("id index capacity covers all live workspace slots");
}

fn indexHash(id: u64, comptime capacity: usize) usize {
    return @as(usize, @intCast((id *% 0x9E37_79B9_7F4A_7C15) % capacity));
}

fn hashPath(path: []const u8) usize {
    return @as(usize, @truncate(std.hash.Fnv1a_64.hash(path)));
}

fn removeEntry(entries: *[MAX_WORKSPACE_ENTRIES]Entry, count: *usize, index: usize) void {
    var cursor = index;
    while (cursor + 1 < count.*) : (cursor += 1) {
        entries[cursor] = entries[cursor + 1];
    }
    count.* -= 1;
    entries[count.*] = Entry{};
}

fn recordDeletedEntries(workspace: *WorkspaceRecord) void {
    for (workspace.entries[0..workspace.entry_count]) |entry| {
        const staged_index = findStagedEntryIndex(workspace, entry.pathSlice()) orelse continue;
        if (isDeleteTombstone(workspace.staged_entries[staged_index])) {
            appendDeleted(workspace, entry);
        }
    }
}

fn recordDeletedEntriesAgainst(workspace: *WorkspaceRecord, target_entries: []const Entry) void {
    for (workspace.entries[0..workspace.entry_count]) |entry| {
        if (findEntryIndex(target_entries, entry.pathSlice()) != null) continue;
        appendDeleted(workspace, entry);
    }
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

fn applyTransactionOverlay(workspace: *WorkspaceRecord) void {
    var next_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
    var next_count: usize = 0;

    for (workspace.entries[0..workspace.entry_count]) |entry| {
        if (findStagedEntryIndex(workspace, entry.pathSlice())) |staged_index| {
            const staged_entry = workspace.staged_entries[staged_index];
            if (isDeleteTombstone(staged_entry)) continue;
            next_entries[next_count] = staged_entry;
        } else {
            next_entries[next_count] = entry;
        }
        next_count += 1;
    }

    for (workspace.staged_entries[0..workspace.staged_entry_count]) |staged_entry| {
        if (isDeleteTombstone(staged_entry)) continue;
        if (findWorkspaceEntryIndex(workspace, staged_entry.pathSlice()) != null) continue;
        next_entries[next_count] = staged_entry;
        next_count += 1;
    }

    clearEntries(&workspace.entries);
    workspace.entry_count = next_count;
    copyEntries(workspace.entries[0..next_count], next_entries[0..next_count]);
}

fn applyTransactionDelta(workspace: *WorkspaceRecord) void {
    var staged_index: usize = 0;
    while (staged_index < workspace.staged_entry_count) : (staged_index += 1) {
        const staged_entry = workspace.staged_entries[staged_index];
        const path = staged_entry.pathSlice();

        if (isDeleteTombstone(staged_entry)) {
            const existing_index = findWorkspaceEntryIndex(workspace, path) orelse continue;
            appendDeleted(workspace, workspace.entries[existing_index]);
            removeEntry(&workspace.entries, &workspace.entry_count, existing_index);
            rebuildWorkspaceEntryIndex(workspace);
            continue;
        }

        if (findWorkspaceEntryIndex(workspace, path)) |existing_index| {
            workspace.entries[existing_index] = staged_entry;
            continue;
        }

        workspace.entries[workspace.entry_count] = staged_entry;
        entryIndexInsert(&workspace.entry_index_slots, path, workspace.entry_count);
        workspace.entry_count += 1;
    }
}

fn clearTransactionState(workspace: *WorkspaceRecord) void {
    workspace.transaction_open = false;
    workspace.staged_entry_count = 0;
    workspace.staged_effective_entry_count = 0;
    workspace.staged_entry_index_slots = emptyEntryIndexTable();
}

test "workspace transactions, snapshot restore, delete recovery, and signed export import work" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x61} ** 32,
    };
    const first = try store.putVersion(.{
        .preferred_object_id = 900,
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello", 10),
    });
    const second = try store.putVersion(.{
        .preferred_object_id = 900,
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
        .preferred_object_id = 901,
        .object_type = .document,
        .payload = "baseline",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "baseline", 30),
    });
    const second = try store.putVersion(.{
        .preferred_object_id = 901,
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
    try directory.stagePut(workspace.id, "documents/draft.md", 10, 20, .document);
    try directory.stageDelete(workspace.id, "documents/draft.md");
    try std.testing.expectEqual(@as(u32, 1), try directory.commit(workspace.id, 40));
    try std.testing.expectEqual(@as(usize, 0), (try directory.entries(workspace.id)).len);
    try std.testing.expectError(error.EntryNotFound, directory.resolve(workspace.id, "documents/draft.md"));
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
        .snapshot_id = 0,
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
        .preferred_object_id = 902,
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
        .preferred_object_id = 901,
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
