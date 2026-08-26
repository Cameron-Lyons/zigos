const builtin = @import("builtin");
const std = @import("std");
const binary_cursor = @import("binary_cursor");
const ids = @import("../../core/ids.zig");
const indexed_arena = @import("../../core/indexed_arena.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const object_store = @import("../object_store.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const workspace_index = @import("index.zig");
const workspace_merkle = @import("merkle.zig");
const workspace_sharing = @import("sharing.zig");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("../../../kernel/memory/memory.zig")
else
    struct {};

pub const MAX_WORKSPACES: usize = 8;
pub const MAX_WORKSPACE_ENTRIES: usize = 96;
pub const MAX_WORKSPACE_ENTRY_MUTATIONS: usize = MAX_WORKSPACE_ENTRIES * 2;

pub const MUTATION_LOG_COMPACTION_THRESHOLD: usize = MAX_WORKSPACE_ENTRY_MUTATIONS * 3 / 4;
pub const MAX_SNAPSHOTS: usize = 16;
pub const MAX_RECOVERABLE_DELETES: usize = 24;
pub const MAX_ENTRY_PATH_BYTES: usize = 96;
pub const MAX_WORKSPACE_LABEL_BYTES: usize = 48;
pub const MAX_SHARE_GRANTS: usize = 8;
pub const MAX_EXPORT_SIGNATURE_FORMAT_BYTES: usize = 16;
pub const MAX_EXPORT_SIGNATURE_SIGNER_BYTES: usize = MAX_WORKSPACE_LABEL_BYTES;
pub const WorkspacePathLength = u8;
pub const WorkspaceEntryCount = u8;
pub const WorkspaceMutationCount = u8;
pub const WorkspaceShareGrantCount = u8;
pub const RecoverableDeleteCount = u8;
pub const COMPACT_STAGING_METADATA = true;
pub const WORKSPACE_STAGING_STATE_SIZE_CEILING_BYTES: usize = 3;
pub const COMPACT_SNAPSHOT_EXPORT_METADATA = true;
pub const SNAPSHOT_RECORD_SIZE_CEILING_BYTES: usize = 224;
pub const EXPORT_PACKAGE_SIZE_CEILING_BYTES: usize = 11_808;
pub const COMPACT_WORKSPACE_LABEL_METADATA = true;
pub const COMPACT_WORKSPACE_TABLE_METADATA = true;
pub const NO_SNAPSHOT_GENERATION: u32 = std.math.maxInt(u32);

comptime {
    if (MAX_ENTRY_PATH_BYTES > std.math.maxInt(WorkspacePathLength)) {
        @compileError("workspace path capacity exceeds its compact length field");
    }
    if (MAX_SHARE_GRANTS > std.math.maxInt(u8)) {
        @compileError("workspace share capacity exceeds its compact index");
    }
    if (MAX_WORKSPACE_ENTRIES > std.math.maxInt(u8)) {
        @compileError("workspace staging metadata exceeds u8 capacity");
    }
    if (MAX_WORKSPACE_ENTRIES > std.math.maxInt(WorkspaceEntryCount) or
        MAX_WORKSPACE_ENTRY_MUTATIONS > std.math.maxInt(WorkspaceMutationCount) or
        MAX_SHARE_GRANTS > std.math.maxInt(WorkspaceShareGrantCount) or
        MAX_RECOVERABLE_DELETES > std.math.maxInt(RecoverableDeleteCount))
    {
        @compileError("workspace table metadata exceeds its compact count type");
    }
    if (MAX_WORKSPACE_LABEL_BYTES > std.math.maxInt(u8) or
        MAX_EXPORT_SIGNATURE_FORMAT_BYTES > std.math.maxInt(u8) or
        MAX_EXPORT_SIGNATURE_SIGNER_BYTES > std.math.maxInt(u8))
    {
        @compileError("workspace text metadata exceeds u8 capacity");
    }
}
const WORKSPACE_INDEX_CAPACITY: usize = MAX_WORKSPACES * 2;
const SNAPSHOT_INDEX_CAPACITY: usize = MAX_SNAPSHOTS * 2;
const SHARE_GRANT_INDEX_CAPACITY: usize = MAX_SHARE_GRANTS * 2;
const ENTRY_INDEX_CAPACITY: usize = MAX_WORKSPACE_ENTRIES * 2;
const ENTRY_OBJECT_INDEX_CAPACITY: usize = MAX_WORKSPACE_ENTRIES;
pub const SnapshotRootAddress = workspace_merkle.RootAddress;
const snapshot_message_buffer_bytes: usize = 4096;
pub const WorkspaceEntrySlotIndex = workspace_index.EntrySlotIndex;
const EntryIndexSlot = workspace_index.EntryIndexSlot;
const EntryObjectIndexSlot = workspace_index.EntryObjectIndexSlot;

const ShareGrantPrincipalIndexSlot = struct {
    in_use: bool = false,
    principal_id: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    grant_index: u8 = 0,
};

pub const ShareGrantPrincipalIndex = struct {
    slots: [SHARE_GRANT_INDEX_CAPACITY]ShareGrantPrincipalIndexSlot =
        [_]ShareGrantPrincipalIndexSlot{ShareGrantPrincipalIndexSlot{}} ** SHARE_GRANT_INDEX_CAPACITY,

    pub fn init() ShareGrantPrincipalIndex {
        return .{};
    }

    pub fn reset(self: *ShareGrantPrincipalIndex) void {
        self.* = ShareGrantPrincipalIndex.init();
    }

    pub fn count(self: *const ShareGrantPrincipalIndex, key: u64) usize {
        var matches: usize = 0;
        for (self.slots) |slot| {
            if (!slot.in_use) continue;
            if (shareGrantPrincipalKey(slot.principal_id) == key) matches += 1;
        }
        return matches;
    }

    fn lookup(self: *const ShareGrantPrincipalIndex, principal_id: principal.PrincipalId) ?usize {
        const key = shareGrantPrincipalKey(principal_id);
        var slot_index = shareGrantProbeIndex(key);
        var attempts: usize = 0;
        while (attempts < SHARE_GRANT_INDEX_CAPACITY) : (attempts += 1) {
            const slot = self.slots[slot_index];
            if (!slot.in_use) return null;
            if (slot.principal_id.eql(principal_id)) return @intCast(slot.grant_index);
            slot_index = (slot_index + 1) % SHARE_GRANT_INDEX_CAPACITY;
        }
        return null;
    }

    fn insert(self: *ShareGrantPrincipalIndex, principal_id: principal.PrincipalId, grant_index: usize) bool {
        if (grant_index >= MAX_SHARE_GRANTS) return false;
        const key = shareGrantPrincipalKey(principal_id);
        var slot_index = shareGrantProbeIndex(key);
        var attempts: usize = 0;
        while (attempts < SHARE_GRANT_INDEX_CAPACITY) : (attempts += 1) {
            const slot = &self.slots[slot_index];
            if (!slot.in_use or slot.principal_id.eql(principal_id)) {
                slot.* = .{
                    .in_use = true,
                    .principal_id = principal_id,
                    .grant_index = @intCast(grant_index),
                };
                return true;
            }
            slot_index = (slot_index + 1) % SHARE_GRANT_INDEX_CAPACITY;
        }
        return false;
    }
};

pub const Entry = struct {
    path: [MAX_ENTRY_PATH_BYTES]u8 = [_]u8{0} ** MAX_ENTRY_PATH_BYTES,
    object_id: ids.ObjectId = ids.ObjectId.zero,
    version_id: ids.VersionId = ids.VersionId.zero,
    path_len: WorkspacePathLength = 0,
    object_type: object_store.ObjectType = .blob,

    pub fn init(path: []const u8, object_id: ids.ObjectId, version_id: ids.VersionId, object_type: object_store.ObjectType) Error!Entry {
        var entry = Entry{
            .object_id = object_id,
            .version_id = version_id,
            .object_type = object_type,
        };
        entry.path_len = @intCast(native_util.copyTextExact(&entry.path, path) catch return error.PathTooLong);
        return entry;
    }

    pub fn pathSlice(self: *const Entry) []const u8 {
        return self.path[0..@min(@as(usize, self.path_len), self.path.len)];
    }

    pub fn pathHash(self: *const Entry) u64 {
        return native_util.fnv1a64(self.pathSlice());
    }
};

pub const EntryMutation = struct {
    generation: u32 = 0,
    entry: Entry = .{},
};
const MutationEntries = [MAX_WORKSPACE_ENTRY_MUTATIONS]EntryMutation;
const heap_backed_mutation_logs = builtin.target.os.tag == .freestanding;
const RecoverableDeleteEntries = [MAX_RECOVERABLE_DELETES]Entry;
pub const HEAP_BACKED_RECOVERABLE_DELETE_LOGS_ON_FREESTANDING = true;
const heap_backed_recoverable_delete_logs = HEAP_BACKED_RECOVERABLE_DELETE_LOGS_ON_FREESTANDING and builtin.target.os.tag == .freestanding;
pub const WORKSPACE_RECORD_SIZE_CEILING_BYTES: usize = if (heap_backed_mutation_logs and heap_backed_recoverable_delete_logs) 16_488 else 43_928;
pub const DIRECTORY_SIZE_CEILING_BYTES: usize = if (heap_backed_mutation_logs and heap_backed_recoverable_delete_logs) 137_880 else 357_400;
const MutationBacking = if (heap_backed_mutation_logs) ?*MutationEntries else MutationEntries;
const RecoverableDeleteBacking = if (heap_backed_recoverable_delete_logs) ?*RecoverableDeleteEntries else RecoverableDeleteEntries;
pub const recoverable_delete_layout = .{
    .heap_backs_log_on_freestanding = HEAP_BACKED_RECOVERABLE_DELETE_LOGS_ON_FREESTANDING,
    .freestanding_handle_size_bytes = @sizeOf(?*RecoverableDeleteEntries),
    .backing_size_bytes = @sizeOf(RecoverableDeleteEntries),
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
    scope_object_id: ids.ObjectId = ids.ObjectId.zero,
    expires_at_ticks: u64 = 0,
    scope_path: [MAX_ENTRY_PATH_BYTES]u8 = [_]u8{0} ** MAX_ENTRY_PATH_BYTES,
    can_read: bool = true,
    can_write: bool = false,
    can_admin: bool = false,
    can_export: bool = false,
    scope_path_len: WorkspacePathLength = 0,
    network_scope: ShareNetworkScope = .local_only,
    reshare_policy: ResharePolicy = .owner_only,
    audit_visibility: AuditVisibility = .owner_only,

    pub fn withObjectScope(self: ShareGrant, object_id: ids.ObjectId, path: []const u8) Error!ShareGrant {
        var grant = self;
        grant.scope_object_id = object_id;
        @memset(grant.scope_path[0..], 0);
        grant.scope_path_len = @intCast(native_util.copyTextExact(&grant.scope_path, path) catch return error.PathTooLong);
        return grant;
    }

    pub fn isActive(self: ShareGrant, now_ticks: u64) bool {
        return self.expires_at_ticks == 0 or now_ticks <= self.expires_at_ticks;
    }

    pub fn allowsNetworkScope(self: ShareGrant, requested: ShareNetworkScope) bool {
        return workspace_sharing.networkScopeRank(requested) <= workspace_sharing.networkScopeRank(self.network_scope);
    }

    pub fn isObjectScoped(self: ShareGrant) bool {
        return !self.scope_object_id.isZero() or self.scope_path_len != 0;
    }

    pub fn scopePathSlice(self: *const ShareGrant) []const u8 {
        return self.scope_path[0..@min(@as(usize, self.scope_path_len), self.scope_path.len)];
    }

    pub fn allowsObject(self: ShareGrant, object_id: ids.ObjectId, path: []const u8) bool {
        if (!self.isObjectScoped()) return true;
        if (!self.scope_object_id.isZero() and (object_id.isZero() or !self.scope_object_id.eql(object_id))) return false;
        if (self.scope_path_len != 0 and (path.len == 0 or !std.mem.eql(u8, self.scopePathSlice(), path))) return false;
        return true;
    }
};

pub const ShareRequest = ShareGrant;

pub const AccessRequest = struct {
    principal_id: principal.PrincipalId,
    object_id: ids.ObjectId = ids.ObjectId.zero,
    path: []const u8 = "",
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
    label_len: u8,
    entry_count: u8,
    label: [MAX_WORKSPACE_LABEL_BYTES]u8,
    root_address: SnapshotRootAddress,
    signature: manifest.Signature = .{},

    comptime {
        if (@sizeOf(@This()) > SNAPSHOT_RECORD_SIZE_CEILING_BYTES) {
            @compileError("workspace snapshot record exceeds its compact layout ceiling");
        }
    }

    pub fn labelSlice(self: *const SnapshotRecord) []const u8 {
        return self.label[0..@min(@as(usize, self.label_len), self.label.len)];
    }

    pub fn signerSlice(self: *const SnapshotRecord) []const u8 {
        return self.signature.signer;
    }
};

pub const ExportPackage = struct {
    workspace_id: ids.WorkspaceId,
    snapshot_id: ids.SnapshotId,
    generation: u32,
    label_len: u8,
    entry_count: u8,
    signature_format_len: u8 = 0,
    signature_signer_len: u8 = 0,
    label: [MAX_WORKSPACE_LABEL_BYTES]u8,
    root_address: SnapshotRootAddress,
    signature: manifest.Signature = .{},
    signature_format_storage: [MAX_EXPORT_SIGNATURE_FORMAT_BYTES]u8 = [_]u8{0} ** MAX_EXPORT_SIGNATURE_FORMAT_BYTES,
    signature_signer_storage: [MAX_EXPORT_SIGNATURE_SIGNER_BYTES]u8 = [_]u8{0} ** MAX_EXPORT_SIGNATURE_SIGNER_BYTES,
    entries: [MAX_WORKSPACE_ENTRIES]Entry,

    comptime {
        if (@sizeOf(@This()) > EXPORT_PACKAGE_SIZE_CEILING_BYTES) {
            @compileError("workspace export package exceeds its compact layout ceiling");
        }
    }

    pub fn labelSlice(self: *const ExportPackage) []const u8 {
        return self.label[0..@min(@as(usize, self.label_len), self.label.len)];
    }

    pub fn signerSlice(self: *const ExportPackage) []const u8 {
        return exportPackageSignature(self).signer;
    }
};

pub const WorkspacePathIndex = struct {
    entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
    path_slots: [ENTRY_INDEX_CAPACITY]EntryIndexSlot = workspace_index.emptyEntryIndexTable(ENTRY_INDEX_CAPACITY),
    object_slots: [ENTRY_OBJECT_INDEX_CAPACITY]EntryObjectIndexSlot = workspace_index.emptyEntryObjectIndexTable(ENTRY_OBJECT_INDEX_CAPACITY),
    leaf_hashes: [MAX_WORKSPACE_ENTRIES]SnapshotRootAddress =
        [_]SnapshotRootAddress{workspace_merkle.zeroRootAddress()} ** MAX_WORKSPACE_ENTRIES,
    root_address: SnapshotRootAddress = workspace_merkle.zeroRootAddress(),
};

pub const WorkspaceMutationLog = struct {
    backing: MutationBacking = if (heap_backed_mutation_logs) null else [_]EntryMutation{EntryMutation{}} ** MAX_WORKSPACE_ENTRY_MUTATIONS,

    pub fn ensureBacking(self: *WorkspaceMutationLog) error{NoSpaceLeft}!void {
        if (comptime heap_backed_mutation_logs) {
            if (self.backing != null) return;
            const allocation = kernel_memory.kmalloc(@sizeOf(MutationEntries)) orelse return error.NoSpaceLeft;
            const backing: *MutationEntries = @ptrCast(@alignCast(allocation));
            backing.* = [_]EntryMutation{EntryMutation{}} ** MAX_WORKSPACE_ENTRY_MUTATIONS;
            self.backing = backing;
        }
    }

    pub fn entries(self: *WorkspaceMutationLog) *MutationEntries {
        if (comptime heap_backed_mutation_logs) {
            return self.backing orelse
                native_util.impossibleByInvariant("live workspaces retain mutation-log backing");
        }
        return &self.backing;
    }

    pub fn entriesConst(self: *const WorkspaceMutationLog) *const MutationEntries {
        if (comptime heap_backed_mutation_logs) {
            return self.backing orelse
                native_util.impossibleByInvariant("live workspaces retain mutation-log backing");
        }
        return &self.backing;
    }

    pub fn releaseBacking(self: *WorkspaceMutationLog) void {
        if (comptime heap_backed_mutation_logs) {
            if (self.backing) |backing| {
                @memset(std.mem.asBytes(backing), 0);
                kernel_memory.kfree(@ptrCast(backing));
                self.backing = null;
            }
        } else {
            @memset(std.mem.asBytes(&self.backing), 0);
        }
    }
};

pub const WorkspaceShareTable = struct {
    share_grants: [MAX_SHARE_GRANTS]ShareGrant = [_]ShareGrant{ShareGrant{
        .principal_id = .{ .kind = .service, .serial = 0 },
    }} ** MAX_SHARE_GRANTS,
    share_grant_principal_index: ShareGrantPrincipalIndex = ShareGrantPrincipalIndex.init(),
};

pub const WorkspaceStagingState = struct {
    transaction_open: bool = false,
    staged_entry_count: u8 = 0,
    staged_effective_entry_count: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > WORKSPACE_STAGING_STATE_SIZE_CEILING_BYTES) {
            @compileError("workspace staging state exceeds its compact layout ceiling");
        }
    }
};

pub const RecoverableDeleteLog = struct {
    backing: RecoverableDeleteBacking = if (heap_backed_recoverable_delete_logs) null else [_]Entry{Entry{}} ** MAX_RECOVERABLE_DELETES,

    pub fn ensureBacking(self: *RecoverableDeleteLog) error{NoSpaceLeft}!void {
        if (comptime heap_backed_recoverable_delete_logs) {
            if (self.backing != null) return;
            const allocation = kernel_memory.kmalloc(@sizeOf(RecoverableDeleteEntries)) orelse return error.NoSpaceLeft;
            const backing: *RecoverableDeleteEntries = @ptrCast(@alignCast(allocation));
            backing.* = [_]Entry{Entry{}} ** MAX_RECOVERABLE_DELETES;
            self.backing = backing;
        }
    }

    pub fn entries(self: *RecoverableDeleteLog) *RecoverableDeleteEntries {
        if (comptime heap_backed_recoverable_delete_logs) {
            return self.backing orelse
                native_util.impossibleByInvariant("live recoverable deletes retain backing");
        }
        return &self.backing;
    }

    pub fn entriesConst(self: *const RecoverableDeleteLog, count: usize) []const Entry {
        if (count == 0) return &.{};
        if (comptime heap_backed_recoverable_delete_logs) {
            const backing = self.backing orelse
                native_util.impossibleByInvariant("non-empty recoverable deletes retain backing");
            return backing[0..count];
        }
        return self.backing[0..count];
    }

    pub fn releaseBacking(self: *RecoverableDeleteLog) void {
        if (comptime heap_backed_recoverable_delete_logs) {
            if (self.backing) |backing| {
                @memset(std.mem.asBytes(backing), 0);
                kernel_memory.kfree(@ptrCast(backing));
                self.backing = null;
            }
        } else {
            @memset(std.mem.asBytes(&self.backing), 0);
        }
    }
};

pub const WorkspaceTableCounts = struct {
    entry_count: WorkspaceEntryCount = 0,
    entry_mutation_count: WorkspaceMutationCount = 0,
    share_grant_count: WorkspaceShareGrantCount = 0,
    deleted_count: RecoverableDeleteCount = 0,
};

pub const WorkspaceRecord = struct {
    id: ids.WorkspaceId,
    owner: principal.PrincipalId,
    label_len: u8,
    label: [MAX_WORKSPACE_LABEL_BYTES]u8,
    generation: u32,
    counts: WorkspaceTableCounts = .{},
    path_index: WorkspacePathIndex,
    mutation_log: WorkspaceMutationLog,
    share_table: WorkspaceShareTable,
    staging: WorkspaceStagingState,
    recoverable_deletes: RecoverableDeleteLog,
    oldest_snapshot_generation: u32 = NO_SNAPSHOT_GENERATION,

    pub fn labelSlice(self: *const WorkspaceRecord) []const u8 {
        return self.label[0..@min(@as(usize, self.label_len), self.label.len)];
    }

    pub fn entryCount(self: *const WorkspaceRecord) usize {
        return @intCast(self.counts.entry_count);
    }

    pub fn deletedCount(self: *const WorkspaceRecord) usize {
        return @intCast(self.counts.deleted_count);
    }

    pub fn rootAddress(self: *const WorkspaceRecord) SnapshotRootAddress {
        return self.path_index.root_address;
    }

    pub fn oldestSnapshotGeneration(self: *const WorkspaceRecord) ?u32 {
        if (self.oldest_snapshot_generation == NO_SNAPSHOT_GENERATION) return null;
        return self.oldest_snapshot_generation;
    }

    pub fn findShareGrant(self: *const WorkspaceRecord, principal_id: principal.PrincipalId) ?ShareGrant {
        const grant_index = findShareGrantIndex(self, principal_id) orelse return null;
        return self.share_table.share_grants[grant_index];
    }

    pub fn hasAccess(self: *const WorkspaceRecord, request: AccessRequest) bool {
        if (self.owner.eql(request.principal_id)) return true;

        const grant = self.findShareGrant(request.principal_id) orelse return false;
        if (!grant.isActive(request.now_ticks)) return false;
        if (!grant.allowsNetworkScope(request.network_scope)) return false;
        if (!grant.allowsObject(request.object_id, request.path)) return false;
        if (request.wants_admin and !grant.can_admin) return false;
        if (request.wants_write and !grant.can_write) return false;
        if (request.wants_export and !grant.can_export) return false;
        if (!request.wants_write and !request.wants_admin and !grant.can_read) return false;
        return true;
    }

    pub fn hasAnyAccess(self: *const WorkspaceRecord, request: AccessRequest) bool {
        if (self.owner.eql(request.principal_id)) return true;

        const grant = self.findShareGrant(request.principal_id) orelse return false;
        if (!grant.isActive(request.now_ticks)) return false;
        if (!grant.allowsNetworkScope(request.network_scope)) return false;
        if (request.wants_admin and !grant.can_admin) return false;
        if (request.wants_write and !grant.can_write) return false;
        if (request.wants_export and !grant.can_export) return false;
        if (!request.wants_write and !request.wants_admin and !grant.can_read) return false;
        return true;
    }

    pub fn resolveBorrowedWithPathHash(self: *const WorkspaceRecord, path: []const u8, path_hash: u64) Error!*const Entry {
        const index = findWorkspaceEntryIndexWithPathHash(self, path, path_hash) orelse return error.EntryNotFound;
        return &self.path_index.entries[index];
    }
};

pub const Error = error{
    DuplicatePath,
    EntryNotFound,
    EntryTableFull,
    NoActiveTransaction,
    PathTooLong,
    ShareTableFull,
    SnapshotIdExhausted,
    SnapshotNotFound,
    SnapshotTableFull,
    TransactionAlreadyOpen,
    InvalidSignature,
    LabelTooLong,
    NoSpaceLeft,
    SignatureFormatTooLong,
    SignatureSignerTooLong,
    UnsignedExport,
    UnsignedSnapshot,
    WorkspaceIdExhausted,
    WorkspaceNotFound,
    WorkspaceTableFull,
};

const WorkspaceSlot = struct {
    in_use: bool = false,
    workspace: WorkspaceRecord = zeroWorkspace(),
};

comptime {
    if (heap_backed_mutation_logs and @sizeOf(WorkspaceMutationLog) > 16) {
        @compileError("heap-backed workspace mutation logs exceed their compact layout");
    }
    if (heap_backed_mutation_logs and heap_backed_recoverable_delete_logs and @sizeOf(WorkspaceRecord) > WORKSPACE_RECORD_SIZE_CEILING_BYTES) {
        @compileError("heap-backed workspace records exceed their compact layout");
    }
    if (heap_backed_mutation_logs and heap_backed_recoverable_delete_logs and @sizeOf(WorkspaceSlot) > 16_496) {
        @compileError("heap-backed workspace slots exceed their compact layout");
    }
}

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

fn workspaceLabelKey(label: []const u8) u64 {
    return indexed_arena.nonZeroKey(native_util.fnv1a64(label));
}

fn workspaceOwnerLabelKey(owner: principal.PrincipalId, label: []const u8) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(owner.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, owner.serial);
    hash = native_util.fnv1a64WithSeed(hash, label);
    return indexed_arena.nonZeroKey(hash);
}

fn snapshotLabelKey(workspace_id: ids.WorkspaceId, label: []const u8) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, workspace_id.raw());
    hash = native_util.fnv1a64WithSeed(hash, label);
    return indexed_arena.nonZeroKey(hash);
}

pub fn shareGrantPrincipalKey(principal_id: principal.PrincipalId) u64 {
    var hash: u64 = 0x5753_4752_414e_5401;
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(principal_id.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, principal_id.serial);
    return indexed_arena.nonZeroKey(hash);
}

pub fn shareGrantSlotIndex(record: *const WorkspaceRecord, principal_id: principal.PrincipalId) ?usize {
    return findShareGrantIndex(record, principal_id);
}

fn shareGrantProbeIndex(key: u64) usize {
    return @intCast((key *% 0x9E37_79B9_7F4A_7C15) % SHARE_GRANT_INDEX_CAPACITY);
}

const WorkspaceArena = indexed_arena.DirtyTrackedIndexedArenaWithKey(ids.WorkspaceId, WorkspaceSlot, MAX_WORKSPACES, WORKSPACE_INDEX_CAPACITY, workspaceSlotId);
const SnapshotArena = indexed_arena.DirtyTrackedIndexedArenaWithKey(ids.SnapshotId, SnapshotSlot, MAX_SNAPSHOTS, SNAPSHOT_INDEX_CAPACITY, snapshotSlotId);
const WorkspaceOwnerLabelIndex = indexed_arena.UniqueIndex(WORKSPACE_INDEX_CAPACITY);
const WorkspaceLabelIndex = indexed_arena.MultimapIndex(MAX_WORKSPACES, MAX_WORKSPACES, WORKSPACE_INDEX_CAPACITY);
const SnapshotLabelIndex = indexed_arena.UniqueIndex(SNAPSHOT_INDEX_CAPACITY);

pub const Directory = struct {
    next_workspace_id: u64 = 1,
    next_snapshot_id: u64 = 1,
    workspaces: WorkspaceArena = WorkspaceArena.init(),
    snapshots: SnapshotArena = SnapshotArena.init(),
    workspace_owner_label_index: WorkspaceOwnerLabelIndex = WorkspaceOwnerLabelIndex.init(),
    workspace_label_index: WorkspaceLabelIndex = WorkspaceLabelIndex.init(),
    snapshot_label_index: SnapshotLabelIndex = SnapshotLabelIndex.init(),

    pub fn init() Directory {
        return .{};
    }

    comptime {
        if (@sizeOf(@This()) > DIRECTORY_SIZE_CEILING_BYTES) {
            @compileError("workspace directory exceeds its compact layout ceiling");
        }
    }

    pub fn reset(self: *Directory) void {
        self.next_workspace_id = 1;
        self.next_snapshot_id = 1;
        for (self.workspaces.slots[0..self.workspaces.next_unclaimed_index]) |*slot| {
            if (slot.in_use) {
                slot.workspace.mutation_log.releaseBacking();
                slot.workspace.recoverable_deletes.releaseBacking();
                slot.* = WorkspaceSlot{};
            }
        }
        self.workspaces.resetRetainingPayloads();
        for (self.snapshots.slots[0..self.snapshots.next_unclaimed_index]) |*slot| {
            if (slot.in_use) slot.* = SnapshotSlot{};
        }
        self.snapshots.resetRetainingPayloads();
        self.workspace_owner_label_index.reset();
        self.workspace_label_index.reset();
        self.snapshot_label_index.reset();
    }

    pub fn rebuildIndexes(self: *Directory) void {
        self.workspaces.rebuildPrimaryIndex();
        self.snapshots.rebuildPrimaryIndex();
        self.rebuildDerivedIndexes();
    }

    pub fn rebuildDerivedIndexes(self: *Directory) void {
        self.workspace_owner_label_index.reset();
        self.workspace_label_index.reset();
        self.snapshot_label_index.reset();

        for (&self.workspaces.slots, 0..) |*slot, slot_index| {
            if (!slot.in_use) continue;
            self.indexWorkspace(slot_index);
            normalizeAndRebuildWorkspaceIndexes(&slot.workspace);
        }
        for (self.snapshots.slots, 0..) |slot, slot_index| {
            if (!slot.in_use) continue;
            self.snapshot_label_index.insert(snapshotLabelKey(slot.snapshot.workspace_id, slot.snapshot.labelSlice()), slot_index);
            self.recordWorkspaceSnapshotGeneration(slot.snapshot.workspace_id, slot.snapshot.generation);
        }
    }

    pub fn create(self: *Directory, request: CreateRequest) Error!*WorkspaceRecord {
        return self.createRef(&request);
    }

    pub fn createRef(self: *Directory, request: *const CreateRequest) Error!*WorkspaceRecord {
        var label: [MAX_WORKSPACE_LABEL_BYTES]u8 = [_]u8{0} ** MAX_WORKSPACE_LABEL_BYTES;
        const label_len = native_util.copyTextExact(&label, request.label) catch return error.LabelTooLong;
        if (self.workspaceCount() >= MAX_WORKSPACES) return error.WorkspaceTableFull;
        if (self.next_workspace_id == 0) return error.WorkspaceIdExhausted;
        const workspace_id = ids.workspace(self.next_workspace_id);
        const slot_index = self.workspaces.reserveIndex(workspace_id) orelse return error.WorkspaceTableFull;
        const slot = &self.workspaces.slots[slot_index];
        slot.workspace = zeroWorkspace();
        slot.workspace.mutation_log.ensureBacking() catch |err| {
            std.debug.assert(self.workspaces.removeIndex(slot_index));
            return err;
        };
        self.next_workspace_id +%= 1;
        slot.workspace.id = workspace_id;
        slot.workspace.owner = request.owner;
        slot.workspace.label = label;
        slot.workspace.label_len = @intCast(label_len);
        rebuildWorkspaceEntryIndex(&slot.workspace);
        self.indexWorkspace(slot_index);
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
        const lookup = WorkspaceLookup{
            .owner = owner,
            .label = label,
        };
        const slot = self.lookupWorkspaceOwnerLabel(lookup) orelse return null;
        return &slot.workspace;
    }

    pub fn findOwnedConst(self: *const Directory, owner: principal.PrincipalId, label: []const u8) ?*const WorkspaceRecord {
        const lookup = WorkspaceLookup{
            .owner = owner,
            .label = label,
        };
        const slot = self.lookupWorkspaceOwnerLabelConst(lookup) orelse return null;
        return &slot.workspace;
    }

    pub fn findByLabel(self: *Directory, label: []const u8) ?*WorkspaceRecord {
        const slot = self.lookupWorkspaceLabel(label) orelse return null;
        return &slot.workspace;
    }

    pub fn findSnapshotByLabel(self: *Directory, workspace_id: ids.WorkspaceId, label: []const u8) ?*SnapshotRecord {
        const lookup = SnapshotLookup{
            .workspace_id = workspace_id,
            .label = label,
        };
        const slot = self.lookupSnapshotLabel(lookup) orelse return null;
        return &slot.snapshot;
    }

    pub fn findSnapshotByLabelConst(self: *const Directory, workspace_id: ids.WorkspaceId, label: []const u8) ?*const SnapshotRecord {
        const lookup = SnapshotLookup{
            .workspace_id = workspace_id,
            .label = label,
        };
        const slot = self.lookupSnapshotLabelConst(lookup) orelse return null;
        return &slot.snapshot;
    }

    pub fn findSnapshot(self: *Directory, snapshot_id: ids.SnapshotId) ?*SnapshotRecord {
        const slot = self.snapshots.get(snapshot_id) orelse return null;
        return &slot.snapshot;
    }

    pub fn findSnapshotConst(self: *const Directory, snapshot_id: ids.SnapshotId) ?*const SnapshotRecord {
        const slot = self.snapshots.getConst(snapshot_id) orelse return null;
        return &slot.snapshot;
    }

    pub fn beginTransaction(self: *Directory, workspace_id: ids.WorkspaceId) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (workspace.staging.transaction_open) return error.TransactionAlreadyOpen;
        workspace.staging.transaction_open = true;
        workspace.staging.staged_entry_count = 0;
        workspace.staging.staged_effective_entry_count = @intCast(workspace.counts.entry_count);
    }

    pub fn abortTransaction(self: *Directory, workspace_id: ids.WorkspaceId) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.staging.transaction_open) return error.NoActiveTransaction;
        discardTransactionState(workspace);
        workspace.staging.staged_effective_entry_count = @intCast(workspace.counts.entry_count);
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
        if (!workspace.staging.transaction_open) return error.NoActiveTransaction;

        if (findStagedEntryIndex(workspace, path)) |index| {
            const staged_entry = stagedEntryAt(workspace, index);
            if (isDeleteTombstone(staged_entry.*)) {
                workspace.staging.staged_effective_entry_count += 1;
            }
            staged_entry.* = try Entry.init(path, object_id, version_id, object_type);
            return;
        }
        const adds_entry = findWorkspaceEntryIndex(workspace, path) == null;
        if (adds_entry) {
            if (workspace.staging.staged_effective_entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;
        }
        try insertSortedStagedEntry(workspace, try Entry.init(path, object_id, version_id, object_type));
        if (adds_entry) workspace.staging.staged_effective_entry_count += 1;
    }

    pub fn stageDelete(self: *Directory, workspace_id: ids.WorkspaceId, path: []const u8) Error!void {
        if (path.len > MAX_ENTRY_PATH_BYTES) return error.PathTooLong;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.staging.transaction_open) return error.NoActiveTransaction;
        const base_exists = findWorkspaceEntryIndex(workspace, path) != null;

        if (findStagedEntryIndex(workspace, path)) |index| {
            const staged_entry = stagedEntryAt(workspace, index);
            if (isDeleteTombstone(staged_entry.*)) return error.EntryNotFound;

            workspace.staging.staged_effective_entry_count -= 1;
            if (base_exists) {
                staged_entry.* = try deleteTombstone(path);
            } else {
                removeStagedEntry(workspace, index);
            }
            return;
        }

        if (!base_exists) return error.EntryNotFound;

        try insertSortedStagedEntry(workspace, try deleteTombstone(path));
        workspace.staging.staged_effective_entry_count -= 1;
    }

    pub fn commit(self: *Directory, workspace_id: ids.WorkspaceId, tick: u64) Error!u32 {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.staging.transaction_open) return error.NoActiveTransaction;

        try applyTransactionDelta(workspace);
        closeTransactionState(workspace);
        compactMutationLogIfSafe(workspace);
        self.markWorkspaceDirty(workspace_id);
        return workspace.generation;
    }

    fn compactMutationLogIfSafe(workspace: *WorkspaceRecord) void {
        if (workspace.counts.entry_mutation_count <= MUTATION_LOG_COMPACTION_THRESHOLD) return;
        if (workspace.oldest_snapshot_generation < workspace.generation) return;
        compactMutationLogToCurrentEntries(workspace) catch return;
    }

    pub fn share(self: *Directory, workspace_id: ids.WorkspaceId, request: ShareRequest) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (findShareGrantIndex(workspace, request.principal_id)) |grant_index| {
            workspace.share_table.share_grants[grant_index] = request;
            self.markWorkspaceDirty(workspace_id);
            return;
        }
        if (workspace.counts.share_grant_count >= MAX_SHARE_GRANTS) return error.ShareTableFull;
        const grant_index = workspace.counts.share_grant_count;
        workspace.share_table.share_grants[grant_index] = request;
        workspace.counts.share_grant_count += 1;
        indexShareGrant(workspace, grant_index);
        self.markWorkspaceDirty(workspace_id);
    }

    pub fn findShareGrant(
        self: *const Directory,
        workspace_id: ids.WorkspaceId,
        principal_id: principal.PrincipalId,
    ) ?ShareGrant {
        const workspace = self.lookupConst(workspace_id) orelse return null;
        return workspace.findShareGrant(principal_id);
    }

    pub fn hasAccess(self: *const Directory, workspace_id: ids.WorkspaceId, request: AccessRequest) bool {
        const workspace = self.lookupConst(workspace_id) orelse return false;
        return workspace.hasAccess(request);
    }

    pub fn hasAnyAccess(self: *const Directory, workspace_id: ids.WorkspaceId, request: AccessRequest) bool {
        const workspace = self.lookupConst(workspace_id) orelse return false;
        return workspace.hasAnyAccess(request);
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
        return (try self.resolveBorrowed(workspace_id, path)).*;
    }

    pub fn resolveBorrowed(self: *const Directory, workspace_id: ids.WorkspaceId, path: []const u8) Error!*const Entry {
        return self.resolveBorrowedWithPathHash(workspace_id, path, workspace_index.pathHash(path));
    }

    pub fn resolveBorrowedWithPathHash(self: *const Directory, workspace_id: ids.WorkspaceId, path: []const u8, path_hash: u64) Error!*const Entry {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        return workspace.resolveBorrowedWithPathHash(path, path_hash);
    }

    pub fn resolveObject(self: *const Directory, workspace_id: ids.WorkspaceId, object_id: ids.ObjectId) Error!Entry {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        const index = findWorkspaceEntryObjectIndex(workspace, object_id) orelse return error.EntryNotFound;
        return workspace.path_index.entries[index];
    }

    pub fn entries(self: *const Directory, workspace_id: ids.WorkspaceId) Error![]const Entry {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        return workspace.path_index.entries[0..workspace.counts.entry_count];
    }

    pub fn snapshot(
        self: *Directory,
        workspace_id: ids.WorkspaceId,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) Error!*SnapshotRecord {
        if (identity.label.len == 0) return error.UnsignedSnapshot;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        var label_copy: [MAX_WORKSPACE_LABEL_BYTES]u8 = [_]u8{0} ** MAX_WORKSPACE_LABEL_BYTES;
        const label_len = native_util.copyTextExact(&label_copy, label) catch return error.LabelTooLong;
        if (self.snapshotCount() >= MAX_SNAPSHOTS) return error.SnapshotTableFull;
        if (self.next_snapshot_id == 0) return error.SnapshotIdExhausted;

        const snapshot_id = ids.snapshot(self.next_snapshot_id);
        var snapshot_record = zeroSnapshot();
        snapshot_record.id = snapshot_id;
        snapshot_record.workspace_id = workspace.id;
        snapshot_record.generation = workspace.generation;
        snapshot_record.label = label_copy;
        snapshot_record.label_len = @intCast(label_len);
        const snapshot_entries = workspace.path_index.entries[0..workspace.counts.entry_count];
        snapshot_record.entry_count = @intCast(snapshot_entries.len);
        snapshot_record.root_address = workspace.path_index.root_address;
        signSnapshotRecord(&snapshot_record, snapshot_entries, identity) catch return error.InvalidSignature;

        const slot_index = self.snapshots.reserveIndex(snapshot_id) orelse return error.SnapshotTableFull;
        const slot = &self.snapshots.slots[slot_index];
        self.next_snapshot_id +%= 1;
        slot.snapshot = snapshot_record;
        self.snapshot_label_index.insert(snapshotLabelKey(slot.snapshot.workspace_id, slot.snapshot.labelSlice()), slot_index);
        self.recordWorkspaceSnapshotGeneration(slot.snapshot.workspace_id, slot.snapshot.generation);
        return &slot.snapshot;
    }

    pub fn restore(self: *Directory, workspace_id: ids.WorkspaceId, snapshot_id: ids.SnapshotId, tick: u64) Error!u32 {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (workspace.staging.transaction_open) return error.TransactionAlreadyOpen;
        const snapshot_record = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;
        if (!snapshot_record.workspace_id.eql(workspace_id)) return error.SnapshotNotFound;
        var materialized_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        const snapshot_entries = if (snapshot_record.generation == workspace.generation)
            workspace.path_index.entries[0..workspace.counts.entry_count]
        else blk: {
            const snapshot_entry_count = try materializeEntriesAtGeneration(workspace, snapshot_record.generation, &materialized_entries);
            break :blk materialized_entries[0..snapshot_entry_count];
        };
        if (snapshot_entries.len != snapshot_record.entry_count) return error.InvalidSignature;
        if (!verifySnapshotRecord(snapshot_record, snapshot_entries)) return error.InvalidSignature;

        try replaceCurrentEntriesWith(workspace, snapshot_entries);
        self.markWorkspaceDirty(workspace_id);
        return workspace.generation;
    }

    pub fn recoverDeleted(self: *Directory, workspace_id: ids.WorkspaceId, path: []const u8, tick: u64) Error!bool {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (workspace.staging.transaction_open) return error.TransactionAlreadyOpen;
        if (findWorkspaceEntryIndex(workspace, path) != null) return false;

        const deleted_entries = workspace.recoverable_deletes.entriesConst(workspace.counts.deleted_count);
        var index = workspace.counts.deleted_count;
        while (index > 0) {
            index -= 1;
            const entry = deleted_entries[index];
            if (!std.mem.eql(u8, entry.pathSlice(), path)) continue;
            if (workspace.counts.entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;
            if (workspace.counts.entry_mutation_count >= MAX_WORKSPACE_ENTRY_MUTATIONS) return error.EntryTableFull;

            workspace.generation += 1;
            try appendEntryMutation(workspace, workspace.generation, entry);
            try insertSortedEntry(&workspace.path_index.entries, &workspace.counts.entry_count, entry);
            rebuildWorkspaceEntryIndex(workspace);
            self.markWorkspaceDirty(workspace_id);
            return true;
        }

        return false;
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
        var materialized_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        const snapshot_entries = if (snapshot_record.generation == workspace.generation)
            workspace.path_index.entries[0..workspace.counts.entry_count]
        else blk: {
            const snapshot_entry_count = try materializeEntriesAtGeneration(workspace, snapshot_record.generation, &materialized_entries);
            break :blk materialized_entries[0..snapshot_entry_count];
        };
        if (snapshot_entries.len != snapshot_record.entry_count) return error.InvalidSignature;
        if (!verifySnapshotRecord(snapshot_record, snapshot_entries)) return error.InvalidSignature;

        out.* = zeroExportPackage();
        out.workspace_id = workspace_id;
        out.snapshot_id = snapshot_id;
        out.generation = snapshot_record.generation;
        out.root_address = snapshot_record.root_address;
        out.entry_count = @intCast(snapshot_entries.len);
        out.label_len = @intCast(native_util.copyTextExact(&out.label, snapshot_record.labelSlice()) catch return error.LabelTooLong);
        copyEntries(out.entries[0..snapshot_entries.len], snapshot_entries);
        signExportPackage(out, identity) catch return error.InvalidSignature;
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
        if (workspace.staging.transaction_open) return error.TransactionAlreadyOpen;
        try replaceCurrentEntriesWith(workspace, package.entries[0..package.entry_count]);
        self.markWorkspaceDirty(workspace_id);
        return workspace.generation;
    }

    pub fn dirtyWorkspaceIds(self: *const Directory) []const ids.WorkspaceId {
        return self.workspaces.dirtyIds();
    }

    pub fn dirtySnapshotIds(self: *const Directory) []const ids.SnapshotId {
        return self.snapshots.dirtyIds();
    }

    pub fn workspaceCount(self: *const Directory) usize {
        return self.workspaces.countInUse();
    }

    pub fn snapshotCount(self: *const Directory) usize {
        return self.snapshots.countInUse();
    }

    pub fn entryChangesSince(self: *const Directory, workspace_id: ids.WorkspaceId, generation: u32) Error![]const EntryMutation {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        const mutations = workspace.mutation_log.entriesConst();
        var start_index: usize = 0;
        while (start_index < workspace.counts.entry_mutation_count and mutations[start_index].generation <= generation) : (start_index += 1) {}
        return mutations[start_index..workspace.counts.entry_mutation_count];
    }

    pub fn clearDirty(self: *Directory) void {
        self.workspaces.clearDirty();
        self.snapshots.clearDirty();
    }

    fn lookupConst(self: *const Directory, workspace_id: ids.WorkspaceId) ?*const WorkspaceRecord {
        const slot = self.workspaces.getConst(workspace_id) orelse return null;
        return &slot.workspace;
    }

    fn markWorkspaceDirty(self: *Directory, workspace_id: ids.WorkspaceId) void {
        self.workspaces.markDirty(workspace_id);
    }

    fn recordWorkspaceSnapshotGeneration(self: *Directory, workspace_id: ids.WorkspaceId, generation: u32) void {
        const workspace = self.find(workspace_id) orelse return;
        recordSnapshotGeneration(workspace, generation);
    }

    fn indexWorkspace(self: *Directory, slot_index: usize) void {
        const slot = &self.workspaces.slots[slot_index];
        self.workspace_owner_label_index.insert(workspaceOwnerLabelKey(slot.workspace.owner, slot.workspace.labelSlice()), slot_index);
        if (!self.workspace_label_index.append(workspaceLabelKey(slot.workspace.labelSlice()), slot_index)) {
            native_util.impossibleByInvariant("workspace label index capacity covers workspace slots");
        }
    }

    fn lookupWorkspaceOwnerLabel(self: *Directory, lookup: WorkspaceLookup) ?*WorkspaceSlot {
        const slot_index = self.workspace_owner_label_index.lookup(workspaceOwnerLabelKey(lookup.owner, lookup.label)) orelse return null;
        return self.workspaceSlotAt(slot_index, lookup);
    }

    fn lookupWorkspaceOwnerLabelConst(self: *const Directory, lookup: WorkspaceLookup) ?*const WorkspaceSlot {
        const slot_index = self.workspace_owner_label_index.lookup(workspaceOwnerLabelKey(lookup.owner, lookup.label)) orelse return null;
        return self.workspaceSlotAtConst(slot_index, lookup);
    }

    fn lookupWorkspaceLabel(self: *Directory, label: []const u8) ?*WorkspaceSlot {
        var cursor = self.workspace_label_index.head(workspaceLabelKey(label));
        while (cursor != indexed_arena.no_index) : (cursor = self.workspace_label_index.next(cursor)) {
            if (cursor >= MAX_WORKSPACES) native_util.impossibleByInvariant("workspace label index points outside slots");
            const slot = &self.workspaces.slots[cursor];
            if (slot.in_use and workspaceSlotMatchesLabel(label, slot)) return slot;
        }
        return null;
    }

    fn lookupSnapshotLabel(self: *Directory, lookup: SnapshotLookup) ?*SnapshotSlot {
        const slot_index = self.snapshot_label_index.lookup(snapshotLabelKey(lookup.workspace_id, lookup.label)) orelse return null;
        return self.snapshotSlotAt(slot_index, lookup);
    }

    fn lookupSnapshotLabelConst(self: *const Directory, lookup: SnapshotLookup) ?*const SnapshotSlot {
        const slot_index = self.snapshot_label_index.lookup(snapshotLabelKey(lookup.workspace_id, lookup.label)) orelse return null;
        return self.snapshotSlotAtConst(slot_index, lookup);
    }

    fn workspaceSlotAt(self: *Directory, slot_index: usize, lookup: WorkspaceLookup) ?*WorkspaceSlot {
        if (slot_index >= MAX_WORKSPACES) native_util.impossibleByInvariant("workspace owner-label index points outside slots");
        const slot = &self.workspaces.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("workspace owner-label index points at a free slot");
        if (!workspaceSlotMatchesOwnerLabel(lookup, slot)) native_util.impossibleByInvariant("workspace owner-label index points at the wrong slot");
        return slot;
    }

    fn workspaceSlotAtConst(self: *const Directory, slot_index: usize, lookup: WorkspaceLookup) ?*const WorkspaceSlot {
        if (slot_index >= MAX_WORKSPACES) native_util.impossibleByInvariant("workspace owner-label index points outside slots");
        const slot = &self.workspaces.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("workspace owner-label index points at a free slot");
        if (!workspaceSlotMatchesOwnerLabel(lookup, slot)) native_util.impossibleByInvariant("workspace owner-label index points at the wrong slot");
        return slot;
    }

    fn snapshotSlotAt(self: *Directory, slot_index: usize, lookup: SnapshotLookup) ?*SnapshotSlot {
        if (slot_index >= MAX_SNAPSHOTS) native_util.impossibleByInvariant("snapshot label index points outside slots");
        const slot = &self.snapshots.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("snapshot label index points at a free slot");
        if (!snapshotSlotMatchesWorkspaceLabel(lookup, slot)) native_util.impossibleByInvariant("snapshot label index points at the wrong slot");
        return slot;
    }

    fn snapshotSlotAtConst(self: *const Directory, slot_index: usize, lookup: SnapshotLookup) ?*const SnapshotSlot {
        if (slot_index >= MAX_SNAPSHOTS) native_util.impossibleByInvariant("snapshot label index points outside slots");
        const slot = &self.snapshots.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("snapshot label index points at a free slot");
        if (!snapshotSlotMatchesWorkspaceLabel(lookup, slot)) native_util.impossibleByInvariant("snapshot label index points at the wrong slot");
        return slot;
    }
};

fn zeroWorkspace() WorkspaceRecord {
    return .{
        .id = ids.WorkspaceId.zero,
        .owner = .{ .kind = .service, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** MAX_WORKSPACE_LABEL_BYTES,
        .generation = 0,
        .counts = .{},
        .path_index = .{},
        .mutation_log = .{},
        .share_table = .{},
        .staging = .{},
        .recoverable_deletes = .{},
        .oldest_snapshot_generation = NO_SNAPSHOT_GENERATION,
    };
}

pub fn emptyWorkspaceRecord() WorkspaceRecord {
    return zeroWorkspace();
}

pub fn pathHash(path: []const u8) u64 {
    return workspace_index.pathHash(path);
}

pub fn workspaceRootAddress(entries: []const Entry) SnapshotRootAddress {
    return workspace_merkle.rootAddress(entries);
}

fn zeroSnapshot() SnapshotRecord {
    return .{
        .id = ids.SnapshotId.zero,
        .workspace_id = ids.WorkspaceId.zero,
        .generation = 0,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_WORKSPACE_LABEL_BYTES,
        .root_address = workspace_merkle.zeroRootAddress(),
        .signature = .{},
        .entry_count = 0,
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
        .label = [_]u8{0} ** MAX_WORKSPACE_LABEL_BYTES,
        .root_address = workspace_merkle.zeroRootAddress(),
        .signature = .{},
        .signature_format_len = 0,
        .signature_format_storage = [_]u8{0} ** MAX_EXPORT_SIGNATURE_FORMAT_BYTES,
        .signature_signer_len = 0,
        .signature_signer_storage = [_]u8{0} ** MAX_EXPORT_SIGNATURE_SIGNER_BYTES,
        .entry_count = 0,
        .entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
    };
}

pub fn emptyExportPackage() ExportPackage {
    return zeroExportPackage();
}

pub fn resetExportPackage(package: *ExportPackage) void {
    @memset(std.mem.asBytes(package), 0);
    package.signature.signer = "";
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
    const canonical_root_address = workspaceRootAddress(entries);
    if (!std.mem.eql(u8, &snapshot.root_address, &canonical_root_address)) {
        return error.InvalidSignature;
    }
    var message_buffer: [snapshot_message_buffer_bytes]u8 = undefined;
    const message = try snapshotMessage(
        &message_buffer,
        "snapshot",
        snapshot.workspace_id,
        snapshot.generation,
        snapshot.labelSlice(),
        snapshot.root_address,
        snapshot.entry_count,
    );
    snapshot.signature = try signing.sign(identity, message);
}

fn verifySnapshotRecord(snapshot: *const SnapshotRecord, entries: []const Entry) bool {
    if (!snapshot.signature.isPresent()) return false;
    const root_address = workspaceRootAddress(entries);
    if (!std.mem.eql(u8, &snapshot.root_address, &root_address)) return false;
    var message_buffer: [snapshot_message_buffer_bytes]u8 = undefined;
    const message = snapshotMessage(
        &message_buffer,
        "snapshot",
        snapshot.workspace_id,
        snapshot.generation,
        snapshot.labelSlice(),
        snapshot.root_address,
        snapshot.entry_count,
    ) catch return false;
    return signing.verify(snapshot.signature, message);
}

fn signExportPackage(package: *ExportPackage, identity: signing.SignerIdentity) !void {
    package.root_address = workspaceRootAddress(package.entries[0..@as(usize, package.entry_count)]);
    var message_buffer: [snapshot_message_buffer_bytes]u8 = undefined;
    const message = try snapshotMessage(
        &message_buffer,
        "export",
        package.workspace_id,
        package.generation,
        package.labelSlice(),
        package.root_address,
        package.entry_count,
    );
    package.signature = try signing.sign(identity, message);
    try persistExportPackageSignature(package);
}

fn verifyExportPackage(package: *const ExportPackage) bool {
    const signature = exportPackageSignature(package);
    if (!signature.isPresent()) return false;
    const root_address = workspaceRootAddress(package.entries[0..@as(usize, package.entry_count)]);
    if (!std.mem.eql(u8, &package.root_address, &root_address)) return false;
    var message_buffer: [snapshot_message_buffer_bytes]u8 = undefined;
    const message = snapshotMessage(
        &message_buffer,
        "export",
        package.workspace_id,
        package.generation,
        package.labelSlice(),
        package.root_address,
        package.entry_count,
    ) catch return false;
    return signing.verify(signature, message);
}

fn persistExportPackageSignature(package: *ExportPackage) Error!void {
    package.signature_format_len = @intCast(native_util.copyTextExact(&package.signature_format_storage, package.signature.formatSlice()) catch return error.SignatureFormatTooLong);
    package.signature_signer_len = @intCast(native_util.copyTextExact(&package.signature_signer_storage, package.signature.signer) catch return error.SignatureSignerTooLong);
    package.signature.format = manifest.parseSignatureFormat(package.signature_format_storage[0..@as(usize, package.signature_format_len)]);
    package.signature.signer = package.signature_signer_storage[0..@as(usize, package.signature_signer_len)];
}

fn exportPackageSignature(package: *const ExportPackage) manifest.Signature {
    var signature = package.signature;
    if (package.signature_format_len != 0) {
        signature.format = manifest.parseSignatureFormat(package.signature_format_storage[0..@as(usize, package.signature_format_len)]);
    }
    if (package.signature_signer_len != 0) {
        signature.signer = package.signature_signer_storage[0..@as(usize, package.signature_signer_len)];
    }
    return signature;
}

fn snapshotMessage(
    buffer: []u8,
    tag: []const u8,
    workspace_id: ids.WorkspaceId,
    generation: u32,
    label: []const u8,
    root_address: SnapshotRootAddress,
    entry_count: usize,
) error{NoSpaceLeft}![]const u8 {
    var writer = BinaryWriter{ .buffer = buffer };
    try writer.writeBytes("zigos.workspace.snapshot-root");
    try writeLengthPrefixed(&writer, tag);
    try writer.writeU64(workspace_id.raw());
    try writer.writeU32(generation);
    try writeLengthPrefixed(&writer, label);
    try writer.writeU16(@intCast(entry_count));
    try writer.writeBytes(&root_address);
    return buffer[0..writer.offset];
}

const BinaryWriter = binary_cursor.Writer(error{NoSpaceLeft}, error.NoSpaceLeft);

fn writeLengthPrefixed(writer: *BinaryWriter, bytes: []const u8) error{NoSpaceLeft}!void {
    if (bytes.len > std.math.maxInt(u16)) return error.NoSpaceLeft;
    try writer.writeU16(@intCast(bytes.len));
    try writer.writeBytes(bytes);
}

fn normalizeAndRebuildWorkspaceIndexes(workspace: *WorkspaceRecord) void {
    sortEntries(workspace.path_index.entries[0..workspace.counts.entry_count]);
    rebuildWorkspaceEntryIndex(workspace);
    rebuildShareGrantIndex(workspace);
    workspace.oldest_snapshot_generation = NO_SNAPSHOT_GENERATION;
}

fn recordSnapshotGeneration(workspace: *WorkspaceRecord, generation: u32) void {
    if (generation < workspace.oldest_snapshot_generation) {
        workspace.oldest_snapshot_generation = generation;
    }
}

fn rebuildShareGrantIndex(workspace: *WorkspaceRecord) void {
    workspace.share_table.share_grant_principal_index.reset();
    var grant_index: usize = 0;
    while (grant_index < workspace.counts.share_grant_count) : (grant_index += 1) {
        indexShareGrant(workspace, grant_index);
    }
}

fn indexShareGrant(workspace: *WorkspaceRecord, grant_index: usize) void {
    if (grant_index >= workspace.counts.share_grant_count) {
        native_util.impossibleByInvariant("share grant index points outside active grants");
    }
    const grant = workspace.share_table.share_grants[grant_index];
    if (!workspace.share_table.share_grant_principal_index.insert(grant.principal_id, grant_index)) {
        native_util.impossibleByInvariant("share grant index capacity covers share grant table");
    }
}

fn findShareGrantIndex(workspace: *const WorkspaceRecord, principal_id: principal.PrincipalId) ?usize {
    if (workspace.share_table.share_grant_principal_index.lookup(principal_id)) |grant_index| {
        if (grant_index >= MAX_SHARE_GRANTS) native_util.impossibleByInvariant("share grant index points outside grant slots");
        if (grant_index >= workspace.counts.share_grant_count) native_util.impossibleByInvariant("share grant index points outside active grants");
        const grant = workspace.share_table.share_grants[grant_index];
        if (!grant.principal_id.eql(principal_id)) native_util.impossibleByInvariant("share grant index points at the wrong grant");
        return grant_index;
    }
    debugAssertShareGrantIndexMissAbsent(workspace, principal_id);
    return null;
}

fn debugAssertShareGrantIndexMissAbsent(workspace: *const WorkspaceRecord, principal_id: principal.PrincipalId) void {
    if (!debugIndexChecksEnabled()) return;
    for (workspace.share_table.share_grants[0..workspace.counts.share_grant_count]) |grant| {
        if (grant.principal_id.eql(principal_id)) {
            native_util.impossibleByInvariant("share grant index missed a live grant");
        }
    }
}

fn rebuildWorkspaceEntryIndex(workspace: *WorkspaceRecord) void {
    debugAssertEntriesSorted(workspace.path_index.entries[0..workspace.counts.entry_count]);
    workspace_index.rebuildPathSlots(
        ENTRY_INDEX_CAPACITY,
        &workspace.path_index.path_slots,
        workspace.path_index.entries[0..workspace.counts.entry_count],
    );
    workspace_index.rebuildObjectSlots(
        ENTRY_OBJECT_INDEX_CAPACITY,
        &workspace.path_index.object_slots,
        workspace.path_index.entries[0..workspace.counts.entry_count],
    );
    workspace_merkle.rebuildPathMerkle(&workspace.path_index, workspace.counts.entry_count);
}

fn findWorkspaceEntryIndex(workspace: *const WorkspaceRecord, path: []const u8) ?usize {
    return findWorkspaceEntryIndexWithPathHash(workspace, path, workspace_index.pathHash(path));
}

fn findWorkspaceEntryIndexWithPathHash(workspace: *const WorkspaceRecord, path: []const u8, path_hash: u64) ?usize {
    const entries = workspace.path_index.entries[0..workspace.counts.entry_count];
    if (workspace_index.findIndexedEntryPathWithHash(ENTRY_INDEX_CAPACITY, &workspace.path_index.path_slots, entries, path, path_hash)) |index| return index;
    debugAssertPathIndexMissAbsent(entries, path);
    return null;
}

fn findWorkspaceEntryObjectIndex(workspace: *const WorkspaceRecord, object_id: ids.ObjectId) ?usize {
    const entries = workspace.path_index.entries[0..workspace.counts.entry_count];
    if (workspace_index.findIndexedEntryObject(ENTRY_OBJECT_INDEX_CAPACITY, &workspace.path_index.object_slots, entries, object_id)) |index| return index;
    debugAssertObjectIndexMissAbsent(entries, object_id);
    return null;
}

fn findStagedEntryIndex(workspace: *const WorkspaceRecord, path: []const u8) ?usize {
    var left: usize = 0;
    var right: usize = workspace.staging.staged_entry_count;
    while (left < right) {
        const middle = left + (right - left) / 2;
        switch (compareEntryPath(stagedEntryAtConst(workspace, middle).pathSlice(), path)) {
            .lt => left = middle + 1,
            .eq => return middle,
            .gt => right = middle,
        }
    }
    return null;
}

fn stagedEntryAt(workspace: *WorkspaceRecord, staged_index: usize) *Entry {
    return &workspace.mutation_log.entries()[stagedMutationIndex(workspace, staged_index)].entry;
}

fn stagedEntryAtConst(workspace: *const WorkspaceRecord, staged_index: usize) *const Entry {
    return &workspace.mutation_log.entriesConst()[stagedMutationIndex(workspace, staged_index)].entry;
}

fn stagedMutationIndex(workspace: *const WorkspaceRecord, staged_index: usize) usize {
    const mutation_index = workspace.counts.entry_mutation_count + staged_index;
    if (staged_index >= @as(usize, workspace.staging.staged_entry_count) or mutation_index >= MAX_WORKSPACE_ENTRY_MUTATIONS) {
        native_util.impossibleByInvariant("staged workspace entry occupies the unused mutation-log tail");
    }
    return mutation_index;
}

fn insertSortedStagedEntry(workspace: *WorkspaceRecord, entry: Entry) Error!void {
    const staged_count: usize = workspace.staging.staged_entry_count;
    if (staged_count >= MAX_WORKSPACE_ENTRIES or
        workspace.counts.entry_mutation_count + staged_count >= MAX_WORKSPACE_ENTRY_MUTATIONS)
    {
        return error.EntryTableFull;
    }

    var insert_index: usize = 0;
    while (insert_index < staged_count and compareEntryPath(stagedEntryAtConst(workspace, insert_index).pathSlice(), entry.pathSlice()) == .lt) : (insert_index += 1) {}
    if (insert_index < staged_count and compareEntryPath(stagedEntryAtConst(workspace, insert_index).pathSlice(), entry.pathSlice()) == .eq) {
        return error.DuplicatePath;
    }

    const base_index = workspace.counts.entry_mutation_count;
    const mutations = workspace.mutation_log.entries();
    var move_index = staged_count;
    while (move_index > insert_index) : (move_index -= 1) {
        mutations[base_index + move_index] = mutations[base_index + move_index - 1];
    }
    mutations[base_index + insert_index] = .{ .entry = entry };
    workspace.staging.staged_entry_count += 1;
}

fn removeStagedEntry(workspace: *WorkspaceRecord, staged_index: usize) void {
    const staged_count: usize = workspace.staging.staged_entry_count;
    if (staged_index >= staged_count) native_util.impossibleByInvariant("staged workspace entry removal stays within the transaction");
    const base_index = workspace.counts.entry_mutation_count;
    const mutations = workspace.mutation_log.entries();
    var move_index = staged_index + 1;
    while (move_index < staged_count) : (move_index += 1) {
        mutations[base_index + move_index - 1] = mutations[base_index + move_index];
    }
    mutations[base_index + staged_count - 1] = .{};
    workspace.staging.staged_entry_count -= 1;
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

fn debugAssertObjectIndexMissAbsent(entries: []const Entry, object_id: ids.ObjectId) void {
    if (!debugIndexChecksEnabled()) return;
    for (entries) |entry| {
        if (entry.object_id.eql(object_id)) {
            native_util.impossibleByInvariant("workspace object index missed a live entry");
        }
    }
}

fn debugAssertPathIndexMissAbsent(entries: []const Entry, path: []const u8) void {
    if (!debugIndexChecksEnabled()) return;
    if (findEntryIndex(entries, path) != null) {
        native_util.impossibleByInvariant("workspace path index missed a live entry");
    }
}

fn removeEntry(entries: *[MAX_WORKSPACE_ENTRIES]Entry, count: anytype, index: usize) void {
    var active_count: usize = @intCast(count.*);
    var cursor = index;
    while (cursor + 1 < active_count) : (cursor += 1) {
        entries[cursor] = entries[cursor + 1];
    }
    active_count -= 1;
    count.* = @intCast(active_count);
    entries[active_count] = Entry{};
}

fn insertSortedEntry(entries: *[MAX_WORKSPACE_ENTRIES]Entry, count: anytype, entry: Entry) Error!void {
    const active_count: usize = @intCast(count.*);
    if (active_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;
    const insert_index = lowerBoundEntry(entries[0..active_count], entry.pathSlice());
    if (insert_index < active_count and compareEntryPath(entries[insert_index].pathSlice(), entry.pathSlice()) == .eq) {
        entries[insert_index] = entry;
        return;
    }

    var cursor = active_count;
    while (cursor > insert_index) : (cursor -= 1) {
        entries[cursor] = entries[cursor - 1];
    }
    entries[insert_index] = entry;
    count.* = @intCast(active_count + 1);
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
    const deleted_entries = workspace.recoverable_deletes.entries();
    if (workspace.counts.deleted_count < MAX_RECOVERABLE_DELETES) {
        deleted_entries[workspace.counts.deleted_count] = entry;
        workspace.counts.deleted_count += 1;
        return;
    }

    var index: usize = 1;
    while (index < MAX_RECOVERABLE_DELETES) : (index += 1) {
        deleted_entries[index - 1] = deleted_entries[index];
    }
    deleted_entries[MAX_RECOVERABLE_DELETES - 1] = entry;
}

fn appendEntryMutation(workspace: *WorkspaceRecord, generation: u32, entry: Entry) Error!void {
    if (workspace.counts.entry_mutation_count >= MAX_WORKSPACE_ENTRY_MUTATIONS) return error.EntryTableFull;
    workspace.mutation_log.entries()[workspace.counts.entry_mutation_count] = .{
        .generation = generation,
        .entry = entry,
    };
    workspace.counts.entry_mutation_count += 1;
}

fn seedWorkspaceEntries(workspace: *WorkspaceRecord, source_entries: []const Entry, generation: u32) Error!void {
    workspace.counts.entry_count = 0;
    workspace.counts.entry_mutation_count = 0;
    workspace.path_index.path_slots = workspace_index.emptyEntryIndexTable(ENTRY_INDEX_CAPACITY);
    workspace.path_index.object_slots = workspace_index.emptyEntryObjectIndexTable(ENTRY_OBJECT_INDEX_CAPACITY);
    clearEntries(&workspace.path_index.entries);
    for (workspace.mutation_log.entries()) |*mutation| {
        mutation.* = EntryMutation{};
    }

    for (source_entries) |entry| {
        if (isDeleteTombstone(entry)) continue;
        try insertSortedEntry(&workspace.path_index.entries, &workspace.counts.entry_count, entry);
        try appendEntryMutation(workspace, generation, entry);
    }
    rebuildWorkspaceEntryIndex(workspace);
}

fn compactMutationLogToCurrentEntries(workspace: *WorkspaceRecord) Error!void {
    var current_entries: [MAX_WORKSPACE_ENTRIES]Entry = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
    const count = workspace.counts.entry_count;
    for (workspace.path_index.entries[0..count], 0..) |entry, index| {
        current_entries[index] = entry;
    }

    try seedWorkspaceEntries(workspace, current_entries[0..count], workspace.generation);
}

fn materializeEntriesAtGeneration(
    workspace: *const WorkspaceRecord,
    generation: u32,
    out: *[MAX_WORKSPACE_ENTRIES]Entry,
) Error!usize {
    clearEntries(out);
    var out_count: usize = 0;
    for (workspace.mutation_log.entriesConst()[0..workspace.counts.entry_mutation_count]) |mutation| {
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
    var deletion_needed = false;
    var current_index: usize = 0;
    var target_index: usize = 0;
    while (current_index < workspace.counts.entry_count or target_index < target_count) {
        if (current_index >= workspace.counts.entry_count) {
            mutation_count_needed += 1;
            target_index += 1;
            continue;
        }
        if (target_index >= target_count) {
            mutation_count_needed += 1;
            deletion_needed = true;
            current_index += 1;
            continue;
        }

        switch (compareEntryPath(workspace.path_index.entries[current_index].pathSlice(), target_entries[target_index].pathSlice())) {
            .lt => {
                mutation_count_needed += 1;
                deletion_needed = true;
                current_index += 1;
            },
            .gt => {
                mutation_count_needed += 1;
                target_index += 1;
            },
            .eq => {
                if (!entryContentEql(workspace.path_index.entries[current_index], target_entries[target_index])) {
                    mutation_count_needed += 1;
                }
                current_index += 1;
                target_index += 1;
            },
        }
    }
    if (workspace.counts.entry_mutation_count + mutation_count_needed > MAX_WORKSPACE_ENTRY_MUTATIONS) return error.EntryTableFull;
    if (deletion_needed) try workspace.recoverable_deletes.ensureBacking();

    const next_generation = workspace.generation + 1;
    current_index = 0;
    target_index = 0;
    while (current_index < workspace.counts.entry_count or target_index < target_count) {
        if (current_index >= workspace.counts.entry_count) {
            const target_entry = target_entries[target_index];
            try insertSortedEntry(&workspace.path_index.entries, &workspace.counts.entry_count, target_entry);
            try appendEntryMutation(workspace, next_generation, target_entry);
            current_index += 1;
            target_index += 1;
            continue;
        }
        if (target_index >= target_count) {
            const deleted_entry = workspace.path_index.entries[current_index];
            appendDeleted(workspace, deleted_entry);
            try appendEntryMutation(workspace, next_generation, try deleteTombstone(deleted_entry.pathSlice()));
            removeEntry(&workspace.path_index.entries, &workspace.counts.entry_count, current_index);
            continue;
        }

        const current_entry = workspace.path_index.entries[current_index];
        const target_entry = target_entries[target_index];
        switch (compareEntryPath(current_entry.pathSlice(), target_entry.pathSlice())) {
            .lt => {
                appendDeleted(workspace, current_entry);
                try appendEntryMutation(workspace, next_generation, try deleteTombstone(current_entry.pathSlice()));
                removeEntry(&workspace.path_index.entries, &workspace.counts.entry_count, current_index);
            },
            .gt => {
                try insertSortedEntry(&workspace.path_index.entries, &workspace.counts.entry_count, target_entry);
                try appendEntryMutation(workspace, next_generation, target_entry);
                current_index += 1;
                target_index += 1;
            },
            .eq => {
                if (!entryContentEql(current_entry, target_entry)) {
                    workspace.path_index.entries[current_index] = target_entry;
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
    debugAssertEntriesSorted(workspace.path_index.entries[0..workspace.counts.entry_count]);
    if (workspace.counts.entry_mutation_count + @as(usize, workspace.staging.staged_entry_count) > MAX_WORKSPACE_ENTRY_MUTATIONS) return error.EntryTableFull;
    const next_generation = workspace.generation + 1;
    const staged_entry_start = workspace.counts.entry_mutation_count;
    const staged_entry_count: usize = workspace.staging.staged_entry_count;
    const mutations = workspace.mutation_log.entries();
    for (mutations[staged_entry_start .. staged_entry_start + staged_entry_count]) |mutation| {
        if (!isDeleteTombstone(mutation.entry)) continue;
        try workspace.recoverable_deletes.ensureBacking();
        break;
    }
    var structural_change = false;
    var object_index_dirty = false;
    for (0..staged_entry_count) |staged_index| {
        const staged_entry = mutations[staged_entry_start + staged_index].entry;
        if (isDeleteTombstone(staged_entry)) {
            const existing_index = findEntryIndex(workspace.path_index.entries[0..workspace.counts.entry_count], staged_entry.pathSlice()) orelse return error.EntryNotFound;
            appendDeleted(workspace, workspace.path_index.entries[existing_index]);
            removeEntry(&workspace.path_index.entries, &workspace.counts.entry_count, existing_index);
            structural_change = true;
            try appendEntryMutation(workspace, next_generation, staged_entry);
            continue;
        }

        if (findEntryIndex(workspace.path_index.entries[0..workspace.counts.entry_count], staged_entry.pathSlice())) |existing_index| {
            object_index_dirty = object_index_dirty or
                !workspace.path_index.entries[existing_index].object_id.eql(staged_entry.object_id);
            workspace.path_index.entries[existing_index] = staged_entry;
            workspace_merkle.updatePathLeaf(&workspace.path_index, existing_index);
        } else {
            try insertSortedEntry(&workspace.path_index.entries, &workspace.counts.entry_count, staged_entry);
            structural_change = true;
        }
        try appendEntryMutation(workspace, next_generation, staged_entry);
    }
    workspace.generation = next_generation;
    if (structural_change) {
        rebuildWorkspaceEntryIndex(workspace);
    } else if (workspace.staging.staged_entry_count != 0) {
        if (object_index_dirty) {
            workspace_index.rebuildObjectSlots(
                ENTRY_OBJECT_INDEX_CAPACITY,
                &workspace.path_index.object_slots,
                workspace.path_index.entries[0..workspace.counts.entry_count],
            );
        }
        workspace_merkle.refreshPathRoot(&workspace.path_index, workspace.counts.entry_count);
    }
}

fn discardTransactionState(workspace: *WorkspaceRecord) void {
    const staged_entry_start = workspace.counts.entry_mutation_count;
    const staged_entry_end = @min(staged_entry_start + @as(usize, workspace.staging.staged_entry_count), MAX_WORKSPACE_ENTRY_MUTATIONS);
    for (workspace.mutation_log.entries()[staged_entry_start..staged_entry_end]) |*mutation| {
        mutation.* = .{};
    }
    closeTransactionState(workspace);
}

fn closeTransactionState(workspace: *WorkspaceRecord) void {
    workspace.staging.transaction_open = false;
    workspace.staging.staged_entry_count = 0;
    workspace.staging.staged_effective_entry_count = 0;
}

test "workspace staging metadata stays compact" {
    try std.testing.expectEqual(u8, @FieldType(WorkspaceStagingState, "staged_entry_count"));
    try std.testing.expectEqual(u8, @FieldType(WorkspaceStagingState, "staged_effective_entry_count"));
    try std.testing.expectEqual(@as(usize, 3), @sizeOf(WorkspaceStagingState));
}

test "workspace snapshot and export metadata stay compact" {
    try std.testing.expectEqual(u8, @FieldType(SnapshotRecord, "label_len"));
    try std.testing.expectEqual(u8, @FieldType(SnapshotRecord, "entry_count"));
    try std.testing.expectEqual(@as(usize, 224), @sizeOf(SnapshotRecord));
    try std.testing.expectEqual(@as(usize, 232), @sizeOf(SnapshotSlot));
    try std.testing.expectEqual(u8, @FieldType(ExportPackage, "label_len"));
    try std.testing.expectEqual(u8, @FieldType(ExportPackage, "entry_count"));
    try std.testing.expectEqual(u8, @FieldType(ExportPackage, "signature_format_len"));
    try std.testing.expectEqual(u8, @FieldType(ExportPackage, "signature_signer_len"));
    try std.testing.expectEqual(@as(usize, 11_808), @sizeOf(ExportPackage));
}

test "workspace label metadata stays compact" {
    try std.testing.expectEqual(u8, @FieldType(WorkspaceRecord, "label_len"));
}

test "workspace table counts share compact resident metadata" {
    try std.testing.expect(COMPACT_WORKSPACE_TABLE_METADATA);
    try std.testing.expectEqual(WorkspaceEntryCount, @FieldType(WorkspaceTableCounts, "entry_count"));
    try std.testing.expectEqual(WorkspaceMutationCount, @FieldType(WorkspaceTableCounts, "entry_mutation_count"));
    try std.testing.expectEqual(WorkspaceShareGrantCount, @FieldType(WorkspaceTableCounts, "share_grant_count"));
    try std.testing.expectEqual(RecoverableDeleteCount, @FieldType(WorkspaceTableCounts, "deleted_count"));
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(WorkspaceTableCounts));
}

test "workspace recoverable deletion history uses on-demand freestanding backing" {
    try std.testing.expect(recoverable_delete_layout.heap_backs_log_on_freestanding);
    try std.testing.expectEqual(@sizeOf(?*anyopaque), recoverable_delete_layout.freestanding_handle_size_bytes);
    try std.testing.expectEqual(@as(usize, 2_880), recoverable_delete_layout.backing_size_bytes);
}

fn debugIndexChecksEnabled() bool {
    return builtin.mode == .Debug;
}

test "workspace sharing uses capacity-sized resident indexes" {
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(ShareGrantPrincipalIndexSlot));
    try std.testing.expectEqual(@as(usize, 384), @sizeOf(ShareGrantPrincipalIndex));
    try std.testing.expectEqual(@as(usize, 1_472), @sizeOf(WorkspaceShareTable));
    try std.testing.expectEqual(@as(usize, 43_928), @sizeOf(WorkspaceRecord));
    try std.testing.expectEqual(@as(usize, 43_936), @sizeOf(WorkspaceSlot));
    try std.testing.expectEqual(@as(usize, 357_400), @sizeOf(Directory));
}

test "workspace borrowed resolution returns the directory owned entry" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .app, .serial = 1 },
        .label = "borrowed-resolution",
    });
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/note.md", ids.object(7), ids.version(11), .document);
    _ = try directory.commit(workspace.id, 1);

    const borrowed = try directory.resolveBorrowed(workspace.id, "documents/note.md");
    const stored_workspace = directory.findConst(workspace.id).?;
    try std.testing.expect(borrowed == &stored_workspace.path_index.entries[0]);
    try std.testing.expectEqual(ids.object(7), borrowed.object_id);
    try std.testing.expectEqual(ids.version(11), borrowed.version_id);
    try std.testing.expectEqual(borrowed.*, try directory.resolve(workspace.id, "documents/note.md"));
}

test "workspace commits preserve path order and index rebuilds normalize loaded entries" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .app, .serial = 1 },
        .label = "sorted-index",
    });

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "z-last", ids.object(1), ids.version(1), .document);
    try directory.stagePut(workspace.id, "a-first", ids.object(2), ids.version(2), .document);
    try directory.stagePut(workspace.id, "m-middle", ids.object(3), ids.version(3), .document);
    _ = try directory.commit(workspace.id, 1);

    var entries = try directory.entries(workspace.id);
    try std.testing.expectEqualStrings("a-first", entries[0].pathSlice());
    try std.testing.expectEqualStrings("m-middle", entries[1].pathSlice());
    try std.testing.expectEqualStrings("z-last", entries[2].pathSlice());

    std.mem.swap(Entry, &workspace.path_index.entries[0], &workspace.path_index.entries[2]);
    workspace.path_index.path_slots = workspace_index.emptyEntryIndexTable(ENTRY_INDEX_CAPACITY);
    workspace.path_index.object_slots = workspace_index.emptyEntryObjectIndexTable(ENTRY_OBJECT_INDEX_CAPACITY);
    const zero_root = workspace_merkle.zeroRootAddress();
    for (workspace.path_index.leaf_hashes[0..workspace.counts.entry_count]) |*leaf_hash| {
        leaf_hash.* = zero_root;
    }
    workspace.path_index.root_address = zero_root;
    directory.rebuildDerivedIndexes();

    entries = try directory.entries(workspace.id);
    try std.testing.expectEqualStrings("a-first", entries[0].pathSlice());
    try std.testing.expectEqualStrings("m-middle", entries[1].pathSlice());
    try std.testing.expectEqualStrings("z-last", entries[2].pathSlice());
    try std.testing.expectEqual(
        @as(?usize, 0),
        workspace_index.findIndexedEntryPath(ENTRY_INDEX_CAPACITY, &workspace.path_index.path_slots, entries, "a-first"),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        workspace_index.findIndexedEntryPath(ENTRY_INDEX_CAPACITY, &workspace.path_index.path_slots, entries, "m-middle"),
    );
    try std.testing.expectEqual(
        @as(?usize, 2),
        workspace_index.findIndexedEntryPath(ENTRY_INDEX_CAPACITY, &workspace.path_index.path_slots, entries, "z-last"),
    );
    try std.testing.expectEqual(
        @as(?usize, 0),
        workspace_index.findIndexedEntryObject(ENTRY_OBJECT_INDEX_CAPACITY, &workspace.path_index.object_slots, entries, ids.object(2)),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        workspace_index.findIndexedEntryObject(ENTRY_OBJECT_INDEX_CAPACITY, &workspace.path_index.object_slots, entries, ids.object(3)),
    );
    try std.testing.expectEqual(
        @as(?usize, 2),
        workspace_index.findIndexedEntryObject(ENTRY_OBJECT_INDEX_CAPACITY, &workspace.path_index.object_slots, entries, ids.object(1)),
    );
    try std.testing.expectEqual(ids.object(2), (try directory.resolve(workspace.id, "a-first")).object_id);
    try std.testing.expectEqual(ids.object(1), (try directory.resolve(workspace.id, "z-last")).object_id);
    try std.testing.expectEqualStrings("a-first", (try directory.resolveObject(workspace.id, ids.object(2))).pathSlice());
    try std.testing.expectEqualStrings("m-middle", (try directory.resolveObject(workspace.id, ids.object(3))).pathSlice());
    try std.testing.expectEqualStrings("z-last", (try directory.resolveObject(workspace.id, ids.object(1))).pathSlice());
    try std.testing.expectEqual(workspaceRootAddress(entries), workspace.rootAddress());
    try std.testing.expect(!std.mem.eql(u8, &workspace.path_index.root_address, &zero_root));
}

fn debugAssertEntriesSorted(entries: []const Entry) void {
    if (!debugIndexChecksEnabled() or entries.len < 2) return;
    for (entries[1..], entries[0 .. entries.len - 1]) |entry, previous| {
        if (compareEntryPath(previous.pathSlice(), entry.pathSlice()) != .lt) {
            native_util.impossibleByInvariant("workspace entries remain strictly path-sorted");
        }
    }
}

test "directory reset scrubs live workspace and snapshot records" {
    var directory = Directory.init();

    const workspace_slot_index = directory.workspaces.reserveIndex(ids.workspace(7)).?;
    const workspace_slot = &directory.workspaces.slots[workspace_slot_index];
    workspace_slot.workspace.id = ids.workspace(7);
    workspace_slot.workspace.label_len = 6;
    @memcpy(workspace_slot.workspace.label[0..6], "secret");
    workspace_slot.workspace.counts.entry_count = 1;
    workspace_slot.workspace.path_index.entries[0] = try Entry.init("secret", ids.object(8), ids.version(9), .document);

    const snapshot_slot_index = directory.snapshots.reserveIndex(ids.snapshot(10)).?;
    const snapshot_slot = &directory.snapshots.slots[snapshot_slot_index];
    snapshot_slot.snapshot.id = ids.snapshot(10);
    snapshot_slot.snapshot.label_len = 6;
    @memcpy(snapshot_slot.snapshot.label[0..6], "secret");

    directory.reset();

    try std.testing.expectEqual(@as(usize, 0), directory.workspaces.countInUse());
    try std.testing.expectEqual(@as(usize, 0), directory.snapshots.countInUse());
    try std.testing.expect(workspace_slot.workspace.id.isZero());
    try std.testing.expectEqual(@as(usize, 0), workspace_slot.workspace.label_len);
    try std.testing.expectEqual(@as(usize, 0), workspace_slot.workspace.counts.entry_count);
    try std.testing.expectEqual(@as(usize, 0), snapshot_slot.snapshot.label_len);
}
