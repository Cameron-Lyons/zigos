const std = @import("std");
const manifest = @import("manifest.zig");
const object_store = @import("object_store.zig");
const principal = @import("principal.zig");
const signing = @import("signing.zig");

pub const MAX_WORKSPACES: usize = 8;
pub const MAX_WORKSPACE_ENTRIES: usize = 24;
pub const MAX_SNAPSHOTS: usize = 16;
pub const MAX_RECOVERABLE_DELETES: usize = 24;
pub const MAX_ENTRY_PATH_BYTES: usize = 96;
pub const MAX_SHARE_GRANTS: usize = 8;

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
        return self.path[0..self.path_len];
    }
};

pub const CreateRequest = struct {
    owner: principal.PrincipalId,
    label: []const u8,
};

pub const ShareGrant = struct {
    principal_id: principal.PrincipalId,
    can_read: bool = true,
    can_write: bool = false,
    can_export: bool = false,
    local_only: bool = false,
};

pub const ShareRequest = ShareGrant;

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
        return self.label[0..self.label_len];
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
    entry_count: usize,
    entries: [MAX_WORKSPACE_ENTRIES]Entry,

    pub fn labelSlice(self: *const ExportPackage) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn signerSlice(self: *const ExportPackage) []const u8 {
        return self.signature.signer;
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
    share_grant_count: usize,
    share_grants: [MAX_SHARE_GRANTS]ShareGrant,
    transaction_open: bool,
    staged_entry_count: usize,
    staged_entries: [MAX_WORKSPACE_ENTRIES]Entry,
    deleted_count: usize,
    deleted_entries: [MAX_RECOVERABLE_DELETES]Entry,

    pub fn labelSlice(self: *const WorkspaceRecord) []const u8 {
        return self.label[0..self.label_len];
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

pub const Directory = struct {
    next_workspace_id: u64 = 1,
    next_snapshot_id: u64 = 1,
    workspaces: [MAX_WORKSPACES]WorkspaceSlot = [_]WorkspaceSlot{WorkspaceSlot{}} ** MAX_WORKSPACES,
    snapshots: [MAX_SNAPSHOTS]SnapshotSlot = [_]SnapshotSlot{SnapshotSlot{}} ** MAX_SNAPSHOTS,

    pub fn init() Directory {
        return .{};
    }

    pub fn reset(self: *Directory) void {
        self.next_workspace_id = 1;
        self.next_snapshot_id = 1;
        for (&self.workspaces) |*slot| {
            slot.* = .{};
        }
        for (&self.snapshots) |*slot| {
            slot.* = .{};
        }
    }

    pub fn create(self: *Directory, request: CreateRequest) Error!*WorkspaceRecord {
        for (&self.workspaces) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.workspace = zeroWorkspace();
            slot.workspace.id = self.nextWorkspaceId();
            slot.workspace.owner = request.owner;
            slot.workspace.label_len = copyText(&slot.workspace.label, request.label);
            return &slot.workspace;
        }
        return error.WorkspaceTableFull;
    }

    pub fn find(self: *Directory, workspace_id: u64) ?*WorkspaceRecord {
        for (&self.workspaces) |*slot| {
            if (slot.in_use and slot.workspace.id == workspace_id) return &slot.workspace;
        }
        return null;
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
        workspace.staged_entry_count = workspace.entry_count;
        workspace.staged_entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        copyEntries(
            workspace.staged_entries[0..workspace.entry_count],
            workspace.entries[0..workspace.entry_count],
        );
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

        if (findEntryIndex(workspace.staged_entries[0..workspace.staged_entry_count], path)) |index| {
            workspace.staged_entries[index] = Entry.init(path, object_id, version_id, object_type);
            return;
        }
        if (workspace.staged_entry_count >= MAX_WORKSPACE_ENTRIES) return error.EntryTableFull;

        workspace.staged_entries[workspace.staged_entry_count] = Entry.init(path, object_id, version_id, object_type);
        workspace.staged_entry_count += 1;
    }

    pub fn stageDelete(self: *Directory, workspace_id: u64, path: []const u8) Error!void {
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.transaction_open) return error.NoActiveTransaction;
        const index = findEntryIndex(workspace.staged_entries[0..workspace.staged_entry_count], path) orelse return error.EntryNotFound;
        removeEntry(&workspace.staged_entries, &workspace.staged_entry_count, index);
    }

    pub fn commit(self: *Directory, workspace_id: u64, tick: u64) Error!u32 {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        if (!workspace.transaction_open) return error.NoActiveTransaction;

        recordDeletedEntries(workspace);
        workspace.entry_count = workspace.staged_entry_count;
        workspace.entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        copyEntries(
            workspace.entries[0..workspace.entry_count],
            workspace.staged_entries[0..workspace.entry_count],
        );
        workspace.staged_entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        workspace.staged_entry_count = 0;
        workspace.transaction_open = false;
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

    pub fn hasAccess(
        self: *const Directory,
        workspace_id: u64,
        principal_id: principal.PrincipalId,
        wants_write: bool,
        wants_export: bool,
        local_only: bool,
    ) bool {
        const workspace = self.lookupConst(workspace_id) orelse return false;
        if (workspace.owner.eql(principal_id)) return true;

        for (workspace.share_grants[0..workspace.share_grant_count]) |grant| {
            if (!grant.principal_id.eql(principal_id)) continue;
            if (local_only and !grant.local_only) continue;
            if (wants_write and !grant.can_write) continue;
            if (wants_export and !grant.can_export) continue;
            if (!wants_write and !grant.can_read) continue;
            return true;
        }
        return false;
    }

    pub fn resolve(self: *const Directory, workspace_id: u64, path: []const u8) Error!Entry {
        const workspace = self.lookupConst(workspace_id) orelse return error.WorkspaceNotFound;
        const index = findEntryIndex(workspace.entries[0..workspace.entry_count], path) orelse return error.EntryNotFound;
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

        for (&self.snapshots) |*slot| {
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
            return &slot.snapshot;
        }

        return error.SnapshotTableFull;
    }

    pub fn restore(self: *Directory, workspace_id: u64, snapshot_id: u64, tick: u64) Error!u32 {
        _ = tick;
        const workspace = self.find(workspace_id) orelse return error.WorkspaceNotFound;
        const snapshot_record = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;
        if (snapshot_record.workspace_id != workspace_id) return error.SnapshotNotFound;
        if (!verifySnapshotRecord(snapshot_record.*)) return error.InvalidSignature;

        var staged = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        copyEntries(staged[0..snapshot_record.entry_count], snapshot_record.entries[0..snapshot_record.entry_count]);
        recordDeletedEntriesAgainst(workspace, staged[0..snapshot_record.entry_count]);

        workspace.entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        workspace.entry_count = snapshot_record.entry_count;
        copyEntries(
            workspace.entries[0..snapshot_record.entry_count],
            snapshot_record.entries[0..snapshot_record.entry_count],
        );
        workspace.transaction_open = false;
        workspace.staged_entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES;
        workspace.staged_entry_count = 0;
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
        if (identity.label.len == 0) return error.UnsignedExport;
        const snapshot_record = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;
        if (snapshot_record.workspace_id != workspace_id) return error.SnapshotNotFound;
        if (!verifySnapshotRecord(snapshot_record.*)) return error.InvalidSignature;

        var package = ExportPackage{
            .workspace_id = workspace_id,
            .snapshot_id = snapshot_id,
            .generation = snapshot_record.generation,
            .label_len = 0,
            .label = [_]u8{0} ** 48,
            .signature = .{},
            .entry_count = snapshot_record.entry_count,
            .entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
        };
        package.label_len = copyText(&package.label, snapshot_record.labelSlice());
        copyEntries(package.entries[0..snapshot_record.entry_count], snapshot_record.entries[0..snapshot_record.entry_count]);
        signExportPackage(&package, identity) catch return error.InvalidSignature;
        return package;
    }

    pub fn importWorkspace(
        self: *Directory,
        owner: principal.PrincipalId,
        label: []const u8,
        package: ExportPackage,
        tick: u64,
    ) Error!*WorkspaceRecord {
        _ = tick;
        if (!package.signature.isPresent()) return error.UnsignedExport;
        if (!verifyExportPackage(package)) return error.InvalidSignature;
        const workspace = try self.create(.{
            .owner = owner,
            .label = label,
        });
        workspace.generation = package.generation;
        workspace.entry_count = package.entry_count;
        copyEntries(workspace.entries[0..package.entry_count], package.entries[0..package.entry_count]);
        return workspace;
    }

    fn lookupConst(self: *const Directory, workspace_id: u64) ?*const WorkspaceRecord {
        for (&self.workspaces) |*slot| {
            if (slot.in_use and slot.workspace.id == workspace_id) return &slot.workspace;
        }
        return null;
    }

    fn findSnapshot(self: *Directory, snapshot_id: u64) ?*SnapshotRecord {
        for (&self.snapshots) |*slot| {
            if (slot.in_use and slot.snapshot.id == snapshot_id) return &slot.snapshot;
        }
        return null;
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
        .share_grant_count = 0,
        .share_grants = [_]ShareGrant{ShareGrant{
            .principal_id = .{ .kind = .service, .serial = 0 },
        }} ** MAX_SHARE_GRANTS,
        .transaction_open = false,
        .staged_entry_count = 0,
        .staged_entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
        .deleted_count = 0,
        .deleted_entries = [_]Entry{Entry{}} ** MAX_RECOVERABLE_DELETES,
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

fn copyEntries(dest: []Entry, src: []const Entry) void {
    for (src, 0..) |entry, index| {
        dest[index] = entry;
    }
}

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
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

fn verifySnapshotRecord(snapshot: SnapshotRecord) bool {
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
}

fn verifyExportPackage(package: ExportPackage) bool {
    if (!package.signature.isPresent()) return false;
    var message_buffer: [4096]u8 = undefined;
    const message = snapshotMessage(
        &message_buffer,
        "export",
        package.workspace_id,
        package.generation,
        package.labelSlice(),
        package.entries[0..package.entry_count],
    ) catch return false;
    return signing.verify(package.signature, message);
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

fn findEntryIndex(entries: []const Entry, path: []const u8) ?usize {
    for (entries, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.pathSlice(), path)) return index;
    }
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

fn recordDeletedEntries(workspace: *WorkspaceRecord) void {
    recordDeletedEntriesAgainst(workspace, workspace.staged_entries[0..workspace.staged_entry_count]);
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

test "workspace sharing acts as a mutable policy container" {
    var directory = Directory.init();
    const notes = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try directory.share(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 7 },
        .can_read = true,
        .can_write = false,
        .can_export = true,
        .local_only = true,
    });

    try std.testing.expect(directory.hasAccess(notes.id, .{ .kind = .app, .serial = 7 }, false, true, true));
    try std.testing.expect(!directory.hasAccess(notes.id, .{ .kind = .app, .serial = 7 }, true, false, true));
    try std.testing.expect(directory.hasAccess(notes.id, .{ .kind = .app, .serial = 7 }, false, false, false));
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
