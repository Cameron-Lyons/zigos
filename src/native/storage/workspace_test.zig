const std = @import("std");

const ids = @import("../core/ids.zig");
const object_store = @import("object_store.zig");
const signing = @import("../core/signing.zig");
const workspace_model = @import("workspace.zig");
const workspace_merkle = @import("workspace/merkle.zig");

const AuditVisibility = workspace_model.AuditVisibility;
const Directory = workspace_model.Directory;
const Entry = workspace_model.Entry;
const ExportPackage = workspace_model.ExportPackage;
const MAX_WORKSPACE_ENTRIES = workspace_model.MAX_WORKSPACE_ENTRIES;
const MAX_WORKSPACE_ENTRY_MUTATIONS = workspace_model.MAX_WORKSPACE_ENTRY_MUTATIONS;
const ResharePolicy = workspace_model.ResharePolicy;
const ShareNetworkScope = workspace_model.ShareNetworkScope;
const workspaceRootAddress = workspace_model.workspaceRootAddress;

test "workspace transactions, snapshot restore, delete recovery, and signed export import work" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x61),
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
    try std.testing.expectEqual(@as(usize, 1), directory.workspaceCount());
    try std.testing.expectEqual(@as(usize, 0), directory.snapshotCount());
    try std.testing.expect(directory.findConst(workspace.id).?.oldestSnapshotGeneration() == null);
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/notes.md", first.object_id, first.version_id, .document);
    try std.testing.expectEqual(@as(u32, 1), try directory.commit(workspace.id, 20));

    const snapshot_identity = signing.SignerIdentity{
        .label = "zigos-workspace-key",
        .seed = signing.seedFromByte(0x62),
    };
    const export_identity = signing.SignerIdentity{
        .label = "zigos-export-key",
        .seed = signing.seedFromByte(0x63),
    };
    const baseline = try directory.snapshot(workspace.id, "baseline", snapshot_identity);
    try std.testing.expectEqual(@as(usize, 1), directory.snapshotCount());
    try std.testing.expectEqual(baseline.id, directory.findSnapshotConst(baseline.id).?.id);
    try std.testing.expectEqual(@as(u32, 1), directory.findConst(workspace.id).?.oldestSnapshotGeneration().?);
    directory.rebuildIndexes();
    try std.testing.expectEqual(baseline.id, directory.findSnapshotConst(baseline.id).?.id);
    try std.testing.expectEqual(@as(u32, 1), directory.findConst(workspace.id).?.oldestSnapshotGeneration().?);
    try std.testing.expect(!std.mem.eql(u8, &baseline.root_address, &workspace_merkle.zeroRootAddress()));
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/notes.md", second.object_id, second.version_id, .document);
    try std.testing.expectEqual(@as(u32, 2), try directory.commit(workspace.id, 21));
    try std.testing.expectEqual(second.version_id, (try directory.resolve(workspace.id, "documents/notes.md")).version_id);

    try directory.beginTransaction(workspace.id);
    try directory.stageDelete(workspace.id, "documents/notes.md");
    try std.testing.expectError(error.TransactionAlreadyOpen, directory.restore(workspace.id, baseline.id, 22));
    try directory.abortTransaction(workspace.id);
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
    try std.testing.expect(std.mem.eql(u8, &baseline.root_address, &package.root_address));
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

    const max_path = [_]u8{'p'} ** workspace_model.MAX_ENTRY_PATH_BYTES;
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, &max_path, ids.object(11), ids.version(21), .document);
    _ = try directory.commit(workspace.id, 1);
    try std.testing.expectEqualStrings(&max_path, (try directory.resolve(workspace.id, &max_path)).pathSlice());

    const scoped_grant = try (workspace_model.ShareGrant{
        .principal_id = .{ .kind = .user, .serial = 45 },
    }).withObjectScope(ids.object(11), &max_path);
    try std.testing.expectEqualStrings(&max_path, scoped_grant.scopePathSlice());
}

test "workspace can restore the original workspace from a signed export package" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x64),
    };
    const export_signer = signing.SignerIdentity{
        .label = "zigos-export-key",
        .seed = signing.seedFromByte(0x65),
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
    try std.testing.expectEqual(@as(usize, 3), record.deletedCount());
}

test "workspace path index keeps cached root and lookups current across incremental updates" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 8 },
        .label = "path-index",
    });

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "z.md", ids.object(30), ids.version(300), .document);
    try directory.stagePut(workspace.id, "a.md", ids.object(31), ids.version(301), .document);
    _ = try directory.commit(workspace.id, 43);

    const entries_after_put = try directory.entries(workspace.id);
    const record_after_put = directory.find(workspace.id).?;
    try std.testing.expectEqual(workspaceRootAddress(entries_after_put), record_after_put.rootAddress());
    try std.testing.expectEqual(ids.version(301), (try directory.resolve(workspace.id, "a.md")).version_id);
    try std.testing.expectEqual(ids.version(301), (try directory.resolveObject(workspace.id, ids.object(31))).version_id);

    const signer = signing.SignerIdentity{
        .label = "zigos-workspace-key",
        .seed = signing.seedFromByte(0x68),
    };
    const snapshot_record = try directory.snapshot(workspace.id, "indexed", signer);
    try std.testing.expectEqual(record_after_put.rootAddress(), snapshot_record.root_address);

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "a.md", ids.object(31), ids.version(303), .document);
    _ = try directory.commit(workspace.id, 44);
    const same_object_entries = try directory.entries(workspace.id);
    try std.testing.expectEqual(workspaceRootAddress(same_object_entries), directory.find(workspace.id).?.rootAddress());
    try std.testing.expectEqual(ids.version(303), (try directory.resolveObject(workspace.id, ids.object(31))).version_id);

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "a.md", ids.object(33), ids.version(304), .document);
    _ = try directory.commit(workspace.id, 45);
    const new_object_entries = try directory.entries(workspace.id);
    try std.testing.expectEqual(workspaceRootAddress(new_object_entries), directory.find(workspace.id).?.rootAddress());
    try std.testing.expectError(error.EntryNotFound, directory.resolveObject(workspace.id, ids.object(31)));
    try std.testing.expectEqual(ids.version(304), (try directory.resolveObject(workspace.id, ids.object(33))).version_id);

    try directory.beginTransaction(workspace.id);
    try directory.stageDelete(workspace.id, "a.md");
    try directory.stagePut(workspace.id, "m.md", ids.object(32), ids.version(302), .document);
    _ = try directory.commit(workspace.id, 46);

    const entries_after_delta = try directory.entries(workspace.id);
    const record_after_delta = directory.find(workspace.id).?;
    try std.testing.expectEqual(workspaceRootAddress(entries_after_delta), record_after_delta.rootAddress());
    try std.testing.expectError(error.EntryNotFound, directory.resolve(workspace.id, "a.md"));
    try std.testing.expectError(error.EntryNotFound, directory.resolveObject(workspace.id, ids.object(31)));
    try std.testing.expectEqual(ids.version(302), (try directory.resolve(workspace.id, "m.md")).version_id);
    try std.testing.expectEqualStrings("m.md", (try directory.resolveObject(workspace.id, ids.object(32))).pathSlice());
}

test "compact workspace indexes cover every entry slot at capacity" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 12 },
        .label = "full-index",
    });

    try directory.beginTransaction(workspace.id);
    for (0..MAX_WORKSPACE_ENTRIES) |entry_index| {
        var path_buffer: [32]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "documents/entry-{d}", .{entry_index});
        try directory.stagePut(
            workspace.id,
            path,
            ids.object(entry_index + 1),
            ids.version(entry_index + 101),
            .document,
        );
    }
    _ = try directory.commit(workspace.id, 52);

    try std.testing.expectEqual(MAX_WORKSPACE_ENTRIES, (try directory.entries(workspace.id)).len);
    for (0..MAX_WORKSPACE_ENTRIES) |entry_index| {
        var path_buffer: [32]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "documents/entry-{d}", .{entry_index});
        const expected_object_id = ids.object(entry_index + 1);
        try std.testing.expectEqual(expected_object_id, (try directory.resolve(workspace.id, path)).object_id);
        try std.testing.expectEqualStrings(path, (try directory.resolveObject(workspace.id, expected_object_id)).pathSlice());
    }
    try std.testing.expectError(error.EntryNotFound, directory.resolveObject(workspace.id, ids.object(MAX_WORKSPACE_ENTRIES + 1)));

    directory.rebuildIndexes();
    try std.testing.expectEqual(
        ids.object(MAX_WORKSPACE_ENTRIES),
        (try directory.resolve(workspace.id, "documents/entry-95")).object_id,
    );
}

test "structural workspace commits scrub the full inactive Merkle tail" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 11 },
        .label = "merkle-tail",
    });

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "a.md", ids.object(50), ids.version(500), .document);
    try directory.stagePut(workspace.id, "b.md", ids.object(51), ids.version(501), .document);
    try directory.stagePut(workspace.id, "c.md", ids.object(52), ids.version(502), .document);
    _ = try directory.commit(workspace.id, 47);

    const record = directory.find(workspace.id).?;
    const poisoned_leaf = record.path_index.root_address;
    const zero_leaf = workspace_merkle.zeroRootAddress();
    try std.testing.expect(!std.mem.eql(u8, &poisoned_leaf, &zero_leaf));
    for (record.path_index.leaf_hashes[record.counts.entry_count..]) |*leaf_hash| {
        leaf_hash.* = poisoned_leaf;
    }

    try directory.beginTransaction(workspace.id);
    try directory.stageDelete(workspace.id, "b.md");
    try directory.stagePut(workspace.id, "d.md", ids.object(53), ids.version(503), .document);
    _ = try directory.commit(workspace.id, 48);

    const entries_after_structural_commit = try directory.entries(workspace.id);
    const record_after = directory.find(workspace.id).?;
    const index_after = &record_after.path_index;
    try std.testing.expectEqual(workspaceRootAddress(entries_after_structural_commit), index_after.root_address);
    for (index_after.leaf_hashes[record_after.counts.entry_count..]) |leaf_hash| {
        try std.testing.expectEqual(zero_leaf, leaf_hash);
    }
}

test "replacement-only workspace commits preserve duplicate fallbacks and object swaps" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 9 },
        .label = "replacement-index",
    });

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "a.md", ids.object(10), ids.version(100), .document);
    try directory.stagePut(workspace.id, "b.md", ids.object(10), ids.version(101), .document);
    try directory.stagePut(workspace.id, "c.md", ids.object(20), ids.version(102), .document);
    try directory.stagePut(workspace.id, "d.md", ids.object(30), ids.version(103), .document);
    _ = try directory.commit(workspace.id, 47);
    try std.testing.expectEqualStrings("a.md", (try directory.resolveObject(workspace.id, ids.object(10))).pathSlice());

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "a.md", ids.object(11), ids.version(104), .document);
    _ = try directory.commit(workspace.id, 48);
    try std.testing.expectEqualStrings("b.md", (try directory.resolveObject(workspace.id, ids.object(10))).pathSlice());
    try std.testing.expectEqualStrings("a.md", (try directory.resolveObject(workspace.id, ids.object(11))).pathSlice());

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "c.md", ids.object(30), ids.version(105), .document);
    try directory.stagePut(workspace.id, "d.md", ids.object(20), ids.version(106), .document);
    _ = try directory.commit(workspace.id, 49);
    try std.testing.expectEqualStrings("c.md", (try directory.resolveObject(workspace.id, ids.object(30))).pathSlice());
    try std.testing.expectEqualStrings("d.md", (try directory.resolveObject(workspace.id, ids.object(20))).pathSlice());

    const root_before = directory.find(workspace.id).?.path_index.root_address;
    const leaf_0_before = directory.find(workspace.id).?.path_index.leaf_hashes[0];
    const leaf_1_before = directory.find(workspace.id).?.path_index.leaf_hashes[1];
    const leaf_2_before = directory.find(workspace.id).?.path_index.leaf_hashes[2];
    const leaf_3_before = directory.find(workspace.id).?.path_index.leaf_hashes[3];
    const path_slots_before = directory.find(workspace.id).?.path_index.path_slots;
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "a.md", ids.object(11), ids.version(107), .document);
    try directory.stagePut(workspace.id, "d.md", ids.object(20), ids.version(108), .document);
    _ = try directory.commit(workspace.id, 50);

    const entries_after_replacements = try directory.entries(workspace.id);
    const path_index_after = &directory.find(workspace.id).?.path_index;
    try std.testing.expectEqual(workspaceRootAddress(entries_after_replacements), path_index_after.root_address);
    try std.testing.expect(!std.mem.eql(u8, &root_before, &path_index_after.root_address));
    try std.testing.expect(!std.mem.eql(u8, &leaf_0_before, &path_index_after.leaf_hashes[0]));
    try std.testing.expectEqual(leaf_1_before, path_index_after.leaf_hashes[1]);
    try std.testing.expectEqual(leaf_2_before, path_index_after.leaf_hashes[2]);
    try std.testing.expect(!std.mem.eql(u8, &leaf_3_before, &path_index_after.leaf_hashes[3]));
    try std.testing.expectEqual(path_slots_before, path_index_after.path_slots);
    try std.testing.expectEqual(ids.version(107), (try directory.resolveObject(workspace.id, ids.object(11))).version_id);
    try std.testing.expectEqual(ids.version(108), (try directory.resolveObject(workspace.id, ids.object(20))).version_id);
}

test "workspace snapshot signing rejects stale cached roots and preserves canonical roots" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 10 },
        .label = "root-signing",
    });
    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "signed.md", ids.object(40), ids.version(400), .document);
    _ = try directory.commit(workspace.id, 51);

    const canonical_root = workspaceRootAddress(try directory.entries(workspace.id));
    const zero_root = workspace_merkle.zeroRootAddress();
    try std.testing.expect(!std.mem.eql(u8, &canonical_root, &zero_root));
    workspace.path_index.root_address = zero_root;

    const snapshot_signer = signing.SignerIdentity{
        .label = "zigos-workspace-key",
        .seed = signing.seedFromByte(0x69),
    };
    try std.testing.expectError(error.InvalidSignature, directory.snapshot(workspace.id, "stale", snapshot_signer));
    try std.testing.expectEqual(@as(usize, 0), directory.snapshotCount());
    try std.testing.expectEqual(zero_root, workspace.path_index.root_address);

    directory.rebuildIndexes();
    try std.testing.expectEqual(canonical_root, workspace.rootAddress());
    const snapshot_record = try directory.snapshot(workspace.id, "canonical", snapshot_signer);
    try std.testing.expectEqual(ids.snapshot(1), snapshot_record.id);
    try std.testing.expectEqual(canonical_root, snapshot_record.root_address);

    const export_signer = signing.SignerIdentity{
        .label = "zigos-export-key",
        .seed = signing.seedFromByte(0x6a),
    };
    const package = try directory.exportSnapshot(workspace.id, snapshot_record.id, export_signer);
    try std.testing.expectEqual(canonical_root, package.root_address);
    const imported = try directory.importWorkspace(.{ .kind = .service, .serial = 12 }, "root-import", package, 52);
    const imported_entries = try directory.entries(imported.id);
    try std.testing.expectEqual(workspaceRootAddress(imported_entries), imported.rootAddress());
    try std.testing.expectEqual(canonical_root, imported.rootAddress());
}

test "workspace snapshots and exports must stay signed" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .label = "unsigned",
    });
    try std.testing.expectError(error.UnsignedSnapshot, directory.snapshot(workspace.id, "baseline", .{
        .label = "",
        .seed = signing.seedFromByte(0),
    }));

    const package = ExportPackage{
        .workspace_id = workspace.id,
        .snapshot_id = ids.SnapshotId.zero,
        .generation = 0,
        .label_len = 0,
        .label = [_]u8{0} ** workspace_model.MAX_WORKSPACE_LABEL_BYTES,
        .root_address = workspace_merkle.zeroRootAddress(),
        .signature = .{},
        .signature_format_len = 0,
        .signature_format_storage = [_]u8{0} ** workspace_model.MAX_EXPORT_SIGNATURE_FORMAT_BYTES,
        .signature_signer_len = 0,
        .signature_signer_storage = [_]u8{0} ** workspace_model.MAX_EXPORT_SIGNATURE_SIGNER_BYTES,
        .entry_count = 0,
        .entries = [_]Entry{Entry{}} ** MAX_WORKSPACE_ENTRIES,
    };
    try std.testing.expectError(error.UnsignedExport, directory.importWorkspace(.{ .kind = .service, .serial = 10 }, "import", package, 0));
}

test "export packages keep self-contained signature state across copies" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x66),
    };
    const export_signer = signing.SignerIdentity{
        .label = "zigos-export-key",
        .seed = signing.seedFromByte(0x67),
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

    try std.testing.expect(package.signerSlice().len != 0);
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
    const app_grant_key = workspace_model.shareGrantPrincipalKey(.{ .kind = .app, .serial = 7 });
    try std.testing.expectEqual(@as(usize, 1), notes.share_table.share_grant_principal_index.count(app_grant_key));
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
    try std.testing.expectEqual(@as(usize, 1), notes.share_table.share_grant_principal_index.count(app_grant_key));
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
        .seed = signing.seedFromByte(0x64),
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
        .seed = signing.seedFromByte(0x65),
    });
    snapshot.generation += 1;
    try std.testing.expectError(error.InvalidSignature, directory.restore(notes.id, snapshot.id, 12));
}

test "aborting a transaction discards staged entries and reopens the workspace" {
    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x66),
    };
    const object = try store.putVersion(.{
        .preferred_object_id = ids.object(902),
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello", 10),
    });

    var directory = Directory.init();
    const notes = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });

    try std.testing.expectError(error.NoActiveTransaction, directory.abortTransaction(notes.id));

    try directory.beginTransaction(notes.id);
    try directory.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    try directory.abortTransaction(notes.id);
    try std.testing.expect(!notes.staging.transaction_open);
    try std.testing.expectEqual(@as(usize, 0), notes.staging.staged_entry_count);
    try std.testing.expectEqualDeep(workspace_model.EntryMutation{}, notes.mutation_log.entriesConst()[0]);

    try std.testing.expectError(error.EntryNotFound, directory.resolve(notes.id, "documents/notes.md"));
    try directory.beginTransaction(notes.id);
    try directory.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    _ = try directory.commit(notes.id, 11);
    try std.testing.expectEqual(@as(usize, 1), notes.counts.entry_mutation_count);
    try std.testing.expectEqualStrings("documents/notes.md", notes.mutation_log.entriesConst()[0].entry.pathSlice());
    try std.testing.expectEqualDeep(workspace_model.EntryMutation{}, notes.mutation_log.entriesConst()[1]);
    _ = try directory.resolve(notes.id, "documents/notes.md");

    try directory.beginTransaction(notes.id);
    try std.testing.expectError(error.TransactionAlreadyOpen, directory.recoverDeleted(notes.id, "documents/missing.md", 12));
    try directory.abortTransaction(notes.id);
}

test "workspace staging is bounded by the unused mutation-log tail" {
    var directory = Directory.init();
    const workspace = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .label = "bounded-staging",
    });
    workspace.counts.entry_mutation_count = MAX_WORKSPACE_ENTRY_MUTATIONS - 1;

    try directory.beginTransaction(workspace.id);
    try directory.stagePut(workspace.id, "documents/last.md", ids.object(1), ids.version(1), .document);
    try std.testing.expectError(
        error.EntryTableFull,
        directory.stagePut(workspace.id, "documents/overflow.md", ids.object(2), ids.version(2), .document),
    );
    try std.testing.expectEqual(@as(usize, 1), workspace.staging.staged_entry_count);
    try std.testing.expectEqual(@as(usize, 1), workspace.staging.staged_effective_entry_count);

    try directory.abortTransaction(workspace.id);
    try std.testing.expectEqualDeep(
        workspace_model.EntryMutation{},
        workspace.mutation_log.entriesConst()[MAX_WORKSPACE_ENTRY_MUTATIONS - 1],
    );
}

test "workspace and snapshot identifiers stop at exhaustion" {
    var directory = Directory.init();
    directory.next_workspace_id = std.math.maxInt(u64);

    const workspace_record = try directory.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "final-workspace",
    });
    try std.testing.expectEqual(std.math.maxInt(u64), workspace_record.id.raw());
    try std.testing.expectEqual(@as(u64, 0), directory.next_workspace_id);
    try std.testing.expectError(error.WorkspaceIdExhausted, directory.create(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .label = "must-not-publish",
    }));
    try std.testing.expectEqual(@as(usize, 1), directory.workspaceCount());

    directory.next_snapshot_id = std.math.maxInt(u64);
    const signer = signing.SignerIdentity{
        .label = "snapshot-id-exhaustion",
        .seed = signing.seedFromByte(0x69),
    };
    const snapshot_record = try directory.snapshot(workspace_record.id, "final-snapshot", signer);
    try std.testing.expectEqual(std.math.maxInt(u64), snapshot_record.id.raw());
    try std.testing.expectEqual(@as(u64, 0), directory.next_snapshot_id);
    try std.testing.expectError(
        error.SnapshotIdExhausted,
        directory.snapshot(workspace_record.id, "must-not-publish", signer),
    );
    try std.testing.expectEqual(@as(usize, 1), directory.snapshotCount());
}
