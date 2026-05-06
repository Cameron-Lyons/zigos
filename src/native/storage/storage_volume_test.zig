const std = @import("std");
const object_store = @import("object_store.zig");
const signing = @import("../core/signing.zig");
const storage_volume = @import("storage_volume.zig");
const workspace = @import("workspace.zig");

const Volume = storage_volume.Volume;
const image_bytes = storage_volume.image_bytes;
const saveToImage = storage_volume.saveToImage;
const loadFromImage = storage_volume.loadFromImage;

test "storage volume image reloads the latest persisted state across slot generations" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x71} ** 32,
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(900),
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello", 10),
    });
    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(notes.id, 11);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 1), workspaces.dirtyWorkspaceIds().len);
    const generation_one = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 1), generation_one.generation);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 0), workspaces.dirtyWorkspaceIds().len);
    const first_log_bytes = try storage_volume.testing.latestImageLogBytes(image);

    const second = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(900),
        .object_type = .document,
        .payload = "hello again",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello again", 12),
        .parent_version_id = first.version_id,
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", second.object_id, second.version_id, .document);
    _ = try workspaces.commit(notes.id, 13);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 1), workspaces.dirtyWorkspaceIds().len);
    const generation_two = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 2), generation_two.generation);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 0), workspaces.dirtyWorkspaceIds().len);
    const second_log_bytes = try storage_volume.testing.latestImageLogBytes(image);
    try std.testing.expect(second_log_bytes > first_log_bytes);
    try std.testing.expect(second_log_bytes < first_log_bytes + 4 * storage_volume.sector_size);
    const unchanged_generation = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(generation_two.generation, unchanged_generation.generation);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_generation = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(@as(u64, 2), loaded_generation);
    try std.testing.expectEqual(@as(usize, 1), loaded_store.objectCount());
    try std.testing.expectEqual(@as(usize, 2), loaded_store.blobCount());
    try std.testing.expectEqual(second.version_id, loaded_store.latestVersion(900).?.id);
    try std.testing.expectEqualStrings("hello again", try loaded_store.versionPayload(loaded_store.latestVersion(900).?));
    try std.testing.expectEqualStrings("zigos-storage-key", loaded_store.latestVersion(900).?.metadata.signature.signer);
    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 1 }, "notes").?;
    try std.testing.expectEqual(second.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);
}

test "storage volume persists workspace snapshot roots through entry mutations" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x74} ** 32,
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(930),
        .object_type = .document,
        .payload = "baseline",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "baseline", 20),
    });
    const second = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(930),
        .object_type = .document,
        .payload = "later",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "later", 21),
        .parent_version_id = first.version_id,
    });

    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 9 },
        .label = "snapshot-notes",
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(notes.id, 22);
    _ = try workspaces.snapshot(notes.id, "baseline", signer);

    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", second.object_id, second.version_id, .document);
    _ = try workspaces.commit(notes.id, 23);
    _ = try saveToImage(image, &store, &workspaces);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try loadFromImage(image, &loaded_store, &loaded_workspaces);

    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 9 }, "snapshot-notes").?;
    const loaded_snapshot = loaded_workspaces.findSnapshotByLabel(loaded_notes.id, "baseline").?;
    try std.testing.expectEqual(second.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);

    _ = try loaded_workspaces.restore(loaded_notes.id, loaded_snapshot.id, 24);
    try std.testing.expectEqual(first.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);
}

test "storage volume instances keep image reload state isolated" {
    var first_volume = Volume.init();
    var second_volume = Volume.init();
    const first_image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(first_image);
    const second_image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(second_image);
    @memset(first_image, 0);
    @memset(second_image, 0);

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x73} ** 32,
    };

    var first_store = object_store.Store.init();
    var first_workspaces = workspace.Directory.init();
    _ = try first_store.putVersion(.{
        .preferred_object_id = object_store.ids.object(910),
        .object_type = .document,
        .payload = "first volume",
        .metadata = try object_store.signMetadata(signer, "first", "text/plain", .document, "first volume", 1),
    });
    _ = try first_volume.saveToImage(first_image, &first_store, &first_workspaces);

    var second_store = object_store.Store.init();
    var second_workspaces = workspace.Directory.init();
    _ = try second_store.putVersion(.{
        .preferred_object_id = object_store.ids.object(920),
        .object_type = .document,
        .payload = "second volume",
        .metadata = try object_store.signMetadata(signer, "second", "text/plain", .document, "second volume", 2),
    });
    _ = try second_volume.saveToImage(second_image, &second_store, &second_workspaces);

    var loaded_first_store = object_store.Store.init();
    var loaded_first_workspaces = workspace.Directory.init();
    var loaded_second_store = object_store.Store.init();
    var loaded_second_workspaces = workspace.Directory.init();

    _ = try first_volume.loadFromImage(first_image, &loaded_first_store, &loaded_first_workspaces);
    _ = try second_volume.loadFromImage(second_image, &loaded_second_store, &loaded_second_workspaces);

    try std.testing.expectEqualStrings("first volume", try loaded_first_store.versionPayload(loaded_first_store.latestVersion(910).?));
    try std.testing.expectEqualStrings("second volume", try loaded_second_store.versionPayload(loaded_second_store.latestVersion(920).?));
    try std.testing.expect(loaded_first_store.latestVersion(920) == null);
    try std.testing.expect(loaded_second_store.latestVersion(910) == null);
}

test "storage volume rejects corrupted slot payloads" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x72} ** 32,
    };
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(901),
        .object_type = .blob,
        .payload = "blob",
        .metadata = try object_store.signMetadata(signer, "blob", "application/octet-stream", .blob, "blob", 10),
    });
    _ = try saveToImage(image, &store, &workspaces);
    storage_volume.testing.corruptDataByte(image, 3);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, loadFromImage(image, &loaded_store, &loaded_workspaces));
}
