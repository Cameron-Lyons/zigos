const std = @import("std");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_volume = @import("storage_volume.zig");
const volume_root_slot = @import("volume/root_slot.zig");
const workspace = @import("workspace.zig");

const Volume = storage_volume.Volume;
const image_bytes = storage_volume.image_bytes;
const saveToImage = storage_volume.saveToImage;
const loadFromImage = storage_volume.loadFromImage;
const DELTA_PAYLOAD_BUFFER_BYTES: usize = 32;

const WriteBackBackend = struct {
    const Event = enum(u8) {
        data_write,
        root_write,
        flush,
    };

    const max_events = 32;

    var visible: []u8 = &.{};
    var durable: []u8 = &.{};
    var events: [max_events]Event = undefined;
    var event_count: usize = 0;
    var flush_count: usize = 0;
    var fail_on_flush: usize = 0;

    fn attach(volume: *Volume, visible_image: []u8, durable_image: []u8) void {
        visible = visible_image;
        durable = durable_image;
        @memset(visible, 0);
        @memset(durable, 0);
        beginAttempt(0);
        volume.attachBackend(.{
            .sector_count = storage_volume.required_device_sectors,
            .read = read,
            .write = write,
            .flush = flush,
        });
    }

    fn beginAttempt(failing_flush: usize) void {
        event_count = 0;
        flush_count = 0;
        fail_on_flush = failing_flush;
    }

    fn powerLoss() void {
        @memcpy(visible, durable);
    }

    fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
        const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
        const end = start + buffer_len;
        if (end > visible.len) return false;
        @memcpy(buffer_ptr[0..buffer_len], visible[start..end]);
        return true;
    }

    fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
        const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
        const end = start + buffer_len;
        if (end > visible.len) return false;
        record(if (start_lba < storage_volume.header_sectors) .root_write else .data_write);
        @memcpy(visible[start..end], buffer_ptr[0..buffer_len]);
        return true;
    }

    fn flush() callconv(.c) bool {
        record(.flush);
        flush_count += 1;
        if (fail_on_flush != 0 and flush_count == fail_on_flush) return false;
        @memcpy(durable, visible);
        return true;
    }

    fn record(event: Event) void {
        if (event_count >= events.len) return;
        events[event_count] = event;
        event_count += 1;
    }

    fn firstFlushIndex() ?usize {
        for (events[0..event_count], 0..) |event, index| {
            if (event == .flush) return index;
        }
        return null;
    }
};

fn putBarrierTestVersion(store: *object_store.Store, workspaces: *workspace.Directory, serial: u64) !void {
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-barrier",
        .seed = signing.seedFromByte(0x6B),
    };
    const result = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(serial),
        .object_type = .document,
        .payload = "explicit durability barrier",
        .metadata = try object_store.signMetadata(signer, "barrier", "text/plain", .document, "explicit durability barrier", 1),
    });
    const record = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = serial },
        .label = "barrier-workspace",
    });
    try workspaces.beginTransaction(record.id);
    try workspaces.stagePut(record.id, "documents/barrier.md", result.object_id, result.version_id, .document);
    _ = try workspaces.commit(record.id, 2);
}

fn expectOrderedBarrierTrace() !void {
    const first_flush = WriteBackBackend.firstFlushIndex() orelse return error.MissingDurabilityBarrier;
    try std.testing.expect(first_flush > 0);
    for (WriteBackBackend.events[0..first_flush]) |event| {
        try std.testing.expectEqual(WriteBackBackend.Event.data_write, event);
    }
    try std.testing.expectEqual(first_flush + 3, WriteBackBackend.event_count);
    try std.testing.expectEqual(WriteBackBackend.Event.root_write, WriteBackBackend.events[first_flush + 1]);
    try std.testing.expectEqual(WriteBackBackend.Event.flush, WriteBackBackend.events[first_flush + 2]);
}

fn expectBarrierFailurePreservesDirtyState(failing_flush: usize, object_serial: u64) !void {
    const allocator = std.testing.allocator;
    const visible = try allocator.alloc(u8, image_bytes);
    defer allocator.free(visible);
    const durable = try allocator.alloc(u8, image_bytes);
    defer allocator.free(durable);
    const volume = try allocator.create(Volume);
    defer allocator.destroy(volume);
    volume.reset();
    WriteBackBackend.attach(volume, visible, durable);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    try putBarrierTestVersion(&store, &workspaces, object_serial);
    WriteBackBackend.beginAttempt(failing_flush);

    try std.testing.expectError(error.DurabilityBarrierFailed, volume.saveToVolume(&store, &workspaces));
    try std.testing.expectEqual(@as(usize, 1), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 1), workspaces.dirtyWorkspaceIds().len);
    try std.testing.expectEqual(failing_flush, WriteBackBackend.flush_count);
    try std.testing.expect(std.mem.allEqual(
        u8,
        durable[0 .. storage_volume.header_sectors * storage_volume.sector_size],
        0,
    ));

    WriteBackBackend.beginAttempt(0);
    const retried = try volume.saveToVolume(&store, &workspaces);
    try std.testing.expectEqual(@as(u64, if (failing_flush == 2) 2 else 1), retried.generation);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 0), workspaces.dirtyWorkspaceIds().len);

    WriteBackBackend.powerLoss();
    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expect(volume.loadFromVolume(&loaded_store, &loaded_workspaces));
    try std.testing.expect(loaded_store.latestVersion(object_serial) != null);
}

test "storage backend commits log and root through ordered durability barriers" {
    const allocator = std.testing.allocator;
    const visible = try allocator.alloc(u8, image_bytes);
    defer allocator.free(visible);
    const durable = try allocator.alloc(u8, image_bytes);
    defer allocator.free(durable);
    const volume = try allocator.create(Volume);
    defer allocator.destroy(volume);
    volume.reset();
    WriteBackBackend.attach(volume, visible, durable);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    try putBarrierTestVersion(&store, &workspaces, 0xB401);
    const persisted = try volume.saveToVolume(&store, &workspaces);

    try std.testing.expectEqual(@as(u64, 1), persisted.generation);
    try std.testing.expectEqual(@as(usize, 2), WriteBackBackend.flush_count);
    try expectOrderedBarrierTrace();
    try std.testing.expectEqualSlices(u8, durable, visible);

    WriteBackBackend.powerLoss();
    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expect(volume.loadFromVolume(&loaded_store, &loaded_workspaces));
    try std.testing.expect(loaded_store.latestVersion(0xB401) != null);
}

test "storage backend barrier failures preserve dirty state and withhold the new root" {
    try expectBarrierFailurePreservesDirtyState(1, 0xB402);
    try expectBarrierFailurePreservesDirtyState(2, 0xB403);
}

test "storage volume exposes the first supported product capacity envelope" {
    const envelope = storage_volume.productCapacityEnvelope();

    try std.testing.expectEqual(storage_volume.image_bytes, envelope.volume_image_bytes);
    try std.testing.expectEqual(storage_volume.required_device_sectors, envelope.required_device_sectors);
    try std.testing.expectEqual(object_store.MAX_PAYLOAD_BYTES, envelope.max_object_payload_bytes);
    try std.testing.expectEqual(object_store.MAX_OBJECTS, envelope.max_object_records);
    try std.testing.expectEqual(object_store.MAX_VERSIONS, envelope.max_version_records);
    try std.testing.expectEqual(object_store.MAX_BLOBS, envelope.max_blob_records);
    try std.testing.expectEqual(object_store.MAX_BLOB_CHUNKS, envelope.max_blob_chunks_per_payload);
    try std.testing.expectEqual(object_store.MAX_CHUNKS, envelope.max_chunk_records);
    try std.testing.expectEqual(object_store.MAX_CHUNK_BYTES, envelope.max_chunk_bytes);
    try std.testing.expectEqual(workspace.MAX_WORKSPACES, envelope.max_workspaces);
    try std.testing.expectEqual(workspace.MAX_WORKSPACE_ENTRIES, envelope.max_workspace_entries_per_workspace);
    try std.testing.expectEqual(workspace.MAX_SNAPSHOTS, envelope.max_snapshots);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    try storage_volume.ensureWithinProductCapacityEnvelope(&store, &workspaces);
}

test "storage volume preserves exhausted identifier watermarks" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    defer allocator.destroy(volume);
    volume.reset();

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    store.next_version_id = 0;
    workspaces.next_snapshot_id = 0;
    _ = try volume.saveToImage(image, &store, &workspaces);

    const loaded_root = (try volume_root_slot.findLatestImageRoot(image)).?;
    try std.testing.expectEqual(std.math.maxInt(u64), loaded_root.root.last_version_id);
    try std.testing.expectEqual(std.math.maxInt(u64), loaded_root.root.last_snapshot_id);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(@as(u64, 0), loaded_store.next_version_id);
    try std.testing.expectEqual(@as(u64, 0), loaded_workspaces.next_snapshot_id);
}

test "storage volume compacts instead of trusting ahead delta watermarks" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    defer allocator.destroy(volume);
    volume.reset();

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-watermark",
        .seed = signing.seedFromByte(0x57),
    };
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(941),
        .object_type = .document,
        .payload = "first",
        .metadata = try object_store.signMetadata(signer, "watermark", "text/plain", .document, "first", 1),
    });
    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 941 },
        .label = "watermark-notes",
    });
    _ = try volume.saveToImage(image, &store, &workspaces);

    var loaded_root = (try volume_root_slot.findLatestImageRoot(image)).?;
    loaded_root.root.next_version_id += 4;
    loaded_root.root.last_version_id = volume_root_slot.lastIssuedId(loaded_root.root.next_version_id);
    loaded_root.root.next_snapshot_id += 4;
    loaded_root.root.last_snapshot_id = volume_root_slot.lastIssuedId(loaded_root.root.next_snapshot_id);
    try volume_root_slot.writeImageRoot(image, loaded_root.sector_index, loaded_root.root);

    const second = try store.putVersion(.{
        .preferred_object_id = first.object_id,
        .object_type = .document,
        .payload = "second",
        .metadata = try object_store.signMetadata(signer, "watermark", "text/plain", .document, "second", 2),
        .parent_version_id = first.version_id,
    });
    _ = try workspaces.snapshot(notes.id, "after-watermark", signer);

    const saved = try volume.saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 2), saved.generation);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(second.version_id, loaded_store.object(first.object_id).?.latest_version_id);
    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 941 }, "watermark-notes").?;
    try std.testing.expect(loaded_workspaces.findSnapshotByLabel(loaded_notes.id, "after-watermark") != null);
}

test "storage volume compacts around a noncanonical newer root" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    defer allocator.destroy(volume);
    volume.reset();

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-root-selection",
        .seed = signing.seedFromByte(0x52),
    };
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(942),
        .object_type = .document,
        .payload = "first",
        .metadata = try object_store.signMetadata(signer, "root-selection", "text/plain", .document, "first", 1),
    });
    _ = try volume.saveToImage(image, &store, &workspaces);
    const second = try store.putVersion(.{
        .preferred_object_id = first.object_id,
        .object_type = .document,
        .payload = "second",
        .metadata = try object_store.signMetadata(signer, "root-selection", "text/plain", .document, "second", 2),
        .parent_version_id = first.version_id,
    });
    _ = try volume.saveToImage(image, &store, &workspaces);

    var newest = (try volume_root_slot.findLatestImageRoot(image)).?;
    newest.root.last_version_id = newest.root.next_version_id;
    try volume_root_slot.writeImageRoot(image, newest.sector_index, newest.root);

    const third = try store.putVersion(.{
        .preferred_object_id = first.object_id,
        .object_type = .document,
        .payload = "third",
        .metadata = try object_store.signMetadata(signer, "root-selection", "text/plain", .document, "third", 3),
        .parent_version_id = second.version_id,
    });
    const saved = try volume.saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 2), saved.generation);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(@as(usize, 3), loaded_store.versionCount());
    try std.testing.expect(loaded_store.version(second.version_id) != null);
    try std.testing.expectEqual(third.version_id, loaded_store.object(first.object_id).?.latest_version_id);
}

test "storage volume rejects replayed identifiers beyond root watermarks" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    defer allocator.destroy(volume);
    volume.reset();

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-root-rewind",
        .seed = signing.seedFromByte(0x51),
    };
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    _ = try store.putVersion(.{
        .object_type = .document,
        .payload = "issued",
        .metadata = try object_store.signMetadata(signer, "root-rewind", "text/plain", .document, "issued", 1),
    });
    _ = try volume.saveToImage(image, &store, &workspaces);

    var root = (try volume_root_slot.findLatestImageRoot(image)).?;
    root.root.next_version_id = 1;
    root.root.last_version_id = 0;
    try volume_root_slot.writeImageRoot(image, root.sector_index, root.root);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, volume.loadFromImage(image, &loaded_store, &loaded_workspaces));
}

test "storage quota policy rejects writes above the first supported envelope" {
    const policy = storage_volume.productQuotaPolicy();

    try std.testing.expectEqual(storage_volume.OverLimitWriteBehavior.reject_without_partial_persistence, policy.over_limit_write_behavior);
    try std.testing.expect(policy.persistence_error == error.NoSpaceLeft);
    try std.testing.expect(policy.retry_requires_freeing_space);
    try std.testing.expectEqual(storage_volume.productCapacityEnvelope().max_object_records, policy.envelope.max_object_records);

    const payload_rejection = storage_volume.quotaRejectionForUsage(.{
        .object_payload_bytes = object_store.MAX_PAYLOAD_BYTES + 1,
    }).?;
    try std.testing.expectEqual(storage_volume.QuotaLimit.object_payload_bytes, payload_rejection.limit);
    try std.testing.expectEqual(object_store.MAX_PAYLOAD_BYTES + 1, payload_rejection.used);
    try std.testing.expectEqual(object_store.MAX_PAYLOAD_BYTES, payload_rejection.allowed);
    try std.testing.expectEqualStrings("storage.quota.object_payload_bytes", payload_rejection.userVisibleCode());

    const object_rejection = storage_volume.quotaRejectionForUsage(.{
        .object_records = object_store.MAX_OBJECTS + 1,
    }).?;
    try std.testing.expectEqual(storage_volume.QuotaLimit.object_records, object_rejection.limit);
    try std.testing.expectEqualStrings("storage.quota.object_records", object_rejection.userVisibleCode());

    const workspace_rejection = storage_volume.quotaRejectionForUsage(.{
        .max_workspace_entries = workspace.MAX_WORKSPACE_ENTRIES + 1,
    }).?;
    try std.testing.expectEqual(storage_volume.QuotaLimit.workspace_entries, workspace_rejection.limit);
    try std.testing.expectEqualStrings("storage.quota.workspace_entries", workspace_rejection.userVisibleCode());

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    try std.testing.expect(storage_volume.quotaRejectionForCurrentState(&store, &workspaces) == null);

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x78),
    };
    const payload = "quota-observed-payload";
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(904),
        .object_type = .document,
        .payload = payload,
        .metadata = try object_store.signMetadata(signer, "quota", "text/plain", .document, payload, 16),
    });
    const usage = storage_volume.productCapacityUsage(&store, &workspaces);
    try std.testing.expectEqual(payload.len, store.maxBlobPayloadBytes());
    try std.testing.expectEqual(payload.len, usage.object_payload_bytes);
    try storage_volume.ensureWithinProductCapacityEnvelope(&store, &workspaces);
}

test "storage volume separates generic and target nvme attachments" {
    try std.testing.expect(!@hasField(Volume, "attached_ata_device"));
    try std.testing.expect(!@hasDecl(Volume, "attachAtaBootstrapDevice"));
    try std.testing.expect(!@hasDecl(storage_volume, "attachAtaBootstrapDevice"));
    try std.testing.expect(std.meta.stringToEnum(storage_volume.AttachedBackendKind, "ata_bootstrap_broker") == null);

    const BackendFns = struct {
        fn read(_: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            @memset(buffer_ptr[0..buffer_len], 0);
            return true;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return true;
        }

        fn flush() callconv(.c) bool {
            return true;
        }
    };

    var volume = Volume.init();
    const backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors,
        .read = BackendFns.read,
        .write = BackendFns.write,
        .flush = BackendFns.flush,
    };
    volume.attachBackend(backend);
    try std.testing.expectEqual(storage_volume.AttachedBackendKind.generic, volume.attached_backend_kind);
    try std.testing.expect(!volume.hasProductionStorageBackend());

    volume.attachNvmePciBackend(backend);
    try std.testing.expectEqual(storage_volume.AttachedBackendKind.nvme_pci, volume.attached_backend_kind);
    try std.testing.expect(volume.hasProductionStorageBackend());

    const undersized_nvme_backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors - 1,
        .read = BackendFns.read,
        .write = BackendFns.write,
        .flush = BackendFns.flush,
    };
    volume.attachNvmePciBackend(undersized_nvme_backend);
    try std.testing.expectEqual(storage_volume.AttachedBackendKind.nvme_pci, volume.attached_backend_kind);
    try std.testing.expect(!volume.hasProductionStorageBackend());
}

test "storage volume rejects undersized images without mutating state" {
    const undersized_image = try std.testing.allocator.alloc(u8, image_bytes - storage_volume.sector_size);
    defer std.testing.allocator.free(undersized_image);
    @memset(undersized_image, 0xA5);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x79),
    };
    _ = try loaded_store.putVersion(.{
        .preferred_object_id = object_store.ids.object(905),
        .object_type = .document,
        .payload = "preexisting",
        .metadata = try object_store.signMetadata(signer, "preexisting", "text/plain", .document, "preexisting", 17),
    });

    try std.testing.expectError(error.ImageTooSmall, loadFromImage(undersized_image, &loaded_store, &loaded_workspaces));
    try std.testing.expectEqual(@as(usize, 1), loaded_store.objectCount());
    try std.testing.expectEqual(@as(usize, 0), loaded_workspaces.workspaces.countInUse());
}

test "storage volume image reloads the latest persisted state across slot generations" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x71),
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

test "storage volume compacts segmented logs and reloads page-sized blob payloads" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x75),
    };

    var large_payload: [object_store.PAGE_SIZE_BYTES * 2 + 19]u8 = undefined;
    for (&large_payload, 0..) |*byte, index| {
        byte.* = @intCast((index * 23) & 0xFF);
    }
    const large = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(940),
        .object_type = .media_asset,
        .payload = &large_payload,
        .metadata = try object_store.signMetadata(signer, "large", "application/octet-stream", .media_asset, &large_payload, 30),
    });
    _ = try saveToImage(image, &store, &workspaces);

    var previous_version_id = object_store.ids.VersionId.zero;
    const compaction_mutations = @as(usize, storage_volume.testing.maxReplayLogSegments()) + 4;
    for (0..compaction_mutations) |index| {
        var payload_buffer: [DELTA_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buffer, "delta-{d}", .{index});
        const result = try store.putVersion(.{
            .preferred_object_id = object_store.ids.object(941),
            .object_type = .document,
            .payload = payload,
            .metadata = try object_store.signMetadata(signer, "delta", "text/plain", .document, payload, 31 + @as(u64, @intCast(index))),
            .parent_version_id = if (previous_version_id.isZero()) null else previous_version_id,
        });
        previous_version_id = result.version_id;
        _ = try saveToImage(image, &store, &workspaces);
    }

    try std.testing.expect((try storage_volume.testing.latestImageCompactedGeneration(image)) > 1);
    try std.testing.expect((try storage_volume.testing.latestImageLogRecordCount(image)) <= 128);
    try std.testing.expect((try storage_volume.testing.latestImageLogSegmentCount(image)) <= 16);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try loadFromImage(image, &loaded_store, &loaded_workspaces);

    var out: [large_payload.len]u8 = undefined;
    const loaded_large = try loaded_store.versionPayloadInto(loaded_store.version(large.version_id).?, &out);
    try std.testing.expectEqualSlices(u8, &large_payload, loaded_large);
    try std.testing.expectEqual(previous_version_id, loaded_store.latestVersion(941).?.id);
}

test "storage volume persists workspace snapshot roots through entry mutations" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x74),
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
    const allocator = std.testing.allocator;
    const first_volume = try allocator.create(Volume);
    defer allocator.destroy(first_volume);
    const second_volume = try allocator.create(Volume);
    defer allocator.destroy(second_volume);
    first_volume.reset();
    second_volume.reset();
    const first_image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(first_image);
    const second_image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(second_image);
    @memset(first_image, 0);
    @memset(second_image, 0);

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x73),
    };

    const first_store = try allocator.create(object_store.Store);
    defer allocator.destroy(first_store);
    const first_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(first_workspaces);
    first_store.* = object_store.Store.init();
    first_workspaces.* = workspace.Directory.init();
    _ = try first_store.putVersion(.{
        .preferred_object_id = object_store.ids.object(910),
        .object_type = .document,
        .payload = "first volume",
        .metadata = try object_store.signMetadata(signer, "first", "text/plain", .document, "first volume", 1),
    });
    _ = try first_volume.saveToImage(first_image, first_store, first_workspaces);

    const second_store = try allocator.create(object_store.Store);
    defer allocator.destroy(second_store);
    const second_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(second_workspaces);
    second_store.* = object_store.Store.init();
    second_workspaces.* = workspace.Directory.init();
    _ = try second_store.putVersion(.{
        .preferred_object_id = object_store.ids.object(920),
        .object_type = .document,
        .payload = "second volume",
        .metadata = try object_store.signMetadata(signer, "second", "text/plain", .document, "second volume", 2),
    });
    _ = try second_volume.saveToImage(second_image, second_store, second_workspaces);

    const loaded_first_store = try allocator.create(object_store.Store);
    defer allocator.destroy(loaded_first_store);
    const loaded_first_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(loaded_first_workspaces);
    const loaded_second_store = try allocator.create(object_store.Store);
    defer allocator.destroy(loaded_second_store);
    const loaded_second_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(loaded_second_workspaces);
    loaded_first_store.* = object_store.Store.init();
    loaded_first_workspaces.* = workspace.Directory.init();
    loaded_second_store.* = object_store.Store.init();
    loaded_second_workspaces.* = workspace.Directory.init();

    _ = try first_volume.loadFromImage(first_image, loaded_first_store, loaded_first_workspaces);
    _ = try second_volume.loadFromImage(second_image, loaded_second_store, loaded_second_workspaces);

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
        .seed = signing.seedFromByte(0x72),
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

test "storage volume rejects root log metadata that does not match replayed records" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x76),
    };
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(902),
        .object_type = .document,
        .payload = "root-log",
        .metadata = try object_store.signMetadata(signer, "root-log", "text/plain", .document, "root-log", 14),
    });
    _ = try saveToImage(image, &store, &workspaces);

    try storage_volume.testing.forceLatestImageRootLogRecordCount(
        image,
        (try storage_volume.testing.latestImageLogRecordCount(image)) + 1,
    );

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, loadFromImage(image, &loaded_store, &loaded_workspaces));
}

test "storage volume rejects torn records referenced by a valid root" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x77),
    };
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(903),
        .object_type = .document,
        .payload = "torn-record",
        .metadata = try object_store.signMetadata(signer, "torn-record", "text/plain", .document, "torn-record", 15),
    });
    _ = try saveToImage(image, &store, &workspaces);

    try storage_volume.testing.forceLatestImageRootLogBytes(
        image,
        @intCast(storage_volume.testing.recordHeaderBytes() + 1),
    );

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, loadFromImage(image, &loaded_store, &loaded_workspaces));
}

test "storage volume ignores power-loss data writes that happen before root commit" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    const interrupted = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(interrupted);
    @memset(image, 0);
    @memset(interrupted, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x7A),
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(906),
        .object_type = .document,
        .payload = "committed-before-power-loss",
        .metadata = try object_store.signMetadata(signer, "power", "text/plain", .document, "committed-before-power-loss", 19),
    });
    const generation_one = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 1), generation_one.generation);
    @memcpy(interrupted, image);

    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(906),
        .object_type = .document,
        .payload = "dirty-during-power-loss",
        .metadata = try object_store.signMetadata(signer, "power", "text/plain", .document, "dirty-during-power-loss", 20),
        .parent_version_id = first.version_id,
    });
    _ = try saveToImage(interrupted, &store, &workspaces);

    @memcpy(image[storage_volume.sector_size * 2 ..], interrupted[storage_volume.sector_size * 2 ..]);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_generation = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(generation_one.generation, loaded_generation);
    try std.testing.expectEqual(first.version_id, loaded_store.latestVersion(906).?.id);
    try std.testing.expectEqualStrings("committed-before-power-loss", try loaded_store.versionPayload(loaded_store.latestVersion(906).?));
}

test "storage volume survives an interrupted compaction into the alternate region" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x7C),
    };

    const committed = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(909),
        .object_type = .document,
        .payload = "survives-compaction-power-loss",
        .metadata = try object_store.signMetadata(signer, "compact", "text/plain", .document, "survives-compaction-power-loss", 40),
    });
    _ = try saveToImage(image, &store, &workspaces);

    var previous_version_id = object_store.ids.VersionId.zero;
    const compaction_mutations = @as(usize, storage_volume.testing.maxReplayLogSegments()) + 4;
    for (0..compaction_mutations) |index| {
        var payload_buffer: [DELTA_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buffer, "compact-delta-{d}", .{index});
        const result = try store.putVersion(.{
            .preferred_object_id = object_store.ids.object(910),
            .object_type = .document,
            .payload = payload,
            .metadata = try object_store.signMetadata(signer, "compact", "text/plain", .document, payload, 41 + @as(u64, @intCast(index))),
            .parent_version_id = if (previous_version_id.isZero()) null else previous_version_id,
        });
        previous_version_id = result.version_id;
        _ = try saveToImage(image, &store, &workspaces);
    }

    try std.testing.expect((try storage_volume.testing.latestImageCompactedGeneration(image)) > 1);

    const committed_offset = try storage_volume.testing.latestImageDataOffset(image);
    const alternate: u32 = if (committed_offset == 0) storage_volume.testing.alternateDataRegionOffset() else 0;
    storage_volume.testing.scribbleDataRegion(image, alternate);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try loadFromImage(image, &loaded_store, &loaded_workspaces);

    try std.testing.expectEqualStrings("survives-compaction-power-loss", try loaded_store.versionPayload(loaded_store.version(committed.version_id).?));
    try std.testing.expectEqual(previous_version_id, loaded_store.latestVersion(910).?.id);
}

test "storage volume falls back when a partial-sector corruption hits only the newest log generation" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x7B),
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(907),
        .object_type = .document,
        .payload = "sector-safe-v1",
        .metadata = try object_store.signMetadata(signer, "sector", "text/plain", .document, "sector-safe-v1", 21),
    });
    const generation_one = try saveToImage(image, &store, &workspaces);
    const first_log_bytes = try storage_volume.testing.latestImageLogBytes(image);

    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(907),
        .object_type = .document,
        .payload = "sector-corrupted-v2",
        .metadata = try object_store.signMetadata(signer, "sector", "text/plain", .document, "sector-corrupted-v2", 22),
        .parent_version_id = first.version_id,
    });
    const generation_two = try saveToImage(image, &store, &workspaces);
    try std.testing.expect(generation_two.generation > generation_one.generation);
    storage_volume.testing.corruptDataByte(image, @as(usize, first_log_bytes) + storage_volume.testing.recordHeaderBytes());

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_generation = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(generation_one.generation, loaded_generation);
    try std.testing.expectEqual(first.version_id, loaded_store.latestVersion(907).?.id);
    try std.testing.expectEqualStrings("sector-safe-v1", try loaded_store.versionPayload(loaded_store.latestVersion(907).?));
}

test "storage volume gates long-running replay by compacting before record and segment limits" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x7C),
    };

    var previous_version_id = object_store.ids.VersionId.zero;
    const iterations = @as(usize, storage_volume.testing.maxReplayLogSegments()) * 2 + 10;
    for (0..iterations) |index| {
        const payload = "stable-long-run-payload";
        const result = try store.putVersion(.{
            .preferred_object_id = object_store.ids.object(908),
            .object_type = .event_stream,
            .payload = payload,
            .metadata = try object_store.signMetadata(signer, "long-run", "text/plain", .event_stream, payload, 30 + @as(u64, @intCast(index))),
            .parent_version_id = if (previous_version_id.isZero()) null else previous_version_id,
        });
        previous_version_id = result.version_id;
        _ = try saveToImage(image, &store, &workspaces);
        try std.testing.expect((try storage_volume.testing.latestImageLogRecordCount(image)) <= storage_volume.testing.maxReplayLogRecords());
        try std.testing.expect((try storage_volume.testing.latestImageLogSegmentCount(image)) <= storage_volume.testing.maxReplayLogSegments());
    }

    try std.testing.expect((try storage_volume.testing.latestImageCompactedGeneration(image)) > storage_volume.testing.maxReplayLogSegments());

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(previous_version_id, loaded_store.latestVersion(908).?.id);
    try std.testing.expectEqual(@as(usize, iterations), loaded_store.versionCount());
}

test "storage volume persists a mutated workspace alongside an untouched one across saves" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    const allocator = std.testing.allocator;
    const volume = try allocator.create(storage_volume.Volume);
    defer allocator.destroy(volume);
    volume.reset();
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x72),
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(901),
        .object_type = .document,
        .payload = "alpha",
        .metadata = try object_store.signMetadata(signer, "alpha", "text/markdown", .document, "alpha", 20),
    });
    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    const journal = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "journal",
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(notes.id, 21);
    try workspaces.beginTransaction(journal.id);
    try workspaces.stagePut(journal.id, "documents/journal.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(journal.id, 22);
    _ = try volume.saveToImage(image, &store, &workspaces);

    const shared_principal = principal.PrincipalId{ .kind = .user, .serial = 2 };
    try workspaces.share(journal.id, .{
        .principal_id = shared_principal,
        .can_read = true,
        .can_write = true,
    });
    _ = try volume.saveToImage(image, &store, &workspaces);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_volume = try allocator.create(storage_volume.Volume);
    defer allocator.destroy(loaded_volume);
    loaded_volume.reset();
    _ = try loaded_volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 1 }, "notes").?;
    const loaded_journal = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 1 }, "journal").?;
    try std.testing.expectEqual(first.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);
    try std.testing.expectEqual(first.version_id, (try loaded_workspaces.resolve(loaded_journal.id, "documents/journal.md")).version_id);
    const loaded_grant = loaded_workspaces.findShareGrant(loaded_journal.id, shared_principal) orelse return error.ShareGrantNotPersisted;
    try std.testing.expect(loaded_grant.can_write);
}
