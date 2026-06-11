const std = @import("std");

const signing = @import("../../core/signing.zig");
const object_store = @import("store.zig");

const BlobSlot = object_store.BlobSlot;
const ChunkRef = object_store.ChunkRef;
const ChunkSlot = object_store.ChunkSlot;
const Error = object_store.Error;
const MAX_BLOB_CHUNKS = object_store.MAX_BLOB_CHUNKS;
const MAX_CHUNK_BYTES = object_store.MAX_CHUNK_BYTES;
const MAX_PAYLOAD_BYTES = object_store.MAX_PAYLOAD_BYTES;
const PAGE_SIZE_BYTES = object_store.PAGE_SIZE_BYTES;
const ObjectType = object_store.ObjectType;
const SignedMetadata = object_store.SignedMetadata;
const Store = object_store.Store;
const StoreWith = object_store.StoreWith;
const computeBlobAddress = object_store.computeBlobAddress;
const computeBlobManifestAddress = object_store.computeBlobManifestAddress;
const computeBlobMerkleRoot = object_store.computeBlobMerkleRoot;
const ids = object_store.ids;
const signMetadata = object_store.signMetadata;

test "object store keeps immutable signed versions with stable version addresses" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x21} ** 32,
    };
    const metadata_v1 = try signMetadata(signer, "notes", "text/markdown", .document, "hello", 10);
    const metadata_v2 = try signMetadata(signer, "notes", "text/markdown", .document, "hello, world", 11);

    const first = try store.putVersion(.{
        .preferred_object_id = ids.object(900),
        .object_type = .document,
        .payload = "hello",
        .metadata = metadata_v1,
    });
    const second = try store.putVersion(.{
        .preferred_object_id = ids.object(900),
        .object_type = .document,
        .payload = "hello, world",
        .metadata = metadata_v2,
        .parent_version_id = first.version_id,
    });

    try std.testing.expectEqual(@as(usize, 1), store.objectCount());
    try std.testing.expectEqual(@as(usize, 2), store.versionCount());
    try std.testing.expectEqual(ids.object(900), first.object_id);
    try std.testing.expectEqual(ids.object(900), second.object_id);
    try std.testing.expect(!std.mem.eql(u8, &first.version_address, &second.version_address));
    try std.testing.expectEqualStrings("hello", try store.versionPayload(store.version(first.version_id).?));
    try std.testing.expectEqualStrings("hello, world", try store.versionPayload(store.latestVersion(first.object_id).?));
    try std.testing.expectEqual(first.version_id, store.version(second.version_id).?.previous_version_id);
    try std.testing.expectEqual(@as(u8, 1), store.version(second.version_id).?.parent_count);
    try std.testing.expectEqual(first.version_id, store.version(second.version_id).?.parent_version_ids[0]);
    try std.testing.expectEqualStrings("zigos-storage-key", store.latestVersion(first.object_id).?.metadata.signature.signer);
    const object = store.object(first.object_id).?;
    try std.testing.expect(object.isPrimaryUserDataModel());
    const model = try store.objectOperatingModel(first.object_id);
    try std.testing.expect(model.isWholeOsObject());
    try std.testing.expectEqual(first.object_id, model.object_id);
    try std.testing.expectEqual(ObjectType.document, model.object_type);
    try std.testing.expectEqual(second.version_id, model.latest_version_id);
    try std.testing.expectEqual(@as(u16, 2), model.version_count);
    try std.testing.expectEqual(object_store.ObjectAccessModel.capability_scoped, model.access_model);
    try std.testing.expectEqual(object_store.ObjectSyncPolicy.local_first_selective, model.sync_policy);
    try std.testing.expectEqual(object_store.ObjectHistoryPolicy.signed_version_chain, model.history_policy);
    try std.testing.expectEqual(object_store.FileBridgePolicy.import_export_only, model.file_bridge_policy);
    try std.testing.expect(model.typed);
    try std.testing.expect(model.signed);
    try std.testing.expect(model.versioned);
    try std.testing.expect(model.has_history);
    try std.testing.expect(model.has_sync_policy);
    try std.testing.expect(model.has_sharing_policy);
    try std.testing.expect(model.recoverable);
    try std.testing.expectEqual(@as(u64, 10), object.provenance.created_at_ticks);
    try std.testing.expectEqual(@as(u64, 11), object.provenance.updated_at_ticks);
    try std.testing.expectEqual(@as(u16, 2), object.snapshot_state.snapshot_count);
    try std.testing.expectEqual(second.version_id, object.snapshot_state.latest_snapshot_version_id);
    try std.testing.expectEqual(second.version_id, object.sync_state.last_synced_version_id);
    try std.testing.expect(object.sharing_policy.requires_explicit_file_bridge_grant);
    try std.testing.expect(object.sharing_policy.export_only_file_bridge);
    try std.testing.expectEqual(first.version_id, object.recovery_history.latest_recoverable_version_id);
}

test "signed metadata rejects overlong labels instead of truncating" {
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x29} ** 32,
    };
    try std.testing.expectError(
        error.LabelTooLong,
        signMetadata(
            signer,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "text/plain",
            .document,
            "payload",
            1,
        ),
    );
}

test "object store splits blob and version addresses" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x44} ** 32,
    };
    const metadata_v1 = try signMetadata(signer, "notes-a", "text/plain", .document, "same", 10);
    const metadata_v2 = try signMetadata(signer, "notes-b", "text/plain", .document, "same", 11);

    const first = try store.putVersion(.{
        .preferred_object_id = ids.object(910),
        .object_type = .document,
        .payload = "same",
        .metadata = metadata_v1,
    });
    const second = try store.putVersion(.{
        .preferred_object_id = ids.object(911),
        .object_type = .document,
        .payload = "same",
        .metadata = metadata_v2,
    });

    try std.testing.expect(std.mem.eql(u8, &first.blob_address, &second.blob_address));
    try std.testing.expect(!std.mem.eql(u8, &first.version_address, &second.version_address));
    try std.testing.expect(std.mem.eql(u8, &store.version(first.version_id).?.blob_address, &first.blob_address));
    try std.testing.expect(std.mem.eql(u8, &store.version(second.version_id).?.version_address, &second.version_address));
    try std.testing.expectEqual(@as(usize, 1), store.blobCount());
}

test "object store indexes full blob addresses authoritatively" {
    var store = Store.init();

    const first_address = computeBlobAddress("first");
    const second_address = computeBlobAddress("second");

    const first_slot = try store.putBlob(first_address, "first");
    const second_slot = try store.putBlob(second_address, "second");
    try std.testing.expect(first_slot != second_slot);
    try std.testing.expectEqual(@as(usize, 2), store.blobCount());

    const first_again = try store.putBlob(first_address, "first");
    try std.testing.expectEqual(first_slot, first_again);
    try std.testing.expectEqual(@as(usize, 2), store.blobCount());
    try std.testing.expectEqual(@as(usize, 2), store.chunkCount());
    try std.testing.expectEqual(@as(u16, 2), store.blobSlotAtConst(first_slot).blob.ref_count);
    try std.testing.expectEqual(@as(u16, 1), store.blobSlotAtConst(second_slot).blob.ref_count);
    const first_blob = store.blob(first_address).?;
    const second_blob = store.blob(second_address).?;
    try std.testing.expectEqual(@as(u16, 1), first_blob.chunk_count);
    try std.testing.expectEqualStrings("first", store.chunk(first_blob.chunks[0].address).?.chunkSlice());
    try std.testing.expectEqualStrings("second", store.chunk(second_blob.chunks[0].address).?.chunkSlice());
    try std.testing.expectError(error.CorruptBlob, store.putBlob(first_address, "changed"));
}

test "object store streams page-sized chunks into Merkle-addressed blob manifests" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-large-storage-key",
        .seed = [_]u8{0x46} ** 32,
    };
    var payload: [PAGE_SIZE_BYTES * 3 + 17]u8 = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @intCast((index * 31) & 0xFF);
    }

    const result = try store.putVersion(.{
        .preferred_object_id = ids.object(913),
        .object_type = .media_asset,
        .payload = &payload,
        .metadata = try signMetadata(signer, "large-media", "application/octet-stream", .media_asset, &payload, 13),
    });

    const version_record = store.version(result.version_id).?;
    const blob = store.blob(version_record.blob_address).?;
    try std.testing.expectEqual(payload.len, blob.payload_len);
    try std.testing.expectEqual(@as(u16, 4), blob.chunk_count);
    try std.testing.expectEqual(@as(u16, PAGE_SIZE_BYTES), blob.chunks[0].payload_len);
    try std.testing.expectEqual(@as(u16, 17), blob.chunks[3].payload_len);
    const chunk_count: usize = @intCast(blob.chunk_count);
    try std.testing.expect(std.mem.eql(u8, &blob.merkle_root, &computeBlobMerkleRoot(blob.chunks[0..chunk_count])));
    try std.testing.expect(std.mem.eql(u8, &blob.address, &computeBlobManifestAddress(blob.payload_len, blob.chunks[0..chunk_count])));
    try std.testing.expectEqual(@as(usize, 0), store.verifiedBlobManifestCount());

    var cursor = try store.versionChunkCursor(version_record);
    try std.testing.expectEqual(@as(usize, 1), store.verifiedBlobManifestCount());
    var streamed_len: usize = 0;
    var streamed_chunks: usize = 0;
    while (try cursor.next()) |chunk| {
        try std.testing.expectEqual(streamed_len, chunk.offset);
        try std.testing.expectEqualSlices(u8, payload[chunk.offset .. chunk.offset + chunk.bytes.len], chunk.bytes);
        streamed_len += chunk.bytes.len;
        streamed_chunks += 1;
    }
    try std.testing.expectEqual(payload.len, streamed_len);
    try std.testing.expectEqual(chunk_count, streamed_chunks);

    var out: [payload.len]u8 = undefined;
    const transferred = try store.transferVersionPayload(version_record, &out);
    try std.testing.expectEqual(payload.len, transferred.bytes_transferred);
    try std.testing.expectEqual(chunk_count, transferred.chunks_transferred);
    try std.testing.expectEqualSlices(u8, &payload, out[0..transferred.bytes_transferred]);
    try std.testing.expectEqual(@as(usize, 1), store.verifiedBlobManifestCount());
}

test "object store accepts payloads beyond the old sixteen-page ceiling" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-paged-storage-key",
        .seed = [_]u8{0x47} ** 32,
    };
    var payload: [PAGE_SIZE_BYTES * 16 + 17]u8 = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @intCast((index * 17 + 3) & 0xFF);
    }

    const result = try store.putVersion(.{
        .preferred_object_id = ids.object(914),
        .object_type = .model_artifact,
        .payload = &payload,
        .metadata = try signMetadata(signer, "model-shard", "application/octet-stream", .model_artifact, &payload, 14),
    });

    const version_record = store.version(result.version_id).?;
    const blob = store.blob(version_record.blob_address).?;
    try std.testing.expectEqual(@as(u16, 17), blob.chunk_count);
    try std.testing.expectEqual(payload.len, blob.payload_len);

    var out: [payload.len]u8 = undefined;
    const loaded = try store.versionPayloadInto(version_record, &out);
    try std.testing.expectEqualSlices(u8, &payload, loaded);
}

test "object store verifies blob backend corruption before serving payloads" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x45} ** 32,
    };

    const result = try store.putVersion(.{
        .preferred_object_id = ids.object(912),
        .object_type = .document,
        .payload = "checked",
        .metadata = try signMetadata(signer, "checked", "text/plain", .document, "checked", 12),
    });

    const version_record = store.version(result.version_id).?;
    const chunk_slot_index = store.blobSlotAtConst(version_record.blob_slot_index).blob.chunks[0].slot_index;
    store.chunkSlotAt(chunk_slot_index).chunk.payload[0] ^= 0xFF;
    try std.testing.expectError(error.CorruptBlob, store.versionPayload(version_record));
}

test "object store supports every native object type and rejects unsigned metadata" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x34} ** 32,
    };
    const object_types = [_]ObjectType{
        .blob,
        .document,
        .collection,
        .secret,
        .media_asset,
        .model_artifact,
        .event_stream,
    };

    for (object_types, 0..) |object_type, index| {
        const payload = switch (object_type) {
            .blob => "blob",
            .document => "document",
            .collection => "collection",
            .secret => "secret",
            .media_asset => "media",
            .model_artifact => "model",
            .event_stream => "events",
        };
        _ = try store.putVersion(.{
            .preferred_object_id = ids.object(1000 + @as(u64, @intCast(index))),
            .object_type = object_type,
            .payload = payload,
            .metadata = try signMetadata(signer, payload, "application/octet-stream", object_type, payload, @intCast(index)),
        });
    }

    try std.testing.expectEqual(object_types.len, store.objectCount());
    try std.testing.expectError(error.UnsignedMetadata, store.putVersion(.{
        .object_type = .blob,
        .payload = "unsigned",
        .metadata = try SignedMetadata.init("unsigned", "application/octet-stream", .{}, 0),
    }));
}

test "object store rejects tampered metadata signatures" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x55} ** 32,
    };
    var metadata = try signMetadata(signer, "notes", "text/markdown", .document, "hello", 10);
    metadata.created_at_ticks = 11;

    try std.testing.expectError(error.InvalidSignature, store.putVersion(.{
        .preferred_object_id = ids.object(901),
        .object_type = .document,
        .payload = "hello",
        .metadata = metadata,
    }));
}

test "object store capacity is configurable" {
    const SmallStore = StoreWith(.{
        .max_objects = 1,
        .max_versions = 1,
        .max_blobs = 64,
        .max_chunks = 64,
        .object_index_capacity = 2,
        .version_index_capacity = 2,
        .blob_index_capacity = 128,
        .chunk_index_capacity = 128,
    });
    var store = SmallStore.init();
    const signer = signing.SignerIdentity{
        .label = "small-store",
        .seed = [_]u8{0x66} ** 32,
    };

    _ = try store.putVersion(.{
        .preferred_object_id = ids.object(1),
        .object_type = .document,
        .payload = "one",
        .metadata = try signMetadata(signer, "one", "text/plain", .document, "one", 1),
    });

    try std.testing.expectError(error.ObjectTableFull, store.putVersion(.{
        .preferred_object_id = ids.object(2),
        .object_type = .document,
        .payload = "two",
        .metadata = try signMetadata(signer, "two", "text/plain", .document, "two", 2),
    }));
    try std.testing.expectEqual(@as(usize, 64), store.blobSlotCapacity());
    try std.testing.expectEqual(@as(usize, 64), store.chunkSlotCapacity());
}
