const std = @import("std");

const signing = @import("../../core/signing.zig");
const object_store = @import("store.zig");

const BlobSlot = object_store.BlobSlot;
const BlobRecord = object_store.BlobRecord;
const BlobChunkSlotIndex = object_store.BlobChunkSlotIndex;
const VersionBlobSlotIndex = object_store.VersionBlobSlotIndex;
const ChunkRef = object_store.ChunkRef;
const ChunkSlot = object_store.ChunkSlot;
const Error = object_store.Error;
const MAX_BLOB_CHUNKS = object_store.MAX_BLOB_CHUNKS;
const MAX_CHUNK_BYTES = object_store.MAX_CHUNK_BYTES;
const MAX_INLINE_PAYLOAD_BYTES = object_store.MAX_INLINE_PAYLOAD_BYTES;
const MAX_OBJECT_QUERY_RESULTS = object_store.MAX_OBJECT_QUERY_RESULTS;
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

test "blob manifests store compact chunk slot edges" {
    try std.testing.expectEqual(@as(usize, 2), @sizeOf(BlobChunkSlotIndex));
    try std.testing.expect(@hasField(object_store.BlobRecord, "chunk_slot_indexes"));
    try std.testing.expect(!@hasField(object_store.BlobRecord, "chunks"));
}

test "resident object metadata uses capacity-sized length fields" {
    try std.testing.expectEqual(@as(usize, 248), @sizeOf(SignedMetadata));
    try std.testing.expectEqual(@as(usize, 132), @sizeOf(BlobRecord));
    try std.testing.expectEqual(@as(usize, 136), @sizeOf(BlobSlot));
}

test "object query and history outputs use compact bounded metadata" {
    try std.testing.expect(object_store.COMPACT_OBJECT_RESULT_METADATA);
    try std.testing.expectEqual(u8, @FieldType(object_store.ObjectQueryResult, "label_len"));
    try std.testing.expectEqual(u8, @FieldType(object_store.ObjectQueryResult, "content_type_len"));
    try std.testing.expectEqual(u32, @FieldType(object_store.ObjectHistoryEntry, "payload_len"));
    try std.testing.expectEqual(u8, @FieldType(object_store.ObjectHistoryEntry, "label_len"));
    try std.testing.expectEqual(u8, @FieldType(object_store.ObjectHistoryEntry, "content_type_len"));
    try std.testing.expectEqual(
        @as(usize, object_store.OBJECT_QUERY_RESULT_SIZE_CEILING_BYTES),
        @sizeOf(object_store.ObjectQueryResult),
    );
    try std.testing.expectEqual(
        @as(usize, object_store.OBJECT_HISTORY_ENTRY_SIZE_CEILING_BYTES),
        @sizeOf(object_store.ObjectHistoryEntry),
    );
}

test "object type index uses capacity-sized resident links" {
    const ObjectTypeIndex = @FieldType(Store, "object_type_index");

    try std.testing.expectEqual(@as(usize, 213), @sizeOf(ObjectTypeIndex));
}
test "versions retain only compact canonical blob references" {
    try std.testing.expectEqual(@as(usize, 2), @sizeOf(VersionBlobSlotIndex));
    try std.testing.expect(!@hasField(object_store.VersionRecord, "blob_address"));
    try std.testing.expect(!@hasField(object_store.VersionRecord, "payload_len"));
    try std.testing.expect(!@hasField(object_store.VersionRecord, "chunk_count"));
}

test "object store keeps immutable signed versions with stable version addresses" {
    var store = Store.init();
    try std.testing.expect(object_store.DERIVES_LATEST_INSERTED_VERSION_FROM_ARENA_STATE);
    try std.testing.expect(!@hasField(Store, "latest_inserted_version_id"));
    try std.testing.expect(store.latestInsertedVersionConst() == null);

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x21),
    };
    const metadata_v1 = try signMetadata(signer, "notes", "text/markdown", .document, "hello", 10);
    const metadata_v2 = try signMetadata(signer, "notes", "text/markdown", .document, "hello, world", 11);

    const first = try store.putVersion(.{
        .preferred_object_id = ids.object(900),
        .object_type = .document,
        .payload = "hello",
        .metadata = metadata_v1,
    });
    try std.testing.expectEqual(first.version_id, store.latestInsertedVersionConst().?.id);

    const second = try store.putVersion(.{
        .preferred_object_id = ids.object(900),
        .object_type = .document,
        .payload = "hello, world",
        .metadata = metadata_v2,
        .parent_version_id = first.version_id,
    });
    try std.testing.expectEqual(second.version_id, store.latestInsertedVersionConst().?.id);
    store.next_version_id += 4;
    try std.testing.expectEqual(second.version_id, store.latestInsertedVersionConst().?.id);
    store.rebuildIndexes();
    try std.testing.expectEqual(second.version_id, store.latestInsertedVersionConst().?.id);

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
    try std.testing.expectEqual(@as(u32, 2), model.sync_generation);
    try std.testing.expectEqual(@as(u32, 1), model.sharing_policy_generation);
    try std.testing.expect(model.has_history);
    try std.testing.expect(model.has_sync_policy);
    try std.testing.expect(model.has_sharing_policy);
    try std.testing.expect(model.recoverable);
    try std.testing.expect(object_store.DERIVES_OBJECT_MODEL_VERSION_IDS_FROM_CANONICAL_HEAD);
    try std.testing.expect(object_store.DERIVES_OBJECT_MODEL_COUNTERS_FROM_VERSION_COUNT);
    try std.testing.expect(!@hasField(object_store.ObjectRecord, "snapshot_state"));
    try std.testing.expect(!@hasField(object_store.ObjectRecord, "sync_state"));
    try std.testing.expect(object_store.DERIVES_OBJECT_POLICY_AND_RECOVERY_FROM_CANONICAL_DATA);
    try std.testing.expect(!@hasField(object_store.ObjectRecord, "sharing_policy"));
    try std.testing.expect(!@hasField(object_store.ObjectRecord, "recovery_history"));
    try std.testing.expect(object_store.DERIVES_OBJECT_PROVENANCE_FROM_CANONICAL_VERSIONS);
    try std.testing.expect(!@hasField(object_store.ObjectRecord, "provenance"));
    try std.testing.expectEqual(@as(usize, object_store.OBJECT_RECORD_SIZE_CEILING_BYTES), @sizeOf(object_store.ObjectRecord));
}

test "signed metadata rejects overlong labels instead of truncating" {
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x29),
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
        .seed = signing.seedFromByte(0x44),
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
    try std.testing.expect(std.mem.eql(u8, &store.versionBlob(store.version(first.version_id).?).?.address, &first.blob_address));
    try std.testing.expect(std.mem.eql(u8, &store.version(second.version_id).?.version_address, &second.version_address));
    try std.testing.expectEqual(@as(usize, 1), store.blobCount());
}

test "object store indexes full blob addresses authoritatively" {
    var store = Store.init();
    try std.testing.expectEqual(@as(usize, 0), store.maxBlobPayloadBytes());

    const first_address = computeBlobAddress("first");
    const second_address = computeBlobAddress("second");

    const first_slot = try store.putBlob(first_address, "first");
    const second_slot = try store.putBlob(second_address, "second");
    try std.testing.expect(first_slot != second_slot);
    try std.testing.expectEqual(@as(usize, 2), store.blobCount());
    try std.testing.expectEqual(@as(usize, "second".len), store.maxBlobPayloadBytes());

    const first_again = try store.putBlob(first_address, "first");
    try std.testing.expectEqual(first_slot, first_again);
    store.rebuildIndexes();
    try std.testing.expectEqual(@as(usize, "second".len), store.maxBlobPayloadBytes());
    try std.testing.expectEqual(@as(usize, 2), store.blobCount());
    try std.testing.expectEqual(@as(usize, 2), store.chunkCount());
    try std.testing.expectEqual(@as(u16, 2), store.blobSlotAtConst(first_slot).blob.ref_count);
    try std.testing.expectEqual(@as(u16, 1), store.blobSlotAtConst(second_slot).blob.ref_count);
    const first_blob = store.blob(first_address).?;
    const second_blob = store.blob(second_address).?;
    try std.testing.expectEqual(@as(u16, 1), first_blob.chunk_count);
    try std.testing.expectEqualStrings("first", store.blobChunk(first_blob, 0).?.chunkSlice());
    try std.testing.expectEqualStrings("second", store.blobChunk(second_blob, 0).?.chunkSlice());
    try std.testing.expectError(error.CorruptBlob, store.putBlob(first_address, "changed"));
}

test "object store streams page-sized chunks into Merkle-addressed blob manifests" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-large-storage-key",
        .seed = signing.seedFromByte(0x46),
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
    const blob = store.versionBlob(version_record).?;
    try std.testing.expectEqual(payload.len, blob.payloadLen());
    try std.testing.expectEqual(@as(u16, 4), blob.chunk_count);
    try std.testing.expectEqual(@as(u16, PAGE_SIZE_BYTES), store.blobChunk(blob, 0).?.payload_len);
    try std.testing.expectEqual(@as(u16, 17), store.blobChunk(blob, 3).?.payload_len);
    var chunk_refs = [_]ChunkRef{ChunkRef{}} ** MAX_BLOB_CHUNKS;
    const live_chunk_refs = try store.copyBlobChunkRefs(blob, &chunk_refs);
    const chunk_count = live_chunk_refs.len;
    try std.testing.expect(std.mem.eql(u8, &blob.merkle_root, &computeBlobMerkleRoot(live_chunk_refs)));
    try std.testing.expect(std.mem.eql(u8, &blob.address, &computeBlobManifestAddress(blob.payloadLen(), live_chunk_refs)));
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
        .seed = signing.seedFromByte(0x47),
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
    const blob = store.versionBlob(version_record).?;
    try std.testing.expectEqual(@as(u16, 17), blob.chunk_count);
    try std.testing.expectEqual(payload.len, blob.payloadLen());

    var out: [payload.len]u8 = undefined;
    const loaded = try store.versionPayloadInto(version_record, &out);
    try std.testing.expectEqualSlices(u8, &payload, loaded);
}

test "inline payload reads are bounded independently from object capacity" {
    try std.testing.expect(MAX_INLINE_PAYLOAD_BYTES < MAX_PAYLOAD_BYTES);
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-inline-read-key",
        .seed = signing.seedFromByte(0x48),
    };

    const inline_payload = [_]u8{0x31} ** MAX_INLINE_PAYLOAD_BYTES;
    const inline_result = try store.putVersion(.{
        .preferred_object_id = ids.object(915),
        .object_type = .document,
        .payload = &inline_payload,
        .metadata = try signMetadata(signer, "inline", "application/octet-stream", .document, &inline_payload, 15),
    });
    try std.testing.expectEqualSlices(
        u8,
        &inline_payload,
        try store.versionPayload(store.version(inline_result.version_id).?),
    );

    const streamed_payload = [_]u8{0x32} ** (MAX_INLINE_PAYLOAD_BYTES + 1);
    const streamed_result = try store.putVersion(.{
        .preferred_object_id = ids.object(916),
        .object_type = .model_artifact,
        .payload = &streamed_payload,
        .metadata = try signMetadata(signer, "streamed", "application/octet-stream", .model_artifact, &streamed_payload, 16),
    });
    const streamed_version = store.version(streamed_result.version_id).?;
    try std.testing.expectError(error.PayloadRequiresStreaming, store.versionPayload(streamed_version));
    var out: [streamed_payload.len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &streamed_payload,
        try store.versionPayloadInto(streamed_version, &out),
    );
}

test "object store verifies blob backend corruption before serving payloads" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x45),
    };

    const result = try store.putVersion(.{
        .preferred_object_id = ids.object(912),
        .object_type = .document,
        .payload = "checked",
        .metadata = try signMetadata(signer, "checked", "text/plain", .document, "checked", 12),
    });

    const version_record = store.version(result.version_id).?;
    const version_blob_slot_index = version_record.blob_slot_index;
    version_record.blob_slot_index = std.math.maxInt(VersionBlobSlotIndex);
    try std.testing.expectError(error.CorruptBlob, store.versionPayload(version_record));
    version_record.blob_slot_index = version_blob_slot_index;

    const blob = &store.blobSlotAtConst(version_record.blob_slot_index).blob;
    const chunk_slot_index = store.blobChunkSlotIndex(blob, 0).?;
    store.chunkSlotAt(chunk_slot_index).chunk.payload[0] ^= 0xFF;
    try std.testing.expectError(error.CorruptBlob, store.versionPayload(version_record));

    store.chunkSlotAt(chunk_slot_index).chunk.payload[0] ^= 0xFF;
    store.blobSlotAt(version_record.blob_slot_index).blob.chunk_slot_indexes[0] = std.math.maxInt(BlobChunkSlotIndex);
    try std.testing.expectError(error.CorruptBlob, store.versionPayload(version_record));
}

test "object store supports every native object type and rejects unsigned metadata" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x34),
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
    var query_buffer: [MAX_OBJECT_QUERY_RESULTS]object_store.ObjectQueryResult = undefined;
    const secret_results = store.queryObjects(.{ .object_type = .secret }, &query_buffer);
    try std.testing.expectEqual(@as(usize, 1), secret_results.len);
    try std.testing.expectEqual(ObjectType.secret, secret_results[0].object_type);
    try std.testing.expectEqual(@as(usize, 1), store.object_type_index.count(.secret));
    store.rebuildIndexes();
    const media_results = store.queryObjects(.{ .object_type = .media_asset }, &query_buffer);
    try std.testing.expectEqual(@as(usize, 1), media_results.len);
    try std.testing.expectEqual(ObjectType.media_asset, media_results[0].object_type);

    try std.testing.expectError(error.UnsignedMetadata, store.putVersion(.{
        .object_type = .blob,
        .payload = "unsigned",
        .metadata = try SignedMetadata.init("unsigned", "application/octet-stream", .{}, 0),
    }));
}

test "object queries select globally newest bounded results" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "bounded-query-key",
        .seed = signing.seedFromByte(0x35),
    };
    const objects = [_]struct {
        id: u64,
        object_type: ObjectType,
        updated_at_ticks: u64,
    }{
        .{ .id = 100, .object_type = .document, .updated_at_ticks = 50 },
        .{ .id = 101, .object_type = .blob, .updated_at_ticks = 100 },
        .{ .id = 102, .object_type = .document, .updated_at_ticks = 10 },
        .{ .id = 105, .object_type = .document, .updated_at_ticks = 40 },
        .{ .id = 104, .object_type = .blob, .updated_at_ticks = 90 },
        .{ .id = 103, .object_type = .document, .updated_at_ticks = 40 },
    };

    for (objects) |object| {
        const payload = if (object.object_type == .document) "document" else "blob";
        _ = try store.putVersion(.{
            .preferred_object_id = ids.object(object.id),
            .object_type = object.object_type,
            .payload = payload,
            .metadata = try signMetadata(
                signer,
                "query candidate",
                "text/plain",
                object.object_type,
                payload,
                object.updated_at_ticks,
            ),
        });
    }

    var newest_buffer: [3]object_store.ObjectQueryResult = undefined;
    const newest = store.queryObjects(.{}, &newest_buffer);
    try std.testing.expectEqual(@as(usize, 3), newest.len);
    try std.testing.expectEqual(ids.object(101), newest[0].object_id);
    try std.testing.expectEqual(ids.object(104), newest[1].object_id);
    try std.testing.expectEqual(ids.object(100), newest[2].object_id);

    store.rebuildIndexes();
    var document_buffer: [2]object_store.ObjectQueryResult = undefined;
    const newest_documents = store.queryObjects(.{
        .object_type = .document,
        .label_contains = "QUERY",
        .content_type = "text/plain",
        .updated_since_ticks = 40,
    }, &document_buffer);
    try std.testing.expectEqual(@as(usize, 2), newest_documents.len);
    try std.testing.expectEqual(ids.object(100), newest_documents[0].object_id);
    try std.testing.expectEqual(ids.object(103), newest_documents[1].object_id);
}

test "object store rejects tampered metadata signatures" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x55),
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

test "object store locally signs trusted writes and keeps submitted metadata verification" {
    var store = Store.init();
    const signer = signing.SignerIdentity{
        .label = "local-storage-writer",
        .seed = signing.seedFromByte(0x56),
    };
    const result = try store.putLocallySignedVersion(.{
        .preferred_object_id = ids.object(902),
        .object_type = .document,
        .payload = "locally signed",
        .signer = signer,
        .label = "local",
        .content_type = "text/plain",
        .created_at_ticks = 12,
    });

    const version = store.version(result.version_id).?;
    try std.testing.expect(version.metadata.signature.isComplete());
    try std.testing.expectEqualStrings(signer.label, version.metadata.signature.signer);
    try std.testing.expect(version.metadata.verifyFor(.document, "locally signed"));

    var submitted = version.metadata;
    submitted.created_at_ticks += 1;
    try std.testing.expectError(error.InvalidSignature, store.putVersion(.{
        .preferred_object_id = ids.object(903),
        .object_type = .document,
        .payload = "locally signed",
        .metadata = submitted,
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
        .seed = signing.seedFromByte(0x66),
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

test "object store stops generated object identifiers at exhaustion" {
    var store = Store.init();
    store.next_object_id = std.math.maxInt(u64);
    const signer = signing.SignerIdentity{
        .label = "object-id-exhaustion",
        .seed = signing.seedFromByte(0x67),
    };

    const final = try store.putVersion(.{
        .object_type = .document,
        .payload = "final object",
        .metadata = try signMetadata(signer, "final", "text/plain", .document, "final object", 1),
    });
    try std.testing.expectEqual(std.math.maxInt(u64), final.object_id.raw());
    try std.testing.expectEqual(@as(u64, 0), store.next_object_id);

    const object_count = store.objectCount();
    const version_count = store.versionCount();
    const blob_count = store.blobCount();
    const chunk_count = store.chunkCount();
    const next_version_id = store.next_version_id;
    try std.testing.expectError(error.ObjectIdExhausted, store.putVersion(.{
        .preferred_object_id = ids.object(17),
        .object_type = .document,
        .payload = "must not publish",
        .metadata = try signMetadata(signer, "rejected", "text/plain", .document, "must not publish", 2),
    }));
    try std.testing.expectEqual(object_count, store.objectCount());
    try std.testing.expectEqual(version_count, store.versionCount());
    try std.testing.expectEqual(blob_count, store.blobCount());
    try std.testing.expectEqual(chunk_count, store.chunkCount());
    try std.testing.expectEqual(next_version_id, store.next_version_id);
}

test "object store stops version identifiers before publishing a new object" {
    var store = Store.init();
    store.next_version_id = std.math.maxInt(u64);
    const signer = signing.SignerIdentity{
        .label = "version-id-exhaustion",
        .seed = signing.seedFromByte(0x68),
    };

    const final = try store.putVersion(.{
        .preferred_object_id = ids.object(77),
        .object_type = .document,
        .payload = "final version",
        .metadata = try signMetadata(signer, "final", "text/plain", .document, "final version", 1),
    });
    try std.testing.expectEqual(std.math.maxInt(u64), final.version_id.raw());
    try std.testing.expectEqual(@as(u64, 0), store.next_version_id);
    try std.testing.expectEqual(final.version_id, store.latestInsertedVersionConst().?.id);

    const object_count = store.objectCount();
    const blob_count = store.blobCount();
    const chunk_count = store.chunkCount();
    const next_object_id = store.next_object_id;
    try std.testing.expectError(error.VersionIdExhausted, store.putVersion(.{
        .preferred_object_id = ids.object(78),
        .object_type = .document,
        .payload = "must not publish",
        .metadata = try signMetadata(signer, "rejected", "text/plain", .document, "must not publish", 2),
    }));
    try std.testing.expectEqual(object_count, store.objectCount());
    try std.testing.expectEqual(@as(usize, 1), store.versionCount());
    try std.testing.expectEqual(blob_count, store.blobCount());
    try std.testing.expectEqual(chunk_count, store.chunkCount());
    try std.testing.expectEqual(next_object_id, store.next_object_id);
    try std.testing.expectEqual(final.version_id, store.latestInsertedVersionConst().?.id);
}
