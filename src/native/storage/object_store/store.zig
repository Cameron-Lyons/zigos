const std = @import("std");
const binary_cursor = @import("binary_cursor");
const crypto_hash = @import("../../core/crypto_hash.zig");
pub const ids = @import("../../core/ids.zig");
const indexed_arena = @import("../../core/indexed_arena.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const signing = @import("../../core/signing.zig");

pub const MAX_OBJECTS: usize = 192;
pub const MAX_VERSIONS: usize = 768;
pub const MAX_BLOBS: usize = 640;
pub const PAGE_SIZE_BYTES: usize = 4096;
pub const MAX_CHUNK_BYTES: usize = PAGE_SIZE_BYTES;
pub const MAX_BLOB_CHUNKS: usize = 28;
pub const MAX_CHUNKS: usize = 224;
pub const MAX_BLOB_BYTES: usize = MAX_CHUNK_BYTES * MAX_BLOB_CHUNKS;
pub const MAX_PAYLOAD_BYTES: usize = MAX_BLOB_BYTES;
pub const MAX_VERSION_PARENTS: usize = 2;
pub const MAX_OBJECT_QUERY_RESULTS: usize = 16;
pub const MAX_OBJECT_HISTORY_RESULTS: usize = 16;
const MAX_METADATA_MESSAGE_BYTES: usize = 256;
pub const MAX_METADATA_LABEL_BYTES: usize = 48;
pub const MAX_CONTENT_TYPE_BYTES: usize = 64;
const OBJECT_INDEX_CAPACITY: usize = MAX_OBJECTS * 2;
const VERSION_INDEX_CAPACITY: usize = MAX_VERSIONS * 2;
const BLOB_INDEX_CAPACITY: usize = MAX_BLOBS * 2;
const CHUNK_INDEX_CAPACITY: usize = MAX_CHUNKS * 2;
const BLOB_PAGE_SIZE: usize = 64;
const CHUNK_PAGE_SIZE: usize = 32;

pub const StoreConfig = struct {
    max_objects: usize = MAX_OBJECTS,
    max_versions: usize = MAX_VERSIONS,
    max_blobs: usize = MAX_BLOBS,
    max_chunks: usize = MAX_CHUNKS,
    object_index_capacity: usize = OBJECT_INDEX_CAPACITY,
    version_index_capacity: usize = VERSION_INDEX_CAPACITY,
    blob_index_capacity: usize = BLOB_INDEX_CAPACITY,
    chunk_index_capacity: usize = CHUNK_INDEX_CAPACITY,

    pub fn validate(comptime config: StoreConfig) void {
        if (config.max_objects == 0) @compileError("object store requires at least one object slot");
        if (config.max_versions == 0) @compileError("object store requires at least one version slot");
        if (config.max_blobs == 0) @compileError("object store requires at least one blob slot");
        if (config.max_chunks == 0) @compileError("object store requires at least one chunk slot");
        if (config.object_index_capacity < config.max_objects) @compileError("object index capacity must cover object slots");
        if (config.version_index_capacity < config.max_versions) @compileError("version index capacity must cover version slots");
        if (config.blob_index_capacity < config.max_blobs) @compileError("blob index capacity must cover blob slabs");
        if (config.chunk_index_capacity < config.max_chunks) @compileError("chunk index capacity must cover chunk slots");
        if (config.max_blobs % BLOB_PAGE_SIZE != 0) @compileError("blob slab capacity must be a whole number of pages");
        if (config.max_chunks % CHUNK_PAGE_SIZE != 0) @compileError("chunk slab capacity must be a whole number of pages");
    }
};

pub const ObjectType = enum(u8) {
    blob,
    document,
    collection,
    secret,
    media_asset,
    model_artifact,
    event_stream,
};
const OBJECT_TYPE_COUNT: usize = @typeInfo(ObjectType).@"enum".fields.len;

pub const BlobAddress = crypto_hash.Digest;
pub const ChunkAddress = crypto_hash.Digest;
pub const VersionAddress = crypto_hash.Digest;

pub const SignedMetadata = struct {
    signature: manifest.Signature = .{},
    label_len: usize = 0,
    label: [MAX_METADATA_LABEL_BYTES]u8 = [_]u8{0} ** MAX_METADATA_LABEL_BYTES,
    content_type_len: usize = 0,
    content_type: [MAX_CONTENT_TYPE_BYTES]u8 = [_]u8{0} ** MAX_CONTENT_TYPE_BYTES,
    created_at_ticks: u64 = 0,

    pub fn init(
        label: []const u8,
        content_type: []const u8,
        signature: manifest.Signature,
        created_at_ticks: u64,
    ) error{ LabelTooLong, ContentTypeTooLong }!SignedMetadata {
        var metadata = SignedMetadata{
            .signature = signature,
            .created_at_ticks = created_at_ticks,
        };
        metadata.label_len = native_util.copyTextExact(&metadata.label, label) catch return error.LabelTooLong;
        metadata.content_type_len = native_util.copyTextExact(&metadata.content_type, content_type) catch return error.ContentTypeTooLong;
        return metadata;
    }

    pub fn labelSlice(self: *const SignedMetadata) []const u8 {
        return self.label[0..@min(self.label_len, self.label.len)];
    }

    pub fn contentTypeSlice(self: *const SignedMetadata) []const u8 {
        return self.content_type[0..@min(self.content_type_len, self.content_type.len)];
    }

    pub fn isSigned(self: *const SignedMetadata) bool {
        return self.signature.isPresent();
    }

    pub fn verifyFor(
        self: *const SignedMetadata,
        object_type: ObjectType,
        payload: []const u8,
    ) bool {
        var message_buffer: [MAX_METADATA_MESSAGE_BYTES]u8 = undefined;
        const message = metadataMessage(&message_buffer, object_type, payload, self.*) catch return false;
        return signing.verify(self.signature, message);
    }
};

pub const PutRequest = struct {
    preferred_object_id: ?ids.ObjectId = null,
    object_type: ObjectType,
    payload: []const u8,
    metadata: SignedMetadata,
    parent_version_id: ?ids.VersionId = null,
};

pub const PutResult = struct {
    object_id: ids.ObjectId,
    version_id: ids.VersionId,
    blob_address: BlobAddress,
    version_address: VersionAddress,
    new_object: bool,
};

pub const ObjectQuery = struct {
    object_type: ?ObjectType = null,
    label_contains: []const u8 = "",
    content_type: []const u8 = "",
    updated_since_ticks: u64 = 0,
};

pub const ObjectQueryResult = struct {
    object_id: ids.ObjectId = ids.ObjectId.zero,
    latest_version_id: ids.VersionId = ids.VersionId.zero,
    object_type: ObjectType = .blob,
    version_count: u16 = 0,
    snapshot_count: u16 = 0,
    updated_at_ticks: u64 = 0,
    label_len: usize = 0,
    label: [MAX_METADATA_LABEL_BYTES]u8 = [_]u8{0} ** MAX_METADATA_LABEL_BYTES,
    content_type_len: usize = 0,
    content_type: [MAX_CONTENT_TYPE_BYTES]u8 = [_]u8{0} ** MAX_CONTENT_TYPE_BYTES,

    pub fn labelSlice(self: *const ObjectQueryResult) []const u8 {
        return self.label[0..@min(self.label_len, self.label.len)];
    }

    pub fn contentTypeSlice(self: *const ObjectQueryResult) []const u8 {
        return self.content_type[0..@min(self.content_type_len, self.content_type.len)];
    }
};

pub const ObjectHistoryEntry = struct {
    object_id: ids.ObjectId = ids.ObjectId.zero,
    version_id: ids.VersionId = ids.VersionId.zero,
    previous_version_id: ids.VersionId = ids.VersionId.zero,
    parent_count: u8 = 0,
    object_type: ObjectType = .blob,
    payload_len: usize = 0,
    created_at_ticks: u64 = 0,
    label_len: usize = 0,
    label: [MAX_METADATA_LABEL_BYTES]u8 = [_]u8{0} ** MAX_METADATA_LABEL_BYTES,
    content_type_len: usize = 0,
    content_type: [MAX_CONTENT_TYPE_BYTES]u8 = [_]u8{0} ** MAX_CONTENT_TYPE_BYTES,

    pub fn labelSlice(self: *const ObjectHistoryEntry) []const u8 {
        return self.label[0..@min(self.label_len, self.label.len)];
    }

    pub fn contentTypeSlice(self: *const ObjectHistoryEntry) []const u8 {
        return self.content_type[0..@min(self.content_type_len, self.content_type.len)];
    }
};

pub const ObjectAccessModel = enum(u8) {
    capability_scoped,
};

pub const ObjectSyncPolicy = enum(u8) {
    local_first_selective,
};

pub const ObjectHistoryPolicy = enum(u8) {
    signed_version_chain,
};

pub const FileBridgePolicy = enum(u8) {
    import_export_only,
};

pub const ObjectOperatingModel = struct {
    object_id: ids.ObjectId = ids.ObjectId.zero,
    object_type: ObjectType = .blob,
    latest_version_id: ids.VersionId = ids.VersionId.zero,
    version_count: u16 = 0,
    typed: bool = false,
    signed: bool = false,
    versioned: bool = false,
    access_model: ObjectAccessModel = .capability_scoped,
    sync_policy: ObjectSyncPolicy = .local_first_selective,
    history_policy: ObjectHistoryPolicy = .signed_version_chain,
    file_bridge_policy: FileBridgePolicy = .import_export_only,
    sync_generation: u32 = 0,
    sharing_policy_generation: u32 = 0,
    has_history: bool = false,
    has_sync_policy: bool = false,
    has_sharing_policy: bool = false,
    recoverable: bool = false,

    pub fn isWholeOsObject(self: *const ObjectOperatingModel) bool {
        return self.typed and
            self.signed and
            self.versioned and
            self.access_model == .capability_scoped and
            self.sync_policy == .local_first_selective and
            self.history_policy == .signed_version_chain and
            self.file_bridge_policy == .import_export_only and
            self.has_history and
            self.has_sync_policy and
            self.has_sharing_policy and
            self.recoverable;
    }
};

pub const ObjectRecord = struct {
    id: ids.ObjectId,
    object_type: ObjectType,
    latest_version_id: ids.VersionId,
    version_count: u16,
    provenance: ObjectProvenance = .{},
    snapshot_state: ObjectSnapshotState = .{},
    sync_state: ObjectSyncState = .{},
    sharing_policy: ObjectSharingPolicy = .{},
    recovery_history: ObjectRecoveryHistory = .{},

    pub fn isPrimaryUserDataModel(self: *const ObjectRecord) bool {
        const model = self.operatingModel();
        return model.isWholeOsObject();
    }

    pub fn operatingModel(self: *const ObjectRecord) ObjectOperatingModel {
        return .{
            .object_id = self.id,
            .object_type = self.object_type,
            .latest_version_id = self.latest_version_id,
            .version_count = self.version_count,
            .typed = true,
            .signed = self.provenance.creator_signature.isPresent() and self.provenance.latest_version_addressed,
            .versioned = self.version_count > 0 and !self.latest_version_id.isZero(),
            .sync_generation = self.sync_state.sync_generation,
            .sharing_policy_generation = self.sharing_policy.policy_generation,
            .has_history = self.snapshot_state.snapshot_count >= self.version_count and !self.snapshot_state.latest_snapshot_version_id.isZero(),
            .has_sync_policy = self.sync_state.version_watermark >= self.version_count and !self.sync_state.last_synced_version_id.isZero(),
            .has_sharing_policy = self.sharing_policy.requires_explicit_file_bridge_grant and self.sharing_policy.export_only_file_bridge,
            .recoverable = self.recovery_history.recoverable,
        };
    }
};

pub const ObjectProvenance = struct {
    created_at_ticks: u64 = 0,
    updated_at_ticks: u64 = 0,
    creator_signature: manifest.Signature = .{},
    latest_version_addressed: bool = false,
};

pub const ObjectSnapshotState = struct {
    snapshot_count: u16 = 0,
    latest_snapshot_version_id: ids.VersionId = ids.VersionId.zero,
};

pub const ObjectSyncState = struct {
    sync_generation: u32 = 0,
    version_watermark: u16 = 0,
    last_synced_version_id: ids.VersionId = ids.VersionId.zero,
};

pub const ObjectSharingPolicy = struct {
    policy_generation: u32 = 1,
    requires_explicit_file_bridge_grant: bool = true,
    export_only_file_bridge: bool = true,
};

pub const ObjectRecoveryHistory = struct {
    recovery_generation: u32 = 0,
    recoverable: bool = true,
    latest_recoverable_version_id: ids.VersionId = ids.VersionId.zero,
};

pub const VersionRecord = struct {
    id: ids.VersionId,
    object_id: ids.ObjectId,
    previous_version_id: ids.VersionId,
    parent_count: u8,
    parent_version_ids: [MAX_VERSION_PARENTS]ids.VersionId,
    object_type: ObjectType,
    blob_address: BlobAddress,
    version_address: VersionAddress,
    metadata: SignedMetadata,
    payload_len: usize,
    blob_slot_index: usize,
    chunk_count: u16,
};

pub const ChunkRef = struct {
    address: ChunkAddress = crypto_hash.zero_digest,
    payload_len: u16 = 0,
    slot_index: usize = 0,
};

pub const BlobRecord = struct {
    address: BlobAddress,
    merkle_root: BlobAddress,
    payload_len: usize,
    chunk_count: u16,
    chunks: [MAX_BLOB_CHUNKS]ChunkRef,
    ref_count: u16,
    manifest_verified: bool = false,
};

pub const ChunkRecord = struct {
    address: ChunkAddress,
    payload_len: u16,
    payload: [MAX_CHUNK_BYTES]u8,

    pub fn chunkSlice(self: *const ChunkRecord) []const u8 {
        return self.payload[0..@as(usize, @intCast(self.payload_len))];
    }
};

pub const Error = error{
    ContentTypeTooLong,
    InvalidSignature,
    LabelTooLong,
    ObjectIdExhausted,
    ObjectNotFound,
    ObjectTableFull,
    ParentMismatch,
    PayloadTooLarge,
    TypeMismatch,
    UnsignedMetadata,
    VersionIdExhausted,
    VersionNotFound,
    VersionTableFull,
    BlobNotFound,
    BlobTableFull,
    CorruptBlob,
};

pub const PayloadChunk = struct {
    index: usize,
    offset: usize,
    address: ChunkAddress,
    bytes: []const u8,
};

pub const PayloadTransferSummary = struct {
    bytes_transferred: usize = 0,
    chunks_transferred: usize = 0,
};

pub const SignMetadataError = error{ ContentTypeTooLong, LabelTooLong } || anyerror;

const ObjectSlot = struct {
    in_use: bool = false,
    object: ObjectRecord = .{
        .id = ids.ObjectId.zero,
        .object_type = .blob,
        .latest_version_id = ids.VersionId.zero,
        .version_count = 0,
    },
};

const VersionSlot = struct {
    in_use: bool = false,
    version: VersionRecord = .{
        .id = ids.VersionId.zero,
        .object_id = ids.ObjectId.zero,
        .previous_version_id = ids.VersionId.zero,
        .parent_count = 0,
        .parent_version_ids = [_]ids.VersionId{ids.VersionId.zero} ** MAX_VERSION_PARENTS,
        .object_type = .blob,
        .blob_address = crypto_hash.zero_digest,
        .version_address = crypto_hash.zero_digest,
        .metadata = .{},
        .payload_len = 0,
        .blob_slot_index = 0,
        .chunk_count = 0,
    },
};

pub const BlobSlot = struct {
    in_use: bool = false,
    blob: BlobRecord = .{
        .address = crypto_hash.zero_digest,
        .merkle_root = crypto_hash.zero_digest,
        .payload_len = 0,
        .chunk_count = 0,
        .chunks = [_]ChunkRef{ChunkRef{}} ** MAX_BLOB_CHUNKS,
        .ref_count = 0,
        .manifest_verified = false,
    },
};

pub const ChunkSlot = struct {
    in_use: bool = false,
    chunk: ChunkRecord = .{
        .address = crypto_hash.zero_digest,
        .payload_len = 0,
        .payload = [_]u8{0} ** MAX_CHUNK_BYTES,
    },
};

fn objectSlotId(slot: *const ObjectSlot) ids.ObjectId {
    return slot.object.id;
}

fn versionSlotId(slot: *const VersionSlot) ids.VersionId {
    return slot.version.id;
}

fn blobSlotMatchesAddress(address: BlobAddress, slot: *const BlobSlot) bool {
    return std.mem.eql(u8, &slot.blob.address, &address);
}

fn blobSlotIndexId(slot: *const BlobSlot) u64 {
    return indexIdForBytes(&slot.blob.address);
}

fn chunkSlotMatchesAddress(address: ChunkAddress, slot: *const ChunkSlot) bool {
    return std.mem.eql(u8, &slot.chunk.address, &address);
}

fn chunkSlotIndexId(slot: *const ChunkSlot) u64 {
    return indexIdForBytes(&slot.chunk.address);
}

pub const Store = StoreWith(.{});

fn ObjectTypeIndexWith(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        heads: [OBJECT_TYPE_COUNT]usize = [_]usize{indexed_arena.no_index} ** OBJECT_TYPE_COUNT,
        tails: [OBJECT_TYPE_COUNT]usize = [_]usize{indexed_arena.no_index} ** OBJECT_TYPE_COUNT,
        counts: [OBJECT_TYPE_COUNT]usize = [_]usize{0} ** OBJECT_TYPE_COUNT,
        next_by_slot: [capacity]usize = [_]usize{indexed_arena.no_index} ** capacity,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.* = Self.init();
        }

        pub fn count(self: *const Self, object_type: ObjectType) usize {
            return self.counts[objectTypeBucket(object_type)];
        }

        pub fn head(self: *const Self, object_type: ObjectType) usize {
            return self.heads[objectTypeBucket(object_type)];
        }

        pub fn next(self: *const Self, slot_index: usize) usize {
            if (slot_index >= capacity) return indexed_arena.no_index;
            return self.next_by_slot[slot_index];
        }

        pub fn append(self: *Self, object_type: ObjectType, slot_index: usize) bool {
            if (slot_index >= capacity) return false;
            const bucket = objectTypeBucket(object_type);
            self.next_by_slot[slot_index] = indexed_arena.no_index;
            if (self.tails[bucket] == indexed_arena.no_index) {
                self.heads[bucket] = slot_index;
            } else {
                self.next_by_slot[self.tails[bucket]] = slot_index;
            }
            self.tails[bucket] = slot_index;
            self.counts[bucket] += 1;
            return true;
        }
    };
}

fn objectTypeBucket(object_type: ObjectType) usize {
    return @intFromEnum(object_type);
}

pub fn StoreWith(comptime config: StoreConfig) type {
    config.validate();
    return struct {
        const Self = @This();
        const MAX_STORE_OBJECTS = config.max_objects;
        const MAX_STORE_VERSIONS = config.max_versions;
        const MAX_STORE_BLOBS = config.max_blobs;
        const MAX_STORE_CHUNKS = config.max_chunks;
        const STORE_OBJECT_INDEX_CAPACITY = config.object_index_capacity;
        const STORE_VERSION_INDEX_CAPACITY = config.version_index_capacity;
        const STORE_BLOB_INDEX_CAPACITY = config.blob_index_capacity;
        const STORE_CHUNK_INDEX_CAPACITY = config.chunk_index_capacity;
        const STORE_BLOB_PAGE_COUNT = config.max_blobs / BLOB_PAGE_SIZE;
        const STORE_CHUNK_PAGE_COUNT = config.max_chunks / CHUNK_PAGE_SIZE;
        const ObjectArena = indexed_arena.DirtyTrackedIndexedArenaWithKey(ids.ObjectId, ObjectSlot, MAX_STORE_OBJECTS, STORE_OBJECT_INDEX_CAPACITY, objectSlotId);
        const ObjectTypeIndex = ObjectTypeIndexWith(MAX_STORE_OBJECTS);
        const VersionArena = indexed_arena.DirtyTrackedIndexedArenaWithKey(ids.VersionId, VersionSlot, MAX_STORE_VERSIONS, STORE_VERSION_INDEX_CAPACITY, versionSlotId);
        const BlobArena = indexed_arena.PagedIndexedArena(BlobSlot, BLOB_PAGE_SIZE, STORE_BLOB_PAGE_COUNT, STORE_BLOB_INDEX_CAPACITY, blobSlotIndexId);
        const ChunkArena = indexed_arena.PagedIndexedArena(ChunkSlot, CHUNK_PAGE_SIZE, STORE_CHUNK_PAGE_COUNT, STORE_CHUNK_INDEX_CAPACITY, chunkSlotIndexId);

        pub const VersionChunkCursor = struct {
            store: *const Self,
            blob: *const BlobRecord,
            chunk_count: usize,
            next_chunk_index: usize = 0,
            byte_offset: usize = 0,

            pub fn next(self: *VersionChunkCursor) Error!?PayloadChunk {
                if (self.next_chunk_index >= self.chunk_count) return null;
                const chunk_ref = self.blob.chunks[self.next_chunk_index];
                if (chunk_ref.slot_index >= self.store.chunkSlotCapacity()) return error.CorruptBlob;
                const chunk_slot = self.store.chunkSlotAtConst(chunk_ref.slot_index);
                if (!chunk_slot.in_use) return error.BlobNotFound;
                const chunk_record = &chunk_slot.chunk;
                if (chunk_record.payload_len != chunk_ref.payload_len) return error.CorruptBlob;
                if (!std.mem.eql(u8, &chunk_record.address, &chunk_ref.address)) return error.CorruptBlob;

                const payload_chunk = PayloadChunk{
                    .index = self.next_chunk_index,
                    .offset = self.byte_offset,
                    .address = chunk_ref.address,
                    .bytes = chunk_record.chunkSlice(),
                };
                self.next_chunk_index += 1;
                self.byte_offset += payload_chunk.bytes.len;
                return payload_chunk;
            }
        };

        next_object_id: u64 = 1,
        next_version_id: u64 = 1,
        latest_inserted_version_id: ids.VersionId = ids.VersionId.zero,
        max_blob_payload_bytes: usize = 0,
        objects: ObjectArena = ObjectArena.init(),
        object_type_index: ObjectTypeIndex = ObjectTypeIndex.init(),
        versions: VersionArena = VersionArena.init(),
        blobs: BlobArena = BlobArena.init(),
        chunks: ChunkArena = ChunkArena.init(),
        payload_read_buffer: [MAX_PAYLOAD_BYTES]u8 = undefined,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.next_object_id = 1;
            self.next_version_id = 1;
            self.latest_inserted_version_id = ids.VersionId.zero;
            self.max_blob_payload_bytes = 0;
            self.objects.reset();
            self.object_type_index.reset();
            self.versions.reset();
            self.blobs.reset();
            self.chunks.reset();
        }

        pub fn rebuildIndexes(self: *Self) void {
            self.objects.rebuildPrimaryIndex();
            self.versions.rebuildPrimaryIndex();
            self.blobs.rebuildPrimaryIndex();
            self.chunks.rebuildPrimaryIndex();
            self.rebuildDerivedIndexes();
        }

        pub fn rebuildDerivedIndexes(self: *Self) void {
            self.rebuildObjectTypeIndex();
            self.rebuildLatestInsertedVersionId();
            self.rebuildMaxBlobPayloadBytes();
        }

        pub fn putVersion(self: *Self, request: PutRequest) Error!PutResult {
            return self.putVersionRef(&request);
        }

        pub fn putVersionRef(self: *Self, request: *const PutRequest) Error!PutResult {
            if (!request.metadata.isSigned()) return error.UnsignedMetadata;
            if (request.payload.len > MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
            if (!request.metadata.signature.isComplete() or !request.metadata.verifyFor(request.object_type, request.payload)) {
                return error.InvalidSignature;
            }

            var object_record: ?*ObjectRecord = null;
            var pending_object_id: ?ids.ObjectId = null;
            if (request.parent_version_id) |parent_version_id| {
                const parent = self.version(parent_version_id) orelse return error.VersionNotFound;
                if (parent.object_type != request.object_type) return error.TypeMismatch;
                const existing = self.object(parent.object_id) orelse return error.ObjectNotFound;
                if (!existing.latest_version_id.eql(parent_version_id)) return error.ParentMismatch;
                if (request.preferred_object_id) |preferred_object_id| {
                    if (!preferred_object_id.eql(existing.id)) return error.ParentMismatch;
                }
                object_record = existing;
            } else if (request.preferred_object_id) |preferred_object_id| {
                if (self.object(preferred_object_id)) |existing| {
                    if (existing.object_type != request.object_type) return error.TypeMismatch;
                    object_record = existing;
                } else {
                    pending_object_id = preferred_object_id;
                }
            } else {
                if (self.objectCount() >= MAX_STORE_OBJECTS) return error.ObjectTableFull;
                pending_object_id = try self.nextObjectId();
            }

            if (pending_object_id != null) {
                if (self.objectCount() >= MAX_STORE_OBJECTS) return error.ObjectTableFull;
                if (self.next_object_id == 0) return error.ObjectIdExhausted;
            }
            if (self.versionCount() >= MAX_STORE_VERSIONS) return error.VersionTableFull;
            const version_id = try self.nextVersionId();

            var created_new_object = false;
            if (pending_object_id) |object_id| {
                object_record = try self.createObject(object_id, request.object_type);
                created_new_object = true;
            }
            const target_object = object_record orelse native_util.impossibleByInvariant("version target must resolve to an object");

            const previous_version_id = if (request.parent_version_id) |parent_version_id|
                parent_version_id
            else
                target_object.latest_version_id;
            if (!target_object.latest_version_id.isZero() and !previous_version_id.eql(target_object.latest_version_id)) {
                return error.ParentMismatch;
            }

            var chunk_refs = [_]ChunkRef{ChunkRef{}} ** MAX_BLOB_CHUNKS;
            const chunk_count = try buildChunkRefs(request.payload, &chunk_refs);
            const merkle_root = computeBlobMerkleRoot(chunk_refs[0..chunk_count]);
            const blob_address = blobManifestAddressFromMerkleRoot(request.payload.len, chunk_count, merkle_root);
            const blob_slot_index = try self.putBlobPrepared(blob_address, merkle_root, request.payload, &chunk_refs, chunk_count);
            const parents = versionParents(previous_version_id);
            const parent_count = parentCount(parents);
            const version_address = computeVersionAddress(parents[0..@as(usize, @intCast(parent_count))], request.metadata, blob_address);
            try self.insertVersion(.{
                .id = version_id,
                .object_id = target_object.id,
                .previous_version_id = previous_version_id,
                .parent_count = parent_count,
                .parent_version_ids = parents,
                .object_type = request.object_type,
                .blob_address = blob_address,
                .version_address = version_address,
                .metadata = &request.metadata,
                .payload_len = request.payload.len,
                .blob_slot_index = blob_slot_index,
            });

            target_object.latest_version_id = version_id;
            target_object.version_count += 1;
            target_object.provenance.updated_at_ticks = request.metadata.created_at_ticks;
            if (!target_object.provenance.creator_signature.isPresent()) {
                target_object.provenance.created_at_ticks = request.metadata.created_at_ticks;
                target_object.provenance.creator_signature = request.metadata.signature;
            }
            target_object.provenance.latest_version_addressed = true;
            target_object.snapshot_state.snapshot_count += 1;
            target_object.snapshot_state.latest_snapshot_version_id = version_id;
            target_object.sync_state.sync_generation += 1;
            target_object.sync_state.version_watermark = target_object.version_count;
            target_object.sync_state.last_synced_version_id = version_id;
            target_object.recovery_history.recovery_generation += 1;
            target_object.recovery_history.latest_recoverable_version_id = previous_version_id;
            self.markObjectDirty(target_object.id);
            self.markVersionDirty(version_id);

            return .{
                .object_id = target_object.id,
                .version_id = version_id,
                .blob_address = blob_address,
                .version_address = version_address,
                .new_object = created_new_object,
            };
        }

        pub fn object(self: *Self, object_id: anytype) ?*ObjectRecord {
            const slot = self.objects.get(ids.coerce(ids.ObjectId, object_id)) orelse return null;
            return &slot.object;
        }

        pub fn objectConst(self: *const Self, object_id: anytype) ?*const ObjectRecord {
            const slot = self.objects.getConst(ids.coerce(ids.ObjectId, object_id)) orelse return null;
            return &slot.object;
        }

        pub fn version(self: *Self, version_id: anytype) ?*VersionRecord {
            const slot = self.versions.get(ids.coerce(ids.VersionId, version_id)) orelse return null;
            return &slot.version;
        }

        pub fn versionConst(self: *const Self, version_id: anytype) ?*const VersionRecord {
            const slot = self.versions.getConst(ids.coerce(ids.VersionId, version_id)) orelse return null;
            return &slot.version;
        }

        pub fn latestInsertedVersionConst(self: *const Self) ?*const VersionRecord {
            if (self.latest_inserted_version_id.isZero()) return null;
            return self.versionConst(self.latest_inserted_version_id);
        }

        pub fn latestVersion(self: *Self, object_id: anytype) ?*VersionRecord {
            const object_record = self.object(object_id) orelse return null;
            if (object_record.latest_version_id.isZero()) return null;
            return self.version(object_record.latest_version_id);
        }

        pub fn latestVersionConst(self: *const Self, object_id: anytype) ?*const VersionRecord {
            const object_record = self.objectConst(object_id) orelse return null;
            if (object_record.latest_version_id.isZero()) return null;
            return self.versionConst(object_record.latest_version_id);
        }

        pub fn queryObjects(
            self: *const Self,
            query: ObjectQuery,
            output: []ObjectQueryResult,
        ) []const ObjectQueryResult {
            var count: usize = 0;
            if (query.object_type) |object_type| {
                var slot_index = self.object_type_index.head(object_type);
                while (slot_index != indexed_arena.no_index) : (slot_index = self.object_type_index.next(slot_index)) {
                    const slot = &self.objects.slots[slot_index];
                    self.appendQueryObject(query, output, &count, &slot.object);
                    if (count >= output.len) break;
                }
                std.sort.heap(ObjectQueryResult, output[0..count], {}, compareObjectQueryResults);
                return output[0..count];
            }

            for (&self.objects.slots) |*slot| {
                if (!slot.in_use) continue;
                self.appendQueryObject(query, output, &count, &slot.object);
                if (count >= output.len) break;
            }
            std.sort.heap(ObjectQueryResult, output[0..count], {}, compareObjectQueryResults);
            return output[0..count];
        }

        fn appendQueryObject(
            self: *const Self,
            query: ObjectQuery,
            output: []ObjectQueryResult,
            count: *usize,
            object_record: *const ObjectRecord,
        ) void {
            if (query.object_type) |object_type| {
                if (object_record.object_type != object_type) return;
            }
            if (object_record.provenance.updated_at_ticks < query.updated_since_ticks) return;
            const latest = self.versionConst(object_record.latest_version_id) orelse return;
            if (query.content_type.len != 0 and !std.mem.eql(u8, latest.metadata.contentTypeSlice(), query.content_type)) return;
            if (query.label_contains.len != 0 and indexOfFold(latest.metadata.labelSlice(), query.label_contains) == null) return;
            if (count.* >= output.len) return;
            output[count.*] = queryResultFor(object_record, latest);
            count.* += 1;
        }

        pub fn objectHistory(
            self: *const Self,
            object_id: anytype,
            output: []ObjectHistoryEntry,
        ) Error![]const ObjectHistoryEntry {
            const object_record = self.objectConst(object_id) orelse return error.ObjectNotFound;
            var count: usize = 0;
            var current_version_id = object_record.latest_version_id;
            while (!current_version_id.isZero() and count < output.len) {
                const version_record = self.versionConst(current_version_id) orelse return error.VersionNotFound;
                output[count] = historyEntryFor(version_record);
                count += 1;
                current_version_id = version_record.previous_version_id;
            }
            return output[0..count];
        }

        pub fn objectOperatingModel(self: *const Self, object_id: anytype) Error!ObjectOperatingModel {
            const object_record = self.objectConst(object_id) orelse return error.ObjectNotFound;
            var model = object_record.operatingModel();
            const latest = self.versionConst(object_record.latest_version_id) orelse return error.VersionNotFound;
            model.signed = model.signed and latest.metadata.isSigned();
            return model;
        }

        pub fn versionPayload(self: *Self, version_record: *const VersionRecord) Error![]const u8 {
            if (version_record.payload_len > self.payload_read_buffer.len) return error.PayloadTooLarge;
            return self.versionPayloadInto(version_record, self.payload_read_buffer[0..version_record.payload_len]);
        }

        pub fn versionChunkCursor(self: *Self, version_record: *const VersionRecord) Error!VersionChunkCursor {
            const blob_record = try self.verifiedBlobManifest(version_record);
            return .{
                .store = self,
                .blob = blob_record,
                .chunk_count = @intCast(blob_record.chunk_count),
            };
        }

        pub fn transferVersionPayload(
            self: *Self,
            version_record: *const VersionRecord,
            out: []u8,
        ) Error!PayloadTransferSummary {
            if (out.len < version_record.payload_len) return error.PayloadTooLarge;
            var cursor = try self.versionChunkCursor(version_record);
            var summary = PayloadTransferSummary{};
            while (try cursor.next()) |payload_chunk| {
                const next_offset = payload_chunk.offset + payload_chunk.bytes.len;
                if (next_offset > version_record.payload_len or next_offset > out.len) return error.CorruptBlob;
                @memcpy(out[payload_chunk.offset..next_offset], payload_chunk.bytes);
                summary.bytes_transferred = next_offset;
                summary.chunks_transferred += 1;
            }
            if (summary.bytes_transferred != version_record.payload_len) return error.CorruptBlob;
            return summary;
        }

        pub fn versionPayloadInto(
            self: *Self,
            version_record: *const VersionRecord,
            out: []u8,
        ) Error![]const u8 {
            const summary = try self.transferVersionPayload(version_record, out);
            return out[0..summary.bytes_transferred];
        }

        pub fn blob(self: *const Self, address: BlobAddress) ?*const BlobRecord {
            const slot_index = self.blobSlotIndex(address) orelse return null;
            const slot = self.blobSlotAtConst(slot_index);
            return &slot.blob;
        }

        pub fn chunk(self: *const Self, address: ChunkAddress) ?*const ChunkRecord {
            const slot_index = self.chunkSlotIndex(address) orelse return null;
            const slot = self.chunkSlotAtConst(slot_index);
            return &slot.chunk;
        }

        pub fn blobSlotIndex(self: *const Self, address: BlobAddress) ?usize {
            const slot_index = self.blobs.slotIndexOf(indexIdForBytes(&address)) orelse return null;
            const slot = self.blobSlotAtConst(slot_index);
            if (!blobSlotMatchesAddress(address, slot)) native_util.impossibleByInvariant("blob address index points at the wrong blob slot");
            return slot_index;
        }

        pub fn chunkSlotIndex(self: *const Self, address: ChunkAddress) ?usize {
            const slot_index = self.chunks.slotIndexOf(indexIdForBytes(&address)) orelse return null;
            const slot = self.chunkSlotAtConst(slot_index);
            if (!chunkSlotMatchesAddress(address, slot)) native_util.impossibleByInvariant("chunk address index points at the wrong chunk slot");
            return slot_index;
        }

        pub fn blobCount(self: *const Self) usize {
            return self.blobs.countInUse();
        }

        pub fn maxBlobPayloadBytes(self: *const Self) usize {
            return self.max_blob_payload_bytes;
        }

        pub fn chunkCount(self: *const Self) usize {
            return self.chunks.countInUse();
        }

        pub fn blobSlotAt(self: *Self, slot_index: usize) *BlobSlot {
            return self.blobs.slotAt(slot_index);
        }

        pub fn reserveBlobSlot(self: *Self, address: BlobAddress) ?usize {
            return self.blobs.reserveIndex(indexIdForBytes(&address));
        }

        pub fn blobSlotAtConst(self: *const Self, slot_index: usize) *const BlobSlot {
            return self.blobs.slotAtConst(slot_index);
        }

        pub fn chunkSlotAt(self: *Self, slot_index: usize) *ChunkSlot {
            return self.chunks.slotAt(slot_index);
        }

        pub fn chunkSlotAtConst(self: *const Self, slot_index: usize) *const ChunkSlot {
            return self.chunks.slotAtConst(slot_index);
        }

        pub fn blobSlotCapacity(self: *const Self) usize {
            _ = self;
            return MAX_STORE_BLOBS;
        }

        pub fn chunkSlotCapacity(self: *const Self) usize {
            _ = self;
            return MAX_STORE_CHUNKS;
        }

        pub fn objectCount(self: *const Self) usize {
            return self.objects.countInUse();
        }

        pub fn versionCount(self: *const Self) usize {
            return self.versions.countInUse();
        }

        pub fn dirtyObjectIds(self: *const Self) []const ids.ObjectId {
            return self.objects.dirtyIds();
        }

        pub fn dirtyVersionIds(self: *const Self) []const ids.VersionId {
            return self.versions.dirtyIds();
        }

        pub fn clearDirty(self: *Self) void {
            self.objects.clearDirty();
            self.versions.clearDirty();
        }

        fn nextObjectId(self: *Self) Error!ids.ObjectId {
            if (self.next_object_id == 0) return error.ObjectIdExhausted;
            return ids.object(self.next_object_id);
        }

        fn nextVersionId(self: *Self) Error!ids.VersionId {
            if (self.next_version_id == 0) return error.VersionIdExhausted;
            return ids.version(self.next_version_id);
        }

        fn createObject(self: *Self, object_id: ids.ObjectId, object_type: ObjectType) Error!*ObjectRecord {
            if (self.objects.countInUse() >= MAX_STORE_OBJECTS) return error.ObjectTableFull;
            if (self.next_object_id == 0) return error.ObjectIdExhausted;
            const slot_index = self.objects.reserveIndex(object_id) orelse return error.ObjectTableFull;
            const slot = &self.objects.slots[slot_index];
            slot.object = .{
                .id = object_id,
                .object_type = object_type,
                .latest_version_id = ids.VersionId.zero,
                .version_count = 0,
            };
            self.indexObjectTypeSlot(slot_index);
            if (object_id.raw() >= self.next_object_id) {
                self.next_object_id = object_id.raw() +% 1;
            }
            return &slot.object;
        }

        fn rebuildObjectTypeIndex(self: *Self) void {
            self.object_type_index.reset();
            for (&self.objects.slots, 0..) |*slot, slot_index| {
                if (!slot.in_use) continue;
                self.indexObjectTypeSlot(slot_index);
            }
        }

        fn indexObjectTypeSlot(self: *Self, slot_index: usize) void {
            const slot = &self.objects.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("object type index points at a free object slot");
            if (!self.object_type_index.append(slot.object.object_type, slot_index)) {
                native_util.impossibleByInvariant("object type index capacity covers object slots");
            }
        }

        fn insertVersion(self: *Self, request: struct {
            id: ids.VersionId,
            object_id: ids.ObjectId,
            previous_version_id: ids.VersionId,
            parent_count: u8,
            parent_version_ids: [MAX_VERSION_PARENTS]ids.VersionId,
            object_type: ObjectType,
            blob_address: BlobAddress,
            version_address: VersionAddress,
            metadata: *const SignedMetadata,
            payload_len: usize,
            blob_slot_index: usize,
        }) Error!void {
            const slot = self.versions.reserve(request.id) orelse return error.VersionTableFull;
            slot.version.id = request.id;
            slot.version.object_id = request.object_id;
            slot.version.previous_version_id = request.previous_version_id;
            slot.version.parent_count = request.parent_count;
            slot.version.parent_version_ids = request.parent_version_ids;
            slot.version.object_type = request.object_type;
            slot.version.blob_address = request.blob_address;
            slot.version.version_address = request.version_address;
            writeMetadata(&slot.version.metadata, request.metadata);
            slot.version.payload_len = request.payload_len;
            slot.version.blob_slot_index = request.blob_slot_index;
            slot.version.chunk_count = @intCast(chunkCountForLen(request.payload_len));
            if (request.id.raw() >= self.next_version_id) {
                self.next_version_id = request.id.raw() +% 1;
            }
            self.recordLatestInsertedVersionId(request.id);
        }

        fn rebuildLatestInsertedVersionId(self: *Self) void {
            self.latest_inserted_version_id = ids.VersionId.zero;
            for (&self.versions.slots) |*slot| {
                if (!slot.in_use) continue;
                self.recordLatestInsertedVersionId(slot.version.id);
            }
        }

        fn recordLatestInsertedVersionId(self: *Self, version_id: ids.VersionId) void {
            if (version_id.raw() > self.latest_inserted_version_id.raw()) {
                self.latest_inserted_version_id = version_id;
            }
        }

        fn rebuildMaxBlobPayloadBytes(self: *Self) void {
            self.max_blob_payload_bytes = 0;
            var blob_slot_index: usize = 0;
            while (blob_slot_index < self.blobSlotCapacity()) : (blob_slot_index += 1) {
                const slot = self.blobSlotAtConst(blob_slot_index);
                if (!slot.in_use) continue;
                self.recordBlobPayloadBytes(slot.blob.payload_len);
            }
        }

        fn recordBlobPayloadBytes(self: *Self, payload_len: usize) void {
            self.max_blob_payload_bytes = @max(self.max_blob_payload_bytes, payload_len);
        }

        pub fn putBlob(self: *Self, address: BlobAddress, payload: []const u8) Error!usize {
            if (payload.len > MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
            var chunk_refs = [_]ChunkRef{ChunkRef{}} ** MAX_BLOB_CHUNKS;
            const chunk_count = try buildChunkRefs(payload, &chunk_refs);
            const merkle_root = computeBlobMerkleRoot(chunk_refs[0..chunk_count]);
            const computed_address = blobManifestAddressFromMerkleRoot(payload.len, chunk_count, merkle_root);
            if (!std.mem.eql(u8, &computed_address, &address)) return error.CorruptBlob;
            return self.putBlobPrepared(address, merkle_root, payload, &chunk_refs, chunk_count);
        }

        /// `chunk_refs` addresses must already be derived from `payload` and
        /// `address`/`merkle_root` from those refs; callers own that proof.
        fn putBlobPrepared(
            self: *Self,
            address: BlobAddress,
            merkle_root: BlobAddress,
            payload: []const u8,
            chunk_refs: *[MAX_BLOB_CHUNKS]ChunkRef,
            chunk_count: usize,
        ) Error!usize {
            for (chunk_refs[0..chunk_count], 0..) |*chunk_ref, chunk_index| {
                const start = chunk_index * MAX_CHUNK_BYTES;
                const end = @min(start + MAX_CHUNK_BYTES, payload.len);
                chunk_ref.slot_index = try self.putChunkPrepared(chunk_ref.address, payload[start..end]);
            }

            if (self.blobSlotIndex(address)) |slot_index| {
                const slot = self.blobSlotAt(slot_index);
                if (!blobManifestMatches(slot.blob, payload.len, chunk_refs[0..chunk_count])) return error.CorruptBlob;
                slot.blob.ref_count +|= 1;
                self.recordBlobPayloadBytes(payload.len);
                return slot_index;
            }
            const slot_index = self.blobs.reserveIndex(indexIdForBytes(&address)) orelse return error.BlobTableFull;
            const slot = self.blobSlotAt(slot_index);
            slot.blob.address = address;
            slot.blob.merkle_root = merkle_root;
            slot.blob.payload_len = payload.len;
            slot.blob.chunk_count = @intCast(chunk_count);
            slot.blob.chunks = chunk_refs.*;
            slot.blob.ref_count = 1;
            slot.blob.manifest_verified = false;
            self.recordBlobPayloadBytes(payload.len);
            return slot_index;
        }

        pub fn putChunk(self: *Self, address: ChunkAddress, payload: []const u8) Error!usize {
            if (payload.len > MAX_CHUNK_BYTES) return error.PayloadTooLarge;
            if (!std.mem.eql(u8, &computeChunkAddress(payload), &address)) return error.CorruptBlob;
            return self.putChunkPrepared(address, payload);
        }

        /// `address` must already be `computeChunkAddress(payload)`; callers own that proof.
        fn putChunkPrepared(self: *Self, address: ChunkAddress, payload: []const u8) Error!usize {
            if (self.chunkSlotIndex(address)) |slot_index| {
                const slot = self.chunkSlotAt(slot_index);
                if (slot.chunk.payload_len != payload.len or !std.mem.eql(u8, slot.chunk.chunkSlice(), payload)) return error.CorruptBlob;
                return slot_index;
            }

            const slot_index = self.chunks.reserveIndex(indexIdForBytes(&address)) orelse return error.BlobTableFull;
            const slot = self.chunkSlotAt(slot_index);
            slot.chunk.address = address;
            slot.chunk.payload_len = @intCast(payload.len);
            @memcpy(slot.chunk.payload[0..payload.len], payload);
            @memset(slot.chunk.payload[payload.len..], 0);
            return slot_index;
        }

        pub fn verifiedBlobManifestCount(self: *const Self) usize {
            var count: usize = 0;
            var slot_index: usize = 0;
            while (slot_index < self.blobSlotCapacity()) : (slot_index += 1) {
                const slot = self.blobSlotAtConst(slot_index);
                if (slot.in_use and slot.blob.manifest_verified) count += 1;
            }
            return count;
        }

        fn verifiedBlobManifest(self: *Self, version_record: *const VersionRecord) Error!*const BlobRecord {
            if (version_record.blob_slot_index >= self.blobSlotCapacity()) return error.CorruptBlob;
            const slot = self.blobSlotAt(version_record.blob_slot_index);
            if (!slot.in_use) return error.BlobNotFound;
            if (!std.mem.eql(u8, &slot.blob.address, &version_record.blob_address)) return error.CorruptBlob;
            if (slot.blob.payload_len != version_record.payload_len) return error.CorruptBlob;
            if (slot.blob.chunk_count != version_record.chunk_count) return error.CorruptBlob;

            if (slot.blob.manifest_verified) return &slot.blob;

            const blob_chunk_count: usize = @intCast(slot.blob.chunk_count);
            if (!std.mem.eql(u8, &computeBlobMerkleRoot(slot.blob.chunks[0..blob_chunk_count]), &slot.blob.merkle_root)) {
                return error.CorruptBlob;
            }
            if (!std.mem.eql(u8, &computeBlobManifestAddress(slot.blob.payload_len, slot.blob.chunks[0..blob_chunk_count]), &version_record.blob_address)) {
                return error.CorruptBlob;
            }

            for (slot.blob.chunks[0..blob_chunk_count]) |chunk_ref| {
                if (chunk_ref.slot_index >= self.chunkSlotCapacity()) return error.CorruptBlob;
                const chunk_slot = self.chunkSlotAtConst(chunk_ref.slot_index);
                if (!chunk_slot.in_use) return error.BlobNotFound;
                const chunk_record = &chunk_slot.chunk;
                if (chunk_record.payload_len != chunk_ref.payload_len) return error.CorruptBlob;
                if (!std.mem.eql(u8, &chunk_record.address, &chunk_ref.address)) return error.CorruptBlob;
                if (!std.mem.eql(u8, &computeChunkAddress(chunk_record.chunkSlice()), &chunk_ref.address)) return error.CorruptBlob;
            }

            slot.blob.manifest_verified = true;
            return &slot.blob;
        }

        fn markObjectDirty(self: *Self, object_id: ids.ObjectId) void {
            self.objects.markDirty(object_id);
        }

        fn markVersionDirty(self: *Self, version_id: ids.VersionId) void {
            self.versions.markDirty(version_id);
        }
    };
}

pub fn signMetadata(
    identity: signing.SignerIdentity,
    label: []const u8,
    content_type: []const u8,
    object_type: ObjectType,
    payload: []const u8,
    created_at_ticks: u64,
) SignMetadataError!SignedMetadata {
    var metadata = try SignedMetadata.init(label, content_type, .{}, created_at_ticks);
    var message_buffer: [MAX_METADATA_MESSAGE_BYTES]u8 = undefined;
    const message = try metadataMessage(&message_buffer, object_type, payload, metadata);
    metadata.signature = try signing.sign(identity, message);
    return metadata;
}

fn queryResultFor(object_record: *const ObjectRecord, latest: *const VersionRecord) ObjectQueryResult {
    var result = ObjectQueryResult{
        .object_id = object_record.id,
        .latest_version_id = object_record.latest_version_id,
        .object_type = object_record.object_type,
        .version_count = object_record.version_count,
        .snapshot_count = object_record.snapshot_state.snapshot_count,
        .updated_at_ticks = object_record.provenance.updated_at_ticks,
    };
    result.label_len = latest.metadata.label_len;
    result.label = latest.metadata.label;
    result.content_type_len = latest.metadata.content_type_len;
    result.content_type = latest.metadata.content_type;
    return result;
}

fn historyEntryFor(version_record: *const VersionRecord) ObjectHistoryEntry {
    var entry = ObjectHistoryEntry{
        .object_id = version_record.object_id,
        .version_id = version_record.id,
        .previous_version_id = version_record.previous_version_id,
        .parent_count = version_record.parent_count,
        .object_type = version_record.object_type,
        .payload_len = version_record.payload_len,
        .created_at_ticks = version_record.metadata.created_at_ticks,
    };
    entry.label_len = version_record.metadata.label_len;
    entry.label = version_record.metadata.label;
    entry.content_type_len = version_record.metadata.content_type_len;
    entry.content_type = version_record.metadata.content_type;
    return entry;
}

fn compareObjectQueryResults(_: void, left: ObjectQueryResult, right: ObjectQueryResult) bool {
    if (left.updated_at_ticks == right.updated_at_ticks) return left.object_id.raw() < right.object_id.raw();
    return left.updated_at_ticks > right.updated_at_ticks;
}

fn indexOfFold(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        var matches = true;
        for (needle, 0..) |needle_byte, offset| {
            if (std.ascii.toLower(haystack[index + offset]) != std.ascii.toLower(needle_byte)) {
                matches = false;
                break;
            }
        }
        if (matches) return index;
    }
    return null;
}

fn writeMetadata(dest: *SignedMetadata, src: *const SignedMetadata) void {
    dest.signature.format = src.signature.format;
    dest.signature.signer = src.signature.signer;
    dest.signature.public_key_len = src.signature.public_key_len;
    dest.signature.value_len = src.signature.value_len;
    dest.signature.public_key = src.signature.public_key;
    dest.signature.value = src.signature.value;
    dest.label_len = src.label_len;
    dest.label = src.label;
    dest.content_type_len = src.content_type_len;
    dest.content_type = src.content_type;
    dest.created_at_ticks = src.created_at_ticks;
}

fn indexIdForBytes(bytes: []const u8) u64 {
    const id = native_util.fnv1a64(bytes);
    return if (id == 0) 1 else id;
}

fn chunkCountForLen(payload_len: usize) usize {
    if (payload_len == 0) return 0;
    return (payload_len + MAX_CHUNK_BYTES - 1) / MAX_CHUNK_BYTES;
}

pub fn computeBlobAddress(payload: []const u8) BlobAddress {
    var chunk_refs = [_]ChunkRef{ChunkRef{}} ** MAX_BLOB_CHUNKS;
    const chunk_count = buildChunkRefs(payload, &chunk_refs) catch return crypto_hash.zero_digest;
    return computeBlobManifestAddress(payload.len, chunk_refs[0..chunk_count]);
}

pub fn computeChunkAddress(payload: []const u8) ChunkAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "chunk", payload);
    return crypto_hash.finalize(&hasher);
}

pub fn computeBlobManifestAddress(payload_len: usize, chunk_refs: []const ChunkRef) BlobAddress {
    return blobManifestAddressFromMerkleRoot(payload_len, chunk_refs.len, computeBlobMerkleRoot(chunk_refs));
}

fn blobManifestAddressFromMerkleRoot(payload_len: usize, chunk_count: usize, merkle_root: BlobAddress) BlobAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "payload-len", payload_len);
    crypto_hash.updateInt(&hasher, "chunk-count", chunk_count);
    crypto_hash.updateBytes(&hasher, "chunk-merkle-root", &merkle_root);
    return crypto_hash.finalize(&hasher);
}

pub fn computeBlobMerkleRoot(chunk_refs: []const ChunkRef) BlobAddress {
    if (chunk_refs.len == 0) {
        var empty_hasher = crypto_hash.init();
        crypto_hash.updateBytes(&empty_hasher, "blob-merkle-empty", "");
        return crypto_hash.finalize(&empty_hasher);
    }

    var level = [_]BlobAddress{crypto_hash.zero_digest} ** MAX_BLOB_CHUNKS;
    var level_count = chunk_refs.len;
    for (chunk_refs, 0..) |chunk_ref, index| {
        var hasher = crypto_hash.init();
        crypto_hash.updateBytes(&hasher, "blob-merkle-leaf", &chunk_ref.address);
        crypto_hash.updateInt(&hasher, "chunk-len", chunk_ref.payload_len);
        level[index] = crypto_hash.finalize(&hasher);
    }

    while (level_count > 1) {
        var next_count: usize = 0;
        var index: usize = 0;
        while (index < level_count) : (index += 2) {
            const left = level[index];
            const right = if (index + 1 < level_count) level[index + 1] else left;
            var hasher = crypto_hash.init();
            crypto_hash.updateBytes(&hasher, "blob-merkle-left", &left);
            crypto_hash.updateBytes(&hasher, "blob-merkle-right", &right);
            level[next_count] = crypto_hash.finalize(&hasher);
            next_count += 1;
        }
        level_count = next_count;
    }
    return level[0];
}

fn buildChunkRefs(payload: []const u8, out: *[MAX_BLOB_CHUNKS]ChunkRef) Error!usize {
    if (payload.len > MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
    const chunk_count = chunkCountForLen(payload.len);
    if (chunk_count > MAX_BLOB_CHUNKS) return error.PayloadTooLarge;
    var chunk_index: usize = 0;
    while (chunk_index < chunk_count) : (chunk_index += 1) {
        const start = chunk_index * MAX_CHUNK_BYTES;
        const end = @min(start + MAX_CHUNK_BYTES, payload.len);
        const chunk_payload = payload[start..end];
        out[chunk_index] = .{
            .address = computeChunkAddress(chunk_payload),
            .payload_len = @intCast(chunk_payload.len),
            .slot_index = 0,
        };
    }
    return chunk_count;
}

fn computeVersionAddress(
    parent_version_ids: []const ids.VersionId,
    metadata: SignedMetadata,
    blob_address: BlobAddress,
) VersionAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "parent-count", parent_version_ids.len);
    for (parent_version_ids) |parent_version_id| {
        crypto_hash.updateInt(&hasher, "parent-version-id", parent_version_id.raw());
    }
    crypto_hash.updateBytes(&hasher, "label", metadata.labelSlice());
    crypto_hash.updateBytes(&hasher, "content-type", metadata.contentTypeSlice());
    crypto_hash.updateInt(&hasher, "created-at", metadata.created_at_ticks);
    crypto_hash.updateBytes(&hasher, "signature-signer", metadata.signature.signer);
    crypto_hash.updateBytes(&hasher, "signature-public-key", metadata.signature.publicKeySlice());
    crypto_hash.updateBytes(&hasher, "signature-value", metadata.signature.valueSlice());
    crypto_hash.updateBytes(&hasher, "blob-address", &blob_address);
    return crypto_hash.finalize(&hasher);
}

fn versionParents(previous_version_id: ids.VersionId) [MAX_VERSION_PARENTS]ids.VersionId {
    var parents = [_]ids.VersionId{ids.VersionId.zero} ** MAX_VERSION_PARENTS;
    if (!previous_version_id.isZero()) {
        parents[0] = previous_version_id;
    }
    return parents;
}

fn parentCount(parent_version_ids: [MAX_VERSION_PARENTS]ids.VersionId) u8 {
    var count: u8 = 0;
    for (parent_version_ids) |parent_version_id| {
        if (!parent_version_id.isZero()) count += 1;
    }
    return count;
}

fn blobManifestMatches(blob_record: BlobRecord, payload_len: usize, chunk_refs: []const ChunkRef) bool {
    if (blob_record.payload_len != payload_len) return false;
    const chunk_count: usize = @intCast(blob_record.chunk_count);
    if (chunk_count != chunk_refs.len) return false;
    if (!std.mem.eql(u8, &blob_record.merkle_root, &computeBlobMerkleRoot(chunk_refs))) return false;
    var index: usize = 0;
    while (index < chunk_count) : (index += 1) {
        if (!std.mem.eql(u8, &blob_record.chunks[index].address, &chunk_refs[index].address)) return false;
        if (blob_record.chunks[index].payload_len != chunk_refs[index].payload_len) return false;
    }
    return true;
}

fn metadataMessage(
    buffer: []u8,
    object_type: ObjectType,
    payload: []const u8,
    metadata: SignedMetadata,
) error{NoSpaceLeft}![]const u8 {
    var writer = BinaryWriter{ .buffer = buffer };
    try writer.writeBytes("zigos.object.metadata");
    try writer.writeByte(@intFromEnum(object_type));
    try writeLengthPrefixed(&writer, metadata.labelSlice());
    try writeLengthPrefixed(&writer, metadata.contentTypeSlice());
    try writer.writeU64(metadata.created_at_ticks);
    try writer.writeU64(@intCast(payload.len));
    const payload_digest = computePayloadDigest(payload);
    try writer.writeBytes(&payload_digest);
    return buffer[0..writer.offset];
}

fn computePayloadDigest(payload: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    var offset: usize = 0;
    while (offset < payload.len) {
        const end = @min(offset + MAX_CHUNK_BYTES, payload.len);
        crypto_hash.updateBytes(&hasher, "payload-page", payload[offset..end]);
        offset = end;
    }
    crypto_hash.updateInt(&hasher, "payload-len", payload.len);
    return crypto_hash.finalize(&hasher);
}

const BinaryWriter = binary_cursor.Writer(error{NoSpaceLeft}, error.NoSpaceLeft);

fn writeLengthPrefixed(writer: *BinaryWriter, bytes: []const u8) error{NoSpaceLeft}!void {
    if (bytes.len > std.math.maxInt(u16)) return error.NoSpaceLeft;
    try writer.writeU16(@intCast(bytes.len));
    try writer.writeBytes(bytes);
}
