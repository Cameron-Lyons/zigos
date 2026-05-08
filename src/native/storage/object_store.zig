const std = @import("std");
const binary_cursor = @import("../core/binary_cursor.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
pub const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const signing = @import("../core/signing.zig");

pub const MAX_OBJECTS: usize = 128;
pub const MAX_VERSIONS: usize = 512;
pub const MAX_BLOBS: usize = 512;
pub const PAGE_SIZE_BYTES: usize = 4096;
pub const MAX_CHUNK_BYTES: usize = PAGE_SIZE_BYTES;
pub const MAX_BLOB_CHUNKS: usize = 24;
pub const MAX_CHUNKS: usize = 192;
pub const MAX_BLOB_BYTES: usize = MAX_CHUNK_BYTES * MAX_BLOB_CHUNKS;
pub const MAX_PAYLOAD_BYTES: usize = MAX_BLOB_BYTES;
pub const MAX_VERSION_PARENTS: usize = 2;
const MAX_METADATA_MESSAGE_BYTES: usize = 256;
const OBJECT_INDEX_CAPACITY: usize = MAX_OBJECTS * 2;
const VERSION_INDEX_CAPACITY: usize = MAX_VERSIONS * 2;
const BLOB_INDEX_CAPACITY: usize = MAX_BLOBS * 2;
const CHUNK_INDEX_CAPACITY: usize = MAX_CHUNKS * 2;
const BLOB_PAGE_SIZE: usize = 64;
const BLOB_PAGE_COUNT: usize = MAX_BLOBS / BLOB_PAGE_SIZE;
const CHUNK_PAGE_SIZE: usize = 64;

pub const StoreConfig = struct {
    max_objects: usize = MAX_OBJECTS,
    max_versions: usize = MAX_VERSIONS,
    max_chunks: usize = MAX_CHUNKS,
    object_index_capacity: usize = OBJECT_INDEX_CAPACITY,
    version_index_capacity: usize = VERSION_INDEX_CAPACITY,
    blob_index_capacity: usize = BLOB_INDEX_CAPACITY,
    chunk_index_capacity: usize = CHUNK_INDEX_CAPACITY,

    pub fn validate(comptime config: StoreConfig) void {
        if (config.max_objects == 0) @compileError("object store requires at least one object slot");
        if (config.max_versions == 0) @compileError("object store requires at least one version slot");
        if (config.max_chunks == 0) @compileError("object store requires at least one chunk slot");
        if (config.object_index_capacity < config.max_objects) @compileError("object index capacity must cover object slots");
        if (config.version_index_capacity < config.max_versions) @compileError("version index capacity must cover version slots");
        if (config.blob_index_capacity < MAX_BLOBS) @compileError("blob index capacity must cover blob slabs");
        if (config.chunk_index_capacity < config.max_chunks) @compileError("chunk index capacity must cover chunk slots");
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

pub const BlobAddress = [32]u8;
pub const ChunkAddress = [32]u8;
pub const VersionAddress = [32]u8;

pub const SignedMetadata = struct {
    signature: manifest.Signature = .{},
    label_len: usize = 0,
    label: [48]u8 = [_]u8{0} ** 48,
    content_type_len: usize = 0,
    content_type: [64]u8 = [_]u8{0} ** 64,
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

pub const ObjectRecord = struct {
    id: ids.ObjectId,
    object_type: ObjectType,
    latest_version_id: ids.VersionId,
    version_count: u16,
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
    address: ChunkAddress = [_]u8{0} ** 32,
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
    ObjectNotFound,
    ObjectTableFull,
    ParentMismatch,
    PayloadTooLarge,
    TypeMismatch,
    UnsignedMetadata,
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
        .blob_address = [_]u8{0} ** 32,
        .version_address = [_]u8{0} ** 32,
        .metadata = .{},
        .payload_len = 0,
        .blob_slot_index = 0,
        .chunk_count = 0,
    },
};

pub const BlobSlot = struct {
    in_use: bool = false,
    blob: BlobRecord = .{
        .address = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
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
        .address = [_]u8{0} ** 32,
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

pub fn StoreWith(comptime config: StoreConfig) type {
    config.validate();
    return struct {
        const Self = @This();
        const MAX_STORE_OBJECTS = config.max_objects;
        const MAX_STORE_VERSIONS = config.max_versions;
        const MAX_STORE_CHUNKS = config.max_chunks;
        const STORE_OBJECT_INDEX_CAPACITY = config.object_index_capacity;
        const STORE_VERSION_INDEX_CAPACITY = config.version_index_capacity;
        const STORE_BLOB_INDEX_CAPACITY = config.blob_index_capacity;
        const STORE_CHUNK_INDEX_CAPACITY = config.chunk_index_capacity;
        const STORE_CHUNK_PAGE_COUNT = config.max_chunks / CHUNK_PAGE_SIZE;
        const ObjectArena = indexed_arena.IndexedArenaWithKey(ids.ObjectId, ObjectSlot, MAX_STORE_OBJECTS, STORE_OBJECT_INDEX_CAPACITY, objectSlotId);
        const VersionArena = indexed_arena.IndexedArenaWithKey(ids.VersionId, VersionSlot, MAX_STORE_VERSIONS, STORE_VERSION_INDEX_CAPACITY, versionSlotId);
        const BlobArena = indexed_arena.PagedIndexedArena(BlobSlot, BLOB_PAGE_SIZE, BLOB_PAGE_COUNT, STORE_BLOB_INDEX_CAPACITY, blobSlotIndexId);
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
        objects: ObjectArena = ObjectArena.init(),
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
            self.objects.reset();
            self.versions.reset();
            self.blobs.reset();
            self.chunks.reset();
        }

        pub fn rebuildIndexes(self: *Self) void {
            self.objects.rebuildPrimaryIndex();
            self.versions.rebuildPrimaryIndex();
            self.blobs.rebuildPrimaryIndex();
            self.chunks.rebuildPrimaryIndex();
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

            var created_new_object = false;
            const object_record = blk: {
                if (request.parent_version_id) |parent_version_id| {
                    const parent = self.version(parent_version_id) orelse return error.VersionNotFound;
                    if (parent.object_type != request.object_type) return error.TypeMismatch;
                    const existing = self.object(parent.object_id) orelse return error.ObjectNotFound;
                    if (!existing.latest_version_id.eql(parent_version_id)) return error.ParentMismatch;
                    if (request.preferred_object_id) |preferred_object_id| {
                        if (!preferred_object_id.eql(existing.id)) return error.ParentMismatch;
                    }
                    break :blk existing;
                }

                if (request.preferred_object_id) |preferred_object_id| {
                    if (self.object(preferred_object_id)) |existing| {
                        if (existing.object_type != request.object_type) return error.TypeMismatch;
                        break :blk existing;
                    }
                    created_new_object = true;
                    break :blk try self.createObject(preferred_object_id, request.object_type);
                }

                created_new_object = true;
                break :blk try self.createObject(self.nextObjectId(), request.object_type);
            };

            const previous_version_id = if (request.parent_version_id) |parent_version_id|
                parent_version_id
            else
                object_record.latest_version_id;
            if (!object_record.latest_version_id.isZero() and !previous_version_id.eql(object_record.latest_version_id)) {
                return error.ParentMismatch;
            }

            const version_id = self.nextVersionId();
            const blob_address = computeBlobAddress(request.payload);
            const blob_slot_index = try self.putBlob(blob_address, request.payload);
            const parents = versionParents(previous_version_id);
            const parent_count = parentCount(parents);
            const version_address = computeVersionAddress(parents[0..@as(usize, @intCast(parent_count))], request.metadata, blob_address);
            try self.insertVersion(.{
                .id = version_id,
                .object_id = object_record.id,
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

            object_record.latest_version_id = version_id;
            object_record.version_count += 1;
            self.markObjectDirty(object_record.id);
            self.markVersionDirty(version_id);

            return .{
                .object_id = object_record.id,
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

        pub fn version(self: *Self, version_id: anytype) ?*VersionRecord {
            const slot = self.versions.get(ids.coerce(ids.VersionId, version_id)) orelse return null;
            return &slot.version;
        }

        pub fn latestVersion(self: *Self, object_id: anytype) ?*VersionRecord {
            const object_record = self.object(object_id) orelse return null;
            if (object_record.latest_version_id.isZero()) return null;
            return self.version(object_record.latest_version_id);
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
                copyBytes(out[payload_chunk.offset..next_offset], payload_chunk.bytes);
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
            return MAX_BLOBS;
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

        fn nextObjectId(self: *Self) ids.ObjectId {
            defer self.next_object_id += 1;
            return ids.object(self.next_object_id);
        }

        fn nextVersionId(self: *Self) ids.VersionId {
            defer self.next_version_id += 1;
            return ids.version(self.next_version_id);
        }

        fn createObject(self: *Self, object_id: ids.ObjectId, object_type: ObjectType) Error!*ObjectRecord {
            const slot = self.objects.reserve(object_id) orelse return error.ObjectTableFull;
            slot.object = .{
                .id = object_id,
                .object_type = object_type,
                .latest_version_id = ids.VersionId.zero,
                .version_count = 0,
            };
            if (object_id.raw() >= self.next_object_id) {
                self.next_object_id = object_id.raw() + 1;
            }
            return &slot.object;
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
            copyBytes(slot.version.blob_address[0..], request.blob_address[0..]);
            copyBytes(slot.version.version_address[0..], request.version_address[0..]);
            writeMetadata(&slot.version.metadata, request.metadata);
            slot.version.payload_len = request.payload_len;
            slot.version.blob_slot_index = request.blob_slot_index;
            slot.version.chunk_count = @intCast(chunkCountForLen(request.payload_len));
        }

        pub fn putBlob(self: *Self, address: BlobAddress, payload: []const u8) Error!usize {
            if (payload.len > MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
            if (!std.mem.eql(u8, &computeBlobAddress(payload), &address)) return error.CorruptBlob;

            var chunk_refs = [_]ChunkRef{ChunkRef{}} ** MAX_BLOB_CHUNKS;
            const chunk_count = try self.putPayloadChunks(payload, &chunk_refs);

            if (self.blobSlotIndex(address)) |slot_index| {
                const slot = self.blobSlotAt(slot_index);
                if (!blobManifestMatches(slot.blob, payload.len, chunk_refs[0..chunk_count])) return error.CorruptBlob;
                slot.blob.ref_count +|= 1;
                return slot_index;
            }
            const slot_index = self.blobs.reserveIndex(indexIdForBytes(&address)) orelse return error.BlobTableFull;
            const slot = self.blobSlotAt(slot_index);
            slot.blob.address = address;
            slot.blob.merkle_root = computeBlobMerkleRoot(chunk_refs[0..chunk_count]);
            slot.blob.payload_len = payload.len;
            slot.blob.chunk_count = @intCast(chunk_count);
            slot.blob.chunks = chunk_refs;
            slot.blob.ref_count = 1;
            slot.blob.manifest_verified = false;
            return slot_index;
        }

        fn putPayloadChunks(self: *Self, payload: []const u8, out: *[MAX_BLOB_CHUNKS]ChunkRef) Error!usize {
            const chunk_count = chunkCountForLen(payload.len);
            if (chunk_count > MAX_BLOB_CHUNKS) return error.PayloadTooLarge;

            var chunk_index: usize = 0;
            while (chunk_index < chunk_count) : (chunk_index += 1) {
                const start = chunk_index * MAX_CHUNK_BYTES;
                const end = @min(start + MAX_CHUNK_BYTES, payload.len);
                const payload_chunk = payload[start..end];
                const chunk_address = computeChunkAddress(payload_chunk);
                const slot_index = try self.putChunk(chunk_address, payload_chunk);
                out[chunk_index] = .{
                    .address = chunk_address,
                    .payload_len = @intCast(payload_chunk.len),
                    .slot_index = slot_index,
                };
            }
            return chunk_count;
        }

        pub fn putChunk(self: *Self, address: ChunkAddress, payload: []const u8) Error!usize {
            if (payload.len > MAX_CHUNK_BYTES) return error.PayloadTooLarge;
            if (!std.mem.eql(u8, &computeChunkAddress(payload), &address)) return error.CorruptBlob;
            if (self.chunkSlotIndex(address)) |slot_index| {
                const slot = self.chunkSlotAt(slot_index);
                if (slot.chunk.payload_len != payload.len or !std.mem.eql(u8, slot.chunk.chunkSlice(), payload)) return error.CorruptBlob;
                return slot_index;
            }

            const slot_index = self.chunks.reserveIndex(indexIdForBytes(&address)) orelse return error.BlobTableFull;
            const slot = self.chunkSlotAt(slot_index);
            slot.chunk.address = address;
            slot.chunk.payload_len = @intCast(payload.len);
            @memset(slot.chunk.payload[0..], 0);
            copyBytes(slot.chunk.payload[0..payload.len], payload);
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

fn copyBytes(dest: []u8, src: []const u8) void {
    var index: usize = 0;
    const len = @min(dest.len, src.len);
    while (index < len) : (index += 1) {
        dest[index] = src[index];
    }
}

fn writeMetadata(dest: *SignedMetadata, src: *const SignedMetadata) void {
    dest.signature.format = src.signature.format;
    dest.signature.signer = src.signature.signer;
    dest.signature.public_key_len = src.signature.public_key_len;
    dest.signature.value_len = src.signature.value_len;
    copyBytes(dest.signature.public_key[0..], src.signature.public_key[0..]);
    copyBytes(dest.signature.value[0..], src.signature.value[0..]);
    dest.label_len = src.label_len;
    copyBytes(dest.label[0..], src.label[0..]);
    dest.content_type_len = src.content_type_len;
    copyBytes(dest.content_type[0..], src.content_type[0..]);
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
    const chunk_count = buildChunkRefs(payload, &chunk_refs) catch return [_]u8{0} ** 32;
    return computeBlobManifestAddress(payload.len, chunk_refs[0..chunk_count]);
}

pub fn computeChunkAddress(payload: []const u8) ChunkAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "chunk", payload);
    return crypto_hash.finalize(&hasher);
}

pub fn computeBlobManifestAddress(payload_len: usize, chunk_refs: []const ChunkRef) BlobAddress {
    const merkle_root = computeBlobMerkleRoot(chunk_refs);
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "payload-len", payload_len);
    crypto_hash.updateInt(&hasher, "chunk-count", chunk_refs.len);
    crypto_hash.updateBytes(&hasher, "chunk-merkle-root", &merkle_root);
    return crypto_hash.finalize(&hasher);
}

pub fn computeBlobMerkleRoot(chunk_refs: []const ChunkRef) BlobAddress {
    if (chunk_refs.len == 0) {
        var empty_hasher = crypto_hash.init();
        crypto_hash.updateBytes(&empty_hasher, "blob-merkle-empty", "");
        return crypto_hash.finalize(&empty_hasher);
    }

    var level = [_]BlobAddress{[_]u8{0} ** 32} ** MAX_BLOB_CHUNKS;
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
    try writer.writeBytes("zigos.object.metadata.v2");
    try writer.writeByte(@intFromEnum(object_type));
    try writeLengthPrefixed(&writer, metadata.labelSlice());
    try writeLengthPrefixed(&writer, metadata.contentTypeSlice());
    try writer.writeU64(metadata.created_at_ticks);
    try writer.writeU64(@intCast(payload.len));
    const payload_digest = computePayloadDigest(payload);
    try writer.writeBytes(&payload_digest);
    return buffer[0..writer.offset];
}

fn computePayloadDigest(payload: []const u8) [32]u8 {
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
        .object_index_capacity = 2,
        .version_index_capacity = 2,
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
}
