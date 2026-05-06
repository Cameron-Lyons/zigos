const std = @import("std");
const binary_cursor = @import("../core/binary_cursor.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const fixed_table = @import("../core/fixed_table.zig");
pub const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const signing = @import("../core/signing.zig");

pub const MAX_OBJECTS: usize = 128;
pub const MAX_VERSIONS: usize = 512;
pub const MAX_BLOBS: usize = 512;
pub const MAX_BLOB_BYTES: usize = 512;
pub const MAX_PAYLOAD_BYTES: usize = MAX_BLOB_BYTES;
const MAX_METADATA_MESSAGE_BYTES: usize = MAX_PAYLOAD_BYTES + 256;
const OBJECT_INDEX_CAPACITY: usize = MAX_OBJECTS * 2;
const VERSION_INDEX_CAPACITY: usize = MAX_VERSIONS * 2;
const BLOB_INDEX_CAPACITY: usize = MAX_BLOBS * 2;

pub const StoreConfig = struct {
    max_objects: usize = MAX_OBJECTS,
    max_versions: usize = MAX_VERSIONS,
    object_index_capacity: usize = OBJECT_INDEX_CAPACITY,
    version_index_capacity: usize = VERSION_INDEX_CAPACITY,
    blob_index_capacity: usize = BLOB_INDEX_CAPACITY,

    pub fn validate(comptime config: StoreConfig) void {
        if (config.max_objects == 0) @compileError("object store requires at least one object slot");
        if (config.max_versions == 0) @compileError("object store requires at least one version slot");
        if (config.object_index_capacity < config.max_objects) @compileError("object index capacity must cover object slots");
        if (config.version_index_capacity < config.max_versions) @compileError("version index capacity must cover version slots");
        if (config.blob_index_capacity < config.max_versions) @compileError("blob index capacity must cover version blobs");
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
    object_type: ObjectType,
    blob_address: BlobAddress,
    version_address: VersionAddress,
    metadata: SignedMetadata,
    payload_len: usize,
    blob_slot_index: usize,
    chunk_count: u16,
};

pub const BlobRecord = struct {
    address: BlobAddress,
    payload_len: usize,
    payload: [MAX_BLOB_BYTES]u8,
    ref_count: u16,

    pub fn payloadSlice(self: *const BlobRecord) []const u8 {
        return self.payload[0..self.payload_len];
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
        .payload_len = 0,
        .payload = [_]u8{0} ** MAX_BLOB_BYTES,
        .ref_count = 0,
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

pub const Store = StoreWith(.{});

pub fn StoreWith(comptime config: StoreConfig) type {
    config.validate();
    return struct {
        const Self = @This();
        const MAX_STORE_OBJECTS = config.max_objects;
        const MAX_STORE_VERSIONS = config.max_versions;
        const STORE_OBJECT_INDEX_CAPACITY = config.object_index_capacity;
        const STORE_VERSION_INDEX_CAPACITY = config.version_index_capacity;
        const STORE_BLOB_INDEX_CAPACITY = config.blob_index_capacity;
        const ObjectArena = indexed_arena.IndexedArenaWithKey(ids.ObjectId, ObjectSlot, MAX_STORE_OBJECTS, STORE_OBJECT_INDEX_CAPACITY, objectSlotId);
        const VersionArena = indexed_arena.IndexedArenaWithKey(ids.VersionId, VersionSlot, MAX_STORE_VERSIONS, STORE_VERSION_INDEX_CAPACITY, versionSlotId);
        const BlobIndex = indexed_arena.UniqueIndex(STORE_BLOB_INDEX_CAPACITY);

        next_object_id: u64 = 1,
        next_version_id: u64 = 1,
        objects: ObjectArena = ObjectArena.init(),
        versions: VersionArena = VersionArena.init(),
        blob_index: BlobIndex = BlobIndex.init(),
        blobs: [MAX_BLOBS]BlobSlot = [_]BlobSlot{BlobSlot{}} ** MAX_BLOBS,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.next_object_id = 1;
            self.next_version_id = 1;
            self.objects.reset();
            self.versions.reset();
            self.blob_index.reset();
            for (&self.blobs) |*slot| {
                if (!slot.in_use) continue;
                slot.* = .{};
            }
        }

        pub fn rebuildIndexes(self: *Self) void {
            self.objects.rebuildPrimaryIndex();
            self.versions.rebuildPrimaryIndex();
            self.blob_index.reset();

            for (self.blobs, 0..) |slot, slot_index| {
                if (!slot.in_use) continue;
                self.blob_index.insert(indexIdForBytes(&slot.blob.address), slot_index);
            }
        }

        pub fn putVersion(self: *Self, request: PutRequest) Error!PutResult {
            return self.putVersionRef(&request);
        }

        pub fn putVersionRef(self: *Self, request: *const PutRequest) Error!PutResult {
            if (!request.metadata.isSigned()) return error.UnsignedMetadata;
            if (!request.metadata.signature.isComplete() or !request.metadata.verifyFor(request.object_type, request.payload)) {
                return error.InvalidSignature;
            }
            if (request.payload.len > MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;

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
            const version_address = computeVersionAddress(previous_version_id.raw(), request.metadata, blob_address);
            try self.insertVersion(.{
                .id = version_id,
                .object_id = object_record.id,
                .previous_version_id = previous_version_id,
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

        pub fn versionPayload(self: *const Self, version_record: *const VersionRecord) Error![]const u8 {
            const blob_record = self.blob(version_record.blob_address) orelse return error.BlobNotFound;
            if (blob_record.payload_len != version_record.payload_len) return error.CorruptBlob;
            if (!std.mem.eql(u8, &blob_record.address, &version_record.blob_address)) return error.CorruptBlob;
            if (!std.mem.eql(u8, &computeBlobAddress(blob_record.payloadSlice()), &version_record.blob_address)) return error.CorruptBlob;
            return blob_record.payloadSlice();
        }

        pub fn blob(self: *const Self, address: BlobAddress) ?*const BlobRecord {
            const slot_index = self.blobSlotIndex(address) orelse return null;
            const slot = &self.blobs[slot_index];
            return &slot.blob;
        }

        pub fn blobSlotIndex(self: *const Self, address: BlobAddress) ?usize {
            if (self.indexedBlobSlot(address)) |slot| {
                return (@intFromPtr(slot) - @intFromPtr(&self.blobs[0])) / @sizeOf(BlobSlot);
            }
            return null;
        }

        pub fn blobCount(self: *const Self) usize {
            return fixed_table.countInUse(BlobSlot, MAX_BLOBS, &self.blobs);
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
            slot.version.object_type = request.object_type;
            copyBytes(slot.version.blob_address[0..], request.blob_address[0..]);
            copyBytes(slot.version.version_address[0..], request.version_address[0..]);
            writeMetadata(&slot.version.metadata, request.metadata);
            slot.version.payload_len = request.payload_len;
            slot.version.blob_slot_index = request.blob_slot_index;
            slot.version.chunk_count = chunkCountForLen(request.payload_len);
        }

        pub fn putBlob(self: *Self, address: BlobAddress, payload: []const u8) Error!usize {
            if (payload.len > MAX_BLOB_BYTES) return error.PayloadTooLarge;
            if (self.blobSlotIndex(address)) |slot_index| {
                const slot = &self.blobs[slot_index];
                if (slot.blob.payload_len != payload.len or !std.mem.eql(u8, slot.blob.payloadSlice(), payload)) return error.CorruptBlob;
                slot.blob.ref_count +|= 1;
                return slot_index;
            }
            const slot_index = fixed_table.firstFreeSlotIndex(BlobSlot, MAX_BLOBS, &self.blobs) orelse return error.BlobTableFull;
            const slot = &self.blobs[slot_index];
            slot.in_use = true;
            slot.blob.address = address;
            slot.blob.payload_len = payload.len;
            @memset(slot.blob.payload[0..], 0);
            copyBytes(slot.blob.payload[0..payload.len], payload);
            slot.blob.ref_count = 1;
            self.blob_index.insert(indexIdForBytes(&address), slot_index);
            return slot_index;
        }

        fn indexedBlobSlot(self: *const Self, address: BlobAddress) ?*const BlobSlot {
            return fixed_table.findIndexedConstSlot(
                BlobSlot,
                MAX_BLOBS,
                STORE_BLOB_INDEX_CAPACITY,
                &self.blobs,
                &self.blob_index.slots,
                indexIdForBytes(&address),
                blobSlotIndexId,
                address,
                blobSlotMatchesAddress,
            );
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

fn chunkCountForLen(payload_len: usize) u16 {
    const chunk_size: usize = 128;
    if (payload_len == 0) return 0;
    return @intCast((payload_len + chunk_size - 1) / chunk_size);
}

pub fn computeBlobAddress(payload: []const u8) BlobAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "payload", payload);
    return crypto_hash.finalize(&hasher);
}

fn computeVersionAddress(
    previous_version_id: u64,
    metadata: SignedMetadata,
    blob_address: BlobAddress,
) VersionAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "previous-version-id", previous_version_id);
    crypto_hash.updateBytes(&hasher, "label", metadata.labelSlice());
    crypto_hash.updateBytes(&hasher, "content-type", metadata.contentTypeSlice());
    crypto_hash.updateInt(&hasher, "created-at", metadata.created_at_ticks);
    crypto_hash.updateBytes(&hasher, "signature-signer", metadata.signature.signer);
    crypto_hash.updateBytes(&hasher, "signature-public-key", metadata.signature.publicKeySlice());
    crypto_hash.updateBytes(&hasher, "signature-value", metadata.signature.valueSlice());
    crypto_hash.updateBytes(&hasher, "blob-address", &blob_address);
    return crypto_hash.finalize(&hasher);
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
    try writeLengthPrefixed(&writer, payload);
    return buffer[0..writer.offset];
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

    var first_address = [_]u8{0} ** 32;
    var second_address = [_]u8{0} ** 32;
    const shared_prefix = [_]u8{ 0xD0, 0xED, 0x0B, 0x10, 0xBA, 0x5E, 0xAA, 0x55 };
    @memcpy(first_address[0..shared_prefix.len], &shared_prefix);
    @memcpy(second_address[0..shared_prefix.len], &shared_prefix);
    first_address[8] = 1;
    second_address[8] = 2;

    const first_slot = try store.putBlob(first_address, "first");
    const second_slot = try store.putBlob(second_address, "second");
    try std.testing.expect(first_slot != second_slot);
    try std.testing.expectEqual(@as(usize, 2), store.blobCount());

    const first_again = try store.putBlob(first_address, "first");
    try std.testing.expectEqual(first_slot, first_again);
    try std.testing.expectEqual(@as(usize, 2), store.blobCount());
    try std.testing.expectEqual(@as(u16, 2), store.blobs[first_slot].blob.ref_count);
    try std.testing.expectEqual(@as(u16, 1), store.blobs[second_slot].blob.ref_count);
    try std.testing.expectEqualStrings("first", store.blob(first_address).?.payloadSlice());
    try std.testing.expectEqualStrings("second", store.blob(second_address).?.payloadSlice());
    try std.testing.expectError(error.CorruptBlob, store.putBlob(first_address, "changed"));
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
    store.blobs[version_record.blob_slot_index].blob.payload[0] ^= 0xFF;
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
        .blob_index_capacity = 2,
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
