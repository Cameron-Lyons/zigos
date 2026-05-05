const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const fixed_table = @import("../core/fixed_table.zig");
const id_index = @import("../core/id_index.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const signing = @import("../core/signing.zig");
const copyText = native_util.copyText;

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
    content_type: [32]u8 = [_]u8{0} ** 32,
    created_at_ticks: u64 = 0,

    pub fn init(
        label: []const u8,
        content_type: []const u8,
        signature: manifest.Signature,
        created_at_ticks: u64,
    ) SignedMetadata {
        var metadata = SignedMetadata{
            .signature = signature,
            .created_at_ticks = created_at_ticks,
        };
        metadata.label_len = copyText(&metadata.label, label);
        metadata.content_type_len = copyText(&metadata.content_type, content_type);
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
    preferred_object_id: ?u64 = null,
    object_type: ObjectType,
    payload: []const u8,
    metadata: SignedMetadata,
    parent_version_id: ?u64 = null,
};

pub const PutResult = struct {
    object_id: u64,
    version_id: u64,
    blob_address: BlobAddress,
    version_address: VersionAddress,
    new_object: bool,
};

pub const ObjectRecord = struct {
    id: u64,
    object_type: ObjectType,
    latest_version_id: u64,
    version_count: u16,
};

pub const VersionRecord = struct {
    id: u64,
    object_id: u64,
    previous_version_id: u64,
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
    InvalidSignature,
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

pub const SignMetadataError = anyerror;

const ObjectSlot = struct {
    in_use: bool = false,
    object: ObjectRecord = .{
        .id = 0,
        .object_type = .blob,
        .latest_version_id = 0,
        .version_count = 0,
    },
};

const VersionSlot = struct {
    in_use: bool = false,
    version: VersionRecord = .{
        .id = 0,
        .object_id = 0,
        .previous_version_id = 0,
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

const IdIndexSlot = id_index.Slot;

fn objectSlotMatchesId(object_id: u64, slot: *const ObjectSlot) bool {
    return slot.object.id == object_id;
}

fn objectSlotId(slot: *const ObjectSlot) u64 {
    return slot.object.id;
}

fn versionSlotMatchesId(version_id: u64, slot: *const VersionSlot) bool {
    return slot.version.id == version_id;
}

fn versionSlotId(slot: *const VersionSlot) u64 {
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

        next_object_id: u64 = 1,
        next_version_id: u64 = 1,
        object_index_slots: [STORE_OBJECT_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(STORE_OBJECT_INDEX_CAPACITY),
        version_index_slots: [STORE_VERSION_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(STORE_VERSION_INDEX_CAPACITY),
        blob_index_slots: [STORE_BLOB_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(STORE_BLOB_INDEX_CAPACITY),
        objects: [MAX_STORE_OBJECTS]ObjectSlot = [_]ObjectSlot{ObjectSlot{}} ** MAX_STORE_OBJECTS,
        versions: [MAX_STORE_VERSIONS]VersionSlot = [_]VersionSlot{VersionSlot{}} ** MAX_STORE_VERSIONS,
        blobs: [MAX_BLOBS]BlobSlot = [_]BlobSlot{BlobSlot{}} ** MAX_BLOBS,
        dirty_object_count: usize = 0,
        dirty_object_ids: [MAX_STORE_OBJECTS]u64 = [_]u64{0} ** MAX_STORE_OBJECTS,
        dirty_version_count: usize = 0,
        dirty_version_ids: [MAX_STORE_VERSIONS]u64 = [_]u64{0} ** MAX_STORE_VERSIONS,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.next_object_id = 1;
            self.next_version_id = 1;
            self.object_index_slots = emptyIndexTable(STORE_OBJECT_INDEX_CAPACITY);
            self.version_index_slots = emptyIndexTable(STORE_VERSION_INDEX_CAPACITY);
            self.blob_index_slots = emptyIndexTable(STORE_BLOB_INDEX_CAPACITY);
            self.clearDirty();
            for (&self.objects) |*slot| {
                if (!slot.in_use) continue;
                slot.* = .{};
            }
            for (&self.versions) |*slot| {
                if (!slot.in_use) continue;
                slot.* = .{};
            }
            for (&self.blobs) |*slot| {
                if (!slot.in_use) continue;
                slot.* = .{};
            }
        }

        pub fn rebuildIndexes(self: *Self) void {
            self.object_index_slots = emptyIndexTable(STORE_OBJECT_INDEX_CAPACITY);
            self.version_index_slots = emptyIndexTable(STORE_VERSION_INDEX_CAPACITY);
            self.blob_index_slots = emptyIndexTable(STORE_BLOB_INDEX_CAPACITY);

            for (self.objects, 0..) |slot, slot_index| {
                if (!slot.in_use) continue;
                indexInsert(STORE_OBJECT_INDEX_CAPACITY, &self.object_index_slots, slot.object.id, slot_index);
            }
            for (self.versions, 0..) |slot, slot_index| {
                if (!slot.in_use) continue;
                indexInsert(STORE_VERSION_INDEX_CAPACITY, &self.version_index_slots, slot.version.id, slot_index);
            }
            for (self.blobs, 0..) |slot, slot_index| {
                if (!slot.in_use) continue;
                indexInsertBytes(STORE_BLOB_INDEX_CAPACITY, &self.blob_index_slots, &slot.blob.address, slot_index);
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
                    if (existing.latest_version_id != parent_version_id) return error.ParentMismatch;
                    if (request.preferred_object_id) |preferred_object_id| {
                        if (preferred_object_id != existing.id) return error.ParentMismatch;
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
            if (object_record.latest_version_id != 0 and previous_version_id != object_record.latest_version_id) {
                return error.ParentMismatch;
            }

            const version_id = self.nextVersionId();
            const blob_address = computeBlobAddress(request.payload);
            const blob_slot_index = try self.putBlob(blob_address, request.payload);
            const version_address = computeVersionAddress(previous_version_id, request.metadata, blob_address);
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

        pub fn object(self: *Self, object_id: u64) ?*ObjectRecord {
            const slot = fixed_table.findIndexedSlot(
                ObjectSlot,
                MAX_STORE_OBJECTS,
                STORE_OBJECT_INDEX_CAPACITY,
                &self.objects,
                &self.object_index_slots,
                object_id,
                objectSlotId,
                object_id,
                objectSlotMatchesId,
            ) orelse return null;
            return &slot.object;
        }

        pub fn version(self: *Self, version_id: u64) ?*VersionRecord {
            const slot = fixed_table.findIndexedSlot(
                VersionSlot,
                MAX_STORE_VERSIONS,
                STORE_VERSION_INDEX_CAPACITY,
                &self.versions,
                &self.version_index_slots,
                version_id,
                versionSlotId,
                version_id,
                versionSlotMatchesId,
            ) orelse return null;
            return &slot.version;
        }

        pub fn latestVersion(self: *Self, object_id: u64) ?*VersionRecord {
            const object_record = self.object(object_id) orelse return null;
            if (object_record.latest_version_id == 0) return null;
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
            if (self.indexedBlobSlot(address)) |slot| return &slot.blob;
            for (&self.blobs) |*slot| {
                if (slot.in_use and std.mem.eql(u8, &slot.blob.address, &address)) return &slot.blob;
            }
            return null;
        }

        pub fn blobCount(self: *const Self) usize {
            return fixed_table.countInUse(BlobSlot, MAX_BLOBS, &self.blobs);
        }

        pub fn objectCount(self: *const Self) usize {
            return fixed_table.countInUse(ObjectSlot, MAX_STORE_OBJECTS, &self.objects);
        }

        pub fn versionCount(self: *const Self) usize {
            return fixed_table.countInUse(VersionSlot, MAX_STORE_VERSIONS, &self.versions);
        }

        pub fn dirtyObjectIds(self: *const Self) []const u64 {
            return self.dirty_object_ids[0..self.dirty_object_count];
        }

        pub fn dirtyVersionIds(self: *const Self) []const u64 {
            return self.dirty_version_ids[0..self.dirty_version_count];
        }

        pub fn clearDirty(self: *Self) void {
            @memset(self.dirty_object_ids[0..], 0);
            @memset(self.dirty_version_ids[0..], 0);
            self.dirty_object_count = 0;
            self.dirty_version_count = 0;
        }

        fn nextObjectId(self: *Self) u64 {
            defer self.next_object_id += 1;
            return self.next_object_id;
        }

        fn nextVersionId(self: *Self) u64 {
            defer self.next_version_id += 1;
            return self.next_version_id;
        }

        fn createObject(self: *Self, object_id: u64, object_type: ObjectType) Error!*ObjectRecord {
            const slot_index = fixed_table.firstFreeSlotIndex(ObjectSlot, MAX_STORE_OBJECTS, &self.objects) orelse return error.ObjectTableFull;
            const slot = &self.objects[slot_index];
            slot.in_use = true;
            slot.object = .{
                .id = object_id,
                .object_type = object_type,
                .latest_version_id = 0,
                .version_count = 0,
            };
            if (object_id >= self.next_object_id) {
                self.next_object_id = object_id + 1;
            }
            indexInsert(STORE_OBJECT_INDEX_CAPACITY, &self.object_index_slots, object_id, slot_index);
            return &slot.object;
        }

        fn insertVersion(self: *Self, request: struct {
            id: u64,
            object_id: u64,
            previous_version_id: u64,
            object_type: ObjectType,
            blob_address: BlobAddress,
            version_address: VersionAddress,
            metadata: *const SignedMetadata,
            payload_len: usize,
            blob_slot_index: usize,
        }) Error!void {
            const slot_index = fixed_table.firstFreeSlotIndex(VersionSlot, MAX_STORE_VERSIONS, &self.versions) orelse return error.VersionTableFull;
            const slot = &self.versions[slot_index];
            slot.in_use = true;
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
            indexInsert(STORE_VERSION_INDEX_CAPACITY, &self.version_index_slots, request.id, slot_index);
        }

        pub fn putBlob(self: *Self, address: BlobAddress, payload: []const u8) Error!usize {
            if (payload.len > MAX_BLOB_BYTES) return error.PayloadTooLarge;
            if (indexLookupBytes(STORE_BLOB_INDEX_CAPACITY, &self.blob_index_slots, &address)) |slot_index| {
                const slot = &self.blobs[slot_index];
                if (slot.in_use and std.mem.eql(u8, &slot.blob.address, &address)) {
                    if (slot.blob.payload_len != payload.len or !std.mem.eql(u8, slot.blob.payloadSlice(), payload)) return error.CorruptBlob;
                    slot.blob.ref_count +|= 1;
                    return slot_index;
                }
            }
            if (self.exactBlobSlotIndex(address)) |exact_slot_index| {
                const exact = &self.blobs[exact_slot_index];
                if (exact.blob.payload_len != payload.len or !std.mem.eql(u8, exact.blob.payloadSlice(), payload)) return error.CorruptBlob;
                exact.blob.ref_count +|= 1;
                return exact_slot_index;
            }
            const slot_index = fixed_table.firstFreeSlotIndex(BlobSlot, MAX_BLOBS, &self.blobs) orelse return error.BlobTableFull;
            const slot = &self.blobs[slot_index];
            slot.in_use = true;
            slot.blob.address = address;
            slot.blob.payload_len = payload.len;
            @memset(slot.blob.payload[0..], 0);
            copyBytes(slot.blob.payload[0..payload.len], payload);
            slot.blob.ref_count = 1;
            indexInsertBytes(STORE_BLOB_INDEX_CAPACITY, &self.blob_index_slots, &address, slot_index);
            return slot_index;
        }

        fn indexedBlobSlot(self: *const Self, address: BlobAddress) ?*const BlobSlot {
            return fixed_table.findIndexedConstSlot(
                BlobSlot,
                MAX_BLOBS,
                STORE_BLOB_INDEX_CAPACITY,
                &self.blobs,
                &self.blob_index_slots,
                indexIdForBytes(&address),
                blobSlotIndexId,
                address,
                blobSlotMatchesAddress,
            );
        }

        fn exactBlobSlotIndex(self: *Self, address: BlobAddress) ?usize {
            for (&self.blobs, 0..) |*slot, slot_index| {
                if (slot.in_use and std.mem.eql(u8, &slot.blob.address, &address)) return slot_index;
            }
            return null;
        }

        fn markObjectDirty(self: *Self, object_id: u64) void {
            appendDirtyId(MAX_STORE_OBJECTS, &self.dirty_object_ids, &self.dirty_object_count, object_id);
        }

        fn markVersionDirty(self: *Self, version_id: u64) void {
            appendDirtyId(MAX_STORE_VERSIONS, &self.dirty_version_ids, &self.dirty_version_count, version_id);
        }
    };
}

fn appendDirtyId(comptime capacity: usize, ids: *[capacity]u64, count: *usize, id: u64) void {
    if (id == 0) return;
    for (ids[0..count.*]) |existing| {
        if (existing == id) return;
    }
    if (count.* >= capacity) native_util.impossibleByInvariant("dirty id capacity covers table slots");
    ids[count.*] = id;
    count.* += 1;
}

pub fn signMetadata(
    identity: signing.SignerIdentity,
    label: []const u8,
    content_type: []const u8,
    object_type: ObjectType,
    payload: []const u8,
    created_at_ticks: u64,
) SignMetadataError!SignedMetadata {
    var metadata = SignedMetadata.init(label, content_type, .{}, created_at_ticks);
    var message_buffer: [MAX_METADATA_MESSAGE_BYTES]u8 = undefined;
    const message = try metadataMessage(&message_buffer, object_type, payload, metadata);
    metadata.signature = try signing.sign(identity, message);
    return metadata;
}

fn copyPayload(payload: []const u8) [MAX_PAYLOAD_BYTES]u8 {
    var buffer = [_]u8{0} ** MAX_PAYLOAD_BYTES;
    @memcpy(buffer[0..payload.len], payload);
    return buffer;
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

fn emptyIndexTable(comptime capacity: usize) [capacity]IdIndexSlot {
    return id_index.emptyTable(capacity);
}

fn indexLookup(comptime capacity: usize, table: *const [capacity]IdIndexSlot, id: u64) ?usize {
    return id_index.lookup(capacity, table, id);
}

fn indexInsert(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64, slot_index: usize) void {
    id_index.insert(capacity, table, id, slot_index, "id indexes never store the reserved zero id");
}

fn indexLookupBytes(comptime capacity: usize, table: *const [capacity]IdIndexSlot, bytes: []const u8) ?usize {
    return indexLookup(capacity, table, indexIdForBytes(bytes));
}

fn indexInsertBytes(comptime capacity: usize, table: *[capacity]IdIndexSlot, bytes: []const u8, slot_index: usize) void {
    indexInsert(capacity, table, indexIdForBytes(bytes), slot_index);
}

fn indexIdForBytes(bytes: []const u8) u64 {
    var id: u64 = 0;
    const len = @min(bytes.len, @sizeOf(u64));
    var index: usize = 0;
    while (index < len) : (index += 1) {
        id |= @as(u64, bytes[index]) << @intCast(index * 8);
    }
    if (id == 0) id = 1;
    return id;
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
    var used: usize = 0;
    used = try appendFormat(
        buffer,
        used,
        "object:{s}\nlabel:{s}\ncontent-type:{s}\ncreated:{d}\npayload:",
        .{ objectTypeName(object_type), metadata.labelSlice(), metadata.contentTypeSlice(), metadata.created_at_ticks },
    );
    used = try appendBytes(buffer, used, payload);
    return buffer[0..used];
}

fn objectTypeName(object_type: ObjectType) []const u8 {
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

fn appendBytes(buffer: []u8, offset: usize, bytes: []const u8) error{NoSpaceLeft}!usize {
    if (offset + bytes.len > buffer.len) return error.NoSpaceLeft;
    @memcpy(buffer[offset .. offset + bytes.len], bytes);
    return offset + bytes.len;
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
        .preferred_object_id = 900,
        .object_type = .document,
        .payload = "hello",
        .metadata = metadata_v1,
    });
    const second = try store.putVersion(.{
        .preferred_object_id = 900,
        .object_type = .document,
        .payload = "hello, world",
        .metadata = metadata_v2,
        .parent_version_id = first.version_id,
    });

    try std.testing.expectEqual(@as(usize, 1), store.objectCount());
    try std.testing.expectEqual(@as(usize, 2), store.versionCount());
    try std.testing.expectEqual(@as(u64, 900), first.object_id);
    try std.testing.expectEqual(@as(u64, 900), second.object_id);
    try std.testing.expect(!std.mem.eql(u8, &first.version_address, &second.version_address));
    try std.testing.expectEqualStrings("hello", try store.versionPayload(store.version(first.version_id).?));
    try std.testing.expectEqualStrings("hello, world", try store.versionPayload(store.latestVersion(first.object_id).?));
    try std.testing.expectEqual(first.version_id, store.version(second.version_id).?.previous_version_id);
    try std.testing.expectEqualStrings("zigos-storage-key", store.latestVersion(first.object_id).?.metadata.signature.signer);
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
        .preferred_object_id = 910,
        .object_type = .document,
        .payload = "same",
        .metadata = metadata_v1,
    });
    const second = try store.putVersion(.{
        .preferred_object_id = 911,
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

test "object store falls back to exact blob address match after index-key collision" {
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
        .preferred_object_id = 912,
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
            .preferred_object_id = 1000 + @as(u64, @intCast(index)),
            .object_type = object_type,
            .payload = payload,
            .metadata = try signMetadata(signer, payload, "application/octet-stream", object_type, payload, @intCast(index)),
        });
    }

    try std.testing.expectEqual(object_types.len, store.objectCount());
    try std.testing.expectError(error.UnsignedMetadata, store.putVersion(.{
        .object_type = .blob,
        .payload = "unsigned",
        .metadata = SignedMetadata.init("unsigned", "application/octet-stream", .{}, 0),
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
        .preferred_object_id = 901,
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
        .preferred_object_id = 1,
        .object_type = .document,
        .payload = "one",
        .metadata = try signMetadata(signer, "one", "text/plain", .document, "one", 1),
    });

    try std.testing.expectError(error.ObjectTableFull, store.putVersion(.{
        .preferred_object_id = 2,
        .object_type = .document,
        .payload = "two",
        .metadata = try signMetadata(signer, "two", "text/plain", .document, "two", 2),
    }));
}
