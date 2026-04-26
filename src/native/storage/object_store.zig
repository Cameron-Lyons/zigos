const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const signing = @import("../core/signing.zig");
const copyText = native_util.copyText;

pub const MAX_OBJECTS: usize = 128;
pub const MAX_VERSIONS: usize = 512;
pub const MAX_PAYLOAD_BYTES: usize = 512;
const MAX_METADATA_MESSAGE_BYTES: usize = MAX_PAYLOAD_BYTES + 256;
const OBJECT_INDEX_CAPACITY: usize = MAX_OBJECTS * 2;
const VERSION_INDEX_CAPACITY: usize = MAX_VERSIONS * 2;

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
    payload: [MAX_PAYLOAD_BYTES]u8,

    pub fn payloadSlice(self: *const VersionRecord) []const u8 {
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
        .payload = [_]u8{0} ** MAX_PAYLOAD_BYTES,
    },
};

const IndexState = enum(u8) {
    empty,
    filled,
    tombstone,
};

const IdIndexSlot = struct {
    state: IndexState = .empty,
    id: u64 = 0,
    slot_index: usize = 0,
};

pub const Store = struct {
    next_object_id: u64 = 1,
    next_version_id: u64 = 1,
    object_index_slots: [OBJECT_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(OBJECT_INDEX_CAPACITY),
    version_index_slots: [VERSION_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(VERSION_INDEX_CAPACITY),
    objects: [MAX_OBJECTS]ObjectSlot = [_]ObjectSlot{ObjectSlot{}} ** MAX_OBJECTS,
    versions: [MAX_VERSIONS]VersionSlot = [_]VersionSlot{VersionSlot{}} ** MAX_VERSIONS,

    pub fn init() Store {
        return .{};
    }

    pub fn reset(self: *Store) void {
        self.next_object_id = 1;
        self.next_version_id = 1;
        self.object_index_slots = emptyIndexTable(OBJECT_INDEX_CAPACITY);
        self.version_index_slots = emptyIndexTable(VERSION_INDEX_CAPACITY);
        for (&self.objects) |*slot| {
            if (!slot.in_use) continue;
            slot.* = .{};
        }
        for (&self.versions) |*slot| {
            if (!slot.in_use) continue;
            slot.* = .{};
        }
    }

    pub fn rebuildIndexes(self: *Store) void {
        self.object_index_slots = emptyIndexTable(OBJECT_INDEX_CAPACITY);
        self.version_index_slots = emptyIndexTable(VERSION_INDEX_CAPACITY);

        for (self.objects, 0..) |slot, slot_index| {
            if (!slot.in_use) continue;
            indexInsert(OBJECT_INDEX_CAPACITY, &self.object_index_slots, slot.object.id, slot_index);
        }
        for (self.versions, 0..) |slot, slot_index| {
            if (!slot.in_use) continue;
            indexInsert(VERSION_INDEX_CAPACITY, &self.version_index_slots, slot.version.id, slot_index);
        }
    }

    pub fn putVersion(self: *Store, request: PutRequest) Error!PutResult {
        return self.putVersionRef(&request);
    }

    pub fn putVersionRef(self: *Store, request: *const PutRequest) Error!PutResult {
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
        const version_address = computeVersionAddress(previous_version_id, request.metadata, blob_address);
        try self.insertVersion(.{
            .id = version_id,
            .object_id = object_record.id,
            .previous_version_id = previous_version_id,
            .object_type = request.object_type,
            .blob_address = blob_address,
            .version_address = version_address,
            .metadata = &request.metadata,
            .payload = request.payload,
        });

        object_record.latest_version_id = version_id;
        object_record.version_count += 1;

        return .{
            .object_id = object_record.id,
            .version_id = version_id,
            .blob_address = blob_address,
            .version_address = version_address,
            .new_object = created_new_object,
        };
    }

    pub fn object(self: *Store, object_id: u64) ?*ObjectRecord {
        if (self.indexedObjectSlot(object_id)) |slot| return &slot.object;
        for (&self.objects) |*slot| {
            if (slot.in_use and slot.object.id == object_id) return &slot.object;
        }
        return null;
    }

    pub fn version(self: *Store, version_id: u64) ?*VersionRecord {
        if (self.indexedVersionSlot(version_id)) |slot| return &slot.version;
        for (&self.versions) |*slot| {
            if (slot.in_use and slot.version.id == version_id) return &slot.version;
        }
        return null;
    }

    pub fn latestVersion(self: *Store, object_id: u64) ?*VersionRecord {
        const object_record = self.object(object_id) orelse return null;
        if (object_record.latest_version_id == 0) return null;
        return self.version(object_record.latest_version_id);
    }

    pub fn objectCount(self: *const Store) usize {
        var count: usize = 0;
        for (self.objects) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn versionCount(self: *const Store) usize {
        var count: usize = 0;
        for (self.versions) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    fn nextObjectId(self: *Store) u64 {
        defer self.next_object_id += 1;
        return self.next_object_id;
    }

    fn nextVersionId(self: *Store) u64 {
        defer self.next_version_id += 1;
        return self.next_version_id;
    }

    fn createObject(self: *Store, object_id: u64, object_type: ObjectType) Error!*ObjectRecord {
        for (&self.objects, 0..) |*slot, slot_index| {
            if (slot.in_use) continue;
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
            indexInsert(OBJECT_INDEX_CAPACITY, &self.object_index_slots, object_id, slot_index);
            return &slot.object;
        }
        return error.ObjectTableFull;
    }

    fn insertVersion(self: *Store, request: struct {
        id: u64,
        object_id: u64,
        previous_version_id: u64,
        object_type: ObjectType,
        blob_address: BlobAddress,
        version_address: VersionAddress,
        metadata: *const SignedMetadata,
        payload: []const u8,
    }) Error!void {
        for (&self.versions, 0..) |*slot, slot_index| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.version.id = request.id;
            slot.version.object_id = request.object_id;
            slot.version.previous_version_id = request.previous_version_id;
            slot.version.object_type = request.object_type;
            copyBytes(slot.version.blob_address[0..], request.blob_address[0..]);
            copyBytes(slot.version.version_address[0..], request.version_address[0..]);
            writeMetadata(&slot.version.metadata, request.metadata);
            slot.version.payload_len = request.payload.len;
            copyBytes(slot.version.payload[0..request.payload.len], request.payload);
            indexInsert(VERSION_INDEX_CAPACITY, &self.version_index_slots, request.id, slot_index);
            return;
        }
        return error.VersionTableFull;
    }

    fn indexedObjectSlot(self: *Store, object_id: u64) ?*ObjectSlot {
        const slot_index = indexLookup(OBJECT_INDEX_CAPACITY, &self.object_index_slots, object_id) orelse return null;
        const slot = &self.objects[slot_index];
        if (!slot.in_use or slot.object.id != object_id) return null;
        return slot;
    }

    fn indexedVersionSlot(self: *Store, version_id: u64) ?*VersionSlot {
        const slot_index = indexLookup(VERSION_INDEX_CAPACITY, &self.version_index_slots, version_id) orelse return null;
        const slot = &self.versions[slot_index];
        if (!slot.in_use or slot.version.id != version_id) return null;
        return slot;
    }
};

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
    return [_]IdIndexSlot{IdIndexSlot{}} ** capacity;
}

fn indexLookup(comptime capacity: usize, table: *const [capacity]IdIndexSlot, id: u64) ?usize {
    if (id == 0) return null;

    var index = indexHash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry = table[index];
        switch (entry.state) {
            .empty => return null,
            .filled => if (entry.id == id) return entry.slot_index,
            .tombstone => {},
        }
        index = (index + 1) % capacity;
    }
    return null;
}

fn indexInsert(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64, slot_index: usize) void {
    if (id == 0) unreachable;

    var index = indexHash(id, capacity);
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table[index].state) {
            .empty => {
                const insert_index = first_tombstone orelse index;
                table[insert_index] = .{
                    .state = .filled,
                    .id = id,
                    .slot_index = slot_index,
                };
                return;
            },
            .filled => {
                if (table[index].id == id) {
                    table[index].slot_index = slot_index;
                    return;
                }
            },
            .tombstone => {
                if (first_tombstone == null) first_tombstone = index;
            },
        }
        index = (index + 1) % capacity;
    }

    unreachable;
}

fn indexHash(id: u64, comptime capacity: usize) usize {
    return @as(usize, @intCast((id *% 0x9E37_79B9_7F4A_7C15) % capacity));
}

fn computeBlobAddress(payload: []const u8) BlobAddress {
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
    try std.testing.expectEqualStrings("hello", store.version(first.version_id).?.payloadSlice());
    try std.testing.expectEqualStrings("hello, world", store.latestVersion(first.object_id).?.payloadSlice());
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
