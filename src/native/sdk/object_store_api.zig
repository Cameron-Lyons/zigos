const std = @import("std");
const object_store_facade = @import("../storage/object_store.zig");
const signing = @import("../core/signing.zig");

const object_store = object_store_facade;

pub const Store = object_store.Store;
pub const ObjectType = object_store.ObjectType;
pub const PutResult = object_store.PutResult;
pub const ObjectQueryResult = object_store.ObjectQueryResult;
pub const ObjectHistoryEntry = object_store.ObjectHistoryEntry;
pub const ObjectOperatingModel = object_store.ObjectOperatingModel;
pub const COMPACT_OBJECT_HANDLE_METADATA = true;
pub const OBJECT_HANDLE_SIZE_CEILING_BYTES: usize = 136;
pub const LOADED_OBJECT_SIZE_CEILING_BYTES: usize = 152;
pub const Error = object_store.Error || error{
    ObjectPayloadUnavailable,
    StaleObjectVersion,
    LabelTooLong,
    ContentTypeTooLong,
};

comptime {
    if (object_store.MAX_METADATA_LABEL_BYTES > std.math.maxInt(u8) or
        object_store.MAX_CONTENT_TYPE_BYTES > std.math.maxInt(u8))
    {
        @compileError("object-store SDK metadata exceeds its compact length fields");
    }
}

pub const ObjectHandle = struct {
    object_id: object_store.ids.ObjectId,
    version_id: object_store.ids.VersionId,
    object_type: ObjectType,
    label_len: u8 = 0,
    label: [object_store.MAX_METADATA_LABEL_BYTES]u8 = [_]u8{0} ** object_store.MAX_METADATA_LABEL_BYTES,
    content_type_len: u8 = 0,
    content_type: [object_store.MAX_CONTENT_TYPE_BYTES]u8 = [_]u8{0} ** object_store.MAX_CONTENT_TYPE_BYTES,

    pub fn labelSlice(self: *const ObjectHandle) []const u8 {
        return self.label[0..@min(@as(usize, self.label_len), self.label.len)];
    }

    pub fn contentTypeSlice(self: *const ObjectHandle) []const u8 {
        return self.content_type[0..@min(@as(usize, self.content_type_len), self.content_type.len)];
    }

    comptime {
        if (@sizeOf(@This()) > OBJECT_HANDLE_SIZE_CEILING_BYTES) {
            @compileError("object-store SDK handle exceeds its compact size ceiling");
        }
    }
};

pub const LoadedObject = struct {
    handle: ObjectHandle,
    payload: []const u8,

    comptime {
        if (@sizeOf(@This()) > LOADED_OBJECT_SIZE_CEILING_BYTES) {
            @compileError("loaded object exceeds its compact size ceiling");
        }
    }
};

pub const Client = struct {
    store: Store = Store.init(),
    identity: signing.SignerIdentity,
    tick: u64 = 1,

    pub fn init(identity: signing.SignerIdentity) Client {
        return .{ .identity = identity };
    }

    pub fn putDocument(self: *Client, label: []const u8, content_type: []const u8, payload: []const u8) !PutResult {
        return self.put(.document, label, content_type, payload, null);
    }

    pub fn putDocumentObject(self: *Client, label: []const u8, content_type: []const u8, payload: []const u8) !ObjectHandle {
        const result = try self.putDocument(label, content_type, payload);
        return handleFromPut(result, .document, label, content_type);
    }

    pub fn update(
        self: *Client,
        previous: PutResult,
        label: []const u8,
        content_type: []const u8,
        payload: []const u8,
    ) !PutResult {
        return self.put(.document, label, content_type, payload, previous.version_id);
    }

    pub fn compareAndUpdate(
        self: *Client,
        previous: ObjectHandle,
        payload: []const u8,
    ) !ObjectHandle {
        const latest = self.store.latestVersion(previous.object_id) orelse return error.ObjectNotFound;
        if (!latest.id.eql(previous.version_id)) return error.StaleObjectVersion;
        const result = try self.put(
            previous.object_type,
            previous.labelSlice(),
            previous.contentTypeSlice(),
            payload,
            previous.version_id,
        );
        return handleFromPut(result, previous.object_type, previous.labelSlice(), previous.contentTypeSlice());
    }

    pub fn latestPayload(self: *Client, object_id: anytype) ![]const u8 {
        const latest = self.store.latestVersion(object_id) orelse return error.ObjectNotFound;
        return self.store.versionPayload(latest);
    }

    pub fn load(self: *Client, handle: ObjectHandle) !LoadedObject {
        const latest = self.store.latestVersion(handle.object_id) orelse return error.ObjectNotFound;
        const current = try handleFromVersion(latest);
        return .{
            .handle = current,
            .payload = try self.store.versionPayload(latest),
        };
    }

    pub fn queryByLabel(self: *Client, label: []const u8, out: []ObjectQueryResult) []const ObjectQueryResult {
        return self.store.queryObjects(.{ .label_contains = label }, out);
    }

    pub fn history(self: *Client, object_id: anytype, out: []ObjectHistoryEntry) ![]const ObjectHistoryEntry {
        return self.store.objectHistory(object_id, out);
    }

    pub fn operatingModel(self: *Client, object_id: anytype) !ObjectOperatingModel {
        return self.store.objectOperatingModel(object_id);
    }

    fn put(
        self: *Client,
        object_type: ObjectType,
        label: []const u8,
        content_type: []const u8,
        payload: []const u8,
        parent_version_id: ?object_store.ids.VersionId,
    ) !PutResult {
        const metadata = try object_store.signMetadata(
            self.identity,
            label,
            content_type,
            object_type,
            payload,
            self.nextTick(),
        );
        return self.store.putVersion(.{
            .object_type = object_type,
            .payload = payload,
            .metadata = metadata,
            .parent_version_id = parent_version_id,
        });
    }

    fn nextTick(self: *Client) u64 {
        defer self.tick += 1;
        return self.tick;
    }
};

fn handleFromPut(
    result: PutResult,
    object_type: ObjectType,
    label: []const u8,
    content_type: []const u8,
) Error!ObjectHandle {
    var handle = ObjectHandle{
        .object_id = result.object_id,
        .version_id = result.version_id,
        .object_type = object_type,
    };
    handle.label_len = @intCast(copyText(&handle.label, label) catch return error.LabelTooLong);
    handle.content_type_len = @intCast(copyText(&handle.content_type, content_type) catch return error.ContentTypeTooLong);
    return handle;
}

fn handleFromVersion(version: *const object_store.VersionRecord) Error!ObjectHandle {
    var handle = ObjectHandle{
        .object_id = version.object_id,
        .version_id = version.id,
        .object_type = version.object_type,
    };
    handle.label_len = @intCast(copyText(&handle.label, version.metadata.labelSlice()) catch return error.LabelTooLong);
    handle.content_type_len = @intCast(copyText(&handle.content_type, version.metadata.contentTypeSlice()) catch return error.ContentTypeTooLong);
    return handle;
}

fn copyText(dest: []u8, source: []const u8) error{TextTooLong}!usize {
    if (source.len > dest.len) return error.TextTooLong;
    @memcpy(dest[0..source.len], source);
    return source.len;
}

test "object-store SDK handle uses compact bounded metadata" {
    try std.testing.expect(COMPACT_OBJECT_HANDLE_METADATA);
    try std.testing.expectEqual(u8, @FieldType(ObjectHandle, "label_len"));
    try std.testing.expectEqual(u8, @FieldType(ObjectHandle, "content_type_len"));
    try std.testing.expect(@sizeOf(ObjectHandle) <= OBJECT_HANDLE_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(LoadedObject) <= LOADED_OBJECT_SIZE_CEILING_BYTES);
}

test "object-store SDK stores signed versions and queries developer fixtures" {
    const identity = signing.SignerIdentity{
        .label = "sdk.object-store",
        .seed = signing.seedFromByte(0x34),
    };
    var client = Client.init(identity);
    const first = try client.putDocument("notes.md", "text/markdown", "# Notes");
    const second = try client.update(first, "notes.md", "text/markdown", "# Notes\n\nUpdated");
    try std.testing.expect(!second.new_object);

    const payload = try client.latestPayload(first.object_id);
    try std.testing.expectEqualStrings("# Notes\n\nUpdated", payload);

    var query_results: [4]ObjectQueryResult = undefined;
    const found = client.queryByLabel("notes", &query_results);
    try std.testing.expectEqual(@as(usize, 1), found.len);

    var history_entries: [4]ObjectHistoryEntry = undefined;
    const entries = try client.history(first.object_id, &history_entries);
    try std.testing.expectEqual(@as(usize, 2), entries.len);

    const model = try client.operatingModel(first.object_id);
    try std.testing.expect(model.isWholeOsObject());
    try std.testing.expectEqual(ObjectType.document, model.object_type);
    try std.testing.expectEqual(second.version_id, model.latest_version_id);
    try std.testing.expectEqual(object_store.FileBridgePolicy.import_export_only, model.file_bridge_policy);

    const handle = try client.putDocumentObject("typed-note.md", "text/markdown", "# Typed");
    const updated = try client.compareAndUpdate(handle, "# Typed\n\nNative handle");
    const loaded = try client.load(updated);
    try std.testing.expectEqual(updated.version_id, loaded.handle.version_id);
    try std.testing.expectEqualStrings("# Typed\n\nNative handle", loaded.payload);
    try std.testing.expectError(error.StaleObjectVersion, client.compareAndUpdate(handle, "# stale"));
}
