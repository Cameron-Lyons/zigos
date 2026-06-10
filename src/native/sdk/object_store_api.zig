const std = @import("std");
const object_store = @import("../storage/object_store.zig");
const signing = @import("../core/signing.zig");

pub const Store = object_store.Store;
pub const ObjectType = object_store.ObjectType;
pub const PutResult = object_store.PutResult;
pub const ObjectQueryResult = object_store.ObjectQueryResult;
pub const ObjectHistoryEntry = object_store.ObjectHistoryEntry;
pub const Error = object_store.Error || error{
    ObjectPayloadUnavailable,
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

    pub fn putMedia(self: *Client, label: []const u8, content_type: []const u8, payload: []const u8) !PutResult {
        return self.put(.media_asset, label, content_type, payload, null);
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

    pub fn latestPayload(self: *Client, object_id: anytype) ![]const u8 {
        const latest = self.store.latestVersion(object_id) orelse return error.ObjectNotFound;
        return self.store.versionPayload(latest);
    }

    pub fn queryByLabel(self: *Client, label: []const u8, out: []ObjectQueryResult) []const ObjectQueryResult {
        return self.store.queryObjects(.{ .label_contains = label }, out);
    }

    pub fn history(self: *Client, object_id: anytype, out: []ObjectHistoryEntry) ![]const ObjectHistoryEntry {
        return self.store.objectHistory(object_id, out);
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

test "object-store SDK stores signed versions and queries developer fixtures" {
    const identity = signing.SignerIdentity{
        .label = "sdk.object-store",
        .seed = [_]u8{0x34} ** signing.SEED_BYTES,
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
}
