const std = @import("std");
const ids = @import("../core/ids.zig");
const object_store = @import("object_store.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("storage_service.zig");
const storage_volume = @import("storage_volume.zig");
const document_save = @import("document_save.zig");

pub const signer = signing.SignerIdentity{ .label = "document-save-test", .seed = signing.seedFromByte(0xc1) };
pub const path = "documents/note.md";

// Writes enter volatile device state. Only a successful flush survives crash().
pub const Fixture = struct {
    var active: ?*Fixture = null;
    checkpoint: *storage_service.CheckpointStore,
    service: storage_service.Service,
    image: []u8,
    durable_image: []u8,
    workspace_id: u64 = 0,
    original_version_id: u64 = 0,
    fail_writes: bool = false,
    fail_flushes: bool = false,
    fail_flush_from: ?usize = null,
    writes: usize = 0,
    flushes: usize = 0,
    before_flush: ?struct { context: *anyopaque, call: *const fn (*anyopaque) void } = null,

    pub fn init(attach: bool) !*Fixture {
        storage_volume.clearAttachedBackend();
        const allocator = std.testing.allocator;
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        const checkpoint = try allocator.create(storage_service.CheckpointStore);
        errdefer allocator.destroy(checkpoint);
        checkpoint.* = .{};
        const image = try allocator.alloc(u8, storage_volume.image_bytes);
        errdefer allocator.free(image);
        const durable = try allocator.alloc(u8, storage_volume.image_bytes);
        errdefer allocator.free(durable);
        @memset(image, 0);
        @memset(durable, 0);
        self.* = .{ .checkpoint = checkpoint, .service = undefined, .image = image, .durable_image = durable };
        active = self;
        if (attach) storage_volume.attachBackend(.{
            .sector_count = storage_volume.required_device_sectors,
            .read = read,
            .write = write,
            .flush = flush,
        });
        self.service = storage_service.Service.initWithStore(500, 501, .{ .kind = .service, .serial = 500 }, checkpoint);
        const original = try self.service.putVersion(.{
            .preferred_object_id = ids.object(900),
            .object_type = .document,
            .payload = "original",
            .metadata = try object_store.signMetadata(signer, path, "text/markdown", .document, "original", 1),
        });
        const ws = try self.service.createWorkspace(.{ .owner = .{ .kind = .user, .serial = 1 }, .label = "notes" });
        self.workspace_id = ws.id.raw();
        self.original_version_id = original.version_id.raw();
        try self.service.beginTransaction(ws.id);
        try self.service.stagePut(ws.id, path, original.object_id, original.version_id, .document);
        _ = try self.service.commit(ws.id, 2);
        return self;
    }

    pub fn deinit(self: *Fixture) void {
        storage_volume.clearAttachedBackend();
        self.checkpoint.resetPersistent();
        active = null;
        const allocator = std.testing.allocator;
        allocator.free(self.image);
        allocator.free(self.durable_image);
        allocator.destroy(self.checkpoint);
        allocator.destroy(self);
    }

    // Tests with multiple independent images select the device before each
    // serialized storage operation; the modeled driver has one active disk.
    pub fn activate(self: *Fixture) void {
        active = self;
        storage_volume.attachBackend(.{ .sector_count = storage_volume.required_device_sectors, .read = read, .write = write, .flush = flush });
    }

    fn request(self: *Fixture, payload: []const u8) document_save.VerificationRequest {
        return .{ .workspace_id = self.workspace_id, .path = path, .expected_version_id = self.original_version_id, .payload = payload, .signer = signer, .tick = 10 };
    }

    pub fn crash(self: *Fixture) void {
        @memcpy(self.image, self.durable_image);
        self.checkpoint.resetPreparedState();
        self.service = storage_service.Service.initWithStore(500, 501, .{ .kind = .service, .serial = 500 }, self.checkpoint);
    }

    pub fn text(self: *Fixture) ![]const u8 {
        const entry = try self.service.resolve(self.workspace_id, path);
        return self.service.versionPayload(self.service.version(entry.version_id).?);
    }

    fn read(lba: u64, out: [*]u8, len: usize) callconv(.c) bool {
        const self = active.?;
        const offset: usize = @intCast(lba * storage_volume.sector_size);
        if (offset > self.image.len or len > self.image.len - offset) return false;
        @memcpy(out[0..len], self.image[offset..][0..len]);
        return true;
    }

    fn write(lba: u64, bytes: [*]const u8, len: usize) callconv(.c) bool {
        const self = active.?;
        self.writes += 1;
        if (self.fail_writes) return false;
        const offset: usize = @intCast(lba * storage_volume.sector_size);
        if (offset > self.image.len or len > self.image.len - offset) return false;
        @memcpy(self.image[offset..][0..len], bytes[0..len]);
        return true;
    }

    fn flush() callconv(.c) bool {
        const self = active.?;
        self.flushes += 1;
        if (self.before_flush) |callback| callback.call(callback.context);
        if (self.fail_flushes) return false;
        if (self.fail_flush_from) |first| if (self.flushes >= first) return false;
        @memcpy(self.durable_image, self.image);
        return true;
    }
};

test "document save acknowledges one durable object and path checkpoint and reopens it" {
    const fixture = try Fixture.init(true);
    defer fixture.deinit();
    var editor = document_save.Session{};
    const generation = fixture.checkpoint.last_checkpoint_generation;
    const saved = try editor.saveForVerification(&fixture.service, fixture.request("saved draft"));
    try std.testing.expectEqual(generation + 1, saved.checkpoint_generation);
    try std.testing.expectEqual(fixture.original_version_id, saved.previous_version_id);
    try std.testing.expectEqual(@as(usize, 2), fixture.service.versionCount());
    try std.testing.expect(editor.pending == null);
    fixture.crash();
    try std.testing.expect(fixture.service.loaded_from_volume);
    try std.testing.expectEqualStrings("saved draft", try fixture.text());
    try std.testing.expectEqual(saved.version_id, (try fixture.service.resolve(fixture.workspace_id, path)).version_id.raw());
    // An unchanged reopened checkpoint also produces a real generation receipt.
    try std.testing.expectEqual(saved.checkpoint_generation, try fixture.service.checkpointDurable());
}

test "failed document writes retain one pending version across retries" {
    const fixture = try Fixture.init(true);
    defer fixture.deinit();
    var editor = document_save.Session{};
    fixture.fail_writes = true;
    for (0..4) |_| {
        try std.testing.expectError(error.CorruptImage, editor.saveForVerification(&fixture.service, fixture.request("pending draft")));
        try std.testing.expectEqual(@as(usize, 2), fixture.service.versionCount());
        try std.testing.expect(editor.pending != null);
        try std.testing.expect(fixture.checkpoint.dirty);
    }
    const pending_version = editor.pending.?.version_id;
    fixture.fail_writes = false;
    const saved = try editor.saveForVerification(&fixture.service, fixture.request("pending draft"));
    try std.testing.expectEqual(pending_version, saved.version_id);
    try std.testing.expectEqual(@as(usize, 2), fixture.service.versionCount());
    fixture.crash();
    try std.testing.expectEqualStrings("pending draft", try fixture.text());
}

test "failed flush is not acknowledged and volatile draft disappears after power loss" {
    // Fail either the data barrier or the later root-commit barrier. A device
    // may accept root writes without making them survive a power loss.
    for ([_]usize{ 1, 2 }) |barrier| {
        const fixture = try Fixture.init(true);
        defer fixture.deinit();
        var editor = document_save.Session{};
        fixture.fail_flush_from = fixture.flushes + barrier;
        try std.testing.expectError(error.DurabilityBarrierFailed, editor.saveForVerification(&fixture.service, fixture.request("volatile draft")));
        try std.testing.expect(fixture.checkpoint.dirty);
        fixture.crash();
        try std.testing.expect(fixture.service.loaded_from_volume);
        try std.testing.expectEqualStrings("original", try fixture.text());
        try std.testing.expectEqual(fixture.original_version_id, (try fixture.service.resolve(fixture.workspace_id, path)).version_id.raw());
    }
}

test "failed root commit barrier is retried before a document save is acknowledged" {
    const fixture = try Fixture.init(true);
    defer fixture.deinit();
    var editor = document_save.Session{};
    fixture.fail_flush_from = fixture.flushes + 2;
    try std.testing.expectError(error.DurabilityBarrierFailed, editor.saveForVerification(&fixture.service, fixture.request("pending root")));
    const pending_version = editor.pending.?.version_id;
    const failed_flushes = fixture.flushes;
    fixture.fail_flush_from = null;
    const saved = try editor.saveForVerification(&fixture.service, fixture.request("pending root"));
    try std.testing.expect(fixture.flushes > failed_flushes);
    try std.testing.expectEqual(pending_version, saved.version_id);
    try std.testing.expectEqual(@as(usize, 2), fixture.service.versionCount());
    fixture.crash();
    try std.testing.expectEqualStrings("pending root", try fixture.text());
}

test "save retry flushes the original version before accepting a newer draft" {
    const fixture = try Fixture.init(true);
    defer fixture.deinit();
    var editor = document_save.Session{};
    fixture.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, editor.saveForVerification(&fixture.service, fixture.request("first draft")));
    const pending_version = editor.pending.?.version_id;
    try std.testing.expectError(error.DurabilityBarrierFailed, editor.saveForVerification(&fixture.service, fixture.request("second draft")));
    try std.testing.expectEqual(@as(usize, 2), fixture.service.versionCount());
    fixture.fail_flushes = false;
    const saved = try editor.saveForVerification(&fixture.service, fixture.request("second draft"));
    try std.testing.expectEqual(pending_version, saved.previous_version_id);
    try std.testing.expectEqual(@as(usize, 3), fixture.service.versionCount());
    fixture.crash();
    try std.testing.expectEqualStrings("second draft", try fixture.text());
}

test "stale editor and pending save cannot overwrite another editor" {
    const fixture = try Fixture.init(true);
    defer fixture.deinit();
    var first = document_save.Session{};
    var second = document_save.Session{};
    fixture.fail_writes = true;
    try std.testing.expectError(error.CorruptImage, first.saveForVerification(&fixture.service, fixture.request("first")));
    fixture.fail_writes = false;
    var next = fixture.request("second");
    next.expected_version_id = first.pending.?.version_id;
    _ = try second.saveForVerification(&fixture.service, next);
    const count = fixture.service.versionCount();
    const writes = fixture.writes;
    try std.testing.expectError(error.DocumentChanged, first.saveForVerification(&fixture.service, fixture.request("first")));
    try std.testing.expectError(error.DocumentChanged, second.saveForVerification(&fixture.service, fixture.request("stale")));
    try std.testing.expectEqual(count, fixture.service.versionCount());
    try std.testing.expectEqual(writes, fixture.writes);
    try std.testing.expectEqualStrings("second", try fixture.text());
}

test "explicit document save rejects absent devices and incomplete checkpoints" {
    const fixture = try Fixture.init(false);
    defer fixture.deinit();
    var editor = document_save.Session{};
    const count = fixture.service.versionCount();
    try std.testing.expectError(error.NoBackingDevice, editor.saveForVerification(&fixture.service, fixture.request("no device")));
    try std.testing.expectError(error.NoBackingDevice, fixture.service.checkpointDurable());
    try fixture.service.beginTransaction(fixture.workspace_id);
    try std.testing.expectError(error.CheckpointDeferred, editor.saveForVerification(&fixture.service, fixture.request("transaction")));
    try fixture.service.abortTransaction(fixture.workspace_id);
    fixture.service.beginCheckpointBatch();
    try std.testing.expectError(error.CheckpointDeferred, fixture.service.checkpointDurable());
    fixture.service.endCheckpointBatch();
    try std.testing.expectEqual(count, fixture.service.versionCount());
    try std.testing.expect(editor.pending == null);
}

test "saving a pinned workspace version preserves other workspace pointers" {
    const fixture = try Fixture.init(true);
    defer fixture.deinit();
    const other = try fixture.service.createWorkspace(.{ .owner = .{ .kind = .user, .serial = 1 }, .label = "other" });
    const newer = try fixture.service.putVersion(.{
        .preferred_object_id = ids.object(900),
        .object_type = .document,
        .payload = "other workspace",
        .metadata = try object_store.signMetadata(signer, path, "text/markdown", .document, "other workspace", 3),
        .parent_version_id = ids.version(fixture.original_version_id),
    });
    try fixture.service.beginTransaction(other.id);
    try fixture.service.stagePut(other.id, path, newer.object_id, newer.version_id, .document);
    _ = try fixture.service.commit(other.id, 4);
    var editor = document_save.Session{};
    const saved = try editor.saveForVerification(&fixture.service, fixture.request("pinned draft"));
    try std.testing.expectEqual(fixture.original_version_id, saved.previous_version_id);
    try std.testing.expectEqual(newer.version_id, fixture.service.version(saved.version_id).?.previousVersionId());
    try std.testing.expectEqual(newer.version_id, (try fixture.service.resolve(other.id, path)).version_id);
    const other_id = other.id;
    fixture.crash();
    try std.testing.expectEqualStrings("pinned draft", try fixture.text());
    try std.testing.expectEqual(newer.version_id, (try fixture.service.resolve(other_id, path)).version_id);
}

test "an empty document and explicit save with automatic checkpoints disabled are durable" {
    const fixture = try Fixture.init(true);
    defer fixture.deinit();
    var editor = document_save.Session{};
    fixture.service.checkpoint_enabled = false;
    _ = try editor.saveForVerification(&fixture.service, fixture.request(""));
    fixture.crash();
    try std.testing.expectEqualStrings("", try fixture.text());
}
