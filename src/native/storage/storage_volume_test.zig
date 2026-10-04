const std = @import("std");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_volume = @import("storage_volume.zig");
const volume_layout = @import("volume/layout.zig");
const volume_log = @import("volume/log.zig");
const volume_hashing = @import("volume/hashing.zig");
const volume_root_slot = @import("volume/root_slot.zig");
const workspace = @import("workspace.zig");
const ids = @import("../core/ids.zig");
const cooperative = @import("../task/cooperative_worker.zig");

const Volume = storage_volume.Volume;
const image_bytes = storage_volume.image_bytes;
const saveToImage = storage_volume.saveToImage;
const loadFromImage = storage_volume.loadFromImage;
const DELTA_PAYLOAD_BUFFER_BYTES: usize = 32;

// Device callbacks retain the actual Volume scratch borrow while the worker
// suspends. The main test thread can then exercise another storage caller.
const SuspendedVolumeDevice = struct {
    const Phase = enum { none, read, write, flush };
    var current: *@This() = undefined;
    visible: []u8,
    durable: []u8,
    pause: Phase = .none,
    paused: bool = false,
    pause_on: usize = 1,
    phase_hits: usize = 0,
    fail_flush: bool = false,
    cancelled: bool = false,
    reenter: ?*SuspendedVolumeJob = null,
    reenter_spare: ?*Volume = null,
    reentry_ok: bool = false,

    fn backend() storage_volume.Backend {
        return .{ .sector_count = storage_volume.required_device_sectors, .read = read, .write = write, .flush = flush };
    }

    fn pauseAt(phase: Phase) bool {
        if (current.pause == phase) current.phase_hits += 1;
        if (current.pause == phase and current.phase_hits == current.pause_on and !current.paused) {
            if (current.reenter) |job| {
                current.reenter = null;
                current.reentry_ok = busyCallsRejected(job, current.reenter_spare.?);
            }
            current.paused = true;
            cooperative.current().?.yield();
            if (cooperative.current().?.cancel_requested) {
                current.cancelled = true;
                return false;
            }
        }
        return true;
    }

    fn read(lba: u64, ptr: [*]u8, len: usize) callconv(.c) bool {
        if (!pauseAt(.read)) return false;
        const offset = @as(usize, @intCast(lba)) * storage_volume.sector_size;
        if (offset > current.visible.len or len > current.visible.len - offset) return false;
        @memcpy(ptr[0..len], current.visible[offset..][0..len]);
        return true;
    }

    fn write(lba: u64, ptr: [*]const u8, len: usize) callconv(.c) bool {
        if (!pauseAt(.write)) return false;
        const offset = @as(usize, @intCast(lba)) * storage_volume.sector_size;
        if (offset > current.visible.len or len > current.visible.len - offset) return false;
        @memcpy(current.visible[offset..][0..len], ptr[0..len]);
        return true;
    }

    fn flush() callconv(.c) bool {
        if (!pauseAt(.flush) or current.fail_flush) return false;
        @memcpy(current.durable, current.visible);
        return true;
    }
};

const SuspendedVolumeJob = struct {
    volume: *Volume,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
    result: ?storage_volume.PersistResult = null,
    failure: ?anyerror = null,
    load: bool = false,
    loaded: bool = false,
    clear: bool = false,
    cleared: bool = false,

    fn run(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.clear) {
            self.cleared = self.volume.clearAttachedVolume();
            return;
        }
        if (self.load) {
            self.loaded = self.volume.loadFromVolume(self.store, self.workspaces);
            return;
        }
        self.result = self.volume.saveToVolume(self.store, self.workspaces) catch |err| {
            self.failure = err;
            return;
        };
    }
};

fn busyCallsRejected(job: *SuspendedVolumeJob, spare: *Volume) bool {
    const volume = job.volume;
    if (!volume.operationBusy() or !volume.attachmentBusy()) return false;
    if (volume.reset() or volume.clearAttachedBackend() or volume.clearAttachedVolume()) return false;
    if (volume.attachBackend(SuspendedVolumeDevice.backend()) or volume.attachNvmePciBackend(SuspendedVolumeDevice.backend())) return false;
    if (volume.attachNvmePciBackendFns(storage_volume.required_device_sectors, SuspendedVolumeDevice.read, SuspendedVolumeDevice.write, SuspendedVolumeDevice.flush)) return false;
    if (volume.adoptAttachedBackendFrom(spare) or spare.adoptAttachedBackendFrom(volume)) return false;
    if (volume.loadFromVolume(job.store, job.workspaces)) return false;
    if (volume.saveToVolume(job.store, job.workspaces)) |_| return false else |err| {
        if (err != error.VolumeOperationBusy) return false;
    }
    if (volume.saveToImage(SuspendedVolumeDevice.current.visible, job.store, job.workspaces)) |_| return false else |err| {
        if (err != error.VolumeOperationBusy) return false;
    }
    if (volume.loadFromImage(SuspendedVolumeDevice.current.visible, job.store, job.workspaces)) |_| return false else |err| {
        if (err != error.VolumeOperationBusy) return false;
    }
    return true;
}

const SuspendedVolumeFixture = struct {
    volume: *Volume,
    spare: *Volume,
    store: *object_store.Store,
    directory: *workspace.Directory,
    visible: []u8,
    durable: []u8,
    workspace_id: ids.WorkspaceId,

    fn init() !@This() {
        const allocator = std.testing.allocator;
        const volume = try allocator.create(Volume);
        errdefer allocator.destroy(volume);
        volume.* = Volume.init();
        const spare = try allocator.create(Volume);
        errdefer allocator.destroy(spare);
        spare.* = Volume.init();
        const store = try allocator.create(object_store.Store);
        errdefer allocator.destroy(store);
        store.* = object_store.Store.init();
        const directory = try allocator.create(workspace.Directory);
        errdefer allocator.destroy(directory);
        directory.* = workspace.Directory.init();
        const visible = try allocator.alloc(u8, image_bytes);
        errdefer allocator.free(visible);
        const durable = try allocator.alloc(u8, image_bytes);
        errdefer allocator.free(durable);
        @memset(visible, 0);
        @memset(durable, 0);
        const workspace_id = (try directory.create(.{ .owner = .{ .kind = .user, .serial = 1 }, .label = "paused" })).id;
        return .{ .volume = volume, .spare = spare, .store = store, .directory = directory, .visible = visible, .durable = durable, .workspace_id = workspace_id };
    }

    fn deinit(self: *@This()) void {
        if (self.volume.operationBusy() or self.spare.operationBusy()) @panic("test destroys suspended volume");
        _ = self.volume.reset();
        _ = self.spare.reset();
        self.directory.reset();
        self.store.reset();
        const allocator = std.testing.allocator;
        allocator.destroy(self.volume);
        allocator.destroy(self.spare);
        allocator.destroy(self.store);
        allocator.destroy(self.directory);
        allocator.free(self.visible);
        allocator.free(self.durable);
    }

    fn version(self: *@This(), payload: []const u8) !object_store.PutResult {
        return putSuspendedVersion(self.store, self.directory, self.workspace_id, payload);
    }
};

fn putSuspendedVersion(store: *object_store.Store, directory: *workspace.Directory, workspace_id: ids.WorkspaceId, payload: []const u8) !object_store.PutResult {
    const signer = signing.SignerIdentity{ .label = "paused-volume", .seed = signing.seedFromByte(0x6D) };
    const result = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(0xB900),
        .object_type = .document,
        .payload = payload,
        .metadata = try object_store.signMetadata(signer, "paused", "text/plain", .document, payload, 1),
    });
    try directory.beginTransaction(workspace_id);
    try directory.stagePut(workspace_id, "documents/paused.md", result.object_id, result.version_id, .document);
    _ = try directory.commit(workspace_id, 2);
    return result;
}

fn expectSuspendedCheckpointMutation(phase: SuspendedVolumeDevice.Phase, existing_root: bool, force_compaction: bool) !void {
    const allocator = std.testing.allocator;
    const volume = try allocator.create(Volume);
    volume.* = Volume.init();
    defer allocator.destroy(volume);
    const store = try allocator.create(object_store.Store);
    defer allocator.destroy(store);
    store.* = object_store.Store.init();
    const directory = try allocator.create(workspace.Directory);
    defer allocator.destroy(directory);
    directory.* = workspace.Directory.init();
    const visible = try allocator.alloc(u8, image_bytes);
    defer allocator.free(visible);
    const durable = try allocator.alloc(u8, image_bytes);
    defer allocator.free(durable);
    @memset(visible, 0);
    @memset(durable, 0);
    var device = SuspendedVolumeDevice{ .visible = visible, .durable = durable };
    SuspendedVolumeDevice.current = &device;
    _ = volume.attachBackend(SuspendedVolumeDevice.backend());
    const ws_id = (try directory.create(.{ .owner = .{ .kind = .user, .serial = 1 }, .label = "paused" })).id;
    if (existing_root) {
        _ = try putSuspendedVersion(store, directory, ws_id, "initial");
        _ = try volume.saveToVolume(store, directory);
        if (force_compaction) {
            var root = (try volume_root_slot.findLatestImageRoot(visible)).?;
            root.root.next_version_id += 4;
            try volume_root_slot.writeImageRoot(visible, root.sector_index, root.root);
            try volume_root_slot.writeImageRoot(durable, root.sector_index, root.root);
        }
    }
    const captured = try putSuspendedVersion(store, directory, ws_id, "captured");
    device.pause = phase;
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    var job = SuspendedVolumeJob{ .volume = volume, .store = store, .workspaces = directory };
    try worker.start(&job, SuspendedVolumeJob.run);
    try worker.step();
    try std.testing.expect(device.paused and worker.state == .suspended);
    const newer = try putSuspendedVersion(store, directory, ws_id, "newer");
    try worker.step();
    try std.testing.expect(worker.state == .complete and job.failure == null);
    try std.testing.expect(!job.result.?.snapshot_current);
    try std.testing.expect(store.dirtyVersionIds().len != 0 and directory.dirtyWorkspaceIds().len != 0);

    const reopened_store = try allocator.create(object_store.Store);
    defer allocator.destroy(reopened_store);
    reopened_store.* = object_store.Store.init();
    const reopened_directory = try allocator.create(workspace.Directory);
    defer allocator.destroy(reopened_directory);
    reopened_directory.* = workspace.Directory.init();
    const reopened_volume = try allocator.create(Volume);
    reopened_volume.* = Volume.init();
    defer allocator.destroy(reopened_volume);
    reopened_volume.* = Volume.init();
    _ = try reopened_volume.loadFromImage(durable, reopened_store, reopened_directory);
    try std.testing.expectEqual(captured.version_id, reopened_store.latestVersion(0xB900).?.id);
    try std.testing.expectEqual(captured.version_id, (try reopened_directory.resolve(ws_id, "documents/paused.md")).version_id);
    device.pause = .none;
    _ = try volume.saveToVolume(store, directory);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyVersionIds().len);
    _ = try reopened_volume.loadFromImage(durable, reopened_store, reopened_directory);
    try std.testing.expectEqual(newer.version_id, reopened_store.latestVersion(0xB900).?.id);
    try std.testing.expectEqual(newer.version_id, (try reopened_directory.resolve(ws_id, "documents/paused.md")).version_id);
}

test "storage suspended checkpoint preserves mutations after serialization" {
    try expectSuspendedCheckpointMutation(.write, false, false);
    try expectSuspendedCheckpointMutation(.flush, false, false);
    try expectSuspendedCheckpointMutation(.write, true, false);
    try expectSuspendedCheckpointMutation(.flush, true, false);
    try expectSuspendedCheckpointMutation(.flush, true, true);
}

test "storage suspended device callbacks reject scratch reuse and attachment mutation" {
    for ([_]SuspendedVolumeDevice.Phase{ .read, .write, .flush }) |phase| {
        var fixture = try SuspendedVolumeFixture.init();
        defer fixture.deinit();
        var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable, .pause = phase, .reenter_spare = fixture.spare };
        SuspendedVolumeDevice.current = &device;
        try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
        _ = try fixture.version("owned scratch");
        var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = fixture.directory };
        device.reenter = &job;
        var stack: [128 * 1024]u8 align(16) = undefined;
        var worker = cooperative.Worker{ .stack = &stack };
        try worker.start(&job, SuspendedVolumeJob.run);
        try worker.step();
        try std.testing.expect(device.reentry_ok and device.paused and worker.state == .suspended);
        try std.testing.expect(busyCallsRejected(&job, fixture.spare));
        try worker.step();
        try std.testing.expect(job.failure == null and worker.state == .complete);
        try std.testing.expect(!fixture.volume.attachmentBusy());
        try std.testing.expect(fixture.spare.adoptAttachedBackendFrom(fixture.volume));
        try std.testing.expect(fixture.spare.clearAttachedBackend());
    }
}

test "storage suspended load rejects foreign mutation before live replay" {
    // The third read is the payload after both root sectors were examined.
    for ([_]usize{ 1, 3 }) |pause_on| {
        var fixture = try SuspendedVolumeFixture.init();
        defer fixture.deinit();
        var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable };
        SuspendedVolumeDevice.current = &device;
        try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
        _ = try fixture.version("disk");
        _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
        device.pause = .read;
        device.pause_on = pause_on;
        var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = fixture.directory, .load = true };
        var stack: [128 * 1024]u8 align(16) = undefined;
        var worker = cooperative.Worker{ .stack = &stack };
        try worker.start(&job, SuspendedVolumeJob.run);
        try worker.step();
        try std.testing.expect(device.paused);
        const newer = try fixture.version("must remain in RAM");
        try worker.step();
        try std.testing.expect(!job.loaded and worker.state == .complete);
        try std.testing.expectEqual(newer.version_id, fixture.store.latestVersion(0xB900).?.id);
        try std.testing.expectEqual(newer.version_id, (try fixture.directory.resolve(fixture.workspace_id, "documents/paused.md")).version_id);
        try std.testing.expect(fixture.store.dirtyVersionIds().len != 0 and fixture.directory.dirtyWorkspaceIds().len != 0);
        try std.testing.expect(!fixture.volume.operationBusy());
    }
}

test "storage suspended barriers and cancellation preserve immutable retry state" {
    for ([_]bool{ false, true }) |cancel| {
        for ([_]usize{ 1, 2 }) |pause_on| {
            var fixture = try SuspendedVolumeFixture.init();
            defer fixture.deinit();
            var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable };
            SuspendedVolumeDevice.current = &device;
            try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
            _ = try fixture.version("disk");
            _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
            const candidate = try fixture.version("candidate");
            device.pause = .flush;
            device.pause_on = pause_on;
            var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = fixture.directory };
            var stack: [128 * 1024]u8 align(16) = undefined;
            var worker = cooperative.Worker{ .stack = &stack };
            try worker.start(&job, SuspendedVolumeJob.run);
            try worker.step();
            try std.testing.expect(device.paused);
            if (cancel) worker.cancel() else device.fail_flush = true;
            try worker.step();
            try std.testing.expectEqual(error.DurabilityBarrierFailed, job.failure.?);
            try std.testing.expect(!fixture.volume.operationBusy());
            try std.testing.expectEqual(@as(usize, 2), fixture.store.versionCount());
            try std.testing.expect(fixture.store.dirtyVersionIds().len != 0 and fixture.directory.dirtyWorkspaceIds().len != 0);
            try std.testing.expectEqual(@as(u64, 1), (try volume_root_slot.findLatestImageRoot(fixture.durable)).?.root.generation);
            device.pause = .none;
            device.fail_flush = false;
            _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
            try std.testing.expectEqual(@as(usize, 2), fixture.store.versionCount());
            try std.testing.expectEqual(@as(usize, 0), fixture.store.dirtyVersionIds().len);
            _ = try fixture.spare.loadFromImage(fixture.durable, fixture.store, fixture.directory);
            try std.testing.expectEqual(candidate.version_id, fixture.store.latestVersion(0xB900).?.id);
        }
    }
}

test "storage suspended load cancellation retains live dirty records" {
    var fixture = try SuspendedVolumeFixture.init();
    defer fixture.deinit();
    var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable };
    SuspendedVolumeDevice.current = &device;
    try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
    _ = try fixture.version("disk");
    _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
    const live = try fixture.version("live");
    device.pause = .read;
    device.pause_on = 3;
    var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = fixture.directory, .load = true };
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    try worker.start(&job, SuspendedVolumeJob.run);
    try worker.step();
    try std.testing.expect(device.paused);
    worker.cancel();
    try worker.step();
    try std.testing.expect(!job.loaded and device.cancelled and worker.state == .complete);
    try std.testing.expectEqual(live.version_id, fixture.store.latestVersion(0xB900).?.id);
    try std.testing.expect(fixture.store.dirtyVersionIds().len != 0 and fixture.directory.dirtyWorkspaceIds().len != 0);
}

test "storage suspended clear owns callbacks and reports failed durability" {
    var fixture = try SuspendedVolumeFixture.init();
    defer fixture.deinit();
    var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable };
    SuspendedVolumeDevice.current = &device;
    try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
    _ = try fixture.version("disk");
    _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
    device.pause = .write;
    var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = fixture.directory, .clear = true };
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    try worker.start(&job, SuspendedVolumeJob.run);
    try worker.step();
    try std.testing.expect(device.paused and busyCallsRejected(&job, fixture.spare));
    device.fail_flush = true;
    try worker.step();
    try std.testing.expect(!job.cleared and !fixture.volume.operationBusy());
    try std.testing.expect((try volume_root_slot.findLatestImageRoot(fixture.durable)) != null);
    device.pause = .none;
    device.fail_flush = false;
    try std.testing.expect(fixture.volume.clearAttachedVolume());
    try std.testing.expect((try volume_root_slot.findLatestImageRoot(fixture.durable)) == null);
    try std.testing.expect(fixture.volume.clearAttachedBackend());
    try std.testing.expect(fixture.volume.clearAttachedVolume());
}

test "storage checkpoint revision saturation cannot acknowledge newer state" {
    var fixture = try SuspendedVolumeFixture.init();
    defer fixture.deinit();
    const before_reset = fixture.store.dirtyRevision();
    fixture.store.reset();
    try std.testing.expect(!fixture.store.dirtyRevisionIsCurrent(before_reset));
    fixture.store.dirty_revision = std.math.maxInt(u64) - 1;
    fixture.directory.dirty_revision = std.math.maxInt(u64) - 1;
    _ = try fixture.version("saturated");
    try std.testing.expect(fixture.store.dirtyRevision() == null and fixture.directory.dirtyRevision() == null);
    _ = try fixture.volume.saveToImage(fixture.visible, fixture.store, fixture.directory);
    try std.testing.expect(fixture.store.dirtyVersionIds().len != 0 and fixture.directory.dirtyWorkspaceIds().len != 0);
    try std.testing.expect(!fixture.store.dirtyRevisionIsCurrent(null) and !fixture.directory.dirtyRevisionIsCurrent(null));
    var root = (try volume_root_slot.findLatestImageRoot(fixture.visible)).?;
    root.root.generation = std.math.maxInt(u64);
    try volume_root_slot.writeImageRoot(fixture.visible, root.sector_index, root.root);
    try std.testing.expectError(error.VolumeGenerationExhausted, fixture.volume.saveToImage(fixture.visible, fixture.store, fixture.directory));
    try std.testing.expect(!fixture.volume.operationBusy());
}

test "storage suspended no-op checkpoint keeps changed workspace sharing dirty" {
    var fixture = try SuspendedVolumeFixture.init();
    defer fixture.deinit();
    var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable };
    SuspendedVolumeDevice.current = &device;
    try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
    _ = try fixture.version("disk");
    const recipient = principal.PrincipalId{ .kind = .app, .serial = 2 };
    try fixture.directory.share(fixture.workspace_id, .{ .principal_id = recipient, .expires_at_ticks = 100 });
    _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
    // Equal sharing state has no new log record but still needs its barrier.
    try fixture.directory.share(fixture.workspace_id, .{ .principal_id = recipient, .expires_at_ticks = 100 });
    device.pause = .flush;
    var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = fixture.directory };
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    try worker.start(&job, SuspendedVolumeJob.run);
    try worker.step();
    try std.testing.expect(device.paused);
    try fixture.directory.share(fixture.workspace_id, .{ .principal_id = recipient, .expires_at_ticks = 200 });
    try worker.step();
    try std.testing.expectEqual(@as(u64, 1), job.result.?.generation);
    try std.testing.expect(fixture.directory.dirtyWorkspaceIds().len != 0);
    try std.testing.expect(!job.result.?.snapshot_current);
    var reopened = try SuspendedVolumeFixture.init();
    defer reopened.deinit();
    _ = try fixture.spare.loadFromImage(fixture.durable, reopened.store, reopened.directory);
    try std.testing.expectEqual(@as(u64, 100), reopened.directory.findConst(fixture.workspace_id).?.findShareGrant(recipient).?.expires_at_ticks);
    device.pause = .none;
    const next = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
    try std.testing.expect(next.snapshot_current);
    _ = try fixture.spare.loadFromImage(fixture.durable, reopened.store, reopened.directory);
    try std.testing.expectEqual(@as(u64, 200), reopened.directory.findConst(fixture.workspace_id).?.findShareGrant(recipient).?.expires_at_ticks);
}

test "storage suspended checkpoint receipt detects raw reset and dirty acknowledgment" {
    for ([_]bool{ false, true }) |reset| {
        var fixture = try SuspendedVolumeFixture.init();
        defer fixture.deinit();
        var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable, .pause = .write };
        SuspendedVolumeDevice.current = &device;
        try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
        const captured = try fixture.version("captured");
        var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = fixture.directory };
        var stack: [128 * 1024]u8 align(16) = undefined;
        var worker = cooperative.Worker{ .stack = &stack };
        try worker.start(&job, SuspendedVolumeJob.run);
        try worker.step();
        try std.testing.expect(device.paused);
        if (reset) {
            fixture.store.reset();
            fixture.directory.reset();
        } else {
            fixture.store.clearDirty();
            fixture.directory.clearDirty();
        }
        try worker.step();
        try std.testing.expect(job.failure == null and !job.result.?.snapshot_current);
        try std.testing.expectEqual(@as(usize, 0), fixture.store.dirtyVersionIds().len);
        try std.testing.expectEqual(@as(usize, 0), fixture.directory.dirtyWorkspaceIds().len);
        var reopened = try SuspendedVolumeFixture.init();
        defer reopened.deinit();
        _ = try fixture.spare.loadFromImage(fixture.durable, reopened.store, reopened.directory);
        try std.testing.expectEqual(captured.version_id, reopened.store.latestVersion(0xB900).?.id);
        device.pause = .none;
        const next = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
        try std.testing.expect(next.snapshot_current);
        _ = try fixture.spare.loadFromImage(fixture.durable, reopened.store, reopened.directory);
        if (reset) {
            try std.testing.expectEqual(@as(usize, 0), reopened.store.objectCount());
            try std.testing.expectEqual(@as(usize, 0), reopened.directory.workspaceCount());
        } else {
            try std.testing.expectEqual(captured.version_id, reopened.store.latestVersion(0xB900).?.id);
        }
    }
}

fn corruptLatestDelta(image: []u8, semantic: bool) !void {
    const loaded = (try volume_root_slot.findLatestImageRoot(image)).?;
    try std.testing.expect(loaded.root.log_bytes < storage_volume.sector_size);
    const start = volume_layout.data_start_byte + loaded.root.data_offset;
    const log = image[start..][0..loaded.root.log_bytes];
    if (!semantic) {
        log[log.len - 1] ^= 0x80;
        return;
    }
    var offset: usize = 0;
    while (offset < log.len) {
        const payload_len = std.mem.readInt(u32, log[offset + 1 ..][0..4], .little);
        if (log[offset] == @backingInt(volume_log.RecordKind.object_state)) {
            const payload = log[offset + volume_log.recordHeaderLen() ..][0..payload_len];
            // Valid framing/checksum, invalid logical ObjectType after the
            // preceding checkpoint has already reconstructed live records.
            payload[8] = 0xff;
            std.mem.writeInt(u64, log[offset + volume_layout.log_record_checksum_offset ..][0..8], volume_hashing.checksumBytes(payload), .little);
            return;
        }
        offset += volume_log.recordHeaderLen() + payload_len;
    }
    return error.MissingDeltaObject;
}

fn expectCorruptCandidateBoundary(semantic: bool) !void {
    var fixture = try SuspendedVolumeFixture.init();
    defer fixture.deinit();
    var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable };
    SuspendedVolumeDevice.current = &device;
    try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
    const first = try fixture.version("disk first");
    _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
    if (semantic) {
        try std.testing.expect(fixture.volume.loadFromVolume(fixture.store, fixture.directory));
        var bytes: [64]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "disk first", try fixture.store.versionPayloadInto(fixture.store.latestVersion(0xB900).?, &bytes));
    }
    _ = try fixture.version("disk second");
    _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
    const live = try fixture.version("RAM live");
    try corruptLatestDelta(fixture.visible, semantic);
    device.pause = .read;
    device.pause_on = 4;
    var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = fixture.directory, .load = true };
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    try worker.start(&job, SuspendedVolumeJob.run);
    defer if (worker.state == .suspended) {
        worker.cancel();
        worker.step() catch @panic("test failed to drain corrupt candidate");
    };
    try worker.step();
    if (semantic) {
        try std.testing.expect(!device.paused and worker.state == .complete and !job.loaded);
        try std.testing.expectEqual(@as(usize, 0), fixture.store.objectCount());
        try std.testing.expectEqual(@as(usize, 0), fixture.directory.workspaceCount());
        // A later load must reconstruct disk payload after RAM repopulation.
        fixture.workspace_id = (try fixture.directory.create(.{ .owner = .{ .kind = .user, .serial = 1 }, .label = "paused" })).id;
        _ = try fixture.version("RAM recreated");
        const bad = (try volume_root_slot.findLatestImageRoot(fixture.visible)).?;
        const bad_offset = @as(usize, bad.sector_index) * storage_volume.sector_size;
        @memset(fixture.visible[bad_offset..][0..storage_volume.sector_size], 0);
        device.pause = .none;
        try std.testing.expect(fixture.volume.loadFromVolume(fixture.store, fixture.directory));
        var bytes: [64]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "disk first", try fixture.store.versionPayloadInto(fixture.store.latestVersion(0xB900).?, &bytes));
    } else {
        try std.testing.expect(device.paused and worker.state == .suspended);
        try std.testing.expectEqual(live.version_id, fixture.store.latestVersion(0xB900).?.id);
        try std.testing.expectEqual(live.version_id, (try fixture.directory.resolve(fixture.workspace_id, "documents/paused.md")).version_id);
        try worker.step();
        try std.testing.expect(job.loaded and worker.state == .complete);
        try std.testing.expectEqual(first.version_id, fixture.store.latestVersion(0xB900).?.id);
    }
    try std.testing.expect(!fixture.volume.operationBusy());
}

test "storage corrupt candidate fallback retains live state before yielding read" {
    try expectCorruptCandidateBoundary(false);
}

test "storage corrupt candidate logical replay failure never yields partial state" {
    try expectCorruptCandidateBoundary(true);
}

test "storage same root reload restores disk payload into changed or alternate RAM" {
    const Change = enum { version, reset, alternate };
    for ([_]bool{ false, true }) |from_image| {
        for ([_]Change{ .version, .reset, .alternate }) |change| {
            var fixture = try SuspendedVolumeFixture.init();
            defer fixture.deinit();
            var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable };
            SuspendedVolumeDevice.current = &device;
            try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
            const disk = try fixture.version("same root disk payload");
            _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
            if (from_image) {
                _ = try fixture.volume.loadFromImage(fixture.durable, fixture.store, fixture.directory);
            } else {
                try std.testing.expect(fixture.volume.loadFromVolume(fixture.store, fixture.directory));
            }

            var alternate = try SuspendedVolumeFixture.init();
            defer alternate.deinit();
            const store = if (change == .alternate) alternate.store else fixture.store;
            const directory = if (change == .alternate) alternate.directory else fixture.directory;
            var workspace_id = if (change == .alternate) alternate.workspace_id else fixture.workspace_id;
            if (change == .reset) {
                store.reset();
                directory.reset();
                workspace_id = (try directory.create(.{ .owner = .{ .kind = .user, .serial = 1 }, .label = "paused" })).id;
            }
            _ = try putSuspendedVersion(store, directory, workspace_id, "RAM must be replaced");
            if (from_image) {
                _ = try fixture.volume.loadFromImage(fixture.durable, store, directory);
            } else {
                try std.testing.expect(fixture.volume.loadFromVolume(store, directory));
            }
            var bytes: [64]u8 = undefined;
            try std.testing.expectEqualSlices(u8, "same root disk payload", try store.versionPayloadInto(store.latestVersion(0xB900).?, &bytes));
            try std.testing.expectEqual(disk.version_id, (try directory.resolve(fixture.workspace_id, "documents/paused.md")).version_id);
            try std.testing.expectEqual(@as(usize, 1), store.versionCount());
            try std.testing.expectEqual(@as(usize, 0), store.dirtyVersionIds().len);
            try std.testing.expectEqual(@as(usize, 0), directory.dirtyWorkspaceIds().len);
        }
    }
}

test "storage suspended load retains successful transient workspace mutations" {
    const Mutation = enum { begin, put_new, put_replace, put_resurrect, delete_base, delete_staged, abort };
    for ([_]usize{ 1, 3 }) |pause_on| {
        for ([_]Mutation{ .begin, .put_new, .put_replace, .put_resurrect, .delete_base, .delete_staged, .abort }) |mutation| {
            var fixture = try SuspendedVolumeFixture.init();
            defer fixture.deinit();
            var device = SuspendedVolumeDevice{ .visible = fixture.visible, .durable = fixture.durable };
            SuspendedVolumeDevice.current = &device;
            try std.testing.expect(fixture.volume.attachBackend(SuspendedVolumeDevice.backend()));
            const disk = try fixture.version("disk survives staging");
            _ = try fixture.volume.saveToVolume(fixture.store, fixture.directory);
            const directory = fixture.directory;
            const workspace_id = fixture.workspace_id;
            if (mutation != .begin) try directory.beginTransaction(workspace_id);
            switch (mutation) {
                .put_replace, .delete_staged, .abort => try directory.stagePut(workspace_id, "transient.md", disk.object_id, disk.version_id, .document),
                .put_resurrect => try directory.stageDelete(workspace_id, "documents/paused.md"),
                else => {},
            }
            const before = directory.dirtyRevision();
            device.pause = .read;
            device.pause_on = pause_on;
            var job = SuspendedVolumeJob{ .volume = fixture.volume, .store = fixture.store, .workspaces = directory, .load = true };
            var stack: [128 * 1024]u8 align(16) = undefined;
            var worker = cooperative.Worker{ .stack = &stack };
            try worker.start(&job, SuspendedVolumeJob.run);
            defer if (worker.state == .suspended) {
                worker.cancel();
                worker.step() catch @panic("test failed to drain transaction load");
            };
            try worker.step();
            try std.testing.expect(device.paused and worker.state == .suspended);
            switch (mutation) {
                .begin => try directory.beginTransaction(workspace_id),
                .put_new, .put_replace => try directory.stagePut(workspace_id, "transient.md", disk.object_id, disk.version_id, .document),
                .put_resurrect => try directory.stagePut(workspace_id, "documents/paused.md", disk.object_id, disk.version_id, .document),
                .delete_base => try directory.stageDelete(workspace_id, "documents/paused.md"),
                .delete_staged => try directory.stageDelete(workspace_id, "transient.md"),
                .abort => try directory.abortTransaction(workspace_id),
            }
            try worker.step();
            try std.testing.expect(worker.state == .complete and !job.loaded);
            try std.testing.expect(!directory.dirtyRevisionIsCurrent(before));
            const resident = directory.find(workspace_id).?;
            try std.testing.expectEqual(mutation != .abort, resident.staging.transaction_open);
            const expected_count: usize = switch (mutation) {
                .begin, .delete_staged, .abort => 0,
                else => 1,
            };
            try std.testing.expectEqual(expected_count, resident.staging.staged_entry_count);
            try std.testing.expectEqual(disk.version_id, (try directory.resolve(workspace_id, "documents/paused.md")).version_id);
            try std.testing.expectEqual(@as(usize, 0), directory.dirtyWorkspaceIds().len);
            try std.testing.expectEqual(@as(usize, 0), fixture.store.dirtyVersionIds().len);
        }
    }
}

test "storage rejected workspace staging leaves revision and dirty IDs unchanged" {
    var fixture = try SuspendedVolumeFixture.init();
    defer fixture.deinit();
    const disk = try fixture.version("clean staging");
    fixture.directory.clearDirty();
    const directory = fixture.directory;
    const workspace_id = fixture.workspace_id;
    var before = directory.dirtyRevision();
    try std.testing.expectError(error.NoActiveTransaction, directory.abortTransaction(workspace_id));
    try std.testing.expectError(error.NoActiveTransaction, directory.stagePut(workspace_id, "transient.md", disk.object_id, disk.version_id, .document));
    try std.testing.expect(directory.dirtyRevisionIsCurrent(before));
    try directory.beginTransaction(workspace_id);
    before = directory.dirtyRevision();
    try std.testing.expectError(error.TransactionAlreadyOpen, directory.beginTransaction(workspace_id));
    try std.testing.expectError(error.InvalidEntry, directory.stagePut(workspace_id, "transient.md", ids.object(0), disk.version_id, .document));
    try std.testing.expectError(error.EntryNotFound, directory.stageDelete(workspace_id, "missing.md"));
    try std.testing.expect(directory.dirtyRevisionIsCurrent(before));
    try directory.stageDelete(workspace_id, "documents/paused.md");
    before = directory.dirtyRevision();
    try std.testing.expectError(error.EntryNotFound, directory.stageDelete(workspace_id, "documents/paused.md"));
    try std.testing.expect(directory.dirtyRevisionIsCurrent(before));
    try std.testing.expectEqual(@as(usize, 0), directory.dirtyWorkspaceIds().len);
    try std.testing.expectEqual(@as(usize, 0), directory.dirtySnapshotIds().len);
}

const WriteBackBackend = struct {
    const Event = enum(u8) {
        data_write,
        root_write,
        flush,
    };

    const max_events = 32;

    var visible: []u8 = &.{};
    var durable: []u8 = &.{};
    var events: [max_events]Event = undefined;
    var event_count: usize = 0;
    var flush_count: usize = 0;
    var fail_on_flush: usize = 0;
    var written_bytes: usize = 0;

    fn attach(volume: *Volume, visible_image: []u8, durable_image: []u8) void {
        visible = visible_image;
        durable = durable_image;
        @memset(visible, 0);
        @memset(durable, 0);
        beginAttempt(0);
        _ = volume.attachBackend(.{
            .sector_count = storage_volume.required_device_sectors,
            .read = read,
            .write = write,
            .flush = flush,
        });
    }

    fn beginAttempt(failing_flush: usize) void {
        event_count = 0;
        flush_count = 0;
        fail_on_flush = failing_flush;
        written_bytes = 0;
    }

    fn powerLoss() void {
        @memcpy(visible, durable);
    }

    fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
        const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
        const end = start + buffer_len;
        if (end > visible.len) return false;
        @memcpy(buffer_ptr[0..buffer_len], visible[start..end]);
        return true;
    }

    fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
        const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
        const end = start + buffer_len;
        if (end > visible.len) return false;
        record(if (start_lba < storage_volume.header_sectors) .root_write else .data_write);
        written_bytes += buffer_len;
        @memcpy(visible[start..end], buffer_ptr[0..buffer_len]);
        return true;
    }

    fn flush() callconv(.c) bool {
        record(.flush);
        flush_count += 1;
        if (fail_on_flush != 0 and flush_count == fail_on_flush) return false;
        @memcpy(durable, visible);
        return true;
    }

    fn record(event: Event) void {
        if (event_count >= events.len) return;
        events[event_count] = event;
        event_count += 1;
    }

    fn firstFlushIndex() ?usize {
        for (events[0..event_count], 0..) |event, index| {
            if (event == .flush) return index;
        }
        return null;
    }
};

fn putBarrierTestVersion(store: *object_store.Store, workspaces: *workspace.Directory, serial: u64) !void {
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-barrier",
        .seed = signing.seedFromByte(0x6B),
    };
    const result = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(serial),
        .object_type = .document,
        .payload = "explicit durability barrier",
        .metadata = try object_store.signMetadata(signer, "barrier", "text/plain", .document, "explicit durability barrier", 1),
    });
    const record = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = serial },
        .label = "barrier-workspace",
    });
    try workspaces.beginTransaction(record.id);
    try workspaces.stagePut(record.id, "documents/barrier.md", result.object_id, result.version_id, .document);
    _ = try workspaces.commit(record.id, 2);
}

fn expectOrderedBarrierTrace() !void {
    const first_flush = WriteBackBackend.firstFlushIndex() orelse return error.MissingDurabilityBarrier;
    try std.testing.expect(first_flush > 0);
    for (WriteBackBackend.events[0..first_flush]) |event| {
        try std.testing.expectEqual(WriteBackBackend.Event.data_write, event);
    }
    try std.testing.expectEqual(first_flush + 3, WriteBackBackend.event_count);
    try std.testing.expectEqual(WriteBackBackend.Event.root_write, WriteBackBackend.events[first_flush + 1]);
    try std.testing.expectEqual(WriteBackBackend.Event.flush, WriteBackBackend.events[first_flush + 2]);
}

fn expectBarrierFailurePreservesDirtyState(failing_flush: usize, object_serial: u64) !void {
    const allocator = std.testing.allocator;
    const visible = try allocator.alloc(u8, image_bytes);
    defer allocator.free(visible);
    const durable = try allocator.alloc(u8, image_bytes);
    defer allocator.free(durable);
    const volume = try allocator.create(Volume);
    volume.* = Volume.init();
    defer allocator.destroy(volume);
    _ = volume.reset();
    WriteBackBackend.attach(volume, visible, durable);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    try putBarrierTestVersion(&store, &workspaces, object_serial);
    WriteBackBackend.beginAttempt(failing_flush);

    try std.testing.expectError(error.DurabilityBarrierFailed, volume.saveToVolume(&store, &workspaces));
    try std.testing.expectEqual(@as(usize, 1), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 1), workspaces.dirtyWorkspaceIds().len);
    try std.testing.expectEqual(failing_flush, WriteBackBackend.flush_count);
    try std.testing.expect(std.mem.allEqual(
        u8,
        durable[0 .. storage_volume.header_sectors * storage_volume.sector_size],
        0,
    ));

    WriteBackBackend.beginAttempt(0);
    const retried = try volume.saveToVolume(&store, &workspaces);
    try std.testing.expectEqual(@as(u64, if (failing_flush == 2) 2 else 1), retried.generation);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 0), workspaces.dirtyWorkspaceIds().len);

    WriteBackBackend.powerLoss();
    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expect(volume.loadFromVolume(&loaded_store, &loaded_workspaces));
    try std.testing.expect(loaded_store.latestVersion(object_serial) != null);
}

test "storage backend commits log and root through ordered durability barriers" {
    const allocator = std.testing.allocator;
    const visible = try allocator.alloc(u8, image_bytes);
    defer allocator.free(visible);
    const durable = try allocator.alloc(u8, image_bytes);
    defer allocator.free(durable);
    const volume = try allocator.create(Volume);
    volume.* = Volume.init();
    defer allocator.destroy(volume);
    _ = volume.reset();
    WriteBackBackend.attach(volume, visible, durable);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    try putBarrierTestVersion(&store, &workspaces, 0xB401);
    const persisted = try volume.saveToVolume(&store, &workspaces);

    try std.testing.expectEqual(@as(u64, 1), persisted.generation);
    try std.testing.expectEqual(@as(usize, 2), WriteBackBackend.flush_count);
    try expectOrderedBarrierTrace();
    try std.testing.expectEqualSlices(u8, durable, visible);

    WriteBackBackend.powerLoss();
    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expect(volume.loadFromVolume(&loaded_store, &loaded_workspaces));
    try std.testing.expect(loaded_store.latestVersion(0xB401) != null);
}

test "storage backend barrier failures preserve dirty state and withhold the new root" {
    try expectBarrierFailurePreservesDirtyState(1, 0xB402);
    try expectBarrierFailurePreservesDirtyState(2, 0xB403);
}

const LogRecordStats = struct {
    counts: [9]usize = @as([9]usize, @splat(0)),
    bytes: [9]usize = @as([9]usize, @splat(0)),
};

fn latestLogRecordStats(image: []const u8) !LogRecordStats {
    const root = (try volume_root_slot.findLatestImageRoot(image)).?.root;
    const start = volume_layout.data_start_byte + root.data_offset;
    const log = image[start .. start + root.log_bytes];
    var stats = LogRecordStats{};
    var offset: usize = 0;
    while (offset < log.len) {
        const kind = log[offset];
        if (kind >= stats.counts.len) return error.CorruptImage;
        const payload_length = std.mem.readInt(u32, log[offset + 1 ..][0..4], .little);
        const record_length = volume_log.recordHeaderLen() + payload_length;
        if (record_length > log.len - offset) return error.CorruptImage;
        stats.counts[kind] += 1;
        stats.bytes[kind] += record_length;
        offset += record_length;
    }
    return stats;
}

test "storage deltas persist shared chunks once across committed versions and dirty batches" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    volume.* = Volume.init();
    defer allocator.destroy(volume);
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{ .label = "dedup", .seed = signing.seedFromByte(0x6D) };

    var payload: [object_store.MAX_CHUNK_BYTES * 3]u8 = undefined;
    for (0..3) |index| @memset(payload[index * object_store.MAX_CHUNK_BYTES ..][0..object_store.MAX_CHUNK_BYTES], @intCast(index + 1));
    const first = try store.putVersion(.{
        .object_type = .media_asset,
        .payload = &payload,
        .metadata = try object_store.signMetadata(signer, "asset", "application/octet-stream", .media_asset, &payload, 1),
    });
    _ = try volume.saveToImage(image, &store, &workspaces);

    for (2..4) |tick| {
        _ = try store.putVersion(.{
            .preferred_object_id = first.object_id,
            .object_type = .media_asset,
            .payload = &payload,
            .metadata = try object_store.signMetadata(signer, "asset", "application/octet-stream", .media_asset, &payload, tick),
        });
    }
    const checkpoint_bytes = try storage_volume.testing.latestImageLogBytes(image);
    _ = try volume.saveToImage(image, &store, &workspaces);
    const shared = try latestLogRecordStats(image);
    try std.testing.expectEqual(@as(usize, 0), shared.counts[@backingInt(volume_log.RecordKind.chunk_state)]);
    try std.testing.expectEqual(@as(usize, 1), shared.counts[@backingInt(volume_log.RecordKind.blob_state)]);
    try std.testing.expectEqual(@as(u16, 6), try storage_volume.testing.latestImageLogRecordCount(image));
    // Two revisions of 12 KiB content require less than one KiB of new metadata.
    try std.testing.expect((try storage_volume.testing.latestImageLogBytes(image)) - checkpoint_bytes < 1024);

    // A cold replay reconstructs the committed set without a process-local cache.
    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = volume.reset();
    _ = try volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    payload[object_store.MAX_CHUNK_BYTES + 17] = 9;
    const edited = try loaded_store.putVersion(.{
        .preferred_object_id = first.object_id,
        .object_type = .media_asset,
        .payload = &payload,
        .metadata = try object_store.signMetadata(signer, "asset", "application/octet-stream", .media_asset, &payload, 4),
    });
    _ = try volume.saveToImage(image, &loaded_store, &loaded_workspaces);
    const changed = try latestLogRecordStats(image);
    try std.testing.expectEqual(@as(usize, 1), changed.counts[@backingInt(volume_log.RecordKind.chunk_state)]);
    try std.testing.expectEqual(
        volume_log.recordHeaderLen() + @sizeOf(object_store.ChunkAddress) + @sizeOf(u16) + object_store.MAX_CHUNK_BYTES,
        changed.bytes[@backingInt(volume_log.RecordKind.chunk_state)],
    );
    try std.testing.expectEqual(@as(u16, 11), try storage_volume.testing.latestImageLogRecordCount(image));
    _ = volume.reset();
    store.reset();
    _ = try volume.loadFromImage(image, &store, &workspaces);
    var output: [payload.len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &payload, try store.versionPayloadInto(store.version(edited.version_id).?, &output));
    try std.testing.expectEqual(@as(u16, 3), store.versionBlob(store.version(first.version_id).?).?.refCount());
}

test "storage delta chunk reuse survives failed barriers retries and power loss" {
    for (1..3) |failing_flush| {
        const allocator = std.testing.allocator;
        const visible = try allocator.alloc(u8, image_bytes);
        defer allocator.free(visible);
        const durable = try allocator.alloc(u8, image_bytes);
        defer allocator.free(durable);
        const volume = try allocator.create(Volume);
        volume.* = Volume.init();
        defer allocator.destroy(volume);
        volume.* = Volume.init();
        WriteBackBackend.attach(volume, visible, durable);
        var store = object_store.Store.init();
        var workspaces = workspace.Directory.init();
        const signer = signing.SignerIdentity{ .label = "retry-dedup", .seed = signing.seedFromByte(0x6E) };
        var payload: [object_store.MAX_CHUNK_BYTES * 3]u8 = undefined;
        for (0..3) |index| @memset(payload[index * object_store.MAX_CHUNK_BYTES ..][0..object_store.MAX_CHUNK_BYTES], @intCast(index + 1));
        const first = try store.putVersion(.{
            .object_type = .media_asset,
            .payload = &payload,
            .metadata = try object_store.signMetadata(signer, "asset", "application/octet-stream", .media_asset, &payload, 1),
        });
        _ = try volume.saveToVolume(&store, &workspaces);
        payload[object_store.MAX_CHUNK_BYTES + 17] = 9;
        const edited = try store.putVersion(.{
            .preferred_object_id = first.object_id,
            .object_type = .media_asset,
            .payload = &payload,
            .metadata = try object_store.signMetadata(signer, "asset", "application/octet-stream", .media_asset, &payload, 2),
        });
        WriteBackBackend.beginAttempt(failing_flush);
        try std.testing.expectError(error.DurabilityBarrierFailed, volume.saveToVolume(&store, &workspaces));
        try std.testing.expectEqual(@as(usize, 1), store.dirtyVersionIds().len);
        WriteBackBackend.powerLoss();
        const reboot = try allocator.create(Volume);
        reboot.* = Volume.init();
        defer allocator.destroy(reboot);
        reboot.* = Volume.init();
        var reboot_store = object_store.Store.init();
        var reboot_workspaces = workspace.Directory.init();
        _ = try reboot.loadFromImage(durable, &reboot_store, &reboot_workspaces);
        try std.testing.expectEqual(first.version_id, reboot_store.latestVersion(first.object_id).?.id);

        WriteBackBackend.beginAttempt(0);
        _ = try volume.saveToVolume(&store, &workspaces);
        // One changed page plus metadata touches two data blocks and one root.
        try std.testing.expectEqual(@as(usize, 3 * storage_volume.sector_size), WriteBackBackend.written_bytes);
        const stats = try latestLogRecordStats(durable);
        try std.testing.expectEqual(@as(usize, 1), stats.counts[@backingInt(volume_log.RecordKind.chunk_state)]);
        WriteBackBackend.powerLoss();
        _ = reboot.reset();
        reboot_store.reset();
        _ = try reboot.loadFromImage(durable, &reboot_store, &reboot_workspaces);
        var output: [payload.len]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &payload, try reboot_store.versionPayloadInto(reboot_store.version(edited.version_id).?, &output));
    }
}

test "storage delta deduplicates new shared chunks between distinct blobs in one batch" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    volume.* = Volume.init();
    defer allocator.destroy(volume);
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    _ = try volume.saveToImage(image, &store, &workspaces);
    const signer = signing.SignerIdentity{ .label = "batch-dedup", .seed = signing.seedFromByte(0x6F) };
    var payload: [object_store.MAX_CHUNK_BYTES * 2]u8 = undefined;
    @memset(payload[0..object_store.MAX_CHUNK_BYTES], 1);
    @memset(payload[object_store.MAX_CHUNK_BYTES..], 2);
    const first = try store.putVersion(.{
        .object_type = .media_asset,
        .payload = &payload,
        .metadata = try object_store.signMetadata(signer, "first", "application/octet-stream", .media_asset, &payload, 1),
    });
    @memset(payload[object_store.MAX_CHUNK_BYTES..], 3);
    const second = try store.putVersion(.{
        .object_type = .media_asset,
        .payload = &payload,
        .metadata = try object_store.signMetadata(signer, "other", "application/octet-stream", .media_asset, &payload, 2),
    });
    _ = try volume.saveToImage(image, &store, &workspaces);
    const stats = try latestLogRecordStats(image);
    try std.testing.expectEqual(@as(usize, 3), stats.counts[@backingInt(volume_log.RecordKind.chunk_state)]);
    try std.testing.expectEqual(@as(usize, 2), stats.counts[@backingInt(volume_log.RecordKind.blob_state)]);
    try std.testing.expectEqual(
        @as(usize, 3) * (volume_log.recordHeaderLen() + @sizeOf(object_store.ChunkAddress) + @sizeOf(u16) + object_store.MAX_CHUNK_BYTES),
        stats.bytes[@backingInt(volume_log.RecordKind.chunk_state)],
    );
    try std.testing.expectEqual(@as(u16, 11), try storage_volume.testing.latestImageLogRecordCount(image));
    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = volume.reset();
    _ = try volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    var output: [payload.len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &payload, try loaded_store.versionPayloadInto(loaded_store.version(second.version_id).?, &output));
    @memset(payload[object_store.MAX_CHUNK_BYTES..], 2);
    try std.testing.expectEqualSlices(u8, &payload, try loaded_store.versionPayloadInto(loaded_store.version(first.version_id).?, &output));
}

test "storage volume exposes the first supported product capacity envelope" {
    const envelope = storage_volume.productCapacityEnvelope();

    try std.testing.expectEqual(storage_volume.image_bytes, envelope.volume_image_bytes);
    try std.testing.expectEqual(storage_volume.required_device_sectors, envelope.required_device_sectors);
    try std.testing.expectEqual(object_store.MAX_PAYLOAD_BYTES, envelope.max_object_payload_bytes);
    try std.testing.expectEqual(object_store.MAX_OBJECTS, envelope.max_object_records);
    try std.testing.expectEqual(object_store.MAX_VERSIONS, envelope.max_version_records);
    try std.testing.expectEqual(object_store.MAX_BLOBS, envelope.max_blob_records);
    try std.testing.expectEqual(object_store.MAX_BLOB_CHUNKS, envelope.max_blob_chunks_per_payload);
    try std.testing.expectEqual(object_store.MAX_CHUNKS, envelope.max_chunk_records);
    try std.testing.expectEqual(object_store.MAX_CHUNK_BYTES, envelope.max_chunk_bytes);
    try std.testing.expectEqual(workspace.MAX_WORKSPACES, envelope.max_workspaces);
    try std.testing.expectEqual(workspace.MAX_WORKSPACE_ENTRIES, envelope.max_workspace_entries_per_workspace);
    try std.testing.expectEqual(workspace.MAX_SNAPSHOTS, envelope.max_snapshots);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    try storage_volume.ensureWithinProductCapacityEnvelope(&store, &workspaces);
}

test "single chunk blobs fill their quota and survive a volume round trip" {
    const allocator = std.testing.allocator;
    const store = try allocator.create(object_store.Store);
    defer allocator.destroy(store);
    store.* = object_store.Store.init();
    defer store.reset();
    const workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(workspaces);
    workspaces.* = workspace.Directory.init();
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    var volume = Volume.init();
    defer _ = volume.reset();
    const signer = signing.SignerIdentity{ .label = "chunk-quota", .seed = signing.seedFromByte(0xE3) };
    var payload: [8]u8 = undefined;
    for (0..object_store.MAX_BLOBS) |index| {
        std.mem.writeInt(u64, &payload, index, .little);
        _ = try store.putLocallySignedVersion(.{
            .preferred_object_id = object_store.ids.object(1),
            .object_type = .document,
            .payload = &payload,
            .signer = signer,
            .label = "quota-history",
            .content_type = "text/plain",
            .created_at_ticks = index,
        });
    }
    try std.testing.expectEqual(object_store.MAX_BLOBS, store.blobCount());
    try std.testing.expectEqual(object_store.MAX_BLOBS, store.chunkCount());
    const next_version = store.next_version_id;
    for (0..8) |_| {
        try std.testing.expectError(error.BlobTableFull, store.putLocallySignedVersion(.{
            .object_type = .document,
            .payload = "overflow",
            .signer = signer,
            .label = "overflow",
            .content_type = "text/plain",
            .created_at_ticks = next_version,
        }));
        try std.testing.expectEqual(@as(usize, 1), store.objectCount());
        try std.testing.expectEqual(object_store.MAX_BLOBS, store.versionCount());
        try std.testing.expectEqual(object_store.MAX_BLOBS, store.chunkCount());
        try std.testing.expectEqual(next_version, store.next_version_id);
    }
    _ = try volume.saveToImage(image, store, workspaces);
    store.reset();
    _ = try volume.loadFromImage(image, store, workspaces);
    try std.testing.expectEqual(object_store.MAX_BLOBS, store.chunkCount());
    for (0..object_store.MAX_BLOBS) |index| {
        std.mem.writeInt(u64, &payload, index, .little);
        const version = store.versionConst(index + 1).?;
        try std.testing.expectEqualSlices(u8, &payload, try store.versionPayload(version));
    }
}

test "storage volume preserves exhausted identifier watermarks" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    volume.* = Volume.init();
    defer allocator.destroy(volume);
    _ = volume.reset();

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    store.next_version_id = 0;
    workspaces.next_snapshot_id = 0;
    _ = try volume.saveToImage(image, &store, &workspaces);

    const loaded_root = (try volume_root_slot.findLatestImageRoot(image)).?;
    try std.testing.expectEqual(std.math.maxInt(u64), volume_root_slot.versionWatermark(loaded_root.root));
    try std.testing.expectEqual(std.math.maxInt(u64), volume_root_slot.snapshotWatermark(loaded_root.root));

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(@as(u64, 0), loaded_store.next_version_id);
    try std.testing.expectEqual(@as(u64, 0), loaded_workspaces.next_snapshot_id);
}

test "storage volume compacts instead of trusting ahead delta watermarks" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    volume.* = Volume.init();
    defer allocator.destroy(volume);
    _ = volume.reset();

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-watermark",
        .seed = signing.seedFromByte(0x57),
    };
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(941),
        .object_type = .document,
        .payload = "first",
        .metadata = try object_store.signMetadata(signer, "watermark", "text/plain", .document, "first", 1),
    });
    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 941 },
        .label = "watermark-notes",
    });
    _ = try volume.saveToImage(image, &store, &workspaces);

    var loaded_root = (try volume_root_slot.findLatestImageRoot(image)).?;
    loaded_root.root.next_version_id += 4;
    loaded_root.root.next_snapshot_id += 4;
    try volume_root_slot.writeImageRoot(image, loaded_root.sector_index, loaded_root.root);

    const second = try store.putVersion(.{
        .preferred_object_id = first.object_id,
        .object_type = .document,
        .payload = "second",
        .metadata = try object_store.signMetadata(signer, "watermark", "text/plain", .document, "second", 2),
        .parent_version_id = first.version_id,
    });
    _ = try workspaces.snapshot(notes.id, "after-watermark", signer);

    const saved = try volume.saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 2), saved.generation);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(second.version_id, loaded_store.object(first.object_id).?.latest_version_id);
    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 941 }, "watermark-notes").?;
    try std.testing.expect(loaded_workspaces.findSnapshotByLabel(loaded_notes.id, "after-watermark") != null);
}

test "storage volume rejects replayed identifiers beyond root watermarks" {
    const allocator = std.testing.allocator;
    const image = try allocator.alloc(u8, image_bytes);
    defer allocator.free(image);
    @memset(image, 0);
    const volume = try allocator.create(Volume);
    volume.* = Volume.init();
    defer allocator.destroy(volume);
    _ = volume.reset();

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-root-rewind",
        .seed = signing.seedFromByte(0x51),
    };
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    _ = try store.putVersion(.{
        .object_type = .document,
        .payload = "issued",
        .metadata = try object_store.signMetadata(signer, "root-rewind", "text/plain", .document, "issued", 1),
    });
    _ = try volume.saveToImage(image, &store, &workspaces);

    var root = (try volume_root_slot.findLatestImageRoot(image)).?;
    root.root.next_version_id = 1;
    try volume_root_slot.writeImageRoot(image, root.sector_index, root.root);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, volume.loadFromImage(image, &loaded_store, &loaded_workspaces));
}

test "storage quota policy rejects writes above the first supported envelope" {
    const policy = storage_volume.productQuotaPolicy();

    try std.testing.expectEqual(storage_volume.OverLimitWriteBehavior.reject_without_partial_persistence, policy.over_limit_write_behavior);
    try std.testing.expect(policy.persistence_error == error.NoSpaceLeft);
    try std.testing.expect(policy.retry_requires_freeing_space);
    try std.testing.expectEqual(storage_volume.productCapacityEnvelope().max_object_records, policy.envelope.max_object_records);

    const payload_rejection = storage_volume.quotaRejectionForUsage(.{
        .object_payload_bytes = object_store.MAX_PAYLOAD_BYTES + 1,
    }).?;
    try std.testing.expectEqual(storage_volume.QuotaLimit.object_payload_bytes, payload_rejection.limit);
    try std.testing.expectEqual(object_store.MAX_PAYLOAD_BYTES + 1, payload_rejection.used);
    try std.testing.expectEqual(object_store.MAX_PAYLOAD_BYTES, payload_rejection.allowed);
    try std.testing.expectEqualStrings("storage.quota.object_payload_bytes", payload_rejection.userVisibleCode());

    const object_rejection = storage_volume.quotaRejectionForUsage(.{
        .object_records = object_store.MAX_OBJECTS + 1,
    }).?;
    try std.testing.expectEqual(storage_volume.QuotaLimit.object_records, object_rejection.limit);
    try std.testing.expectEqualStrings("storage.quota.object_records", object_rejection.userVisibleCode());

    const workspace_rejection = storage_volume.quotaRejectionForUsage(.{
        .max_workspace_entries = workspace.MAX_WORKSPACE_ENTRIES + 1,
    }).?;
    try std.testing.expectEqual(storage_volume.QuotaLimit.workspace_entries, workspace_rejection.limit);
    try std.testing.expectEqualStrings("storage.quota.workspace_entries", workspace_rejection.userVisibleCode());

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    try std.testing.expect(storage_volume.quotaRejectionForCurrentState(&store, &workspaces) == null);

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x78),
    };
    const payload = "quota-observed-payload";
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(904),
        .object_type = .document,
        .payload = payload,
        .metadata = try object_store.signMetadata(signer, "quota", "text/plain", .document, payload, 16),
    });
    const usage = storage_volume.productCapacityUsage(&store, &workspaces);
    try std.testing.expectEqual(payload.len, store.maxBlobPayloadBytes());
    try std.testing.expectEqual(payload.len, usage.object_payload_bytes);
    try storage_volume.ensureWithinProductCapacityEnvelope(&store, &workspaces);
}

test "storage volume separates generic and target nvme attachments" {
    try std.testing.expect(!@hasField(Volume, "attached_ata_device"));
    try std.testing.expect(!@hasDecl(Volume, "attachAtaBootstrapDevice"));
    try std.testing.expect(!@hasDecl(storage_volume, "attachAtaBootstrapDevice"));
    try std.testing.expect(std.meta.stringToEnum(storage_volume.AttachedBackendKind, "ata_bootstrap_broker") == null);

    const BackendFns = struct {
        fn read(_: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            @memset(buffer_ptr[0..buffer_len], 0);
            return true;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return true;
        }

        fn flush() callconv(.c) bool {
            return true;
        }
    };

    var volume = Volume.init();
    const backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors,
        .read = BackendFns.read,
        .write = BackendFns.write,
        .flush = BackendFns.flush,
    };
    _ = volume.attachBackend(backend);
    try std.testing.expectEqual(storage_volume.AttachedBackendKind.generic, volume.attached_backend_kind);
    try std.testing.expect(!volume.hasProductionStorageBackend());

    _ = volume.attachNvmePciBackend(backend);
    try std.testing.expectEqual(storage_volume.AttachedBackendKind.nvme_pci, volume.attached_backend_kind);
    try std.testing.expect(volume.hasProductionStorageBackend());

    const undersized_nvme_backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors - 1,
        .read = BackendFns.read,
        .write = BackendFns.write,
        .flush = BackendFns.flush,
    };
    _ = volume.attachNvmePciBackend(undersized_nvme_backend);
    try std.testing.expectEqual(storage_volume.AttachedBackendKind.nvme_pci, volume.attached_backend_kind);
    try std.testing.expect(!volume.hasProductionStorageBackend());
}

test "storage volume rejects undersized images without mutating state" {
    const undersized_image = try std.testing.allocator.alloc(u8, image_bytes - storage_volume.sector_size);
    defer std.testing.allocator.free(undersized_image);
    @memset(undersized_image, 0xA5);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x79),
    };
    _ = try loaded_store.putVersion(.{
        .preferred_object_id = object_store.ids.object(905),
        .object_type = .document,
        .payload = "preexisting",
        .metadata = try object_store.signMetadata(signer, "preexisting", "text/plain", .document, "preexisting", 17),
    });

    try std.testing.expectError(error.ImageTooSmall, loadFromImage(undersized_image, &loaded_store, &loaded_workspaces));
    try std.testing.expectEqual(@as(usize, 1), loaded_store.objectCount());
    try std.testing.expectEqual(@as(usize, 0), loaded_workspaces.workspaces.countInUse());
}

test "storage volume image reloads the latest persisted state across slot generations" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x71),
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(900),
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello", 10),
    });
    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(notes.id, 11);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 1), workspaces.dirtyWorkspaceIds().len);
    const generation_one = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 1), generation_one.generation);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 0), workspaces.dirtyWorkspaceIds().len);
    const first_log_bytes = try storage_volume.testing.latestImageLogBytes(image);

    const second = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(900),
        .object_type = .document,
        .payload = "hello again",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello again", 12),
        .parent_version_id = first.version_id,
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", second.object_id, second.version_id, .document);
    _ = try workspaces.commit(notes.id, 13);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 1), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 1), workspaces.dirtyWorkspaceIds().len);
    const generation_two = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 2), generation_two.generation);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyObjectIds().len);
    try std.testing.expectEqual(@as(usize, 0), store.dirtyVersionIds().len);
    try std.testing.expectEqual(@as(usize, 0), workspaces.dirtyWorkspaceIds().len);
    const second_log_bytes = try storage_volume.testing.latestImageLogBytes(image);
    try std.testing.expect(second_log_bytes > first_log_bytes);
    try std.testing.expect(second_log_bytes < first_log_bytes + 4 * storage_volume.sector_size);
    const unchanged_generation = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(generation_two.generation, unchanged_generation.generation);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_generation = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(@as(u64, 2), loaded_generation);
    try std.testing.expectEqual(@as(usize, 1), loaded_store.objectCount());
    try std.testing.expectEqual(@as(usize, 2), loaded_store.blobCount());
    try std.testing.expectEqual(second.version_id, loaded_store.latestVersion(900).?.id);
    try std.testing.expectEqual(second.version_id, loaded_store.latestInsertedVersionConst().?.id);
    try std.testing.expectEqual("hello again".len, loaded_store.maxBlobPayloadBytes());
    var document_results: [2]object_store.ObjectQueryResult = undefined;
    const loaded_documents = loaded_store.queryObjects(.{ .object_type = .document }, &document_results);
    try std.testing.expectEqual(@as(usize, 1), loaded_documents.len);
    try std.testing.expectEqual(first.object_id, loaded_documents[0].object_id);
    try std.testing.expectEqualStrings("hello again", try loaded_store.versionPayload(loaded_store.latestVersion(900).?));
    try std.testing.expectEqualStrings("zigos-storage-key", loaded_store.latestVersion(900).?.metadata.signature.signer);
    const loaded_first = loaded_store.version(first.version_id).?;
    const loaded_second = loaded_store.version(second.version_id).?;
    try std.testing.expect(loaded_first.metadata.signature.signer.ptr == loaded_second.metadata.signature.signer.ptr);
    try std.testing.expectEqual(@as(usize, 1 + signer.label.len), storage_volume.testing.signerTextBytes());
    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 1 }, "notes").?;
    try std.testing.expectEqual(second.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);
}

test "storage volume compacts segmented logs and reloads page-sized blob payloads" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x75),
    };

    var large_payload: [object_store.PAGE_SIZE_BYTES * 2 + 19]u8 = undefined;
    for (&large_payload, 0..) |*byte, index| {
        byte.* = @intCast((index * 23) & 0xFF);
    }
    const large = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(940),
        .object_type = .media_asset,
        .payload = &large_payload,
        .metadata = try object_store.signMetadata(signer, "large", "application/octet-stream", .media_asset, &large_payload, 30),
    });
    _ = try saveToImage(image, &store, &workspaces);

    var previous_version_id = object_store.ids.VersionId.zero;
    const compaction_mutations = @as(usize, storage_volume.testing.maxReplayLogSegments()) + 4;
    for (0..compaction_mutations) |index| {
        var payload_buffer: [DELTA_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buffer, "delta-{d}", .{index});
        const result = try store.putVersion(.{
            .preferred_object_id = object_store.ids.object(941),
            .object_type = .document,
            .payload = payload,
            .metadata = try object_store.signMetadata(signer, "delta", "text/plain", .document, payload, 31 + @as(u64, @intCast(index))),
            .parent_version_id = if (previous_version_id.isZero()) null else previous_version_id,
        });
        previous_version_id = result.version_id;
        _ = try saveToImage(image, &store, &workspaces);
    }

    try std.testing.expect((try storage_volume.testing.latestImageCompactedGeneration(image)) > 1);
    try std.testing.expect((try storage_volume.testing.latestImageLogRecordCount(image)) <= 128);
    try std.testing.expect((try storage_volume.testing.latestImageLogSegmentCount(image)) <= 16);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try loadFromImage(image, &loaded_store, &loaded_workspaces);

    var out: [large_payload.len]u8 = undefined;
    const loaded_large = try loaded_store.versionPayloadInto(loaded_store.version(large.version_id).?, &out);
    try std.testing.expectEqualSlices(u8, &large_payload, loaded_large);
    try std.testing.expectEqual(previous_version_id, loaded_store.latestVersion(941).?.id);
}

test "storage volume persists workspace snapshot roots through entry mutations" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x74),
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(930),
        .object_type = .document,
        .payload = "baseline",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "baseline", 20),
    });
    const second = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(930),
        .object_type = .document,
        .payload = "later",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "later", 21),
        .parent_version_id = first.version_id,
    });

    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 9 },
        .label = "snapshot-notes",
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(notes.id, 22);
    _ = try workspaces.snapshot(notes.id, "baseline", signer);

    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", second.object_id, second.version_id, .document);
    _ = try workspaces.commit(notes.id, 23);
    _ = try saveToImage(image, &store, &workspaces);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try loadFromImage(image, &loaded_store, &loaded_workspaces);

    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 9 }, "snapshot-notes").?;
    const loaded_snapshot = loaded_workspaces.findSnapshotByLabel(loaded_notes.id, "baseline").?;
    try std.testing.expectEqual(second.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);

    _ = try loaded_workspaces.restore(loaded_notes.id, loaded_snapshot.id, 24);
    try std.testing.expectEqual(first.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);
}

test "storage volume instances keep image reload state isolated" {
    const allocator = std.testing.allocator;
    const first_volume = try allocator.create(Volume);
    first_volume.* = Volume.init();
    defer allocator.destroy(first_volume);
    const second_volume = try allocator.create(Volume);
    second_volume.* = Volume.init();
    defer allocator.destroy(second_volume);
    _ = first_volume.reset();
    _ = second_volume.reset();
    const first_image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(first_image);
    const second_image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(second_image);
    @memset(first_image, 0);
    @memset(second_image, 0);

    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x73),
    };

    const first_store = try allocator.create(object_store.Store);
    defer allocator.destroy(first_store);
    const first_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(first_workspaces);
    first_store.* = object_store.Store.init();
    first_workspaces.* = workspace.Directory.init();
    _ = try first_store.putVersion(.{
        .preferred_object_id = object_store.ids.object(910),
        .object_type = .document,
        .payload = "first volume",
        .metadata = try object_store.signMetadata(signer, "first", "text/plain", .document, "first volume", 1),
    });
    _ = try first_volume.saveToImage(first_image, first_store, first_workspaces);

    const second_store = try allocator.create(object_store.Store);
    defer allocator.destroy(second_store);
    const second_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(second_workspaces);
    second_store.* = object_store.Store.init();
    second_workspaces.* = workspace.Directory.init();
    _ = try second_store.putVersion(.{
        .preferred_object_id = object_store.ids.object(920),
        .object_type = .document,
        .payload = "second volume",
        .metadata = try object_store.signMetadata(signer, "second", "text/plain", .document, "second volume", 2),
    });
    _ = try second_volume.saveToImage(second_image, second_store, second_workspaces);

    const loaded_first_store = try allocator.create(object_store.Store);
    defer allocator.destroy(loaded_first_store);
    const loaded_first_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(loaded_first_workspaces);
    const loaded_second_store = try allocator.create(object_store.Store);
    defer allocator.destroy(loaded_second_store);
    const loaded_second_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(loaded_second_workspaces);
    loaded_first_store.* = object_store.Store.init();
    loaded_first_workspaces.* = workspace.Directory.init();
    loaded_second_store.* = object_store.Store.init();
    loaded_second_workspaces.* = workspace.Directory.init();

    _ = try first_volume.loadFromImage(first_image, loaded_first_store, loaded_first_workspaces);
    _ = try second_volume.loadFromImage(second_image, loaded_second_store, loaded_second_workspaces);

    try std.testing.expectEqualStrings("first volume", try loaded_first_store.versionPayload(loaded_first_store.latestVersion(910).?));
    try std.testing.expectEqualStrings("second volume", try loaded_second_store.versionPayload(loaded_second_store.latestVersion(920).?));
    try std.testing.expect(loaded_first_store.latestVersion(920) == null);
    try std.testing.expect(loaded_second_store.latestVersion(910) == null);
}

test "storage volume rejects corrupted slot payloads" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x72),
    };
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(901),
        .object_type = .blob,
        .payload = "blob",
        .metadata = try object_store.signMetadata(signer, "blob", "application/octet-stream", .blob, "blob", 10),
    });
    _ = try saveToImage(image, &store, &workspaces);
    storage_volume.testing.corruptDataByte(image, 3);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, loadFromImage(image, &loaded_store, &loaded_workspaces));
}

test "storage volume rejects root log metadata that does not match replayed records" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x76),
    };
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(902),
        .object_type = .document,
        .payload = "root-log",
        .metadata = try object_store.signMetadata(signer, "root-log", "text/plain", .document, "root-log", 14),
    });
    _ = try saveToImage(image, &store, &workspaces);

    try storage_volume.testing.forceLatestImageRootLogRecordCount(
        image,
        (try storage_volume.testing.latestImageLogRecordCount(image)) + 1,
    );

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, loadFromImage(image, &loaded_store, &loaded_workspaces));
}

test "storage volume rejects torn records referenced by a valid root" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x77),
    };
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(903),
        .object_type = .document,
        .payload = "torn-record",
        .metadata = try object_store.signMetadata(signer, "torn-record", "text/plain", .document, "torn-record", 15),
    });
    _ = try saveToImage(image, &store, &workspaces);

    try storage_volume.testing.forceLatestImageRootLogBytes(
        image,
        @intCast(storage_volume.testing.recordHeaderBytes() + 1),
    );

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, loadFromImage(image, &loaded_store, &loaded_workspaces));
}

test "storage volume ignores power-loss data writes that happen before root commit" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    const interrupted = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(interrupted);
    @memset(image, 0);
    @memset(interrupted, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x7A),
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(906),
        .object_type = .document,
        .payload = "committed-before-power-loss",
        .metadata = try object_store.signMetadata(signer, "power", "text/plain", .document, "committed-before-power-loss", 19),
    });
    const generation_one = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 1), generation_one.generation);
    @memcpy(interrupted, image);

    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(906),
        .object_type = .document,
        .payload = "dirty-during-power-loss",
        .metadata = try object_store.signMetadata(signer, "power", "text/plain", .document, "dirty-during-power-loss", 20),
        .parent_version_id = first.version_id,
    });
    _ = try saveToImage(interrupted, &store, &workspaces);

    @memcpy(image[storage_volume.sector_size * 2 ..], interrupted[storage_volume.sector_size * 2 ..]);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_generation = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(generation_one.generation, loaded_generation);
    try std.testing.expectEqual(first.version_id, loaded_store.latestVersion(906).?.id);
    try std.testing.expectEqualStrings("committed-before-power-loss", try loaded_store.versionPayload(loaded_store.latestVersion(906).?));
}

test "storage volume survives an interrupted compaction into the alternate region" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x7C),
    };

    const committed = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(909),
        .object_type = .document,
        .payload = "survives-compaction-power-loss",
        .metadata = try object_store.signMetadata(signer, "compact", "text/plain", .document, "survives-compaction-power-loss", 40),
    });
    _ = try saveToImage(image, &store, &workspaces);

    var previous_version_id = object_store.ids.VersionId.zero;
    const compaction_mutations = @as(usize, storage_volume.testing.maxReplayLogSegments()) + 4;
    for (0..compaction_mutations) |index| {
        var payload_buffer: [DELTA_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buffer, "compact-delta-{d}", .{index});
        const result = try store.putVersion(.{
            .preferred_object_id = object_store.ids.object(910),
            .object_type = .document,
            .payload = payload,
            .metadata = try object_store.signMetadata(signer, "compact", "text/plain", .document, payload, 41 + @as(u64, @intCast(index))),
            .parent_version_id = if (previous_version_id.isZero()) null else previous_version_id,
        });
        previous_version_id = result.version_id;
        _ = try saveToImage(image, &store, &workspaces);
    }

    try std.testing.expect((try storage_volume.testing.latestImageCompactedGeneration(image)) > 1);

    const committed_offset = try storage_volume.testing.latestImageDataOffset(image);
    const alternate: u32 = if (committed_offset == 0) storage_volume.testing.alternateDataRegionOffset() else 0;
    storage_volume.testing.scribbleDataRegion(image, alternate);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try loadFromImage(image, &loaded_store, &loaded_workspaces);

    try std.testing.expectEqualStrings("survives-compaction-power-loss", try loaded_store.versionPayload(loaded_store.version(committed.version_id).?));
    try std.testing.expectEqual(previous_version_id, loaded_store.latestVersion(910).?.id);
}

test "storage volume falls back when a partial-sector corruption hits only the newest log generation" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x7B),
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(907),
        .object_type = .document,
        .payload = "sector-safe-v1",
        .metadata = try object_store.signMetadata(signer, "sector", "text/plain", .document, "sector-safe-v1", 21),
    });
    const generation_one = try saveToImage(image, &store, &workspaces);
    const first_log_bytes = try storage_volume.testing.latestImageLogBytes(image);

    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(907),
        .object_type = .document,
        .payload = "sector-corrupted-v2",
        .metadata = try object_store.signMetadata(signer, "sector", "text/plain", .document, "sector-corrupted-v2", 22),
        .parent_version_id = first.version_id,
    });
    const generation_two = try saveToImage(image, &store, &workspaces);
    try std.testing.expect(generation_two.generation > generation_one.generation);
    storage_volume.testing.corruptDataByte(image, @as(usize, first_log_bytes) + storage_volume.testing.recordHeaderBytes());

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_generation = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(generation_one.generation, loaded_generation);
    try std.testing.expectEqual(first.version_id, loaded_store.latestVersion(907).?.id);
    try std.testing.expectEqualStrings("sector-safe-v1", try loaded_store.versionPayload(loaded_store.latestVersion(907).?));
    try std.testing.expectEqualStrings(signer.label, loaded_store.latestVersion(907).?.metadata.signature.signer);
    try std.testing.expectEqual(@as(usize, 1 + signer.label.len), storage_volume.testing.signerTextBytes());
}

test "storage volume gates long-running replay by compacting before record and segment limits" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x7C),
    };

    var previous_version_id = object_store.ids.VersionId.zero;
    const iterations = @as(usize, storage_volume.testing.maxReplayLogSegments()) * 2 + 10;
    for (0..iterations) |index| {
        const payload = "stable-long-run-payload";
        const result = try store.putVersion(.{
            .preferred_object_id = object_store.ids.object(908),
            .object_type = .event_stream,
            .payload = payload,
            .metadata = try object_store.signMetadata(signer, "long-run", "text/plain", .event_stream, payload, 30 + @as(u64, @intCast(index))),
            .parent_version_id = if (previous_version_id.isZero()) null else previous_version_id,
        });
        previous_version_id = result.version_id;
        _ = try saveToImage(image, &store, &workspaces);
        try std.testing.expect((try storage_volume.testing.latestImageLogRecordCount(image)) <= storage_volume.testing.maxReplayLogRecords());
        try std.testing.expect((try storage_volume.testing.latestImageLogSegmentCount(image)) <= storage_volume.testing.maxReplayLogSegments());
    }

    try std.testing.expect((try storage_volume.testing.latestImageCompactedGeneration(image)) > storage_volume.testing.maxReplayLogSegments());

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    _ = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(previous_version_id, loaded_store.latestVersion(908).?.id);
    try std.testing.expectEqual(@as(usize, iterations), loaded_store.versionCount());
}

test "storage volume persists a mutated workspace alongside an untouched one across saves" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    const allocator = std.testing.allocator;
    const volume = try allocator.create(storage_volume.Volume);
    defer allocator.destroy(volume);
    _ = volume.reset();
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x72),
    };
    const first = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(901),
        .object_type = .document,
        .payload = "alpha",
        .metadata = try object_store.signMetadata(signer, "alpha", "text/markdown", .document, "alpha", 20),
    });
    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    const journal = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "journal",
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(notes.id, 21);
    try workspaces.beginTransaction(journal.id);
    try workspaces.stagePut(journal.id, "documents/journal.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(journal.id, 22);
    _ = try volume.saveToImage(image, &store, &workspaces);

    const shared_principal = principal.PrincipalId{ .kind = .user, .serial = 2 };
    try workspaces.share(journal.id, .{
        .principal_id = shared_principal,
        .can_read = true,
        .can_write = true,
    });
    _ = try volume.saveToImage(image, &store, &workspaces);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_volume = try allocator.create(storage_volume.Volume);
    defer allocator.destroy(loaded_volume);
    _ = loaded_volume.reset();
    _ = try loaded_volume.loadFromImage(image, &loaded_store, &loaded_workspaces);
    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 1 }, "notes").?;
    const loaded_journal = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 1 }, "journal").?;
    try std.testing.expectEqual(first.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);
    try std.testing.expectEqual(first.version_id, (try loaded_workspaces.resolve(loaded_journal.id, "documents/journal.md")).version_id);
    const loaded_grant = loaded_workspaces.findShareGrant(loaded_journal.id, shared_principal) orelse return error.ShareGrantNotPersisted;
    try std.testing.expect(loaded_grant.can_write);
}
