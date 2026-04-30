const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const state_support = @import("sync_state_support.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");

pub const Error = state_support.Error;
pub const MAX_TRANSPORT_FRAMES = state_support.MAX_TRANSPORT_FRAMES;

pub const MergeRequest = struct {
    store: *const storage_service.Service,
    entry: workspace.Entry,
    remote_version_id: u64 = 0,
};

pub const MergeResult = struct {
    merged: bool,
    conflict: bool,
};

pub const MergeableDocumentAdapter = struct {
    mergeFn: *const fn (request: MergeRequest) Error!MergeResult,

    pub fn merge(self: *const MergeableDocumentAdapter, request: MergeRequest) Error!MergeResult {
        return self.mergeFn(request);
    }
};

pub const ChunkReplicationRequest = struct {
    store: *const storage_service.Service,
    entry: workspace.Entry,
};

pub const ChunkReplicationResult = struct {
    snapshot_replicated: bool,
    replicated_chunks: usize,
};

pub const ChunkMediaAdapter = struct {
    replicateFn: *const fn (request: ChunkReplicationRequest) Error!ChunkReplicationResult,

    pub fn replicate(self: *const ChunkMediaAdapter, request: ChunkReplicationRequest) Error!ChunkReplicationResult {
        return self.replicateFn(request);
    }
};

pub const SecretTransferRequest = struct {
    store: *const storage_service.Service,
    workspace_id: u64,
    object_id: u64,
    from_device: principal.PrincipalId,
    to_device: principal.PrincipalId,
    personal_e2ee: bool,
};

pub const SecretTransferResult = struct {
    transferred: bool,
    encrypted_payload: bool,
};

pub const SecretTransferAdapter = struct {
    transferFn: *const fn (request: SecretTransferRequest) Error!SecretTransferResult,

    pub fn transfer(self: *const SecretTransferAdapter, request: SecretTransferRequest) Error!SecretTransferResult {
        return self.transferFn(request);
    }
};

pub const DatabaseSyncRequest = struct {
    contract: *const state_support.DatabaseContract,
    workspace_id: u64,
    from_device: principal.PrincipalId,
    to_device: principal.PrincipalId,
};

pub const DatabaseSyncResult = struct {
    replicated: bool,
    transactional_contract: bool,
};

pub const DatabaseSyncAdapter = struct {
    replicateFn: *const fn (request: DatabaseSyncRequest) Error!DatabaseSyncResult,

    pub fn replicate(self: *const DatabaseSyncAdapter, request: DatabaseSyncRequest) Error!DatabaseSyncResult {
        return self.replicateFn(request);
    }
};

pub const TransportFrame = struct {
    id: u64 = 0,
    workspace_id: u64 = 0,
    object_id: u64 = 0,
    version_id: u64 = 0,
    source_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    target_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    transport: state_support.TransportMode = .device_to_device,
    semantic: state_support.SyncSemantic = .mergeable_crdt,
    encrypted: bool = false,
    path_len: usize = 0,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8 = [_]u8{0} ** workspace.MAX_ENTRY_PATH_BYTES,

    pub fn pathSlice(self: *const TransportFrame) []const u8 {
        return self.path[0..self.path_len];
    }
};

pub const QueueFrameRequest = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    transport: state_support.TransportMode,
    semantic: state_support.SyncSemantic,
    encrypted: bool,
    path: []const u8,
};

const TransportFrameSlot = struct {
    in_use: bool = false,
    frame: TransportFrame = .{},
};

pub const TransportQueue = struct {
    next_frame_id: u64 = 1,
    frames: [MAX_TRANSPORT_FRAMES]TransportFrameSlot = [_]TransportFrameSlot{TransportFrameSlot{}} ** MAX_TRANSPORT_FRAMES,

    pub fn init() TransportQueue {
        return .{};
    }

    pub fn reset(self: *TransportQueue) void {
        self.* = .{};
    }

    pub fn enqueue(self: *TransportQueue, request: QueueFrameRequest) Error!TransportFrame {
        const slot = self.allocateSlot() orelse return error.TransportQueueFull;
        var frame = TransportFrame{
            .id = self.nextFrameId(),
            .workspace_id = request.workspace_id,
            .object_id = request.object_id,
            .version_id = request.version_id,
            .source_device = request.source_device,
            .target_device = request.target_device,
            .transport = request.transport,
            .semantic = request.semantic,
            .encrypted = request.encrypted,
        };
        frame.path_len = copyPath(&frame.path, request.path);
        slot.in_use = true;
        slot.frame = frame;
        return slot.frame;
    }

    pub fn count(self: *const TransportQueue) usize {
        var total: usize = 0;
        for (self.frames) |slot| {
            if (slot.in_use) total += 1;
        }
        return total;
    }

    pub fn countFor(self: *const TransportQueue, workspace_id: u64, target_device: principal.PrincipalId) usize {
        var total: usize = 0;
        for (self.frames) |slot| {
            if (!slot.in_use) continue;
            if (slot.frame.workspace_id == workspace_id and slot.frame.target_device.eql(target_device)) {
                total += 1;
            }
        }
        return total;
    }

    pub fn latestForPath(
        self: *const TransportQueue,
        workspace_id: u64,
        target_device: principal.PrincipalId,
        path: []const u8,
    ) ?TransportFrame {
        var index = self.frames.len;
        while (index > 0) {
            index -= 1;
            const slot = self.frames[index];
            if (!slot.in_use) continue;
            if (slot.frame.workspace_id != workspace_id) continue;
            if (!slot.frame.target_device.eql(target_device)) continue;
            if (!std.mem.eql(u8, slot.frame.pathSlice(), path)) continue;
            return slot.frame;
        }
        return null;
    }

    fn allocateSlot(self: *TransportQueue) ?*TransportFrameSlot {
        for (&self.frames) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }

    fn nextFrameId(self: *TransportQueue) u64 {
        defer self.next_frame_id += 1;
        return self.next_frame_id;
    }
};

pub const DefaultMergeableDocumentAdapter = struct {
    pub fn adapter() MergeableDocumentAdapter {
        return .{ .mergeFn = merge };
    }

    fn merge(request: MergeRequest) Error!MergeResult {
        if (request.entry.object_type != .document and request.entry.object_type != .collection and request.entry.object_type != .blob) {
            return error.TypeMismatch;
        }
        const local_version = request.store.version(request.entry.version_id) orelse return error.VersionNotFound;
        if (local_version.object_type != request.entry.object_type) return error.TypeMismatch;
        if (request.remote_version_id == 0 or request.remote_version_id == request.entry.version_id) {
            return .{ .merged = true, .conflict = false };
        }
        if (local_version.previous_version_id == request.remote_version_id) {
            return .{ .merged = true, .conflict = false };
        }
        return .{ .merged = true, .conflict = true };
    }
};

pub const DefaultChunkMediaAdapter = struct {
    pub fn adapter() ChunkMediaAdapter {
        return .{ .replicateFn = replicate };
    }

    fn replicate(request: ChunkReplicationRequest) Error!ChunkReplicationResult {
        const version = request.store.version(request.entry.version_id) orelse return error.VersionNotFound;
        if (version.object_type != request.entry.object_type) return error.TypeMismatch;
        const payload = try request.store.versionPayload(version);
        const chunk_count = @max(@as(usize, version.chunk_count), chunkCountForPayload(payload.len));
        return .{
            .snapshot_replicated = true,
            .replicated_chunks = chunk_count,
        };
    }
};

pub const DefaultSecretTransferAdapter = struct {
    pub fn adapter() SecretTransferAdapter {
        return .{ .transferFn = transfer };
    }

    fn transfer(request: SecretTransferRequest) Error!SecretTransferResult {
        _ = request.workspace_id;
        _ = request.from_device;
        _ = request.to_device;
        if (!request.personal_e2ee) return error.TransportDenied;
        const object_record = request.store.object(request.object_id) orelse return error.ObjectNotFound;
        if (object_record.object_type != .secret) return error.TypeMismatch;
        const version = request.store.latestVersion(request.object_id) orelse return error.VersionNotFound;
        const payload = try request.store.versionPayload(version);
        return .{
            .transferred = true,
            .encrypted_payload = std.mem.startsWith(u8, payload, "enc:"),
        };
    }
};

pub const DefaultDatabaseSyncAdapter = struct {
    pub fn adapter() DatabaseSyncAdapter {
        return .{ .replicateFn = replicate };
    }

    fn replicate(request: DatabaseSyncRequest) Error!DatabaseSyncResult {
        _ = request.from_device;
        _ = request.to_device;
        if (request.contract.workspace_id != request.workspace_id) return error.InvalidContractSignature;
        var message_buffer: [160]u8 = undefined;
        const message = databaseContractMessage(
            &message_buffer,
            request.contract.workspace_id,
            request.contract.bundleIdSlice(),
            request.contract.labelSlice(),
        ) catch return error.InvalidContractSignature;
        if (!signing.verify(request.contract.signature, message)) return error.InvalidContractSignature;
        return .{
            .replicated = true,
            .transactional_contract = true,
        };
    }
};

pub const default_mergeable_document_adapter = DefaultMergeableDocumentAdapter.adapter();
pub const default_chunk_media_adapter = DefaultChunkMediaAdapter.adapter();
pub const default_secret_transfer_adapter = DefaultSecretTransferAdapter.adapter();
pub const default_database_sync_adapter = DefaultDatabaseSyncAdapter.adapter();

fn copyPath(destination: *[workspace.MAX_ENTRY_PATH_BYTES]u8, path: []const u8) usize {
    const len = @min(destination.len, path.len);
    @memset(destination[0..], 0);
    @memcpy(destination[0..len], path[0..len]);
    return len;
}

fn chunkCountForPayload(payload_len: usize) usize {
    const chunk_size: usize = 128;
    if (payload_len == 0) return 0;
    return (payload_len + chunk_size - 1) / chunk_size;
}

fn databaseContractMessage(
    buffer: []u8,
    workspace_id: u64,
    bundle_id: []const u8,
    label: []const u8,
) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buffer, "db-contract:{d}:{s}:{s}", .{ workspace_id, bundle_id, label }) catch error.NoSpaceLeft;
}

test "default chunk media adapter reports concrete payload chunks" {
    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 401 };
    const signer = signing.SignerIdentity{
        .label = "sync-adapter-storage",
        .seed = [_]u8{0x91} ** 32,
    };
    var checkpoint_store = storage_service.CheckpointStore{};
    checkpoint_store.resetPersistent();
    var storage = storage_service.Service.initWithStore(401, 4, storage_owner, &checkpoint_store);
    const media = try storage.putVersion(.{
        .object_type = .media_asset,
        .payload = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
        .metadata = try object_store.signMetadata(signer, "clip", "video/raw", .media_asset, "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789", 1),
    });
    const adapter_value = DefaultChunkMediaAdapter.adapter();
    const result = try adapter_value.replicate(.{
        .store = &storage,
        .entry = workspace.Entry.init("assets/clip.raw", media.object_id, media.version_id, .media_asset),
    });
    try std.testing.expect(result.snapshot_replicated);
    try std.testing.expectEqual(@as(usize, 2), result.replicated_chunks);
}

test "transport queue records encrypted semantic replication frames" {
    var queue = TransportQueue.init();
    const frame = try queue.enqueue(.{
        .workspace_id = 42,
        .object_id = 80,
        .version_id = 81,
        .source_device = .{ .kind = .device, .serial = 1 },
        .target_device = .{ .kind = .device, .serial = 2 },
        .transport = .relay_assisted,
        .semantic = .secure_transfer,
        .encrypted = true,
        .path = "secrets/token",
    });

    try std.testing.expectEqual(@as(u64, 1), frame.id);
    try std.testing.expect(frame.encrypted);
    try std.testing.expectEqual(state_support.SyncSemantic.secure_transfer, frame.semantic);
    try std.testing.expectEqual(@as(usize, 1), queue.countFor(42, .{ .kind = .device, .serial = 2 }));
    try std.testing.expectEqualStrings("secrets/token", queue.latestForPath(42, .{ .kind = .device, .serial = 2 }, "secrets/token").?.pathSlice());
}
