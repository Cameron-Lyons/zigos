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
pub const MAX_DOCUMENT_OPERATIONS: usize = 16;
pub const MAX_DOCUMENT_OPERATION_TEXT_BYTES: usize = 64;
pub const MAX_DOCUMENT_VECTOR_CLOCKS: usize = 8;

pub const DocumentOperationKind = enum(u8) {
    insert,
    delete,
};

pub const DocumentOperation = struct {
    kind: DocumentOperationKind,
    position: usize,
    delete_len: usize = 0,
    text_len: usize = 0,
    text: [MAX_DOCUMENT_OPERATION_TEXT_BYTES]u8 = [_]u8{0} ** MAX_DOCUMENT_OPERATION_TEXT_BYTES,
    actor: principal.PrincipalId,
    lamport: u64,

    pub fn insert(position: usize, text: []const u8, actor: principal.PrincipalId, lamport: u64) Error!DocumentOperation {
        if (text.len > MAX_DOCUMENT_OPERATION_TEXT_BYTES) return error.DocumentOperationTooLarge;
        var operation = DocumentOperation{
            .kind = .insert,
            .position = position,
            .actor = actor,
            .lamport = lamport,
        };
        operation.text_len = text.len;
        @memcpy(operation.text[0..text.len], text);
        return operation;
    }

    pub fn remove(position: usize, delete_len: usize, actor: principal.PrincipalId, lamport: u64) DocumentOperation {
        return .{
            .kind = .delete,
            .position = position,
            .delete_len = delete_len,
            .actor = actor,
            .lamport = lamport,
        };
    }

    pub fn textSlice(self: *const DocumentOperation) []const u8 {
        return self.text[0..self.text_len];
    }
};

pub const DocumentOperationId = struct {
    actor: principal.PrincipalId,
    lamport: u64,

    fn eql(self: DocumentOperationId, other: DocumentOperationId) bool {
        return self.lamport == other.lamport and self.actor.eql(other.actor);
    }
};

pub const DocumentVectorClock = struct {
    actor: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    lamport: u64 = 0,
};

pub const DocumentOperationLog = struct {
    operations: [MAX_DOCUMENT_OPERATIONS]DocumentOperation = undefined,
    operation_count: usize = 0,
    clocks: [MAX_DOCUMENT_VECTOR_CLOCKS]DocumentVectorClock = [_]DocumentVectorClock{.{}} ** MAX_DOCUMENT_VECTOR_CLOCKS,
    clock_count: usize = 0,

    pub fn append(self: *DocumentOperationLog, operation: DocumentOperation) Error!void {
        const id = operationId(operation);
        if (self.contains(id)) return error.DuplicateDocumentOperation;
        if (self.operation_count >= self.operations.len) return error.DocumentOperationLogFull;
        self.operations[self.operation_count] = operation;
        self.operation_count += 1;
        try self.observe(operation.actor, operation.lamport);
    }

    pub fn mergeFrom(self: *DocumentOperationLog, remote: *const DocumentOperationLog) Error!void {
        for (remote.slice()) |operation| {
            const id = operationId(operation);
            if (self.contains(id)) {
                try self.observe(operation.actor, operation.lamport);
                continue;
            }
            try self.append(operation);
        }
    }

    pub fn slice(self: *const DocumentOperationLog) []const DocumentOperation {
        return self.operations[0..self.operation_count];
    }

    pub fn clockFor(self: *const DocumentOperationLog, actor: principal.PrincipalId) u64 {
        for (self.clocks[0..self.clock_count]) |clock| {
            if (clock.actor.eql(actor)) return clock.lamport;
        }
        return 0;
    }

    pub fn apply(self: *const DocumentOperationLog, base_document: []const u8, output: []u8) Error![]const u8 {
        return applyMergeableDocumentOperations(base_document, self.slice(), &.{}, output);
    }

    fn contains(self: *const DocumentOperationLog, id: DocumentOperationId) bool {
        for (self.slice()) |operation| {
            if (operationId(operation).eql(id)) return true;
        }
        return false;
    }

    fn observe(self: *DocumentOperationLog, actor: principal.PrincipalId, lamport: u64) Error!void {
        for (self.clocks[0..self.clock_count]) |*clock| {
            if (!clock.actor.eql(actor)) continue;
            clock.lamport = @max(clock.lamport, lamport);
            return;
        }
        if (self.clock_count >= self.clocks.len) return error.DocumentOperationLogFull;
        self.clocks[self.clock_count] = .{ .actor = actor, .lamport = lamport };
        self.clock_count += 1;
    }
};

fn operationId(operation: DocumentOperation) DocumentOperationId {
    return .{ .actor = operation.actor, .lamport = operation.lamport };
}

pub const MergeRequest = struct {
    store: *const storage_service.Service,
    entry: workspace.Entry,
    remote_version_id: u64 = 0,
    base_document: []const u8 = "",
    local_operations: []const DocumentOperation = &.{},
    remote_operations: []const DocumentOperation = &.{},
    merge_buffer: ?[]u8 = null,
};

pub const MergeResult = struct {
    merged: bool,
    conflict: bool,
    merged_document_len: usize = 0,
};

pub const MergeableDocumentAdapter = struct {
    mergeFn: *const fn (request: MergeRequest) Error!MergeResult,

    pub fn merge(self: *const MergeableDocumentAdapter, request: MergeRequest) Error!MergeResult {
        return self.mergeFn(request);
    }
};

pub fn applyMergeableDocumentOperations(
    base_document: []const u8,
    local_operations: []const DocumentOperation,
    remote_operations: []const DocumentOperation,
    output: []u8,
) Error![]const u8 {
    if (base_document.len > output.len) return error.DocumentBufferTooSmall;
    var operations: [MAX_DOCUMENT_OPERATIONS * 2]DocumentOperation = undefined;
    var operation_count: usize = 0;
    for (local_operations) |operation| {
        if (operation_count >= operations.len) return error.TooManyDocumentOperations;
        operations[operation_count] = operation;
        operation_count += 1;
    }
    for (remote_operations) |operation| {
        if (operation_count >= operations.len) return error.TooManyDocumentOperations;
        operations[operation_count] = operation;
        operation_count += 1;
    }
    sortDocumentOperations(operations[0..operation_count]);

    @memcpy(output[0..base_document.len], base_document);
    var len = base_document.len;
    for (operations[0..operation_count]) |operation| {
        len = try applyDocumentOperation(operation, output, len);
    }
    return output[0..len];
}

pub fn mergeDocumentOperationLogs(
    base_document: []const u8,
    local_log: *const DocumentOperationLog,
    remote_log: *const DocumentOperationLog,
    merged_log: *DocumentOperationLog,
    output: []u8,
) Error![]const u8 {
    merged_log.* = DocumentOperationLog{};
    try merged_log.mergeFrom(local_log);
    try merged_log.mergeFrom(remote_log);
    return merged_log.apply(base_document, output);
}

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
        if (request.local_operations.len != 0 or request.remote_operations.len != 0) {
            if (request.entry.object_type != .document) return error.TypeMismatch;
            const merge_buffer = request.merge_buffer orelse return error.DocumentBufferTooSmall;
            const merged_document = try applyMergeableDocumentOperations(
                request.base_document,
                request.local_operations,
                request.remote_operations,
                merge_buffer,
            );
            return .{ .merged = true, .conflict = false, .merged_document_len = merged_document.len };
        }
        if (request.remote_version_id == 0 or request.remote_version_id == request.entry.version_id.raw()) {
            return .{ .merged = true, .conflict = false };
        }
        if (local_version.previous_version_id.raw() == request.remote_version_id) {
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

fn sortDocumentOperations(operations: []DocumentOperation) void {
    var index: usize = 1;
    while (index < operations.len) : (index += 1) {
        const value = operations[index];
        var insert_at = index;
        while (insert_at > 0 and documentOperationLess(value, operations[insert_at - 1])) : (insert_at -= 1) {
            operations[insert_at] = operations[insert_at - 1];
        }
        operations[insert_at] = value;
    }
}

fn documentOperationLess(left: DocumentOperation, right: DocumentOperation) bool {
    if (left.lamport != right.lamport) return left.lamport < right.lamport;
    if (left.actor.serial != right.actor.serial) return left.actor.serial < right.actor.serial;
    if (left.actor.kind != right.actor.kind) return @intFromEnum(left.actor.kind) < @intFromEnum(right.actor.kind);
    if (left.position != right.position) return left.position < right.position;
    return @intFromEnum(left.kind) < @intFromEnum(right.kind);
}

fn applyDocumentOperation(operation: DocumentOperation, output: []u8, current_len: usize) Error!usize {
    return switch (operation.kind) {
        .insert => applyInsert(operation, output, current_len),
        .delete => applyDelete(operation, output, current_len),
    };
}

fn applyInsert(operation: DocumentOperation, output: []u8, current_len: usize) Error!usize {
    if (operation.text_len == 0) return current_len;
    if (current_len + operation.text_len > output.len) return error.DocumentBufferTooSmall;
    const position = @min(operation.position, current_len);
    var index = current_len;
    while (index > position) : (index -= 1) {
        output[index + operation.text_len - 1] = output[index - 1];
    }
    @memcpy(output[position .. position + operation.text_len], operation.textSlice());
    return current_len + operation.text_len;
}

fn applyDelete(operation: DocumentOperation, output: []u8, current_len: usize) Error!usize {
    if (operation.delete_len == 0 or operation.position >= current_len) return current_len;
    const delete_end = @min(current_len, operation.position + operation.delete_len);
    const removed = delete_end - operation.position;
    var index = delete_end;
    while (index < current_len) : (index += 1) {
        output[index - removed] = output[index];
    }
    return current_len - removed;
}

fn databaseContractMessage(
    buffer: []u8,
    workspace_id: u64,
    bundle_id: []const u8,
    label: []const u8,
) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buffer, "db-contract:{d}:{s}:{s}", .{ workspace_id, bundle_id, label }) catch error.NoSpaceLeft;
}

test "mergeable document adapter applies deterministic CRDT operations and rejects undersized buffers" {
    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 402 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 7 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 8 };
    const signer = signing.SignerIdentity{
        .label = "sync-crdt-storage",
        .seed = [_]u8{0x92} ** 32,
    };
    var checkpoint_store = storage_service.CheckpointStore{};
    checkpoint_store.resetPersistent();
    var storage = storage_service.Service.initWithStore(402, 5, storage_owner, &checkpoint_store);
    const document = try storage.putVersion(.{
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/plain", .document, "hello", 1),
    });

    const local_operations = [_]DocumentOperation{
        try DocumentOperation.insert(5, " from laptop", laptop, 2),
    };
    const remote_operations = [_]DocumentOperation{
        try DocumentOperation.insert(5, " and tablet", tablet, 1),
    };
    var merge_buffer: [96]u8 = undefined;
    const adapter_value = DefaultMergeableDocumentAdapter.adapter();
    const result = try adapter_value.merge(.{
        .store = &storage,
        .entry = try workspace.Entry.init("documents/notes.md", document.object_id, document.version_id, .document),
        .base_document = "hello",
        .local_operations = local_operations[0..],
        .remote_operations = remote_operations[0..],
        .merge_buffer = merge_buffer[0..],
    });
    try std.testing.expect(result.merged);
    try std.testing.expect(!result.conflict);
    try std.testing.expectEqualStrings("hello from laptop and tablet", merge_buffer[0..result.merged_document_len]);

    var replay_buffer: [96]u8 = undefined;
    const replayed = try applyMergeableDocumentOperations(
        "hello",
        remote_operations[0..],
        local_operations[0..],
        replay_buffer[0..],
    );
    try std.testing.expectEqualStrings(merge_buffer[0..result.merged_document_len], replayed);

    var small_buffer: [8]u8 = undefined;
    try std.testing.expectError(error.DocumentBufferTooSmall, applyMergeableDocumentOperations(
        "hello",
        local_operations[0..],
        remote_operations[0..],
        small_buffer[0..],
    ));

    checkpoint_store.resetPersistent();
}

test "document operation log merges CRDT operations idempotently with vector clocks" {
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 17 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 18 };

    var laptop_log = DocumentOperationLog{};
    try laptop_log.append(try DocumentOperation.insert(6, "from laptop ", laptop, 1));
    try laptop_log.append(try DocumentOperation.insert(18, "today", laptop, 2));

    var tablet_log = DocumentOperationLog{};
    try tablet_log.append(try DocumentOperation.insert(6, "from tablet ", tablet, 1));
    try tablet_log.append(DocumentOperation.remove(0, 0, tablet, 2));

    var merged_log = DocumentOperationLog{};
    var merge_buffer: [128]u8 = undefined;
    const merged = try mergeDocumentOperationLogs("hello ", &laptop_log, &tablet_log, &merged_log, merge_buffer[0..]);
    try std.testing.expectEqualStrings("hello from tablet todayfrom laptop ", merged);
    try std.testing.expectEqual(@as(u64, 2), merged_log.clockFor(laptop));
    try std.testing.expectEqual(@as(u64, 2), merged_log.clockFor(tablet));

    try merged_log.mergeFrom(&tablet_log);
    var replay_buffer: [128]u8 = undefined;
    const replayed = try merged_log.apply("hello ", replay_buffer[0..]);
    try std.testing.expectEqualStrings(merged, replayed);

    try std.testing.expectError(error.DuplicateDocumentOperation, laptop_log.append(try DocumentOperation.insert(6, "duplicate", laptop, 1)));
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
        .entry = try workspace.Entry.init("assets/clip.raw", media.object_id, media.version_id, .media_asset),
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
