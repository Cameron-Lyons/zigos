const std = @import("std");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const state_codec = @import("sync_state_codec.zig");
const state_support = @import("sync_state_support.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");

const Error = state_support.Error;

pub fn ensureWorkspace(storage: *storage_service.Service, owner: principal.PrincipalId) Error!u64 {
    const existing = storage.findWorkspace(owner, state_support.state_workspace_label) orelse try storage.createWorkspace(.{
        .owner = owner,
        .label = state_support.state_workspace_label,
    });
    return existing.id.raw();
}

pub fn load(
    storage: *storage_service.Service,
    workspace_id: u64,
    resident: *state_support.ResidentState,
) Error!bool {
    const index_entry = storage.resolve(workspace_id, state_support.state_index_path) catch |err| switch (err) {
        error.EntryNotFound => return false,
        else => return err,
    };
    const index_version = storage.version(index_entry.version_id) orelse return error.CorruptState;
    const index = try state_codec.decodeStateIndex(try storage.versionPayload(index_version));
    if (index.chunk_count == 0 or index.chunk_count > state_support.max_state_chunks) return error.CorruptState;
    if (index.total_len == 0 or index.total_len > state_support.max_state_bytes) return error.CorruptState;

    var assembled: [state_support.max_state_bytes]u8 = undefined;
    var offset: usize = 0;
    var chunk_index: usize = 0;
    while (chunk_index < index.chunk_count) : (chunk_index += 1) {
        var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
        const path = try state_support.chunkPath(path_buffer[0..], chunk_index);
        const chunk_entry = storage.resolve(workspace_id, path) catch |err| switch (err) {
            error.EntryNotFound => return error.CorruptState,
            else => return err,
        };
        const chunk_version = storage.version(chunk_entry.version_id) orelse return error.CorruptState;
        const payload = try storage.versionPayload(chunk_version);
        if (offset + payload.len > index.total_len) return error.CorruptState;
        @memcpy(assembled[offset .. offset + payload.len], payload);
        offset += payload.len;
    }
    if (offset != index.total_len) return error.CorruptState;
    if (!std.mem.eql(u8, &index.digest, &state_support.stateDigest(assembled[0..offset]))) return error.CorruptState;

    try state_codec.deserialize(resident, assembled[0..offset]);
    resident.has_persisted_state = true;
    return true;
}

pub fn persist(
    storage: *storage_service.Service,
    workspace_id: u64,
    resident: *state_support.ResidentState,
) Error!void {
    var encoded: [state_support.max_state_bytes]u8 = undefined;
    const encoded_len = try state_codec.serialize(resident, encoded[0..]);
    const chunk_count = @divFloor(encoded_len + object_store.MAX_PAYLOAD_BYTES - 1, object_store.MAX_PAYLOAD_BYTES);
    if (chunk_count == 0 or chunk_count > state_support.max_state_chunks) return error.StateTooLarge;

    var chunk_dirty: [state_support.max_state_chunks]bool = [_]bool{false} ** state_support.max_state_chunks;
    var chunk_version_ids: [state_support.max_state_chunks]u64 = [_]u64{0} ** state_support.max_state_chunks;
    var removed_chunk_paths: [state_support.max_state_chunks][workspace.MAX_ENTRY_PATH_BYTES]u8 =
        [_][workspace.MAX_ENTRY_PATH_BYTES]u8{[_]u8{0} ** workspace.MAX_ENTRY_PATH_BYTES} ** state_support.max_state_chunks;
    var removed_chunk_path_lens: [state_support.max_state_chunks]usize = [_]usize{0} ** state_support.max_state_chunks;
    var has_chunk_changes = false;

    var chunk_index: usize = 0;
    while (chunk_index < chunk_count) : (chunk_index += 1) {
        const start = chunk_index * object_store.MAX_PAYLOAD_BYTES;
        const end = @min(start + object_store.MAX_PAYLOAD_BYTES, encoded_len);
        const payload = encoded[start..end];
        var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
        const path = try state_support.chunkPath(path_buffer[0..], chunk_index);
        const existing_entry = storage.resolve(workspace_id, path) catch |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };
        if (existing_entry) |entry| {
            chunk_version_ids[chunk_index] = entry.version_id.raw();
            const existing_version = storage.version(entry.version_id) orelse return error.CorruptState;
            if (std.mem.eql(u8, try storage.versionPayload(existing_version), payload)) continue;
        }

        chunk_dirty[chunk_index] = true;
        has_chunk_changes = true;
    }

    chunk_index = chunk_count;
    while (chunk_index < state_support.max_state_chunks) : (chunk_index += 1) {
        var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
        const path = try state_support.chunkPath(path_buffer[0..], chunk_index);
        const existing_entry = storage.resolve(workspace_id, path) catch |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };
        if (existing_entry == null) continue;
        removed_chunk_path_lens[chunk_index] = path.len;
        @memcpy(removed_chunk_paths[chunk_index][0..path.len], path);
        has_chunk_changes = true;
    }

    var index_payload: [object_store.MAX_PAYLOAD_BYTES]u8 = undefined;
    const index_bytes = try state_codec.encodeStateIndex(
        index_payload[0..],
        encoded_len,
        chunk_count,
        state_support.stateDigest(encoded[0..encoded_len]),
    );
    const existing_index = storage.resolve(workspace_id, state_support.state_index_path) catch |err| switch (err) {
        error.EntryNotFound => null,
        else => return err,
    };

    const index_dirty = blk: {
        if (existing_index) |entry| {
            const version = storage.version(entry.version_id) orelse return error.CorruptState;
            break :blk !std.mem.eql(u8, try storage.versionPayload(version), index_bytes);
        }
        break :blk true;
    };
    if (!has_chunk_changes and !index_dirty) return;

    const tick = resident.nextPersistTick();
    try storage.beginTransaction(workspace_id);

    chunk_index = 0;
    while (chunk_index < chunk_count) : (chunk_index += 1) {
        if (!chunk_dirty[chunk_index]) continue;

        const start = chunk_index * object_store.MAX_PAYLOAD_BYTES;
        const end = @min(start + object_store.MAX_PAYLOAD_BYTES, encoded_len);
        const payload = encoded[start..end];
        var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
        const path = try state_support.chunkPath(path_buffer[0..], chunk_index);
        const result = try storage.putVersion(.{
            .preferred_object_id = object_store.ids.object(state_support.chunkObjectId(chunk_index)),
            .object_type = .blob,
            .payload = payload,
            .metadata = object_store.signMetadata(
                state_support.state_signer,
                path,
                "application/zigos-sync-chunk",
                .blob,
                payload,
                tick,
            ) catch return error.StateSigningFailed,
            .parent_version_id = if (chunk_version_ids[chunk_index] != 0) object_store.ids.version(chunk_version_ids[chunk_index]) else null,
        });
        try storage.stagePut(workspace_id, path, result.object_id, result.version_id, .blob);
    }

    chunk_index = chunk_count;
    while (chunk_index < state_support.max_state_chunks) : (chunk_index += 1) {
        if (removed_chunk_path_lens[chunk_index] == 0) continue;
        try storage.stageDelete(workspace_id, removed_chunk_paths[chunk_index][0..removed_chunk_path_lens[chunk_index]]);
    }

    if (index_dirty) {
        const index_result = try storage.putVersion(.{
            .preferred_object_id = object_store.ids.object(state_support.indexObjectId()),
            .object_type = .document,
            .payload = index_bytes,
            .metadata = object_store.signMetadata(
                state_support.state_signer,
                state_support.state_index_path,
                "application/zigos-sync-index",
                .document,
                index_bytes,
                tick,
            ) catch return error.StateSigningFailed,
            .parent_version_id = if (existing_index) |entry| entry.version_id else null,
        });
        try storage.stagePut(workspace_id, state_support.state_index_path, index_result.object_id, index_result.version_id, .document);
    }

    _ = try storage.commit(workspace_id, tick);
}
