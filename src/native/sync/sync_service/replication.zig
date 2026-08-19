const std = @import("std");
const principal = @import("../../core/principal.zig");
const object_store = @import("../../storage/object_store.zig");
const storage_service = @import("../../storage/storage_service.zig");
const workspace = @import("../../storage/workspace.zig");
const state_support = @import("../sync_state_support.zig");
const sync_adapters = @import("../sync_adapters.zig");

pub const Error = state_support.Error;
pub const ReplicationSummary = state_support.ReplicationSummary;
pub const SyncSemantic = state_support.SyncSemantic;
pub const WorkspacePolicy = state_support.WorkspacePolicy;
pub const TransportFrameRequest = sync_adapters.QueueFrameRequest;

comptime {
    if (state_support.MAX_REPLICA_ENTRIES * sync_adapters.MAX_MEDIA_REPLICATION_CHUNKS > std.math.maxInt(u16)) {
        @compileError("replication snapshot count no longer fits compact result metadata");
    }
}

pub fn applyOutboundSemantic(
    service: anytype,
    store: *const storage_service.Service,
    workspace_id: u64,
    from_device: principal.PrincipalId,
    to_device: principal.PrincipalId,
    policy: *const WorkspacePolicy,
    entry: workspace.Entry,
    semantic: SyncSemantic,
    remote_version_id: u64,
    summary: *ReplicationSummary,
) Error!void {
    switch (semantic) {
        .mergeable_crdt => {
            const result = try service.mergeable_document_adapter.merge(.{
                .store = store,
                .entry = entry,
                .remote_version_id = remote_version_id,
            });
            if (result.merged) summary.merged_count += 1;
            if (result.conflict) {
                try service.recordConflict(
                    workspace_id,
                    to_device,
                    entry.object_id.raw(),
                    entry.pathSlice(),
                    entry.version_id.raw(),
                    remote_version_id,
                    semantic,
                );
            }
        },
        .chunked_snapshot => {
            const result = try service.chunk_media_adapter.replicate(.{
                .store = store,
                .entry = entry,
            });
            if (result.snapshot_replicated) {
                const remaining_capacity = std.math.maxInt(u16) - summary.snapshot_count;
                if (result.replicated_chunks > @as(usize, remaining_capacity)) return error.StateTooLarge;
                summary.snapshot_count += @intCast(result.replicated_chunks);
            }
        },
        .secure_transfer => {
            const result = try service.secret_transfer_adapter.transfer(.{
                .store = store,
                .workspace_id = workspace_id,
                .object_id = entry.object_id.raw(),
                .from_device = from_device,
                .to_device = to_device,
                .personal_e2ee = policy.personal_e2ee,
            });
            if (result.transferred) summary.secret_transfer_count += 1;
        },
        .transactional_contract => {
            const contract = service.findDatabaseContractForPath(workspace_id, entry.pathSlice()) orelse return error.DatabaseContractNotFound;
            const result = try service.database_sync_adapter.replicate(.{
                .contract = contract,
                .workspace_id = workspace_id,
                .from_device = from_device,
                .to_device = to_device,
            });
            if (result.transactional_contract) summary.transactional_count += 1;
        },
    }
}

pub fn applyInboundSemantic(
    service: anytype,
    store: *const storage_service.Service,
    entry: workspace.Entry,
    request: TransportFrameRequest,
    policy: *const WorkspacePolicy,
    semantic: SyncSemantic,
) Error!void {
    switch (semantic) {
        .mergeable_crdt => _ = try service.mergeable_document_adapter.merge(.{
            .store = store,
            .entry = entry,
            .remote_version_id = request.version_id,
        }),
        .chunked_snapshot => _ = try service.chunk_media_adapter.replicate(.{
            .store = store,
            .entry = entry,
        }),
        .secure_transfer => _ = try service.secret_transfer_adapter.transfer(.{
            .store = store,
            .workspace_id = request.workspace_id,
            .object_id = request.object_id,
            .from_device = request.source_device,
            .to_device = request.target_device,
            .personal_e2ee = policy.personal_e2ee,
        }),
        .transactional_contract => {
            const contract = service.findDatabaseContractForPath(request.workspace_id, entry.pathSlice()) orelse return error.DatabaseContractNotFound;
            _ = try service.database_sync_adapter.replicate(.{
                .contract = contract,
                .workspace_id = request.workspace_id,
                .from_device = request.source_device,
                .to_device = request.target_device,
            });
        },
    }
}
