pub const ProductCapacityEnvelope = struct {
    volume_image_bytes: usize,
    required_device_sectors: u64,
    max_volume_log_bytes: usize,
    max_object_payload_bytes: usize,
    max_object_records: usize,
    max_version_records: usize,
    max_blob_records: usize,
    max_blob_chunks_per_payload: usize,
    max_chunk_records: usize,
    max_chunk_bytes: usize,
    max_workspaces: usize,
    max_workspace_entries_per_workspace: usize,
    max_snapshots: usize,
    max_replay_log_records: usize,
    max_log_segments: usize,
};

pub const OverLimitWriteBehavior = enum(u8) {
    reject_without_partial_persistence,
};

pub const QuotaLimit = enum(u8) {
    object_payload_bytes,
    object_records,
    version_records,
    blob_records,
    chunk_records,
    workspaces,
    workspace_entries,
    snapshots,

    pub fn userVisibleCode(self: QuotaLimit) []const u8 {
        return switch (self) {
            .object_payload_bytes => "storage.quota.object_payload_bytes",
            .object_records => "storage.quota.object_records",
            .version_records => "storage.quota.version_records",
            .blob_records => "storage.quota.blob_records",
            .chunk_records => "storage.quota.chunk_records",
            .workspaces => "storage.quota.workspaces",
            .workspace_entries => "storage.quota.workspace_entries",
            .snapshots => "storage.quota.snapshots",
        };
    }
};

pub const ProductCapacityUsage = struct {
    object_payload_bytes: usize = 0,
    object_records: usize = 0,
    version_records: usize = 0,
    blob_records: usize = 0,
    chunk_records: usize = 0,
    workspaces: usize = 0,
    max_workspace_entries: usize = 0,
    snapshots: usize = 0,
};

pub const QuotaRejection = struct {
    limit: QuotaLimit,
    used: usize,
    requested: usize,
    allowed: usize,

    pub fn userVisibleCode(self: QuotaRejection) []const u8 {
        return self.limit.userVisibleCode();
    }
};
