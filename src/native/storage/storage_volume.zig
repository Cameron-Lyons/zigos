const builtin = @import("builtin");
const std = @import("std");
const binary_cursor = @import("../core/binary_cursor.zig");
const ids = @import("../core/ids.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const workspace = @import("workspace.zig");

const ata_bridge = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn zigosStorageBootstrapAtaRead(
            device: *const anyopaque,
            start_lba: u64,
            buffer_ptr: [*]u8,
            buffer_len: usize,
        ) callconv(.c) bool;

        extern fn zigosStorageBootstrapAtaWrite(
            device: *const anyopaque,
            start_lba: u64,
            buffer_ptr: [*]const u8,
            buffer_len: usize,
        ) callconv(.c) bool;

        pub fn read(device: *const anyopaque, start_lba: u64, buffer: []u8) bool {
            return zigosStorageBootstrapAtaRead(device, start_lba, buffer.ptr, buffer.len);
        }

        pub fn write(device: *const anyopaque, start_lba: u64, buffer: []const u8) bool {
            return zigosStorageBootstrapAtaWrite(device, start_lba, buffer.ptr, buffer.len);
        }
    }
else
    struct {
        pub fn read(_: *const anyopaque, _: u64, _: []u8) bool {
            return false;
        }

        pub fn write(_: *const anyopaque, _: u64, _: []const u8) bool {
            return false;
        }
    };

pub const sector_size: usize = 512;
pub const slot_sectors: u32 = 512;
pub const slot_count: u32 = 2;
pub const header_sectors: u32 = 1;
pub const payload_sectors: u32 = slot_sectors - header_sectors;
pub const slot_bytes: usize = slot_sectors * sector_size;
pub const image_bytes: usize = slot_count * slot_bytes;
pub const max_payload_bytes: usize = payload_sectors * sector_size;
pub const required_device_sectors: u64 = slot_count * slot_sectors;
pub const max_signer_bytes: usize = 48;
const root_sector_count: u32 = 2;
const data_start_sector: u32 = root_sector_count;
const data_start_byte: usize = data_start_sector * sector_size;
const data_capacity_bytes: usize = image_bytes - data_start_byte;
const root_magic = "ZG4LOG1";
const root_format_version: u16 = 2;
const max_replay_log_records: u16 = 128;
const max_log_segments: u16 = 16;
const compaction_threshold_bytes: u32 = @intCast((data_capacity_bytes * 3) / 4);
const log_record_kind_bytes: usize = 1;
const log_record_payload_len_bytes: usize = 4;
const log_record_checksum_bytes: usize = 8;
const log_record_payload_len_offset: usize = log_record_kind_bytes;
const log_record_checksum_offset: usize = log_record_payload_len_offset + log_record_payload_len_bytes;
const log_record_header_len: usize = log_record_checksum_offset + log_record_checksum_bytes;

const payload_magic = "ZG4STATE";
const format_version: u16 = 6;

pub const Error = error{
    ChecksumMismatch,
    CorruptImage,
    ImageTooSmall,
    InvalidSignatureEncoding,
    MissingCheckpoint,
    NoSpaceLeft,
    UnsupportedVersion,
};

pub const PersistResult = struct {
    generation: u64,
};

pub const Backend = struct {
    sector_count: u64,
    read: *const fn (start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool,
    write: *const fn (start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool,
};

pub const Volume = struct {
    io_payload_buffer: [max_payload_bytes]u8 = undefined,
    io_log_buffer: [data_capacity_bytes]u8 = undefined,
    sector_buffer: [sector_size]u8 = [_]u8{0} ** sector_size,
    attached_backend_present: bool = false,
    attached_backend_sector_count: u64 = 0,
    attached_backend_read: *const fn (u64, [*]u8, usize) callconv(.c) bool = unattachedRead,
    attached_backend_write: *const fn (u64, [*]const u8, usize) callconv(.c) bool = unattachedWrite,
    attached_backend_kind: AttachedBackendKind = .none,
    attached_ata_device: ?*const anyopaque = null,
    version_signers: [object_store.MAX_VERSIONS][max_signer_bytes]u8 =
        [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** object_store.MAX_VERSIONS,
    snapshot_signers: [workspace.MAX_SNAPSHOTS][max_signer_bytes]u8 =
        [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** workspace.MAX_SNAPSHOTS,

    pub fn init() Volume {
        return .{};
    }

    pub fn attachBackend(self: *Volume, backend: Backend) void {
        self.attachBackendFns(backend.sector_count, backend.read, backend.write);
    }

    pub fn attachBackendFns(
        self: *Volume,
        sector_count: u64,
        read: *const fn (start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool,
        write: *const fn (start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool,
    ) void {
        self.attached_backend_present = true;
        self.attached_backend_sector_count = sector_count;
        self.attached_backend_read = read;
        self.attached_backend_write = write;
        self.attached_backend_kind = .generic;
        self.attached_ata_device = null;
    }

    pub fn attachAtaBootstrapDevice(self: *Volume, device: *const anyopaque, sector_count: u64) void {
        self.attached_backend_present = true;
        self.attached_backend_sector_count = sector_count;
        self.attached_backend_read = unattachedRead;
        self.attached_backend_write = unattachedWrite;
        self.attached_backend_kind = .ata_bootstrap;
        self.attached_ata_device = device;
    }

    pub fn clearAttachedBackend(self: *Volume) void {
        self.attached_backend_present = false;
        self.attached_backend_sector_count = 0;
        self.attached_backend_read = unattachedRead;
        self.attached_backend_write = unattachedWrite;
        self.attached_backend_kind = .none;
        self.attached_ata_device = null;
    }

    pub fn hasAttachedDevice(self: *const Volume) bool {
        return self.attached_backend_present;
    }

    pub fn adoptAttachedBackendFrom(self: *Volume, source: *const Volume) void {
        self.attached_backend_present = source.attached_backend_present;
        self.attached_backend_sector_count = source.attached_backend_sector_count;
        self.attached_backend_read = source.attached_backend_read;
        self.attached_backend_write = source.attached_backend_write;
        self.attached_backend_kind = source.attached_backend_kind;
        self.attached_ata_device = source.attached_ata_device;
    }

    pub fn clearAttachedVolume(self: *Volume) void {
        if (!self.hasAttachedDevice()) return;
        if (self.attached_backend_sector_count < required_device_sectors) return;
        @memset(self.sector_buffer[0..], 0);
        var sector_index: u32 = 0;
        while (sector_index < root_sector_count) : (sector_index += 1) {
            if (!writeAttachedRange(self, sector_index, self.sector_buffer[0..])) return;
        }
    }

    pub fn loadFromVolume(self: *Volume, store: *object_store.Store, workspaces: *workspace.Directory) bool {
        if (!self.hasAttachedDevice()) return false;
        if (self.attached_backend_sector_count < required_device_sectors) return false;

        const loaded = (findLatestBackendRoot(self) catch return false) orelse return false;
        if (loaded.root.log_bytes == 0 or loaded.root.log_bytes > data_capacity_bytes) return false;
        if (!readAttachedBytes(self, data_start_byte, self.io_log_buffer[0..loaded.root.log_bytes])) return false;
        replayLog(self, store, workspaces, self.io_log_buffer[0..loaded.root.log_bytes], loaded.root) catch return false;
        store.clearDirty();
        workspaces.clearDirty();
        return true;
    }

    pub fn saveToVolume(self: *Volume, store: *object_store.Store, workspaces: *workspace.Directory) !PersistResult {
        if (!self.hasAttachedDevice()) return .{ .generation = 0 };
        if (self.attached_backend_sector_count < required_device_sectors) return error.ImageTooSmall;

        const current = findLatestBackendRoot(self) catch null;
        return saveIncremental(self, current, store, workspaces, BackendWriteFns{ .volume = self });
    }

    pub fn saveToImage(self: *Volume, image: []u8, store: *object_store.Store, workspaces: *workspace.Directory) !PersistResult {
        if (image.len < image_bytes) return error.ImageTooSmall;
        const current = findLatestImageRoot(image) catch null;
        return saveIncremental(self, current, store, workspaces, ImageWriteFns{ .image = image });
    }

    pub fn loadFromImage(self: *Volume, image: []const u8, store: *object_store.Store, workspaces: *workspace.Directory) !u64 {
        if (image.len < image_bytes) return error.ImageTooSmall;
        const loaded = (try findLatestImageRoot(image)) orelse return error.CorruptImage;
        if (loaded.root.log_bytes == 0 or loaded.root.log_bytes > data_capacity_bytes) return error.CorruptImage;
        @memcpy(self.io_log_buffer[0..loaded.root.log_bytes], image[data_start_byte .. data_start_byte + loaded.root.log_bytes]);
        try replayLog(self, store, workspaces, self.io_log_buffer[0..loaded.root.log_bytes], loaded.root);
        store.clearDirty();
        workspaces.clearDirty();
        return loaded.root.generation;
    }
};

var default_volume = Volume.init();

pub fn defaultVolume() *Volume {
    return &default_volume;
}

fn unattachedRead(_: u64, _: [*]u8, _: usize) callconv(.c) bool {
    return false;
}

fn unattachedWrite(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
    return false;
}

const CursorWriter = binary_cursor.Writer(Error, error.NoSpaceLeft);
const CursorReader = binary_cursor.Reader(Error, error.CorruptImage);

const WorkspaceSummary = struct {
    id: u64 = 0,
    generation: u32 = 0,
    state_hash: u64 = 0,
};

const RootState = struct {
    generation: u64 = 0,
    log_bytes: u32 = 0,
    next_object_id: u64 = 1,
    next_version_id: u64 = 1,
    next_workspace_id: u64 = 1,
    next_snapshot_id: u64 = 1,
    last_version_id: u64 = 0,
    last_snapshot_id: u64 = 0,
    log_record_count: u16 = 0,
    log_segment_count: u16 = 0,
    compacted_generation: u64 = 0,
    workspace_summary_count: usize = 0,
    workspace_summaries: [workspace.MAX_WORKSPACES]WorkspaceSummary =
        [_]WorkspaceSummary{WorkspaceSummary{}} ** workspace.MAX_WORKSPACES,
};

const LoadedRoot = struct {
    sector_index: u32,
    root: RootState,
};

const LogRecordKind = enum(u8) {
    checkpoint = 1,
    object_state = 2,
    version_state = 3,
    workspace_state = 4,
    snapshot_state = 5,
    blob_state = 6,
    chunk_state = 7,
    segment_boundary = 8,
};

const LogRecordHeader = struct {
    kind: LogRecordKind,
    payload_len: u32,
    checksum: u64,
};

const BuiltLog = struct {
    bytes_len: usize = 0,
    record_count: u16 = 0,
    segment_count: u16 = 0,
};

const AttachedBackendKind = enum(u8) {
    none,
    generic,
    ata_bootstrap,
};

pub fn attachBackend(backend: Backend) void {
    default_volume.attachBackend(backend);
}

pub fn attachBackendFns(
    sector_count: u64,
    read: *const fn (start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool,
    write: *const fn (start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool,
) void {
    default_volume.attachBackendFns(sector_count, read, write);
}

pub fn attachAtaBootstrapDevice(device: *const anyopaque, sector_count: u64) void {
    default_volume.attachAtaBootstrapDevice(device, sector_count);
}

pub fn clearAttachedBackend() void {
    default_volume.clearAttachedBackend();
}

pub fn hasAttachedDevice() bool {
    return default_volume.hasAttachedDevice();
}

pub fn clearAttachedVolume() void {
    default_volume.clearAttachedVolume();
}

pub fn loadFromVolume(store: *object_store.Store, workspaces: *workspace.Directory) bool {
    return default_volume.loadFromVolume(store, workspaces);
}

pub fn saveToVolume(store: *object_store.Store, workspaces: *workspace.Directory) !PersistResult {
    return default_volume.saveToVolume(store, workspaces);
}
pub fn saveToImage(image: []u8, store: *object_store.Store, workspaces: *workspace.Directory) !PersistResult {
    return default_volume.saveToImage(image, store, workspaces);
}

pub fn loadFromImage(image: []const u8, store: *object_store.Store, workspaces: *workspace.Directory) !u64 {
    return default_volume.loadFromImage(image, store, workspaces);
}

const BackendWriteFns = struct {
    volume: *Volume,
};

const ImageWriteFns = struct {
    image: []u8,
};

fn saveIncremental(
    self: *Volume,
    current: ?LoadedRoot,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
    writer: anytype,
) Error!PersistResult {
    const current_generation = if (current) |loaded| loaded.root.generation else 0;
    const delta = if (current) |loaded|
        try buildDeltaLog(self, self.io_log_buffer[0..], loaded.root, store, workspaces)
    else
        BuiltLog{};

    if (current != null and delta.bytes_len == 0) {
        store.clearDirty();
        workspaces.clearDirty();
        return .{ .generation = current_generation };
    }

    if (current != null and appendLogFits(current.?.root, delta)) {
        const next_generation = current_generation + 1;
        const next_log_bytes = current.?.root.log_bytes + @as(u32, @intCast(delta.bytes_len));
        var next_root = try buildRootState(self, next_generation, next_log_bytes, store, workspaces);
        next_root.log_record_count = current.?.root.log_record_count + delta.record_count;
        next_root.log_segment_count = current.?.root.log_segment_count + delta.segment_count;
        next_root.compacted_generation = current.?.root.compacted_generation;
        const next_root_sector = nextRootSector(current);
        try writeBytes(writer, data_start_byte + current.?.root.log_bytes, self.io_log_buffer[0..delta.bytes_len]);
        try writeRoot(writer, next_root_sector, next_root);
        store.clearDirty();
        workspaces.clearDirty();
        return .{ .generation = next_generation };
    }

    const checkpoint_payload_len = try serializeState(store, workspaces, self.io_payload_buffer[0..]);
    var log_writer = CursorWriter{ .buffer = self.io_log_buffer[0..] };
    try appendRecordPayload(&log_writer, .checkpoint, self.io_payload_buffer[0..checkpoint_payload_len]);

    const next_generation = current_generation + 1;
    var next_root = try buildRootState(self, next_generation, @intCast(log_writer.offset), store, workspaces);
    next_root.log_record_count = 1;
    next_root.log_segment_count = 0;
    next_root.compacted_generation = next_generation;
    const next_root_sector = nextRootSector(current);
    try writeBytes(writer, data_start_byte, self.io_log_buffer[0..log_writer.offset]);
    try writeRoot(writer, next_root_sector, next_root);
    store.clearDirty();
    workspaces.clearDirty();
    return .{ .generation = next_generation };
}

fn appendLogFits(root: RootState, delta: BuiltLog) bool {
    if (@as(usize, root.log_bytes) + delta.bytes_len > data_capacity_bytes) return false;
    if (root.log_bytes + @as(u32, @intCast(delta.bytes_len)) > compaction_threshold_bytes) return false;
    if (@as(u32, root.log_record_count) + delta.record_count > max_replay_log_records) return false;
    if (@as(u32, root.log_segment_count) + delta.segment_count > max_log_segments) return false;
    return true;
}

fn writeBytes(writer: anytype, offset: usize, bytes: []const u8) Error!void {
    switch (@TypeOf(writer)) {
        ImageWriteFns => {
            if (offset + bytes.len > writer.image.len) return error.ImageTooSmall;
            @memcpy(writer.image[offset .. offset + bytes.len], bytes);
        },
        BackendWriteFns => {
            if (!writeAttachedBytes(writer.volume, offset, bytes)) return error.CorruptImage;
        },
        else => @compileError("unsupported incremental writer"),
    }
}

fn writeRoot(writer: anytype, sector_index: u32, root: RootState) Error!void {
    switch (@TypeOf(writer)) {
        ImageWriteFns => try writeImageRoot(writer.image, sector_index, root),
        BackendWriteFns => try writeBackendRoot(writer.volume, sector_index, root),
        else => @compileError("unsupported root writer"),
    }
}

fn buildDeltaLog(
    self: *Volume,
    buffer: []u8,
    root: RootState,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
) Error!BuiltLog {
    var writer = CursorWriter{ .buffer = buffer };
    try appendRecordPayload(&writer, .segment_boundary, &.{});

    for (store.dirtyObjectIds()) |object_id| {
        const object_record = store.object(object_id) orelse continue;
        if (object_record.latest_version_id.raw() <= root.last_version_id) continue;
        try appendObjectRecord(&writer, object_record.*);
    }

    for (store.dirtyVersionIds()) |version_id| {
        const version_record = store.version(version_id) orelse continue;
        if (version_record.id.raw() <= root.last_version_id) continue;
        try appendVersionPayloadChunks(&writer, store, version_record);
        const blob = store.blob(version_record.blob_address) orelse return error.CorruptImage;
        try appendBlobRecord(&writer, blob.*);
        try appendVersionRecord(&writer, version_record.*);
    }

    for (workspaces.dirtyWorkspaceIds()) |workspace_id| {
        const workspace_record = workspaces.findConst(workspace_id) orelse continue;
        const summary = findWorkspaceSummary(root, workspace_record.id.raw());
        const state_hash = try workspaceStateHash(self, workspace_record);
        if (summary) |persisted| {
            if (persisted.generation == workspace_record.generation and persisted.state_hash == state_hash) continue;
        }
        try appendWorkspaceRecord(&writer, workspace_record.*);
    }

    for (workspaces.dirtySnapshotIds()) |snapshot_id| {
        const snapshot_record = findSnapshotConst(workspaces, snapshot_id) orelse continue;
        if (snapshot_record.id.raw() <= root.last_snapshot_id) continue;
        try appendSnapshotRecord(&writer, snapshot_record.*);
    }

    if (writer.offset == recordHeaderLen()) return .{};
    return .{
        .bytes_len = writer.offset,
        .record_count = countLogRecords(buffer[0..writer.offset]) catch return error.CorruptImage,
        .segment_count = 1,
    };
}

fn buildRootState(
    self: *Volume,
    generation: u64,
    log_bytes: u32,
    store: *const object_store.Store,
    workspaces: *const workspace.Directory,
) Error!RootState {
    var root = RootState{
        .generation = generation,
        .log_bytes = log_bytes,
        .next_object_id = store.next_object_id,
        .next_version_id = store.next_version_id,
        .next_workspace_id = workspaces.next_workspace_id,
        .next_snapshot_id = workspaces.next_snapshot_id,
        .last_version_id = if (store.next_version_id > 0) store.next_version_id - 1 else 0,
        .last_snapshot_id = if (workspaces.next_snapshot_id > 0) workspaces.next_snapshot_id - 1 else 0,
    };
    for (workspaces.workspaces.slots) |slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        root.workspace_summaries[root.workspace_summary_count] = .{
            .id = slot.workspace.id.raw(),
            .generation = slot.workspace.generation,
            .state_hash = try workspaceStateHash(self, &slot.workspace),
        };
        root.workspace_summary_count += 1;
    }
    return root;
}

fn findWorkspaceSummary(root: RootState, workspace_id: u64) ?WorkspaceSummary {
    var index: usize = 0;
    while (index < root.workspace_summary_count) : (index += 1) {
        const summary = root.workspace_summaries[index];
        if (summary.id == workspace_id) return summary;
    }
    return null;
}

fn workspaceStateHash(self: *Volume, record: *const workspace.WorkspaceRecord) Error!u64 {
    _ = self;
    var hash = native_util.FNV1A_64_OFFSET_BASIS;
    hash = hashBytes(hash, "workspace-state/v4");
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.id.raw());
    hash = hashPrincipal(hash, record.owner);
    hash = hashBytes(hash, record.labelSlice());
    hash = native_util.fnv1a64AppendU32LittleEndian(hash, record.generation);
    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intCast(record.path_index.entry_count));
    hash = hashBytes(hash, &record.path_index.root_address);

    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intCast(record.mutation_log.entry_mutation_count));
    for (record.mutation_log.entry_mutations[0..record.mutation_log.entry_mutation_count]) |mutation| {
        hash = native_util.fnv1a64AppendU32LittleEndian(hash, mutation.generation);
        hash = hashEntry(hash, mutation.entry);
    }

    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intCast(record.share_table.share_grant_count));
    for (record.share_table.share_grants[0..record.share_table.share_grant_count]) |grant| {
        hash = hashShareGrant(hash, grant);
    }

    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intCast(record.recoverable_deletes.deleted_count));
    for (record.recoverable_deletes.deleted_entries[0..record.recoverable_deletes.deleted_count]) |entry| {
        hash = hashEntry(hash, entry);
    }
    return hash;
}

fn replayLog(self: *Volume, store: *object_store.Store, workspaces: *workspace.Directory, log: []const u8, root: RootState) Error!void {
    store.reset();
    workspaces.reset();
    if (root.log_record_count == 0 or root.log_record_count > max_replay_log_records) return error.CorruptImage;
    if (root.log_segment_count > max_log_segments) return error.CorruptImage;

    var reader = CursorReader{ .buffer = log };
    var saw_checkpoint = false;
    var replayed_records: u16 = 0;
    var replayed_segments: u16 = 0;
    while (reader.offset < reader.buffer.len) {
        const header = try readRecordHeader(&reader);
        const payload = try reader.readSlice(header.payload_len);
        if (checksumBytes(payload) != header.checksum) return error.ChecksumMismatch;
        replayed_records += 1;
        if (replayed_records > max_replay_log_records) return error.CorruptImage;

        switch (header.kind) {
            .checkpoint => {
                try deserializeState(self, store, workspaces, payload);
                saw_checkpoint = true;
            },
            .segment_boundary => {
                if (payload.len != 0) return error.CorruptImage;
                replayed_segments += 1;
                if (replayed_segments > max_log_segments) return error.CorruptImage;
            },
            .object_state => try applyObjectRecord(store, payload),
            .chunk_state => try applyChunkRecord(store, payload),
            .blob_state => try applyBlobRecord(store, payload),
            .version_state => try applyVersionRecord(self, store, payload),
            .workspace_state => try applyWorkspaceRecord(workspaces, payload),
            .snapshot_state => try applySnapshotRecord(self, workspaces, payload),
        }
    }
    if (!saw_checkpoint) return error.MissingCheckpoint;
    if (replayed_records != root.log_record_count) return error.CorruptImage;
    if (replayed_segments != root.log_segment_count) return error.CorruptImage;

    store.next_object_id = root.next_object_id;
    store.next_version_id = root.next_version_id;
    workspaces.next_workspace_id = root.next_workspace_id;
    workspaces.next_snapshot_id = root.next_snapshot_id;
    store.rebuildIndexes();
    workspaces.rebuildIndexes();
}

fn countLogRecords(log: []const u8) Error!u16 {
    var reader = CursorReader{ .buffer = log };
    var count: u16 = 0;
    while (reader.offset < reader.buffer.len) {
        const header = try readRecordHeader(&reader);
        _ = try reader.readSlice(header.payload_len);
        count += 1;
    }
    return count;
}

fn appendObjectRecord(writer: *CursorWriter, record: object_store.ObjectRecord) Error!void {
    const header_offset = try beginRecord(writer, .object_state);
    try encodeObjectBody(writer, record);
    try finishRecord(writer, header_offset);
}

fn appendVersionRecord(writer: *CursorWriter, record: object_store.VersionRecord) Error!void {
    const header_offset = try beginRecord(writer, .version_state);
    try encodeVersionBody(writer, record);
    try finishRecord(writer, header_offset);
}

fn appendVersionPayloadChunks(
    writer: *CursorWriter,
    store: *object_store.Store,
    version_record: *const object_store.VersionRecord,
) Error!void {
    var cursor = store.versionChunkCursor(version_record) catch return error.CorruptImage;
    while (cursor.next() catch return error.CorruptImage) |chunk| {
        try appendPayloadChunkRecord(writer, chunk);
    }
}

fn appendWorkspaceRecord(writer: *CursorWriter, record: workspace.WorkspaceRecord) Error!void {
    const header_offset = try beginRecord(writer, .workspace_state);
    try encodeWorkspaceBody(writer, record);
    try finishRecord(writer, header_offset);
}

fn appendSnapshotRecord(writer: *CursorWriter, record: workspace.SnapshotRecord) Error!void {
    const header_offset = try beginRecord(writer, .snapshot_state);
    try encodeSnapshotBody(writer, record);
    try finishRecord(writer, header_offset);
}

fn appendRecordPayload(writer: *CursorWriter, kind: LogRecordKind, payload: []const u8) Error!void {
    const header_offset = try beginRecord(writer, kind);
    try writer.writeBytes(payload);
    try finishRecord(writer, header_offset);
}

fn beginRecord(writer: *CursorWriter, kind: LogRecordKind) Error!usize {
    const header_offset = writer.offset;
    try writer.writeByte(@intFromEnum(kind));
    try writer.writeU32(0);
    try writer.writeU64(0);
    return header_offset;
}

fn finishRecord(writer: *CursorWriter, header_offset: usize) Error!void {
    const payload_offset = header_offset + recordHeaderLen();
    const payload_len = writer.offset - payload_offset;
    const checksum = checksumBytes(writer.buffer[payload_offset..writer.offset]);
    const payload_len_offset = header_offset + log_record_payload_len_offset;
    const checksum_offset = header_offset + log_record_checksum_offset;
    writeU32At(writer.buffer[payload_len_offset..checksum_offset], @intCast(payload_len));
    writeU64At(writer.buffer[checksum_offset .. header_offset + recordHeaderLen()], checksum);
}

fn recordHeaderLen() usize {
    return log_record_header_len;
}

fn readRecordHeader(reader: *CursorReader) Error!LogRecordHeader {
    return .{
        .kind = try parseLogRecordKind(try reader.readByte()),
        .payload_len = try reader.readU32(),
        .checksum = try reader.readU64(),
    };
}

fn parseLogRecordKind(value: u8) Error!LogRecordKind {
    return switch (value) {
        @intFromEnum(LogRecordKind.checkpoint) => .checkpoint,
        @intFromEnum(LogRecordKind.object_state) => .object_state,
        @intFromEnum(LogRecordKind.version_state) => .version_state,
        @intFromEnum(LogRecordKind.workspace_state) => .workspace_state,
        @intFromEnum(LogRecordKind.snapshot_state) => .snapshot_state,
        @intFromEnum(LogRecordKind.blob_state) => .blob_state,
        @intFromEnum(LogRecordKind.chunk_state) => .chunk_state,
        @intFromEnum(LogRecordKind.segment_boundary) => .segment_boundary,
        else => error.CorruptImage,
    };
}

fn encodeObjectBody(writer: *CursorWriter, record: object_store.ObjectRecord) Error!void {
    try writer.writeU64(record.id.raw());
    try writer.writeByte(@intFromEnum(record.object_type));
    try writer.writeU64(record.latest_version_id.raw());
    try writer.writeU16(record.version_count);
}

fn encodeVersionBody(writer: *CursorWriter, record: object_store.VersionRecord) Error!void {
    try writer.writeU64(record.id.raw());
    try writer.writeU64(record.object_id.raw());
    try writer.writeU64(record.previous_version_id.raw());
    try writer.writeByte(record.parent_count);
    var parent_index: usize = 0;
    while (parent_index < object_store.MAX_VERSION_PARENTS) : (parent_index += 1) {
        try writer.writeU64(record.parent_version_ids[parent_index].raw());
    }
    try writer.writeByte(@intFromEnum(record.object_type));
    try writer.writeBytes(&record.blob_address);
    try writer.writeBytes(&record.version_address);
    try writeMetadata(writer, record.metadata);
    try writer.writeU32(@intCast(record.payload_len));
    try writer.writeU16(record.chunk_count);
}

fn appendBlobRecord(writer: *CursorWriter, record: object_store.BlobRecord) Error!void {
    const header_offset = try beginRecord(writer, .blob_state);
    try encodeBlobBody(writer, record);
    try finishRecord(writer, header_offset);
}

fn appendPayloadChunkRecord(writer: *CursorWriter, chunk: object_store.PayloadChunk) Error!void {
    const header_offset = try beginRecord(writer, .chunk_state);
    try writer.writeBytes(&chunk.address);
    try writer.writeU16(@intCast(chunk.bytes.len));
    try writer.writeBytes(chunk.bytes);
    try finishRecord(writer, header_offset);
}

fn encodeBlobBody(writer: *CursorWriter, record: object_store.BlobRecord) Error!void {
    try writer.writeBytes(&record.address);
    try writer.writeBytes(&record.merkle_root);
    try writer.writeU32(@intCast(record.payload_len));
    try writer.writeU16(record.ref_count);
    try writer.writeU16(record.chunk_count);
    const chunk_count: usize = @intCast(record.chunk_count);
    for (record.chunks[0..chunk_count]) |chunk_ref| {
        try writer.writeBytes(&chunk_ref.address);
        try writer.writeU16(chunk_ref.payload_len);
    }
}

fn encodeChunkBody(writer: *CursorWriter, record: object_store.ChunkRecord) Error!void {
    try writer.writeBytes(&record.address);
    try writer.writeU16(record.payload_len);
    try writer.writeBytes(record.chunkSlice());
}

fn encodeWorkspaceBody(writer: *CursorWriter, record: workspace.WorkspaceRecord) Error!void {
    try writer.writeU64(record.id.raw());
    try writePrincipal(writer, record.owner);
    try writeText(writer, record.labelSlice());
    try writer.writeU32(record.generation);
    try writer.writeU16(@intCast(record.path_index.entry_count));
    for (record.path_index.entries[0..record.path_index.entry_count]) |entry| {
        try writeEntry(writer, entry);
    }
    try writer.writeU16(@intCast(record.mutation_log.entry_mutation_count));
    for (record.mutation_log.entry_mutations[0..record.mutation_log.entry_mutation_count]) |mutation| {
        try writer.writeU32(mutation.generation);
        try writeEntry(writer, mutation.entry);
    }
    try writer.writeU16(@intCast(record.share_table.share_grant_count));
    for (record.share_table.share_grants[0..record.share_table.share_grant_count]) |grant| {
        try writeShareGrant(writer, grant);
    }
    try writer.writeU16(@intCast(record.recoverable_deletes.deleted_count));
    for (record.recoverable_deletes.deleted_entries[0..record.recoverable_deletes.deleted_count]) |entry| {
        try writeEntry(writer, entry);
    }
}

fn encodeSnapshotBody(writer: *CursorWriter, record: workspace.SnapshotRecord) Error!void {
    try writer.writeU64(record.id.raw());
    try writer.writeU64(record.workspace_id.raw());
    try writer.writeU32(record.generation);
    try writeText(writer, record.labelSlice());
    try writer.writeBytes(&record.root_address);
    try writeSignature(writer, record.signature);
    try writer.writeU16(@intCast(record.entry_count));
}

fn applyObjectRecord(store: *object_store.Store, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const object_id = ids.object(try reader.readU64());
    const object_type = try parseObjectType(try reader.readByte());
    const latest_version_id = ids.version(try reader.readU64());
    const version_count = try reader.readU16();

    if (store.object(object_id)) |record| {
        record.object_type = object_type;
        record.latest_version_id = latest_version_id;
        record.version_count = version_count;
        return;
    }

    const slot = store.objects.reserve(object_id) orelse return error.CorruptImage;
    slot.object = .{
        .id = object_id,
        .object_type = object_type,
        .latest_version_id = latest_version_id,
        .version_count = version_count,
    };
}

fn applyVersionRecord(self: *Volume, store: *object_store.Store, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const version_id = ids.version(try reader.readU64());
    const slot_index = store.versions.reserveIndex(version_id) orelse return error.CorruptImage;
    store.versions.slots[slot_index].version.id = version_id;
    store.versions.slots[slot_index].version.object_id = ids.object(try reader.readU64());
    store.versions.slots[slot_index].version.previous_version_id = ids.version(try reader.readU64());
    store.versions.slots[slot_index].version.parent_count = try reader.readByte();
    if (store.versions.slots[slot_index].version.parent_count > object_store.MAX_VERSION_PARENTS) return error.CorruptImage;
    var parent_index: usize = 0;
    while (parent_index < object_store.MAX_VERSION_PARENTS) : (parent_index += 1) {
        store.versions.slots[slot_index].version.parent_version_ids[parent_index] = ids.version(try reader.readU64());
    }
    store.versions.slots[slot_index].version.object_type = try parseObjectType(try reader.readByte());
    try reader.readBytes(&store.versions.slots[slot_index].version.blob_address);
    try reader.readBytes(&store.versions.slots[slot_index].version.version_address);
    store.versions.slots[slot_index].version.metadata = try readMetadata(&reader, &self.version_signers[slot_index]);
    store.versions.slots[slot_index].version.payload_len = @intCast(try reader.readU32());
    if (store.versions.slots[slot_index].version.payload_len > object_store.MAX_PAYLOAD_BYTES) return error.CorruptImage;
    store.versions.slots[slot_index].version.chunk_count = try reader.readU16();
    store.versions.slots[slot_index].version.blob_slot_index = findBlobSlotIndex(store, store.versions.slots[slot_index].version.blob_address) orelse return error.CorruptImage;
}

fn applyBlobRecord(store: *object_store.Store, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    var address: object_store.BlobAddress = undefined;
    try reader.readBytes(&address);
    var merkle_root: object_store.BlobAddress = undefined;
    try reader.readBytes(&merkle_root);
    const payload_len: usize = @intCast(try reader.readU32());
    const ref_count = try reader.readU16();
    const chunk_count: usize = @intCast(try reader.readU16());
    if (payload_len > object_store.MAX_PAYLOAD_BYTES or chunk_count > object_store.MAX_BLOB_CHUNKS) return error.CorruptImage;
    var chunk_refs = [_]object_store.ChunkRef{object_store.ChunkRef{}} ** object_store.MAX_BLOB_CHUNKS;
    var chunk_index: usize = 0;
    while (chunk_index < chunk_count) : (chunk_index += 1) {
        try reader.readBytes(&chunk_refs[chunk_index].address);
        chunk_refs[chunk_index].payload_len = try reader.readU16();
        chunk_refs[chunk_index].slot_index = store.chunkSlotIndex(chunk_refs[chunk_index].address) orelse return error.CorruptImage;
    }
    if (!std.mem.eql(u8, &object_store.computeBlobMerkleRoot(chunk_refs[0..chunk_count]), &merkle_root)) return error.CorruptImage;
    if (!std.mem.eql(u8, &object_store.computeBlobManifestAddress(payload_len, chunk_refs[0..chunk_count]), &address)) return error.CorruptImage;
    const slot_index = if (store.blobSlotIndex(address)) |existing_index|
        existing_index
    else
        store.reserveBlobSlot(address) orelse return error.CorruptImage;
    const slot = store.blobSlotAt(slot_index);
    slot.blob.address = address;
    slot.blob.merkle_root = merkle_root;
    slot.blob.payload_len = payload_len;
    slot.blob.ref_count = ref_count;
    slot.blob.chunk_count = @intCast(chunk_count);
    slot.blob.chunks = chunk_refs;
    slot.blob.manifest_verified = false;
}

fn applyChunkRecord(store: *object_store.Store, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    var address: object_store.ChunkAddress = undefined;
    try reader.readBytes(&address);
    const payload_len: usize = @intCast(try reader.readU16());
    if (payload_len > object_store.MAX_CHUNK_BYTES) return error.CorruptImage;
    var bytes: [object_store.MAX_CHUNK_BYTES]u8 = [_]u8{0} ** object_store.MAX_CHUNK_BYTES;
    try reader.readBytes(bytes[0..payload_len]);
    _ = store.putChunk(address, bytes[0..payload_len]) catch return error.CorruptImage;
}

fn applyWorkspaceRecord(workspaces: *workspace.Directory, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const workspace_id = ids.workspace(try reader.readU64());
    const slot = findWorkspaceSlotById(workspaces, workspace_id) orelse
        workspaces.workspaces.reserve(workspace_id) orelse return error.CorruptImage;
    slot.workspace = zeroWorkspaceRecord();
    slot.workspace.id = workspace_id;
    slot.workspace.owner = try readPrincipal(&reader);
    readTextInto(&reader, &slot.workspace.label, &slot.workspace.label_len) catch return error.CorruptImage;
    slot.workspace.generation = try reader.readU32();
    slot.workspace.path_index.entry_count = @intCast(try reader.readU16());
    if (slot.workspace.path_index.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
    for (0..slot.workspace.path_index.entry_count) |entry_index| {
        slot.workspace.path_index.entries[entry_index] = try readEntry(&reader);
    }
    slot.workspace.mutation_log.entry_mutation_count = @intCast(try reader.readU16());
    if (slot.workspace.mutation_log.entry_mutation_count > workspace.MAX_WORKSPACE_ENTRY_MUTATIONS) return error.CorruptImage;
    for (0..slot.workspace.mutation_log.entry_mutation_count) |mutation_index| {
        slot.workspace.mutation_log.entry_mutations[mutation_index] = .{
            .generation = try reader.readU32(),
            .entry = try readEntry(&reader),
        };
    }
    slot.workspace.share_table.share_grant_count = @intCast(try reader.readU16());
    if (slot.workspace.share_table.share_grant_count > workspace.MAX_SHARE_GRANTS) return error.CorruptImage;
    for (0..slot.workspace.share_table.share_grant_count) |grant_index| {
        slot.workspace.share_table.share_grants[grant_index] = try readShareGrant(&reader);
    }
    slot.workspace.recoverable_deletes.deleted_count = @intCast(try reader.readU16());
    if (slot.workspace.recoverable_deletes.deleted_count > workspace.MAX_RECOVERABLE_DELETES) return error.CorruptImage;
    for (0..slot.workspace.recoverable_deletes.deleted_count) |entry_index| {
        slot.workspace.recoverable_deletes.deleted_entries[entry_index] = try readEntry(&reader);
    }
}

fn applySnapshotRecord(self: *Volume, workspaces: *workspace.Directory, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const snapshot_id = ids.snapshot(try reader.readU64());
    const slot_index = findSnapshotSlotIndexById(workspaces, snapshot_id) orelse
        workspaces.snapshots.reserveIndex(snapshot_id) orelse return error.CorruptImage;
    workspaces.snapshots.slots[slot_index].snapshot = zeroSnapshotRecord();
    workspaces.snapshots.slots[slot_index].snapshot.id = snapshot_id;
    workspaces.snapshots.slots[slot_index].snapshot.workspace_id = ids.workspace(try reader.readU64());
    workspaces.snapshots.slots[slot_index].snapshot.generation = try reader.readU32();
    readTextInto(&reader, &workspaces.snapshots.slots[slot_index].snapshot.label, &workspaces.snapshots.slots[slot_index].snapshot.label_len) catch return error.CorruptImage;
    try reader.readBytes(&workspaces.snapshots.slots[slot_index].snapshot.root_address);
    workspaces.snapshots.slots[slot_index].snapshot.signature = try readSignature(&reader, &self.snapshot_signers[slot_index]);
    workspaces.snapshots.slots[slot_index].snapshot.entry_count = @intCast(try reader.readU16());
    if (workspaces.snapshots.slots[slot_index].snapshot.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
}

fn findWorkspaceSlotById(workspaces: *workspace.Directory, workspace_id: ids.WorkspaceId) ?*@TypeOf(workspaces.workspaces.slots[0]) {
    for (&workspaces.workspaces.slots) |*slot| {
        if (slot.in_use and slot.workspace.id.eql(workspace_id)) return slot;
    }
    return null;
}

fn findSnapshotSlotIndexById(workspaces: *workspace.Directory, snapshot_id: ids.SnapshotId) ?usize {
    for (workspaces.snapshots.slots, 0..) |slot, index| {
        if (slot.in_use and slot.snapshot.id.eql(snapshot_id)) return index;
    }
    return null;
}

fn findSnapshotConst(workspaces: *const workspace.Directory, snapshot_id: ids.SnapshotId) ?*const workspace.SnapshotRecord {
    for (&workspaces.snapshots.slots) |*slot| {
        if (slot.in_use and slot.snapshot.id.eql(snapshot_id)) return &slot.snapshot;
    }
    return null;
}

fn indexIdForBytes(bytes: []const u8) u64 {
    const id = native_util.fnv1a64(bytes);
    return if (id == 0) 1 else id;
}

fn serializeState(store: *const object_store.Store, workspaces: *const workspace.Directory, buffer: []u8) Error!usize {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(payload_magic);
    try writer.writeU16(format_version);
    try writer.writeU64(store.next_object_id);
    try writer.writeU64(store.next_version_id);
    try writer.writeU16(@intCast(store.objectCount()));
    try writer.writeU16(@intCast(store.versionCount()));
    try writer.writeU16(@intCast(store.blobCount()));
    try writer.writeU16(@intCast(store.chunkCount()));
    try writer.writeU64(workspaces.next_workspace_id);
    try writer.writeU64(workspaces.next_snapshot_id);
    try writer.writeU16(@intCast(workspaceCount(workspaces)));
    try writer.writeU16(@intCast(snapshotCount(workspaces)));

    for (store.objects.slots) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.object.id.raw());
        try writer.writeByte(@intFromEnum(slot.object.object_type));
        try writer.writeU64(slot.object.latest_version_id.raw());
        try writer.writeU16(slot.object.version_count);
    }

    var chunk_slot_index: usize = 0;
    while (chunk_slot_index < store.chunkSlotCapacity()) : (chunk_slot_index += 1) {
        const slot = store.chunkSlotAtConst(chunk_slot_index).*;
        if (!slot.in_use) continue;
        try encodeChunkBody(&writer, slot.chunk);
    }

    var blob_slot_index: usize = 0;
    while (blob_slot_index < store.blobSlotCapacity()) : (blob_slot_index += 1) {
        const slot = store.blobSlotAtConst(blob_slot_index).*;
        if (!slot.in_use) continue;
        try encodeBlobBody(&writer, slot.blob);
    }

    for (store.versions.slots) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.version.id.raw());
        try writer.writeU64(slot.version.object_id.raw());
        try writer.writeU64(slot.version.previous_version_id.raw());
        try writer.writeByte(slot.version.parent_count);
        var parent_index: usize = 0;
        while (parent_index < object_store.MAX_VERSION_PARENTS) : (parent_index += 1) {
            try writer.writeU64(slot.version.parent_version_ids[parent_index].raw());
        }
        try writer.writeByte(@intFromEnum(slot.version.object_type));
        try writer.writeBytes(&slot.version.blob_address);
        try writer.writeBytes(&slot.version.version_address);
        try writeMetadata(&writer, slot.version.metadata);
        try writer.writeU32(@intCast(slot.version.payload_len));
        try writer.writeU16(slot.version.chunk_count);
    }

    for (workspaces.workspaces.slots) |slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        try writer.writeU64(slot.workspace.id.raw());
        try writePrincipal(&writer, slot.workspace.owner);
        try writeText(&writer, slot.workspace.labelSlice());
        try writer.writeU32(slot.workspace.generation);
        try writer.writeU16(@intCast(slot.workspace.path_index.entry_count));
        for (slot.workspace.path_index.entries[0..slot.workspace.path_index.entry_count]) |entry| {
            try writeEntry(&writer, entry);
        }
        try writer.writeU16(@intCast(slot.workspace.mutation_log.entry_mutation_count));
        for (slot.workspace.mutation_log.entry_mutations[0..slot.workspace.mutation_log.entry_mutation_count]) |mutation| {
            try writer.writeU32(mutation.generation);
            try writeEntry(&writer, mutation.entry);
        }
        try writer.writeU16(@intCast(slot.workspace.share_table.share_grant_count));
        for (slot.workspace.share_table.share_grants[0..slot.workspace.share_table.share_grant_count]) |grant| {
            try writeShareGrant(&writer, grant);
        }
        try writer.writeU16(@intCast(slot.workspace.recoverable_deletes.deleted_count));
        for (slot.workspace.recoverable_deletes.deleted_entries[0..slot.workspace.recoverable_deletes.deleted_count]) |entry| {
            try writeEntry(&writer, entry);
        }
    }

    for (workspaces.snapshots.slots) |slot| {
        if (!persistableSnapshotSlot(slot)) continue;
        try writer.writeU64(slot.snapshot.id.raw());
        try writer.writeU64(slot.snapshot.workspace_id.raw());
        try writer.writeU32(slot.snapshot.generation);
        try writeText(&writer, slot.snapshot.labelSlice());
        try writer.writeBytes(&slot.snapshot.root_address);
        try writeSignature(&writer, slot.snapshot.signature);
        try writer.writeU16(@intCast(slot.snapshot.entry_count));
    }

    return writer.offset;
}

fn deserializeState(self: *Volume, store: *object_store.Store, workspaces: *workspace.Directory, payload: []const u8) Error!void {
    store.reset();
    workspaces.reset();

    var reader = CursorReader{ .buffer = payload };
    var payload_magic_bytes: [payload_magic.len]u8 = undefined;
    try reader.readBytes(&payload_magic_bytes);
    if (!std.mem.eql(u8, &payload_magic_bytes, payload_magic)) return error.CorruptImage;
    if ((try reader.readU16()) != format_version) return error.UnsupportedVersion;

    store.next_object_id = try reader.readU64();
    store.next_version_id = try reader.readU64();
    const object_count = try reader.readU16();
    const version_count = try reader.readU16();
    const blob_count = try reader.readU16();
    const chunk_count = try reader.readU16();
    workspaces.next_workspace_id = try reader.readU64();
    workspaces.next_snapshot_id = try reader.readU64();
    const workspace_count_value = try reader.readU16();
    const snapshot_count_value = try reader.readU16();

    if (object_count > object_store.MAX_OBJECTS or
        version_count > object_store.MAX_VERSIONS or
        blob_count > object_store.MAX_BLOBS or
        chunk_count > object_store.MAX_CHUNKS or
        workspace_count_value > workspace.MAX_WORKSPACES or
        snapshot_count_value > workspace.MAX_SNAPSHOTS)
    {
        return error.CorruptImage;
    }

    for (0..@as(usize, object_count)) |_| {
        const object_id = ids.object(try reader.readU64());
        const slot = store.objects.reserve(object_id) orelse return error.CorruptImage;
        slot.object.id = object_id;
        slot.object.object_type = try parseObjectType(try reader.readByte());
        slot.object.latest_version_id = ids.version(try reader.readU64());
        slot.object.version_count = try reader.readU16();
    }

    for (0..@as(usize, chunk_count)) |_| {
        var address: object_store.ChunkAddress = undefined;
        try reader.readBytes(&address);
        const payload_len: usize = @intCast(try reader.readU16());
        if (payload_len > object_store.MAX_CHUNK_BYTES) return error.CorruptImage;
        var bytes: [object_store.MAX_CHUNK_BYTES]u8 = [_]u8{0} ** object_store.MAX_CHUNK_BYTES;
        try reader.readBytes(bytes[0..payload_len]);
        _ = store.putChunk(address, bytes[0..payload_len]) catch return error.CorruptImage;
    }

    for (0..@as(usize, blob_count)) |_| {
        const payload_start = reader.offset;
        var address: object_store.BlobAddress = undefined;
        try reader.readBytes(&address);
        var merkle_root: object_store.BlobAddress = undefined;
        try reader.readBytes(&merkle_root);
        const payload_len: usize = @intCast(try reader.readU32());
        _ = try reader.readU16();
        const chunk_ref_count: usize = @intCast(try reader.readU16());
        if (payload_len > object_store.MAX_PAYLOAD_BYTES or chunk_ref_count > object_store.MAX_BLOB_CHUNKS) return error.CorruptImage;
        const payload_end = payload_start + 32 + 32 + 4 + 2 + 2 + chunk_ref_count * (32 + 2);
        if (payload_end > reader.buffer.len) return error.CorruptImage;
        reader.offset = payload_start;
        try applyBlobRecord(store, reader.buffer[payload_start..payload_end]);
        reader.offset = payload_end;
    }

    for (0..@as(usize, version_count)) |_| {
        const version_id = ids.version(try reader.readU64());
        const slot_index = store.versions.reserveIndex(version_id) orelse return error.CorruptImage;
        store.versions.slots[slot_index].version.id = version_id;
        store.versions.slots[slot_index].version.object_id = ids.object(try reader.readU64());
        store.versions.slots[slot_index].version.previous_version_id = ids.version(try reader.readU64());
        store.versions.slots[slot_index].version.parent_count = try reader.readByte();
        if (store.versions.slots[slot_index].version.parent_count > object_store.MAX_VERSION_PARENTS) return error.CorruptImage;
        var parent_index: usize = 0;
        while (parent_index < object_store.MAX_VERSION_PARENTS) : (parent_index += 1) {
            store.versions.slots[slot_index].version.parent_version_ids[parent_index] = ids.version(try reader.readU64());
        }
        store.versions.slots[slot_index].version.object_type = try parseObjectType(try reader.readByte());
        try reader.readBytes(&store.versions.slots[slot_index].version.blob_address);
        try reader.readBytes(&store.versions.slots[slot_index].version.version_address);
        store.versions.slots[slot_index].version.metadata = try readMetadata(&reader, &self.version_signers[slot_index]);
        store.versions.slots[slot_index].version.payload_len = @intCast(try reader.readU32());
        if (store.versions.slots[slot_index].version.payload_len > object_store.MAX_PAYLOAD_BYTES) return error.CorruptImage;
        store.versions.slots[slot_index].version.chunk_count = try reader.readU16();
        store.versions.slots[slot_index].version.blob_slot_index = findBlobSlotIndex(store, store.versions.slots[slot_index].version.blob_address) orelse return error.CorruptImage;
    }

    for (0..@as(usize, workspace_count_value)) |_| {
        const workspace_id = ids.workspace(try reader.readU64());
        const slot = workspaces.workspaces.reserve(workspace_id) orelse return error.CorruptImage;
        slot.workspace = zeroWorkspaceRecord();
        slot.workspace.id = workspace_id;
        slot.workspace.owner = try readPrincipal(&reader);
        readTextInto(&reader, &slot.workspace.label, &slot.workspace.label_len) catch return error.CorruptImage;
        slot.workspace.generation = try reader.readU32();
        slot.workspace.path_index.entry_count = @intCast(try reader.readU16());
        if (slot.workspace.path_index.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
        for (0..slot.workspace.path_index.entry_count) |entry_index| {
            slot.workspace.path_index.entries[entry_index] = try readEntry(&reader);
        }
        slot.workspace.mutation_log.entry_mutation_count = @intCast(try reader.readU16());
        if (slot.workspace.mutation_log.entry_mutation_count > workspace.MAX_WORKSPACE_ENTRY_MUTATIONS) return error.CorruptImage;
        for (0..slot.workspace.mutation_log.entry_mutation_count) |mutation_index| {
            slot.workspace.mutation_log.entry_mutations[mutation_index] = .{
                .generation = try reader.readU32(),
                .entry = try readEntry(&reader),
            };
        }
        slot.workspace.share_table.share_grant_count = @intCast(try reader.readU16());
        if (slot.workspace.share_table.share_grant_count > workspace.MAX_SHARE_GRANTS) return error.CorruptImage;
        for (0..slot.workspace.share_table.share_grant_count) |grant_index| {
            slot.workspace.share_table.share_grants[grant_index] = try readShareGrant(&reader);
        }
        slot.workspace.recoverable_deletes.deleted_count = @intCast(try reader.readU16());
        if (slot.workspace.recoverable_deletes.deleted_count > workspace.MAX_RECOVERABLE_DELETES) return error.CorruptImage;
        for (0..slot.workspace.recoverable_deletes.deleted_count) |entry_index| {
            slot.workspace.recoverable_deletes.deleted_entries[entry_index] = try readEntry(&reader);
        }
    }

    for (0..@as(usize, snapshot_count_value)) |_| {
        const snapshot_id = ids.snapshot(try reader.readU64());
        const slot_index = workspaces.snapshots.reserveIndex(snapshot_id) orelse return error.CorruptImage;
        workspaces.snapshots.slots[slot_index].snapshot = zeroSnapshotRecord();
        workspaces.snapshots.slots[slot_index].snapshot.id = snapshot_id;
        workspaces.snapshots.slots[slot_index].snapshot.workspace_id = ids.workspace(try reader.readU64());
        workspaces.snapshots.slots[slot_index].snapshot.generation = try reader.readU32();
        readTextInto(&reader, &workspaces.snapshots.slots[slot_index].snapshot.label, &workspaces.snapshots.slots[slot_index].snapshot.label_len) catch return error.CorruptImage;
        try reader.readBytes(&workspaces.snapshots.slots[slot_index].snapshot.root_address);
        workspaces.snapshots.slots[slot_index].snapshot.signature = try readSignature(&reader, &self.snapshot_signers[slot_index]);
        workspaces.snapshots.slots[slot_index].snapshot.entry_count = @intCast(try reader.readU16());
        if (workspaces.snapshots.slots[slot_index].snapshot.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
    }

    store.rebuildIndexes();
    workspaces.rebuildIndexes();
}

fn writeMetadata(writer: *CursorWriter, metadata: object_store.SignedMetadata) Error!void {
    try writeText(writer, metadata.labelSlice());
    try writeText(writer, metadata.contentTypeSlice());
    try writer.writeU64(metadata.created_at_ticks);
    try writeSignature(writer, metadata.signature);
}

fn readMetadata(reader: *CursorReader, signer_storage: *[max_signer_bytes]u8) Error!object_store.SignedMetadata {
    var metadata = object_store.SignedMetadata{};
    readTextInto(reader, &metadata.label, &metadata.label_len) catch return error.CorruptImage;
    readTextInto(reader, &metadata.content_type, &metadata.content_type_len) catch return error.CorruptImage;
    metadata.created_at_ticks = try reader.readU64();
    metadata.signature = try readSignature(reader, signer_storage);
    return metadata;
}

fn writeSignature(writer: *CursorWriter, signature: anytype) Error!void {
    if (signature.isPresent()) {
        const signer = if (signature.signer.len <= max_signer_bytes)
            signature.signer
        else
            "invalid-signer";
        const public_key_len = @min(signature.public_key_len, signature.public_key.len);
        const value_len = @min(signature.value_len, signature.value.len);
        try writer.writeByte(1);
        try writeText(writer, signer);
        try writer.writeU16(@intCast(public_key_len));
        try writer.writeBytes(signature.public_key[0..public_key_len]);
        try writer.writeU16(@intCast(value_len));
        try writer.writeBytes(signature.value[0..value_len]);
        return;
    }
    try writer.writeByte(0);
}

fn readSignature(reader: *CursorReader, signer_storage: *[max_signer_bytes]u8) Error!@import("../policy/manifest.zig").Signature {
    const manifest = @import("../policy/manifest.zig");
    const present = try reader.readByte();
    if (present == 0) return .{};

    const signer_len = try reader.readU16();
    if (signer_len > max_signer_bytes) return error.InvalidSignatureEncoding;
    @memset(signer_storage[0..], 0);
    try reader.readBytes(signer_storage[0..signer_len]);

    var signature = manifest.Signature{
        .format = "ed25519",
        .signer = signer_storage[0..signer_len],
    };
    signature.public_key_len = try reader.readU16();
    if (signature.public_key_len > signature.public_key.len) return error.InvalidSignatureEncoding;
    try reader.readBytes(signature.public_key[0..signature.public_key_len]);
    signature.value_len = try reader.readU16();
    if (signature.value_len > signature.value.len) return error.InvalidSignatureEncoding;
    try reader.readBytes(signature.value[0..signature.value_len]);
    return signature;
}

fn writeText(writer: *CursorWriter, text: []const u8) Error!void {
    try writer.writeU16(@intCast(text.len));
    try writer.writeBytes(text);
}

fn readTextInto(reader: *CursorReader, buffer: []u8, out_len: *usize) Error!void {
    const len = try reader.readU16();
    if (len > buffer.len) return error.CorruptImage;
    @memset(buffer[0..], 0);
    try reader.readBytes(buffer[0..len]);
    out_len.* = len;
}

fn writePrincipal(writer: *CursorWriter, principal_id: principal.PrincipalId) Error!void {
    try writer.writeByte(@intFromEnum(principal_id.kind));
    try writer.writeU64(principal_id.serial);
}

fn readPrincipal(reader: *CursorReader) Error!principal.PrincipalId {
    return .{
        .kind = try parsePrincipalKind(try reader.readByte()),
        .serial = try reader.readU64(),
    };
}

fn writeEntry(writer: *CursorWriter, entry: workspace.Entry) Error!void {
    try writeText(writer, entry.pathSlice());
    try writer.writeU64(entry.object_id.raw());
    try writer.writeU64(entry.version_id.raw());
    try writer.writeByte(@intFromEnum(entry.object_type));
}

fn readEntry(reader: *CursorReader) Error!workspace.Entry {
    var entry = workspace.Entry{};
    readTextInto(reader, &entry.path, &entry.path_len) catch return error.CorruptImage;
    entry.object_id = ids.object(try reader.readU64());
    entry.version_id = ids.version(try reader.readU64());
    entry.object_type = try parseObjectType(try reader.readByte());
    return entry;
}

fn parseObjectType(value: u8) Error!object_store.ObjectType {
    return switch (value) {
        @intFromEnum(object_store.ObjectType.blob) => .blob,
        @intFromEnum(object_store.ObjectType.document) => .document,
        @intFromEnum(object_store.ObjectType.collection) => .collection,
        @intFromEnum(object_store.ObjectType.secret) => .secret,
        @intFromEnum(object_store.ObjectType.media_asset) => .media_asset,
        @intFromEnum(object_store.ObjectType.model_artifact) => .model_artifact,
        @intFromEnum(object_store.ObjectType.event_stream) => .event_stream,
        else => error.CorruptImage,
    };
}

fn parsePrincipalKind(value: u8) Error!principal.PrincipalKind {
    return switch (value) {
        @intFromEnum(principal.PrincipalKind.user) => .user,
        @intFromEnum(principal.PrincipalKind.team) => .team,
        @intFromEnum(principal.PrincipalKind.device) => .device,
        @intFromEnum(principal.PrincipalKind.app) => .app,
        @intFromEnum(principal.PrincipalKind.service) => .service,
        @intFromEnum(principal.PrincipalKind.policy_authority) => .policy_authority,
        else => error.CorruptImage,
    };
}

fn parseShareNetworkScope(value: u8) Error!workspace.ShareNetworkScope {
    return switch (value) {
        @intFromEnum(workspace.ShareNetworkScope.local_only) => .local_only,
        @intFromEnum(workspace.ShareNetworkScope.trusted_overlay) => .trusted_overlay,
        @intFromEnum(workspace.ShareNetworkScope.relay_assisted) => .relay_assisted,
        @intFromEnum(workspace.ShareNetworkScope.unrestricted) => .unrestricted,
        else => error.CorruptImage,
    };
}

fn parseResharePolicy(value: u8) Error!workspace.ResharePolicy {
    return switch (value) {
        @intFromEnum(workspace.ResharePolicy.owner_only) => .owner_only,
        @intFromEnum(workspace.ResharePolicy.admin_only) => .admin_only,
        @intFromEnum(workspace.ResharePolicy.grantee_allowed) => .grantee_allowed,
        else => error.CorruptImage,
    };
}

fn parseAuditVisibility(value: u8) Error!workspace.AuditVisibility {
    return switch (value) {
        @intFromEnum(workspace.AuditVisibility.owner_only) => .owner_only,
        @intFromEnum(workspace.AuditVisibility.shared_participants) => .shared_participants,
        @intFromEnum(workspace.AuditVisibility.organization_policy) => .organization_policy,
        else => error.CorruptImage,
    };
}

fn writeShareGrant(writer: *CursorWriter, grant: workspace.ShareGrant) Error!void {
    try writePrincipal(writer, grant.principal_id);
    var flags: u8 = 0;
    if (grant.can_read) flags |= 1 << 0;
    if (grant.can_write) flags |= 1 << 1;
    if (grant.can_export) flags |= 1 << 2;
    if (grant.can_admin) flags |= 1 << 3;
    try writer.writeByte(flags);
    try writer.writeByte(@intFromEnum(grant.network_scope));
    try writer.writeByte(@intFromEnum(grant.reshare_policy));
    try writer.writeByte(@intFromEnum(grant.audit_visibility));
    try writer.writeU64(grant.expires_at_ticks);
}

fn readShareGrant(reader: *CursorReader) Error!workspace.ShareGrant {
    const principal_id = try readPrincipal(reader);
    const flags = try reader.readByte();
    return .{
        .principal_id = principal_id,
        .can_read = (flags & (1 << 0)) != 0,
        .can_write = (flags & (1 << 1)) != 0,
        .can_export = (flags & (1 << 2)) != 0,
        .can_admin = (flags & (1 << 3)) != 0,
        .network_scope = try parseShareNetworkScope(try reader.readByte()),
        .reshare_policy = try parseResharePolicy(try reader.readByte()),
        .audit_visibility = try parseAuditVisibility(try reader.readByte()),
        .expires_at_ticks = try reader.readU64(),
    };
}

fn workspaceCount(workspaces: *const workspace.Directory) usize {
    var count: usize = 0;
    for (workspaces.workspaces.slots) |slot| {
        if (persistableWorkspaceSlot(slot)) count += 1;
    }
    return count;
}

fn snapshotCount(workspaces: *const workspace.Directory) usize {
    var count: usize = 0;
    for (workspaces.snapshots.slots) |slot| {
        if (persistableSnapshotSlot(slot)) count += 1;
    }
    return count;
}

fn persistableWorkspaceSlot(slot: anytype) bool {
    if (!slot.in_use) return false;
    return slot.workspace.label_len <= slot.workspace.label.len and
        slot.workspace.path_index.entry_count <= workspace.MAX_WORKSPACE_ENTRIES and
        slot.workspace.mutation_log.entry_mutation_count <= workspace.MAX_WORKSPACE_ENTRY_MUTATIONS and
        slot.workspace.share_table.share_grant_count <= workspace.MAX_SHARE_GRANTS and
        slot.workspace.recoverable_deletes.deleted_count <= workspace.MAX_RECOVERABLE_DELETES;
}

fn persistableSnapshotSlot(slot: anytype) bool {
    if (!slot.in_use) return false;
    return slot.snapshot.label_len <= slot.snapshot.label.len and
        slot.snapshot.entry_count <= workspace.MAX_WORKSPACE_ENTRIES;
}

fn findBlobSlotIndex(store: *const object_store.Store, address: object_store.BlobAddress) ?usize {
    return store.blobSlotIndex(address);
}

fn zeroWorkspaceRecord() workspace.WorkspaceRecord {
    return workspace.emptyWorkspaceRecord();
}

fn zeroSnapshotRecord() workspace.SnapshotRecord {
    return workspace.emptySnapshotRecord();
}

fn hashBytes(hash: u64, bytes: []const u8) u64 {
    var next = native_util.fnv1a64AppendU32LittleEndian(hash, @intCast(bytes.len));
    next = native_util.fnv1a64WithSeed(next, bytes);
    return next;
}

fn hashPrincipal(hash: u64, id: principal.PrincipalId) u64 {
    var next = native_util.fnv1a64AppendByte(hash, @intFromEnum(id.kind));
    next = native_util.fnv1a64AppendU64LittleEndian(next, id.serial);
    return next;
}

fn hashEntry(hash: u64, entry: workspace.Entry) u64 {
    var next = hashBytes(hash, entry.pathSlice());
    next = native_util.fnv1a64AppendU64LittleEndian(next, entry.object_id.raw());
    next = native_util.fnv1a64AppendU64LittleEndian(next, entry.version_id.raw());
    next = native_util.fnv1a64AppendByte(next, @intFromEnum(entry.object_type));
    return next;
}

fn hashShareGrant(hash: u64, grant: workspace.ShareGrant) u64 {
    var next = hashPrincipal(hash, grant.principal_id);
    next = native_util.fnv1a64AppendByte(next, @intFromBool(grant.can_read));
    next = native_util.fnv1a64AppendByte(next, @intFromBool(grant.can_write));
    next = native_util.fnv1a64AppendByte(next, @intFromBool(grant.can_admin));
    next = native_util.fnv1a64AppendByte(next, @intFromBool(grant.can_export));
    next = native_util.fnv1a64AppendByte(next, @intFromEnum(grant.network_scope));
    next = native_util.fnv1a64AppendByte(next, @intFromEnum(grant.reshare_policy));
    next = native_util.fnv1a64AppendByte(next, @intFromEnum(grant.audit_visibility));
    next = native_util.fnv1a64AppendU64LittleEndian(next, grant.expires_at_ticks);
    return next;
}

fn checksumBytes(bytes: []const u8) u64 {
    return native_util.fnv1a64(bytes);
}

fn nextRootSector(current: ?LoadedRoot) u32 {
    return if (current) |loaded|
        if (loaded.sector_index == 0) 1 else 0
    else
        0;
}

fn findLatestImageRoot(image: []const u8) Error!?LoadedRoot {
    var best: ?LoadedRoot = null;
    var sector_index: u32 = 0;
    while (sector_index < root_sector_count) : (sector_index += 1) {
        const root = readImageRoot(image, sector_index) catch continue;
        if (best == null or root.root.generation > best.?.root.generation) {
            best = root;
        }
    }
    return best;
}

fn findLatestBackendRoot(
    self: *Volume,
) Error!?LoadedRoot {
    var best: ?LoadedRoot = null;
    var sector_index: u32 = 0;
    while (sector_index < root_sector_count) : (sector_index += 1) {
        const root = readBackendRoot(self, sector_index) catch continue;
        if (best == null or root.root.generation > best.?.root.generation) {
            best = root;
        }
    }
    return best;
}

fn readImageRoot(image: []const u8, sector_index: u32) Error!LoadedRoot {
    const offset = @as(usize, sector_index) * sector_size;
    if (offset + sector_size > image.len) return error.ImageTooSmall;
    return .{
        .sector_index = sector_index,
        .root = try parseRoot(image[offset .. offset + sector_size]),
    };
}

fn writeImageRoot(image: []u8, sector_index: u32, root: RootState) Error!void {
    const offset = @as(usize, sector_index) * sector_size;
    if (offset + sector_size > image.len) return error.ImageTooSmall;
    try encodeRoot(image[offset .. offset + sector_size], root);
}

fn readBackendRoot(self: *Volume, sector_index: u32) Error!LoadedRoot {
    @memset(self.sector_buffer[0..], 0);
    if (!readAttachedRange(self, sector_index, self.sector_buffer[0..])) return error.CorruptImage;
    return .{
        .sector_index = sector_index,
        .root = try parseRoot(self.sector_buffer[0..]),
    };
}

fn writeBackendRoot(self: *Volume, sector_index: u32, root: RootState) Error!void {
    @memset(self.sector_buffer[0..], 0);
    try encodeRoot(self.sector_buffer[0..], root);
    if (!writeAttachedRange(self, sector_index, self.sector_buffer[0..])) return error.CorruptImage;
}

fn encodeRoot(buffer: []u8, root: RootState) Error!void {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(root_magic);
    try writer.writeU16(root_format_version);
    try writer.writeU64(root.generation);
    try writer.writeU32(root.log_bytes);
    try writer.writeU64(root.next_object_id);
    try writer.writeU64(root.next_version_id);
    try writer.writeU64(root.next_workspace_id);
    try writer.writeU64(root.next_snapshot_id);
    try writer.writeU64(root.last_version_id);
    try writer.writeU64(root.last_snapshot_id);
    try writer.writeU16(root.log_record_count);
    try writer.writeU16(root.log_segment_count);
    try writer.writeU64(root.compacted_generation);
    try writer.writeU16(@intCast(root.workspace_summary_count));
    for (root.workspace_summaries[0..root.workspace_summary_count]) |summary| {
        try writer.writeU64(summary.id);
        try writer.writeU32(summary.generation);
        try writer.writeU64(summary.state_hash);
    }
    const checksum = checksumBytes(buffer[0..writer.offset]);
    try writer.writeU64(checksum);
}

fn parseRoot(buffer: []const u8) Error!RootState {
    var reader = CursorReader{ .buffer = buffer };
    var magic: [root_magic.len]u8 = undefined;
    try reader.readBytes(&magic);
    if (!std.mem.eql(u8, &magic, root_magic)) return error.CorruptImage;
    if ((try reader.readU16()) != root_format_version) return error.UnsupportedVersion;

    var root = RootState{
        .generation = try reader.readU64(),
        .log_bytes = try reader.readU32(),
        .next_object_id = try reader.readU64(),
        .next_version_id = try reader.readU64(),
        .next_workspace_id = try reader.readU64(),
        .next_snapshot_id = try reader.readU64(),
        .last_version_id = try reader.readU64(),
        .last_snapshot_id = try reader.readU64(),
    };
    root.log_record_count = try reader.readU16();
    root.log_segment_count = try reader.readU16();
    root.compacted_generation = try reader.readU64();
    root.workspace_summary_count = try reader.readU16();
    if (root.workspace_summary_count > root.workspace_summaries.len) return error.CorruptImage;
    for (0..root.workspace_summary_count) |index| {
        root.workspace_summaries[index] = .{
            .id = try reader.readU64(),
            .generation = try reader.readU32(),
            .state_hash = try reader.readU64(),
        };
    }
    if (root.log_bytes > data_capacity_bytes) return error.CorruptImage;
    if (root.log_record_count == 0 or root.log_record_count > max_replay_log_records) return error.CorruptImage;
    if (root.log_segment_count > max_log_segments) return error.CorruptImage;
    const checksum_offset = reader.offset;
    const checksum = try reader.readU64();
    if (checksum != checksumBytes(buffer[0..checksum_offset])) return error.ChecksumMismatch;
    return root;
}

fn writeAttachedBytes(self: *Volume, offset: usize, bytes: []const u8) bool {
    if (offset + bytes.len > image_bytes) return false;
    var remaining = bytes.len;
    var cursor: usize = 0;
    while (remaining > 0) {
        const absolute_offset = offset + cursor;
        const sector_index = absolute_offset / sector_size;
        const sector_offset = absolute_offset % sector_size;
        const chunk_len = @min(remaining, sector_size - sector_offset);

        if (sector_offset == 0 and chunk_len == sector_size) {
            if (!writeAttachedRange(self, @intCast(sector_index), bytes[cursor .. cursor + chunk_len])) return false;
        } else {
            if (!readAttachedRange(self, @intCast(sector_index), self.sector_buffer[0..])) return false;
            @memcpy(self.sector_buffer[sector_offset .. sector_offset + chunk_len], bytes[cursor .. cursor + chunk_len]);
            if (!writeAttachedRange(self, @intCast(sector_index), self.sector_buffer[0..])) return false;
        }

        cursor += chunk_len;
        remaining -= chunk_len;
    }
    return true;
}

fn readAttachedBytes(self: *Volume, offset: usize, buffer: []u8) bool {
    if (offset + buffer.len > image_bytes) return false;
    var remaining = buffer.len;
    var cursor: usize = 0;
    while (remaining > 0) {
        const absolute_offset = offset + cursor;
        const sector_index = absolute_offset / sector_size;
        const sector_offset = absolute_offset % sector_size;
        const chunk_len = @min(remaining, sector_size - sector_offset);
        if (!readAttachedRange(self, @intCast(sector_index), self.sector_buffer[0..])) return false;
        @memcpy(buffer[cursor .. cursor + chunk_len], self.sector_buffer[sector_offset .. sector_offset + chunk_len]);
        cursor += chunk_len;
        remaining -= chunk_len;
    }
    return true;
}

fn writeU32At(buffer: []u8, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    @memcpy(buffer[0..4], &bytes);
}

fn writeU64At(buffer: []u8, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    @memcpy(buffer[0..8], &bytes);
}

fn readAttachedRange(self: *Volume, start_lba: u64, buffer: []u8) bool {
    return switch (self.attached_backend_kind) {
        .none => false,
        .generic => self.attached_backend_read(start_lba, buffer.ptr, buffer.len),
        .ata_bootstrap => ataReadRange(self, start_lba, buffer),
    };
}

fn writeAttachedRange(self: *Volume, start_lba: u64, buffer: []const u8) bool {
    return switch (self.attached_backend_kind) {
        .none => false,
        .generic => self.attached_backend_write(start_lba, buffer.ptr, buffer.len),
        .ata_bootstrap => ataWriteRange(self, start_lba, buffer),
    };
}

fn ataReadRange(self: *Volume, start_lba: u64, buffer: []u8) bool {
    const device = self.attached_ata_device orelse return false;
    return ata_bridge.read(device, start_lba, buffer);
}

fn ataWriteRange(self: *Volume, start_lba: u64, buffer: []const u8) bool {
    const device = self.attached_ata_device orelse return false;
    return ata_bridge.write(device, start_lba, buffer);
}

pub const testing = struct {
    pub fn latestImageLogBytes(image: []const u8) Error!u32 {
        return (try findLatestImageRoot(image)).?.root.log_bytes;
    }

    pub fn latestImageLogRecordCount(image: []const u8) Error!u16 {
        return (try findLatestImageRoot(image)).?.root.log_record_count;
    }

    pub fn latestImageLogSegmentCount(image: []const u8) Error!u16 {
        return (try findLatestImageRoot(image)).?.root.log_segment_count;
    }

    pub fn latestImageCompactedGeneration(image: []const u8) Error!u64 {
        return (try findLatestImageRoot(image)).?.root.compacted_generation;
    }

    pub fn corruptDataByte(image: []u8, offset: usize) void {
        image[data_start_byte + offset] ^= 0xFF;
    }
};
