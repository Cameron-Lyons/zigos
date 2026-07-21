const std = @import("std");
const binary_cursor = @import("binary_cursor");
const ids = @import("../core/ids.zig");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const volume_backend = @import("volume/backend.zig");
const volume_capacity = @import("volume/capacity.zig");
const volume_errors = @import("volume/errors.zig");
const volume_hashing = @import("volume/hashing.zig");
const volume_layout = @import("volume/layout.zig");
const volume_log = @import("volume/log.zig");
const volume_quota = @import("volume/quota.zig");
const volume_root_slot = @import("volume/root_slot.zig");
const workspace = @import("workspace.zig");

pub const sector_size = volume_layout.sector_size;
pub const slot_sectors = volume_layout.slot_sectors;
pub const slot_count = volume_layout.slot_count;
pub const header_sectors = volume_layout.header_sectors;
pub const payload_sectors = volume_layout.payload_sectors;
pub const slot_bytes = volume_layout.slot_bytes;
pub const image_bytes = volume_layout.image_bytes;
pub const max_payload_bytes = volume_layout.max_payload_bytes;
pub const required_device_sectors = volume_layout.required_device_sectors;
pub const max_signer_bytes = volume_layout.max_signer_bytes;
pub const replay_gate_records = volume_layout.max_replay_log_records;
pub const replay_gate_segments = volume_layout.max_log_segments;

const data_start_byte = volume_layout.data_start_byte;
const data_capacity_bytes = volume_layout.data_capacity_bytes;
const data_region_bytes = volume_layout.data_region_bytes;
const alternate_data_region_offset = volume_layout.alternate_data_region_offset;
const max_replay_log_records = volume_layout.max_replay_log_records;
const max_log_segments = volume_layout.max_log_segments;
const compaction_threshold_bytes = volume_layout.compaction_threshold_bytes;
const payload_magic = volume_layout.payload_magic;
const format_version = volume_layout.format_version;
const share_grant_flag_read: u8 = 1 << 0;
const share_grant_flag_write: u8 = 1 << 1;
const share_grant_flag_export: u8 = 1 << 2;
const share_grant_flag_admin: u8 = 1 << 3;

const workspaceCount = volume_quota.workspaceCount;
const snapshotCount = volume_quota.snapshotCount;
const persistableWorkspaceSlot = volume_quota.persistableWorkspaceSlot;
const persistableSnapshotSlot = volume_quota.persistableSnapshotSlot;

pub const ProductCapacityEnvelope = volume_capacity.ProductCapacityEnvelope;
pub const OverLimitWriteBehavior = volume_capacity.OverLimitWriteBehavior;
pub const QuotaLimit = volume_capacity.QuotaLimit;
pub const ProductCapacityUsage = volume_capacity.ProductCapacityUsage;
pub const QuotaRejection = volume_capacity.QuotaRejection;

pub const ProductQuotaPolicy = struct {
    envelope: ProductCapacityEnvelope,
    over_limit_write_behavior: OverLimitWriteBehavior,
    persistence_error: Error,
    retry_requires_freeing_space: bool,
};

pub const first_supported_capacity_envelope = volume_quota.first_supported_capacity_envelope;

pub fn productCapacityEnvelope() ProductCapacityEnvelope {
    return first_supported_capacity_envelope;
}

pub fn productQuotaPolicy() ProductQuotaPolicy {
    return .{
        .envelope = first_supported_capacity_envelope,
        .over_limit_write_behavior = .reject_without_partial_persistence,
        .persistence_error = error.NoSpaceLeft,
        .retry_requires_freeing_space = true,
    };
}

pub const Error = volume_errors.Error;

pub const PersistResult = struct {
    generation: u64,
};

pub const Backend = volume_backend.Backend;
pub const AttachedBackendKind = volume_backend.AttachedBackendKind;

pub const Volume = struct {
    io_payload_buffer: [max_payload_bytes]u8 = undefined,
    io_log_buffer: [data_capacity_bytes]u8 = undefined,
    sector_buffer: [sector_size]u8 = [_]u8{0} ** sector_size,
    attached_backend_present: bool = false,
    attached_backend_sector_count: u64 = 0,
    attached_backend_read: *const fn (u64, [*]u8, usize) callconv(.c) bool = volume_backend.unattachedRead,
    attached_backend_write: *const fn (u64, [*]const u8, usize) callconv(.c) bool = volume_backend.unattachedWrite,
    attached_backend_flush: *const fn () callconv(.c) bool = volume_backend.unattachedFlush,
    attached_backend_kind: volume_backend.AttachedBackendKind = .none,
    version_signers: [object_store.MAX_VERSIONS][max_signer_bytes]u8 =
        [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** object_store.MAX_VERSIONS,
    object_signers: [object_store.MAX_OBJECTS][max_signer_bytes]u8 =
        [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** object_store.MAX_OBJECTS,
    snapshot_signers: [workspace.MAX_SNAPSHOTS][max_signer_bytes]u8 =
        [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** workspace.MAX_SNAPSHOTS,
    workspace_state_hashes: WorkspaceStateHashCache = .{},

    pub fn init() Volume {
        var volume: Volume = undefined;
        volume.reset();
        return volume;
    }

    pub fn reset(self: *Volume) void {
        @memset(self.sector_buffer[0..], 0);
        self.attached_backend_present = false;
        self.attached_backend_sector_count = 0;
        self.attached_backend_read = volume_backend.unattachedRead;
        self.attached_backend_write = volume_backend.unattachedWrite;
        self.attached_backend_flush = volume_backend.unattachedFlush;
        self.attached_backend_kind = .none;
        @memset(std.mem.sliceAsBytes(self.version_signers[0..]), 0);
        @memset(std.mem.sliceAsBytes(self.object_signers[0..]), 0);
        @memset(std.mem.sliceAsBytes(self.snapshot_signers[0..]), 0);
        self.workspace_state_hashes = .{};
    }

    pub fn attachBackend(self: *Volume, backend: Backend) void {
        self.attachBackendFnsWithKind(backend.sector_count, backend.read, backend.write, backend.flush, .generic);
    }

    pub fn attachNvmePciBackend(self: *Volume, backend: Backend) void {
        self.attachBackendFnsWithKind(backend.sector_count, backend.read, backend.write, backend.flush, .nvme_pci);
    }

    pub fn attachNvmePciBackendFns(
        self: *Volume,
        sector_count: u64,
        read: *const fn (start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool,
        write: *const fn (start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool,
        flush: *const fn () callconv(.c) bool,
    ) void {
        self.attachBackendFnsWithKind(sector_count, read, write, flush, .nvme_pci);
    }

    pub fn attachAtaBootstrapBrokerBackend(self: *Volume, backend: Backend) void {
        self.attachBackendFnsWithKind(backend.sector_count, backend.read, backend.write, backend.flush, .ata_bootstrap_broker);
    }

    fn attachBackendFnsWithKind(
        self: *Volume,
        sector_count: u64,
        read: *const fn (start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool,
        write: *const fn (start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool,
        flush: *const fn () callconv(.c) bool,
        kind: volume_backend.AttachedBackendKind,
    ) void {
        self.attached_backend_present = true;
        self.attached_backend_sector_count = sector_count;
        self.attached_backend_read = read;
        self.attached_backend_write = write;
        self.attached_backend_flush = flush;
        self.attached_backend_kind = kind;
    }

    pub fn clearAttachedBackend(self: *Volume) void {
        self.attached_backend_present = false;
        self.attached_backend_sector_count = 0;
        self.attached_backend_read = volume_backend.unattachedRead;
        self.attached_backend_write = volume_backend.unattachedWrite;
        self.attached_backend_flush = volume_backend.unattachedFlush;
        self.attached_backend_kind = .none;
    }

    pub fn hasAttachedDevice(self: *const Volume) bool {
        return self.attached_backend_present;
    }

    pub fn hasProductionStorageBackend(self: *const Volume) bool {
        return self.hasAttachedDevice() and
            self.attached_backend_kind == .nvme_pci and
            self.attached_backend_sector_count >= required_device_sectors;
    }

    pub fn adoptAttachedBackendFrom(self: *Volume, source: *const Volume) void {
        self.attached_backend_present = source.attached_backend_present;
        self.attached_backend_sector_count = source.attached_backend_sector_count;
        self.attached_backend_read = source.attached_backend_read;
        self.attached_backend_write = source.attached_backend_write;
        self.attached_backend_flush = source.attached_backend_flush;
        self.attached_backend_kind = source.attached_backend_kind;
    }

    pub fn clearAttachedVolume(self: *Volume) void {
        volume_backend.clearAttachedVolume(self);
    }

    pub fn loadFromVolume(self: *Volume, store: *object_store.Store, workspaces: *workspace.Directory) bool {
        if (!self.hasAttachedDevice()) return false;
        if (self.attached_backend_sector_count < required_device_sectors) return false;

        return loadLatestValidBackendRoot(self, store, workspaces) catch false;
    }

    pub fn saveToVolume(self: *Volume, store: *object_store.Store, workspaces: *workspace.Directory) !PersistResult {
        if (!self.hasAttachedDevice()) return .{ .generation = 0 };
        if (self.attached_backend_sector_count < required_device_sectors) return error.ImageTooSmall;

        const selection = selectBackendSaveRoot(self);
        return saveIncremental(self, selection.current, selection.force_compaction, store, workspaces, BackendWriteFns{ .volume = self });
    }

    pub fn saveToImage(self: *Volume, image: []u8, store: *object_store.Store, workspaces: *workspace.Directory) !PersistResult {
        if (image.len < image_bytes) return error.ImageTooSmall;
        const selection = selectImageSaveRoot(image);
        return saveIncremental(self, selection.current, selection.force_compaction, store, workspaces, ImageWriteFns{ .image = image });
    }

    pub fn loadFromImage(self: *Volume, image: []const u8, store: *object_store.Store, workspaces: *workspace.Directory) !u64 {
        if (image.len < image_bytes) return error.ImageTooSmall;
        return try loadLatestValidImageRoot(self, image, store, workspaces);
    }
};

var default_volume = Volume.init();

pub fn defaultVolume() *Volume {
    return &default_volume;
}

const CursorWriter = binary_cursor.Writer(Error, error.NoSpaceLeft);
const CursorReader = binary_cursor.Reader(Error, error.CorruptImage);

const WorkspaceSummary = volume_root_slot.WorkspaceSummary;
const RootState = volume_root_slot.RootState;
const LoadedRoot = volume_root_slot.LoadedRoot;
const BuiltLog = volume_log.BuiltLog;

const SaveRootSelection = struct {
    current: ?LoadedRoot = null,
    force_compaction: bool = false,
};

pub fn attachBackend(backend: Backend) void {
    default_volume.attachBackend(backend);
}

pub fn attachNvmePciBackend(backend: Backend) void {
    default_volume.attachNvmePciBackend(backend);
}

pub fn attachNvmePciBackendFns(
    sector_count: u64,
    read: *const fn (start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool,
    write: *const fn (start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool,
    flush: *const fn () callconv(.c) bool,
) void {
    default_volume.attachNvmePciBackendFns(sector_count, read, write, flush);
}

pub fn attachAtaBootstrapBrokerBackend(backend: Backend) void {
    default_volume.attachAtaBootstrapBrokerBackend(backend);
}

pub fn clearAttachedBackend() void {
    default_volume.clearAttachedBackend();
}

pub fn hasAttachedDevice() bool {
    return default_volume.hasAttachedDevice();
}

pub fn hasProductionStorageBackend() bool {
    return default_volume.hasProductionStorageBackend();
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
    force_compaction: bool,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
    writer: anytype,
) Error!PersistResult {
    try ensureWithinProductCapacityEnvelope(store, workspaces);
    const started_dirty = store.dirtyObjectIds().len != 0 or
        store.dirtyVersionIds().len != 0 or
        workspaces.dirtyWorkspaceIds().len != 0 or
        workspaces.dirtySnapshotIds().len != 0;
    const current_generation = if (current) |loaded| loaded.root.generation else 0;
    const can_append = !force_compaction and if (current) |loaded|
        canAppendToRoot(loaded.root, store, workspaces)
    else
        false;
    const state_hashes = &self.workspace_state_hashes;
    for (workspaces.dirtyWorkspaceIds()) |workspace_id| {
        state_hashes.invalidate(workspace_id.raw());
    }
    const delta = if (current) |loaded|
        if (can_append)
        try buildDeltaLog(self.io_log_buffer[0..], loaded.root, store, workspaces, state_hashes)
        else
            BuiltLog{}
    else
        BuiltLog{};

    // The selected root can be visible through a write-back cache even when
    // its final durability barrier failed. Settle it before a forced
    // compaction chooses the opposite region, which may still back the prior
    // durable root.
    if (current != null and !can_append) try flushWrites(writer);

    if (can_append and delta.bytes_len == 0) {
        // A failed post-root barrier can leave the new root visible through a
        // write-back controller cache while its corresponding dirty state remains
        // set. Retry the barrier before accepting that visible root as durable.
        if (started_dirty) try flushWrites(writer);
        store.clearDirty();
        workspaces.clearDirty();
        return .{ .generation = current_generation };
    }

    if (can_append and appendLogFits(current.?.root, delta)) {
        const next_generation = current_generation + 1;
        const data_offset = current.?.root.data_offset;
        const next_log_bytes = current.?.root.log_bytes + @as(u32, @intCast(delta.bytes_len));
        var next_root = try buildRootState(next_generation, next_log_bytes, store, workspaces, state_hashes);
        next_root.data_offset = data_offset;
        next_root.log_record_count = current.?.root.log_record_count + delta.record_count;
        next_root.log_segment_count = current.?.root.log_segment_count + delta.segment_count;
        next_root.compacted_generation = current.?.root.compacted_generation;
        const next_root_sector = volume_root_slot.nextRootSector(current);
        // Append-only beyond the current log within the same region: the prior
        // root's prefix is untouched, so an interrupted append falls back to it.
        try writeBytes(writer, data_start_byte + data_offset + current.?.root.log_bytes, self.io_log_buffer[0..delta.bytes_len]);
        try flushWrites(writer);
        try writeRoot(writer, next_root_sector, next_root);
        try flushWrites(writer);
        store.clearDirty();
        workspaces.clearDirty();
        return .{ .generation = next_generation };
    }

    const checkpoint_payload_len = try serializeState(store, workspaces, self.io_payload_buffer[0..]);
    var log_writer = CursorWriter{ .buffer = self.io_log_buffer[0..] };
    try volume_log.appendRecordPayload(&log_writer, .checkpoint, self.io_payload_buffer[0..checkpoint_payload_len]);
    // The compacted checkpoint must fit in a single region so it can be written
    // to the region the live root does not reference. Fail closed rather than
    // overflow into the live root's region.
    if (log_writer.offset > data_region_bytes) return error.NoSpaceLeft;

    const next_generation = current_generation + 1;
    // Ping-pong to the region the current root does not occupy so its backing
    // log survives until the new root is durably committed.
    const next_data_offset: u32 = if (current) |loaded|
        (if (loaded.root.data_offset == 0) alternate_data_region_offset else 0)
    else
        0;
    var next_root = try buildRootState(next_generation, @intCast(log_writer.offset), store, workspaces, state_hashes);
    next_root.data_offset = next_data_offset;
    next_root.log_record_count = 1;
    next_root.log_segment_count = 0;
    next_root.compacted_generation = next_generation;
    const next_root_sector = volume_root_slot.nextRootSector(current);
    try writeBytes(writer, data_start_byte + next_data_offset, self.io_log_buffer[0..log_writer.offset]);
    try flushWrites(writer);
    try writeRoot(writer, next_root_sector, next_root);
    try flushWrites(writer);
    store.clearDirty();
    workspaces.clearDirty();
    return .{ .generation = next_generation };
}

fn selectImageSaveRoot(image: []const u8) SaveRootSelection {
    var selection = SaveRootSelection{};
    var sector_index: u32 = 0;
    while (sector_index < volume_layout.root_sector_count) : (sector_index += 1) {
        const offset = @as(usize, sector_index) * sector_size;
        const sector = image[offset .. offset + sector_size];
        if (!volume_root_slot.hasRootMagic(sector)) continue;
        const loaded = volume_root_slot.readImageRoot(image, sector_index) catch {
            selection.force_compaction = true;
            continue;
        };
        if (selection.current == null or loaded.root.generation > selection.current.?.root.generation) {
            selection.current = loaded;
        }
    }
    return selection;
}

fn selectBackendSaveRoot(self: *Volume) SaveRootSelection {
    var selection = SaveRootSelection{};
    var sector_index: u32 = 0;
    while (sector_index < volume_layout.root_sector_count) : (sector_index += 1) {
        const loaded = volume_root_slot.readBackendRoot(self, sector_index) catch {
            if (volume_root_slot.hasRootMagic(self.sector_buffer[0..])) selection.force_compaction = true;
            continue;
        };
        if (selection.current == null or loaded.root.generation > selection.current.?.root.generation) {
            selection.current = loaded;
        }
    }
    return selection;
}

fn appendLogFits(root: RootState, delta: BuiltLog) bool {
    if (@as(usize, root.log_bytes) + delta.bytes_len > data_region_bytes) return false;
    if (root.log_bytes + @as(u32, @intCast(delta.bytes_len)) > compaction_threshold_bytes) return false;
    if (@as(u32, root.log_record_count) + delta.record_count > max_replay_log_records) return false;
    if (@as(u32, root.log_segment_count) + delta.segment_count > max_log_segments) return false;
    return true;
}

fn loadLatestValidImageRoot(
    self: *Volume,
    image: []const u8,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
) Error!u64 {
    var roots: [volume_layout.root_sector_count]?LoadedRoot = [_]?LoadedRoot{null} ** volume_layout.root_sector_count;
    var root_count: usize = 0;
    var sector_index: u32 = 0;
    while (sector_index < volume_layout.root_sector_count) : (sector_index += 1) {
        roots[root_count] = volume_root_slot.readImageRoot(image, sector_index) catch continue;
        root_count += 1;
    }
    if (root_count == 0) return error.CorruptImage;

    var last_error: ?Error = null;
    while (takeNewestRoot(&roots, root_count)) |loaded| {
        return loadImageRootCandidate(self, image, store, workspaces, loaded) catch |err| {
            last_error = err;
            continue;
        };
    }

    store.reset();
    workspaces.reset();
    return last_error orelse error.CorruptImage;
}

fn loadLatestValidBackendRoot(
    self: *Volume,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
) Error!bool {
    var roots: [volume_layout.root_sector_count]?LoadedRoot = [_]?LoadedRoot{null} ** volume_layout.root_sector_count;
    var root_count: usize = 0;
    var sector_index: u32 = 0;
    while (sector_index < volume_layout.root_sector_count) : (sector_index += 1) {
        roots[root_count] = volume_root_slot.readBackendRoot(self, sector_index) catch continue;
        root_count += 1;
    }
    if (root_count == 0) return error.CorruptImage;

    var last_error: ?Error = null;
    while (takeNewestRoot(&roots, root_count)) |loaded| {
        loadBackendRootCandidate(self, store, workspaces, loaded) catch |err| {
            last_error = err;
            continue;
        };
        return true;
    }

    store.reset();
    workspaces.reset();
    return last_error orelse error.CorruptImage;
}

fn takeNewestRoot(roots: []?LoadedRoot, root_count: usize) ?LoadedRoot {
    var best_index: ?usize = null;
    var index: usize = 0;
    while (index < root_count) : (index += 1) {
        const loaded = roots[index] orelse continue;
        if (best_index == null or loaded.root.generation > roots[best_index.?].?.root.generation) {
            best_index = index;
        }
    }
    const selected_index = best_index orelse return null;
    const loaded = roots[selected_index].?;
    roots[selected_index] = null;
    return loaded;
}

fn loadImageRootCandidate(
    self: *Volume,
    image: []const u8,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
    loaded: LoadedRoot,
) Error!u64 {
    if (loaded.root.log_bytes == 0 or loaded.root.log_bytes > data_region_bytes) return error.CorruptImage;
    const region_start = data_start_byte + loaded.root.data_offset;
    if (region_start + loaded.root.log_bytes > image.len) return error.CorruptImage;
    try replayLog(self, store, workspaces, image[region_start .. region_start + loaded.root.log_bytes], loaded.root);
    try ensureWithinProductCapacityEnvelope(store, workspaces);
    store.clearDirty();
    workspaces.clearDirty();
    return loaded.root.generation;
}

fn loadBackendRootCandidate(
    self: *Volume,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
    loaded: LoadedRoot,
) Error!void {
    if (loaded.root.log_bytes == 0 or loaded.root.log_bytes > data_region_bytes) return error.CorruptImage;
    if (!volume_backend.readAttachedBytes(self, data_start_byte + loaded.root.data_offset, self.io_log_buffer[0..loaded.root.log_bytes])) return error.CorruptImage;
    try replayLog(self, store, workspaces, self.io_log_buffer[0..loaded.root.log_bytes], loaded.root);
    try ensureWithinProductCapacityEnvelope(store, workspaces);
    store.clearDirty();
    workspaces.clearDirty();
}

pub fn ensureWithinProductCapacityEnvelope(store: *const object_store.Store, workspaces: *const workspace.Directory) Error!void {
    if (quotaRejectionForCurrentState(store, workspaces) != null) {
        return error.NoSpaceLeft;
    }

    const envelope = first_supported_capacity_envelope;
    for (&workspaces.workspaces.slots) |*slot| {
        if (!slot.in_use) continue;
        if (!persistableWorkspaceSlot(slot)) return error.NoSpaceLeft;
        if (slot.workspace.path_index.entry_count > envelope.max_workspace_entries_per_workspace) return error.NoSpaceLeft;
    }

    for (&workspaces.snapshots.slots) |*slot| {
        if (!slot.in_use) continue;
        if (!persistableSnapshotSlot(slot)) return error.NoSpaceLeft;
        if (slot.snapshot.entry_count > envelope.max_workspace_entries_per_workspace) return error.NoSpaceLeft;
    }
}

pub fn productCapacityUsage(store: *const object_store.Store, workspaces: *const workspace.Directory) ProductCapacityUsage {
    return volume_quota.productCapacityUsage(store, workspaces);
}

pub fn quotaRejectionForCurrentState(
    store: *const object_store.Store,
    workspaces: *const workspace.Directory,
) ?QuotaRejection {
    return volume_quota.quotaRejectionForCurrentState(store, workspaces, first_supported_capacity_envelope);
}

pub fn quotaRejectionForUsage(usage: ProductCapacityUsage) ?QuotaRejection {
    return volume_quota.quotaRejectionForUsage(usage, first_supported_capacity_envelope);
}

fn writeBytes(writer: anytype, offset: usize, bytes: []const u8) Error!void {
    switch (@TypeOf(writer)) {
        ImageWriteFns => {
            if (offset + bytes.len > writer.image.len) return error.ImageTooSmall;
            @memcpy(writer.image[offset .. offset + bytes.len], bytes);
        },
        BackendWriteFns => {
            if (!volume_backend.writeAttachedBytes(writer.volume, offset, bytes)) return error.CorruptImage;
        },
        else => @compileError("unsupported incremental writer"),
    }
}

fn writeRoot(writer: anytype, sector_index: u32, root: RootState) Error!void {
    switch (@TypeOf(writer)) {
        ImageWriteFns => try volume_root_slot.writeImageRoot(writer.image, sector_index, root),
        BackendWriteFns => try volume_root_slot.writeBackendRoot(writer.volume, sector_index, root),
        else => @compileError("unsupported root writer"),
    }
}

fn flushWrites(writer: anytype) Error!void {
    switch (@TypeOf(writer)) {
        ImageWriteFns => {},
        BackendWriteFns => {
            if (!volume_backend.flushAttached(writer.volume)) return error.DurabilityBarrierFailed;
        },
        else => @compileError("unsupported durability writer"),
    }
}

/// Per-save memo for workspace state hashes: buildDeltaLog and buildRootState
/// both need the hash of a dirty workspace, and hashing walks the full
/// mutation log, share table, and recoverable-delete list.
// Lives on the Volume and survives across saves: the full workspace state
// hash walks every entry, mutation, share grant, and recoverable delete, and
// buildRootState needs a hash for EVERY workspace on EVERY flush - which
// noteMutation triggers on each durable boundary. Entries are invalidated
// from the directory's dirty-id set at the top of each save, so the cache
// leans on exactly the completeness contract the delta builder already
// requires: a workspace absent from the dirty set has not changed since the
// last clearDirty.
const WorkspaceStateHashCache = struct {
    ids: [workspace.MAX_WORKSPACES]u64 = [_]u64{0} ** workspace.MAX_WORKSPACES,
    hashes: [workspace.MAX_WORKSPACES]u64 = [_]u64{0} ** workspace.MAX_WORKSPACES,
    count: usize = 0,

    fn getOrCompute(self: *WorkspaceStateHashCache, record: *const workspace.WorkspaceRecord) Error!u64 {
        const id = record.id.raw();
        for (self.ids[0..self.count], 0..) |cached_id, index| {
            if (cached_id == id) return self.hashes[index];
        }
        const hash = try volume_hashing.workspaceStateHash(record);
        if (self.count < self.ids.len) {
            self.ids[self.count] = id;
            self.hashes[self.count] = hash;
            self.count += 1;
        }
        return hash;
    }

    fn invalidate(self: *WorkspaceStateHashCache, id: u64) void {
        for (self.ids[0..self.count], 0..) |cached_id, index| {
            if (cached_id != id) continue;
            self.count -= 1;
            self.ids[index] = self.ids[self.count];
            self.hashes[index] = self.hashes[self.count];
            self.ids[self.count] = 0;
            self.hashes[self.count] = 0;
            return;
        }
    }

    fn reset(self: *WorkspaceStateHashCache) void {
        self.* = .{};
    }
};

fn buildDeltaLog(
    buffer: []u8,
    root: RootState,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
    state_hashes: *WorkspaceStateHashCache,
) Error!BuiltLog {
    var writer = CursorWriter{ .buffer = buffer };
    try volume_log.appendRecordPayload(&writer, .segment_boundary, &.{});

    for (store.dirtyObjectIds()) |object_id| {
        const object_record = store.object(object_id) orelse continue;
        if (object_record.latest_version_id.raw() <= root.last_version_id) continue;
        try appendObjectRecord(&writer, object_record);
    }

    for (store.dirtyVersionIds()) |version_id| {
        const version_record = store.version(version_id) orelse continue;
        if (version_record.id.raw() <= root.last_version_id) continue;
        try appendVersionPayloadChunks(&writer, store, version_record);
        const blob = store.blob(version_record.blob_address) orelse return error.CorruptImage;
        try appendBlobRecord(&writer, blob);
        try appendVersionRecord(&writer, version_record);
    }

    for (workspaces.dirtyWorkspaceIds()) |workspace_id| {
        const workspace_record = workspaces.findConst(workspace_id) orelse continue;
        const summary = findWorkspaceSummary(root, workspace_record.id.raw());
        const state_hash = try state_hashes.getOrCompute(workspace_record);
        if (summary) |persisted| {
            if (persisted.generation == workspace_record.generation and persisted.state_hash == state_hash) continue;
        }
        try appendWorkspaceRecord(&writer, workspace_record);
    }

    for (workspaces.dirtySnapshotIds()) |snapshot_id| {
        const snapshot_record = workspaces.findSnapshotConst(snapshot_id) orelse continue;
        if (snapshot_record.id.raw() <= root.last_snapshot_id) continue;
        try appendSnapshotRecord(&writer, snapshot_record);
    }

    if (writer.offset == volume_log.recordHeaderLen()) return .{};
    return .{
        .bytes_len = writer.offset,
        .record_count = countLogRecords(buffer[0..writer.offset]) catch return error.CorruptImage,
        .segment_count = 1,
    };
}

fn canAppendToRoot(root: RootState, store: *const object_store.Store, workspaces: *const workspace.Directory) bool {
    if (!volume_root_slot.hasCanonicalDeltaWatermarks(root)) return false;
    if (volume_root_slot.lastIssuedId(root.next_object_id) > volume_root_slot.lastIssuedId(store.next_object_id)) return false;
    if (root.last_version_id > volume_root_slot.lastIssuedId(store.next_version_id)) return false;
    if (volume_root_slot.lastIssuedId(root.next_workspace_id) > volume_root_slot.lastIssuedId(workspaces.next_workspace_id)) return false;
    if (root.last_snapshot_id > volume_root_slot.lastIssuedId(workspaces.next_snapshot_id)) return false;

    // Dirty identifiers at or below a root watermark are ambiguous: they can
    // come from a visible root whose final durability barrier failed, or from a
    // corrupted root that falsely claims data is already present. Compacting
    // is safe in both cases and avoids silently clearing unpersisted records.
    for (store.dirtyObjectIds()) |object_id| {
        const object_record = store.objectConst(object_id) orelse return false;
        if (object_record.latest_version_id.raw() <= root.last_version_id) return false;
    }
    for (store.dirtyVersionIds()) |version_id| {
        _ = store.versionConst(version_id) orelse return false;
        if (version_id.raw() <= root.last_version_id) return false;
    }
    for (workspaces.dirtyWorkspaceIds()) |workspace_id| {
        _ = workspaces.findConst(workspace_id) orelse return false;
    }
    for (workspaces.dirtySnapshotIds()) |snapshot_id| {
        _ = workspaces.findSnapshotConst(snapshot_id) orelse return false;
        if (snapshot_id.raw() <= root.last_snapshot_id) return false;
    }
    return true;
}

fn replayedIdsFitRoot(root: RootState, store: *const object_store.Store, workspaces: *const workspace.Directory) bool {
    for (&store.objects.slots) |*slot| {
        if (!slot.in_use) continue;
        if (!issuedBeforeNext(slot.object.id.raw(), root.next_object_id)) return false;
    }
    for (&store.versions.slots) |*slot| {
        if (!slot.in_use) continue;
        if (slot.version.id.raw() > root.last_version_id) return false;
    }
    for (&workspaces.workspaces.slots) |*slot| {
        if (!slot.in_use) continue;
        if (!issuedBeforeNext(slot.workspace.id.raw(), root.next_workspace_id)) return false;
    }
    for (&workspaces.snapshots.slots) |*slot| {
        if (!slot.in_use) continue;
        if (slot.snapshot.id.raw() > root.last_snapshot_id) return false;
    }
    return true;
}

fn issuedBeforeNext(id: u64, next_id: u64) bool {
    return next_id == 0 or id < next_id;
}

fn buildRootState(
    generation: u64,
    log_bytes: u32,
    store: *const object_store.Store,
    workspaces: *const workspace.Directory,
    state_hashes: *WorkspaceStateHashCache,
) Error!RootState {
    var root = RootState{
        .generation = generation,
        .log_bytes = log_bytes,
        .next_object_id = store.next_object_id,
        .next_version_id = store.next_version_id,
        .next_workspace_id = workspaces.next_workspace_id,
        .next_snapshot_id = workspaces.next_snapshot_id,
        .last_version_id = volume_root_slot.lastIssuedId(store.next_version_id),
        .last_snapshot_id = volume_root_slot.lastIssuedId(workspaces.next_snapshot_id),
    };
    for (&workspaces.workspaces.slots) |*slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        root.workspace_summaries[root.workspace_summary_count] = .{
            .id = slot.workspace.id.raw(),
            .generation = slot.workspace.generation,
            .state_hash = try state_hashes.getOrCompute(&slot.workspace),
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

fn replayLog(self: *Volume, store: *object_store.Store, workspaces: *workspace.Directory, log: []const u8, root: RootState) Error!void {
    if (!volume_root_slot.hasCanonicalDeltaWatermarks(root)) return error.CorruptImage;
    store.reset();
    workspaces.reset();
    // The directory contents are replaced wholesale below and replay clears
    // dirty tracking, so cached hashes keyed to the old contents must go.
    self.workspace_state_hashes.reset();
    if (root.log_record_count == 0 or root.log_record_count > max_replay_log_records) return error.CorruptImage;
    if (root.log_segment_count > max_log_segments) return error.CorruptImage;

    var reader = CursorReader{ .buffer = log };
    var replayed_records: u16 = 0;
    var replayed_segments: u16 = 0;
    while (reader.offset < reader.buffer.len) {
        const header = try volume_log.readRecordHeader(&reader);
        const payload = try reader.readSlice(header.payload_len);
        if (volume_hashing.checksumBytes(payload) != header.checksum) return error.ChecksumMismatch;
        if (replayed_records == 0 and header.kind != .checkpoint) return error.MissingCheckpoint;
        if (replayed_records != 0 and header.kind == .checkpoint) return error.CorruptImage;
        replayed_records += 1;
        if (replayed_records > max_replay_log_records) return error.CorruptImage;

        switch (header.kind) {
            .checkpoint => try deserializeState(self, store, workspaces, payload),
            .segment_boundary => {
                if (payload.len != 0) return error.CorruptImage;
                replayed_segments += 1;
                if (replayed_segments > max_log_segments) return error.CorruptImage;
            },
            .object_state => try applyObjectRecord(self, store, payload),
            .chunk_state => try applyChunkRecord(store, payload),
            .blob_state => try applyBlobRecord(store, payload),
            .version_state => try applyVersionRecord(self, store, payload),
            .workspace_state => try applyWorkspaceRecord(workspaces, payload),
            .snapshot_state => try applySnapshotRecord(self, workspaces, payload),
        }
    }
    if (replayed_records == 0) return error.MissingCheckpoint;
    if (replayed_records != root.log_record_count) return error.CorruptImage;
    if (replayed_segments != root.log_segment_count) return error.CorruptImage;
    if (!replayedIdsFitRoot(root, store, workspaces)) return error.CorruptImage;

    store.next_object_id = root.next_object_id;
    store.next_version_id = root.next_version_id;
    workspaces.next_workspace_id = root.next_workspace_id;
    workspaces.next_snapshot_id = root.next_snapshot_id;
    store.rebuildDerivedIndexes();
    workspaces.rebuildDerivedIndexes();
}

fn countLogRecords(log: []const u8) Error!u16 {
    var reader = CursorReader{ .buffer = log };
    var count: u16 = 0;
    while (reader.offset < reader.buffer.len) {
        const header = try volume_log.readRecordHeader(&reader);
        _ = try reader.readSlice(header.payload_len);
        count += 1;
    }
    return count;
}

fn appendObjectRecord(writer: *CursorWriter, record: *const object_store.ObjectRecord) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .object_state);
    try encodeObjectBody(writer, record);
    try volume_log.finishRecord(writer, header_offset);
}

fn appendVersionRecord(writer: *CursorWriter, record: *const object_store.VersionRecord) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .version_state);
    try encodeVersionBody(writer, record);
    try volume_log.finishRecord(writer, header_offset);
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

fn appendWorkspaceRecord(writer: *CursorWriter, record: *const workspace.WorkspaceRecord) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .workspace_state);
    try encodeWorkspaceBody(writer, record);
    try volume_log.finishRecord(writer, header_offset);
}

fn appendSnapshotRecord(writer: *CursorWriter, record: *const workspace.SnapshotRecord) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .snapshot_state);
    try encodeSnapshotBody(writer, record);
    try volume_log.finishRecord(writer, header_offset);
}

fn encodeObjectBody(writer: *CursorWriter, record: *const object_store.ObjectRecord) Error!void {
    try writer.writeU64(record.id.raw());
    try writer.writeByte(@intFromEnum(record.object_type));
    try writer.writeU64(record.latest_version_id.raw());
    try writer.writeU16(record.version_count);
    try writer.writeU64(record.provenance.created_at_ticks);
    try writer.writeU64(record.provenance.updated_at_ticks);
    try writeSignature(writer, record.provenance.creator_signature);
    try writer.writeByte(if (record.provenance.latest_version_addressed) 1 else 0);
    try writer.writeU16(record.snapshot_state.snapshot_count);
    try writer.writeU64(record.snapshot_state.latest_snapshot_version_id.raw());
    try writer.writeU32(record.sync_state.sync_generation);
    try writer.writeU16(record.sync_state.version_watermark);
    try writer.writeU64(record.sync_state.last_synced_version_id.raw());
    try writer.writeU32(record.sharing_policy.policy_generation);
    try writer.writeByte(if (record.sharing_policy.requires_explicit_file_bridge_grant) 1 else 0);
    try writer.writeByte(if (record.sharing_policy.export_only_file_bridge) 1 else 0);
    try writer.writeU32(record.recovery_history.recovery_generation);
    try writer.writeByte(if (record.recovery_history.recoverable) 1 else 0);
    try writer.writeU64(record.recovery_history.latest_recoverable_version_id.raw());
}

fn encodeVersionBody(writer: *CursorWriter, record: *const object_store.VersionRecord) Error!void {
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

fn appendBlobRecord(writer: *CursorWriter, record: *const object_store.BlobRecord) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .blob_state);
    try encodeBlobBody(writer, record);
    try volume_log.finishRecord(writer, header_offset);
}

fn appendPayloadChunkRecord(writer: *CursorWriter, chunk: object_store.PayloadChunk) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .chunk_state);
    try writer.writeBytes(&chunk.address);
    try writer.writeU16(@intCast(chunk.bytes.len));
    try writer.writeBytes(chunk.bytes);
    try volume_log.finishRecord(writer, header_offset);
}

fn encodeBlobBody(writer: *CursorWriter, record: *const object_store.BlobRecord) Error!void {
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

fn encodeChunkBody(writer: *CursorWriter, record: *const object_store.ChunkRecord) Error!void {
    try writer.writeBytes(&record.address);
    try writer.writeU16(record.payload_len);
    try writer.writeBytes(record.chunkSlice());
}

fn encodeWorkspaceBody(writer: *CursorWriter, record: *const workspace.WorkspaceRecord) Error!void {
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

fn encodeSnapshotBody(writer: *CursorWriter, record: *const workspace.SnapshotRecord) Error!void {
    try writer.writeU64(record.id.raw());
    try writer.writeU64(record.workspace_id.raw());
    try writer.writeU32(record.generation);
    try writeText(writer, record.labelSlice());
    try writer.writeBytes(&record.root_address);
    try writeSignature(writer, record.signature);
    try writer.writeU16(@intCast(record.entry_count));
}

fn applyObjectRecord(self: *Volume, store: *object_store.Store, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const object_id = ids.object(try reader.readU64());
    const slot_index = store.objects.slotIndexOf(object_id) orelse store.objects.reserveIndexClean(object_id) orelse return error.CorruptImage;
    const object_type = try parseObjectType(try reader.readByte());
    const latest_version_id = ids.version(try reader.readU64());
    const version_count = try reader.readU16();
    var object_record = object_store.ObjectRecord{
        .id = object_id,
        .object_type = object_type,
        .latest_version_id = latest_version_id,
        .version_count = version_count,
    };
    try readObjectUserDataTail(&reader, &object_record, &self.object_signers[slot_index]);
    store.objects.slots[slot_index].object = object_record;
}

fn applyVersionRecord(self: *Volume, store: *object_store.Store, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const version_id = ids.version(try reader.readU64());
    const slot_index = store.versions.reserveIndexClean(version_id) orelse return error.CorruptImage;
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
    const chunk_count_value = try reader.readU16();
    if (chunk_count_value > object_store.MAX_BLOB_CHUNKS) return error.CorruptImage;
    store.versions.slots[slot_index].version.chunk_count = chunk_count_value;
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
    const slot = workspaces.workspaces.get(workspace_id) orelse
        workspaces.workspaces.reserveClean(workspace_id) orelse return error.CorruptImage;
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
    const slot_index = workspaces.snapshots.slotIndexOf(snapshot_id) orelse
        workspaces.snapshots.reserveIndexClean(snapshot_id) orelse return error.CorruptImage;
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

    for (&store.objects.slots) |*slot| {
        if (!slot.in_use) continue;
        try encodeObjectBody(&writer, &slot.object);
    }

    var chunk_slot_index: usize = 0;
    while (chunk_slot_index < store.chunkSlotCapacity()) : (chunk_slot_index += 1) {
        const slot = store.chunkSlotAtConst(chunk_slot_index);
        if (!slot.in_use) continue;
        try encodeChunkBody(&writer, &slot.chunk);
    }

    var blob_slot_index: usize = 0;
    while (blob_slot_index < store.blobSlotCapacity()) : (blob_slot_index += 1) {
        const slot = store.blobSlotAtConst(blob_slot_index);
        if (!slot.in_use) continue;
        try encodeBlobBody(&writer, &slot.blob);
    }

    for (&store.versions.slots) |*slot| {
        if (!slot.in_use) continue;
        try encodeVersionBody(&writer, &slot.version);
    }

    for (&workspaces.workspaces.slots) |*slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        try encodeWorkspaceBody(&writer, &slot.workspace);
    }

    for (&workspaces.snapshots.slots) |*slot| {
        if (!persistableSnapshotSlot(slot)) continue;
        try encodeSnapshotBody(&writer, &slot.snapshot);
    }

    return writer.offset;
}

fn deserializeState(self: *Volume, store: *object_store.Store, workspaces: *workspace.Directory, payload: []const u8) Error!void {
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
        const slot_index = store.objects.reserveIndexClean(object_id) orelse return error.CorruptImage;
        const slot = &store.objects.slots[slot_index];
        slot.object.id = object_id;
        slot.object.object_type = try parseObjectType(try reader.readByte());
        slot.object.latest_version_id = ids.version(try reader.readU64());
        slot.object.version_count = try reader.readU16();
        try readObjectUserDataTail(&reader, &slot.object, &self.object_signers[slot_index]);
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
        const slot_index = store.versions.reserveIndexClean(version_id) orelse return error.CorruptImage;
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
        const chunk_count_value = try reader.readU16();
        if (chunk_count_value > object_store.MAX_BLOB_CHUNKS) return error.CorruptImage;
        store.versions.slots[slot_index].version.chunk_count = chunk_count_value;
        store.versions.slots[slot_index].version.blob_slot_index = findBlobSlotIndex(store, store.versions.slots[slot_index].version.blob_address) orelse return error.CorruptImage;
    }

    for (0..@as(usize, workspace_count_value)) |_| {
        const workspace_id = ids.workspace(try reader.readU64());
        const slot = workspaces.workspaces.reserveClean(workspace_id) orelse return error.CorruptImage;
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
        const slot_index = workspaces.snapshots.reserveIndexClean(snapshot_id) orelse return error.CorruptImage;
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

fn readObjectUserDataTail(
    reader: *CursorReader,
    record: *object_store.ObjectRecord,
    signer_storage: *[max_signer_bytes]u8,
) Error!void {
    record.provenance.created_at_ticks = try reader.readU64();
    record.provenance.updated_at_ticks = try reader.readU64();
    record.provenance.creator_signature = try readSignature(reader, signer_storage);
    record.provenance.latest_version_addressed = (try reader.readByte()) != 0;
    record.snapshot_state.snapshot_count = try reader.readU16();
    record.snapshot_state.latest_snapshot_version_id = ids.version(try reader.readU64());
    record.sync_state.sync_generation = try reader.readU32();
    record.sync_state.version_watermark = try reader.readU16();
    record.sync_state.last_synced_version_id = ids.version(try reader.readU64());
    record.sharing_policy.policy_generation = try reader.readU32();
    record.sharing_policy.requires_explicit_file_bridge_grant = (try reader.readByte()) != 0;
    record.sharing_policy.export_only_file_bridge = (try reader.readByte()) != 0;
    record.recovery_history.recovery_generation = try reader.readU32();
    record.recovery_history.recoverable = (try reader.readByte()) != 0;
    record.recovery_history.latest_recoverable_version_id = ids.version(try reader.readU64());
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
        .format = manifest.SIGNATURE_FORMAT_ED25519,
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
    if (grant.can_read) flags |= share_grant_flag_read;
    if (grant.can_write) flags |= share_grant_flag_write;
    if (grant.can_export) flags |= share_grant_flag_export;
    if (grant.can_admin) flags |= share_grant_flag_admin;
    try writer.writeByte(flags);
    try writer.writeByte(@intFromEnum(grant.network_scope));
    try writer.writeByte(@intFromEnum(grant.reshare_policy));
    try writer.writeByte(@intFromEnum(grant.audit_visibility));
    try writer.writeU64(grant.expires_at_ticks);
    try writer.writeU64(grant.scope_object_id.raw());
    try writeText(writer, grant.scopePathSlice());
}

fn readShareGrant(reader: *CursorReader) Error!workspace.ShareGrant {
    const principal_id = try readPrincipal(reader);
    const flags = try reader.readByte();
    var grant = workspace.ShareGrant{
        .principal_id = principal_id,
        .can_read = (flags & share_grant_flag_read) != 0,
        .can_write = (flags & share_grant_flag_write) != 0,
        .can_export = (flags & share_grant_flag_export) != 0,
        .can_admin = (flags & share_grant_flag_admin) != 0,
        .network_scope = try parseShareNetworkScope(try reader.readByte()),
        .reshare_policy = try parseResharePolicy(try reader.readByte()),
        .audit_visibility = try parseAuditVisibility(try reader.readByte()),
        .expires_at_ticks = try reader.readU64(),
    };
    grant.scope_object_id = ids.object(try reader.readU64());
    readTextInto(reader, &grant.scope_path, &grant.scope_path_len) catch return error.CorruptImage;
    return grant;
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

test "storage replay requires exactly one leading checkpoint" {
    const allocator = std.testing.allocator;
    const volume = try allocator.create(Volume);
    defer allocator.destroy(volume);
    volume.reset();

    const store = try allocator.create(object_store.Store);
    defer allocator.destroy(store);
    store.* = object_store.Store.init();

    const workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(workspaces);
    workspaces.* = workspace.Directory.init();

    const checkpoint_payload = try allocator.alloc(u8, max_payload_bytes);
    defer allocator.free(checkpoint_payload);
    const checkpoint_payload_len = try serializeState(store, workspaces, checkpoint_payload);
    const log = try allocator.alloc(u8, 2 * (volume_log.recordHeaderLen() + checkpoint_payload_len));
    defer allocator.free(log);

    var missing_writer = CursorWriter{ .buffer = log };
    try volume_log.appendRecordPayload(&missing_writer, .segment_boundary, "");
    try std.testing.expectError(error.MissingCheckpoint, replayLog(
        volume,
        store,
        workspaces,
        log[0..missing_writer.offset],
        .{ .log_record_count = 1, .log_segment_count = 1 },
    ));

    var late_writer = CursorWriter{ .buffer = log };
    try volume_log.appendRecordPayload(&late_writer, .segment_boundary, "");
    try volume_log.appendRecordPayload(&late_writer, .checkpoint, checkpoint_payload[0..checkpoint_payload_len]);
    try std.testing.expectError(error.MissingCheckpoint, replayLog(
        volume,
        store,
        workspaces,
        log[0..late_writer.offset],
        .{ .log_record_count = 2, .log_segment_count = 1 },
    ));

    var duplicate_writer = CursorWriter{ .buffer = log };
    try volume_log.appendRecordPayload(&duplicate_writer, .checkpoint, checkpoint_payload[0..checkpoint_payload_len]);
    try volume_log.appendRecordPayload(&duplicate_writer, .checkpoint, checkpoint_payload[0..checkpoint_payload_len]);
    try std.testing.expectError(error.CorruptImage, replayLog(
        volume,
        store,
        workspaces,
        log[0..duplicate_writer.offset],
        .{ .log_record_count = 2 },
    ));
}

test "storage append rejects issuance watermark rewind" {
    const allocator = std.testing.allocator;
    const store = try allocator.create(object_store.Store);
    defer allocator.destroy(store);
    store.* = object_store.Store.init();
    const workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(workspaces);
    workspaces.* = workspace.Directory.init();

    try std.testing.expect(canAppendToRoot(.{}, store, workspaces));
    try std.testing.expect(!canAppendToRoot(.{ .next_object_id = 2 }, store, workspaces));
    try std.testing.expect(!canAppendToRoot(.{
        .next_version_id = 2,
        .last_version_id = 1,
    }, store, workspaces));
    try std.testing.expect(!canAppendToRoot(.{ .next_workspace_id = 2 }, store, workspaces));
    try std.testing.expect(!canAppendToRoot(.{
        .next_snapshot_id = 2,
        .last_snapshot_id = 1,
    }, store, workspaces));
}

pub const testing = struct {
    pub fn latestImageLogBytes(image: []const u8) Error!u32 {
        return (try volume_root_slot.findLatestImageRoot(image)).?.root.log_bytes;
    }

    pub fn latestImageLogRecordCount(image: []const u8) Error!u16 {
        return (try volume_root_slot.findLatestImageRoot(image)).?.root.log_record_count;
    }

    pub fn latestImageLogSegmentCount(image: []const u8) Error!u16 {
        return (try volume_root_slot.findLatestImageRoot(image)).?.root.log_segment_count;
    }

    pub fn latestImageCompactedGeneration(image: []const u8) Error!u64 {
        return (try volume_root_slot.findLatestImageRoot(image)).?.root.compacted_generation;
    }

    pub fn corruptDataByte(image: []u8, offset: usize) void {
        image[data_start_byte + offset] ^= 0xFF;
    }

    pub fn latestImageDataOffset(image: []const u8) Error!u32 {
        return (try volume_root_slot.findLatestImageRoot(image)).?.root.data_offset;
    }

    pub fn dataRegionBytes() usize {
        return data_region_bytes;
    }

    pub fn alternateDataRegionOffset() u32 {
        return alternate_data_region_offset;
    }

    // Scribble an entire data region as a stand-in for a compaction checkpoint
    // write that was interrupted by power loss before its root committed.
    pub fn scribbleDataRegion(image: []u8, region_offset: u32) void {
        const start = data_start_byte + region_offset;
        @memset(image[start .. start + data_region_bytes], 0xAB);
    }

    pub fn recordHeaderBytes() usize {
        return volume_log.recordHeaderLen();
    }

    pub fn maxReplayLogRecords() u16 {
        return max_replay_log_records;
    }

    pub fn maxReplayLogSegments() u16 {
        return max_log_segments;
    }

    pub fn forceLatestImageRootLogBytes(image: []u8, log_bytes: u32) Error!void {
        const loaded = (try volume_root_slot.findLatestImageRoot(image)) orelse return error.CorruptImage;
        var root = loaded.root;
        root.log_bytes = log_bytes;
        try volume_root_slot.writeImageRoot(image, loaded.sector_index, root);
    }

    pub fn forceLatestImageRootLogRecordCount(image: []u8, log_record_count: u16) Error!void {
        const loaded = (try volume_root_slot.findLatestImageRoot(image)) orelse return error.CorruptImage;
        var root = loaded.root;
        root.log_record_count = log_record_count;
        try volume_root_slot.writeImageRoot(image, loaded.sector_index, root);
    }
};
