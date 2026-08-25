const builtin = @import("builtin");
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
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/memory/memory.zig")
else
    struct {};

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
pub const SIGNER_TEXT_POOL_BYTES: usize = 12 * 1024;
pub const replay_gate_records = volume_layout.max_replay_log_records;
pub const replay_gate_segments = volume_layout.max_log_segments;
pub const DATA_REGION_BYTES = volume_layout.data_region_bytes;
pub const IO_LOG_WORKSPACE_BYTES = DATA_REGION_BYTES;
pub const TRACKS_REPLAY_ID_BOUNDS_INLINE = true;
const heap_backed_io_workspace = builtin.target.os.tag == .freestanding;
const IoLogWorkspace = if (heap_backed_io_workspace) ?[*]u8 else [IO_LOG_WORKSPACE_BYTES]u8;

comptime {
    if (SIGNER_TEXT_POOL_BYTES > std.math.maxInt(u16)) {
        @compileError("signer text pool exceeds its compact length field");
    }
}

const data_start_byte = volume_layout.data_start_byte;
const data_region_bytes = DATA_REGION_BYTES;
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
    io_log_buffer: IoLogWorkspace = if (heap_backed_io_workspace) null else undefined,
    sector_buffer: [sector_size]u8 = [_]u8{0} ** sector_size,
    attached_backend_present: bool = false,
    attached_backend_sector_count: u64 = 0,
    attached_backend_read: *const fn (u64, [*]u8, usize) callconv(.c) bool = volume_backend.unattachedRead,
    attached_backend_write: *const fn (u64, [*]const u8, usize) callconv(.c) bool = volume_backend.unattachedWrite,
    attached_backend_flush: *const fn () callconv(.c) bool = volume_backend.unattachedFlush,
    attached_backend_kind: volume_backend.AttachedBackendKind = .none,
    signer_text_len: u16 = 0,
    signer_text_pool: [SIGNER_TEXT_POOL_BYTES]u8 = [_]u8{0} ** SIGNER_TEXT_POOL_BYTES,
    workspace_state_hashes: WorkspaceStateHashCache = .{},

    pub fn init() Volume {
        return .{};
    }

    pub fn reset(self: *Volume) void {
        self.releaseIoLogWorkspace();
        @memset(self.sector_buffer[0..], 0);
        self.attached_backend_present = false;
        self.attached_backend_sector_count = 0;
        self.attached_backend_read = volume_backend.unattachedRead;
        self.attached_backend_write = volume_backend.unattachedWrite;
        self.attached_backend_flush = volume_backend.unattachedFlush;
        self.attached_backend_kind = .none;
        self.resetSignerText();
        self.workspace_state_hashes = .{};
    }

    fn ioLogWorkspace(self: *Volume) Error![]u8 {
        if (comptime heap_backed_io_workspace) {
            if (self.io_log_buffer) |buffer| return buffer[0..IO_LOG_WORKSPACE_BYTES];
            const allocation = kernel_memory.kmalloc(IO_LOG_WORKSPACE_BYTES) orelse return error.NoSpaceLeft;
            const buffer: [*]u8 = @ptrCast(allocation);
            self.io_log_buffer = buffer;
            return buffer[0..IO_LOG_WORKSPACE_BYTES];
        }
        return self.io_log_buffer[0..];
    }

    fn releaseIoLogWorkspace(self: *Volume) void {
        if (comptime heap_backed_io_workspace) {
            if (self.io_log_buffer) |buffer| {
                @memset(buffer[0..IO_LOG_WORKSPACE_BYTES], 0);
                kernel_memory.kfree(@ptrCast(buffer));
                self.io_log_buffer = null;
            }
        }
    }

    fn resetSignerText(self: *Volume) void {
        self.signer_text_len = 0;
        @memset(&self.signer_text_pool, 0);
    }

    fn internSigner(self: *Volume, signer: []const u8) Error![]const u8 {
        if (signer.len == 0) return "";
        if (signer.len > max_signer_bytes or signer.len > std.math.maxInt(u8)) {
            return error.InvalidSignatureEncoding;
        }

        const used: usize = self.signer_text_len;
        var offset: usize = 0;
        while (offset < used) {
            const stored_len: usize = self.signer_text_pool[offset];
            const start = offset + 1;
            const end = start + stored_len;
            if (end > used) return error.InvalidSignatureEncoding;
            if (std.mem.eql(u8, self.signer_text_pool[start..end], signer)) {
                return self.signer_text_pool[start..end];
            }
            offset = end;
        }

        const start = used + 1;
        const end = start + signer.len;
        if (end > self.signer_text_pool.len) return error.InvalidSignatureEncoding;
        self.signer_text_pool[used] = @intCast(signer.len);
        @memcpy(self.signer_text_pool[start..end], signer);
        self.signer_text_len = @intCast(end);
        return self.signer_text_pool[start..end];
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

comptime {
    if (heap_backed_io_workspace and @sizeOf(Volume) > 16 * 1024) {
        @compileError("heap-backed storage volumes exceed their compact resident layout");
    }
}

var default_volume = Volume.init();

pub fn defaultVolume() *Volume {
    return &default_volume;
}

const CursorWriter = binary_cursor.Writer(Error, error.NoSpaceLeft);
const CursorReader = binary_cursor.Reader(Error, error.CorruptImage);

fn readBoundedCount(comptime Count: type, reader: *CursorReader, comptime maximum: usize) Error!Count {
    if (maximum > std.math.maxInt(Count)) {
        @compileError("bounded persisted count exceeds its resident type");
    }
    const value = try reader.readU16();
    if (value > maximum) return error.CorruptImage;
    return @intCast(value);
}

test "bounded persisted counts reject invalid values before narrowing" {
    const above_capacity = [_]u8{ 97, 0 };
    var capacity_reader = CursorReader{ .buffer = &above_capacity };
    try std.testing.expectError(
        error.CorruptImage,
        readBoundedCount(workspace.WorkspaceEntryCount, &capacity_reader, workspace.MAX_WORKSPACE_ENTRIES),
    );

    const above_resident_type = [_]u8{ 0, 1 };
    var type_reader = CursorReader{ .buffer = &above_resident_type };
    try std.testing.expectError(
        error.CorruptImage,
        readBoundedCount(workspace.WorkspaceEntryCount, &type_reader, workspace.MAX_WORKSPACE_ENTRIES),
    );
}

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
    const io_log_buffer = try self.ioLogWorkspace();
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
            try tryBuildAppendDelta(io_log_buffer, loaded.root, store, workspaces, state_hashes)
        else
            null
    else
        null;

    if (current != null and !can_append) try flushWrites(writer);

    if (can_append and delta != null and delta.?.bytes_len == 0) {
        if (started_dirty) try flushWrites(writer);
        store.clearDirty();
        workspaces.clearDirty();
        return .{ .generation = current_generation };
    }

    if (can_append and delta != null and appendLogFits(current.?.root, delta.?)) {
        const next_generation = current_generation + 1;
        const data_offset = current.?.root.data_offset;
        const next_log_bytes = current.?.root.log_bytes + @as(u32, @intCast(delta.?.bytes_len));
        var next_root = try buildRootState(next_generation, next_log_bytes, store, workspaces, state_hashes);
        next_root.data_offset = data_offset;
        next_root.log_record_count = current.?.root.log_record_count + delta.?.record_count;
        next_root.log_segment_count = current.?.root.log_segment_count + delta.?.segment_count;
        next_root.compacted_generation = current.?.root.compacted_generation;
        const next_root_sector = volume_root_slot.nextRootSector(current);

        try writeBytes(writer, data_start_byte + data_offset + current.?.root.log_bytes, io_log_buffer[0..delta.?.bytes_len]);
        try flushWrites(writer);
        try writeRoot(writer, next_root_sector, next_root);
        try flushWrites(writer);
        store.clearDirty();
        workspaces.clearDirty();
        return .{ .generation = next_generation };
    }

    const checkpoint_log_len = try serializeCheckpointRecord(
        store,
        workspaces,
        io_log_buffer[0..data_region_bytes],
    );

    const next_generation = current_generation + 1;

    const next_data_offset: u32 = if (current) |loaded|
        (if (loaded.root.data_offset == 0) alternate_data_region_offset else 0)
    else
        0;
    var next_root = try buildRootState(next_generation, @intCast(checkpoint_log_len), store, workspaces, state_hashes);
    next_root.data_offset = next_data_offset;
    next_root.log_record_count = 1;
    next_root.log_segment_count = 0;
    next_root.compacted_generation = next_generation;
    const next_root_sector = volume_root_slot.nextRootSector(current);
    try writeBytes(writer, data_start_byte + next_data_offset, io_log_buffer[0..checkpoint_log_len]);
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
    self.resetSignerText();
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
    self.resetSignerText();
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
    const io_log_buffer = try self.ioLogWorkspace();
    if (!volume_backend.readAttachedBytes(self, data_start_byte + loaded.root.data_offset, io_log_buffer[0..loaded.root.log_bytes])) return error.CorruptImage;
    try replayLog(self, store, workspaces, io_log_buffer[0..loaded.root.log_bytes], loaded.root);
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
        if (slot.workspace.counts.entry_count > envelope.max_workspace_entries_per_workspace) return error.NoSpaceLeft;
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

const ReplayIdBounds = struct {
    max_object_id: u64 = 0,
    max_version_id: u64 = 0,
    max_workspace_id: u64 = 0,
    max_snapshot_id: u64 = 0,

    fn noteObject(self: *ReplayIdBounds, id: u64) void {
        self.max_object_id = @max(self.max_object_id, id);
    }

    fn noteVersion(self: *ReplayIdBounds, id: u64) void {
        self.max_version_id = @max(self.max_version_id, id);
    }

    fn noteWorkspace(self: *ReplayIdBounds, id: u64) void {
        self.max_workspace_id = @max(self.max_workspace_id, id);
    }

    fn noteSnapshot(self: *ReplayIdBounds, id: u64) void {
        self.max_snapshot_id = @max(self.max_snapshot_id, id);
    }

    fn fitRoot(self: ReplayIdBounds, root: RootState) bool {
        return issuedBeforeNext(self.max_object_id, root.next_object_id) and
            self.max_version_id <= root.last_version_id and
            issuedBeforeNext(self.max_workspace_id, root.next_workspace_id) and
            self.max_snapshot_id <= root.last_snapshot_id;
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
        const blob = store.versionBlob(version_record) orelse return error.CorruptImage;
        try appendBlobRecord(&writer, store, blob);
        try appendVersionRecord(&writer, store, version_record);
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

fn tryBuildAppendDelta(
    buffer: []u8,
    root: RootState,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
    state_hashes: *WorkspaceStateHashCache,
) Error!?BuiltLog {
    return buildDeltaLog(buffer, root, store, workspaces, state_hashes) catch |err| switch (err) {
        error.NoSpaceLeft => null,
        else => return err,
    };
}

fn canAppendToRoot(root: RootState, store: *const object_store.Store, workspaces: *const workspace.Directory) bool {
    if (!volume_root_slot.hasCanonicalDeltaWatermarks(root)) return false;
    if (volume_root_slot.lastIssuedId(root.next_object_id) > volume_root_slot.lastIssuedId(store.next_object_id)) return false;
    if (root.last_version_id > volume_root_slot.lastIssuedId(store.next_version_id)) return false;
    if (volume_root_slot.lastIssuedId(root.next_workspace_id) > volume_root_slot.lastIssuedId(workspaces.next_workspace_id)) return false;
    if (root.last_snapshot_id > volume_root_slot.lastIssuedId(workspaces.next_snapshot_id)) return false;

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
    self.resetSignerText();

    self.workspace_state_hashes.reset();
    if (root.log_record_count == 0 or root.log_record_count > max_replay_log_records) return error.CorruptImage;
    if (root.log_segment_count > max_log_segments) return error.CorruptImage;

    var reader = CursorReader{ .buffer = log };
    var replayed_id_bounds = ReplayIdBounds{};
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
            .checkpoint => try deserializeState(self, store, workspaces, payload, &replayed_id_bounds),
            .segment_boundary => {
                if (payload.len != 0) return error.CorruptImage;
                replayed_segments += 1;
                if (replayed_segments > max_log_segments) return error.CorruptImage;
            },
            .object_state => replayed_id_bounds.noteObject(try applyObjectRecord(self, store, payload)),
            .chunk_state => try applyChunkRecord(store, payload),
            .blob_state => try applyBlobRecord(store, payload),
            .version_state => replayed_id_bounds.noteVersion(try applyVersionRecord(self, store, payload)),
            .workspace_state => replayed_id_bounds.noteWorkspace(try applyWorkspaceRecord(workspaces, payload)),
            .snapshot_state => replayed_id_bounds.noteSnapshot(try applySnapshotRecord(self, workspaces, payload)),
        }
    }
    if (replayed_records == 0) return error.MissingCheckpoint;
    if (replayed_records != root.log_record_count) return error.CorruptImage;
    if (replayed_segments != root.log_segment_count) return error.CorruptImage;
    if (!replayed_id_bounds.fitRoot(root)) return error.CorruptImage;

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

fn appendVersionRecord(writer: *CursorWriter, store: *const object_store.Store, record: *const object_store.VersionRecord) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .version_state);
    try encodeVersionBody(writer, store, record);
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

fn encodeVersionBody(writer: *CursorWriter, store: *const object_store.Store, record: *const object_store.VersionRecord) Error!void {
    const blob = store.versionBlob(record) orelse return error.CorruptImage;
    try writer.writeU64(record.id.raw());
    try writer.writeU64(record.object_id.raw());
    try writer.writeU64(record.previous_version_id.raw());
    try writer.writeByte(record.parent_count);
    var parent_index: usize = 0;
    while (parent_index < object_store.MAX_VERSION_PARENTS) : (parent_index += 1) {
        try writer.writeU64(record.parent_version_ids[parent_index].raw());
    }
    try writer.writeByte(@intFromEnum(record.object_type));
    try writer.writeBytes(&blob.address);
    try writer.writeBytes(&record.version_address);
    try writeMetadata(writer, record.metadata);
    try writer.writeU32(blob.payload_len);
    try writer.writeU16(blob.chunk_count);
}

fn appendBlobRecord(writer: *CursorWriter, store: *const object_store.Store, record: *const object_store.BlobRecord) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .blob_state);
    try encodeBlobBody(writer, store, record);
    try volume_log.finishRecord(writer, header_offset);
}

fn appendPayloadChunkRecord(writer: *CursorWriter, chunk: object_store.PayloadChunk) Error!void {
    const header_offset = try volume_log.beginRecord(writer, .chunk_state);
    try writer.writeBytes(&chunk.address);
    try writer.writeU16(@intCast(chunk.bytes.len));
    try writer.writeBytes(chunk.bytes);
    try volume_log.finishRecord(writer, header_offset);
}

fn encodeBlobBody(writer: *CursorWriter, store: *const object_store.Store, record: *const object_store.BlobRecord) Error!void {
    try writer.writeBytes(&record.address);
    try writer.writeBytes(&record.merkle_root);
    try writer.writeU32(record.payload_len);
    try writer.writeU16(record.ref_count);
    try writer.writeU16(record.chunk_count);
    const chunk_count: usize = @intCast(record.chunk_count);
    for (0..chunk_count) |chunk_index| {
        const chunk_ref = store.blobChunkRef(record, chunk_index) catch return error.CorruptImage;
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
    try writer.writeU16(@intCast(record.counts.entry_count));
    for (record.path_index.entries[0..record.counts.entry_count]) |entry| {
        try writeEntry(writer, entry);
    }
    try writer.writeU16(@intCast(record.counts.entry_mutation_count));
    for (record.mutation_log.entriesConst()[0..record.counts.entry_mutation_count]) |mutation| {
        try writer.writeU32(mutation.generation);
        try writeEntry(writer, mutation.entry);
    }
    try writer.writeU16(@intCast(record.counts.share_grant_count));
    for (record.share_table.share_grants[0..record.counts.share_grant_count]) |grant| {
        try writeShareGrant(writer, grant);
    }
    try writer.writeU16(@intCast(record.counts.deleted_count));
    for (record.recoverable_deletes.deleted_entries[0..record.counts.deleted_count]) |entry| {
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

fn applyObjectRecord(self: *Volume, store: *object_store.Store, payload: []const u8) Error!u64 {
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
    try readObjectUserDataTail(self, &reader, &object_record);
    store.objects.slots[slot_index].object = object_record;
    return object_id.raw();
}

fn applyVersionRecord(self: *Volume, store: *object_store.Store, payload: []const u8) Error!u64 {
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
    var blob_address: object_store.BlobAddress = undefined;
    try reader.readBytes(&blob_address);
    try reader.readBytes(&store.versions.slots[slot_index].version.version_address);
    store.versions.slots[slot_index].version.metadata = try readMetadata(self, &reader);
    const payload_len: usize = @intCast(try reader.readU32());
    if (payload_len > object_store.MAX_PAYLOAD_BYTES) return error.CorruptImage;
    const chunk_count_value = try reader.readU16();
    if (chunk_count_value > object_store.MAX_BLOB_CHUNKS) return error.CorruptImage;
    const blob_slot_index = findBlobSlotIndex(store, blob_address) orelse return error.CorruptImage;
    const blob = &store.blobSlotAtConst(blob_slot_index).blob;
    if (blob.payloadLen() != payload_len or blob.chunk_count != chunk_count_value) return error.CorruptImage;
    store.versions.slots[slot_index].version.blob_slot_index = @intCast(blob_slot_index);
    return version_id.raw();
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
    var chunk_slot_indexes = [_]object_store.BlobChunkSlotIndex{0} ** object_store.MAX_BLOB_CHUNKS;
    var chunk_index: usize = 0;
    while (chunk_index < chunk_count) : (chunk_index += 1) {
        try reader.readBytes(&chunk_refs[chunk_index].address);
        chunk_refs[chunk_index].payload_len = try reader.readU16();
        const chunk_slot_index = store.chunkSlotIndex(chunk_refs[chunk_index].address) orelse return error.CorruptImage;
        const chunk_slot = store.chunkSlotAtConst(chunk_slot_index);
        if (!chunk_slot.in_use or chunk_slot.chunk.payload_len != chunk_refs[chunk_index].payload_len) return error.CorruptImage;
        chunk_slot_indexes[chunk_index] = @intCast(chunk_slot_index);
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
    slot.blob.payload_len = @intCast(payload_len);
    slot.blob.ref_count = ref_count;
    slot.blob.chunk_count = @intCast(chunk_count);
    slot.blob.chunk_slot_indexes = chunk_slot_indexes;
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

fn applyWorkspaceRecord(workspaces: *workspace.Directory, payload: []const u8) Error!u64 {
    var reader = CursorReader{ .buffer = payload };
    const workspace_id = ids.workspace(try reader.readU64());
    const existing_slot = workspaces.workspaces.get(workspace_id);
    const slot = existing_slot orelse
        workspaces.workspaces.reserveClean(workspace_id) orelse return error.CorruptImage;
    slot.workspace.mutation_log.ensureBacking() catch {
        if (existing_slot == null) std.debug.assert(workspaces.workspaces.remove(workspace_id));
        return error.NoSpaceLeft;
    };

    const previous_entry_count = slot.workspace.counts.entry_count;
    const previous_mutation_count = slot.workspace.counts.entry_mutation_count;
    const previous_share_grant_count = slot.workspace.counts.share_grant_count;
    const previous_staged_entry_count = slot.workspace.staging.staged_entry_count;
    const previous_mutation_tail = @min(
        previous_mutation_count + previous_staged_entry_count,
        workspace.MAX_WORKSPACE_ENTRY_MUTATIONS,
    );
    const previous_deleted_count = slot.workspace.counts.deleted_count;
    slot.workspace.id = workspace_id;
    slot.workspace.owner = try readPrincipal(&reader);
    readTextInto(&reader, &slot.workspace.label, &slot.workspace.label_len) catch return error.CorruptImage;
    slot.workspace.generation = try reader.readU32();
    slot.workspace.counts.entry_count = try readBoundedCount(workspace.WorkspaceEntryCount, &reader, workspace.MAX_WORKSPACE_ENTRIES);
    for (0..slot.workspace.counts.entry_count) |entry_index| {
        slot.workspace.path_index.entries[entry_index] = try readEntry(&reader);
    }
    if (slot.workspace.counts.entry_count < previous_entry_count) {
        for (slot.workspace.path_index.entries[slot.workspace.counts.entry_count..previous_entry_count]) |*entry| {
            entry.* = .{};
        }
    }
    slot.workspace.counts.entry_mutation_count = try readBoundedCount(workspace.WorkspaceMutationCount, &reader, workspace.MAX_WORKSPACE_ENTRY_MUTATIONS);
    const mutations = slot.workspace.mutation_log.entries();
    for (0..slot.workspace.counts.entry_mutation_count) |mutation_index| {
        mutations[mutation_index] = .{
            .generation = try reader.readU32(),
            .entry = try readEntry(&reader),
        };
    }
    if (slot.workspace.counts.entry_mutation_count < previous_mutation_tail) {
        for (mutations[slot.workspace.counts.entry_mutation_count..previous_mutation_tail]) |*mutation| {
            mutation.* = .{};
        }
    }
    slot.workspace.counts.share_grant_count = try readBoundedCount(workspace.WorkspaceShareGrantCount, &reader, workspace.MAX_SHARE_GRANTS);
    for (0..slot.workspace.counts.share_grant_count) |grant_index| {
        slot.workspace.share_table.share_grants[grant_index] = try readShareGrant(&reader);
    }
    if (slot.workspace.counts.share_grant_count < previous_share_grant_count) {
        for (slot.workspace.share_table.share_grants[slot.workspace.counts.share_grant_count..previous_share_grant_count]) |*grant| {
            grant.* = .{ .principal_id = .{ .kind = .service, .serial = 0 } };
        }
    }
    slot.workspace.counts.deleted_count = try readBoundedCount(workspace.RecoverableDeleteCount, &reader, workspace.MAX_RECOVERABLE_DELETES);
    for (0..slot.workspace.counts.deleted_count) |entry_index| {
        slot.workspace.recoverable_deletes.deleted_entries[entry_index] = try readEntry(&reader);
    }
    if (slot.workspace.counts.deleted_count < previous_deleted_count) {
        for (slot.workspace.recoverable_deletes.deleted_entries[slot.workspace.counts.deleted_count..previous_deleted_count]) |*entry| {
            entry.* = .{};
        }
    }

    slot.workspace.staging.transaction_open = false;
    slot.workspace.staging.staged_entry_count = 0;
    slot.workspace.staging.staged_effective_entry_count = 0;
    return workspace_id.raw();
}

fn applySnapshotRecord(self: *Volume, workspaces: *workspace.Directory, payload: []const u8) Error!u64 {
    var reader = CursorReader{ .buffer = payload };
    const snapshot_id = ids.snapshot(try reader.readU64());
    const slot_index = workspaces.snapshots.slotIndexOf(snapshot_id) orelse
        workspaces.snapshots.reserveIndexClean(snapshot_id) orelse return error.CorruptImage;
    workspaces.snapshots.slots[slot_index].snapshot.id = snapshot_id;
    workspaces.snapshots.slots[slot_index].snapshot.workspace_id = ids.workspace(try reader.readU64());
    workspaces.snapshots.slots[slot_index].snapshot.generation = try reader.readU32();
    readTextInto(&reader, &workspaces.snapshots.slots[slot_index].snapshot.label, &workspaces.snapshots.slots[slot_index].snapshot.label_len) catch return error.CorruptImage;
    try reader.readBytes(&workspaces.snapshots.slots[slot_index].snapshot.root_address);
    workspaces.snapshots.slots[slot_index].snapshot.signature = try readSignature(self, &reader);
    workspaces.snapshots.slots[slot_index].snapshot.entry_count = try readBoundedCount(u8, &reader, workspace.MAX_WORKSPACE_ENTRIES);
    return snapshot_id.raw();
}

fn serializeCheckpointRecord(
    store: *const object_store.Store,
    workspaces: *const workspace.Directory,
    buffer: []u8,
) Error!usize {
    var writer = CursorWriter{ .buffer = buffer };
    const header_offset = try volume_log.beginRecord(&writer, .checkpoint);
    writer.offset += try serializeState(store, workspaces, buffer[writer.offset..]);
    try volume_log.finishRecord(&writer, header_offset);
    return writer.offset;
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
        try encodeBlobBody(&writer, store, &slot.blob);
    }

    for (&store.versions.slots) |*slot| {
        if (!slot.in_use) continue;
        try encodeVersionBody(&writer, store, &slot.version);
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

fn deserializeState(
    self: *Volume,
    store: *object_store.Store,
    workspaces: *workspace.Directory,
    payload: []const u8,
    replayed_id_bounds: *ReplayIdBounds,
) Error!void {
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
        replayed_id_bounds.noteObject(object_id.raw());
        const slot_index = store.objects.reserveIndexClean(object_id) orelse return error.CorruptImage;
        const slot = &store.objects.slots[slot_index];
        slot.object.id = object_id;
        slot.object.object_type = try parseObjectType(try reader.readByte());
        slot.object.latest_version_id = ids.version(try reader.readU64());
        slot.object.version_count = try reader.readU16();
        try readObjectUserDataTail(self, &reader, &slot.object);
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
        replayed_id_bounds.noteVersion(version_id.raw());
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
        var blob_address: object_store.BlobAddress = undefined;
        try reader.readBytes(&blob_address);
        try reader.readBytes(&store.versions.slots[slot_index].version.version_address);
        store.versions.slots[slot_index].version.metadata = try readMetadata(self, &reader);
        const payload_len: usize = @intCast(try reader.readU32());
        if (payload_len > object_store.MAX_PAYLOAD_BYTES) return error.CorruptImage;
        const chunk_count_value = try reader.readU16();
        if (chunk_count_value > object_store.MAX_BLOB_CHUNKS) return error.CorruptImage;
        const blob_slot_index = findBlobSlotIndex(store, blob_address) orelse return error.CorruptImage;
        const blob = &store.blobSlotAtConst(blob_slot_index).blob;
        if (blob.payloadLen() != payload_len or blob.chunk_count != chunk_count_value) return error.CorruptImage;
        store.versions.slots[slot_index].version.blob_slot_index = @intCast(blob_slot_index);
    }

    for (0..@as(usize, workspace_count_value)) |_| {
        const workspace_id = ids.workspace(try reader.readU64());
        replayed_id_bounds.noteWorkspace(workspace_id.raw());
        const slot = workspaces.workspaces.reserveClean(workspace_id) orelse return error.CorruptImage;
        slot.workspace.mutation_log.ensureBacking() catch {
            std.debug.assert(workspaces.workspaces.remove(workspace_id));
            return error.NoSpaceLeft;
        };
        slot.workspace.id = workspace_id;
        slot.workspace.owner = try readPrincipal(&reader);
        readTextInto(&reader, &slot.workspace.label, &slot.workspace.label_len) catch return error.CorruptImage;
        slot.workspace.generation = try reader.readU32();
        slot.workspace.counts.entry_count = try readBoundedCount(workspace.WorkspaceEntryCount, &reader, workspace.MAX_WORKSPACE_ENTRIES);
        for (0..slot.workspace.counts.entry_count) |entry_index| {
            slot.workspace.path_index.entries[entry_index] = try readEntry(&reader);
        }
        slot.workspace.counts.entry_mutation_count = try readBoundedCount(workspace.WorkspaceMutationCount, &reader, workspace.MAX_WORKSPACE_ENTRY_MUTATIONS);
        const mutations = slot.workspace.mutation_log.entries();
        for (0..slot.workspace.counts.entry_mutation_count) |mutation_index| {
            mutations[mutation_index] = .{
                .generation = try reader.readU32(),
                .entry = try readEntry(&reader),
            };
        }
        slot.workspace.counts.share_grant_count = try readBoundedCount(workspace.WorkspaceShareGrantCount, &reader, workspace.MAX_SHARE_GRANTS);
        for (0..slot.workspace.counts.share_grant_count) |grant_index| {
            slot.workspace.share_table.share_grants[grant_index] = try readShareGrant(&reader);
        }
        slot.workspace.counts.deleted_count = try readBoundedCount(workspace.RecoverableDeleteCount, &reader, workspace.MAX_RECOVERABLE_DELETES);
        for (0..slot.workspace.counts.deleted_count) |entry_index| {
            slot.workspace.recoverable_deletes.deleted_entries[entry_index] = try readEntry(&reader);
        }
    }

    for (0..@as(usize, snapshot_count_value)) |_| {
        const snapshot_id = ids.snapshot(try reader.readU64());
        replayed_id_bounds.noteSnapshot(snapshot_id.raw());
        const slot_index = workspaces.snapshots.reserveIndexClean(snapshot_id) orelse return error.CorruptImage;
        workspaces.snapshots.slots[slot_index].snapshot.id = snapshot_id;
        workspaces.snapshots.slots[slot_index].snapshot.workspace_id = ids.workspace(try reader.readU64());
        workspaces.snapshots.slots[slot_index].snapshot.generation = try reader.readU32();
        readTextInto(&reader, &workspaces.snapshots.slots[slot_index].snapshot.label, &workspaces.snapshots.slots[slot_index].snapshot.label_len) catch return error.CorruptImage;
        try reader.readBytes(&workspaces.snapshots.slots[slot_index].snapshot.root_address);
        workspaces.snapshots.slots[slot_index].snapshot.signature = try readSignature(self, &reader);
        workspaces.snapshots.slots[slot_index].snapshot.entry_count = try readBoundedCount(u8, &reader, workspace.MAX_WORKSPACE_ENTRIES);
    }
}

fn writeMetadata(writer: *CursorWriter, metadata: object_store.SignedMetadata) Error!void {
    try writeText(writer, metadata.labelSlice());
    try writeText(writer, metadata.contentTypeSlice());
    try writer.writeU64(metadata.created_at_ticks);
    try writeSignature(writer, metadata.signature);
}

fn readMetadata(self: *Volume, reader: *CursorReader) Error!object_store.SignedMetadata {
    var metadata = object_store.SignedMetadata{};
    readTextInto(reader, &metadata.label, &metadata.label_len) catch return error.CorruptImage;
    readTextInto(reader, &metadata.content_type, &metadata.content_type_len) catch return error.CorruptImage;
    metadata.created_at_ticks = try reader.readU64();
    metadata.signature = try readSignature(self, reader);
    return metadata;
}

fn readObjectUserDataTail(
    self: *Volume,
    reader: *CursorReader,
    record: *object_store.ObjectRecord,
) Error!void {
    record.provenance.created_at_ticks = try reader.readU64();
    record.provenance.updated_at_ticks = try reader.readU64();
    record.provenance.creator_signature = try readSignature(self, reader);
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
        const public_key_len = @min(@as(usize, signature.public_key_len), signature.public_key.len);
        const value_len = @min(@as(usize, signature.value_len), signature.value.len);
        try writer.writeByte(1);
        try writeText(writer, signer);
        try writer.writeByte(@intCast(public_key_len));
        try writer.writeBytes(signature.public_key[0..public_key_len]);
        try writer.writeByte(@intCast(value_len));
        try writer.writeBytes(signature.value[0..value_len]);
        return;
    }
    try writer.writeByte(0);
}

fn readSignature(self: *Volume, reader: *CursorReader) Error!@import("../policy/manifest.zig").Signature {
    const manifest = @import("../policy/manifest.zig");
    const present = try reader.readByte();
    if (present == 0) return .{};

    const signer_len = try reader.readU16();
    if (signer_len > max_signer_bytes) return error.InvalidSignatureEncoding;
    var signer_storage: [max_signer_bytes]u8 = undefined;
    try reader.readBytes(signer_storage[0..signer_len]);
    const signer = try self.internSigner(signer_storage[0..signer_len]);

    var signature = manifest.Signature{
        .format = .ed25519,
        .signer = signer,
    };
    const public_key_len = try reader.readByte();
    if (public_key_len > signature.public_key.len) return error.InvalidSignatureEncoding;
    signature.public_key_len = @intCast(public_key_len);
    try reader.readBytes(signature.public_key[0..public_key_len]);
    const value_len = try reader.readByte();
    if (value_len > signature.value.len) return error.InvalidSignatureEncoding;
    signature.value_len = @intCast(value_len);
    try reader.readBytes(signature.value[0..value_len]);
    return signature;
}

fn writeText(writer: *CursorWriter, text: []const u8) Error!void {
    try writer.writeU16(@intCast(text.len));
    try writer.writeBytes(text);
}

fn readTextInto(reader: *CursorReader, buffer: []u8, out_len: anytype) Error!void {
    const len: usize = try reader.readU16();
    if (len > buffer.len) return error.CorruptImage;
    const Length = @TypeOf(out_len.*);
    if (len > std.math.maxInt(Length)) return error.CorruptImage;
    @memset(buffer[0..], 0);
    try reader.readBytes(buffer[0..len]);
    out_len.* = @intCast(len);
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

test "storage volume bounds its log io workspace to one durable data region" {
    try std.testing.expect(@hasField(Volume, "io_log_buffer"));
    try std.testing.expect(!@hasField(Volume, "io_payload_buffer"));
    try std.testing.expectEqual(DATA_REGION_BYTES, IO_LOG_WORKSPACE_BYTES);
    if (heap_backed_io_workspace) {
        try std.testing.expect(@sizeOf(@FieldType(Volume, "io_log_buffer")) <= @sizeOf(usize));
    } else {
        try std.testing.expectEqual(IO_LOG_WORKSPACE_BYTES, @sizeOf(@FieldType(Volume, "io_log_buffer")));
    }
}

test "append workspace exhaustion falls back to checkpoint compaction" {
    const allocator = std.testing.allocator;
    const store = try allocator.create(object_store.Store);
    defer allocator.destroy(store);
    store.* = object_store.Store.init();
    const workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(workspaces);
    workspaces.* = workspace.Directory.init();
    var state_hashes = WorkspaceStateHashCache{};
    var exhausted_workspace: [0]u8 = .{};

    try std.testing.expectEqual(
        @as(?BuiltLog, null),
        try tryBuildAppendDelta(&exhausted_workspace, .{}, store, workspaces, &state_hashes),
    );
}

test "checkpoint records accept exact capacity and reject one byte less" {
    const allocator = std.testing.allocator;
    const store = try allocator.create(object_store.Store);
    defer allocator.destroy(store);
    store.* = object_store.Store.init();
    const workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(workspaces);
    workspaces.* = workspace.Directory.init();

    var payload_probe: [128]u8 = undefined;
    const payload_len = try serializeState(store, workspaces, payload_probe[0..]);
    const exact_record_len = volume_log.recordHeaderLen() + payload_len;
    const record_storage = try allocator.alloc(u8, exact_record_len + 1);
    defer allocator.free(record_storage);
    @memset(record_storage, 0);

    record_storage[exact_record_len] = 0xA5;
    const written = try serializeCheckpointRecord(store, workspaces, record_storage[0..exact_record_len]);
    try std.testing.expectEqual(exact_record_len, written);
    try std.testing.expectEqual(@as(u8, 0xA5), record_storage[exact_record_len]);

    var reader = CursorReader{ .buffer = record_storage[0..written] };
    const header = try volume_log.readRecordHeader(&reader);
    try std.testing.expectEqual(volume_log.RecordKind.checkpoint, header.kind);
    try std.testing.expectEqual(@as(u32, @intCast(payload_len)), header.payload_len);
    try std.testing.expectEqual(
        volume_hashing.checksumBytes(record_storage[volume_log.recordHeaderLen()..written]),
        header.checksum,
    );

    record_storage[exact_record_len - 1] = 0x5A;
    try std.testing.expectError(
        error.NoSpaceLeft,
        serializeCheckpointRecord(store, workspaces, record_storage[0 .. exact_record_len - 1]),
    );
    try std.testing.expectEqual(@as(u8, 0x5A), record_storage[exact_record_len - 1]);
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

test "workspace delta replay overwrites live prefixes and scrubs retired data" {
    const allocator = std.testing.allocator;
    const workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(workspaces);
    workspaces.* = workspace.Directory.init();

    const live = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 41 },
        .label = "live-workspace",
    });
    live.counts.entry_count = 2;
    live.path_index.entries[0] = try workspace.Entry.init("documents/keep.md", ids.object(1), ids.version(1), .document);
    live.path_index.entries[1] = try workspace.Entry.init("documents/retired.md", ids.object(2), ids.version(2), .document);
    live.counts.entry_mutation_count = 2;
    live.mutation_log.entries()[0] = .{ .generation = 1, .entry = live.path_index.entries[0] };
    live.mutation_log.entries()[1] = .{ .generation = 2, .entry = live.path_index.entries[1] };
    live.counts.share_grant_count = 2;
    live.share_table.share_grants[0] = .{ .principal_id = .{ .kind = .user, .serial = 42 } };
    live.share_table.share_grants[1] = .{ .principal_id = .{ .kind = .user, .serial = 43 } };
    live.counts.deleted_count = 2;
    live.recoverable_deletes.deleted_entries[0] = live.path_index.entries[0];
    live.recoverable_deletes.deleted_entries[1] = live.path_index.entries[1];
    live.staging.transaction_open = true;
    live.staging.staged_entry_count = 1;
    live.staging.staged_effective_entry_count = 2;
    live.mutation_log.entries()[live.counts.entry_mutation_count] = .{
        .entry = try workspace.Entry.init("documents/staged-secret.md", ids.object(3), ids.version(3), .document),
    };

    const replacement_workspaces = try allocator.create(workspace.Directory);
    defer allocator.destroy(replacement_workspaces);
    replacement_workspaces.* = workspace.Directory.init();
    const replacement = try replacement_workspaces.create(.{
        .owner = live.owner,
        .label = "replacement-workspace",
    });
    replacement.generation = 7;
    replacement.counts.entry_count = 1;
    replacement.path_index.entries[0] = try workspace.Entry.init("documents/current.md", ids.object(4), ids.version(4), .document);
    replacement.counts.entry_mutation_count = 1;
    replacement.mutation_log.entries()[0] = .{ .generation = 7, .entry = replacement.path_index.entries[0] };
    replacement.counts.share_grant_count = 1;
    replacement.share_table.share_grants[0] = .{ .principal_id = .{ .kind = .user, .serial = 44 } };
    replacement.counts.deleted_count = 1;
    replacement.recoverable_deletes.deleted_entries[0] = replacement.path_index.entries[0];

    const payload = try allocator.alloc(u8, max_payload_bytes);
    defer allocator.free(payload);
    var writer = CursorWriter{ .buffer = payload };
    try encodeWorkspaceBody(&writer, replacement);
    _ = try applyWorkspaceRecord(workspaces, payload[0..writer.offset]);

    try std.testing.expectEqualStrings("replacement-workspace", live.labelSlice());
    try std.testing.expectEqual(@as(u32, 7), live.generation);
    try std.testing.expectEqual(@as(usize, 1), live.counts.entry_count);
    try std.testing.expectEqualStrings("documents/current.md", live.path_index.entries[0].pathSlice());
    try std.testing.expectEqualDeep(workspace.Entry{}, live.path_index.entries[1]);
    try std.testing.expectEqualDeep(workspace.EntryMutation{}, live.mutation_log.entriesConst()[1]);
    try std.testing.expectEqual(principal.PrincipalKind.service, live.share_table.share_grants[1].principal_id.kind);
    try std.testing.expectEqual(@as(u64, 0), live.share_table.share_grants[1].principal_id.serial);
    try std.testing.expectEqualDeep(workspace.Entry{}, live.recoverable_deletes.deleted_entries[1]);
    try std.testing.expect(!live.staging.transaction_open);
    try std.testing.expectEqual(@as(usize, 0), live.staging.staged_entry_count);
    try std.testing.expectEqualDeep(workspace.EntryMutation{}, live.mutation_log.entriesConst()[2]);
}

test "inline replay ID bounds preserve root watermark validation" {
    try std.testing.expect(TRACKS_REPLAY_ID_BOUNDS_INLINE);

    var bounds = ReplayIdBounds{};
    bounds.noteObject(4);
    bounds.noteObject(8);
    bounds.noteVersion(12);
    bounds.noteWorkspace(3);
    bounds.noteSnapshot(9);

    try std.testing.expect(bounds.fitRoot(.{
        .next_object_id = 9,
        .last_version_id = 12,
        .next_workspace_id = 4,
        .last_snapshot_id = 9,
    }));
    try std.testing.expect(!bounds.fitRoot(.{
        .next_object_id = 8,
        .last_version_id = 12,
        .next_workspace_id = 4,
        .last_snapshot_id = 9,
    }));
    try std.testing.expect(!bounds.fitRoot(.{
        .next_object_id = 9,
        .last_version_id = 11,
        .next_workspace_id = 4,
        .last_snapshot_id = 9,
    }));
    try std.testing.expect(!bounds.fitRoot(.{
        .next_object_id = 9,
        .last_version_id = 12,
        .next_workspace_id = 3,
        .last_snapshot_id = 9,
    }));
    try std.testing.expect(!bounds.fitRoot(.{
        .next_object_id = 9,
        .last_version_id = 12,
        .next_workspace_id = 4,
        .last_snapshot_id = 8,
    }));
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

test "storage volume interns repeated signer labels within a bounded pool" {
    var volume = Volume.init();
    const first = try volume.internSigner("persistent-key");
    const repeated = try volume.internSigner("persistent-key");
    try std.testing.expect(first.ptr == repeated.ptr);
    try std.testing.expectEqualStrings(first, repeated);
    try std.testing.expectEqual(@as(u16, 1 + "persistent-key".len), volume.signer_text_len);

    var overflowed = false;
    const attempts = SIGNER_TEXT_POOL_BYTES / (max_signer_bytes + 1) + 2;
    for (0..attempts) |index| {
        var signer = [_]u8{'s'} ** max_signer_bytes;
        std.mem.writeInt(u32, signer[0..@sizeOf(u32)], @intCast(index), .little);
        _ = volume.internSigner(&signer) catch |err| {
            try std.testing.expect(err == error.InvalidSignatureEncoding);
            overflowed = true;
            break;
        };
    }
    try std.testing.expect(overflowed);
    try std.testing.expect(@as(usize, volume.signer_text_len) <= volume.signer_text_pool.len);
}

pub const testing = struct {
    pub fn signerTextBytes() usize {
        return default_volume.signer_text_len;
    }

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
