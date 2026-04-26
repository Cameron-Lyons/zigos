const builtin = @import("builtin");
const std = @import("std");
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
pub const slot_sectors: u32 = 384;
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
const root_format_version: u16 = 1;
const max_workspace_state_bytes: usize = 16 * 1024;

const volume_magic = "ZG4VOL1";
const payload_magic = "ZG4STATE";
const format_version: u16 = 2;

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

var io_payload_buffer: [max_payload_bytes]u8 = undefined;
var io_log_buffer: [data_capacity_bytes]u8 = undefined;
var sector_buffer: [sector_size]u8 = [_]u8{0} ** sector_size;
var workspace_state_buffer: [max_workspace_state_bytes]u8 = undefined;
var attached_backend_present = false;
var attached_backend_sector_count: u64 = 0;
var attached_backend_read: *const fn (u64, [*]u8, usize) callconv(.c) bool = unattachedRead;
var attached_backend_write: *const fn (u64, [*]const u8, usize) callconv(.c) bool = unattachedWrite;
var attached_backend_kind: AttachedBackendKind = .none;
var attached_ata_device: ?*const anyopaque = null;
var version_signers: [object_store.MAX_VERSIONS][max_signer_bytes]u8 =
    [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** object_store.MAX_VERSIONS;
var snapshot_signers: [workspace.MAX_SNAPSHOTS][max_signer_bytes]u8 =
    [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** workspace.MAX_SNAPSHOTS;

fn unattachedRead(_: u64, _: [*]u8, _: usize) callconv(.c) bool {
    return false;
}

fn unattachedWrite(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
    return false;
}

const CursorWriter = struct {
    buffer: []u8,
    offset: usize = 0,

    fn writeByte(self: *CursorWriter, value: u8) Error!void {
        if (self.offset >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    fn writeBytes(self: *CursorWriter, bytes: []const u8) Error!void {
        if (self.offset + bytes.len > self.buffer.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn writeU16(self: *CursorWriter, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU32(self: *CursorWriter, value: u32) Error!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU64(self: *CursorWriter, value: u64) Error!void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }
};

const CursorReader = struct {
    buffer: []const u8,
    offset: usize = 0,

    fn readByte(self: *CursorReader) Error!u8 {
        if (self.offset >= self.buffer.len) return error.CorruptImage;
        const value = self.buffer[self.offset];
        self.offset += 1;
        return value;
    }

    fn readBytes(self: *CursorReader, dest: []u8) Error!void {
        if (self.offset + dest.len > self.buffer.len) return error.CorruptImage;
        @memcpy(dest, self.buffer[self.offset .. self.offset + dest.len]);
        self.offset += dest.len;
    }

    fn readSlice(self: *CursorReader, len: usize) Error![]const u8 {
        if (self.offset + len > self.buffer.len) return error.CorruptImage;
        const slice = self.buffer[self.offset .. self.offset + len];
        self.offset += len;
        return slice;
    }

    fn readU16(self: *CursorReader) Error!u16 {
        var bytes: [2]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u16, &bytes, .little);
    }

    fn readU32(self: *CursorReader) Error!u32 {
        var bytes: [4]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u32, &bytes, .little);
    }

    fn readU64(self: *CursorReader) Error!u64 {
        var bytes: [8]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }
};

const SlotHeader = struct {
    generation: u64,
    payload_len: u32,
    checksum: u64,
};

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
};

const LogRecordHeader = struct {
    kind: LogRecordKind,
    payload_len: u32,
    checksum: u64,
};

const AttachedBackendKind = enum(u8) {
    none,
    generic,
    ata_bootstrap,
};

pub fn attachBackend(backend: Backend) void {
    attachBackendFns(backend.sector_count, backend.read, backend.write);
}

pub fn attachBackendFns(
    sector_count: u64,
    read: *const fn (start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool,
    write: *const fn (start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool,
) void {
    attached_backend_present = true;
    attached_backend_sector_count = sector_count;
    attached_backend_read = read;
    attached_backend_write = write;
    attached_backend_kind = .generic;
    attached_ata_device = null;
}

pub fn attachAtaBootstrapDevice(device: *const anyopaque, sector_count: u64) void {
    attached_backend_present = true;
    attached_backend_sector_count = sector_count;
    attached_backend_read = unattachedRead;
    attached_backend_write = unattachedWrite;
    attached_backend_kind = .ata_bootstrap;
    attached_ata_device = device;
}

pub fn clearAttachedBackend() void {
    attached_backend_present = false;
    attached_backend_sector_count = 0;
    attached_backend_read = unattachedRead;
    attached_backend_write = unattachedWrite;
    attached_backend_kind = .none;
    attached_ata_device = null;
}

pub fn hasAttachedDevice() bool {
    return attached_backend_present;
}

pub fn clearAttachedVolume() void {
    if (!hasAttachedDevice()) return;
    if (attached_backend_sector_count < required_device_sectors) return;
    @memset(sector_buffer[0..], 0);
    var sector_index: u32 = 0;
    while (sector_index < root_sector_count) : (sector_index += 1) {
        if (!writeAttachedRange(sector_index, sector_buffer[0..])) return;
    }
}

pub fn loadFromVolume(store: *object_store.Store, workspaces: *workspace.Directory) bool {
    if (!hasAttachedDevice()) return false;
    if (attached_backend_sector_count < required_device_sectors) return false;

    const loaded = (findLatestBackendRoot() catch return false) orelse return false;
    if (loaded.root.log_bytes == 0 or loaded.root.log_bytes > data_capacity_bytes) return false;
    if (!readAttachedBytes(data_start_byte, io_log_buffer[0..loaded.root.log_bytes])) return false;
    replayLog(store, workspaces, io_log_buffer[0..loaded.root.log_bytes], loaded.root) catch return false;
    return true;
}

pub fn saveToVolume(store: *const object_store.Store, workspaces: *const workspace.Directory) !PersistResult {
    if (!hasAttachedDevice()) return .{ .generation = 0 };
    if (attached_backend_sector_count < required_device_sectors) return error.ImageTooSmall;

    const current = findLatestBackendRoot() catch null;
    return saveIncremental(current, store, workspaces, BackendWriteFns{
        .write_bytes = writeAttachedBytes,
        .write_root = writeBackendRoot,
    });
}
pub fn saveToImage(image: []u8, store: *const object_store.Store, workspaces: *const workspace.Directory) !PersistResult {
    if (image.len < image_bytes) return error.ImageTooSmall;
    const current = findLatestImageRoot(image) catch null;
    return saveIncremental(current, store, workspaces, ImageWriteFns{
        .image = image,
    });
}

pub fn loadFromImage(image: []const u8, store: *object_store.Store, workspaces: *workspace.Directory) !u64 {
    if (image.len < image_bytes) return error.ImageTooSmall;
    const loaded = (try findLatestImageRoot(image)) orelse return error.CorruptImage;
    if (loaded.root.log_bytes == 0 or loaded.root.log_bytes > data_capacity_bytes) return error.CorruptImage;
    @memcpy(io_log_buffer[0..loaded.root.log_bytes], image[data_start_byte .. data_start_byte + loaded.root.log_bytes]);
    try replayLog(store, workspaces, io_log_buffer[0..loaded.root.log_bytes], loaded.root);
    return loaded.root.generation;
}

const BackendWriteFns = struct {
    write_bytes: *const fn (offset: usize, bytes: []const u8) bool,
    write_root: *const fn (sector_index: u32, root: RootState) Error!void,
};

const ImageWriteFns = struct {
    image: []u8,
};

fn saveIncremental(
    current: ?LoadedRoot,
    store: *const object_store.Store,
    workspaces: *const workspace.Directory,
    writer: anytype,
) Error!PersistResult {
    const current_generation = if (current) |loaded| loaded.root.generation else 0;
    const append_len = if (current) |loaded|
        try buildDeltaLog(io_log_buffer[0..], loaded.root, store, workspaces)
    else
        0;

    if (current != null and append_len == 0) {
        return .{ .generation = current_generation };
    }

    if (current != null and appendLenFits(current.?.root, append_len)) {
        const next_generation = current_generation + 1;
        const next_root = buildRootState(next_generation, current.?.root.log_bytes + @as(u32, @intCast(append_len)), store, workspaces);
        const next_root_sector = nextRootSector(current);
        try writeBytes(writer, data_start_byte + current.?.root.log_bytes, io_log_buffer[0..append_len]);
        try writeRoot(writer, next_root_sector, next_root);
        return .{ .generation = next_generation };
    }

    const checkpoint_payload_len = try serializeState(store, workspaces, io_payload_buffer[0..]);
    var log_writer = CursorWriter{ .buffer = io_log_buffer[0..] };
    try appendRecordPayload(&log_writer, .checkpoint, io_payload_buffer[0..checkpoint_payload_len]);

    const next_generation = current_generation + 1;
    const next_root = buildRootState(next_generation, @intCast(log_writer.offset), store, workspaces);
    const next_root_sector = nextRootSector(current);
    try writeBytes(writer, data_start_byte, io_log_buffer[0..log_writer.offset]);
    try writeRoot(writer, next_root_sector, next_root);
    return .{ .generation = next_generation };
}

fn appendLenFits(root: RootState, append_len: usize) bool {
    return @as(usize, root.log_bytes) + append_len <= data_capacity_bytes;
}

fn writeBytes(writer: anytype, offset: usize, bytes: []const u8) Error!void {
    switch (@TypeOf(writer)) {
        ImageWriteFns => {
            if (offset + bytes.len > writer.image.len) return error.ImageTooSmall;
            @memcpy(writer.image[offset .. offset + bytes.len], bytes);
        },
        BackendWriteFns => {
            if (!writer.write_bytes(offset, bytes)) return error.CorruptImage;
        },
        else => @compileError("unsupported incremental writer"),
    }
}

fn writeRoot(writer: anytype, sector_index: u32, root: RootState) Error!void {
    switch (@TypeOf(writer)) {
        ImageWriteFns => try writeImageRoot(writer.image, sector_index, root),
        BackendWriteFns => try writer.write_root(sector_index, root),
        else => @compileError("unsupported root writer"),
    }
}

fn buildDeltaLog(
    buffer: []u8,
    root: RootState,
    store: *const object_store.Store,
    workspaces: *const workspace.Directory,
) Error!usize {
    var writer = CursorWriter{ .buffer = buffer };

    for (store.objects) |slot| {
        if (!slot.in_use) continue;
        if (slot.object.latest_version_id <= root.last_version_id) continue;
        try appendObjectRecord(&writer, slot.object);
    }

    for (store.versions) |slot| {
        if (!slot.in_use) continue;
        if (slot.version.id <= root.last_version_id) continue;
        try appendVersionRecord(&writer, slot.version);
    }

    for (workspaces.workspaces) |slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        const summary = findWorkspaceSummary(root, slot.workspace.id);
        const state_hash = try workspaceStateHash(&slot.workspace);
        if (summary) |persisted| {
            if (persisted.generation == slot.workspace.generation and persisted.state_hash == state_hash) continue;
        }
        try appendWorkspaceRecord(&writer, slot.workspace);
    }

    for (workspaces.snapshots) |slot| {
        if (!persistableSnapshotSlot(slot)) continue;
        if (slot.snapshot.id <= root.last_snapshot_id) continue;
        try appendSnapshotRecord(&writer, slot.snapshot);
    }

    return writer.offset;
}

fn buildRootState(
    generation: u64,
    log_bytes: u32,
    store: *const object_store.Store,
    workspaces: *const workspace.Directory,
) RootState {
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
    for (workspaces.workspaces) |slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        root.workspace_summaries[root.workspace_summary_count] = .{
            .id = slot.workspace.id,
            .generation = slot.workspace.generation,
            .state_hash = workspaceStateHash(&slot.workspace) catch unreachable,
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

fn workspaceStateHash(record: *const workspace.WorkspaceRecord) Error!u64 {
    var writer = CursorWriter{ .buffer = workspace_state_buffer[0..] };
    try encodeWorkspaceBody(&writer, record.*);
    return checksumBytes(workspace_state_buffer[0..writer.offset]);
}

fn replayLog(store: *object_store.Store, workspaces: *workspace.Directory, log: []const u8, root: RootState) Error!void {
    store.reset();
    workspaces.reset();

    var reader = CursorReader{ .buffer = log };
    var saw_checkpoint = false;
    while (reader.offset < reader.buffer.len) {
        const header = try readRecordHeader(&reader);
        const payload = try reader.readSlice(header.payload_len);
        if (checksumBytes(payload) != header.checksum) return error.ChecksumMismatch;

        switch (header.kind) {
            .checkpoint => {
                try deserializeState(store, workspaces, payload);
                saw_checkpoint = true;
            },
            .object_state => try applyObjectRecord(store, payload),
            .version_state => try applyVersionRecord(store, payload),
            .workspace_state => try applyWorkspaceRecord(workspaces, payload),
            .snapshot_state => try applySnapshotRecord(workspaces, payload),
        }
    }
    if (!saw_checkpoint) return error.MissingCheckpoint;

    store.next_object_id = root.next_object_id;
    store.next_version_id = root.next_version_id;
    workspaces.next_workspace_id = root.next_workspace_id;
    workspaces.next_snapshot_id = root.next_snapshot_id;
    store.rebuildIndexes();
    workspaces.rebuildIndexes();
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
    writeU32At(writer.buffer[header_offset + 1 .. header_offset + 5], @intCast(payload_len));
    writeU64At(writer.buffer[header_offset + 5 .. header_offset + 13], checksum);
}

fn recordHeaderLen() usize {
    return 1 + 4 + 8;
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
        else => error.CorruptImage,
    };
}

fn encodeObjectBody(writer: *CursorWriter, record: object_store.ObjectRecord) Error!void {
    try writer.writeU64(record.id);
    try writer.writeByte(@intFromEnum(record.object_type));
    try writer.writeU64(record.latest_version_id);
    try writer.writeU16(record.version_count);
}

fn encodeVersionBody(writer: *CursorWriter, record: object_store.VersionRecord) Error!void {
    try writer.writeU64(record.id);
    try writer.writeU64(record.object_id);
    try writer.writeU64(record.previous_version_id);
    try writer.writeByte(@intFromEnum(record.object_type));
    try writer.writeBytes(&record.blob_address);
    try writer.writeBytes(&record.version_address);
    try writeMetadata(writer, record.metadata);
    try writer.writeU16(@intCast(record.payload_len));
    try writer.writeBytes(record.payloadSlice());
}

fn encodeWorkspaceBody(writer: *CursorWriter, record: workspace.WorkspaceRecord) Error!void {
    try writer.writeU64(record.id);
    try writePrincipal(writer, record.owner);
    try writeText(writer, record.labelSlice());
    try writer.writeU32(record.generation);
    try writer.writeU16(@intCast(record.entry_count));
    for (record.entries[0..record.entry_count]) |entry| {
        try writeEntry(writer, entry);
    }
    try writer.writeU16(@intCast(record.share_grant_count));
    for (record.share_grants[0..record.share_grant_count]) |grant| {
        try writeShareGrant(writer, grant);
    }
    try writer.writeU16(@intCast(record.deleted_count));
    for (record.deleted_entries[0..record.deleted_count]) |entry| {
        try writeEntry(writer, entry);
    }
}

fn encodeSnapshotBody(writer: *CursorWriter, record: workspace.SnapshotRecord) Error!void {
    try writer.writeU64(record.id);
    try writer.writeU64(record.workspace_id);
    try writer.writeU32(record.generation);
    try writeText(writer, record.labelSlice());
    try writeSignature(writer, record.signature);
    try writer.writeU16(@intCast(record.entry_count));
    for (record.entries[0..record.entry_count]) |entry| {
        try writeEntry(writer, entry);
    }
}

fn applyObjectRecord(store: *object_store.Store, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const object_id = try reader.readU64();
    const object_type = try parseObjectType(try reader.readByte());
    const latest_version_id = try reader.readU64();
    const version_count = try reader.readU16();

    if (store.object(object_id)) |record| {
        record.object_type = object_type;
        record.latest_version_id = latest_version_id;
        record.version_count = version_count;
        return;
    }

    const slot = nextObjectSlot(store) orelse return error.CorruptImage;
    slot.in_use = true;
    slot.object = .{
        .id = object_id,
        .object_type = object_type,
        .latest_version_id = latest_version_id,
        .version_count = version_count,
    };
}

fn applyVersionRecord(store: *object_store.Store, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const slot_index = nextVersionSlotIndex(store) orelse return error.CorruptImage;
    store.versions[slot_index].in_use = true;
    store.versions[slot_index].version.id = try reader.readU64();
    store.versions[slot_index].version.object_id = try reader.readU64();
    store.versions[slot_index].version.previous_version_id = try reader.readU64();
    store.versions[slot_index].version.object_type = try parseObjectType(try reader.readByte());
    try reader.readBytes(&store.versions[slot_index].version.blob_address);
    try reader.readBytes(&store.versions[slot_index].version.version_address);
    store.versions[slot_index].version.metadata = try readMetadata(&reader, &version_signers[slot_index]);
    store.versions[slot_index].version.payload_len = @intCast(try reader.readU16());
    if (store.versions[slot_index].version.payload_len > object_store.MAX_PAYLOAD_BYTES) return error.CorruptImage;
    @memset(store.versions[slot_index].version.payload[0..], 0);
    try reader.readBytes(store.versions[slot_index].version.payload[0..store.versions[slot_index].version.payload_len]);
}

fn applyWorkspaceRecord(workspaces: *workspace.Directory, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const workspace_id = try reader.readU64();
    const slot = findWorkspaceSlotById(workspaces, workspace_id) orelse nextWorkspaceSlot(workspaces) orelse return error.CorruptImage;
    slot.in_use = true;
    slot.workspace = zeroWorkspaceRecord();
    slot.workspace.id = workspace_id;
    slot.workspace.owner = try readPrincipal(&reader);
    readTextInto(&reader, &slot.workspace.label, &slot.workspace.label_len) catch return error.CorruptImage;
    slot.workspace.generation = try reader.readU32();
    slot.workspace.entry_count = @intCast(try reader.readU16());
    if (slot.workspace.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
    for (0..slot.workspace.entry_count) |entry_index| {
        slot.workspace.entries[entry_index] = try readEntry(&reader);
    }
    slot.workspace.share_grant_count = @intCast(try reader.readU16());
    if (slot.workspace.share_grant_count > workspace.MAX_SHARE_GRANTS) return error.CorruptImage;
    for (0..slot.workspace.share_grant_count) |grant_index| {
        slot.workspace.share_grants[grant_index] = try readShareGrant(&reader);
    }
    slot.workspace.deleted_count = @intCast(try reader.readU16());
    if (slot.workspace.deleted_count > workspace.MAX_RECOVERABLE_DELETES) return error.CorruptImage;
    for (0..slot.workspace.deleted_count) |entry_index| {
        slot.workspace.deleted_entries[entry_index] = try readEntry(&reader);
    }
}

fn applySnapshotRecord(workspaces: *workspace.Directory, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const snapshot_id = try reader.readU64();
    const slot_index = findSnapshotSlotIndexById(workspaces, snapshot_id) orelse nextSnapshotSlotIndex(workspaces) orelse return error.CorruptImage;
    workspaces.snapshots[slot_index].in_use = true;
    workspaces.snapshots[slot_index].snapshot = zeroSnapshotRecord();
    workspaces.snapshots[slot_index].snapshot.id = snapshot_id;
    workspaces.snapshots[slot_index].snapshot.workspace_id = try reader.readU64();
    workspaces.snapshots[slot_index].snapshot.generation = try reader.readU32();
    readTextInto(&reader, &workspaces.snapshots[slot_index].snapshot.label, &workspaces.snapshots[slot_index].snapshot.label_len) catch return error.CorruptImage;
    workspaces.snapshots[slot_index].snapshot.signature = try readSignature(&reader, &snapshot_signers[slot_index]);
    workspaces.snapshots[slot_index].snapshot.entry_count = @intCast(try reader.readU16());
    if (workspaces.snapshots[slot_index].snapshot.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
    for (0..workspaces.snapshots[slot_index].snapshot.entry_count) |entry_index| {
        workspaces.snapshots[slot_index].snapshot.entries[entry_index] = try readEntry(&reader);
    }
}

fn findWorkspaceSlotById(workspaces: *workspace.Directory, workspace_id: u64) ?*@TypeOf(workspaces.workspaces[0]) {
    for (&workspaces.workspaces) |*slot| {
        if (slot.in_use and slot.workspace.id == workspace_id) return slot;
    }
    return null;
}

fn findSnapshotSlotIndexById(workspaces: *workspace.Directory, snapshot_id: u64) ?usize {
    for (workspaces.snapshots, 0..) |slot, index| {
        if (slot.in_use and slot.snapshot.id == snapshot_id) return index;
    }
    return null;
}

fn serializeState(store: *const object_store.Store, workspaces: *const workspace.Directory, buffer: []u8) Error!usize {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(payload_magic);
    try writer.writeU16(format_version);
    try writer.writeU64(store.next_object_id);
    try writer.writeU64(store.next_version_id);
    try writer.writeU16(@intCast(store.objectCount()));
    try writer.writeU16(@intCast(store.versionCount()));
    try writer.writeU64(workspaces.next_workspace_id);
    try writer.writeU64(workspaces.next_snapshot_id);
    try writer.writeU16(@intCast(workspaceCount(workspaces)));
    try writer.writeU16(@intCast(snapshotCount(workspaces)));

    for (store.objects) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.object.id);
        try writer.writeByte(@intFromEnum(slot.object.object_type));
        try writer.writeU64(slot.object.latest_version_id);
        try writer.writeU16(slot.object.version_count);
    }

    for (store.versions) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.version.id);
        try writer.writeU64(slot.version.object_id);
        try writer.writeU64(slot.version.previous_version_id);
        try writer.writeByte(@intFromEnum(slot.version.object_type));
        try writer.writeBytes(&slot.version.blob_address);
        try writer.writeBytes(&slot.version.version_address);
        try writeMetadata(&writer, slot.version.metadata);
        try writer.writeU16(@intCast(slot.version.payload_len));
        try writer.writeBytes(slot.version.payloadSlice());
    }

    for (workspaces.workspaces) |slot| {
        if (!persistableWorkspaceSlot(slot)) continue;
        try writer.writeU64(slot.workspace.id);
        try writePrincipal(&writer, slot.workspace.owner);
        try writeText(&writer, slot.workspace.labelSlice());
        try writer.writeU32(slot.workspace.generation);
        try writer.writeU16(@intCast(slot.workspace.entry_count));
        for (slot.workspace.entries[0..slot.workspace.entry_count]) |entry| {
            try writeEntry(&writer, entry);
        }
        try writer.writeU16(@intCast(slot.workspace.share_grant_count));
        for (slot.workspace.share_grants[0..slot.workspace.share_grant_count]) |grant| {
            try writeShareGrant(&writer, grant);
        }
        try writer.writeU16(@intCast(slot.workspace.deleted_count));
        for (slot.workspace.deleted_entries[0..slot.workspace.deleted_count]) |entry| {
            try writeEntry(&writer, entry);
        }
    }

    for (workspaces.snapshots) |slot| {
        if (!persistableSnapshotSlot(slot)) continue;
        try writer.writeU64(slot.snapshot.id);
        try writer.writeU64(slot.snapshot.workspace_id);
        try writer.writeU32(slot.snapshot.generation);
        try writeText(&writer, slot.snapshot.labelSlice());
        try writeSignature(&writer, slot.snapshot.signature);
        try writer.writeU16(@intCast(slot.snapshot.entry_count));
        for (slot.snapshot.entries[0..slot.snapshot.entry_count]) |entry| {
            try writeEntry(&writer, entry);
        }
    }

    return writer.offset;
}

fn deserializeState(store: *object_store.Store, workspaces: *workspace.Directory, payload: []const u8) Error!void {
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
    workspaces.next_workspace_id = try reader.readU64();
    workspaces.next_snapshot_id = try reader.readU64();
    const workspace_count_value = try reader.readU16();
    const snapshot_count_value = try reader.readU16();

    if (object_count > object_store.MAX_OBJECTS or
        version_count > object_store.MAX_VERSIONS or
        workspace_count_value > workspace.MAX_WORKSPACES or
        snapshot_count_value > workspace.MAX_SNAPSHOTS)
    {
        return error.CorruptImage;
    }

    for (0..@as(usize, object_count)) |_| {
        const slot = nextObjectSlot(store) orelse return error.CorruptImage;
        slot.in_use = true;
        slot.object.id = try reader.readU64();
        slot.object.object_type = try parseObjectType(try reader.readByte());
        slot.object.latest_version_id = try reader.readU64();
        slot.object.version_count = try reader.readU16();
    }

    for (0..@as(usize, version_count)) |_| {
        const slot_index = nextVersionSlotIndex(store) orelse return error.CorruptImage;
        store.versions[slot_index].in_use = true;
        store.versions[slot_index].version.id = try reader.readU64();
        store.versions[slot_index].version.object_id = try reader.readU64();
        store.versions[slot_index].version.previous_version_id = try reader.readU64();
        store.versions[slot_index].version.object_type = try parseObjectType(try reader.readByte());
        try reader.readBytes(&store.versions[slot_index].version.blob_address);
        try reader.readBytes(&store.versions[slot_index].version.version_address);
        store.versions[slot_index].version.metadata = try readMetadata(&reader, &version_signers[slot_index]);
        store.versions[slot_index].version.payload_len = @intCast(try reader.readU16());
        if (store.versions[slot_index].version.payload_len > object_store.MAX_PAYLOAD_BYTES) return error.CorruptImage;
        @memset(store.versions[slot_index].version.payload[0..], 0);
        try reader.readBytes(store.versions[slot_index].version.payload[0..store.versions[slot_index].version.payload_len]);
    }

    for (0..@as(usize, workspace_count_value)) |_| {
        const slot = nextWorkspaceSlot(workspaces) orelse return error.CorruptImage;
        slot.in_use = true;
        slot.workspace = zeroWorkspaceRecord();
        slot.workspace.id = try reader.readU64();
        slot.workspace.owner = try readPrincipal(&reader);
        readTextInto(&reader, &slot.workspace.label, &slot.workspace.label_len) catch return error.CorruptImage;
        slot.workspace.generation = try reader.readU32();
        slot.workspace.entry_count = @intCast(try reader.readU16());
        if (slot.workspace.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
        for (0..slot.workspace.entry_count) |entry_index| {
            slot.workspace.entries[entry_index] = try readEntry(&reader);
        }
        slot.workspace.share_grant_count = @intCast(try reader.readU16());
        if (slot.workspace.share_grant_count > workspace.MAX_SHARE_GRANTS) return error.CorruptImage;
        for (0..slot.workspace.share_grant_count) |grant_index| {
            slot.workspace.share_grants[grant_index] = try readShareGrant(&reader);
        }
        slot.workspace.deleted_count = @intCast(try reader.readU16());
        if (slot.workspace.deleted_count > workspace.MAX_RECOVERABLE_DELETES) return error.CorruptImage;
        for (0..slot.workspace.deleted_count) |entry_index| {
            slot.workspace.deleted_entries[entry_index] = try readEntry(&reader);
        }
    }

    for (0..@as(usize, snapshot_count_value)) |_| {
        const slot_index = nextSnapshotSlotIndex(workspaces) orelse return error.CorruptImage;
        workspaces.snapshots[slot_index].in_use = true;
        workspaces.snapshots[slot_index].snapshot = zeroSnapshotRecord();
        workspaces.snapshots[slot_index].snapshot.id = try reader.readU64();
        workspaces.snapshots[slot_index].snapshot.workspace_id = try reader.readU64();
        workspaces.snapshots[slot_index].snapshot.generation = try reader.readU32();
        readTextInto(&reader, &workspaces.snapshots[slot_index].snapshot.label, &workspaces.snapshots[slot_index].snapshot.label_len) catch return error.CorruptImage;
        workspaces.snapshots[slot_index].snapshot.signature = try readSignature(&reader, &snapshot_signers[slot_index]);
        workspaces.snapshots[slot_index].snapshot.entry_count = @intCast(try reader.readU16());
        if (workspaces.snapshots[slot_index].snapshot.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
        for (0..workspaces.snapshots[slot_index].snapshot.entry_count) |entry_index| {
            workspaces.snapshots[slot_index].snapshot.entries[entry_index] = try readEntry(&reader);
        }
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
    try writer.writeU64(entry.object_id);
    try writer.writeU64(entry.version_id);
    try writer.writeByte(@intFromEnum(entry.object_type));
}

fn readEntry(reader: *CursorReader) Error!workspace.Entry {
    var entry = workspace.Entry{};
    readTextInto(reader, &entry.path, &entry.path_len) catch return error.CorruptImage;
    entry.object_id = try reader.readU64();
    entry.version_id = try reader.readU64();
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
    for (workspaces.workspaces) |slot| {
        if (persistableWorkspaceSlot(slot)) count += 1;
    }
    return count;
}

fn snapshotCount(workspaces: *const workspace.Directory) usize {
    var count: usize = 0;
    for (workspaces.snapshots) |slot| {
        if (persistableSnapshotSlot(slot)) count += 1;
    }
    return count;
}

fn persistableWorkspaceSlot(slot: anytype) bool {
    if (!slot.in_use) return false;
    return slot.workspace.label_len <= slot.workspace.label.len and
        slot.workspace.entry_count <= workspace.MAX_WORKSPACE_ENTRIES and
        slot.workspace.share_grant_count <= workspace.MAX_SHARE_GRANTS and
        slot.workspace.deleted_count <= workspace.MAX_RECOVERABLE_DELETES;
}

fn persistableSnapshotSlot(slot: anytype) bool {
    if (!slot.in_use) return false;
    return slot.snapshot.label_len <= slot.snapshot.label.len and
        slot.snapshot.entry_count <= workspace.MAX_WORKSPACE_ENTRIES;
}

fn nextObjectSlot(store: *object_store.Store) ?*@TypeOf(store.objects[0]) {
    for (&store.objects) |*slot| {
        if (!slot.in_use) return slot;
    }
    return null;
}

fn nextVersionSlotIndex(store: *object_store.Store) ?usize {
    for (store.versions, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn nextWorkspaceSlot(workspaces: *workspace.Directory) ?*@TypeOf(workspaces.workspaces[0]) {
    for (&workspaces.workspaces) |*slot| {
        if (!slot.in_use) return slot;
    }
    return null;
}

fn nextSnapshotSlotIndex(workspaces: *workspace.Directory) ?usize {
    for (workspaces.snapshots, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn zeroWorkspaceRecord() workspace.WorkspaceRecord {
    return workspace.emptyWorkspaceRecord();
}

fn zeroSnapshotRecord() workspace.SnapshotRecord {
    return workspace.emptySnapshotRecord();
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

fn findLatestBackendRoot() Error!?LoadedRoot {
    var best: ?LoadedRoot = null;
    var sector_index: u32 = 0;
    while (sector_index < root_sector_count) : (sector_index += 1) {
        const root = readBackendRoot(sector_index) catch continue;
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

fn readBackendRoot(sector_index: u32) Error!LoadedRoot {
    @memset(sector_buffer[0..], 0);
    if (!readAttachedRange(sector_index, sector_buffer[0..])) return error.CorruptImage;
    return .{
        .sector_index = sector_index,
        .root = try parseRoot(sector_buffer[0..]),
    };
}

fn writeBackendRoot(sector_index: u32, root: RootState) Error!void {
    @memset(sector_buffer[0..], 0);
    try encodeRoot(sector_buffer[0..], root);
    if (!writeAttachedRange(sector_index, sector_buffer[0..])) return error.CorruptImage;
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
    const checksum_offset = reader.offset;
    const checksum = try reader.readU64();
    if (checksum != checksumBytes(buffer[0..checksum_offset])) return error.ChecksumMismatch;
    return root;
}

fn writeAttachedBytes(offset: usize, bytes: []const u8) bool {
    if (offset + bytes.len > image_bytes) return false;
    var remaining = bytes.len;
    var cursor: usize = 0;
    while (remaining > 0) {
        const absolute_offset = offset + cursor;
        const sector_index = absolute_offset / sector_size;
        const sector_offset = absolute_offset % sector_size;
        const chunk_len = @min(remaining, sector_size - sector_offset);

        if (sector_offset == 0 and chunk_len == sector_size) {
            if (!writeAttachedRange(@intCast(sector_index), bytes[cursor .. cursor + chunk_len])) return false;
        } else {
            if (!readAttachedRange(@intCast(sector_index), sector_buffer[0..])) return false;
            @memcpy(sector_buffer[sector_offset .. sector_offset + chunk_len], bytes[cursor .. cursor + chunk_len]);
            if (!writeAttachedRange(@intCast(sector_index), sector_buffer[0..])) return false;
        }

        cursor += chunk_len;
        remaining -= chunk_len;
    }
    return true;
}

fn readAttachedBytes(offset: usize, buffer: []u8) bool {
    if (offset + buffer.len > image_bytes) return false;
    var remaining = buffer.len;
    var cursor: usize = 0;
    while (remaining > 0) {
        const absolute_offset = offset + cursor;
        const sector_index = absolute_offset / sector_size;
        const sector_offset = absolute_offset % sector_size;
        const chunk_len = @min(remaining, sector_size - sector_offset);
        if (!readAttachedRange(@intCast(sector_index), sector_buffer[0..])) return false;
        @memcpy(buffer[cursor .. cursor + chunk_len], sector_buffer[sector_offset .. sector_offset + chunk_len]);
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

const SlotCandidate = struct {
    slot_index: u32,
    header: SlotHeader,
};

fn findLatestImageSlot(image: []const u8) Error!?SlotCandidate {
    var best: ?SlotCandidate = null;
    var slot_index: u32 = 0;
    while (slot_index < slot_count) : (slot_index += 1) {
        const header = readImageHeader(image, slot_index) catch continue;
        const payload = readImagePayload(image, slot_index, header.payload_len, io_payload_buffer[0..]) catch continue;
        if (checksumBytes(payload) != header.checksum) continue;
        if (best == null or header.generation > best.?.header.generation) {
            best = .{ .slot_index = slot_index, .header = header };
        }
    }
    return best;
}

fn findLatestBackendSlot() Error!?SlotCandidate {
    var best: ?SlotCandidate = null;
    var slot_index: u32 = 0;
    while (slot_index < slot_count) : (slot_index += 1) {
        const header = readBackendHeader(slot_index) catch continue;
        const payload = readBackendPayload(slot_index, header.payload_len) catch continue;
        if (checksumBytes(payload) != header.checksum) continue;
        if (best == null or header.generation > best.?.header.generation) {
            best = .{ .slot_index = slot_index, .header = header };
        }
    }
    return best;
}

fn slotBaseLba(slot_index: u32) u64 {
    return @as(u64, slot_index) * slot_sectors;
}

fn readImageHeader(image: []const u8, slot_index: u32) Error!SlotHeader {
    const offset: usize = @as(usize, slot_index) * slot_bytes;
    return parseHeader(image[offset .. offset + sector_size]);
}

fn writeImageHeader(image: []u8, slot_index: u32, header: SlotHeader) Error!void {
    const offset: usize = @as(usize, slot_index) * slot_bytes;
    try encodeHeader(image[offset .. offset + sector_size], header);
}

fn writeImagePayload(image: []u8, slot_index: u32, payload: []const u8) Error!void {
    const offset: usize = @as(usize, slot_index) * slot_bytes + sector_size;
    if (payload.len > max_payload_bytes or offset + max_payload_bytes > image.len) return error.ImageTooSmall;
    @memset(image[offset .. offset + max_payload_bytes], 0);
    @memcpy(image[offset .. offset + payload.len], payload);
}

fn readImagePayload(image: []const u8, slot_index: u32, payload_len: u32, buffer: []u8) Error![]const u8 {
    if (payload_len == 0 or payload_len > max_payload_bytes) return error.CorruptImage;
    const offset: usize = @as(usize, slot_index) * slot_bytes + sector_size;
    const payload_len_usize: usize = @intCast(payload_len);
    if (offset + payload_len_usize > image.len or payload_len_usize > buffer.len) return error.ImageTooSmall;
    @memcpy(buffer[0..payload_len_usize], image[offset .. offset + payload_len_usize]);
    return buffer[0..payload_len_usize];
}

fn readBackendHeader(slot_index: u32) Error!SlotHeader {
    @memset(sector_buffer[0..], 0);
    const lba = slotBaseLba(slot_index);
    if (!readAttachedRange(lba, sector_buffer[0..])) return error.CorruptImage;
    return parseHeader(sector_buffer[0..]);
}

fn writeBackendHeader(slot_index: u32, header: SlotHeader) Error!void {
    @memset(sector_buffer[0..], 0);
    try encodeHeader(sector_buffer[0..], header);
    const lba = slotBaseLba(slot_index);
    if (!writeAttachedRange(lba, sector_buffer[0..])) return error.CorruptImage;
}

fn writeBackendPayload(slot_index: u32, payload: []const u8) Error!void {
    if (payload.len > max_payload_bytes) return error.NoSpaceLeft;
    const sectors = sectorCountForPayload(payload.len);
    @memset(io_payload_buffer[payload.len .. sectors * sector_size], 0);
    const lba = slotBaseLba(slot_index) + header_sectors;
    const bytes = sectors * sector_size;
    if (!writeAttachedRange(lba, io_payload_buffer[0..bytes])) return error.CorruptImage;
}

fn readBackendPayload(slot_index: u32, payload_len: u32) Error![]const u8 {
    if (payload_len == 0 or payload_len > max_payload_bytes) return error.CorruptImage;
    const sectors = sectorCountForPayload(payload_len);
    const lba = slotBaseLba(slot_index) + header_sectors;
    const bytes = sectors * sector_size;
    if (!readAttachedRange(lba, io_payload_buffer[0..bytes])) return error.CorruptImage;
    return io_payload_buffer[0..@as(usize, @intCast(payload_len))];
}

fn sectorCountForPayload(payload_len: usize) usize {
    return @max(1, (payload_len + sector_size - 1) / sector_size);
}

fn readAttachedRange(start_lba: u64, buffer: []u8) bool {
    return switch (attached_backend_kind) {
        .none => false,
        .generic => attached_backend_read(start_lba, buffer.ptr, buffer.len),
        .ata_bootstrap => ataReadRange(start_lba, buffer),
    };
}

fn writeAttachedRange(start_lba: u64, buffer: []const u8) bool {
    return switch (attached_backend_kind) {
        .none => false,
        .generic => attached_backend_write(start_lba, buffer.ptr, buffer.len),
        .ata_bootstrap => ataWriteRange(start_lba, buffer),
    };
}

fn ataReadRange(start_lba: u64, buffer: []u8) bool {
    const device = attached_ata_device orelse return false;
    return ata_bridge.read(device, start_lba, buffer);
}

fn ataWriteRange(start_lba: u64, buffer: []const u8) bool {
    const device = attached_ata_device orelse return false;
    return ata_bridge.write(device, start_lba, buffer);
}

fn encodeHeader(buffer: []u8, header: SlotHeader) Error!void {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(volume_magic);
    try writer.writeU16(format_version);
    try writer.writeU64(header.generation);
    try writer.writeU32(header.payload_len);
    try writer.writeU64(header.checksum);
}

fn parseHeader(buffer: []const u8) Error!SlotHeader {
    var reader = CursorReader{ .buffer = buffer };
    var magic: [volume_magic.len]u8 = undefined;
    try reader.readBytes(&magic);
    if (!std.mem.eql(u8, &magic, volume_magic)) return error.CorruptImage;
    if ((try reader.readU16()) != format_version) return error.UnsupportedVersion;

    const header = SlotHeader{
        .generation = try reader.readU64(),
        .payload_len = try reader.readU32(),
        .checksum = try reader.readU64(),
    };
    if (header.payload_len == 0 or header.payload_len > max_payload_bytes) return error.CorruptImage;
    return header;
}

test "storage volume image reloads the latest persisted state across slot generations" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = @import("../core/signing.zig").SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x71} ** 32,
    };
    const first = try store.putVersion(.{
        .preferred_object_id = 900,
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
    const generation_one = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 1), generation_one.generation);
    const root_after_first = (try findLatestImageRoot(image)).?.root;
    const first_log_bytes = root_after_first.log_bytes;

    const second = try store.putVersion(.{
        .preferred_object_id = 900,
        .object_type = .document,
        .payload = "hello again",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello again", 12),
        .parent_version_id = first.version_id,
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", second.object_id, second.version_id, .document);
    _ = try workspaces.commit(notes.id, 13);
    const generation_two = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 2), generation_two.generation);
    const root_after_second = (try findLatestImageRoot(image)).?.root;
    try std.testing.expect(root_after_second.log_bytes > first_log_bytes);
    try std.testing.expect(root_after_second.log_bytes < first_log_bytes + 4 * sector_size);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_generation = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(@as(u64, 2), loaded_generation);
    try std.testing.expectEqual(@as(usize, 1), loaded_store.objectCount());
    try std.testing.expectEqual(second.version_id, loaded_store.latestVersion(900).?.id);
    try std.testing.expectEqualStrings("zigos-storage-key", loaded_store.latestVersion(900).?.metadata.signature.signer);
    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 1 }, "notes").?;
    try std.testing.expectEqual(second.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);
}

test "storage volume rejects corrupted slot payloads" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = @import("../core/signing.zig").SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x72} ** 32,
    };
    _ = try store.putVersion(.{
        .preferred_object_id = 901,
        .object_type = .blob,
        .payload = "blob",
        .metadata = try object_store.signMetadata(signer, "blob", "application/octet-stream", .blob, "blob", 10),
    });
    _ = try saveToImage(image, &store, &workspaces);
    image[data_start_byte + 3] ^= 0xFF;

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, loadFromImage(image, &loaded_store, &loaded_workspaces));
}
