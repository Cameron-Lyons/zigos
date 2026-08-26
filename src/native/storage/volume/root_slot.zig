const std = @import("std");
const binary_cursor = @import("binary_cursor");
const volume_backend = @import("backend.zig");
const volume_errors = @import("errors.zig");
const volume_hashing = @import("hashing.zig");
const volume_layout = @import("layout.zig");
const workspace = @import("../workspace.zig");

pub const Error = volume_errors.Error;
pub const COMPACT_ROOT_SUMMARY_METADATA = true;
pub const DERIVES_DELTA_WATERMARKS_FROM_ALLOCATION_CURSORS = true;
pub const ROOT_STATE_SIZE_CEILING_BYTES: usize = 256;

const CursorWriter = binary_cursor.Writer(Error, error.NoSpaceLeft);
const CursorReader = binary_cursor.Reader(Error, error.CorruptImage);

comptime {
    if (workspace.MAX_WORKSPACES > std.math.maxInt(u8)) {
        @compileError("workspace root summaries exceed compact count capacity");
    }
}

pub const WorkspaceSummary = struct {
    id: u64 = 0,
    generation: u32 = 0,
    state_hash: u64 = 0,
};

pub const RootState = struct {
    generation: u64 = 0,
    log_bytes: u32 = 0,

    data_offset: u32 = 0,
    next_object_id: u64 = 1,
    next_version_id: u64 = 1,
    next_workspace_id: u64 = 1,
    next_snapshot_id: u64 = 1,
    log_record_count: u16 = 0,
    log_segment_count: u16 = 0,
    compacted_generation: u64 = 0,
    workspace_summary_count: u8 = 0,
    workspace_summaries: [workspace.MAX_WORKSPACES]WorkspaceSummary =
        [_]WorkspaceSummary{WorkspaceSummary{}} ** workspace.MAX_WORKSPACES,

    comptime {
        if (@sizeOf(@This()) > ROOT_STATE_SIZE_CEILING_BYTES) {
            @compileError("storage root state exceeds its compact layout ceiling");
        }
    }
};

pub const LoadedRoot = struct {
    sector_index: u32,
    root: RootState,
};

pub fn lastIssuedId(next_id: u64) u64 {
    return if (next_id == 0) std.math.maxInt(u64) else next_id - 1;
}

pub fn versionWatermark(root: RootState) u64 {
    return lastIssuedId(root.next_version_id);
}

pub fn snapshotWatermark(root: RootState) u64 {
    return lastIssuedId(root.next_snapshot_id);
}

pub fn hasRootMagic(buffer: []const u8) bool {
    return buffer.len >= volume_layout.root_magic.len and
        std.mem.eql(u8, buffer[0..volume_layout.root_magic.len], volume_layout.root_magic);
}

test "delta watermarks derive from allocation cursors" {
    try std.testing.expect(DERIVES_DELTA_WATERMARKS_FROM_ALLOCATION_CURSORS);
    try std.testing.expect(!@hasField(RootState, "last_version_id"));
    try std.testing.expect(!@hasField(RootState, "last_snapshot_id"));
    try std.testing.expectEqual(@as(u64, 0), versionWatermark(.{}));
    try std.testing.expectEqual(@as(u64, 0), snapshotWatermark(.{}));
    const exhausted = RootState{
        .next_version_id = 42,
        .next_snapshot_id = 0,
    };
    try std.testing.expectEqual(@as(u64, 41), versionWatermark(exhausted));
    try std.testing.expectEqual(std.math.maxInt(u64), snapshotWatermark(exhausted));
}

pub fn nextRootSector(current: ?LoadedRoot) u32 {
    return if (current) |loaded|
        if (loaded.sector_index == 0) 1 else 0
    else
        0;
}

pub fn findLatestImageRoot(image: []const u8) Error!?LoadedRoot {
    var best: ?LoadedRoot = null;
    var sector_index: u32 = 0;
    while (sector_index < volume_layout.root_sector_count) : (sector_index += 1) {
        const root = readImageRoot(image, sector_index) catch continue;
        if (best == null or root.root.generation > best.?.root.generation) {
            best = root;
        }
    }
    return best;
}

pub fn findLatestBackendRoot(volume: anytype) Error!?LoadedRoot {
    var best: ?LoadedRoot = null;
    var sector_index: u32 = 0;
    while (sector_index < volume_layout.root_sector_count) : (sector_index += 1) {
        const root = readBackendRoot(volume, sector_index) catch continue;
        if (best == null or root.root.generation > best.?.root.generation) {
            best = root;
        }
    }
    return best;
}

pub fn readImageRoot(image: []const u8, sector_index: u32) Error!LoadedRoot {
    const offset = @as(usize, sector_index) * volume_layout.sector_size;
    if (offset + volume_layout.sector_size > image.len) return error.ImageTooSmall;
    return .{
        .sector_index = sector_index,
        .root = try parseRoot(image[offset .. offset + volume_layout.sector_size]),
    };
}

pub fn writeImageRoot(image: []u8, sector_index: u32, root: RootState) Error!void {
    const offset = @as(usize, sector_index) * volume_layout.sector_size;
    if (offset + volume_layout.sector_size > image.len) return error.ImageTooSmall;
    try encodeRoot(image[offset .. offset + volume_layout.sector_size], root);
}

pub fn readBackendRoot(volume: anytype, sector_index: u32) Error!LoadedRoot {
    @memset(volume.sector_buffer[0..], 0);
    if (!volume_backend.readAttachedRange(volume, sector_index, volume.sector_buffer[0..])) return error.CorruptImage;
    return .{
        .sector_index = sector_index,
        .root = try parseRoot(volume.sector_buffer[0..]),
    };
}

pub fn writeBackendRoot(volume: anytype, sector_index: u32, root: RootState) Error!void {
    @memset(volume.sector_buffer[0..], 0);
    try encodeRoot(volume.sector_buffer[0..], root);
    if (!volume_backend.writeAttachedRange(volume, sector_index, volume.sector_buffer[0..])) return error.CorruptImage;
}

pub fn encodeRoot(buffer: []u8, root: RootState) Error!void {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(volume_layout.root_magic);
    try writer.writeU16(volume_layout.root_format_version);
    try writer.writeU64(root.generation);
    try writer.writeU32(root.log_bytes);
    try writer.writeU32(root.data_offset);
    try writer.writeU64(root.next_object_id);
    try writer.writeU64(root.next_version_id);
    try writer.writeU64(root.next_workspace_id);
    try writer.writeU64(root.next_snapshot_id);
    try writer.writeU16(root.log_record_count);
    try writer.writeU16(root.log_segment_count);
    try writer.writeU64(root.compacted_generation);
    try writer.writeU16(@intCast(root.workspace_summary_count));
    for (root.workspace_summaries[0..@as(usize, root.workspace_summary_count)]) |summary| {
        try writer.writeU64(summary.id);
        try writer.writeU32(summary.generation);
        try writer.writeU64(summary.state_hash);
    }
    const checksum = volume_hashing.checksumBytes(buffer[0..writer.offset]);
    try writer.writeU64(checksum);
}

pub fn parseRoot(buffer: []const u8) Error!RootState {
    var reader = CursorReader{ .buffer = buffer };
    var magic: [volume_layout.root_magic.len]u8 = undefined;
    try reader.readBytes(&magic);
    if (!std.mem.eql(u8, &magic, volume_layout.root_magic)) return error.CorruptImage;
    if ((try reader.readU16()) != volume_layout.root_format_version) return error.UnsupportedVersion;

    var root = RootState{
        .generation = try reader.readU64(),
        .log_bytes = try reader.readU32(),
        .data_offset = try reader.readU32(),
        .next_object_id = try reader.readU64(),
        .next_version_id = try reader.readU64(),
        .next_workspace_id = try reader.readU64(),
        .next_snapshot_id = try reader.readU64(),
    };
    root.log_record_count = try reader.readU16();
    root.log_segment_count = try reader.readU16();
    root.compacted_generation = try reader.readU64();
    const workspace_summary_count = try reader.readU16();
    if (workspace_summary_count > root.workspace_summaries.len) return error.CorruptImage;
    root.workspace_summary_count = @intCast(workspace_summary_count);
    for (0..root.workspace_summary_count) |index| {
        root.workspace_summaries[index] = .{
            .id = try reader.readU64(),
            .generation = try reader.readU32(),
            .state_hash = try reader.readU64(),
        };
    }
    if (root.data_offset != 0 and root.data_offset != volume_layout.alternate_data_region_offset) return error.CorruptImage;
    if (root.log_bytes > volume_layout.data_region_bytes) return error.CorruptImage;
    if (@as(usize, root.data_offset) + root.log_bytes > volume_layout.data_capacity_bytes) return error.CorruptImage;
    if (root.log_record_count == 0 or root.log_record_count > volume_layout.max_replay_log_records) return error.CorruptImage;
    if (root.log_segment_count > volume_layout.max_log_segments) return error.CorruptImage;
    const checksum_offset = reader.offset;
    const checksum = try reader.readU64();
    if (checksum != volume_hashing.checksumBytes(buffer[0..checksum_offset])) return error.ChecksumMismatch;
    return root;
}

test "storage root summary metadata stays compact" {
    try std.testing.expectEqual(u8, @FieldType(RootState, "workspace_summary_count"));
    try std.testing.expectEqual(@as(usize, 256), @sizeOf(RootState));
    try std.testing.expectEqual(@as(usize, 264), @sizeOf(LoadedRoot));
}
