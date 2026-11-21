//! Deterministic FAT16 image writer for EFI system partitions.
//!
//! Boot media only needs a handful of 8.3-named files in a fresh volume, so
//! this builds the whole image in memory instead of driving external FAT
//! tools. Output depends only on the inputs: the volume serial is zero and
//! every timestamp comes from the caller's epoch.

const std = @import("std");

pub const File = struct {
    /// Slash-separated path relative to the volume root, e.g. "EFI/BOOT/BOOTX64.EFI".
    path: []const u8,
    data: []const u8,
};

pub const Error = error{
    InvalidFatPath,
    InvalidFatName,
    DuplicateFatPath,
    UnsupportedFatGeometry,
    FatVolumeFull,
    RootDirectoryFull,
    FileTooLarge,
} || std.mem.Allocator.Error;

const sector_size = 512;
const dir_entry_size = 32;
const reserved_sectors = 1;
const fat_count = 2;
const root_entry_count = 512;
const root_sectors = root_entry_count * dir_entry_size / sector_size;
const media_descriptor = 0xF8;
const attr_volume_label = 0x08;
const attr_directory = 0x10;
const attr_archive = 0x20;
const end_of_chain: u16 = 0xFFFF;
const min_fat16_clusters = 4085;
const max_fat16_clusters = 65524;

const Geometry = struct {
    total_sectors: u32,
    sectors_per_cluster: u8,
    fat_sectors: u16,
    clusters: u32,

    fn cluster_bytes(self: Geometry) usize {
        return @as(usize, self.sectors_per_cluster) * sector_size;
    }

    fn data_offset(self: Geometry) usize {
        return (reserved_sectors + fat_count * @as(usize, self.fat_sectors) + root_sectors) * sector_size;
    }

    fn cluster_offset(self: Geometry, cluster: u16) usize {
        return self.data_offset() + (@as(usize, cluster) - 2) * self.cluster_bytes();
    }
};

fn geometry(total_bytes: usize) Error!Geometry {
    if (total_bytes % sector_size != 0) return error.UnsupportedFatGeometry;
    const total_sectors = std.math.cast(u32, total_bytes / sector_size) orelse return error.UnsupportedFatGeometry;
    var sectors_per_cluster: u32 = 1;
    while (sectors_per_cluster <= 128) : (sectors_per_cluster *= 2) {
        var fat_sectors: u32 = 1;
        while (true) {
            const overhead = reserved_sectors + fat_count * fat_sectors + root_sectors;
            if (overhead >= total_sectors) return error.UnsupportedFatGeometry;
            const clusters = (total_sectors - overhead) / sectors_per_cluster;
            const needed = std.math.divCeil(u32, (clusters + 2) * 2, sector_size) catch unreachable;
            if (needed <= fat_sectors) {
                if (clusters > max_fat16_clusters) break;
                if (clusters < min_fat16_clusters) return error.UnsupportedFatGeometry;
                return .{
                    .total_sectors = total_sectors,
                    .sectors_per_cluster = @intCast(sectors_per_cluster),
                    .fat_sectors = std.math.cast(u16, fat_sectors) orelse return error.UnsupportedFatGeometry,
                    .clusters = clusters,
                };
            }
            fat_sectors = needed;
        }
    }
    return error.UnsupportedFatGeometry;
}

/// Converts one path component to an upper-case 8.3 directory name.
fn shortName(component: []const u8) Error![11]u8 {
    var name: [11]u8 = @splat(' ');
    if (component.len == 0 or component[0] == '.') return error.InvalidFatName;
    const dot = std.mem.lastIndexOfScalar(u8, component, '.');
    const base = if (dot) |index| component[0..index] else component;
    const extension = if (dot) |index| component[index + 1 ..] else "";
    if (base.len == 0 or base.len > 8 or extension.len > 3) return error.InvalidFatName;
    if (dot != null and extension.len == 0) return error.InvalidFatName;
    for (base, 0..) |c, i| name[i] = try shortChar(c);
    for (extension, 0..) |c, i| name[8 + i] = try shortChar(c);
    return name;
}

fn shortChar(c: u8) Error!u8 {
    const upper = std.ascii.toUpper(c);
    if (std.ascii.isAlphanumeric(upper)) return upper;
    return switch (upper) {
        '_', '-', '~', '!', '#', '$', '%', '&', '(', ')', '@', '^', '{', '}' => upper,
        else => error.InvalidFatName,
    };
}

const DosTime = struct { time: u16, date: u16 };

fn dosTime(epoch_seconds: u64) DosTime {
    const clamped = std.math.clamp(epoch_seconds, std.time.epoch.dos, 4354819199); // 1980-01-01 .. 2107-12-31
    const seconds: std.time.epoch.EpochSeconds = .{ .secs = clamped };
    const year_day = seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = seconds.getDaySeconds();
    return .{
        .time = (@as(u16, day_seconds.getHoursIntoDay()) << 11) |
            (@as(u16, day_seconds.getMinutesIntoHour()) << 5) |
            (@as(u16, day_seconds.getSecondsIntoMinute()) / 2),
        .date = ((year_day.year - 1980) << 9) |
            (@as(u16, month_day.month.numeric()) << 5) |
            (@as(u16, month_day.day_index) + 1),
    };
}

const Node = struct {
    name: [11]u8,
    parent: ?usize,
    /// null for directories.
    data: ?[]const u8,
    first_cluster: u16 = 0,
    cluster_count: u32 = 0,
    children: std.ArrayList(usize) = .empty,
};

fn writeEntry(slot: []u8, name: [11]u8, attributes: u8, cluster: u16, size: u32, stamp: DosTime) void {
    @memset(slot[0..dir_entry_size], 0);
    @memcpy(slot[0..11], &name);
    slot[11] = attributes;
    std.mem.writeInt(u16, slot[14..16], stamp.time, .little);
    std.mem.writeInt(u16, slot[16..18], stamp.date, .little);
    std.mem.writeInt(u16, slot[18..20], stamp.date, .little);
    std.mem.writeInt(u16, slot[22..24], stamp.time, .little);
    std.mem.writeInt(u16, slot[24..26], stamp.date, .little);
    std.mem.writeInt(u16, slot[26..28], cluster, .little);
    std.mem.writeInt(u32, slot[28..32], size, .little);
}

/// Builds a FAT16 volume of exactly `total_bytes` holding `files`. Parent
/// directories are created implicitly. Names must already be valid 8.3 names;
/// they are stored upper-case.
pub fn buildImage(
    allocator: std.mem.Allocator,
    total_bytes: usize,
    label: []const u8,
    epoch_seconds: u64,
    files: []const File,
) Error![]u8 {
    const geo = try geometry(total_bytes);
    const stamp = dosTime(epoch_seconds);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Node 0 is the root directory, which lives in the fixed root region.
    var nodes: std.ArrayList(Node) = .empty;
    try nodes.append(arena, .{ .name = @splat(' '), .parent = null, .data = null });

    for (files) |file| {
        if (file.path.len == 0 or file.path[0] == '/' or file.path[file.path.len - 1] == '/') return error.InvalidFatPath;
        _ = std.math.cast(u32, file.data.len) orelse return error.FileTooLarge;
        var parent: usize = 0;
        var components = std.mem.splitScalar(u8, file.path, '/');
        while (components.next()) |component| {
            const name = try shortName(component);
            const is_leaf = components.peek() == null;
            const existing = for (nodes.items[parent].children.items) |child| {
                if (std.mem.eql(u8, &nodes.items[child].name, &name)) break child;
            } else null;
            if (existing) |child| {
                if (is_leaf or nodes.items[child].data != null) return error.DuplicateFatPath;
                parent = child;
                continue;
            }
            const index = nodes.items.len;
            try nodes.append(arena, .{ .name = name, .parent = parent, .data = if (is_leaf) file.data else null });
            try nodes.items[parent].children.append(arena, index);
            parent = index;
        }
    }

    var volume_label: [11]u8 = @splat(' ');
    if (label.len > volume_label.len) return error.InvalidFatName;
    for (label, 0..) |c, i| volume_label[i] = std.ascii.toUpper(c);
    const root_used = nodes.items[0].children.items.len + @intFromBool(label.len != 0);
    if (root_used > root_entry_count) return error.RootDirectoryFull;

    // Allocate clusters contiguously in node order.
    const cluster_bytes = geo.cluster_bytes();
    var next_cluster: u32 = 2;
    for (nodes.items[1..]) |*node| {
        const bytes = if (node.data) |data| data.len else (node.children.items.len + 2) * dir_entry_size;
        node.cluster_count = @intCast(std.math.divCeil(usize, bytes, cluster_bytes) catch unreachable);
        if (node.cluster_count == 0) continue;
        if (next_cluster - 2 + node.cluster_count > geo.clusters) return error.FatVolumeFull;
        node.first_cluster = @intCast(next_cluster);
        next_cluster += node.cluster_count;
    }

    const image = try allocator.alloc(u8, total_bytes);
    errdefer allocator.free(image);
    @memset(image, 0);

    // Boot sector.
    const boot = image[0..sector_size];
    boot[0..3].* = .{ 0xEB, 0x3C, 0x90 };
    @memcpy(boot[3..11], "ZIGOS   ");
    std.mem.writeInt(u16, boot[11..13], sector_size, .little);
    boot[13] = geo.sectors_per_cluster;
    std.mem.writeInt(u16, boot[14..16], reserved_sectors, .little);
    boot[16] = fat_count;
    std.mem.writeInt(u16, boot[17..19], root_entry_count, .little);
    std.mem.writeInt(u16, boot[19..21], std.math.cast(u16, geo.total_sectors) orelse 0, .little);
    boot[21] = media_descriptor;
    std.mem.writeInt(u16, boot[22..24], geo.fat_sectors, .little);
    std.mem.writeInt(u16, boot[24..26], 32, .little);
    std.mem.writeInt(u16, boot[26..28], 64, .little);
    std.mem.writeInt(u32, boot[32..36], if (geo.total_sectors > std.math.maxInt(u16)) geo.total_sectors else 0, .little);
    boot[36] = 0x80;
    boot[38] = 0x29;
    @memcpy(boot[43..54], if (label.len != 0) &volume_label else "NO NAME    ");
    @memcpy(boot[54..62], "FAT16   ");
    boot[510] = 0x55;
    boot[511] = 0xAA;

    // First FAT, then mirror it.
    const fat_bytes = @as(usize, geo.fat_sectors) * sector_size;
    const fat = image[reserved_sectors * sector_size ..][0..fat_bytes];
    std.mem.writeInt(u16, fat[0..2], 0xFF00 | media_descriptor, .little);
    std.mem.writeInt(u16, fat[2..4], end_of_chain, .little);
    for (nodes.items[1..]) |node| {
        var i: u32 = 0;
        while (i < node.cluster_count) : (i += 1) {
            const cluster = node.first_cluster + i;
            const value: u16 = if (i + 1 == node.cluster_count) end_of_chain else @intCast(cluster + 1);
            std.mem.writeInt(u16, fat[cluster * 2 ..][0..2], value, .little);
        }
    }
    @memcpy(image[(reserved_sectors * sector_size) + fat_bytes ..][0..fat_bytes], fat);

    // Root directory.
    const root = image[(reserved_sectors + fat_count * @as(usize, geo.fat_sectors)) * sector_size ..][0 .. root_sectors * sector_size];
    var root_slot: usize = 0;
    if (label.len != 0) {
        writeEntry(root[0..dir_entry_size], volume_label, attr_volume_label, 0, 0, stamp);
        root_slot = 1;
    }

    for (nodes.items, 0..) |node, index| {
        if (node.data) |data| {
            if (data.len != 0) @memcpy(image[geo.cluster_offset(node.first_cluster)..][0..data.len], data);
            continue;
        }
        const table = if (index == 0) root[root_slot * dir_entry_size ..] else table: {
            const directory = image[geo.cluster_offset(node.first_cluster)..][0 .. node.cluster_count * cluster_bytes];
            const parent_cluster = if (node.parent) |parent| nodes.items[parent].first_cluster else 0;
            writeEntry(directory[0..dir_entry_size], ".          ".*, attr_directory, node.first_cluster, 0, stamp);
            writeEntry(directory[dir_entry_size..][0..dir_entry_size], "..         ".*, attr_directory, parent_cluster, 0, stamp);
            break :table directory[2 * dir_entry_size ..];
        };
        for (node.children.items, 0..) |child_index, slot| {
            const child = nodes.items[child_index];
            const attributes: u8 = if (child.data == null) attr_directory else attr_archive;
            const size: u32 = if (child.data) |data| @intCast(data.len) else 0;
            writeEntry(table[slot * dir_entry_size ..][0..dir_entry_size], child.name, attributes, child.first_cluster, size, stamp);
        }
    }

    return image;
}

/// Writes a FAT16 image of `size_mib` MiB holding `files` to `path`.
pub fn writeImage(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    size_mib: usize,
    label: []const u8,
    epoch_seconds: u64,
    files: []const File,
) !void {
    const image = try buildImage(allocator, size_mib * 1024 * 1024, label, epoch_seconds, files);
    defer allocator.free(image);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = image });
}

fn readEntry(table: []const u8, slot: usize) struct { name: []const u8, attributes: u8, cluster: u16, size: u32 } {
    const entry = table[slot * dir_entry_size ..][0..dir_entry_size];
    return .{
        .name = entry[0..11],
        .attributes = entry[11],
        .cluster = std.mem.readInt(u16, entry[26..28], .little),
        .size = std.mem.readInt(u32, entry[28..32], .little),
    };
}

test "builds a deterministic FAT16 ESP with nested directories" {
    const allocator = std.testing.allocator;
    var payload: [5000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 31);
    const files = [_]File{
        .{ .path = "EFI/BOOT/BOOTX64.EFI", .data = &payload },
        .{ .path = "boot/cmdline.txt", .data = "quiet\n" },
        .{ .path = "boot/empty.txt", .data = "" },
    };
    const image = try buildImage(allocator, 40 * 1024 * 1024, "ZIGOS", 315532800, &files);
    defer allocator.free(image);
    const again = try buildImage(allocator, 40 * 1024 * 1024, "ZIGOS", 315532800, &files);
    defer allocator.free(again);
    try std.testing.expectEqualSlices(u8, image, again);

    try std.testing.expectEqual(@as(u16, 512), std.mem.readInt(u16, image[11..13], .little));
    try std.testing.expectEqualSlices(u8, "FAT16   ", image[54..62]);
    try std.testing.expectEqual(@as(u8, 0xAA), image[511]);

    const geo = try geometry(40 * 1024 * 1024);
    try std.testing.expect(geo.clusters >= min_fat16_clusters and geo.clusters <= max_fat16_clusters);
    const root = image[(reserved_sectors + fat_count * @as(usize, geo.fat_sectors)) * sector_size ..];
    try std.testing.expectEqualSlices(u8, "ZIGOS      ", readEntry(root, 0).name);
    const efi = readEntry(root, 1);
    try std.testing.expectEqualSlices(u8, "EFI        ", efi.name);
    try std.testing.expectEqual(@as(u8, attr_directory), efi.attributes);
    try std.testing.expectEqualSlices(u8, "BOOT       ", readEntry(root, 2).name);

    const efi_dir = image[geo.cluster_offset(efi.cluster)..];
    try std.testing.expectEqualSlices(u8, ".          ", readEntry(efi_dir, 0).name);
    try std.testing.expectEqual(@as(u16, 0), readEntry(efi_dir, 1).cluster);
    const efi_boot = readEntry(efi_dir, 2);
    const boot_dir = image[geo.cluster_offset(efi_boot.cluster)..];
    try std.testing.expectEqual(efi.cluster, readEntry(boot_dir, 1).cluster);
    const loader = readEntry(boot_dir, 2);
    try std.testing.expectEqualSlices(u8, "BOOTX64 EFI", loader.name);
    try std.testing.expectEqual(@as(u32, payload.len), loader.size);

    // Follow the FAT chain and reassemble the file.
    const fat = image[reserved_sectors * sector_size ..];
    var cluster = loader.cluster;
    var offset: usize = 0;
    while (true) {
        const chunk = @min(geo.cluster_bytes(), payload.len - offset);
        try std.testing.expectEqualSlices(u8, payload[offset..][0..chunk], image[geo.cluster_offset(cluster)..][0..chunk]);
        offset += chunk;
        const next = std.mem.readInt(u16, fat[@as(usize, cluster) * 2 ..][0..2], .little);
        if (next == end_of_chain) break;
        cluster = next;
    }
    try std.testing.expectEqual(payload.len, offset);
    // Both FAT copies match.
    const fat_bytes = @as(usize, geo.fat_sectors) * sector_size;
    try std.testing.expectEqualSlices(u8, fat[0..fat_bytes], fat[fat_bytes..][0..fat_bytes]);
}

test "rejects names outside 8.3 and duplicate paths" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidFatName, buildImage(allocator, 40 * 1024 * 1024, "", 0, &.{.{ .path = "longfilename.efi", .data = "x" }}));
    try std.testing.expectError(error.InvalidFatName, buildImage(allocator, 40 * 1024 * 1024, "", 0, &.{.{ .path = "a/b.c.d", .data = "x" }}));
    try std.testing.expectError(error.InvalidFatPath, buildImage(allocator, 40 * 1024 * 1024, "", 0, &.{.{ .path = "/a", .data = "x" }}));
    try std.testing.expectError(error.DuplicateFatPath, buildImage(allocator, 40 * 1024 * 1024, "", 0, &.{
        .{ .path = "A/B", .data = "x" },
        .{ .path = "a/b", .data = "y" },
    }));
    try std.testing.expectError(error.UnsupportedFatGeometry, buildImage(allocator, 1024 * 1024, "", 0, &.{}));
}

test "encodes DOS timestamps from the media epoch" {
    // 2026-11-26 13:45:30 UTC
    const stamp = dosTime(1795700730);
    try std.testing.expectEqual(@as(u16, ((2026 - 1980) << 9) | (11 << 5) | 26), stamp.date);
    try std.testing.expectEqual(@as(u16, (13 << 11) | (45 << 5) | 15), stamp.time);
    try std.testing.expectEqual(@as(u16, (1 << 5) | 1), dosTime(0).date);
}
