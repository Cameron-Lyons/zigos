const std = @import("std");
const vfs = @import("vfs.zig");
const ata = @import("ata.zig");
const memory = @import("memory.zig");
const vga = @import("vga.zig");

const BootSector = extern struct {
    jump: [3]u8,
    oem_name: [8]u8,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    fat_count: u8,
    root_entries: u16, // 0 for FAT32
    total_sectors_16: u16, // 0 for FAT32
    media_descriptor: u8,
    sectors_per_fat_16: u16, // 0 for FAT32
    sectors_per_track: u16,
    heads: u16,
    hidden_sectors: u32,
    total_sectors_32: u32,

    sectors_per_fat_32: u32,
    ext_flags: u16,
    fs_version: u16,
    root_cluster: u32,
    fs_info_sector: u16,
    backup_boot_sector: u16,
    reserved: [12]u8,
    drive_number: u8,
    reserved1: u8,
    boot_signature: u8,
    volume_id: u32,
    volume_label: [11]u8,
    fs_type: [8]u8,
};

const FSInfo = extern struct {
    signature1: u32, // 0x41615252
    reserved1: [480]u8,
    signature2: u32, // 0x61417272
    free_clusters: u32,
    next_free_cluster: u32,
    reserved2: [12]u8,
    signature3: u32, // 0xAA550000
};

const DirEntry = extern struct {
    name: [8]u8,
    ext: [3]u8,
    attributes: u8,
    reserved: u8,
    create_time_tenth: u8,
    create_time: u16,
    create_date: u16,
    access_date: u16,
    cluster_high: u16,
    modify_time: u16,
    modify_date: u16,
    cluster_low: u16,
    size: u32,
};

const LFNEntry = extern struct {
    order: u8,
    name1: [10]u8,
    attributes: u8,
    type: u8,
    checksum: u8,
    name2: [12]u8,
    cluster: u16,
    name3: [4]u8,
};

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

const FAT32_EOC: u32 = 0x0FFFFFF8; // End of cluster chain
const FAT32_BAD: u32 = 0x0FFFFFF7; // Bad cluster
const FAT32_FREE: u32 = 0x00000000; // Free cluster

const FAT32Data = struct {
    device: *const ata.ATADevice,
    boot_sector: BootSector,
    fs_info: FSInfo,
    fat_start_lba: u32,
    data_start_lba: u32,
    root_dir_cluster: u32,
    sectors_per_cluster: u32,
    bytes_per_cluster: u32,
    total_clusters: u32,
    fat_buffer: ?[]u8,
    fat_buffer_sector: u32,
};

const FAT32VNodeData = struct {
    cluster: u32,
    size: u32,
    is_directory: bool,
};

var fat32_fs_type: vfs.FileSystemType = undefined;
var fat32_fs_ops: vfs.FileSystemOps = undefined;
var fat32_file_ops: vfs.FileOps = undefined;

pub fn init() void {
    fat32_file_ops = vfs.FileOps{
        .read = fat32Read,
        .write = fat32Write,
        .open = fat32Open,
        .close = fat32Close,
        .seek = fat32Seek,
        .ioctl = fat32Ioctl,
        .stat = fat32Stat,
        .readdir = fat32Readdir,
    };

    fat32_fs_ops = vfs.FileSystemOps{
        .mount = fat32Mount,
        .unmount = fat32Unmount,
        .get_root = fat32GetRoot,
        .lookup = fat32Lookup,
        .create = fat32Create,
        .mkdir = fat32Mkdir,
        .unlink = fat32Unlink,
        .rmdir = fat32Rmdir,
        .rename = fat32Rename,
    };

    @memcpy(fat32_fs_type.name[0..5], "fat32");
    fat32_fs_type.name[5] = 0;
    fat32_fs_type.ops = &fat32_fs_ops;
    fat32_fs_type.next = null;

    vfs.registerFileSystem(&fat32_fs_type) catch |err| {
        vga.print("Failed to register FAT32: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
}

fn fat32Mount(mount_point: *vfs.MountPoint) vfs.VFSError!void {
    const device = ata.getPrimaryMaster() orelse return vfs.VFSError.NotFound;

    const data_mem = memory.kmalloc(@sizeOf(FAT32Data)) orelse return vfs.VFSError.OutOfMemory;
    const data = @as(*FAT32Data, @ptrCast(@alignCast(data_mem)));

    data.device = device;
    data.fat_buffer = null;
    data.fat_buffer_sector = 0xFFFFFFFF;

    var boot_sector_buf: [512]u8 align(4) = undefined;
    ata.readSectors(device, 0, 1, &boot_sector_buf) catch return vfs.VFSError.DeviceError;

    data.boot_sector = @as(*const BootSector, @ptrCast(&boot_sector_buf)).*;

    if (data.boot_sector.bytes_per_sector != 512) {
        memory.kfree(@as([*]u8, @ptrCast(data)));
        return vfs.VFSError.InvalidOperation;
    }

    data.sectors_per_cluster = data.boot_sector.sectors_per_cluster;
    data.bytes_per_cluster = data.sectors_per_cluster * 512;
    data.fat_start_lba = data.boot_sector.reserved_sectors;
    data.data_start_lba = data.fat_start_lba +
        (data.boot_sector.fat_count * data.boot_sector.sectors_per_fat_32);
    data.root_dir_cluster = data.boot_sector.root_cluster;
    data.total_clusters = (data.boot_sector.total_sectors_32 - data.data_start_lba) /
        data.sectors_per_cluster;

    if (data.boot_sector.fs_info_sector != 0) {
        var fs_info_buf: [512]u8 align(4) = undefined;
        ata.readSectors(device, data.boot_sector.fs_info_sector, 1, &fs_info_buf) catch {};
        data.fs_info = @as(*const FSInfo, @ptrCast(&fs_info_buf)).*;
    }

    const fat_buf_mem = memory.kmalloc(512) orelse {
        memory.kfree(@as([*]u8, @ptrCast(data)));
        return vfs.VFSError.OutOfMemory;
    };
    data.fat_buffer = @as([*]u8, @ptrCast(fat_buf_mem))[0..512];

    mount_point.private_data = data;
}

fn fat32Unmount(mount_point: *vfs.MountPoint) vfs.VFSError!void {
    if (mount_point.private_data) |data_ptr| {
        const data = @as(*FAT32Data, @ptrCast(@alignCast(data_ptr)));
        if (data.fat_buffer) |buf| {
            memory.kfree(@as([*]u8, @ptrCast(buf.ptr)));
        }
        memory.kfree(@as([*]u8, @ptrCast(data)));
    }
}

fn fat32GetRoot(mount_point: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const data = @as(*FAT32Data, @ptrCast(@alignCast(mount_point.private_data.?)));

    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode = @as(*vfs.VNode, @ptrCast(@alignCast(vnode_mem)));

    const vnode_data_mem = memory.kmalloc(@sizeOf(FAT32VNodeData)) orelse {
        memory.kfree(@as([*]u8, @ptrCast(vnode)));
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data = @as(*FAT32VNodeData, @ptrCast(@alignCast(vnode_data_mem)));

    vnode_data.cluster = data.root_dir_cluster;
    vnode_data.size = 0;
    vnode_data.is_directory = true;

    vnode.* = vfs.VNode{
        .name = [_]u8{0} ** 256,
        .name_len = 0,
        .inode = data.root_dir_cluster,
        .file_type = vfs.FileType.Directory,
        .mode = vfs.FileMode{
            .owner_read = true,
            .owner_write = true,
            .owner_exec = true,
            .group_read = true,
            .group_exec = true,
            .other_read = true,
            .other_exec = true,
        },
        .size = 0,
        .ref_count = 1,
        .mount_point = mount_point,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = &fat32_file_ops,
        .private_data = vnode_data,
    };

    vnode.name[0] = '/';
    vnode.name_len = 1;

    return vnode;
}

fn fat32Lookup(parent: *vfs.VNode, name: []const u8) vfs.VFSError!*vfs.VNode {
    const parent_data = @as(*FAT32VNodeData, @ptrCast(@alignCast(parent.private_data.?)));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data = @as(*FAT32Data, @ptrCast(@alignCast(parent.mount_point.?.private_data.?)));

    var cluster = parent_data.cluster;
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries = @as([*]const DirEntry, @ptrCast(&sector_buf))[0..16];
            for (entries) |entry| {
                if (entry.name[0] == 0x00) break;
                if (entry.name[0] == 0xE5) continue;

                if (entry.attributes == ATTR_LONG_NAME) continue;

                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                var entry_name: [13]u8 = undefined;
                formatDosName(&entry.name, &entry.ext, &entry_name);

                if (std.mem.eql(u8, entry_name[0..strlen(&entry_name)], name)) {
                    return createVNodeFromEntry(parent.mount_point.?, &entry, &entry_name);
                }
            }
        }

        cluster = getNextCluster(mount_data, cluster) catch return vfs.VFSError.DeviceError;
    }

    return vfs.VFSError.NotFound;
}

fn fat32Read(vnode: *vfs.VNode, buffer: []u8, offset: u64) vfs.VFSError!usize {
    const vnode_data = @as(*FAT32VNodeData, @ptrCast(@alignCast(vnode.private_data.?)));
    const mount_data = @as(*FAT32Data, @ptrCast(@alignCast(vnode.mount_point.?.private_data.?)));

    if (vnode_data.is_directory) {
        return vfs.VFSError.IsDirectory;
    }

    if (offset >= vnode_data.size) {
        return 0;
    }

    var bytes_to_read = buffer.len;
    if (offset + bytes_to_read > vnode_data.size) {
        bytes_to_read = @as(usize, @intCast(vnode_data.size - offset));
    }

    var current_cluster = vnode_data.cluster;
    var cluster_offset = offset;

    while (cluster_offset >= mount_data.bytes_per_cluster) {
        current_cluster = getNextCluster(mount_data, current_cluster) catch return vfs.VFSError.DeviceError;
        if (current_cluster >= FAT32_EOC) {
            return 0;
        }
        cluster_offset -= mount_data.bytes_per_cluster;
    }

    var bytes_read: usize = 0;
    var sector_buf: [512]u8 align(4) = undefined;

    while (bytes_read < bytes_to_read and current_cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, current_cluster);
        const sector_in_cluster = cluster_offset / 512;
        const offset_in_sector = cluster_offset % 512;

        ata.readSectors(mount_data.device, first_sector + sector_in_cluster, 1, &sector_buf) catch {
            return vfs.VFSError.DeviceError;
        };

        const bytes_in_sector = @min(512 - offset_in_sector, bytes_to_read - bytes_read);
        const offset_start = @as(usize, @intCast(offset_in_sector));
        @memcpy(buffer[bytes_read .. bytes_read + bytes_in_sector], sector_buf[offset_start .. offset_start + bytes_in_sector]);

        bytes_read += bytes_in_sector;
        cluster_offset += bytes_in_sector;

        if (cluster_offset >= mount_data.bytes_per_cluster) {
            current_cluster = getNextCluster(mount_data, current_cluster) catch return vfs.VFSError.DeviceError;
            cluster_offset = 0;
        }
    }

    return bytes_read;
}

fn fat32Write(vnode: *vfs.VNode, buffer: []const u8, offset: u64) vfs.VFSError!usize {
    _ = vnode;
    _ = buffer;
    _ = offset;
    return vfs.VFSError.ReadOnly;
}

fn fat32Open(vnode: *vfs.VNode, flags: u32) vfs.VFSError!void {
    _ = vnode;
    _ = flags;
}

fn fat32Close(vnode: *vfs.VNode) vfs.VFSError!void {
    _ = vnode;
}

fn fat32Seek(vnode: *vfs.VNode, offset: i64, whence: u32) vfs.VFSError!u64 {
    const vnode_data = @as(*FAT32VNodeData, @ptrCast(@alignCast(vnode.private_data.?)));

    var new_offset: i64 = 0;
    switch (whence) {
        vfs.SEEK_SET => new_offset = offset,
        vfs.SEEK_CUR => new_offset = @as(i64, @intCast(offset)),
        vfs.SEEK_END => new_offset = @as(i64, @intCast(vnode_data.size)) + offset,
        else => return vfs.VFSError.InvalidOperation,
    }

    if (new_offset < 0) {
        return vfs.VFSError.InvalidOperation;
    }

    return @as(u64, @intCast(new_offset));
}

fn fat32Ioctl(vnode: *vfs.VNode, cmd: u32, arg: usize) vfs.VFSError!i32 {
    _ = vnode;
    _ = cmd;
    _ = arg;
    return vfs.VFSError.InvalidOperation;
}

fn fat32Stat(vnode: *vfs.VNode, stat: *vfs.FileStat) vfs.VFSError!void {
    const vnode_data = @as(*FAT32VNodeData, @ptrCast(@alignCast(vnode.private_data.?)));

    stat.* = vfs.FileStat{
        .inode = vnode.inode,
        .mode = vnode.mode,
        .file_type = vnode.file_type,
        .size = vnode_data.size,
        .blocks = (vnode_data.size + 511) / 512,
        .block_size = 512,
        .uid = 0,
        .gid = 0,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
    };
}

fn fat32Readdir(vnode: *vfs.VNode, dirent: *vfs.DirEntry, index: u64) vfs.VFSError!bool {
    const vnode_data = @as(*FAT32VNodeData, @ptrCast(@alignCast(vnode.private_data.?)));
    if (!vnode_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data = @as(*FAT32Data, @ptrCast(@alignCast(vnode.mount_point.?.private_data.?)));

    var cluster = vnode_data.cluster;
    var entry_count: u64 = 0;
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries = @as([*]const DirEntry, @ptrCast(&sector_buf))[0..16];
            for (entries) |entry| {
                if (entry.name[0] == 0x00) return false;
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                if (entry_count == index) {
                    formatDosName(&entry.name, &entry.ext, &dirent.name);
                    dirent.name_len = @as(u16, @intCast(strlen(&dirent.name)));
                    dirent.inode = (@as(u64, entry.cluster_high) << 16) | @as(u64, entry.cluster_low);
                    dirent.file_type = if ((entry.attributes & ATTR_DIRECTORY) != 0)
                        vfs.FileType.Directory
                    else
                        vfs.FileType.Regular;
                    return true;
                }

                entry_count += 1;
            }
        }

        cluster = getNextCluster(mount_data, cluster) catch return vfs.VFSError.DeviceError;
    }

    return false;
}

fn fat32Create(parent: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    _ = parent;
    _ = name;
    _ = mode;
    return vfs.VFSError.ReadOnly;
}

fn fat32Mkdir(parent: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    _ = parent;
    _ = name;
    _ = mode;
    return vfs.VFSError.ReadOnly;
}

fn fat32Unlink(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    _ = parent;
    _ = name;
    return vfs.VFSError.ReadOnly;
}

fn fat32Rmdir(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    _ = parent;
    _ = name;
    return vfs.VFSError.ReadOnly;
}

fn fat32Rename(old_parent: *vfs.VNode, old_name: []const u8, new_parent: *vfs.VNode, new_name: []const u8) vfs.VFSError!void {
    _ = old_parent;
    _ = old_name;
    _ = new_parent;
    _ = new_name;
    return vfs.VFSError.ReadOnly;
}

fn clusterToLBA(data: *const FAT32Data, cluster: u32) u32 {
    return data.data_start_lba + ((cluster - 2) * data.sectors_per_cluster);
}

fn getNextCluster(data: *FAT32Data, cluster: u32) !u32 {
    const fat_offset = cluster * 4;
    const fat_sector = data.fat_start_lba + (fat_offset / 512);
    const entry_offset = fat_offset % 512;

    if (fat_sector != data.fat_buffer_sector) {
        if (data.fat_buffer) |buf| {
            ata.readSectors(data.device, fat_sector, 1, buf) catch return error.DeviceError;
            data.fat_buffer_sector = fat_sector;
        }
    }

    if (data.fat_buffer) |buf| {
        const fat_entry = @as(*const u32, @ptrCast(@alignCast(&buf[entry_offset]))).*;
        return fat_entry & 0x0FFFFFFF;
    }

    return error.DeviceError;
}

fn formatDosName(name: []const u8, ext: []const u8, output: []u8) void {
    var out_idx: usize = 0;

    var name_end: usize = 8;
    while (name_end > 0 and name[name_end - 1] == ' ') : (name_end -= 1) {}

    for (0..name_end) |i| {
        if (name[i] != ' ') {
            output[out_idx] = toLower(name[i]);
            out_idx += 1;
        }
    }

    if (ext[0] != ' ') {
        output[out_idx] = '.';
        out_idx += 1;

        var ext_end: usize = 3;
        while (ext_end > 0 and ext[ext_end - 1] == ' ') : (ext_end -= 1) {}

        for (0..ext_end) |i| {
            output[out_idx] = toLower(ext[i]);
            out_idx += 1;
        }
    }

    output[out_idx] = 0;
}

fn createVNodeFromEntry(mount_point: *vfs.MountPoint, entry: *const DirEntry, name: []const u8) !*vfs.VNode {
    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode = @as(*vfs.VNode, @ptrCast(@alignCast(vnode_mem)));

    const vnode_data_mem = memory.kmalloc(@sizeOf(FAT32VNodeData)) orelse {
        memory.kfree(@as([*]u8, @ptrCast(vnode)));
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data = @as(*FAT32VNodeData, @ptrCast(@alignCast(vnode_data_mem)));

    vnode_data.cluster = (@as(u32, entry.cluster_high) << 16) | entry.cluster_low;
    vnode_data.size = entry.size;
    vnode_data.is_directory = (entry.attributes & ATTR_DIRECTORY) != 0;

    vnode.* = vfs.VNode{
        .name = [_]u8{0} ** 256,
        .name_len = @as(u16, @intCast(strlen(name))),
        .inode = vnode_data.cluster,
        .file_type = if (vnode_data.is_directory) vfs.FileType.Directory else vfs.FileType.Regular,
        .mode = vfs.FileMode{
            .owner_read = true,
            .owner_write = (entry.attributes & ATTR_READ_ONLY) == 0,
            .owner_exec = !vnode_data.is_directory,
            .group_read = true,
            .group_write = (entry.attributes & ATTR_READ_ONLY) == 0,
            .group_exec = !vnode_data.is_directory,
            .other_read = true,
            .other_write = false,
            .other_exec = false,
        },
        .size = entry.size,
        .ref_count = 1,
        .mount_point = mount_point,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = &fat32_file_ops,
        .private_data = vnode_data,
    };

    @memcpy(vnode.name[0..vnode.name_len], name[0..vnode.name_len]);

    return vnode;
}

fn strlen(str: []const u8) usize {
    var i: usize = 0;
    while (i < str.len and str[i] != 0) : (i += 1) {}
    return i;
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') {
        return c + 32;
    }
    return c;
}

