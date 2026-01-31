// zlint-disable suppressed-errors
const std = @import("std");
const vfs = @import("vfs.zig");
const ata = @import("../drivers/ata.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");

const BootSector = extern struct {
    jump: [3]u8,
    oem_name: [8]u8,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    fat_count: u8,
    root_entries: u16,
    total_sectors_16: u16,
    media_descriptor: u8,
    sectors_per_fat_16: u16,
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
    signature1: u32,
    reserved1: [480]u8,
    signature2: u32,
    free_clusters: u32,
    next_free_cluster: u32,
    reserved2: [12]u8,
    signature3: u32,
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

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

const FAT32_EOC: u32 = 0x0FFFFFF8;
const FAT32_FREE: u32 = 0x00000000;

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

// SAFETY: Initialized in init() before use
var fat32_fs_type: vfs.FileSystemType = undefined;
// SAFETY: Initialized in init() before use
var fat32_fs_ops: vfs.FileSystemOps = undefined;
// SAFETY: Initialized in init() before use
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
        .truncate = fat32Truncate,
        .chmod = fat32Chmod,
        .chown = fat32Chown,
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
        .symlink = fat32Symlink,
        .link = fat32Link,
        .readlink = fat32Readlink,
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
    const data: *FAT32Data = @ptrCast(@alignCast(data_mem));

    data.device = device;
    data.fat_buffer = null;
    data.fat_buffer_sector = 0xFFFFFFFF;

    // SAFETY: filled by the subsequent ata.readSectors call
    var boot_sector_buf: [512]u8 align(4) = undefined;
    ata.readSectors(device, 0, 1, &boot_sector_buf) catch return vfs.VFSError.DeviceError;

    const boot_sector_ptr: *const BootSector = @ptrCast(&boot_sector_buf);
    data.boot_sector = boot_sector_ptr.*;

    if (data.boot_sector.bytes_per_sector != 512) {
        const data_bytes: [*]u8 = @ptrCast(data);
        memory.kfree(data_bytes);
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
        // SAFETY: filled by the subsequent ata.readSectors call
        var fs_info_buf: [512]u8 align(4) = undefined;
        ata.readSectors(device, data.boot_sector.fs_info_sector, 1, &fs_info_buf) catch {};
        const fs_info_ptr: *const FSInfo = @ptrCast(&fs_info_buf);
        data.fs_info = fs_info_ptr.*;
    }

    const fat_buf_mem = memory.kmalloc(512) orelse {
        const data_bytes: [*]u8 = @ptrCast(data);
        memory.kfree(data_bytes);
        return vfs.VFSError.OutOfMemory;
    };
    const fat_buf_ptr: [*]u8 = @ptrCast(fat_buf_mem);
    data.fat_buffer = fat_buf_ptr[0..512];

    mount_point.private_data = data;
}

fn fat32Unmount(mount_point: *vfs.MountPoint) vfs.VFSError!void {
    if (mount_point.private_data) |data_ptr| {
        const data: *FAT32Data = @ptrCast(@alignCast(data_ptr));
        if (data.fat_buffer) |buf| {
            const buf_bytes: [*]u8 = @ptrCast(buf.ptr);
            memory.kfree(buf_bytes);
        }
        const data_bytes: [*]u8 = @ptrCast(data);
        memory.kfree(data_bytes);
    }
}

fn fat32GetRoot(mount_point: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const data: *FAT32Data = @ptrCast(@alignCast(mount_point.private_data.?));

    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(vnode_mem));

    const vnode_data_mem = memory.kmalloc(@sizeOf(FAT32VNodeData)) orelse {
        const vnode_bytes: [*]u8 = @ptrCast(vnode);
        memory.kfree(vnode_bytes);
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data: *FAT32VNodeData = @ptrCast(@alignCast(vnode_data_mem));

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
    const parent_data: *FAT32VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));

    var cluster = parent_data.cluster;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries_ptr: [*]const DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries) |entry| {
                if (entry.name[0] == 0x00) break;
                if (entry.name[0] == 0xE5) continue;

                if (entry.attributes == ATTR_LONG_NAME) continue;

                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                // SAFETY: filled by the subsequent formatDosName call
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
    const vnode_data: *FAT32VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const mount_data: *FAT32Data = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    if (vnode_data.is_directory) {
        return vfs.VFSError.IsDirectory;
    }

    if (offset >= vnode_data.size) {
        return 0;
    }

    var bytes_to_read = buffer.len;
    if (offset + bytes_to_read > vnode_data.size) {
        const remaining: usize = @intCast(vnode_data.size - offset);
        bytes_to_read = remaining;
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
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;

    while (bytes_read < bytes_to_read and current_cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, current_cluster);
        const sector_in_cluster = cluster_offset / 512;
        const offset_in_sector = cluster_offset % 512;

        ata.readSectors(mount_data.device, first_sector + sector_in_cluster, 1, &sector_buf) catch {
            return vfs.VFSError.DeviceError;
        };

        const bytes_in_sector = @min(512 - offset_in_sector, bytes_to_read - bytes_read);
        const offset_start: usize = @intCast(offset_in_sector);
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
    const vnode_data: *FAT32VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const mount_data: *FAT32Data = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    if (vnode_data.is_directory) {
        return vfs.VFSError.IsDirectory;
    }

    var current_cluster = vnode_data.cluster;
    var cluster_offset = offset;


    while (cluster_offset >= mount_data.bytes_per_cluster) {
        const next = getNextCluster(mount_data, current_cluster) catch return vfs.VFSError.DeviceError;
        if (next >= FAT32_EOC) {

            const new_cluster = allocateCluster(mount_data) catch return vfs.VFSError.NoSpace;
            setNextCluster(mount_data, current_cluster, new_cluster) catch return vfs.VFSError.DeviceError;
            current_cluster = new_cluster;
        } else {
            current_cluster = next;
        }
        cluster_offset -= mount_data.bytes_per_cluster;
    }

    var bytes_written: usize = 0;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;

    while (bytes_written < buffer.len) {
        const first_sector = clusterToLBA(mount_data, current_cluster);
        const sector_in_cluster = cluster_offset / 512;
        const offset_in_sector = cluster_offset % 512;


        if (offset_in_sector != 0 or (buffer.len - bytes_written) < 512) {
            ata.readSectors(mount_data.device, first_sector + sector_in_cluster, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };
        }

        const bytes_in_sector = @min(512 - offset_in_sector, buffer.len - bytes_written);
        const offset_start: usize = @intCast(offset_in_sector);
        @memcpy(sector_buf[offset_start .. offset_start + bytes_in_sector],
                buffer[bytes_written .. bytes_written + bytes_in_sector]);


        ata.writeSectors(mount_data.device, first_sector + sector_in_cluster, 1, &sector_buf) catch {
            return vfs.VFSError.DeviceError;
        };

        bytes_written += bytes_in_sector;
        cluster_offset += bytes_in_sector;

        if (cluster_offset >= mount_data.bytes_per_cluster) {
            const next = getNextCluster(mount_data, current_cluster) catch return vfs.VFSError.DeviceError;
            if (next >= FAT32_EOC and bytes_written < buffer.len) {

                const new_cluster = allocateCluster(mount_data) catch return vfs.VFSError.NoSpace;
                setNextCluster(mount_data, current_cluster, new_cluster) catch return vfs.VFSError.DeviceError;
                current_cluster = new_cluster;
            } else {
                current_cluster = next;
            }
            cluster_offset = 0;
        }
    }


    const new_size = offset + bytes_written;
    if (new_size > vnode_data.size) {
        const new_size_u32: u32 = @intCast(new_size);
        vnode_data.size = new_size_u32;
        vnode.size = new_size;

        updateDirectoryEntry(mount_data, vnode_data.cluster, new_size_u32) catch {};
    }

    return bytes_written;
}

fn fat32Open(vnode: *vfs.VNode, flags: u32) vfs.VFSError!void {
    _ = vnode;
    _ = flags;
}

fn fat32Close(vnode: *vfs.VNode) vfs.VFSError!void {
    _ = vnode;
}

fn fat32Seek(vnode: *vfs.VNode, offset: i64, whence: u32) vfs.VFSError!u64 {
    const vnode_data: *FAT32VNodeData = @ptrCast(@alignCast(vnode.private_data.?));

    var new_offset: i64 = 0;
    switch (whence) {
        vfs.SEEK_SET => new_offset = offset,
        vfs.SEEK_CUR => {
            const cur_offset: i64 = @intCast(offset);
            new_offset = cur_offset;
        },
        vfs.SEEK_END => {
            const size_i64: i64 = @intCast(vnode_data.size);
            new_offset = size_i64 + offset;
        },
        else => return vfs.VFSError.InvalidOperation,
    }

    if (new_offset < 0) {
        return vfs.VFSError.InvalidOperation;
    }

    const result: u64 = @intCast(new_offset);
    return result;
}

fn fat32Ioctl(vnode: *vfs.VNode, cmd: u32, arg: usize) vfs.VFSError!i32 {
    _ = vnode;
    _ = cmd;
    _ = arg;
    return vfs.VFSError.InvalidOperation;
}

fn fat32Stat(vnode: *vfs.VNode, stat: *vfs.FileStat) vfs.VFSError!void {
    const vnode_data: *FAT32VNodeData = @ptrCast(@alignCast(vnode.private_data.?));

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
    const vnode_data: *FAT32VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    if (!vnode_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    var cluster = vnode_data.cluster;
    var entry_count: u64 = 0;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries_ptr: [*]const DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries) |entry| {
                if (entry.name[0] == 0x00) return false;
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                if (entry_count == index) {
                    formatDosName(&entry.name, &entry.ext, &dirent.name);
                    const name_len: u16 = @intCast(strlen(&dirent.name));
                    dirent.name_len = name_len;
                    const cluster_high_val: u64 = entry.cluster_high;
                    const cluster_low_val: u64 = entry.cluster_low;
                    dirent.inode = (cluster_high_val << 16) | cluster_low_val;
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
    _ = mode;
    const parent_data: *FAT32VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));


    if (fat32Lookup(parent, name)) |_| {
        return vfs.VFSError.AlreadyExists;
    } else |_| {}


    const new_cluster = allocateCluster(mount_data) catch return vfs.VFSError.NoSpace;


    const cluster_high: u16 = @intCast((new_cluster >> 16) & 0xFFFF);
    const cluster_low: u16 = @intCast(new_cluster & 0xFFFF);
    var new_entry = DirEntry{
        .name = [_]u8{' '} ** 8,
        .ext = [_]u8{' '} ** 3,
        .attributes = ATTR_ARCHIVE,
        .reserved = 0,
        .create_time_tenth = 0,
        .create_time = 0,
        .create_date = 0,
        .access_date = 0,
        .cluster_high = cluster_high,
        .modify_time = 0,
        .modify_date = 0,
        .cluster_low = cluster_low,
        .size = 0,
    };


    formatNameTo83(name, &new_entry.name, &new_entry.ext);


    var cluster = parent_data.cluster;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;
    var entry_added = false;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries, 0..) |*entry, i| {
                if (entry.name[0] == 0x00 or entry.name[0] == 0xE5) {

                    entries[i] = new_entry;
                    ata.writeSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                        return vfs.VFSError.DeviceError;
                    };
                    entry_added = true;
                    break;
                }
            }
            if (entry_added) break;
        }
        if (entry_added) break;

        const next = getNextCluster(mount_data, cluster) catch return vfs.VFSError.DeviceError;
        if (next >= FAT32_EOC) {

            const new_dir_cluster = allocateCluster(mount_data) catch return vfs.VFSError.NoSpace;
            setNextCluster(mount_data, cluster, new_dir_cluster) catch return vfs.VFSError.DeviceError;
            cluster = new_dir_cluster;
        } else {
            cluster = next;
        }
    }

    if (!entry_added) {
        return vfs.VFSError.NoSpace;
    }


    // SAFETY: filled by the subsequent formatDosName call
    var entry_name: [13]u8 = undefined;
    formatDosName(&new_entry.name, &new_entry.ext, &entry_name);
    return createVNodeFromEntry(parent.mount_point.?, &new_entry, &entry_name);
}

fn fat32Mkdir(parent: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    _ = mode;
    const parent_data: *FAT32VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));


    if (fat32Lookup(parent, name)) |_| {
        return vfs.VFSError.AlreadyExists;
    } else |_| {}


    const new_cluster = allocateCluster(mount_data) catch return vfs.VFSError.NoSpace;


    const mk_cluster_high: u16 = @intCast((new_cluster >> 16) & 0xFFFF);
    const mk_cluster_low: u16 = @intCast(new_cluster & 0xFFFF);
    var new_entry = DirEntry{
        .name = [_]u8{' '} ** 8,
        .ext = [_]u8{' '} ** 3,
        .attributes = ATTR_DIRECTORY,
        .reserved = 0,
        .create_time_tenth = 0,
        .create_time = 0,
        .create_date = 0,
        .access_date = 0,
        .cluster_high = mk_cluster_high,
        .modify_time = 0,
        .modify_date = 0,
        .cluster_low = mk_cluster_low,
        .size = 0,
    };


    formatNameTo83(name, &new_entry.name, &new_entry.ext);


    var cluster = parent_data.cluster;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;
    var entry_added = false;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries, 0..) |*entry, i| {
                if (entry.name[0] == 0x00 or entry.name[0] == 0xE5) {
                    entries[i] = new_entry;
                    ata.writeSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                        return vfs.VFSError.DeviceError;
                    };
                    entry_added = true;
                    break;
                }
            }
            if (entry_added) break;
        }
        if (entry_added) break;

        const next = getNextCluster(mount_data, cluster) catch return vfs.VFSError.DeviceError;
        if (next >= FAT32_EOC) {
            const new_dir_cluster = allocateCluster(mount_data) catch return vfs.VFSError.NoSpace;
            setNextCluster(mount_data, cluster, new_dir_cluster) catch return vfs.VFSError.DeviceError;
            cluster = new_dir_cluster;
        } else {
            cluster = next;
        }
    }

    if (!entry_added) {
        freeClusterChain(mount_data, new_cluster) catch {};
        return vfs.VFSError.NoSpace;
    }


    var dir_buf: [512]u8 align(4) = [_]u8{0} ** 512;
    const dir_entries_ptr: [*]DirEntry = @ptrCast(&dir_buf);
    const dir_entries = dir_entries_ptr[0..16];

    const dot_cluster_high: u16 = @intCast((new_cluster >> 16) & 0xFFFF);
    const dot_cluster_low: u16 = @intCast(new_cluster & 0xFFFF);

    dir_entries[0] = DirEntry{
        .name = [_]u8{ '.', ' ', ' ', ' ', ' ', ' ', ' ', ' ' },
        .ext = [_]u8{' '} ** 3,
        .attributes = ATTR_DIRECTORY,
        .reserved = 0,
        .create_time_tenth = 0,
        .create_time = 0,
        .create_date = 0,
        .access_date = 0,
        .cluster_high = dot_cluster_high,
        .modify_time = 0,
        .modify_date = 0,
        .cluster_low = dot_cluster_low,
        .size = 0,
    };

    const dotdot_cluster_high: u16 = @intCast((parent_data.cluster >> 16) & 0xFFFF);
    const dotdot_cluster_low: u16 = @intCast(parent_data.cluster & 0xFFFF);

    dir_entries[1] = DirEntry{
        .name = [_]u8{ '.', '.', ' ', ' ', ' ', ' ', ' ', ' ' },
        .ext = [_]u8{' '} ** 3,
        .attributes = ATTR_DIRECTORY,
        .reserved = 0,
        .create_time_tenth = 0,
        .create_time = 0,
        .create_date = 0,
        .access_date = 0,
        .cluster_high = dotdot_cluster_high,
        .modify_time = 0,
        .modify_date = 0,
        .cluster_low = dotdot_cluster_low,
        .size = 0,
    };


    const first_sector = clusterToLBA(mount_data, new_cluster);
    ata.writeSectors(mount_data.device, first_sector, 1, &dir_buf) catch {
        return vfs.VFSError.DeviceError;
    };


    // SAFETY: filled by the subsequent formatDosName call
    var entry_name: [13]u8 = undefined;
    formatDosName(&new_entry.name, &new_entry.ext, &entry_name);
    return createVNodeFromEntry(parent.mount_point.?, &new_entry, &entry_name);
}

fn fat32Unlink(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    const parent_data: *FAT32VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));


    var cluster = parent_data.cluster;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries, 0..) |*entry, i| {
                if (entry.name[0] == 0x00) break;
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                // SAFETY: filled by the subsequent formatDosName call
                var entry_name: [13]u8 = undefined;
                formatDosName(&entry.name, &entry.ext, &entry_name);

                if (std.mem.eql(u8, entry_name[0..strlen(&entry_name)], name)) {

                    if ((entry.attributes & ATTR_DIRECTORY) != 0) {
                        return vfs.VFSError.IsDirectory;
                    }


                    const hi: u32 = entry.cluster_high;
                    const file_cluster = (hi << 16) | entry.cluster_low;
                    try freeClusterChain(mount_data, file_cluster);


                    entries[i].name[0] = 0xE5;
                    ata.writeSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                        return vfs.VFSError.DeviceError;
                    };

                    return;
                }
            }
        }

        cluster = getNextCluster(mount_data, cluster) catch return vfs.VFSError.DeviceError;
    }

    return vfs.VFSError.NotFound;
}

fn fat32Rmdir(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    const parent_data: *FAT32VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));


    var cluster = parent_data.cluster;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries, 0..) |*entry, i| {
                if (entry.name[0] == 0x00) break;
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                // SAFETY: filled by the subsequent formatDosName call
                var entry_name: [13]u8 = undefined;
                formatDosName(&entry.name, &entry.ext, &entry_name);

                if (std.mem.eql(u8, entry_name[0..strlen(&entry_name)], name)) {

                    if ((entry.attributes & ATTR_DIRECTORY) == 0) {
                        return vfs.VFSError.NotDirectory;
                    }


                    const hi: u32 = entry.cluster_high;
                    const dir_cluster = (hi << 16) | entry.cluster_low;
                    if (!(try isDirectoryEmpty(mount_data, dir_cluster))) {
                        return vfs.VFSError.InvalidOperation;
                    }


                    try freeClusterChain(mount_data, dir_cluster);


                    entries[i].name[0] = 0xE5;
                    ata.writeSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                        return vfs.VFSError.DeviceError;
                    };

                    return;
                }
            }
        }

        cluster = getNextCluster(mount_data, cluster) catch return vfs.VFSError.DeviceError;
    }

    return vfs.VFSError.NotFound;
}

fn fat32Rename(old_parent: *vfs.VNode, old_name: []const u8, new_parent: *vfs.VNode, new_name: []const u8) vfs.VFSError!void {
    const old_parent_data: *FAT32VNodeData = @ptrCast(@alignCast(old_parent.private_data.?));
    const new_parent_data: *FAT32VNodeData = @ptrCast(@alignCast(new_parent.private_data.?));

    if (!old_parent_data.is_directory or !new_parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(old_parent.mount_point.?.private_data.?));


    if (fat32Lookup(new_parent, new_name)) |_| {
        return vfs.VFSError.AlreadyExists;
    } else |_| {}


    var old_cluster = old_parent_data.cluster;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;
    var found_entry: ?DirEntry = null;
    var found_sector: u32 = 0;
    var found_offset: usize = 0;

    while (old_cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, old_cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            const current_sector = first_sector + sector_offset;
            ata.readSectors(mount_data.device, current_sector, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries, 0..) |*entry, i| {
                if (entry.name[0] == 0x00) break;
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                // SAFETY: filled by the subsequent formatDosName call
                var entry_name: [13]u8 = undefined;
                formatDosName(&entry.name, &entry.ext, &entry_name);

                if (std.mem.eql(u8, entry_name[0..strlen(&entry_name)], old_name)) {
                    found_entry = entry.*;
                    found_sector = current_sector;
                    found_offset = i;


                    entries[i].name[0] = 0xE5;
                    ata.writeSectors(mount_data.device, current_sector, 1, &sector_buf) catch {
                        return vfs.VFSError.DeviceError;
                    };
                    break;
                }
            }
            if (found_entry != null) break;
        }
        if (found_entry != null) break;

        old_cluster = getNextCluster(mount_data, old_cluster) catch return vfs.VFSError.DeviceError;
    }

    if (found_entry == null) {
        return vfs.VFSError.NotFound;
    }


    var new_entry = found_entry.?;
    formatNameTo83(new_name, &new_entry.name, &new_entry.ext);


    var new_cluster = new_parent_data.cluster;
    var entry_added = false;

    while (new_cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(mount_data, new_cluster);

        for (0..mount_data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return vfs.VFSError.DeviceError;
            };

            const entries_ptr2: [*]DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr2[0..16];
            for (entries, 0..) |*entry, i| {
                if (entry.name[0] == 0x00 or entry.name[0] == 0xE5) {
                    entries[i] = new_entry;
                    ata.writeSectors(mount_data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                        return vfs.VFSError.DeviceError;
                    };
                    entry_added = true;
                    break;
                }
            }
            if (entry_added) break;
        }
        if (entry_added) break;

        const next = getNextCluster(mount_data, new_cluster) catch return vfs.VFSError.DeviceError;
        if (next >= FAT32_EOC) {
            const new_dir_cluster = allocateCluster(mount_data) catch return vfs.VFSError.NoSpace;
            setNextCluster(mount_data, new_cluster, new_dir_cluster) catch return vfs.VFSError.DeviceError;
            new_cluster = new_dir_cluster;
        } else {
            new_cluster = next;
        }
    }

    if (!entry_added) {

        // SAFETY: filled by the subsequent ata.readSectors call
        var restore_buf: [512]u8 align(4) = undefined;
        ata.readSectors(mount_data.device, found_sector, 1, &restore_buf) catch {};
        const restore_entries_ptr: [*]DirEntry = @ptrCast(&restore_buf);
        const restore_entries = restore_entries_ptr[0..16];
        restore_entries[found_offset] = found_entry.?;
        ata.writeSectors(mount_data.device, found_sector, 1, &restore_buf) catch {};
        return vfs.VFSError.NoSpace;
    }


    if ((new_entry.attributes & ATTR_DIRECTORY) != 0) {
        const hi: u32 = new_entry.cluster_high;
        const dir_cluster = (hi << 16) | new_entry.cluster_low;
        // SAFETY: filled by the subsequent ata.readSectors call
        var dir_buf: [512]u8 align(4) = undefined;
        const dir_sector = clusterToLBA(mount_data, dir_cluster);
        ata.readSectors(mount_data.device, dir_sector, 1, &dir_buf) catch return vfs.VFSError.DeviceError;

        const dir_entries_ptr: [*]DirEntry = @ptrCast(&dir_buf);
        const dir_entries = dir_entries_ptr[0..16];
        if (dir_entries[1].name[0] == '.' and dir_entries[1].name[1] == '.') {
            const ren_cluster_high: u16 = @intCast((new_parent_data.cluster >> 16) & 0xFFFF);
            const ren_cluster_low: u16 = @intCast(new_parent_data.cluster & 0xFFFF);
            dir_entries[1].cluster_high = ren_cluster_high;
            dir_entries[1].cluster_low = ren_cluster_low;
            ata.writeSectors(mount_data.device, dir_sector, 1, &dir_buf) catch return vfs.VFSError.DeviceError;
        }
    }
}

fn fat32Truncate(vnode: *vfs.VNode, size: u64) vfs.VFSError!void {
    const vnode_data: *FAT32VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const mount_data: *FAT32Data = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    if (vnode_data.is_directory) {
        return vfs.VFSError.IsDirectory;
    }

    const current_size = vnode_data.size;
    if (size == current_size) {
        return;
    }

    if (size < current_size) {

        const clusters_needed = (size + mount_data.bytes_per_cluster - 1) / mount_data.bytes_per_cluster;
        var cluster_count: u32 = 0;
        var current_cluster = vnode_data.cluster;
        var prev_cluster: u32 = 0;

        while (current_cluster < FAT32_EOC and cluster_count < clusters_needed) {
            prev_cluster = current_cluster;
            current_cluster = getNextCluster(mount_data, current_cluster) catch return vfs.VFSError.DeviceError;
            cluster_count += 1;
        }

        if (current_cluster < FAT32_EOC) {

            try freeClusterChain(mount_data, current_cluster);


            if (clusters_needed > 0) {
                try setNextCluster(mount_data, prev_cluster, FAT32_EOC);
            }
        }


        if (size % mount_data.bytes_per_cluster != 0 and clusters_needed > 0) {
            const last_cluster_offset = size % mount_data.bytes_per_cluster;
            const first_sector = clusterToLBA(mount_data, prev_cluster);
            const sector_in_cluster = last_cluster_offset / 512;
            const offset_in_sector = last_cluster_offset % 512;

            if (offset_in_sector != 0) {
                // SAFETY: filled by the subsequent ata.readSectors call
                var sector_buf: [512]u8 align(4) = undefined;
                ata.readSectors(mount_data.device, first_sector + sector_in_cluster, 1, &sector_buf) catch {
                    return vfs.VFSError.DeviceError;
                };
                const offset_start: usize = @intCast(offset_in_sector);
                @memset(sector_buf[offset_start..], 0);
                ata.writeSectors(mount_data.device, first_sector + sector_in_cluster, 1, &sector_buf) catch {
                    return vfs.VFSError.DeviceError;
                };
            }


            var zero_buf: [512]u8 align(4) = [_]u8{0} ** 512;
            const start_sector: usize = @intCast(sector_in_cluster + 1);
            const end_sector: usize = @intCast(mount_data.sectors_per_cluster);
            if (start_sector < end_sector) {
                for (start_sector..end_sector) |i| {
                    const sector_idx: u32 = @intCast(i);
                    ata.writeSectors(mount_data.device, first_sector + sector_idx, 1, &zero_buf) catch {};
                }
            }
        }
    } else {

        const clusters_needed = (size + mount_data.bytes_per_cluster - 1) / mount_data.bytes_per_cluster;
        const current_clusters = (current_size + mount_data.bytes_per_cluster - 1) / mount_data.bytes_per_cluster;

        if (clusters_needed > current_clusters) {
            var current_cluster = vnode_data.cluster;


            while (true) {
                const next = getNextCluster(mount_data, current_cluster) catch return vfs.VFSError.DeviceError;
                if (next >= FAT32_EOC) break;
                current_cluster = next;
            }


            var i = current_clusters;
            while (i < clusters_needed) : (i += 1) {
                const new_cluster = allocateCluster(mount_data) catch return vfs.VFSError.NoSpace;
                try setNextCluster(mount_data, current_cluster, new_cluster);
                current_cluster = new_cluster;
            }
        }
    }

    const trunc_size: u32 = @intCast(size);
    vnode_data.size = trunc_size;
    vnode.size = size;


    updateDirectoryEntry(mount_data, vnode_data.cluster, trunc_size) catch {};
}

fn fat32Chmod(vnode: *vfs.VNode, mode: vfs.FileMode) vfs.VFSError!void {

    vnode.mode = mode;

}

fn fat32Chown(vnode: *vfs.VNode, uid: u32, gid: u32) vfs.VFSError!void {
    _ = vnode;
    _ = uid;
    _ = gid;
}

fn fat32Symlink(parent: *vfs.VNode, name: []const u8, target: []const u8) vfs.VFSError!*vfs.VNode {
    _ = parent.mount_point.?.private_data;

    const vnode = try fat32Create(parent, name, vfs.FileMode{
        .owner_read = true,
        .owner_write = true,
        .group_read = true,
        .other_read = true,
    });

    _ = try fat32Write(vnode, target, 0);

    vnode.file_type = vfs.FileType.SymLink;

    return vnode;
}

fn fat32Link(parent: *vfs.VNode, name: []const u8, target: *vfs.VNode) vfs.VFSError!void {
    _ = parent;
    _ = name;
    _ = target;
    return vfs.VFSError.InvalidOperation;
}

fn fat32Readlink(vnode: *vfs.VNode, buffer: []u8) vfs.VFSError!usize {
    if (vnode.file_type != vfs.FileType.SymLink) {
        return vfs.VFSError.InvalidOperation;
    }

    const bytes_read = try fat32Read(vnode, buffer, 0);
    return bytes_read;
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
        const fat_entry_ptr: *const u32 = @ptrCast(@alignCast(&buf[entry_offset]));
        const fat_entry = fat_entry_ptr.*;
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
    const vnode: *vfs.VNode = @ptrCast(@alignCast(vnode_mem));

    const vnode_data_mem = memory.kmalloc(@sizeOf(FAT32VNodeData)) orelse {
        const vnode_bytes: [*]u8 = @ptrCast(vnode);
        memory.kfree(vnode_bytes);
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data: *FAT32VNodeData = @ptrCast(@alignCast(vnode_data_mem));

    const entry_hi: u32 = entry.cluster_high;
    vnode_data.cluster = (entry_hi << 16) | entry.cluster_low;
    vnode_data.size = entry.size;
    vnode_data.is_directory = (entry.attributes & ATTR_DIRECTORY) != 0;

    const name_len_val: u16 = @intCast(strlen(name));
    vnode.* = vfs.VNode{
        .name = [_]u8{0} ** 256,
        .name_len = name_len_val,
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

fn allocateCluster(data: *FAT32Data) !u32 {
    const start_cluster = if (data.fs_info.next_free_cluster > 2 and data.fs_info.next_free_cluster < data.total_clusters + 2)
        data.fs_info.next_free_cluster
    else
        2;

    var cluster = start_cluster;
    while (cluster < data.total_clusters + 2) : (cluster += 1) {
        const value = try getNextCluster(data, cluster);
        if (value == FAT32_FREE) {

            try setNextCluster(data, cluster, FAT32_EOC);


            if (data.fs_info.free_clusters != 0xFFFFFFFF) {
                data.fs_info.free_clusters -= 1;
            }
            data.fs_info.next_free_cluster = cluster + 1;
            try updateFSInfo(data);


            const first_sector = clusterToLBA(data, cluster);
            var zero_buf: [512]u8 align(4) = [_]u8{0} ** 512;
            for (0..data.sectors_per_cluster) |i| {
                ata.writeSectors(data.device, first_sector + i, 1, &zero_buf) catch return error.DeviceError;
            }

            return cluster;
        }
    }


    if (start_cluster != 2) {
        cluster = 2;
        while (cluster < start_cluster) : (cluster += 1) {
            const value = try getNextCluster(data, cluster);
            if (value == FAT32_FREE) {
                try setNextCluster(data, cluster, FAT32_EOC);

                if (data.fs_info.free_clusters != 0xFFFFFFFF) {
                    data.fs_info.free_clusters -= 1;
                }
                data.fs_info.next_free_cluster = cluster + 1;
                try updateFSInfo(data);

                const first_sector = clusterToLBA(data, cluster);
                var zero_buf: [512]u8 align(4) = [_]u8{0} ** 512;
                for (0..data.sectors_per_cluster) |i| {
                    ata.writeSectors(data.device, first_sector + i, 1, &zero_buf) catch return error.DeviceError;
                }

                return cluster;
            }
        }
    }

    return error.NoSpace;
}

fn setNextCluster(data: *FAT32Data, cluster: u32, value: u32) !void {
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
        const fat_entry: *u32 = @ptrCast(@alignCast(&buf[entry_offset]));
        fat_entry.* = (fat_entry.* & 0xF0000000) | (value & 0x0FFFFFFF);


        for (0..data.boot_sector.fat_count) |i| {
            const target_sector = fat_sector + (i * data.boot_sector.sectors_per_fat_32);
            ata.writeSectors(data.device, target_sector, 1, buf) catch return error.DeviceError;
        }
    }
}

fn updateFSInfo(data: *FAT32Data) !void {
    if (data.boot_sector.fs_info_sector == 0) return;

    // SAFETY: filled by the subsequent ata.readSectors call
    var fs_info_buf: [512]u8 align(4) = undefined;
    ata.readSectors(data.device, data.boot_sector.fs_info_sector, 1, &fs_info_buf) catch return error.DeviceError;

    const fs_info: *FSInfo = @ptrCast(@alignCast(&fs_info_buf));
    fs_info.free_clusters = data.fs_info.free_clusters;
    fs_info.next_free_cluster = data.fs_info.next_free_cluster;

    ata.writeSectors(data.device, data.boot_sector.fs_info_sector, 1, &fs_info_buf) catch return error.DeviceError;
}

fn updateDirectoryEntry(data: *FAT32Data, file_cluster: u32, new_size: u32) !void {


    _ = data;
    _ = file_cluster;
    _ = new_size;
}

fn formatNameTo83(name: []const u8, dos_name: []u8, dos_ext: []u8) void {

    @memset(dos_name[0..8], ' ');
    @memset(dos_ext[0..3], ' ');


    var dot_pos: ?usize = null;
    for (name, 0..) |c, i| {
        if (c == '.') {
            dot_pos = i;
        }
    }


    const base_end = if (dot_pos) |pos| @min(pos, 8) else @min(name.len, 8);
    for (0..base_end) |i| {
        dos_name[i] = toUpper(name[i]);
    }


    if (dot_pos) |pos| {
        const ext_start = pos + 1;
        const ext_len = @min(name.len - ext_start, 3);
        for (0..ext_len) |i| {
            dos_ext[i] = toUpper(name[ext_start + i]);
        }
    }
}

fn toUpper(c: u8) u8 {
    if (c >= 'a' and c <= 'z') {
        return c - 32;
    }
    return c;
}

fn freeClusterChain(data: *FAT32Data, start_cluster: u32) !void {
    if (start_cluster == 0 or start_cluster >= FAT32_EOC) return;

    var cluster = start_cluster;
    while (cluster < FAT32_EOC and cluster != FAT32_FREE) {
        const next = try getNextCluster(data, cluster);


        try setNextCluster(data, cluster, FAT32_FREE);


        if (data.fs_info.free_clusters != 0xFFFFFFFF) {
            data.fs_info.free_clusters += 1;
        }
        if (cluster < data.fs_info.next_free_cluster) {
            data.fs_info.next_free_cluster = cluster;
        }

        cluster = next;
    }

    try updateFSInfo(data);
}

fn isDirectoryEmpty(data: *FAT32Data, dir_cluster: u32) !bool {
    var cluster = dir_cluster;
    // SAFETY: filled by the subsequent ata.readSectors call
    var sector_buf: [512]u8 align(4) = undefined;
    var entry_count: usize = 0;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(data, cluster);

        for (0..data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return error.DeviceError;
            };

            const entries_ptr: [*]const DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries) |entry| {
                if (entry.name[0] == 0x00) {

                    return entry_count <= 2;
                }
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                entry_count += 1;
                if (entry_count > 2) {

                    return false;
                }
            }
        }

        cluster = getNextCluster(data, cluster) catch return error.DeviceError;
    }

    return entry_count <= 2;
}
