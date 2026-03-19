// zlint-disable suppressed-errors
const std = @import("std");
const vfs = @import("vfs.zig");
const unicode_casefold = @import("unicode_casefold.zig");
const unicode_normalize = @import("unicode_normalize.zig");
const ata = @import("../drivers/ata.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");

const BootSector = extern struct {
    jump: [3]u8,
    oem_name: [8]u8,
    bytes_per_sector: u16 align(1),
    sectors_per_cluster: u8,
    reserved_sectors: u16 align(1),
    fat_count: u8,
    root_entries: u16 align(1),
    total_sectors_16: u16 align(1),
    media_descriptor: u8,
    sectors_per_fat_16: u16 align(1),
    sectors_per_track: u16 align(1),
    heads: u16 align(1),
    hidden_sectors: u32 align(1),
    total_sectors_32: u32 align(1),

    sectors_per_fat_32: u32 align(1),
    ext_flags: u16 align(1),
    fs_version: u16 align(1),
    root_cluster: u32 align(1),
    fs_info_sector: u16 align(1),
    backup_boot_sector: u16 align(1),
    reserved: [12]u8,
    drive_number: u8,
    reserved1: u8,
    boot_signature: u8,
    volume_id: u32 align(1),
    volume_label: [11]u8,
    fs_type: [8]u8,
};

const FSInfo = extern struct {
    signature1: u32 align(1),
    reserved1: [480]u8,
    signature2: u32 align(1),
    free_clusters: u32 align(1),
    next_free_cluster: u32 align(1),
    reserved2: [12]u8,
    signature3: u32 align(1),
};

const DirEntry = extern struct {
    name: [8]u8,
    ext: [3]u8,
    attributes: u8,
    reserved: u8,
    create_time_tenth: u8,
    create_time: u16 align(1),
    create_date: u16 align(1),
    access_date: u16 align(1),
    cluster_high: u16 align(1),
    modify_time: u16 align(1),
    modify_date: u16 align(1),
    cluster_low: u16 align(1),
    size: u32 align(1),
};

const LfnEntry = extern struct {
    order: u8,
    name1: [5]u16 align(1),
    attributes: u8,
    entry_type: u8,
    checksum: u8,
    name2: [6]u16 align(1),
    first_cluster_low: u16 align(1),
    name3: [2]u16 align(1),
};

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_ZIGOS_SYMLINK: u8 = ATTR_SYSTEM | ATTR_ARCHIVE;
const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;
const LFN_LAST_ENTRY: u8 = 0x40;
const LFN_CHARS_PER_ENTRY: usize = 13;
const MAX_LFN_ENTRIES: usize = 20;
const MAX_LFN_CODE_UNITS: usize = MAX_LFN_ENTRIES * LFN_CHARS_PER_ENTRY;
const MAX_LFN_NAME_CODE_UNITS: usize = 255;
const MAX_VISIBLE_NAME_BYTES: usize = 255;
const MAX_COMPARE_CODEPOINTS: usize = MAX_VISIBLE_NAME_BYTES * 4;

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

const LfnState = struct {
    active: bool = false,
    total_entries: u8 = 0,
    checksum: u8 = 0,
    seen_mask: u32 = 0,
    code_units: [MAX_LFN_CODE_UNITS]u16 = [_]u16{0} ** MAX_LFN_CODE_UNITS,
    code_unit_len: usize = 0,
};

const DirMatch = struct {
    entry: DirEntry,
    visible_name: [256]u8,
    visible_len: u16,
    primary_ordinal: u32,
    lfn_count: u8,
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
    const devices = ata.getProbeCandidates();

    const data_mem = memory.kmalloc(@sizeOf(FAT32Data)) orelse return vfs.VFSError.OutOfMemory;
    const data: *FAT32Data = @ptrCast(@alignCast(data_mem));

    data.device = undefined;
    data.fat_buffer = null;
    data.fat_buffer_sector = 0xFFFFFFFF;

    // SAFETY: filled by the subsequent ata.readSectors call
    var boot_sector_buf: [512]u8 align(4) = undefined;

    var mounted = false;
    for (devices) |device| {
        ata.readSectors(device, 0, 1, &boot_sector_buf) catch continue;
        if (!looksLikeFat32BootSector(&boot_sector_buf)) continue;
        data.device = device;
        mounted = true;
        break;
    }

    if (!mounted) {
        const data_bytes: [*]u8 = @ptrCast(data);
        memory.kfree(data_bytes);
        return vfs.VFSError.DeviceError;
    }

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
        ata.readSectors(data.device, data.boot_sector.fs_info_sector, 1, &fs_info_buf) catch {};
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

fn looksLikeFat32BootSector(sector: *const [512]u8) bool {
    if (sector[510] != 0x55 or sector[511] != 0xAA) return false;

    var boot_sector: BootSector = undefined;
    @memcpy(std.mem.asBytes(&boot_sector), sector[0..@sizeOf(BootSector)]);
    if (boot_sector.bytes_per_sector != 512) return false;
    if (boot_sector.sectors_per_cluster == 0) return false;
    if (boot_sector.reserved_sectors == 0) return false;
    if (boot_sector.fat_count == 0) return false;
    if (boot_sector.sectors_per_fat_32 == 0) return false;
    if (boot_sector.root_cluster < 2) return false;

    return true;
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
    const match = findDirectoryEntry(mount_data, parent_data.cluster, name) catch |err| return switch (err) {
        error.NotFound => vfs.VFSError.NotFound,
        error.DeviceError => vfs.VFSError.DeviceError,
    };
    return createVNodeFromEntry(parent.mount_point.?, &match.entry, match.visible_name[0..match.visible_len]);
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
        @memcpy(sector_buf[offset_start .. offset_start + bytes_in_sector], buffer[bytes_written .. bytes_written + bytes_in_sector]);

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
    var sector_buf: [512]u8 align(4) = undefined;
    var lfn_state = LfnState{};

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
                if (entry.name[0] == 0xE5) {
                    resetLfnState(&lfn_state);
                    continue;
                }
                if (entry.attributes == ATTR_LONG_NAME) {
                    consumeLfnEntry(&lfn_state, &entry);
                    continue;
                }
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) {
                    resetLfnState(&lfn_state);
                    continue;
                }

                if (entry_count == index) {
                    const visible = finishVisibleName(&lfn_state, &entry, &dirent.name);
                    dirent.name_len = visible.len;
                    const cluster_high_val: u64 = entry.cluster_high;
                    const cluster_low_val: u64 = entry.cluster_low;
                    dirent.inode = (cluster_high_val << 16) | cluster_low_val;
                    dirent.file_type = if ((entry.attributes & ATTR_DIRECTORY) != 0)
                        vfs.FileType.Directory
                    else if (isSymlinkEntry(&entry))
                        vfs.FileType.SymLink
                    else
                        vfs.FileType.Regular;
                    return true;
                }

                resetLfnState(&lfn_state);
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
    var sequence: [MAX_LFN_ENTRIES + 1]DirEntry = undefined;
    const entries = buildNamedEntrySequence(mount_data, parent_data.cluster, name, new_entry, &sequence) catch return vfs.VFSError.InvalidOperation;
    appendDirectoryEntries(mount_data, parent_data.cluster, entries) catch |err| return switch (err) {
        error.NoSpace => vfs.VFSError.NoSpace,
        else => vfs.VFSError.DeviceError,
    };
    new_entry = entries[entries.len - 1];
    return createVNodeFromEntry(parent.mount_point.?, &new_entry, name);
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
    var sequence: [MAX_LFN_ENTRIES + 1]DirEntry = undefined;
    const entries = buildNamedEntrySequence(mount_data, parent_data.cluster, name, new_entry, &sequence) catch {
        freeClusterChain(mount_data, new_cluster) catch {};
        return vfs.VFSError.InvalidOperation;
    };
    appendDirectoryEntries(mount_data, parent_data.cluster, entries) catch |err| {
        freeClusterChain(mount_data, new_cluster) catch {};
        return switch (err) {
            error.NoSpace => vfs.VFSError.NoSpace,
            else => vfs.VFSError.DeviceError,
        };
    };

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
    new_entry = entries[entries.len - 1];
    return createVNodeFromEntry(parent.mount_point.?, &new_entry, name);
}

fn fat32Unlink(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    const parent_data: *FAT32VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));
    const match = findDirectoryEntry(mount_data, parent_data.cluster, name) catch |err| return switch (err) {
        error.NotFound => vfs.VFSError.NotFound,
        else => vfs.VFSError.DeviceError,
    };
    if ((match.entry.attributes & ATTR_DIRECTORY) != 0) {
        return vfs.VFSError.IsDirectory;
    }

    const file_cluster = entryCluster(&match.entry);
    deleteDirectoryEntries(mount_data, parent_data.cluster, match.primary_ordinal - match.lfn_count, @as(u32, match.lfn_count) + 1) catch {
        return vfs.VFSError.DeviceError;
    };

    if ((countLinksForCluster(mount_data, file_cluster) catch return vfs.VFSError.DeviceError) == 0) {
        freeClusterChain(mount_data, file_cluster) catch return vfs.VFSError.DeviceError;
    }
}

fn fat32Rmdir(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    const parent_data: *FAT32VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));
    const match = findDirectoryEntry(mount_data, parent_data.cluster, name) catch |err| return switch (err) {
        error.NotFound => vfs.VFSError.NotFound,
        else => vfs.VFSError.DeviceError,
    };
    if ((match.entry.attributes & ATTR_DIRECTORY) == 0) {
        return vfs.VFSError.NotDirectory;
    }

    const dir_cluster = entryCluster(&match.entry);
    if (!(isDirectoryEmpty(mount_data, dir_cluster) catch return vfs.VFSError.DeviceError)) {
        return vfs.VFSError.InvalidOperation;
    }

    freeClusterChain(mount_data, dir_cluster) catch return vfs.VFSError.DeviceError;
    deleteDirectoryEntries(mount_data, parent_data.cluster, match.primary_ordinal - match.lfn_count, @as(u32, match.lfn_count) + 1) catch {
        return vfs.VFSError.DeviceError;
    };
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
    const match = findDirectoryEntry(mount_data, old_parent_data.cluster, old_name) catch |err| return switch (err) {
        error.NotFound => vfs.VFSError.NotFound,
        else => vfs.VFSError.DeviceError,
    };

    var new_entry = match.entry;
    var sequence: [MAX_LFN_ENTRIES + 1]DirEntry = undefined;
    const entries = buildNamedEntrySequence(mount_data, new_parent_data.cluster, new_name, new_entry, &sequence) catch return vfs.VFSError.InvalidOperation;
    appendDirectoryEntries(mount_data, new_parent_data.cluster, entries) catch |err| return switch (err) {
        error.NoSpace => vfs.VFSError.NoSpace,
        else => vfs.VFSError.DeviceError,
    };
    new_entry = entries[entries.len - 1];

    if ((new_entry.attributes & ATTR_DIRECTORY) != 0 and old_parent_data.cluster != new_parent_data.cluster) {
        const dir_cluster = entryCluster(&new_entry);
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

    deleteDirectoryEntries(mount_data, old_parent_data.cluster, match.primary_ordinal - match.lfn_count, @as(u32, match.lfn_count) + 1) catch {
        return vfs.VFSError.DeviceError;
    };
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
        .attributes = ATTR_ZIGOS_SYMLINK,
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
    var sequence: [MAX_LFN_ENTRIES + 1]DirEntry = undefined;
    const entries = buildNamedEntrySequence(mount_data, parent_data.cluster, name, new_entry, &sequence) catch |err| {
        freeClusterChain(mount_data, new_cluster) catch {};
        return switch (err) {
            error.InvalidOperation => vfs.VFSError.InvalidOperation,
            else => vfs.VFSError.DeviceError,
        };
    };
    appendDirectoryEntries(mount_data, parent_data.cluster, entries) catch |err| {
        freeClusterChain(mount_data, new_cluster) catch {};
        return switch (err) {
            error.NoSpace => vfs.VFSError.NoSpace,
            else => vfs.VFSError.DeviceError,
        };
    };

    new_entry = entries[entries.len - 1];
    const vnode = try createVNodeFromEntry(parent.mount_point.?, &new_entry, name);
    errdefer fat32Unlink(parent, name) catch {};

    _ = try fat32Write(vnode, target, 0);
    vnode.file_type = .SymLink;
    return vnode;
}

fn fat32Link(parent: *vfs.VNode, name: []const u8, target: *vfs.VNode) vfs.VFSError!void {
    const parent_data: *FAT32VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    if (!parent_data.is_directory) {
        return vfs.VFSError.NotDirectory;
    }
    if (target.mount_point != parent.mount_point) {
        return vfs.VFSError.InvalidOperation;
    }
    if (target.file_type == .Directory) {
        return vfs.VFSError.IsDirectory;
    }

    const mount_data: *FAT32Data = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));
    if (fat32Lookup(parent, name)) |_| {
        return vfs.VFSError.AlreadyExists;
    } else |_| {}

    const target_data: *FAT32VNodeData = @ptrCast(@alignCast(target.private_data.?));
    const cluster_high: u16 = @intCast((target_data.cluster >> 16) & 0xFFFF);
    const cluster_low: u16 = @intCast(target_data.cluster & 0xFFFF);
    const new_entry = DirEntry{
        .name = [_]u8{' '} ** 8,
        .ext = [_]u8{' '} ** 3,
        .attributes = if (target.file_type == .SymLink)
            ATTR_ZIGOS_SYMLINK
        else if (target.mode.owner_write)
            ATTR_ARCHIVE
        else
            ATTR_READ_ONLY,
        .reserved = 0,
        .create_time_tenth = 0,
        .create_time = 0,
        .create_date = 0,
        .access_date = 0,
        .cluster_high = cluster_high,
        .modify_time = 0,
        .modify_date = 0,
        .cluster_low = cluster_low,
        .size = target_data.size,
    };
    var sequence: [MAX_LFN_ENTRIES + 1]DirEntry = undefined;
    const entries = buildNamedEntrySequence(mount_data, parent_data.cluster, name, new_entry, &sequence) catch return vfs.VFSError.InvalidOperation;
    appendDirectoryEntries(mount_data, parent_data.cluster, entries) catch |err| return switch (err) {
        error.NoSpace => vfs.VFSError.NoSpace,
        else => vfs.VFSError.DeviceError,
    };
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
    const is_symlink = isSymlinkEntry(entry);
    const executable = !vnode_data.is_directory and !is_symlink;

    const name_len_val: u16 = @intCast(strlen(name));
    vnode.* = vfs.VNode{
        .name = [_]u8{0} ** 256,
        .name_len = name_len_val,
        .inode = vnode_data.cluster,
        .file_type = if (vnode_data.is_directory)
            vfs.FileType.Directory
        else if (is_symlink)
            vfs.FileType.SymLink
        else
            vfs.FileType.Regular,
        .mode = vfs.FileMode{
            .owner_read = true,
            .owner_write = (entry.attributes & ATTR_READ_ONLY) == 0,
            .owner_exec = executable,
            .group_read = true,
            .group_write = (entry.attributes & ATTR_READ_ONLY) == 0,
            .group_exec = executable,
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

    const fs_info: *FSInfo = @ptrCast(&fs_info_buf);
    fs_info.free_clusters = data.fs_info.free_clusters;
    fs_info.next_free_cluster = data.fs_info.next_free_cluster;

    ata.writeSectors(data.device, data.boot_sector.fs_info_sector, 1, &fs_info_buf) catch return error.DeviceError;
}

fn updateDirectoryEntry(data: *FAT32Data, file_cluster: u32, new_size: u32) !void {
    if (file_cluster == 0 or file_cluster >= FAT32_EOC) return;
    try updateDirectoryEntriesInDirectory(data, data.root_dir_cluster, file_cluster, new_size);
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

fn isSymlinkEntry(entry: *const DirEntry) bool {
    return (entry.attributes & ATTR_DIRECTORY) == 0 and entry.attributes == ATTR_ZIGOS_SYMLINK;
}

fn entryCluster(entry: *const DirEntry) u32 {
    const hi: u32 = entry.cluster_high;
    return (hi << 16) | entry.cluster_low;
}

fn isDotDirectoryEntry(entry: *const DirEntry) bool {
    return (entry.attributes & ATTR_DIRECTORY) != 0 and
        entry.name[0] == '.' and
        (entry.name[1] == ' ' or entry.name[1] == '.');
}

fn asciiLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

fn asciiNamesEqualIgnoreCase(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |l, r| {
        if (asciiLower(l) != asciiLower(r)) return false;
    }
    return true;
}

fn appendCanonicalOrderedCodepoint(out: []u21, classes: []u8, len: *usize, segment_start: *usize, codepoint: u21) error{NameTooLong}!void {
    if (len.* >= out.len or len.* >= classes.len) return error.NameTooLong;

    const combining_class = unicode_normalize.canonicalCombiningClass(codepoint);
    out[len.*] = codepoint;
    classes[len.*] = combining_class;

    if (combining_class == 0) {
        segment_start.* = len.*;
        len.* += 1;
        return;
    }

    var index = len.*;
    while (index > 0 and classes[index - 1] > combining_class) : (index -= 1) {
        const prev_codepoint = out[index - 1];
        const prev_class = classes[index - 1];
        out[index - 1] = out[index];
        classes[index - 1] = classes[index];
        out[index] = prev_codepoint;
        classes[index] = prev_class;
    }

    len.* += 1;
}

fn appendFullyDecomposedCodepoint(out: []u21, classes: []u8, len: *usize, segment_start: *usize, codepoint: u21) error{NameTooLong}!void {
    var decomposition: [3]u21 = undefined;
    const decomposition_len = unicode_normalize.canonicalDecompose(codepoint, &decomposition);
    if (decomposition_len == 1 and decomposition[0] == codepoint) {
        try appendCanonicalOrderedCodepoint(out, classes, len, segment_start, codepoint);
        return;
    }

    for (decomposition[0..decomposition_len]) |part| {
        try appendFullyDecomposedCodepoint(out, classes, len, segment_start, part);
    }
}

fn appendCasefoldedCodepoint(out: []u21, classes: []u8, len: *usize, segment_start: *usize, codepoint: u21) error{NameTooLong}!void {
    var decomposition: [3]u21 = undefined;
    const decomposition_len = unicode_normalize.canonicalDecompose(codepoint, &decomposition);
    if (decomposition_len == 1 and decomposition[0] == codepoint) {
        var folded: [3]u21 = undefined;
        const folded_len = unicode_casefold.foldCodepoint(codepoint, &folded);
        for (folded[0..folded_len]) |folded_codepoint| {
            try appendFullyDecomposedCodepoint(out, classes, len, segment_start, folded_codepoint);
        }
        return;
    }

    for (decomposition[0..decomposition_len]) |part| {
        try appendCasefoldedCodepoint(out, classes, len, segment_start, part);
    }
}

fn normalizeNameForCompare(name: []const u8, out: []u21, classes: []u8) error{ InvalidUtf8, NameTooLong }!usize {
    var src_index: usize = 0;
    var out_len: usize = 0;
    var segment_start: usize = 0;

    while (src_index < name.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(name[src_index]) catch return error.InvalidUtf8;
        const seq_len_usize: usize = seq_len;
        if (src_index + seq_len_usize > name.len) return error.InvalidUtf8;

        const codepoint = std.unicode.utf8Decode(name[src_index .. src_index + seq_len_usize]) catch return error.InvalidUtf8;
        src_index += seq_len_usize;
        try appendCasefoldedCodepoint(out, classes, &out_len, &segment_start, codepoint);
    }

    return out_len;
}

fn namesEqualIgnoreCase(left: []const u8, right: []const u8) bool {
    var left_normalized: [MAX_COMPARE_CODEPOINTS]u21 = undefined;
    var right_normalized: [MAX_COMPARE_CODEPOINTS]u21 = undefined;
    var left_classes: [MAX_COMPARE_CODEPOINTS]u8 = undefined;
    var right_classes: [MAX_COMPARE_CODEPOINTS]u8 = undefined;

    const left_len = normalizeNameForCompare(left, &left_normalized, &left_classes) catch return asciiNamesEqualIgnoreCase(left, right);
    const right_len = normalizeNameForCompare(right, &right_normalized, &right_classes) catch return asciiNamesEqualIgnoreCase(left, right);
    return std.mem.eql(u21, left_normalized[0..left_len], right_normalized[0..right_len]);
}

fn resetLfnState(state: *LfnState) void {
    state.* = .{};
}

fn shortNameChecksum(name: [8]u8, ext: [3]u8) u8 {
    var checksum: u8 = 0;
    for (name) |byte| {
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) +% byte;
    }
    for (ext) |byte| {
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) +% byte;
    }
    return checksum;
}

fn decodeLfnChunk(state: *LfnState, offset: usize, chars: anytype) void {
    var idx: usize = 0;
    while (idx < chars.len and offset + idx < state.code_units.len) : (idx += 1) {
        const code_unit = std.mem.littleToNative(u16, chars[idx]);
        if (code_unit == 0x0000) {
            state.code_unit_len = @min(state.code_unit_len, offset + idx);
            break;
        }
        if (code_unit == 0xFFFF) break;
        state.code_units[offset + idx] = code_unit;
        if (offset + idx + 1 > state.code_unit_len) {
            state.code_unit_len = offset + idx + 1;
        }
    }
}

fn consumeLfnEntry(state: *LfnState, entry: *const DirEntry) void {
    const lfn: LfnEntry = @bitCast(entry.*);
    const order = lfn.order;
    const sequence = order & 0x1F;
    const is_last = (order & LFN_LAST_ENTRY) != 0;

    if (sequence == 0 or sequence > MAX_LFN_ENTRIES) {
        resetLfnState(state);
        return;
    }

    if (is_last) {
        resetLfnState(state);
        state.active = true;
        state.total_entries = sequence;
        state.checksum = lfn.checksum;
        state.code_unit_len = @as(usize, sequence) * LFN_CHARS_PER_ENTRY;
    } else if (!state.active or lfn.checksum != state.checksum or sequence > state.total_entries) {
        resetLfnState(state);
        return;
    }

    const bit: u32 = @as(u32, 1) << @intCast(sequence - 1);
    state.seen_mask |= bit;

    const chunk_offset = (@as(usize, sequence) - 1) * LFN_CHARS_PER_ENTRY;
    decodeLfnChunk(state, chunk_offset, &lfn.name1);
    decodeLfnChunk(state, chunk_offset + 5, &lfn.name2);
    decodeLfnChunk(state, chunk_offset + 11, &lfn.name3);
}

fn completeLfnMask(total_entries: u8) u32 {
    return if (total_entries >= 32) 0xFFFF_FFFF else (@as(u32, 1) << @intCast(total_entries)) - 1;
}

fn utf16NameToUtf8(code_units: []const u16, out: []u8) error{ InvalidUtf16, NameTooLong }!usize {
    var it = std.unicode.Utf16LeIterator.init(code_units);
    var out_len: usize = 0;

    while (true) {
        const maybe_codepoint = it.nextCodepoint() catch return error.InvalidUtf16;
        const codepoint = maybe_codepoint orelse break;
        const utf8_len = std.unicode.utf8CodepointSequenceLength(codepoint) catch unreachable;
        if (out_len + utf8_len > out.len) return error.NameTooLong;
        out_len += std.unicode.utf8Encode(codepoint, out[out_len..]) catch unreachable;
    }

    return out_len;
}

fn utf8NameToUtf16Units(name: []const u8, storage: *[MAX_LFN_CODE_UNITS]u16) error{InvalidOperation}![]const u16 {
    if (name.len == 0 or name.len > MAX_VISIBLE_NAME_BYTES) return error.InvalidOperation;

    const utf16_len = std.unicode.calcUtf16LeLen(name) catch return error.InvalidOperation;
    if (utf16_len == 0 or utf16_len > MAX_LFN_NAME_CODE_UNITS) return error.InvalidOperation;

    _ = std.unicode.utf8ToUtf16Le(storage[0..utf16_len], name) catch return error.InvalidOperation;
    return storage[0..utf16_len];
}

fn finishVisibleName(state: *LfnState, entry: *const DirEntry, out: *[256]u8) struct { len: u16, lfn_count: u8 } {
    const checksum_matches = state.active and state.checksum == shortNameChecksum(entry.name, entry.ext);
    const lfn_complete = checksum_matches and state.seen_mask == completeLfnMask(state.total_entries);
    if (lfn_complete and state.code_unit_len > 0 and state.code_unit_len <= MAX_LFN_NAME_CODE_UNITS) {
        if (utf16NameToUtf8(state.code_units[0..state.code_unit_len], out[0 .. out.len - 1])) |visible_len| {
            out[visible_len] = 0;
            const visible_len_u16: u16 = @intCast(visible_len);
            const lfn_count = state.total_entries;
            resetLfnState(state);
            return .{ .len = visible_len_u16, .lfn_count = lfn_count };
        } else |_| {}

        const lfn_count = state.total_entries;
        resetLfnState(state);
        formatDosName(&entry.name, &entry.ext, out);
        return .{ .len = @intCast(strlen(out)), .lfn_count = lfn_count };
    }

    formatDosName(&entry.name, &entry.ext, out);
    const visible_len: u16 = @intCast(strlen(out));
    resetLfnState(state);
    return .{ .len = visible_len, .lfn_count = 0 };
}

fn splitName(name: []const u8) struct { base: []const u8, ext: []const u8 } {
    var dot_pos: ?usize = null;
    for (name, 0..) |char, index| {
        if (char == '.' and index != 0 and index + 1 < name.len) {
            dot_pos = index;
        }
    }

    if (dot_pos) |dot| {
        return .{ .base = name[0..dot], .ext = name[dot + 1 ..] };
    }

    return .{ .base = name, .ext = "" };
}

fn sanitizeShortChar(char: u8) u8 {
    const upper = toUpper(char);
    if ((upper >= 'A' and upper <= 'Z') or (upper >= '0' and upper <= '9')) {
        return upper;
    }
    return '_';
}

fn requiresLongName(name: []const u8, short_name: [8]u8, short_ext: [3]u8) bool {
    var visible_name: [13]u8 = undefined;
    formatDosName(&short_name, &short_ext, &visible_name);
    return !std.mem.eql(u8, visible_name[0..strlen(&visible_name)], name);
}

fn shortNameExists(data: *FAT32Data, parent_cluster: u32, short_name: [8]u8, short_ext: [3]u8) !bool {
    var cluster = parent_cluster;
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(data, cluster);
        for (0..data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(data.device, first_sector + sector_offset, 1, &sector_buf) catch return error.DeviceError;

            const entries_ptr: [*]const DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries) |entry| {
                if (entry.name[0] == 0x00) return false;
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;
                if (std.mem.eql(u8, entry.name[0..], short_name[0..]) and std.mem.eql(u8, entry.ext[0..], short_ext[0..])) {
                    return true;
                }
            }
        }
        cluster = getNextCluster(data, cluster) catch return error.DeviceError;
    }

    return false;
}

fn makeShortName(data: *FAT32Data, parent_cluster: u32, name: []const u8, out_name: *[8]u8, out_ext: *[3]u8) !void {
    formatNameTo83(name, out_name, out_ext);
    if (!requiresLongName(name, out_name.*, out_ext.*) and !(try shortNameExists(data, parent_cluster, out_name.*, out_ext.*))) {
        return;
    }

    const parts = splitName(name);
    var clean_base: [64]u8 = undefined;
    var clean_ext: [3]u8 = [_]u8{' '} ** 3;
    var clean_base_len: usize = 0;
    for (parts.base) |char| {
        if (clean_base_len >= clean_base.len) break;
        clean_base[clean_base_len] = sanitizeShortChar(char);
        clean_base_len += 1;
    }
    if (clean_base_len == 0) {
        clean_base[0] = '_';
        clean_base_len = 1;
    }

    const ext_len = @min(parts.ext.len, clean_ext.len);
    for (0..ext_len) |index| {
        clean_ext[index] = sanitizeShortChar(parts.ext[index]);
    }

    var counter: usize = 1;
    while (counter < 1_000_000) : (counter += 1) {
        out_name.* = [_]u8{' '} ** 8;
        out_ext.* = [_]u8{' '} ** 3;

        var counter_buf: [8]u8 = undefined;
        const counter_text = std.fmt.bufPrint(&counter_buf, "{d}", .{counter}) catch return error.InvalidOperation;
        const suffix_len = counter_text.len + 1;
        const prefix_len = @max(@as(usize, 1), @as(usize, 8) - suffix_len);
        const actual_prefix_len = @min(clean_base_len, prefix_len);
        @memcpy(out_name[0..actual_prefix_len], clean_base[0..actual_prefix_len]);
        out_name[actual_prefix_len] = '~';
        @memcpy(out_name[actual_prefix_len + 1 .. actual_prefix_len + 1 + counter_text.len], counter_text);
        @memcpy(out_ext[0..ext_len], clean_ext[0..ext_len]);

        if (!(try shortNameExists(data, parent_cluster, out_name.*, out_ext.*))) {
            return;
        }
    }

    return error.NoSpace;
}

fn buildLfnDirEntry(name_code_units: []const u16, sequence: u8, total_entries: u8, checksum: u8) DirEntry {
    var units = [_]u16{0xFFFF} ** LFN_CHARS_PER_ENTRY;
    const start = (@as(usize, sequence) - 1) * LFN_CHARS_PER_ENTRY;
    const end = @min(name_code_units.len, start + LFN_CHARS_PER_ENTRY);
    const chunk = name_code_units[start..end];
    for (chunk, 0..) |code_unit, index| {
        units[index] = std.mem.nativeToLittle(u16, code_unit);
    }
    if (sequence == total_entries and chunk.len < LFN_CHARS_PER_ENTRY) {
        units[chunk.len] = 0x0000;
    }

    const lfn = LfnEntry{
        .order = sequence | if (sequence == total_entries) LFN_LAST_ENTRY else 0,
        .name1 = .{ units[0], units[1], units[2], units[3], units[4] },
        .attributes = ATTR_LONG_NAME,
        .entry_type = 0,
        .checksum = checksum,
        .name2 = .{ units[5], units[6], units[7], units[8], units[9], units[10] },
        .first_cluster_low = 0,
        .name3 = .{ units[11], units[12] },
    };
    return @bitCast(lfn);
}

fn buildNamedEntrySequence(data: *FAT32Data, parent_cluster: u32, name: []const u8, primary_template: DirEntry, storage: *[MAX_LFN_ENTRIES + 1]DirEntry) ![]const DirEntry {
    var short_name: [8]u8 = undefined;
    var short_ext: [3]u8 = undefined;
    try makeShortName(data, parent_cluster, name, &short_name, &short_ext);

    var primary = primary_template;
    primary.name = short_name;
    primary.ext = short_ext;

    if (!requiresLongName(name, short_name, short_ext)) {
        storage[0] = primary;
        return storage[0..1];
    }

    var long_name_units_storage: [MAX_LFN_CODE_UNITS]u16 = undefined;
    const long_name_units = try utf8NameToUtf16Units(name, &long_name_units_storage);
    const total_entries = std.math.divCeil(usize, long_name_units.len, LFN_CHARS_PER_ENTRY) catch unreachable;
    if (total_entries == 0 or total_entries > MAX_LFN_ENTRIES) return error.InvalidOperation;
    const checksum = shortNameChecksum(short_name, short_ext);

    var write_index: usize = 0;
    var sequence = total_entries;
    while (sequence > 0) : (sequence -= 1) {
        storage[write_index] = buildLfnDirEntry(long_name_units, @intCast(sequence), @intCast(total_entries), checksum);
        write_index += 1;
    }
    storage[write_index] = primary;
    return storage[0 .. write_index + 1];
}

const EntryLocation = struct {
    sector_lba: u32,
    entry_index: usize,
};

fn locateDirectoryEntry(data: *FAT32Data, dir_cluster: u32, ordinal: u32) !EntryLocation {
    const entries_per_cluster: u32 = data.sectors_per_cluster * 16;
    var cluster = dir_cluster;
    var remaining = ordinal;

    while (remaining >= entries_per_cluster) {
        cluster = getNextCluster(data, cluster) catch return error.DeviceError;
        if (cluster >= FAT32_EOC) return error.NotFound;
        remaining -= entries_per_cluster;
    }

    const sector_offset = remaining / 16;
    return .{
        .sector_lba = clusterToLBA(data, cluster) + sector_offset,
        .entry_index = @intCast(remaining % 16),
    };
}

fn writeDirectoryEntryAt(data: *FAT32Data, dir_cluster: u32, ordinal: u32, entry: DirEntry) !void {
    const location = try locateDirectoryEntry(data, dir_cluster, ordinal);
    var sector_buf: [512]u8 align(4) = undefined;
    ata.readSectors(data.device, location.sector_lba, 1, &sector_buf) catch return error.DeviceError;

    const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
    entries_ptr[location.entry_index] = entry;
    ata.writeSectors(data.device, location.sector_lba, 1, &sector_buf) catch return error.DeviceError;
}

fn findEndOfDirectoryOrdinal(data: *FAT32Data, dir_cluster: u32) !u32 {
    var cluster = dir_cluster;
    var ordinal: u32 = 0;
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(data, cluster);
        for (0..data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(data.device, first_sector + sector_offset, 1, &sector_buf) catch return error.DeviceError;
            const entries_ptr: [*]const DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries) |entry| {
                if (entry.name[0] == 0x00) return ordinal;
                ordinal += 1;
            }
        }
        cluster = getNextCluster(data, cluster) catch return error.DeviceError;
    }

    return ordinal;
}

fn ensureDirectoryCapacity(data: *FAT32Data, dir_cluster: u32, max_ordinal: u32) !void {
    const entries_per_cluster: u32 = data.sectors_per_cluster * 16;
    const required_clusters = (max_ordinal / entries_per_cluster) + 1;

    var cluster = dir_cluster;
    var current_clusters: u32 = 1;
    while (true) {
        const next = getNextCluster(data, cluster) catch return error.DeviceError;
        if (next >= FAT32_EOC) break;
        cluster = next;
        current_clusters += 1;
    }

    while (current_clusters < required_clusters) : (current_clusters += 1) {
        const new_cluster = allocateCluster(data) catch return error.NoSpace;
        setNextCluster(data, cluster, new_cluster) catch return error.DeviceError;
        cluster = new_cluster;
    }
}

fn appendDirectoryEntries(data: *FAT32Data, dir_cluster: u32, entries: []const DirEntry) !void {
    const start = try findEndOfDirectoryOrdinal(data, dir_cluster);
    const terminator_ordinal = start + @as(u32, @intCast(entries.len));
    try ensureDirectoryCapacity(data, dir_cluster, terminator_ordinal);

    for (entries, 0..) |entry, index| {
        try writeDirectoryEntryAt(data, dir_cluster, start + @as(u32, @intCast(index)), entry);
    }
    try writeDirectoryEntryAt(data, dir_cluster, terminator_ordinal, std.mem.zeroes(DirEntry));
}

fn deleteDirectoryEntries(data: *FAT32Data, dir_cluster: u32, start_ordinal: u32, count: u32) !void {
    var ordinal = start_ordinal;
    const end = start_ordinal + count;
    while (ordinal < end) : (ordinal += 1) {
        const location = try locateDirectoryEntry(data, dir_cluster, ordinal);
        var sector_buf: [512]u8 align(4) = undefined;
        ata.readSectors(data.device, location.sector_lba, 1, &sector_buf) catch return error.DeviceError;
        const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
        entries_ptr[location.entry_index].name[0] = 0xE5;
        ata.writeSectors(data.device, location.sector_lba, 1, &sector_buf) catch return error.DeviceError;
    }
}

fn findDirectoryEntry(data: *FAT32Data, dir_cluster: u32, target_name: []const u8) !DirMatch {
    var cluster = dir_cluster;
    var sector_buf: [512]u8 align(4) = undefined;
    var lfn_state = LfnState{};
    var ordinal: u32 = 0;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(data, cluster);
        for (0..data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(data.device, first_sector + sector_offset, 1, &sector_buf) catch return error.DeviceError;

            const entries_ptr: [*]const DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries) |entry| {
                defer ordinal += 1;

                if (entry.name[0] == 0x00) return error.NotFound;
                if (entry.name[0] == 0xE5) {
                    resetLfnState(&lfn_state);
                    continue;
                }
                if (entry.attributes == ATTR_LONG_NAME) {
                    consumeLfnEntry(&lfn_state, &entry);
                    continue;
                }
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) {
                    resetLfnState(&lfn_state);
                    continue;
                }

                var visible_name: [256]u8 = undefined;
                const visible = finishVisibleName(&lfn_state, &entry, &visible_name);
                const visible_slice = visible_name[0..visible.len];
                if (namesEqualIgnoreCase(visible_slice, target_name)) {
                    return .{
                        .entry = entry,
                        .visible_name = visible_name,
                        .visible_len = visible.len,
                        .primary_ordinal = ordinal,
                        .lfn_count = visible.lfn_count,
                    };
                }
            }
        }
        cluster = getNextCluster(data, cluster) catch return error.DeviceError;
    }

    return error.NotFound;
}

fn insertDirectoryEntry(data: *FAT32Data, parent_cluster: u32, new_entry: DirEntry) !void {
    var cluster = parent_cluster;
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(data, cluster);

        for (0..data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return error.DeviceError;
            };

            const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries, 0..) |*entry, i| {
                if (entry.name[0] == 0x00 or entry.name[0] == 0xE5) {
                    entries[i] = new_entry;
                    ata.writeSectors(data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                        return error.DeviceError;
                    };
                    return;
                }
            }
        }

        const next = getNextCluster(data, cluster) catch return error.DeviceError;
        if (next >= FAT32_EOC) {
            const new_dir_cluster = allocateCluster(data) catch return error.NoSpace;
            setNextCluster(data, cluster, new_dir_cluster) catch return error.DeviceError;
            cluster = new_dir_cluster;
        } else {
            cluster = next;
        }
    }

    return error.NoSpace;
}

fn countLinksForCluster(data: *FAT32Data, target_cluster: u32) !u32 {
    if (target_cluster == 0 or target_cluster >= FAT32_EOC) return 0;
    return countLinksInDirectory(data, data.root_dir_cluster, target_cluster);
}

fn countLinksInDirectory(data: *FAT32Data, dir_cluster: u32, target_cluster: u32) !u32 {
    var total: u32 = 0;
    var cluster = dir_cluster;
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(data, cluster);

        for (0..data.sectors_per_cluster) |sector_offset| {
            ata.readSectors(data.device, first_sector + sector_offset, 1, &sector_buf) catch {
                return error.DeviceError;
            };

            const entries_ptr: [*]const DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            for (entries) |entry| {
                if (entry.name[0] == 0x00) return total;
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                if ((entry.attributes & ATTR_DIRECTORY) == 0 and entryCluster(&entry) == target_cluster) {
                    total += 1;
                }

                if ((entry.attributes & ATTR_DIRECTORY) != 0 and !isDotDirectoryEntry(&entry)) {
                    total += try countLinksInDirectory(data, entryCluster(&entry), target_cluster);
                }
            }
        }

        cluster = getNextCluster(data, cluster) catch return error.DeviceError;
    }

    return total;
}

fn updateDirectoryEntriesInDirectory(data: *FAT32Data, dir_cluster: u32, file_cluster: u32, new_size: u32) !void {
    var cluster = dir_cluster;
    var sector_buf: [512]u8 align(4) = undefined;

    while (cluster < FAT32_EOC) {
        const first_sector = clusterToLBA(data, cluster);

        for (0..data.sectors_per_cluster) |sector_offset| {
            const sector_lba = first_sector + sector_offset;
            ata.readSectors(data.device, sector_lba, 1, &sector_buf) catch {
                return error.DeviceError;
            };

            const entries_ptr: [*]DirEntry = @ptrCast(&sector_buf);
            const entries = entries_ptr[0..16];
            var dirty = false;
            var stop = false;

            for (entries, 0..) |*entry, i| {
                if (entry.name[0] == 0x00) {
                    stop = true;
                    break;
                }
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;

                if ((entry.attributes & ATTR_DIRECTORY) == 0 and entryCluster(entry) == file_cluster and entry.size != new_size) {
                    entries[i].size = new_size;
                    dirty = true;
                }
            }

            if (dirty) {
                ata.writeSectors(data.device, sector_lba, 1, &sector_buf) catch {
                    return error.DeviceError;
                };
            }

            for (entries) |entry| {
                if (entry.name[0] == 0x00) break;
                if (entry.name[0] == 0xE5) continue;
                if (entry.attributes == ATTR_LONG_NAME) continue;
                if ((entry.attributes & ATTR_VOLUME_ID) != 0) continue;
                if ((entry.attributes & ATTR_DIRECTORY) != 0 and !isDotDirectoryEntry(&entry)) {
                    try updateDirectoryEntriesInDirectory(data, entryCluster(&entry), file_cluster, new_size);
                }
            }

            if (stop) return;
        }

        cluster = getNextCluster(data, cluster) catch return error.DeviceError;
    }
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
