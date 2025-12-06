const std = @import("std");
const vfs = @import("vfs.zig");
const ata = @import("../drivers/ata.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");

const EXT2_SUPER_MAGIC = 0xEF53;
const EXT2_ROOT_INO = 2;
const EXT2_GOOD_OLD_REV = 0;
const EXT2_DYNAMIC_REV = 1;
const EXT2_GOOD_OLD_INODE_SIZE = 128;

const EXT2_S_IFSOCK = 0xC000;
const EXT2_S_IFLNK = 0xA000;
const EXT2_S_IFREG = 0x8000;
const EXT2_S_IFBLK = 0x6000;
const EXT2_S_IFDIR = 0x4000;
const EXT2_S_IFCHR = 0x2000;
const EXT2_S_IFIFO = 0x1000;

const EXT2_S_IRUSR = 0x0100;
const EXT2_S_IWUSR = 0x0080;
const EXT2_S_IXUSR = 0x0040;
const EXT2_S_IRGRP = 0x0020;
const EXT2_S_IWGRP = 0x0010;
const EXT2_S_IXGRP = 0x0008;
const EXT2_S_IROTH = 0x0004;
const EXT2_S_IWOTH = 0x0002;
const EXT2_S_IXOTH = 0x0001;

const EXT2_FT_UNKNOWN = 0;
const EXT2_FT_REG_FILE = 1;
const EXT2_FT_DIR = 2;
const EXT2_FT_CHRDEV = 3;
const EXT2_FT_BLKDEV = 4;
const EXT2_FT_FIFO = 5;
const EXT2_FT_SOCK = 6;
const EXT2_FT_SYMLINK = 7;

const Ext2Superblock = extern struct {
    s_inodes_count: u32,
    s_blocks_count: u32,
    s_r_blocks_count: u32,
    s_free_blocks_count: u32,
    s_free_inodes_count: u32,
    s_first_data_block: u32,
    s_log_block_size: u32,
    s_log_frag_size: u32,
    s_blocks_per_group: u32,
    s_frags_per_group: u32,
    s_inodes_per_group: u32,
    s_mtime: u32,
    s_wtime: u32,
    s_mnt_count: u16,
    s_max_mnt_count: u16,
    s_magic: u16,
    s_state: u16,
    s_errors: u16,
    s_minor_rev_level: u16,
    s_lastcheck: u32,
    s_checkinterval: u32,
    s_creator_os: u32,
    s_rev_level: u32,
    s_def_resuid: u16,
    s_def_resgid: u16,
    s_first_ino: u32,
    s_inode_size: u16,
    s_block_group_nr: u16,
    s_feature_compat: u32,
    s_feature_incompat: u32,
    s_feature_ro_compat: u32,
    s_uuid: [16]u8,
    s_volume_name: [16]u8,
    s_last_mounted: [64]u8,
    s_algo_bitmap: u32,
    s_prealloc_blocks: u8,
    s_prealloc_dir_blocks: u8,
    _padding: u16,
    s_journal_uuid: [16]u8,
    s_journal_inum: u32,
    s_journal_dev: u32,
    s_last_orphan: u32,
    s_hash_seed: [4]u32,
    s_def_hash_version: u8,
    _padding2: [3]u8,
    s_default_mount_options: u32,
    s_first_meta_bg: u32,
    _reserved: [760]u8,
};

const Ext2GroupDesc = extern struct {
    bg_block_bitmap: u32,
    bg_inode_bitmap: u32,
    bg_inode_table: u32,
    bg_free_blocks_count: u16,
    bg_free_inodes_count: u16,
    bg_used_dirs_count: u16,
    bg_pad: u16,
    bg_reserved: [12]u8,
};

const Ext2Inode = extern struct {
    i_mode: u16,
    i_uid: u16,
    i_size: u32,
    i_atime: u32,
    i_ctime: u32,
    i_mtime: u32,
    i_dtime: u32,
    i_gid: u16,
    i_links_count: u16,
    i_blocks: u32,
    i_flags: u32,
    i_osd1: u32,
    i_block: [15]u32,
    i_generation: u32,
    i_file_acl: u32,
    i_dir_acl: u32,
    i_faddr: u32,
    i_osd2: [12]u8,
};

const Ext2DirEntry = extern struct {
    inode: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
};

const Ext2FileSystem = struct {
    device: *const ata.ATADevice,
    superblock: Ext2Superblock,
    block_size: u32,
    groups_count: u32,
    group_descs: [*]Ext2GroupDesc,
    cache: BlockCache,

    const BlockCache = struct {
        blocks: [16]CacheEntry,

        const CacheEntry = struct {
            block_num: u32,
            data: [4096]u8,
            dirty: bool,
            valid: bool,
        };

        fn init() BlockCache {
            return BlockCache{
                .blocks = [_]CacheEntry{CacheEntry{
                    .block_num = 0,
                    .data = [_]u8{0} ** 4096,
                    .dirty = false,
                    .valid = false,
                }} ** 16,
            };
        }

        fn get(self: *BlockCache, fs: *Ext2FileSystem, block_num: u32) ![]u8 {
            for (&self.blocks) |*entry| {
                if (entry.valid and entry.block_num == block_num) {
                    return entry.data[0..fs.block_size];
                }
            }

            var lru_idx: usize = 0;
            for (&self.blocks, 0..) |*entry, i| {
                if (!entry.valid) {
                    lru_idx = i;
                    break;
                }
            }

            if (self.blocks[lru_idx].dirty) {
                try fs.writeBlock(self.blocks[lru_idx].block_num, &self.blocks[lru_idx].data);
            }

            try fs.readBlock(block_num, &self.blocks[lru_idx].data);
            self.blocks[lru_idx].block_num = block_num;
            self.blocks[lru_idx].valid = true;
            self.blocks[lru_idx].dirty = false;

            return self.blocks[lru_idx].data[0..fs.block_size];
        }

        fn markDirty(self: *BlockCache, block_num: u32) void {
            for (&self.blocks) |*entry| {
                if (entry.valid and entry.block_num == block_num) {
                    entry.dirty = true;
                    return;
                }
            }
        }

        fn flush(self: *BlockCache, fs: *Ext2FileSystem) !void {
            for (&self.blocks) |*entry| {
                if (entry.valid and entry.dirty) {
                    try fs.writeBlock(entry.block_num, &entry.data);
                    entry.dirty = false;
                }
            }
        }
    };

    fn readBlock(self: *Ext2FileSystem, block_num: u32, buffer: []u8) !void {
        const lba = block_num * (self.block_size / 512);
        const sectors = @as(u8, @intCast(self.block_size / 512));

        ata.readSectors(self.device, lba, sectors, buffer) catch {
            return vfs.VFSError.DeviceError;
        };
    }

    fn writeBlock(self: *Ext2FileSystem, block_num: u32, buffer: []const u8) !void {
        const lba = block_num * (self.block_size / 512);
        const sectors = @as(u8, @intCast(self.block_size / 512));

        ata.writeSectors(self.device, lba, sectors, buffer) catch {
            return vfs.VFSError.DeviceError;
        };
    }

    fn readInode(self: *Ext2FileSystem, inode_num: u32) !Ext2Inode {
        const group = (inode_num - 1) / self.superblock.s_inodes_per_group;
        const index = (inode_num - 1) % self.superblock.s_inodes_per_group;

        const inode_size = if (self.superblock.s_rev_level == EXT2_GOOD_OLD_REV)
            EXT2_GOOD_OLD_INODE_SIZE
        else
            self.superblock.s_inode_size;

        const block_num = self.group_descs[group].bg_inode_table +
                         (index * inode_size) / self.block_size;
        const offset = (index * inode_size) % self.block_size;

        const block = try self.cache.get(self, block_num);
        return @as(*const Ext2Inode, @ptrCast(@alignCast(&block[offset]))).*;
    }

    fn writeInode(self: *Ext2FileSystem, inode_num: u32, inode: *const Ext2Inode) !void {
        const group = (inode_num - 1) / self.superblock.s_inodes_per_group;
        const index = (inode_num - 1) % self.superblock.s_inodes_per_group;

        const inode_size = if (self.superblock.s_rev_level == EXT2_GOOD_OLD_REV)
            EXT2_GOOD_OLD_INODE_SIZE
        else
            self.superblock.s_inode_size;

        const block_num = self.group_descs[group].bg_inode_table +
                         (index * inode_size) / self.block_size;
        const offset = (index * inode_size) % self.block_size;

        const block = try self.cache.get(self, block_num);
        @memcpy(block[offset..offset + @sizeOf(Ext2Inode)], std.mem.asBytes(inode));
        self.cache.markDirty(block_num);
    }

    fn readDataBlock(self: *Ext2FileSystem, inode: *const Ext2Inode, block_index: u32) ![]u8 {
        const block_num = try self.getBlockNumber(inode, block_index);
        if (block_num == 0) {
            return &[_]u8{};
        }
        return try self.cache.get(self, block_num);
    }

    fn getBlockNumber(self: *Ext2FileSystem, inode: *const Ext2Inode, block_index: u32) !u32 {
        const direct_blocks = 12;
        const indirect_per_block = self.block_size / 4;
        const double_indirect_per_block = indirect_per_block * indirect_per_block;

        if (block_index < direct_blocks) {
            return inode.i_block[block_index];
        }

        var index = block_index - direct_blocks;

        if (index < indirect_per_block) {
            if (inode.i_block[12] == 0) return 0;
            const indirect_block = try self.cache.get(self, inode.i_block[12]);
            const block_nums = @as([*]const u32, @ptrCast(@alignCast(indirect_block.ptr)));
            return block_nums[index];
        }

        index -= indirect_per_block;

        if (index < double_indirect_per_block) {
            if (inode.i_block[13] == 0) return 0;
            const double_indirect = try self.cache.get(self, inode.i_block[13]);
            const first_level = @as([*]const u32, @ptrCast(@alignCast(double_indirect.ptr)));
            const first_index = index / indirect_per_block;
            const second_index = index % indirect_per_block;

            if (first_level[first_index] == 0) return 0;
            const second_level = try self.cache.get(self, first_level[first_index]);
            const block_nums = @as([*]const u32, @ptrCast(@alignCast(second_level.ptr)));
            return block_nums[second_index];
        }

        return vfs.VFSError.InvalidOperation;
    }

    fn findDirEntry(self: *Ext2FileSystem, parent_inode: *const Ext2Inode, name: []const u8) !u32 {
        if ((parent_inode.i_mode & EXT2_S_IFDIR) == 0) {
            return vfs.VFSError.NotDirectory;
        }

        const blocks_count = (parent_inode.i_size + self.block_size - 1) / self.block_size;

        for (0..blocks_count) |block_idx| {
            const block = try self.readDataBlock(parent_inode, @as(u32, @intCast(block_idx)));
            var offset: u32 = 0;

            while (offset < self.block_size and offset < parent_inode.i_size) {
                const entry = @as(*const Ext2DirEntry, @ptrCast(@alignCast(&block[offset])));

                if (entry.inode != 0) {
                    const entry_name = @as([*]const u8, @ptrCast(&block[offset + @sizeOf(Ext2DirEntry)]))[0..entry.name_len];
                    if (std.mem.eql(u8, entry_name, name)) {
                        return entry.inode;
                    }
                }

                offset += entry.rec_len;
            }
        }

        return vfs.VFSError.NotFound;
    }
};

const Ext2VNodeData = struct {
    inode_num: u32,
    inode: Ext2Inode,
};

var ext2_filesystems: [4]?Ext2FileSystem = [_]?Ext2FileSystem{null} ** 4;
var num_ext2_fs: u8 = 0;

var ext2_fs_type: vfs.FileSystemType = undefined;
var ext2_fs_ops: vfs.FileSystemOps = undefined;
var ext2_file_ops: vfs.FileOps = undefined;

pub fn init() void {
    vga.print("Initializing ext2 filesystem support...\n");

    ext2_file_ops = vfs.FileOps{
        .read = ext2Read,
        .write = ext2Write,
        .open = ext2Open,
        .close = ext2Close,
        .seek = ext2Seek,
        .ioctl = ext2Ioctl,
        .stat = ext2Stat,
        .readdir = ext2Readdir,
        .truncate = ext2Truncate,
        .chmod = ext2Chmod,
        .chown = ext2Chown,
    };

    ext2_fs_ops = vfs.FileSystemOps{
        .mount = ext2Mount,
        .unmount = ext2Unmount,
        .get_root = ext2GetRoot,
        .lookup = ext2Lookup,
        .create = ext2Create,
        .mkdir = ext2Mkdir,
        .unlink = ext2Unlink,
        .rmdir = ext2Rmdir,
        .rename = ext2Rename,
        .symlink = null,
        .link = null,
        .readlink = null,
    };

    @memcpy(ext2_fs_type.name[0..4], "ext2");
    ext2_fs_type.name[4] = 0;
    ext2_fs_type.ops = &ext2_fs_ops;
    ext2_fs_type.next = null;

    vfs.registerFileSystem(&ext2_fs_type) catch |err| {
        vga.print("Failed to register ext2: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
}

pub fn flushFilesystem(mount_point: *vfs.MountPoint) vfs.VFSError!void {
    if (mount_point.private_data) |fs_ptr| {
        const fs = @as(*Ext2FileSystem, @ptrCast(@alignCast(fs_ptr)));
        fs.cache.flush(fs) catch {
            return vfs.VFSError.DeviceError;
        };
    }
}

pub fn mount(device: *const ata.ATADevice) !*Ext2FileSystem {
    if (num_ext2_fs >= 4) {
        return vfs.VFSError.NoSpace;
    }

    var superblock_buffer: [1024]u8 = undefined;
    ata.readSectors(device, 2, 1, superblock_buffer[0..512]) catch return vfs.VFSError.DeviceError;
    ata.readSectors(device, 3, 1, superblock_buffer[512..]) catch return vfs.VFSError.DeviceError;

    const superblock = @as(*const Ext2Superblock, @ptrCast(@alignCast(&superblock_buffer))).*;

    if (superblock.s_magic != EXT2_SUPER_MAGIC) {
        return vfs.VFSError.InvalidOperation;
    }

    const block_size = @as(u32, 1024) << @as(u5, @intCast(superblock.s_log_block_size));
    const groups_count = (superblock.s_blocks_count + superblock.s_blocks_per_group - 1) /
                        superblock.s_blocks_per_group;

    const group_desc_blocks = (groups_count * @sizeOf(Ext2GroupDesc) + block_size - 1) / block_size;
    const group_desc_mem = memory.kmalloc(group_desc_blocks * block_size) orelse
                           return vfs.VFSError.OutOfMemory;

    ext2_filesystems[num_ext2_fs] = Ext2FileSystem{
        .device = device,
        .superblock = superblock,
        .block_size = block_size,
        .groups_count = groups_count,
        .group_descs = @as([*]Ext2GroupDesc, @ptrCast(@alignCast(group_desc_mem))),
        .cache = Ext2FileSystem.BlockCache.init(),
    };

    const fs = &ext2_filesystems[num_ext2_fs].?;

    const gdt_block: u32 = if (block_size == 1024) 2 else 1;
    for (0..group_desc_blocks) |i| {
        var buffer: [4096]u8 = undefined;
        try fs.readBlock(gdt_block + @as(u32, @intCast(i)), buffer[0..block_size]);
        @memcpy(@as([*]u8, @ptrCast(&fs.group_descs[i * block_size / @sizeOf(Ext2GroupDesc)]))[0..block_size],
                buffer[0..block_size]);
    }

    num_ext2_fs += 1;

    vga.print("ext2 filesystem mounted successfully\n");
    vga.print("  Block size: ");
    printNumber(block_size);
    vga.print(" bytes\n");
    vga.print("  Total blocks: ");
    printNumber(superblock.s_blocks_count);
    vga.print("\n");
    vga.print("  Total inodes: ");
    printNumber(superblock.s_inodes_count);
    vga.print("\n");

    return fs;
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.printChar('0');
        return;
    }

    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[count] = @as(u8, @intCast('0' + (n % 10)));
        count += 1;
    }

    var i = count;
    while (i > 0) {
        i -= 1;
        vga.printChar(digits[i]);
    }
}

fn ext2Mount(mount_point: *vfs.MountPoint) vfs.VFSError!void {
    const device = ata.getPrimaryMaster() orelse return vfs.VFSError.NotFound;
    const fs = try mount(device);
    mount_point.private_data = fs;
}

fn ext2Unmount(mount_point: *vfs.MountPoint) vfs.VFSError!void {
    if (mount_point.private_data) |fs_ptr| {
        const fs = @as(*Ext2FileSystem, @ptrCast(@alignCast(fs_ptr)));
        fs.cache.flush(fs) catch {};
    }
}

fn ext2GetRoot(mount_point: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const fs = @as(*Ext2FileSystem, @ptrCast(@alignCast(mount_point.private_data.?)));
    const root_inode = try fs.readInode(EXT2_ROOT_INO);

    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode = @as(*vfs.VNode, @ptrCast(@alignCast(vnode_mem)));

    const vnode_data_mem = memory.kmalloc(@sizeOf(Ext2VNodeData)) orelse {
        memory.kfree(@as([*]u8, @ptrCast(vnode)));
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data = @as(*Ext2VNodeData, @ptrCast(@alignCast(vnode_data_mem)));

    vnode_data.inode_num = EXT2_ROOT_INO;
    vnode_data.inode = root_inode;

    const file_type = if ((root_inode.i_mode & EXT2_S_IFDIR) != 0)
        vfs.FileType.Directory
    else if ((root_inode.i_mode & EXT2_S_IFREG) != 0)
        vfs.FileType.Regular
    else
        vfs.FileType.Regular;

    vnode.* = vfs.VNode{
        .name = [_]u8{0} ** 256,
        .name_len = 1,
        .inode = EXT2_ROOT_INO,
        .file_type = file_type,
        .mode = ext2ModeToVFSMode(root_inode.i_mode),
        .size = root_inode.i_size,
        .ref_count = 1,
        .mount_point = mount_point,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = &ext2_file_ops,
        .private_data = vnode_data,
    };

    vnode.name[0] = '/';
    return vnode;
}

fn ext2Lookup(parent: *vfs.VNode, name: []const u8) vfs.VFSError!*vfs.VNode {
    const parent_data = @as(*Ext2VNodeData, @ptrCast(@alignCast(parent.private_data.?)));
    const fs = @as(*Ext2FileSystem, @ptrCast(@alignCast(parent.mount_point.?.private_data.?)));

    const inode_num = try fs.findDirEntry(&parent_data.inode, name);
    const inode = try fs.readInode(inode_num);

    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode = @as(*vfs.VNode, @ptrCast(@alignCast(vnode_mem)));

    const vnode_data_mem = memory.kmalloc(@sizeOf(Ext2VNodeData)) orelse {
        memory.kfree(@as([*]u8, @ptrCast(vnode)));
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data = @as(*Ext2VNodeData, @ptrCast(@alignCast(vnode_data_mem)));

    vnode_data.inode_num = inode_num;
    vnode_data.inode = inode;

    const file_type = if ((inode.i_mode & EXT2_S_IFDIR) != 0)
        vfs.FileType.Directory
    else if ((inode.i_mode & EXT2_S_IFREG) != 0)
        vfs.FileType.Regular
    else if ((inode.i_mode & EXT2_S_IFLNK) != 0)
        vfs.FileType.SymLink
    else
        vfs.FileType.Regular;

    const name_len = @min(name.len, 255);
    @memcpy(vnode.name[0..name_len], name[0..name_len]);
    vnode.name[name_len] = 0;
    vnode.name_len = @as(u16, @intCast(name_len));

    vnode.* = vfs.VNode{
        .name = vnode.name,
        .name_len = vnode.name_len,
        .inode = inode_num,
        .file_type = file_type,
        .mode = ext2ModeToVFSMode(inode.i_mode),
        .size = inode.i_size,
        .ref_count = 1,
        .mount_point = parent.mount_point,
        .parent = parent,
        .children = null,
        .next_sibling = null,
        .ops = &ext2_file_ops,
        .private_data = vnode_data,
    };

    return vnode;
}

fn ext2Read(vnode: *vfs.VNode, buffer: []u8, offset: u64) vfs.VFSError!usize {
    const vnode_data = @as(*Ext2VNodeData, @ptrCast(@alignCast(vnode.private_data.?)));
    const fs = @as(*Ext2FileSystem, @ptrCast(@alignCast(vnode.mount_point.?.private_data.?)));

    if (vnode.file_type == vfs.FileType.Directory) {
        return vfs.VFSError.IsDirectory;
    }

    if (offset >= vnode_data.inode.i_size) {
        return 0;
    }

    var bytes_to_read = buffer.len;
    if (offset + bytes_to_read > vnode_data.inode.i_size) {
        bytes_to_read = @as(usize, @intCast(vnode_data.inode.i_size - offset));
    }

    var bytes_read: usize = 0;
    var current_offset = offset;
    const block_size = fs.block_size;

    while (bytes_read < bytes_to_read) {
        const block_index = @as(u32, @intCast(current_offset / block_size));
        const offset_in_block = @as(u32, @intCast(current_offset % block_size));

        const block = try fs.readDataBlock(&vnode_data.inode, block_index);
        if (block.len == 0) break;

        const bytes_in_block = @min(block_size - offset_in_block, bytes_to_read - bytes_read);
        const offset_start = @as(usize, @intCast(offset_in_block));
        @memcpy(buffer[bytes_read..bytes_read + bytes_in_block], block[offset_start..offset_start + bytes_in_block]);

        bytes_read += bytes_in_block;
        current_offset += bytes_in_block;
    }

    return bytes_read;
}

fn ext2Write(vnode: *vfs.VNode, buffer: []const u8, offset: u64) vfs.VFSError!usize {
    _ = vnode;
    _ = buffer;
    _ = offset;
    return vfs.VFSError.ReadOnly;
}

fn ext2Open(vnode: *vfs.VNode, flags: u32) vfs.VFSError!void {
    _ = vnode;
    _ = flags;
}

fn ext2Close(vnode: *vfs.VNode) vfs.VFSError!void {
    _ = vnode;
}

fn ext2Seek(vnode: *vfs.VNode, offset: i64, whence: u32) vfs.VFSError!u64 {
    _ = vnode;
    _ = offset;
    _ = whence;
    return 0;
}

fn ext2Ioctl(vnode: *vfs.VNode, request: u32, arg: usize) vfs.VFSError!i32 {
    _ = vnode;
    _ = request;
    _ = arg;
    return 0;
}

fn ext2Stat(vnode: *vfs.VNode, stat_buf: *vfs.FileStat) vfs.VFSError!void {
    const vnode_data = @as(*Ext2VNodeData, @ptrCast(@alignCast(vnode.private_data.?)));

    stat_buf.* = vfs.FileStat{
        .inode = vnode.inode,
        .mode = vnode.mode,
        .file_type = vnode.file_type,
        .size = vnode.size,
        .blocks = vnode_data.inode.i_blocks,
        .block_size = 512,
        .uid = vnode_data.inode.i_uid,
        .gid = vnode_data.inode.i_gid,
        .atime = vnode_data.inode.i_atime,
        .mtime = vnode_data.inode.i_mtime,
        .ctime = vnode_data.inode.i_ctime,
    };
}

fn ext2Readdir(vnode: *vfs.VNode, dirent: *vfs.DirEntry, index: u64) vfs.VFSError!bool {
    const vnode_data = @as(*Ext2VNodeData, @ptrCast(@alignCast(vnode.private_data.?)));
    const fs = @as(*Ext2FileSystem, @ptrCast(@alignCast(vnode.mount_point.?.private_data.?)));

    if (vnode.file_type != vfs.FileType.Directory) {
        return vfs.VFSError.NotDirectory;
    }

    const blocks_count = (vnode_data.inode.i_size + fs.block_size - 1) / fs.block_size;
    var entry_index: u64 = 0;

    for (0..blocks_count) |block_idx| {
        const block = try fs.readDataBlock(&vnode_data.inode, @as(u32, @intCast(block_idx)));
        var offset: u32 = 0;

        while (offset < fs.block_size and offset < vnode_data.inode.i_size) {
            const entry = @as(*const Ext2DirEntry, @ptrCast(@alignCast(&block[offset])));

            if (entry.inode != 0) {
                if (entry_index == index) {
                    const entry_name = @as([*]const u8, @ptrCast(&block[offset + @sizeOf(Ext2DirEntry)]))[0..entry.name_len];
                    const name_len = @min(entry.name_len, 255);
                    @memcpy(dirent.name[0..name_len], entry_name[0..name_len]);
                    dirent.name[name_len] = 0;
                    dirent.name_len = @as(u16, @intCast(name_len));
                    dirent.inode = entry.inode;

                    const inode = fs.readInode(entry.inode) catch continue;
                    dirent.file_type = if ((inode.i_mode & EXT2_S_IFDIR) != 0)
                        vfs.FileType.Directory
                    else if ((inode.i_mode & EXT2_S_IFREG) != 0)
                        vfs.FileType.Regular
                    else if ((inode.i_mode & EXT2_S_IFLNK) != 0)
                        vfs.FileType.SymLink
                    else
                        vfs.FileType.Regular;

                    return true;
                }
                entry_index += 1;
            }

            offset += entry.rec_len;
        }
    }

    return false;
}

fn ext2Truncate(vnode: *vfs.VNode, size: u64) vfs.VFSError!void {
    _ = vnode;
    _ = size;
    return vfs.VFSError.ReadOnly;
}

fn ext2Chmod(vnode: *vfs.VNode, mode: vfs.FileMode) vfs.VFSError!void {
    _ = vnode;
    _ = mode;
    return vfs.VFSError.ReadOnly;
}

fn ext2Chown(vnode: *vfs.VNode, uid: u32, gid: u32) vfs.VFSError!void {
    _ = vnode;
    _ = uid;
    _ = gid;
    return vfs.VFSError.ReadOnly;
}

fn ext2Create(parent: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    _ = parent;
    _ = name;
    _ = mode;
    return vfs.VFSError.ReadOnly;
}

fn ext2Mkdir(parent: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    _ = parent;
    _ = name;
    _ = mode;
    return vfs.VFSError.ReadOnly;
}

fn ext2Unlink(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    _ = parent;
    _ = name;
    return vfs.VFSError.ReadOnly;
}

fn ext2Rmdir(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    _ = parent;
    _ = name;
    return vfs.VFSError.ReadOnly;
}

fn ext2Rename(old_parent: *vfs.VNode, old_name: []const u8, new_parent: *vfs.VNode, new_name: []const u8) vfs.VFSError!void {
    _ = old_parent;
    _ = old_name;
    _ = new_parent;
    _ = new_name;
    return vfs.VFSError.ReadOnly;
}

fn ext2ModeToVFSMode(mode: u16) vfs.FileMode {
    return vfs.FileMode{
        .owner_read = (mode & EXT2_S_IRUSR) != 0,
        .owner_write = (mode & EXT2_S_IWUSR) != 0,
        .owner_exec = (mode & EXT2_S_IXUSR) != 0,
        .group_read = (mode & EXT2_S_IRGRP) != 0,
        .group_write = (mode & EXT2_S_IWGRP) != 0,
        .group_exec = (mode & EXT2_S_IXGRP) != 0,
        .other_read = (mode & EXT2_S_IROTH) != 0,
        .other_write = (mode & EXT2_S_IWOTH) != 0,
        .other_exec = (mode & EXT2_S_IXOTH) != 0,
    };
}