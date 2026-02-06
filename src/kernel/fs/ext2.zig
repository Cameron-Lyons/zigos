// zlint-disable suppressed-errors
const std = @import("std");
const vfs = @import("vfs.zig");
const ata = @import("../drivers/ata.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");

const EXT2_SUPER_MAGIC = 0xEF53;
const EXT2_ROOT_INO = 2;
const EXT2_GOOD_OLD_REV = 0;
const EXT2_GOOD_OLD_INODE_SIZE = 128;

const EXT2_S_IFLNK = 0xA000;
const EXT2_S_IFREG = 0x8000;
const EXT2_S_IFDIR = 0x4000;

const EXT2_S_IRUSR = 0x0100;
const EXT2_S_IWUSR = 0x0080;
const EXT2_S_IXUSR = 0x0040;
const EXT2_S_IRGRP = 0x0020;
const EXT2_S_IWGRP = 0x0010;
const EXT2_S_IXGRP = 0x0008;
const EXT2_S_IROTH = 0x0004;
const EXT2_S_IWOTH = 0x0002;
const EXT2_S_IXOTH = 0x0001;

const EXT2_FT_REG_FILE = 1;
const EXT2_FT_DIR = 2;

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
        const sectors: u8 = @intCast(self.block_size / 512);

        ata.readSectors(self.device, lba, sectors, buffer) catch {
            return vfs.VFSError.DeviceError;
        };
    }

    fn writeBlock(self: *Ext2FileSystem, block_num: u32, buffer: []const u8) !void {
        const lba = block_num * (self.block_size / 512);
        const sectors: u8 = @intCast(self.block_size / 512);

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
        const inode_ptr: *const Ext2Inode = @ptrCast(@alignCast(&block[offset]));
        return inode_ptr.*;
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
            const block_nums: [*]const u32 = @ptrCast(@alignCast(indirect_block.ptr));
            return block_nums[index];
        }

        index -= indirect_per_block;

        if (index < double_indirect_per_block) {
            if (inode.i_block[13] == 0) return 0;
            const double_indirect = try self.cache.get(self, inode.i_block[13]);
            const first_level: [*]const u32 = @ptrCast(@alignCast(double_indirect.ptr));
            const first_index = index / indirect_per_block;
            const second_index = index % indirect_per_block;

            if (first_level[first_index] == 0) return 0;
            const second_level = try self.cache.get(self, first_level[first_index]);
            const block_nums: [*]const u32 = @ptrCast(@alignCast(second_level.ptr));
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
            const block_idx_u32: u32 = @intCast(block_idx);
            const block = try self.readDataBlock(parent_inode, block_idx_u32);
            var offset: u32 = 0;

            while (offset < self.block_size and offset < parent_inode.i_size) {
                const entry: *const Ext2DirEntry = @ptrCast(@alignCast(&block[offset]));

                if (entry.inode != 0) {
                    const entry_name_ptr: [*]const u8 = @ptrCast(&block[offset + @sizeOf(Ext2DirEntry)]);
                    const entry_name = entry_name_ptr[0..entry.name_len];
                    if (std.mem.eql(u8, entry_name, name)) {
                        return entry.inode;
                    }
                }

                offset += entry.rec_len;
            }
        }

        return vfs.VFSError.NotFound;
    }

    fn allocBlock(self: *Ext2FileSystem) !u32 {
        for (0..self.groups_count) |group_idx| {
            const group: u32 = @intCast(group_idx);
            if (self.group_descs[group].bg_free_blocks_count == 0) continue;

            const bitmap_block = self.group_descs[group].bg_block_bitmap;
            const bitmap = try self.cache.get(self, bitmap_block);

            for (0..self.superblock.s_blocks_per_group) |bit| {
                const byte_idx = bit / 8;
                const bit_idx: u3 = @intCast(bit % 8);

                if (byte_idx >= self.block_size) break;
                const one: u8 = 1;
                if (bitmap[byte_idx] & (one << bit_idx) == 0) {
                    bitmap[byte_idx] |= (one << bit_idx);
                    self.cache.markDirty(bitmap_block);

                    self.group_descs[group].bg_free_blocks_count -= 1;
                    self.superblock.s_free_blocks_count -= 1;

                    const bit_u32: u32 = @intCast(bit);
                    return group * self.superblock.s_blocks_per_group +
                        self.superblock.s_first_data_block + bit_u32;
                }
            }
        }
        return vfs.VFSError.NoSpace;
    }

    fn freeBlock(self: *Ext2FileSystem, block_num: u32) !void {
        if (block_num == 0) return;
        const adjusted = block_num - self.superblock.s_first_data_block;
        const group = adjusted / self.superblock.s_blocks_per_group;
        const bit = adjusted % self.superblock.s_blocks_per_group;

        const bitmap_block = self.group_descs[group].bg_block_bitmap;
        const bitmap = try self.cache.get(self, bitmap_block);

        const byte_idx = bit / 8;
        const bit_idx: u3 = @intCast(bit % 8);
        const one: u8 = 1;
        bitmap[byte_idx] &= ~(one << bit_idx);
        self.cache.markDirty(bitmap_block);

        self.group_descs[group].bg_free_blocks_count += 1;
        self.superblock.s_free_blocks_count += 1;
    }

    fn allocInode(self: *Ext2FileSystem) !u32 {
        for (0..self.groups_count) |group_idx| {
            const group: u32 = @intCast(group_idx);
            if (self.group_descs[group].bg_free_inodes_count == 0) continue;

            const bitmap_block = self.group_descs[group].bg_inode_bitmap;
            const bitmap = try self.cache.get(self, bitmap_block);

            for (0..self.superblock.s_inodes_per_group) |bit| {
                const byte_idx = bit / 8;
                const bit_idx: u3 = @intCast(bit % 8);

                if (byte_idx >= self.block_size) break;
                const one: u8 = 1;
                if (bitmap[byte_idx] & (one << bit_idx) == 0) {
                    bitmap[byte_idx] |= (one << bit_idx);
                    self.cache.markDirty(bitmap_block);

                    self.group_descs[group].bg_free_inodes_count -= 1;
                    self.superblock.s_free_inodes_count -= 1;

                    const bit_u32: u32 = @intCast(bit);
                    return group * self.superblock.s_inodes_per_group + bit_u32 + 1;
                }
            }
        }
        return vfs.VFSError.NoSpace;
    }

    fn freeInode(self: *Ext2FileSystem, inode_num: u32) !void {
        if (inode_num == 0) return;
        const group = (inode_num - 1) / self.superblock.s_inodes_per_group;
        const bit = (inode_num - 1) % self.superblock.s_inodes_per_group;

        const bitmap_block = self.group_descs[group].bg_inode_bitmap;
        const bitmap = try self.cache.get(self, bitmap_block);

        const byte_idx = bit / 8;
        const bit_idx: u3 = @intCast(bit % 8);
        const one: u8 = 1;
        bitmap[byte_idx] &= ~(one << bit_idx);
        self.cache.markDirty(bitmap_block);

        self.group_descs[group].bg_free_inodes_count += 1;
        self.superblock.s_free_inodes_count += 1;
    }

    fn setBlockNumber(self: *Ext2FileSystem, inode: *Ext2Inode, block_index: u32, block_num: u32) !void {
        const direct_blocks: u32 = 12;
        const indirect_per_block = self.block_size / 4;

        if (block_index < direct_blocks) {
            inode.i_block[block_index] = block_num;
            return;
        }

        var index = block_index - direct_blocks;

        if (index < indirect_per_block) {
            if (inode.i_block[12] == 0) {
                inode.i_block[12] = try self.allocBlock();
                const new_block = try self.cache.get(self, inode.i_block[12]);
                @memset(new_block, 0);
                self.cache.markDirty(inode.i_block[12]);
            }
            const indirect_block = try self.cache.get(self, inode.i_block[12]);
            const block_nums: [*]u32 = @ptrCast(@alignCast(indirect_block.ptr));
            block_nums[index] = block_num;
            self.cache.markDirty(inode.i_block[12]);
            return;
        }

        index -= indirect_per_block;

        if (index < indirect_per_block * indirect_per_block) {
            if (inode.i_block[13] == 0) {
                inode.i_block[13] = try self.allocBlock();
                const new_block = try self.cache.get(self, inode.i_block[13]);
                @memset(new_block, 0);
                self.cache.markDirty(inode.i_block[13]);
            }
            const double_indirect = try self.cache.get(self, inode.i_block[13]);
            const first_level: [*]u32 = @ptrCast(@alignCast(double_indirect.ptr));
            const first_index = index / indirect_per_block;
            const second_index = index % indirect_per_block;

            if (first_level[first_index] == 0) {
                first_level[first_index] = try self.allocBlock();
                const nb = try self.cache.get(self, first_level[first_index]);
                @memset(nb, 0);
                self.cache.markDirty(first_level[first_index]);
                self.cache.markDirty(inode.i_block[13]);
            }
            const second_level = try self.cache.get(self, first_level[first_index]);
            const block_nums_2: [*]u32 = @ptrCast(@alignCast(second_level.ptr));
            block_nums_2[second_index] = block_num;
            self.cache.markDirty(first_level[first_index]);
            return;
        }

        return vfs.VFSError.NoSpace;
    }

    fn addDirEntry(self: *Ext2FileSystem, parent_inode: *Ext2Inode, parent_inode_num: u32, name: []const u8, new_inode_num: u32, file_type: u8) !void {
        const entry_size: u32 = @intCast(((@sizeOf(Ext2DirEntry) + name.len + 3) / 4) * 4);
        const blocks_count = (parent_inode.i_size + self.block_size - 1) / self.block_size;

        for (0..blocks_count) |block_idx| {
            const block_idx_u32: u32 = @intCast(block_idx);
            const blk_num = try self.getBlockNumber(parent_inode, block_idx_u32);
            if (blk_num == 0) continue;
            const block = try self.cache.get(self, blk_num);
            var offset: u32 = 0;

            while (offset < self.block_size) {
                const entry: *Ext2DirEntry = @ptrCast(@alignCast(&block[offset]));
                const actual_size: u32 = @intCast(((@sizeOf(Ext2DirEntry) + entry.name_len + 3) / 4) * 4);
                const slack = entry.rec_len - actual_size;

                if (entry.inode != 0 and slack >= entry_size) {
                    entry.rec_len = @intCast(actual_size);

                    const new_offset = offset + actual_size;
                    const new_entry: *Ext2DirEntry = @ptrCast(@alignCast(&block[new_offset]));
                    new_entry.inode = new_inode_num;
                    new_entry.rec_len = @intCast(slack);
                    new_entry.name_len = @intCast(name.len);
                    new_entry.file_type = file_type;
                    const name_start = new_offset + @sizeOf(Ext2DirEntry);
                    @memcpy(block[name_start .. name_start + name.len], name);

                    self.cache.markDirty(blk_num);
                    return;
                } else if (entry.inode == 0 and entry.rec_len >= entry_size) {
                    entry.inode = new_inode_num;
                    entry.name_len = @intCast(name.len);
                    entry.file_type = file_type;
                    const name_start = offset + @sizeOf(Ext2DirEntry);
                    @memcpy(block[name_start .. name_start + name.len], name);

                    self.cache.markDirty(blk_num);
                    return;
                }

                offset += entry.rec_len;
            }
        }

        const new_block_num = try self.allocBlock();
        const new_block = try self.cache.get(self, new_block_num);
        @memset(new_block, 0);

        const entry: *Ext2DirEntry = @ptrCast(@alignCast(new_block.ptr));
        entry.inode = new_inode_num;
        entry.rec_len = @intCast(self.block_size);
        entry.name_len = @intCast(name.len);
        entry.file_type = file_type;
        @memcpy(new_block[@sizeOf(Ext2DirEntry) .. @sizeOf(Ext2DirEntry) + name.len], name);

        self.cache.markDirty(new_block_num);

        try self.setBlockNumber(parent_inode, @intCast(blocks_count), new_block_num);
        parent_inode.i_size += self.block_size;
        parent_inode.i_blocks += self.block_size / 512;
        try self.writeInode(parent_inode_num, parent_inode);
    }

    fn removeDirEntry(self: *Ext2FileSystem, parent_inode: *const Ext2Inode, name: []const u8) !void {
        const blocks_count = (parent_inode.i_size + self.block_size - 1) / self.block_size;

        for (0..blocks_count) |block_idx| {
            const block_idx_u32: u32 = @intCast(block_idx);
            const blk_num = try self.getBlockNumber(parent_inode, block_idx_u32);
            if (blk_num == 0) continue;
            const block = try self.cache.get(self, blk_num);
            var offset: u32 = 0;
            var prev_entry: ?*Ext2DirEntry = null;

            while (offset < self.block_size) {
                const entry: *Ext2DirEntry = @ptrCast(@alignCast(&block[offset]));

                if (entry.inode != 0) {
                    const entry_name_ptr: [*]const u8 = @ptrCast(&block[offset + @sizeOf(Ext2DirEntry)]);
                    const entry_name = entry_name_ptr[0..entry.name_len];
                    if (std.mem.eql(u8, entry_name, name)) {
                        if (prev_entry) |prev| {
                            prev.rec_len += entry.rec_len;
                        } else {
                            entry.inode = 0;
                        }
                        self.cache.markDirty(blk_num);
                        return;
                    }
                }

                prev_entry = entry;
                offset += entry.rec_len;
            }
        }

        return vfs.VFSError.NotFound;
    }

    fn freeInodeBlocks(self: *Ext2FileSystem, inode: *Ext2Inode) !void {
        const indirect_per_block = self.block_size / 4;

        for (0..12) |i| {
            if (inode.i_block[i] != 0) {
                try self.freeBlock(inode.i_block[i]);
                inode.i_block[i] = 0;
            }
        }

        if (inode.i_block[12] != 0) {
            const indirect = try self.cache.get(self, inode.i_block[12]);
            const block_nums: [*]const u32 = @ptrCast(@alignCast(indirect.ptr));
            for (0..indirect_per_block) |i| {
                if (block_nums[i] != 0) {
                    try self.freeBlock(block_nums[i]);
                }
            }
            try self.freeBlock(inode.i_block[12]);
            inode.i_block[12] = 0;
        }

        if (inode.i_block[13] != 0) {
            const double_indirect = try self.cache.get(self, inode.i_block[13]);
            const first_level: [*]const u32 = @ptrCast(@alignCast(double_indirect.ptr));
            for (0..indirect_per_block) |i| {
                if (first_level[i] != 0) {
                    const second_level = try self.cache.get(self, first_level[i]);
                    const bl: [*]const u32 = @ptrCast(@alignCast(second_level.ptr));
                    for (0..indirect_per_block) |j| {
                        if (bl[j] != 0) {
                            try self.freeBlock(bl[j]);
                        }
                    }
                    try self.freeBlock(first_level[i]);
                }
            }
            try self.freeBlock(inode.i_block[13]);
            inode.i_block[13] = 0;
        }

        inode.i_blocks = 0;
    }

    fn isDirEmpty(self: *Ext2FileSystem, inode: *const Ext2Inode) !bool {
        const blocks_count = (inode.i_size + self.block_size - 1) / self.block_size;
        var entry_count: u32 = 0;

        for (0..blocks_count) |block_idx| {
            const block_idx_u32: u32 = @intCast(block_idx);
            const block = try self.readDataBlock(inode, block_idx_u32);
            var offset: u32 = 0;

            while (offset < self.block_size and offset < inode.i_size) {
                const entry: *const Ext2DirEntry = @ptrCast(@alignCast(&block[offset]));
                if (entry.inode != 0) {
                    const ename_ptr: [*]const u8 = @ptrCast(&block[offset + @sizeOf(Ext2DirEntry)]);
                    const ename = ename_ptr[0..entry.name_len];
                    if (!std.mem.eql(u8, ename, ".") and !std.mem.eql(u8, ename, "..")) {
                        entry_count += 1;
                    }
                }
                offset += entry.rec_len;
            }
        }

        return entry_count == 0;
    }
};

const Ext2VNodeData = struct {
    inode_num: u32,
    inode: Ext2Inode,
};

var ext2_filesystems: [4]?Ext2FileSystem = [_]?Ext2FileSystem{null} ** 4;
var num_ext2_fs: u8 = 0;

// SAFETY: fully initialized in init() before use
var ext2_fs_type: vfs.FileSystemType = undefined;
// SAFETY: fully initialized in init() before use
var ext2_fs_ops: vfs.FileSystemOps = undefined;
// SAFETY: fully initialized in init() before use
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
        const fs: *Ext2FileSystem = @ptrCast(@alignCast(fs_ptr));
        fs.cache.flush(fs) catch {
            return vfs.VFSError.DeviceError;
        };
    }
}

pub fn mount(device: *const ata.ATADevice) !*Ext2FileSystem {
    if (num_ext2_fs >= 4) {
        return vfs.VFSError.NoSpace;
    }

    // SAFETY: filled by the subsequent ata.readSectors calls
    var superblock_buffer: [1024]u8 = undefined;
    ata.readSectors(device, 2, 1, superblock_buffer[0..512]) catch return vfs.VFSError.DeviceError;
    ata.readSectors(device, 3, 1, superblock_buffer[512..]) catch return vfs.VFSError.DeviceError;

    const sb_ptr: *const Ext2Superblock = @ptrCast(@alignCast(&superblock_buffer));
    const superblock = sb_ptr.*;

    if (superblock.s_magic != EXT2_SUPER_MAGIC) {
        return vfs.VFSError.InvalidOperation;
    }

    const log_shift: u5 = @intCast(superblock.s_log_block_size);
    const base: u32 = 1024;
    const block_size: u32 = base << log_shift;
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
        .group_descs = @ptrCast(@alignCast(group_desc_mem)),
        .cache = Ext2FileSystem.BlockCache.init(),
    };

    const fs = &ext2_filesystems[num_ext2_fs].?;

    const gdt_block: u32 = if (block_size == 1024) 2 else 1;
    for (0..group_desc_blocks) |i| {
        // SAFETY: filled by the subsequent fs.readBlock call
        var buffer: [4096]u8 = undefined;
        const i_u32: u32 = @intCast(i);
        try fs.readBlock(gdt_block + i_u32, buffer[0..block_size]);
        const gd_ptr: [*]u8 = @ptrCast(&fs.group_descs[i * block_size / @sizeOf(Ext2GroupDesc)]);
        @memcpy(gd_ptr[0..block_size],
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

    // SAFETY: filled by the following digit extraction loop
    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        const digit: u8 = @intCast('0' + (n % 10));
        digits[count] = digit;
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
        const fs: *Ext2FileSystem = @ptrCast(@alignCast(fs_ptr));
        fs.cache.flush(fs) catch {};
        memory.kfree(@as([*]u8, @ptrCast(fs.group_descs)));
        for (&ext2_filesystems) |*slot| {
            if (slot.*) |*s| {
                if (s == fs) {
                    slot.* = null;
                    break;
                }
            }
        }
    }
}

fn ext2GetRoot(mount_point: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(mount_point.private_data.?));
    const root_inode = try fs.readInode(EXT2_ROOT_INO);

    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(vnode_mem));

    const vnode_data_mem = memory.kmalloc(@sizeOf(Ext2VNodeData)) orelse {
        const vnode_bytes: [*]u8 = @ptrCast(vnode);
        memory.kfree(vnode_bytes);
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode_data_mem));

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
    const parent_data: *Ext2VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));

    const inode_num = try fs.findDirEntry(&parent_data.inode, name);
    const inode = try fs.readInode(inode_num);

    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(vnode_mem));

    const vnode_data_mem = memory.kmalloc(@sizeOf(Ext2VNodeData)) orelse {
        const vnode_bytes: [*]u8 = @ptrCast(vnode);
        memory.kfree(vnode_bytes);
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode_data_mem));

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
    const name_len_u16: u16 = @intCast(name_len);
    vnode.name_len = name_len_u16;

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
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    if (vnode.file_type == vfs.FileType.Directory) {
        return vfs.VFSError.IsDirectory;
    }

    if (offset >= vnode_data.inode.i_size) {
        return 0;
    }

    var bytes_to_read = buffer.len;
    if (offset + bytes_to_read > vnode_data.inode.i_size) {
        const remaining: usize = @intCast(vnode_data.inode.i_size - offset);
        bytes_to_read = remaining;
    }

    var bytes_read: usize = 0;
    var current_offset = offset;
    const block_size = fs.block_size;

    while (bytes_read < bytes_to_read) {
        const block_index: u32 = @intCast(current_offset / block_size);
        const offset_in_block: u32 = @intCast(current_offset % block_size);

        const block = try fs.readDataBlock(&vnode_data.inode, block_index);
        if (block.len == 0) break;

        const bytes_in_block = @min(block_size - offset_in_block, bytes_to_read - bytes_read);
        const offset_start: usize = @intCast(offset_in_block);
        @memcpy(buffer[bytes_read..bytes_read + bytes_in_block], block[offset_start..offset_start + bytes_in_block]);

        bytes_read += bytes_in_block;
        current_offset += bytes_in_block;
    }

    return bytes_read;
}

fn ext2Write(vnode: *vfs.VNode, buffer: []const u8, offset: u64) vfs.VFSError!usize {
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    if (vnode.file_type == vfs.FileType.Directory) {
        return vfs.VFSError.IsDirectory;
    }

    var bytes_written: usize = 0;
    var current_offset = offset;
    const block_size = fs.block_size;

    while (bytes_written < buffer.len) {
        const block_index: u32 = @intCast(current_offset / block_size);
        const offset_in_block: u32 = @intCast(current_offset % block_size);

        var blk_num = fs.getBlockNumber(&vnode_data.inode, block_index) catch 0;
        if (blk_num == 0) {
            blk_num = try fs.allocBlock();
            try fs.setBlockNumber(&vnode_data.inode, block_index, blk_num);
            vnode_data.inode.i_blocks += block_size / 512;
        }

        const block = try fs.cache.get(fs, blk_num);
        const bytes_in_block = @min(block_size - offset_in_block, buffer.len - bytes_written);
        const offset_start: usize = @intCast(offset_in_block);
        @memcpy(block[offset_start .. offset_start + bytes_in_block], buffer[bytes_written .. bytes_written + bytes_in_block]);
        fs.cache.markDirty(blk_num);

        bytes_written += bytes_in_block;
        current_offset += bytes_in_block;
    }

    if (current_offset > vnode_data.inode.i_size) {
        vnode_data.inode.i_size = @intCast(current_offset);
        vnode.size = current_offset;
    }

    try fs.writeInode(vnode_data.inode_num, &vnode_data.inode);

    return bytes_written;
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
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode.private_data.?));

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
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    if (vnode.file_type != vfs.FileType.Directory) {
        return vfs.VFSError.NotDirectory;
    }

    const blocks_count = (vnode_data.inode.i_size + fs.block_size - 1) / fs.block_size;
    var entry_index: u64 = 0;

    for (0..blocks_count) |block_idx| {
        const block_idx_u32: u32 = @intCast(block_idx);
        const block = try fs.readDataBlock(&vnode_data.inode, block_idx_u32);
        var offset: u32 = 0;

        while (offset < fs.block_size and offset < vnode_data.inode.i_size) {
            const entry: *const Ext2DirEntry = @ptrCast(@alignCast(&block[offset]));

            if (entry.inode != 0) {
                if (entry_index == index) {
                    const entry_name_ptr: [*]const u8 = @ptrCast(&block[offset + @sizeOf(Ext2DirEntry)]);
                    const entry_name = entry_name_ptr[0..entry.name_len];
                    const name_len = @min(entry.name_len, 255);
                    @memcpy(dirent.name[0..name_len], entry_name[0..name_len]);
                    dirent.name[name_len] = 0;
                    const name_len_u16: u16 = @intCast(name_len);
                    dirent.name_len = name_len_u16;
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
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    if (vnode.file_type == vfs.FileType.Directory) {
        return vfs.VFSError.IsDirectory;
    }

    const new_blocks: u32 = @intCast((size + fs.block_size - 1) / fs.block_size);
    const old_blocks: u32 = @intCast((vnode_data.inode.i_size + fs.block_size - 1) / fs.block_size);

    if (new_blocks < old_blocks) {
        var block_idx = new_blocks;
        while (block_idx < old_blocks) : (block_idx += 1) {
            const blk_num = fs.getBlockNumber(&vnode_data.inode, block_idx) catch continue;
            if (blk_num != 0) {
                fs.freeBlock(blk_num) catch {};
                fs.setBlockNumber(&vnode_data.inode, block_idx, 0) catch {};
            }
        }
    }

    vnode_data.inode.i_size = @intCast(size);
    vnode.size = size;
    try fs.writeInode(vnode_data.inode_num, &vnode_data.inode);
}

fn ext2Chmod(vnode: *vfs.VNode, mode: vfs.FileMode) vfs.VFSError!void {
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    var new_mode = vnode_data.inode.i_mode & 0xF000;
    if (mode.owner_read) new_mode |= EXT2_S_IRUSR;
    if (mode.owner_write) new_mode |= EXT2_S_IWUSR;
    if (mode.owner_exec) new_mode |= EXT2_S_IXUSR;
    if (mode.group_read) new_mode |= EXT2_S_IRGRP;
    if (mode.group_write) new_mode |= EXT2_S_IWGRP;
    if (mode.group_exec) new_mode |= EXT2_S_IXGRP;
    if (mode.other_read) new_mode |= EXT2_S_IROTH;
    if (mode.other_write) new_mode |= EXT2_S_IWOTH;
    if (mode.other_exec) new_mode |= EXT2_S_IXOTH;

    vnode_data.inode.i_mode = new_mode;
    vnode.mode = mode;
    try fs.writeInode(vnode_data.inode_num, &vnode_data.inode);
}

fn ext2Chown(vnode: *vfs.VNode, uid: u32, gid: u32) vfs.VFSError!void {
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(vnode.mount_point.?.private_data.?));

    vnode_data.inode.i_uid = @intCast(uid);
    vnode_data.inode.i_gid = @intCast(gid);
    try fs.writeInode(vnode_data.inode_num, &vnode_data.inode);
}

fn ext2Create(parent: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    const parent_data: *Ext2VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));

    const inode_num = try fs.allocInode();

    var new_inode: Ext2Inode = std.mem.zeroes(Ext2Inode);
    new_inode.i_mode = EXT2_S_IFREG | vfsModeToExt2Mode(mode);
    new_inode.i_links_count = 1;
    new_inode.i_uid = 0;
    new_inode.i_gid = 0;

    try fs.writeInode(inode_num, &new_inode);
    try fs.addDirEntry(&parent_data.inode, parent_data.inode_num, name, inode_num, EXT2_FT_REG_FILE);

    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(vnode_mem));

    const vnode_data_mem = memory.kmalloc(@sizeOf(Ext2VNodeData)) orelse {
        const vnode_bytes: [*]u8 = @ptrCast(vnode);
        memory.kfree(vnode_bytes);
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode_data_mem));
    vnode_data.inode_num = inode_num;
    vnode_data.inode = new_inode;

    vnode.* = vfs.VNode{
        .name = [_]u8{0} ** 256,
        .name_len = @intCast(name.len),
        .inode = inode_num,
        .file_type = .Regular,
        .mode = mode,
        .size = 0,
        .ref_count = 1,
        .mount_point = parent.mount_point,
        .parent = parent,
        .children = null,
        .next_sibling = null,
        .ops = &ext2_file_ops,
        .private_data = vnode_data,
    };
    @memcpy(vnode.name[0..name.len], name);

    return vnode;
}

fn ext2Mkdir(parent: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    const parent_data: *Ext2VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));

    const inode_num = try fs.allocInode();
    const dir_block = try fs.allocBlock();

    var new_inode: Ext2Inode = std.mem.zeroes(Ext2Inode);
    new_inode.i_mode = EXT2_S_IFDIR | vfsModeToExt2Mode(mode);
    new_inode.i_links_count = 2;
    new_inode.i_size = fs.block_size;
    new_inode.i_blocks = fs.block_size / 512;
    new_inode.i_block[0] = dir_block;

    const block = try fs.cache.get(fs, dir_block);
    @memset(block, 0);

    const dot: *Ext2DirEntry = @ptrCast(@alignCast(block.ptr));
    dot.inode = inode_num;
    dot.rec_len = 12;
    dot.name_len = 1;
    dot.file_type = EXT2_FT_DIR;
    block[@sizeOf(Ext2DirEntry)] = '.';

    const dotdot: *Ext2DirEntry = @ptrCast(@alignCast(&block[12]));
    dotdot.inode = parent_data.inode_num;
    dotdot.rec_len = @intCast(fs.block_size - 12);
    dotdot.name_len = 2;
    dotdot.file_type = EXT2_FT_DIR;
    block[12 + @sizeOf(Ext2DirEntry)] = '.';
    block[12 + @sizeOf(Ext2DirEntry) + 1] = '.';

    fs.cache.markDirty(dir_block);

    try fs.writeInode(inode_num, &new_inode);
    try fs.addDirEntry(&parent_data.inode, parent_data.inode_num, name, inode_num, EXT2_FT_DIR);

    parent_data.inode.i_links_count += 1;
    try fs.writeInode(parent_data.inode_num, &parent_data.inode);

    const group = (inode_num - 1) / fs.superblock.s_inodes_per_group;
    fs.group_descs[group].bg_used_dirs_count += 1;

    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(vnode_mem));

    const vnode_data_mem = memory.kmalloc(@sizeOf(Ext2VNodeData)) orelse {
        const vnode_bytes: [*]u8 = @ptrCast(vnode);
        memory.kfree(vnode_bytes);
        return vfs.VFSError.OutOfMemory;
    };
    const vnode_data: *Ext2VNodeData = @ptrCast(@alignCast(vnode_data_mem));
    vnode_data.inode_num = inode_num;
    vnode_data.inode = new_inode;

    vnode.* = vfs.VNode{
        .name = [_]u8{0} ** 256,
        .name_len = @intCast(name.len),
        .inode = inode_num,
        .file_type = .Directory,
        .mode = mode,
        .size = fs.block_size,
        .ref_count = 1,
        .mount_point = parent.mount_point,
        .parent = parent,
        .children = null,
        .next_sibling = null,
        .ops = &ext2_file_ops,
        .private_data = vnode_data,
    };
    @memcpy(vnode.name[0..name.len], name);

    return vnode;
}

fn ext2Unlink(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    const parent_data: *Ext2VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));

    const inode_num = try fs.findDirEntry(&parent_data.inode, name);
    var inode = try fs.readInode(inode_num);

    if ((inode.i_mode & EXT2_S_IFDIR) != 0) {
        return vfs.VFSError.IsDirectory;
    }

    try fs.removeDirEntry(&parent_data.inode, name);

    inode.i_links_count -= 1;
    if (inode.i_links_count == 0) {
        try fs.freeInodeBlocks(&inode);
        try fs.freeInode(inode_num);
    }
    try fs.writeInode(inode_num, &inode);
}

fn ext2Rmdir(parent: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    const parent_data: *Ext2VNodeData = @ptrCast(@alignCast(parent.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(parent.mount_point.?.private_data.?));

    const inode_num = try fs.findDirEntry(&parent_data.inode, name);
    var inode = try fs.readInode(inode_num);

    if ((inode.i_mode & EXT2_S_IFDIR) == 0) {
        return vfs.VFSError.NotDirectory;
    }

    const empty = try fs.isDirEmpty(&inode);
    if (!empty) {
        return vfs.VFSError.InvalidOperation;
    }

    try fs.removeDirEntry(&parent_data.inode, name);
    try fs.freeInodeBlocks(&inode);

    inode.i_links_count = 0;
    try fs.writeInode(inode_num, &inode);

    parent_data.inode.i_links_count -= 1;
    try fs.writeInode(parent_data.inode_num, &parent_data.inode);

    const group = (inode_num - 1) / fs.superblock.s_inodes_per_group;
    fs.group_descs[group].bg_used_dirs_count -= 1;

    try fs.freeInode(inode_num);
}

fn ext2Rename(old_parent: *vfs.VNode, old_name: []const u8, new_parent: *vfs.VNode, new_name: []const u8) vfs.VFSError!void {
    const old_parent_data: *Ext2VNodeData = @ptrCast(@alignCast(old_parent.private_data.?));
    const new_parent_data: *Ext2VNodeData = @ptrCast(@alignCast(new_parent.private_data.?));
    const fs: *Ext2FileSystem = @ptrCast(@alignCast(old_parent.mount_point.?.private_data.?));

    const inode_num = try fs.findDirEntry(&old_parent_data.inode, old_name);
    const inode = try fs.readInode(inode_num);

    const file_type: u8 = if ((inode.i_mode & EXT2_S_IFDIR) != 0) EXT2_FT_DIR else EXT2_FT_REG_FILE;

    _ = fs.findDirEntry(&new_parent_data.inode, new_name) catch |err| switch (err) {
        vfs.VFSError.NotFound => 0,
        else => return err,
    };

    try fs.addDirEntry(&new_parent_data.inode, new_parent_data.inode_num, new_name, inode_num, file_type);
    try fs.removeDirEntry(&old_parent_data.inode, old_name);
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

fn vfsModeToExt2Mode(mode: vfs.FileMode) u16 {
    var result: u16 = 0;
    if (mode.owner_read) result |= EXT2_S_IRUSR;
    if (mode.owner_write) result |= EXT2_S_IWUSR;
    if (mode.owner_exec) result |= EXT2_S_IXUSR;
    if (mode.group_read) result |= EXT2_S_IRGRP;
    if (mode.group_write) result |= EXT2_S_IWGRP;
    if (mode.group_exec) result |= EXT2_S_IXGRP;
    if (mode.other_read) result |= EXT2_S_IROTH;
    if (mode.other_write) result |= EXT2_S_IWOTH;
    if (mode.other_exec) result |= EXT2_S_IXOTH;
    return result;
}