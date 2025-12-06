const std = @import("std");
const memory = @import("memory.zig");
const vga = @import("vga.zig");

pub const MemoryPool = struct {
    block_size: usize,
    blocks_per_chunk: usize,
    free_list: ?*FreeBlock,
    chunks: ?*Chunk,

    const FreeBlock = struct {
        next: ?*FreeBlock,
    };

    const Chunk = struct {
        data: [*]u8,
        next: ?*Chunk,
    };

    pub fn init(block_size: usize, blocks_per_chunk: usize) MemoryPool {
        return MemoryPool{
            .block_size = block_size,
            .blocks_per_chunk = blocks_per_chunk,
            .free_list = null,
            .chunks = null,
        };
    }

    pub fn alloc(self: *MemoryPool) ?[*]u8 {
        if (self.free_list) |block| {
            self.free_list = block.next;
            return @as([*]u8, @ptrCast(block));
        }

        const chunk_size = self.block_size * self.blocks_per_chunk;
        const chunk_mem = memory.kmalloc(chunk_size + @sizeOf(Chunk)) orelse return null;
        const chunk = @as(*Chunk, @ptrCast(@alignCast(chunk_mem)));
        chunk.data = @as([*]u8, @ptrCast(chunk_mem)) + @sizeOf(Chunk);
        chunk.next = self.chunks;
        self.chunks = chunk;

        var i: usize = 1;
        while (i < self.blocks_per_chunk) : (i += 1) {
            const block = @as(*FreeBlock, @ptrCast(@alignCast(&chunk.data[i * self.block_size])));
            block.next = self.free_list;
            self.free_list = block;
        }

        return &chunk.data[0];
    }

    pub fn free(self: *MemoryPool, ptr: [*]u8) void {
        const block = @as(*FreeBlock, @ptrCast(@alignCast(ptr)));
        block.next = self.free_list;
        self.free_list = block;
    }
};

pub const SlabAllocator = struct {
    object_size: usize,
    objects_per_slab: usize,
    slabs: ?*Slab,
    free_slabs: ?*Slab,

    const Slab = struct {
        objects: [*]u8,
        free_bitmap: [*]u32,
        free_count: usize,
        next: ?*Slab,
    };

    pub fn init(object_size: usize) SlabAllocator {
        const objects_per_slab = (4096 - @sizeOf(Slab)) / object_size;
        return SlabAllocator{
            .object_size = object_size,
            .objects_per_slab = objects_per_slab,
            .slabs = null,
            .free_slabs = null,
        };
    }

    pub fn alloc(self: *SlabAllocator) ?[*]u8 {
        var slab = self.slabs;
        while (slab) |s| {
            if (s.free_count > 0) {
                var i: usize = 0;
                while (i < self.objects_per_slab) : (i += 1) {
                    const word_idx = i / 32;
                    const bit_idx = i % 32;
                    if ((s.free_bitmap[word_idx] & (@as(u32, 1) << @as(u5, @intCast(bit_idx)))) == 0) {
                        s.free_bitmap[word_idx] |= @as(u32, 1) << @as(u5, @intCast(bit_idx));
                        s.free_count -= 1;
                        return &s.objects[i * self.object_size];
                    }
                }
            }
            slab = s.next;
        }

        const slab_size = @sizeOf(Slab) + (self.objects_per_slab * self.object_size) +
            ((self.objects_per_slab + 31) / 32) * @sizeOf(u32);
        const slab_mem = memory.kmalloc(slab_size) orelse return null;
        const new_slab = @as(*Slab, @ptrCast(@alignCast(slab_mem)));

        new_slab.objects = @as([*]u8, @ptrCast(slab_mem)) + @sizeOf(Slab);
        const bitmap_offset = @sizeOf(Slab) + (self.objects_per_slab * self.object_size);
        new_slab.free_bitmap = @as([*]u32, @ptrCast(@alignCast(@as([*]u8, @ptrCast(slab_mem)) + bitmap_offset)));
        new_slab.free_count = self.objects_per_slab;
        new_slab.next = self.slabs;
        self.slabs = new_slab;

        new_slab.free_bitmap[0] = 1;
        new_slab.free_count -= 1;

        return &new_slab.objects[0];
    }

    pub fn free(self: *SlabAllocator, ptr: [*]u8) void {
        _ = self;
        _ = ptr;
    }
};

var process_pool: ?MemoryPool = null;
var vnode_pool: ?MemoryPool = null;

pub fn init() void {
    vga.print("Initializing advanced memory allocators...\n");

    process_pool = MemoryPool.init(@sizeOf(@import("process.zig").Process), 64);
    vnode_pool = MemoryPool.init(@sizeOf(@import("vfs.zig").VNode), 256);

    vga.print("Memory pools initialized!\n");
}

pub fn allocProcess() ?[*]u8 {
    if (process_pool) |*pool| {
        return pool.alloc();
    }
    return null;
}

pub fn freeProcess(ptr: [*]u8) void {
    if (process_pool) |*pool| {
        pool.free(ptr);
    }
}

pub fn allocVNode() ?[*]u8 {
    if (vnode_pool) |*pool| {
        return pool.alloc();
    }
    return null;
}

pub fn freeVNode(ptr: [*]u8) void {
    if (vnode_pool) |*pool| {
        pool.free(ptr);
    }
}

