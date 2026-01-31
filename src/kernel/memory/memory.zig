const vga = @import("../drivers/vga.zig");

const HEAP_START: usize = 0x100000;
const HEAP_SIZE: usize = 16 * 1024 * 1024;
const MIN_BLOCK_SIZE: usize = 16;
const BLOCK_ALIGNMENT: usize = 8;

const PAGE_SIZE: usize = 4096;
var next_physical_page: usize = 0x200000;

const BlockHeader = struct {
    size: usize,
    is_free: bool,
    next: ?*BlockHeader,
    prev: ?*BlockHeader,
};

// SAFETY: assigned in init() before any heap operations
var heap_start: [*]u8 = undefined;
// SAFETY: assigned in init() before any heap operations
var heap_end: [*]u8 = undefined;
var free_list: ?*BlockHeader = null;
var is_initialized = false;

pub fn init() void {
    heap_start = @ptrFromInt(HEAP_START);
    heap_end = heap_start + HEAP_SIZE;

    const initial_block: *BlockHeader = @ptrCast(@alignCast(heap_start));
    initial_block.size = HEAP_SIZE - @sizeOf(BlockHeader);
    initial_block.is_free = true;
    initial_block.next = null;
    initial_block.prev = null;

    free_list = initial_block;
    is_initialized = true;

    vga.print("Memory allocator initialized!\n");
    vga.print("Heap start: 0x");
    printHex(@intFromPtr(heap_start));
    vga.print("\nHeap size: ");
    printDec(HEAP_SIZE / 1024 / 1024);
    vga.print(" MB\n");
}

fn printHex(value: usize) void {
    const hex_chars = "0123456789ABCDEF";
    // SAFETY: filled by the following hex digit extraction loop
    var buffer: [16]u8 = undefined;
    var i: usize = 0;
    var v = value;

    if (v == 0) {
        vga.print("0");
        return;
    }

    while (v > 0) : (i += 1) {
        buffer[i] = hex_chars[v & 0xF];
        v >>= 4;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}

fn printDec(value: usize) void {
    // SAFETY: filled by the following decimal digit extraction loop
    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var v = value;

    if (v == 0) {
        vga.print("0");
        return;
    }

    while (v > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}

fn alignUp(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
}

fn splitBlock(block: *BlockHeader, size: usize) void {
    const total_size = block.size;
    const new_block_offset = @sizeOf(BlockHeader) + alignUp(size, BLOCK_ALIGNMENT);

    if (total_size > new_block_offset + @sizeOf(BlockHeader) + MIN_BLOCK_SIZE) {
        const block_bytes: [*]u8 = @ptrCast(block);
        const new_block: *BlockHeader = @ptrCast(@alignCast(block_bytes + new_block_offset));

        new_block.size = total_size - new_block_offset;
        new_block.is_free = true;
        new_block.next = block.next;
        new_block.prev = block;

        if (block.next) |next| {
            next.prev = new_block;
        }

        block.size = size;
        block.next = new_block;
    }
}

fn coalesceBlocks(block: *BlockHeader) void {
    if (block.next) |next| {
        if (next.is_free) {
            block.size += @sizeOf(BlockHeader) + next.size;
            block.next = next.next;
            if (next.next) |next_next| {
                next_next.prev = block;
            }
        }
    }

    if (block.prev) |prev| {
        if (prev.is_free) {
            prev.size += @sizeOf(BlockHeader) + block.size;
            prev.next = block.next;
            if (block.next) |next| {
                next.prev = prev;
            }
        }
    }
}

pub fn kmalloc(size: usize) ?*anyopaque {
    if (!is_initialized or size == 0) return null;

    const aligned_size = alignUp(size, BLOCK_ALIGNMENT);

    var current = free_list;
    while (current) |block| {
        if (block.is_free and block.size >= aligned_size) {
            splitBlock(block, aligned_size);
            block.is_free = false;

            const data_ptr: [*]u8 = @ptrCast(block);
            return @ptrCast(data_ptr + @sizeOf(BlockHeader));
        }
        current = block.next;
    }

    return null;
}

pub fn kfree(ptr: ?*anyopaque) void {
    if (ptr == null or !is_initialized) return;

    const raw_ptr: [*]u8 = @ptrCast(ptr.?);
    const block: *BlockHeader = @ptrCast(@alignCast(raw_ptr - @sizeOf(BlockHeader)));

    if (@intFromPtr(block) < @intFromPtr(heap_start) or
        @intFromPtr(block) >= @intFromPtr(heap_end)) {
        return;
    }

    block.is_free = true;
    coalesceBlocks(block);
}

pub fn krealloc(ptr: ?*anyopaque, new_size: usize) ?*anyopaque {
    if (ptr == null) return kmalloc(new_size);
    if (new_size == 0) {
        kfree(ptr);
        return null;
    }

    const raw_ptr: [*]u8 = @ptrCast(ptr.?);
    const block: *BlockHeader = @ptrCast(@alignCast(raw_ptr - @sizeOf(BlockHeader)));

    if (block.size >= new_size) {
        return ptr;
    }

    const new_ptr = kmalloc(new_size);
    if (new_ptr) |new| {
        const copy_size = @min(block.size, new_size);
        @memcpy(@as([*]u8, @ptrCast(new))[0..copy_size],
                @as([*]u8, @ptrCast(ptr.?))[0..copy_size]);
        kfree(ptr);
    }

    return new_ptr;
}

pub fn getMemoryStats() struct { total: usize, used: usize, free: usize } {
    var total: usize = 0;
    var free: usize = 0;

    var current = free_list;
    while (current) |block| {
        total += block.size + @sizeOf(BlockHeader);
        if (block.is_free) {
            free += block.size;
        }
        current = block.next;
    }

    return .{
        .total = total,
        .used = total - free,
        .free = free,
    };
}

pub fn allocPages(num_pages: usize) ?[*]u8 {
    const page_size = 4096;
    const size = num_pages * page_size;

    const ptr = kmalloc(size);
    if (ptr) |p| {
        return @as([*]u8, @ptrCast(p));
    }
    return null;
}

pub fn freePages(ptr: [*]u8, num_pages: usize) void {
    _ = num_pages;
    kfree(@as(*anyopaque, @ptrCast(ptr)));
}

pub fn allocatePhysicalPage() ?u32 {
    const page = next_physical_page;
    next_physical_page += PAGE_SIZE;

    if (next_physical_page > 128 * 1024 * 1024) {
        return null;
    }

    return @as(u32, @intCast(page));
}

pub fn alloc(comptime T: type) ?*T {
    const size = @sizeOf(T);

    if (kmalloc(size)) |ptr| {
        const typed_ptr: *T = @ptrCast(@alignCast(ptr));
        // SAFETY: Immediately overwritten by caller
        typed_ptr.* = undefined;
        return typed_ptr;
    }

    return null;
}

pub const Allocator = struct {
    pub fn alloc(self: *Allocator, comptime T: type, n: usize) ![]T {
        _ = self;
        const size = @sizeOf(T) * n;
        const ptr = kmalloc(size) orelse return error.OutOfMemory;
        const slice = @as([*]T, @ptrCast(@alignCast(ptr)))[0..n];
        @memset(@as([*]u8, @ptrCast(slice.ptr))[0..size], 0);
        return slice;
    }

    pub fn free(self: *Allocator, memory: []u8) void {
        _ = self;
        kfree(@as(*anyopaque, @ptrCast(memory.ptr)));
    }
};

var default_allocator = Allocator{};

pub fn getDefaultAllocator() *Allocator {
    return &default_allocator;
}