const vga = @import("../drivers/vga.zig");
const numfmt = @import("../utils/numfmt.zig");

const BYTES_PER_MIB: usize = 1024 * 1024;
const HEAP_SIZE: usize = 16 * BYTES_PER_MIB;
const MIN_BLOCK_SIZE: usize = 16;
const BLOCK_ALIGNMENT: usize = 16;

const PAGE_SIZE: usize = 4096;
extern var __kernel_end: u8;

fn alignUp(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
}

fn heapStartAddress() usize {
    return alignUp(@intFromPtr(&__kernel_end), PAGE_SIZE);
}

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
var allocator_lock: u32 = 0;

fn lockAllocator() void {
    while (@cmpxchgWeak(u32, &allocator_lock, 0, 1, .acquire, .monotonic) != null) {
        while (@atomicLoad(u32, &allocator_lock, .monotonic) != 0) {
            asm volatile ("pause");
        }
    }
}

fn unlockAllocator() void {
    @atomicStore(u32, &allocator_lock, 0, .release);
}

pub fn init() void {
    const heap_start_addr = heapStartAddress();
    heap_start = @ptrFromInt(heap_start_addr);
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
    numfmt.printHex(@intFromPtr(heap_start));
    vga.print("\nHeap size: ");
    numfmt.printDec(HEAP_SIZE / BYTES_PER_MIB);
    vga.print(" MB\n");
}

pub fn getReservedMemoryEnd() usize {
    return heapStartAddress() + HEAP_SIZE;
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
    lockAllocator();
    defer unlockAllocator();

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
    lockAllocator();
    defer unlockAllocator();

    const raw_ptr: [*]u8 = @ptrCast(ptr.?);
    const block: *BlockHeader = @ptrCast(@alignCast(raw_ptr - @sizeOf(BlockHeader)));

    if (!blockWithinHeap(block)) {
        return;
    }

    // Guard against double-free: coalescing an already-free block a second time
    // corrupts the free list (it merges neighbours twice).
    if (block.is_free) {
        return;
    }

    block.is_free = true;
    coalesceBlocks(block);
}

fn blockWithinHeap(block: *const BlockHeader) bool {
    const addr = @intFromPtr(block);
    return addr >= @intFromPtr(heap_start) and addr + @sizeOf(BlockHeader) <= @intFromPtr(heap_end);
}
