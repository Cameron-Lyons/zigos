const console = @import("../utils/console.zig");
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
    // Address-ordered neighbours, for splitting and coalescing.
    next: ?*BlockHeader,
    prev: ?*BlockHeader,
    // Free-list links; only meaningful while is_free.
    next_free: ?*BlockHeader,
    prev_free: ?*BlockHeader,
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
    initial_block.next_free = null;
    initial_block.prev_free = null;

    free_list = initial_block;
    is_initialized = true;

    console.print("Memory allocator initialized!\n");
    console.print("Heap start: 0x");
    numfmt.printHex(@intFromPtr(heap_start));
    console.print("\nHeap size: ");
    numfmt.printDec(HEAP_SIZE / BYTES_PER_MIB);
    console.print(" MB\n");
}

pub fn getReservedMemoryEnd() usize {
    return heapStartAddress() + HEAP_SIZE;
}

fn freeListPush(block: *BlockHeader) void {
    block.prev_free = null;
    block.next_free = free_list;
    if (free_list) |head| {
        head.prev_free = block;
    }
    free_list = block;
}

fn freeListRemove(block: *BlockHeader) void {
    if (block.prev_free) |prev| {
        prev.next_free = block.next_free;
    } else {
        free_list = block.next_free;
    }
    if (block.next_free) |next| {
        next.prev_free = block.prev_free;
    }
    block.next_free = null;
    block.prev_free = null;
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
        freeListPush(new_block);
    }
}

fn takeFreeBlock(aligned_size: usize) ?*anyopaque {
    var current = free_list;
    while (current) |block| {
        const next_free = block.next_free;
        if (block.size >= aligned_size) {
            splitBlock(block, aligned_size);
            freeListRemove(block);
            block.is_free = false;

            const data_ptr: [*]u8 = @ptrCast(block);
            return @ptrCast(data_ptr + @sizeOf(BlockHeader));
        }
        current = next_free;
    }
    return null;
}

pub fn kmalloc(size: usize) ?*anyopaque {
    if (!is_initialized or size == 0) return null;
    lockAllocator();
    defer unlockAllocator();

    const aligned_size = alignUp(size, BLOCK_ALIGNMENT);

    return takeFreeBlock(aligned_size);
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

    // Absorb a free successor, then fold into a free predecessor; the
    // neighbour being absorbed leaves the free list, and the surviving
    // block enters it exactly once.
    if (block.next) |next| {
        if (next.is_free) {
            freeListRemove(next);
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
            return;
        }
    }

    freeListPush(block);
}

fn blockWithinHeap(block: *const BlockHeader) bool {
    const addr = @intFromPtr(block);
    return addr >= @intFromPtr(heap_start) and addr + @sizeOf(BlockHeader) <= @intFromPtr(heap_end);
}
