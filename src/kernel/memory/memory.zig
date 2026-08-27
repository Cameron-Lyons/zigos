const console = @import("../utils/console.zig");
const heap_geometry = @import("heap_geometry.zig");
const numfmt = @import("../utils/numfmt.zig");
const spin = @import("../utils/spin.zig");

const BYTES_PER_MIB: usize = 1024 * 1024;
const HEAP_SIZE: usize = 16 * BYTES_PER_MIB;
const MIN_BLOCK_SIZE = heap_geometry.minimum_free_data_size;
const BLOCK_ALIGNMENT = heap_geometry.block_alignment;

const PAGE_SIZE: usize = 4096;
extern var __kernel_end: u8;

fn alignUp(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
}

fn heapStartAddress() usize {
    return alignUp(@intFromPtr(&__kernel_end), PAGE_SIZE);
}

const BlockHeader = heap_geometry.BlockHeader;
const FreeLinks = heap_geometry.FreeLinks;

var heap_start: [*]u8 = undefined;

var heap_end: [*]u8 = undefined;
var free_list: ?*BlockHeader = null;
var is_initialized = false;
var allocator_lock = spin.Lock.init();

fn lockAllocator() void {
    allocator_lock.acquire();
}

fn unlockAllocator() void {
    allocator_lock.release();
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
    freeLinks(initial_block).* = .{ .next = null, .prev = null };

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
    const links = freeLinks(block);
    links.prev = null;
    links.next = free_list;
    if (free_list) |head| {
        freeLinks(head).prev = block;
    }
    free_list = block;
}

fn freeListRemove(block: *BlockHeader) void {
    const links = freeLinks(block);
    if (links.prev) |prev| {
        freeLinks(prev).next = links.next;
    } else {
        free_list = links.next;
    }
    if (links.next) |next| {
        freeLinks(next).prev = links.prev;
    }
    links.* = .{ .next = null, .prev = null };
}

fn freeLinks(block: *BlockHeader) *FreeLinks {
    const block_bytes: [*]u8 = @ptrCast(block);
    return @ptrCast(@alignCast(block_bytes + @sizeOf(BlockHeader)));
}

fn splitBlock(block: *BlockHeader, size: usize) void {
    const total_size = block.size;
    const remainder_size = heap_geometry.splitRemainder(
        total_size,
        size,
        @sizeOf(BlockHeader),
        MIN_BLOCK_SIZE,
    ) orelse return;
    const new_block_offset = @sizeOf(BlockHeader) + size;

    const block_bytes: [*]u8 = @ptrCast(block);
    const new_block: *BlockHeader = @ptrCast(@alignCast(block_bytes + new_block_offset));

    new_block.size = remainder_size;
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

fn takeFreeBlock(aligned_size: usize) ?*anyopaque {
    var current = free_list;
    while (current) |block| {
        const next_free = freeLinks(block).next;
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

    const aligned_size = heap_geometry.alignSize(size, BLOCK_ALIGNMENT) orelse return null;

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

    if (block.is_free) {
        return;
    }

    block.is_free = true;

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
