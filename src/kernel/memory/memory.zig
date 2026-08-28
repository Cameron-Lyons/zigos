const std = @import("std");
const console = @import("../utils/console.zig");
const heap_geometry = @import("heap_geometry.zig");
const numfmt = @import("../utils/numfmt.zig");
const spin = @import("../utils/spin.zig");

const BYTES_PER_MIB: usize = 1024 * 1024;
const HEAP_SIZE: usize = 16 * BYTES_PER_MIB;
const MIN_BLOCK_SIZE = heap_geometry.minimum_free_data_size;
const BLOCK_ALIGNMENT = heap_geometry.block_alignment;
const ALLOCATION_BITMAP_BYTES = HEAP_SIZE / BLOCK_ALIGNMENT / 8;

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
var free_lists: [heap_geometry.free_list_class_count]?*BlockHeader = .{null} ** heap_geometry.free_list_class_count;
var early_claimed_bytes: usize = 0;
var is_initialized = false;
var allocator_lock = spin.Lock.init();

fn lockAllocator() void {
    allocator_lock.acquire();
}

fn unlockAllocator() void {
    allocator_lock.release();
}

pub fn init() void {
    const heap_base = heapStartAddress();
    const heap_start_addr = heap_base + early_claimed_bytes;
    heap_start = @ptrFromInt(heap_start_addr);
    heap_end = @ptrFromInt(heap_base + HEAP_SIZE);
    @memset(allocationBitmap(), 0);

    const initial_block: *BlockHeader = @ptrFromInt(heapDataStartAddress());
    initial_block.size = heapByteCapacity() - ALLOCATION_BITMAP_BYTES - @sizeOf(BlockHeader);
    initial_block.state = heap_geometry.block_state_free;
    initial_block.next = null;
    initial_block.prev = null;
    free_lists = .{null} ** heap_geometry.free_list_class_count;
    freeListPush(initial_block);
    is_initialized = true;
    verifyAllocationStartGuards();

    console.print("Memory allocator initialized!\n");
    console.print("Heap start: 0x");
    numfmt.printHex(@intFromPtr(heap_start));
    console.print("\nEarly heap state: ");
    numfmt.printDec(early_claimed_bytes);
    console.print(" bytes\nHeap allocatable: ");
    numfmt.printDec(initial_block.size);
    console.print(" bytes\n");
}

pub fn claimEarly(bytes: usize, alignment: usize) ?*anyopaque {
    if (is_initialized) return null;

    const heap_base = heapStartAddress();
    const cursor = std.math.add(usize, heap_base, early_claimed_bytes) catch return null;
    const minimum_heap_bytes = ALLOCATION_BITMAP_BYTES + @sizeOf(BlockHeader) + MIN_BLOCK_SIZE;
    const claim_limit = std.math.add(usize, heap_base, HEAP_SIZE - minimum_heap_bytes) catch return null;
    const claim = heap_geometry.claimAlignedRange(cursor, bytes, alignment, claim_limit) orelse return null;
    early_claimed_bytes = claim.end - heap_base;
    return @ptrFromInt(claim.start);
}

pub fn getReservedMemoryEnd() usize {
    return heapStartAddress() + HEAP_SIZE;
}

fn freeListPush(block: *BlockHeader) void {
    const index = freeListIndex(block.size);
    const links = freeLinks(block);
    links.prev = null;
    links.next = free_lists[index];
    if (free_lists[index]) |head| {
        freeLinks(head).prev = block;
    }
    free_lists[index] = block;
}

fn freeListRemove(block: *BlockHeader) void {
    const index = freeListIndex(block.size);
    const links = freeLinks(block);
    if (links.prev) |prev| {
        freeLinks(prev).next = links.next;
    } else {
        free_lists[index] = links.next;
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

fn freeListIndex(size: usize) usize {
    return heap_geometry.freeListIndex(size, PAGE_SIZE);
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
    new_block.state = heap_geometry.block_state_free;
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
    var index = freeListIndex(aligned_size);
    while (index < free_lists.len) : (index += 1) {
        var current = free_lists[index];
        while (current) |block| {
            const next_free = freeLinks(block).next;
            if (block.size >= aligned_size) {
                freeListRemove(block);
                splitBlock(block, aligned_size);
                block.state = heap_geometry.block_state_allocated;

                const data_ptr: [*]u8 = @ptrCast(block);
                const payload: *anyopaque = @ptrCast(data_ptr + @sizeOf(BlockHeader));
                setAllocationMarker(allocationBitIndex(@intFromPtr(payload)), true);
                return payload;
            }
            current = next_free;
        }
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

    const payload_address = @intFromPtr(ptr.?);
    const heap_start_address = heapDataStartAddress();
    if (payload_address < heap_start_address + @sizeOf(BlockHeader)) return;
    const bit_index = allocationMarkerIndex(payload_address) orelse return;

    const block_address = payload_address - @sizeOf(BlockHeader);
    const block: *BlockHeader = @ptrFromInt(block_address);
    if (!allocationStartMarked(bit_index) or
        block.state != heap_geometry.block_state_allocated)
    {
        return;
    }
    setAllocationMarker(bit_index, false);
    block.state = heap_geometry.block_state_free;

    if (block.next) |next| {
        if (blockIsFree(next)) {
            freeListRemove(next);
            block.size += @sizeOf(BlockHeader) + next.size;
            block.next = next.next;
            if (next.next) |next_next| {
                next_next.prev = block;
            }
            next.state = 0;
        }
    }

    if (block.prev) |prev| {
        if (blockIsFree(prev)) {
            freeListRemove(prev);
            prev.size += @sizeOf(BlockHeader) + block.size;
            prev.next = block.next;
            if (block.next) |next| {
                next.prev = prev;
            }
            block.state = 0;
            freeListPush(prev);
            return;
        }
    }

    freeListPush(block);
}

fn blockIsFree(block: *const BlockHeader) bool {
    return block.state == heap_geometry.block_state_free;
}

fn heapDataStartAddress() usize {
    return @intFromPtr(heap_start) + ALLOCATION_BITMAP_BYTES;
}

fn heapByteCapacity() usize {
    return @intFromPtr(heap_end) - @intFromPtr(heap_start);
}

fn heapDataCapacity() usize {
    return heapByteCapacity() - ALLOCATION_BITMAP_BYTES;
}

fn allocationBitmap() *[ALLOCATION_BITMAP_BYTES]u8 {
    return @ptrCast(heap_start);
}

fn allocationStartMarked(bit_index: usize) bool {
    const mask = @as(u8, 1) << @as(u3, @truncate(bit_index));
    return (allocationBitmap()[bit_index / 8] & mask) != 0;
}

fn setAllocationMarker(bit_index: usize, is_live: bool) void {
    const byte = &allocationBitmap()[bit_index / 8];
    const mask = @as(u8, 1) << @as(u3, @truncate(bit_index));
    if (is_live) {
        byte.* |= mask;
    } else {
        byte.* &= ~mask;
    }
}

fn allocationMarkerIndex(payload_address: usize) ?usize {
    return heap_geometry.allocationMarkerIndex(
        payload_address,
        heapDataStartAddress(),
        heapDataCapacity(),
        BLOCK_ALIGNMENT,
    );
}

fn allocationBitIndex(payload_address: usize) usize {
    return (payload_address - heapDataStartAddress()) / BLOCK_ALIGNMENT;
}

fn verifyAllocationStartGuards() void {
    const allocation = kmalloc(64) orelse @panic("kernel heap allocation guard self-check failed");
    const payload_address = @intFromPtr(allocation);
    const bit_index = allocationBitIndex(payload_address);

    kfree(@ptrFromInt(payload_address + BLOCK_ALIGNMENT));
    if (!allocationStartMarked(bit_index)) {
        @panic("kernel heap accepted an interior free");
    }

    kfree(allocation);
    if (allocationStartMarked(bit_index)) {
        @panic("kernel heap retained a released allocation marker");
    }

    kfree(allocation);
    if (allocationStartMarked(bit_index)) {
        @panic("kernel heap accepted a duplicate free");
    }
}
