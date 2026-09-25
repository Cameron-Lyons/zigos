const std = @import("std");
const console = @import("../utils/console.zig");
const heap_allocator = @import("heap_allocator.zig");
const heap_geometry = @import("heap_geometry.zig");
const numfmt = @import("../utils/numfmt.zig");
const spin = @import("../utils/spin.zig");

const HEAP_SIZE = heap_geometry.maximum_heap_bytes;
const PAGE_SIZE: usize = 4096;
extern var __kernel_end: u8;

var heap: heap_allocator.Heap = undefined;
var early_claimed_bytes: usize = 0;
var is_initialized = false;
var allocator_lock = spin.Lock.init();

fn heapStartAddress() usize {
    return heap_geometry.alignSize(@intFromPtr(&__kernel_end), PAGE_SIZE).?;
}

pub fn init() void {
    const heap_start = heapStartAddress() + early_claimed_bytes;
    const arena: [*]u8 = @ptrFromInt(heap_start);
    heap.init(arena[0 .. HEAP_SIZE - early_claimed_bytes]) catch
        @panic("insufficient kernel heap after early claims");
    is_initialized = true;
    verifyAllocationStartGuards();

    console.print("Memory allocator initialized!\n");
    console.print("Heap start: 0x");
    numfmt.printHex(heap_start);
    console.print("\nEarly heap state: ");
    numfmt.printDec(early_claimed_bytes);
    console.print(" bytes\nHeap allocatable: ");
    numfmt.printDec(heap.data.len - @sizeOf(heap_geometry.BlockHeader));
    console.print(" bytes\n");
}

pub fn claimEarly(bytes: usize, alignment: usize) ?*anyopaque {
    if (is_initialized) return null;
    const heap_base = heapStartAddress();
    const cursor = std.math.add(usize, heap_base, early_claimed_bytes) catch return null;
    const minimum_heap_bytes = heap_allocator.minimum_arena_bytes + heap_geometry.block_alignment - 1;
    const claim_limit = std.math.add(usize, heap_base, HEAP_SIZE - minimum_heap_bytes) catch return null;
    const claim = heap_geometry.claimAlignedRange(cursor, bytes, alignment, claim_limit) orelse return null;
    early_claimed_bytes = claim.end - heap_base;
    return @ptrFromInt(claim.start);
}

pub fn getReservedMemoryEnd() usize {
    return heapStartAddress() + HEAP_SIZE;
}

pub fn kmalloc(size: usize) ?*anyopaque {
    if (!is_initialized or size == 0) return null;
    allocator_lock.acquire();
    defer allocator_lock.release();
    return heap.allocate(size);
}

pub fn kfree(ptr: ?*anyopaque) void {
    if (ptr == null or !is_initialized) return;
    allocator_lock.acquire();
    defer allocator_lock.release();
    _ = heap.release(ptr);
}

fn verifyAllocationStartGuards() void {
    const allocation = kmalloc(64) orelse @panic("kernel heap allocation guard self-check failed");
    kfree(@ptrFromInt(@intFromPtr(allocation) + heap_geometry.block_alignment));
    if (heap.allocationSize(allocation) == null) @panic("kernel heap accepted an interior free");
    kfree(allocation);
    if (heap.allocationSize(allocation) != null) @panic("kernel heap retained a released allocation marker");
    kfree(allocation);
    if (heap.allocationSize(allocation) != null) @panic("kernel heap accepted a duplicate free");
}
