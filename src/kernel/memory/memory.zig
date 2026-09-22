const builtin = @import("builtin");
const std = @import("std");
const console = @import("../utils/console.zig");
const heap_geometry = @import("heap_geometry.zig");
const numfmt = @import("../utils/numfmt.zig");
const spin = @import("../utils/spin.zig");

const BYTES_PER_MIB: usize = 1024 * 1024;
pub const HEAP_SIZE: usize = 32 * BYTES_PER_MIB;
const GRANULE = heap_geometry.granule;
const PAGE_SIZE: usize = 4096;
const MAX_SPANS: usize = 4096;
const NO_SPAN: u32 = std.math.maxInt(u32);
const MAGAZINE_DEPTH: usize = 8;
pub const MAGAZINE_CPUS: usize = 8;
const CLASS_COUNT = heap_geometry.free_list_class_count;

extern var __kernel_end: u8;

const Span = struct {
    offset: u32 = 0,
    length: u32 = 0,
    next_free: u32 = NO_SPAN,
    address_next: u32 = NO_SPAN,
    address_prev: u32 = NO_SPAN,
    class_index: u8 = 0,
    live: bool = false,
    in_magazine: bool = false,
};

const SPAN_LOOKUP_SLOTS: usize = 8192;

const Magazine = struct {
    len: u8 = 0,
    slots: [MAGAZINE_DEPTH]u32 = .{NO_SPAN} ** MAGAZINE_DEPTH,
};

var heap_base_address: usize = 0;
var payload_base: usize = 0;
var payload_bytes: usize = 0;
var early_claimed_bytes: usize = 0;
var is_initialized = false;
var allocator_lock = spin.Lock.init();
var spans: [MAX_SPANS]Span = [_]Span{.{}} ** MAX_SPANS;
var span_used: u32 = 0;
var recycled: u32 = NO_SPAN;
var address_head: u32 = NO_SPAN;
var class_heads: [CLASS_COUNT]u32 = .{NO_SPAN} ** CLASS_COUNT;
var magazines: [MAGAZINE_CPUS][CLASS_COUNT]Magazine = [_][CLASS_COUNT]Magazine{[_]Magazine{.{}} ** CLASS_COUNT} ** MAGAZINE_CPUS;
var span_lookup: [SPAN_LOOKUP_SLOTS]u32 = .{NO_SPAN} ** SPAN_LOOKUP_SLOTS;
var recent_span: u32 = NO_SPAN;
var recent_payload: usize = 0;

fn alignUp(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
}

fn heapStartAddress() usize {
    return alignUp(@intFromPtr(&__kernel_end), PAGE_SIZE);
}

pub fn getReservedMemoryEnd() usize {
    return heapStartAddress() + HEAP_SIZE;
}

fn currentCpu() usize {
    if (comptime builtin.os.tag != .freestanding) return 0;
    // CpuState.cpu_index lives at GS+16. A segment load stays on the allocate/free path;
    // reading IA32_GS_BASE with RDMSR does not.
    const index = asm volatile ("movq %%gs:16, %[out]"
        : [out] "=r" (-> usize),
    );
    if (index >= MAGAZINE_CPUS) return 0;
    return index;
}

fn lockAllocator() void {
    allocator_lock.acquire();
}

fn unlockAllocator() void {
    allocator_lock.release();
}

pub fn claimEarly(bytes: usize, alignment: usize) ?*anyopaque {
    if (is_initialized) return null;

    const heap_base = heapStartAddress();
    const cursor = std.math.add(usize, heap_base, early_claimed_bytes) catch return null;
    const claim_limit = std.math.add(usize, heap_base, HEAP_SIZE - GRANULE) catch return null;
    const claim = heap_geometry.claimAlignedRange(cursor, bytes, alignment, claim_limit) orelse return null;
    early_claimed_bytes = claim.end - heap_base;
    return @ptrFromInt(claim.start);
}

pub fn init() void {
    heap_base_address = heapStartAddress();
    payload_base = alignUp(heap_base_address + early_claimed_bytes, GRANULE);
    const heap_end = heap_base_address + HEAP_SIZE;
    if (payload_base >= heap_end) @panic("kernel heap has no payload");
    payload_bytes = (heap_end - payload_base) & ~(GRANULE - 1);
    if (payload_bytes < GRANULE) @panic("kernel heap payload is smaller than one granule");

    spans = [_]Span{.{}} ** MAX_SPANS;
    span_used = 0;
    recycled = NO_SPAN;
    address_head = NO_SPAN;
    class_heads = .{NO_SPAN} ** CLASS_COUNT;
    magazines = [_][CLASS_COUNT]Magazine{[_]Magazine{.{}} ** CLASS_COUNT} ** MAGAZINE_CPUS;
    span_lookup = .{NO_SPAN} ** SPAN_LOOKUP_SLOTS;
    recent_span = NO_SPAN;
    recent_payload = 0;

    const initial = createSpan(0, @intCast(payload_bytes)) orelse @panic("kernel heap span table is exhausted");
    address_head = initial;
    pushFree(initial);
    is_initialized = true;
    verifyAllocationStartGuards();
    verifyOverflowSpansKeepTheirLength();

    console.print("Memory allocator initialized!\n");
    console.print("Heap start: 0x");
    numfmt.printHex(payload_base);
    console.print("\nEarly heap state: ");
    numfmt.printDec(early_claimed_bytes);
    console.print(" bytes\nHeap allocatable: ");
    numfmt.printDec(payload_bytes);
    console.print(" bytes\n");
}

pub fn kmalloc(size: usize) ?*anyopaque {
    if (!is_initialized or size == 0) return null;
    lockAllocator();
    defer unlockAllocator();
    return allocateLocked(size);
}

pub fn kfree(ptr: ?*anyopaque) void {
    if (ptr == null or !is_initialized) return;
    lockAllocator();
    defer unlockAllocator();
    const payload = @intFromPtr(ptr.?);
    const span_id = spanForPayload(payload) orelse return;
    if (!spans[span_id].live) return;
    invalidateRecent(span_id);
    releaseSpan(span_id);
}

fn allocateLocked(size: usize) ?*anyopaque {
    const aligned = heap_geometry.alignSize(size, GRANULE) orelse return null;
    const class_index = heap_geometry.freeListIndex(aligned, PAGE_SIZE);
    const request = heap_geometry.sizeClassBytes(class_index) orelse aligned;
    const cpu = currentCpu();
    const span_id = popMagazine(cpu, class_index) orelse takeSpan(class_index, request) orelse return null;
    spans[span_id].live = true;
    spans[span_id].in_magazine = false;
    noteRecent(span_id);
    return @ptrFromInt(payload_base + spans[span_id].offset);
}

fn releaseSpan(span_id: u32) void {
    const class_index: usize = spans[span_id].class_index;
    if (heap_geometry.reusableMagazineBytes(class_index, @as(usize, spans[span_id].length)) != null) {
        const cpu = currentCpu();
        var magazine = &magazines[cpu][class_index];
        if (magazine.len < MAGAZINE_DEPTH) {
            spans[span_id].live = false;
            spans[span_id].in_magazine = true;
            magazine.slots[magazine.len] = span_id;
            magazine.len += 1;
            return;
        }
    }
    freeSpan(span_id);
}

fn popMagazine(cpu: usize, class_index: usize) ?u32 {
    const class_bytes = heap_geometry.sizeClassBytes(class_index) orelse return null;
    var magazine = &magazines[cpu][class_index];
    if (magazine.len == 0) return null;
    magazine.len -= 1;
    const span_id = magazine.slots[magazine.len];
    if (@as(usize, spans[span_id].length) != class_bytes) @panic("kernel heap magazine span length mismatch");
    return span_id;
}

fn createSpan(offset: u32, length: u32) ?u32 {
    const id = if (recycled != NO_SPAN) recycled_id: {
        const recycled_id = recycled;
        recycled = spans[recycled_id].next_free;
        break :recycled_id recycled_id;
    } else if (span_used < MAX_SPANS) created: {
        const created = span_used;
        span_used += 1;
        break :created created;
    } else return null;
    spans[id] = .{
        .offset = offset,
        .length = length,
    };
    rememberSpan(id);
    return id;
}

fn recycleSpan(id: u32) void {
    forgetSpan(id);
    invalidateRecent(id);
    spans[id] = .{};
    spans[id].next_free = recycled;
    recycled = id;
}

fn pushFree(id: u32) void {
    const class_index = heap_geometry.freeListIndex(spans[id].length, PAGE_SIZE);
    spans[id].class_index = @intCast(class_index);
    spans[id].live = false;
    spans[id].in_magazine = false;
    spans[id].next_free = class_heads[class_index];
    class_heads[class_index] = id;
}

fn unlinkFree(id: u32) void {
    const class_index = spans[id].class_index;
    var previous = NO_SPAN;
    var current = class_heads[class_index];
    while (current != NO_SPAN) {
        if (current == id) {
            if (previous == NO_SPAN) {
                class_heads[class_index] = spans[current].next_free;
            } else {
                spans[previous].next_free = spans[current].next_free;
            }
            spans[id].next_free = NO_SPAN;
            return;
        }
        previous = current;
        current = spans[current].next_free;
    }
}

fn takeSpan(start_class: usize, request: usize) ?u32 {
    var class_index = start_class;
    while (class_index < CLASS_COUNT) : (class_index += 1) {
        var previous = NO_SPAN;
        var current = class_heads[class_index];
        while (current != NO_SPAN) {
            if (spans[current].length >= request) {
                if (previous == NO_SPAN) {
                    class_heads[class_index] = spans[current].next_free;
                } else {
                    spans[previous].next_free = spans[current].next_free;
                }
                spans[current].next_free = NO_SPAN;
                splitRemainder(current, @intCast(request));
                spans[current].class_index = @intCast(start_class);
                return current;
            }
            previous = current;
            current = spans[current].next_free;
        }
    }
    return null;
}

fn splitRemainder(id: u32, request: u32) void {
    const length = spans[id].length;
    const remainder = heap_geometry.splitRemainder(length, request, 0, GRANULE) orelse return;
    const rest = createSpan(spans[id].offset + request, @intCast(remainder)) orelse return;
    spans[id].length = request;
    insertAfter(id, rest);
    pushFree(rest);
}

fn insertAfter(id: u32, rest: u32) void {
    const next = spans[id].address_next;
    spans[rest].address_prev = id;
    spans[rest].address_next = next;
    spans[id].address_next = rest;
    if (next != NO_SPAN) spans[next].address_prev = rest;
}

fn unlinkAddress(id: u32) void {
    const previous = spans[id].address_prev;
    const next = spans[id].address_next;
    if (previous == NO_SPAN) {
        address_head = next;
    } else {
        spans[previous].address_next = next;
    }
    if (next != NO_SPAN) spans[next].address_prev = previous;
}

fn freeSpan(id: u32) void {
    var current = id;
    spans[current].live = false;
    spans[current].in_magazine = false;
    if (spans[current].address_next != NO_SPAN) {
        const next = spans[current].address_next;
        if (!spans[next].live and !spans[next].in_magazine) {
            unlinkFree(next);
            spans[current].length += spans[next].length;
            unlinkAddress(next);
            recycleSpan(next);
        }
    }
    if (spans[current].address_prev != NO_SPAN) {
        const previous = spans[current].address_prev;
        if (!spans[previous].live and !spans[previous].in_magazine) {
            unlinkFree(previous);
            spans[previous].length += spans[current].length;
            unlinkAddress(current);
            recycleSpan(current);
            current = previous;
        }
    }
    pushFree(current);
}

fn noteRecent(span_id: u32) void {
    recent_span = span_id;
    recent_payload = payload_base + spans[span_id].offset;
}

fn invalidateRecent(span_id: u32) void {
    if (recent_span != span_id) return;
    recent_span = NO_SPAN;
    recent_payload = 0;
}

fn spanForPayload(payload: usize) ?u32 {
    if (recent_span != NO_SPAN and payload == recent_payload) {
        const offset = payload - payload_base;
        if (spans[recent_span].offset == offset) return recent_span;
    }
    return findSpan(payload);
}

fn spanLookupSlot(offset: u32) usize {
    return (@as(usize, offset) *% 0x9E3779B1) & (SPAN_LOOKUP_SLOTS - 1);
}

fn rememberSpan(id: u32) void {
    var slot = spanLookupSlot(spans[id].offset);
    var steps: usize = 0;
    while (steps < SPAN_LOOKUP_SLOTS) : (steps += 1) {
        const found = span_lookup[slot];
        if (found == NO_SPAN or found == id) {
            span_lookup[slot] = id;
            return;
        }
        slot = (slot + 1) & (SPAN_LOOKUP_SLOTS - 1);
    }
    @panic("kernel heap span lookup is full");
}

fn forgetSpan(id: u32) void {
    var slot = spanLookupSlot(spans[id].offset);
    var steps: usize = 0;
    while (steps < SPAN_LOOKUP_SLOTS) : (steps += 1) {
        const found = span_lookup[slot];
        if (found == NO_SPAN) return;
        if (found == id) {
            span_lookup[slot] = NO_SPAN;
            var next = (slot + 1) & (SPAN_LOOKUP_SLOTS - 1);
            while (span_lookup[next] != NO_SPAN) {
                const moved = span_lookup[next];
                span_lookup[next] = NO_SPAN;
                rememberSpan(moved);
                next = (next + 1) & (SPAN_LOOKUP_SLOTS - 1);
            }
            return;
        }
        slot = (slot + 1) & (SPAN_LOOKUP_SLOTS - 1);
    }
}

fn findSpan(payload: usize) ?u32 {
    if (payload < payload_base) return null;
    const offset_usize = payload - payload_base;
    if (offset_usize >= payload_bytes or offset_usize > std.math.maxInt(u32)) return null;
    const offset: u32 = @intCast(offset_usize);
    var slot = spanLookupSlot(offset);
    var steps: usize = 0;
    while (steps < SPAN_LOOKUP_SLOTS) : (steps += 1) {
        const id = span_lookup[slot];
        if (id == NO_SPAN) return null;
        if (spans[id].offset == offset) return id;
        slot = (slot + 1) & (SPAN_LOOKUP_SLOTS - 1);
    }
    return null;
}

fn allocationIsLive(payload: usize) bool {
    const span_id = findSpan(payload) orelse return false;
    return spans[span_id].live;
}

fn verifyAllocationStartGuards() void {
    const allocation = allocateLocked(64) orelse @panic("kernel heap allocation guard self-check failed");
    const payload = @intFromPtr(allocation);
    kfree(@ptrFromInt(payload + GRANULE));
    if (!allocationIsLive(payload)) @panic("kernel heap accepted an interior free");
    kfree(allocation);
    if (allocationIsLive(payload)) @panic("kernel heap retained a released allocation marker");
    kfree(allocation);
    if (allocationIsLive(payload)) @panic("kernel heap accepted a duplicate free");
}

fn verifyOverflowSpansKeepTheirLength() void {
    const small = allocateLocked(8 * 1024) orelse @panic("kernel heap overflow self-check failed");
    const large = allocateLocked(16 * 1024) orelse @panic("kernel heap overflow self-check failed");
    kfree(large);
    kfree(small);
    const again = allocateLocked(16 * 1024) orelse @panic("kernel heap overflow self-check failed");
    const length = liveSpanLength(@intFromPtr(again)) orelse @panic("kernel heap overflow self-check lost the span");
    if (length < 16 * 1024) @panic("kernel heap reused a short overflow span");
    kfree(again);
}

fn liveSpanLength(payload: usize) ?u32 {
    const span_id = findSpan(payload) orelse return null;
    if (!spans[span_id].live) return null;
    return spans[span_id].length;
}
