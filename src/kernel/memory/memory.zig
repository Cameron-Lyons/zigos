const builtin = @import("builtin");
const std = @import("std");
const console = @import("../utils/console.zig");
const heap_geometry = @import("heap_geometry.zig");
const numfmt = @import("../utils/numfmt.zig");
const spin = @import("../utils/spin.zig");
const boot_handoff = @import("../boot/handoff.zig");
const boot_image = @import("../../boot/image_info.zig");

pub const HEAP_SIZE: usize = boot_image.KERNEL_HEAP_BYTES;
const GRANULE = heap_geometry.granule;
const PAGE_SIZE: usize = 4096;
const MAX_SPANS: usize = 4096;
const SpanId = u16;
const NO_SPAN: SpanId = std.math.maxInt(SpanId);
const MAGAZINE_DEPTH: usize = 8;
pub const MAGAZINE_CPUS = @import("../cpu_identity.zig").MAX_CPUS;
const CLASS_COUNT = heap_geometry.free_list_class_count;

extern var __kernel_end: u8;
extern var __kernel_start: u8;

const SPAN_FREE: u8 = 0;
const SPAN_LIVE: u8 = 1;
const SPAN_MAGAZINE: u8 = 2;
const SPAN_CLAIMED: u8 = 3;

const Span = struct {
    offset: u32 = 0,
    length: u32 = 0,
    next_free: SpanId = NO_SPAN,
    previous_free: SpanId = NO_SPAN,
    address_next: SpanId = NO_SPAN,
    address_prev: SpanId = NO_SPAN,
    class_index: u8 = 0,
    state: u8 = SPAN_FREE,
};

const SPAN_LOOKUP_SLOTS: usize = MAX_SPANS * 2;

const Magazine = struct {
    len: u8 = 0,
    slots: [MAGAZINE_DEPTH]SpanId = @splat(NO_SPAN),
};

const CpuHeap = struct {
    recent_span: SpanId = NO_SPAN,
    recent_payload: usize = 0,
    classes: [CLASS_COUNT]Magazine = @as([CLASS_COUNT]Magazine, @splat(.{})),
};

const CpuHeapSlot = struct {
    heap: CpuHeap align(128) = .{},
};

comptime {
    if (MAX_SPANS >= NO_SPAN or !std.math.isPowerOfTwo(SPAN_LOOKUP_SLOTS)) {
        @compileError("heap span indices require a reserved sentinel and power-of-two lookup capacity");
    }
    if (@alignOf(CpuHeapSlot) < 128 or @sizeOf(CpuHeapSlot) % 128 != 0) {
        @compileError("per-CPU heap magazines must occupy distinct cache lines");
    }
}

var heap_base_address: usize = 0;
var payload_base: usize = 0;
var payload_bytes: usize = 0;
var early_claimed_bytes: usize = 0;
var is_initialized = false;
var allocator_lock = spin.Lock.init();
var spans: [MAX_SPANS]Span = @as([MAX_SPANS]Span, @splat(.{}));
var span_used: SpanId = 0;
var recycled: SpanId = NO_SPAN;
var address_head: SpanId = NO_SPAN;
var class_heads: [CLASS_COUNT]SpanId = @splat(NO_SPAN);
var cpu_heaps: [MAGAZINE_CPUS]CpuHeapSlot = @as([MAGAZINE_CPUS]CpuHeapSlot, @splat(.{}));
var span_lookup: [SPAN_LOOKUP_SLOTS]SpanId = @splat(NO_SPAN);

pub const metadata_layout = .{
    .span_capacity = MAX_SPANS,
    .span_bytes = @sizeOf(Span),
    .index_bytes = @sizeOf(SpanId),
    .array_bytes = @sizeOf(@TypeOf(spans)) + @sizeOf(@TypeOf(span_lookup)) +
        @sizeOf(@TypeOf(class_heads)) + @sizeOf(@TypeOf(cpu_heaps)),
};

fn alignUp(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
}

pub fn heapStartAddress() usize {
    const info = boot_handoff.capturedInfo() orelse @panic("missing EFI heap handoff");
    const image = info.boot_image orelse @panic("missing EFI heap reservation");
    return @intCast(image.heap_base);
}

pub fn kernelStartAddress() usize {
    return @intFromPtr(&__kernel_start);
}

pub fn kernelEndAddress() usize {
    return alignUp(@intFromPtr(&__kernel_end), PAGE_SIZE);
}

fn currentCpu() usize {
    if (comptime builtin.os.tag != .freestanding) return 0;
    return @import("../cpu_identity.zig").currentIndex();
}

fn pauseInterrupts() bool {
    if (comptime builtin.os.tag != .freestanding) return false;
    const x86 = @import("../../arch/x86.zig");
    const enabled = x86.interruptsEnabled();
    if (enabled) x86.cli();
    return enabled;
}

fn resumeInterrupts(were_enabled: bool) void {
    if (!were_enabled) return;
    @import("../../arch/x86.zig").sti();
}

fn loadSpanState(id: SpanId) u8 {
    return @atomicLoad(u8, &spans[id].state, .acquire);
}

fn storeSpanState(id: SpanId, state: u8) void {
    @atomicStore(u8, &spans[id].state, state, .release);
}

fn claimLiveSpan(id: SpanId) bool {
    return @cmpxchgStrong(u8, &spans[id].state, SPAN_LIVE, SPAN_CLAIMED, .acq_rel, .acquire) == null;
}

fn cpuHeap(cpu: usize) *CpuHeap {
    return &cpu_heaps[cpu].heap;
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

    resetArena();
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

// Host validation exercises exactly the production allocator against a bounded arena.
pub fn initHostArena(arena: []u8) error{ TooSmall, TooLarge }!void {
    if (comptime builtin.os.tag == .freestanding) @compileError("host arenas are unavailable in the kernel");
    if (arena.len > HEAP_SIZE) return error.TooLarge;
    const base = heap_geometry.alignSize(@intFromPtr(arena.ptr), GRANULE) orelse return error.TooSmall;
    const skipped = base - @intFromPtr(arena.ptr);
    if (skipped > arena.len or arena.len - skipped < GRANULE) return error.TooSmall;
    payload_base = base;
    payload_bytes = (arena.len - skipped) & ~(GRANULE - 1);
    resetArena();
}

fn resetArena() void {
    spans = @as([MAX_SPANS]Span, @splat(.{}));
    span_used = 0;
    recycled = NO_SPAN;
    address_head = NO_SPAN;
    class_heads = @splat(NO_SPAN);
    cpu_heaps = @as([MAGAZINE_CPUS]CpuHeapSlot, @splat(.{}));
    span_lookup = @splat(NO_SPAN);

    const initial = createSpan(0, @intCast(payload_bytes)) orelse @panic("kernel heap span table is exhausted");
    address_head = initial;
    pushFree(initial);
    is_initialized = true;
}

pub fn kmalloc(size: usize) ?*anyopaque {
    if (!is_initialized or size == 0) return null;
    const interrupts = pauseInterrupts();
    defer resumeInterrupts(interrupts);
    const aligned = heap_geometry.alignSize(size, GRANULE) orelse return null;
    const class_index = heap_geometry.freeListIndex(aligned, PAGE_SIZE);
    if (heap_geometry.sizeClassBytes(class_index)) |_| {
        if (popMagazine(currentCpu(), class_index)) |span_id| {
            return @ptrFromInt(payload_base + spans[span_id].offset);
        }
    }
    lockAllocator();
    defer unlockAllocator();
    return allocateLocked(size);
}

pub fn kfree(ptr: ?*anyopaque) void {
    if (ptr == null or !is_initialized) return;
    const interrupts = pauseInterrupts();
    defer resumeInterrupts(interrupts);
    const payload = @intFromPtr(ptr.?);
    const cpu = currentCpu();
    if (recentSpan(cpu, payload)) |span_id| {
        if (pushMagazine(cpu, span_id)) return;
    }
    lockAllocator();
    defer unlockAllocator();
    const span_id = spanForPayload(payload) orelse return;
    if (!claimLiveSpan(span_id)) return;
    invalidateRecent(cpu, span_id);
    releaseSpan(span_id);
}

fn allocateLocked(size: usize) ?*anyopaque {
    const aligned = heap_geometry.alignSize(size, GRANULE) orelse return null;
    const class_index = heap_geometry.freeListIndex(aligned, PAGE_SIZE);
    const request = heap_geometry.sizeClassBytes(class_index) orelse aligned;
    const cpu = currentCpu();
    const span_id = popMagazine(cpu, class_index) orelse takeSpan(class_index, request) orelse return null;
    storeSpanState(span_id, SPAN_LIVE);
    noteRecent(cpu, span_id);
    return @ptrFromInt(payload_base + spans[span_id].offset);
}

fn releaseSpan(span_id: SpanId) void {
    const class_index: usize = spans[span_id].class_index;
    if (heap_geometry.reusableMagazineBytes(class_index, @as(usize, spans[span_id].length)) != null) {
        const cpu = currentCpu();
        var magazine = &cpuHeap(cpu).classes[class_index];
        if (magazine.len < MAGAZINE_DEPTH) {
            storeSpanState(span_id, SPAN_MAGAZINE);
            magazine.slots[magazine.len] = span_id;
            magazine.len += 1;
            return;
        }
    }
    freeSpan(span_id);
}

fn pushMagazine(cpu: usize, span_id: SpanId) bool {
    const class_index: usize = spans[span_id].class_index;
    if (heap_geometry.reusableMagazineBytes(class_index, @as(usize, spans[span_id].length)) == null) return false;
    var magazine = &cpuHeap(cpu).classes[class_index];
    if (magazine.len >= MAGAZINE_DEPTH) return false;
    if (!claimLiveSpan(span_id)) return true;
    storeSpanState(span_id, SPAN_MAGAZINE);
    magazine.slots[magazine.len] = span_id;
    magazine.len += 1;
    invalidateRecent(cpu, span_id);
    return true;
}

fn popMagazine(cpu: usize, class_index: usize) ?SpanId {
    const class_bytes = heap_geometry.sizeClassBytes(class_index) orelse return null;
    var magazine = &cpuHeap(cpu).classes[class_index];
    if (magazine.len == 0) return null;
    magazine.len -= 1;
    const span_id = magazine.slots[magazine.len];
    if (@as(usize, spans[span_id].length) != class_bytes) @panic("kernel heap magazine span length mismatch");
    storeSpanState(span_id, SPAN_LIVE);
    noteRecent(cpu, span_id);
    return span_id;
}

fn createSpan(offset: u32, length: u32) ?SpanId {
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

fn recycleSpan(id: SpanId) void {
    forgetSpan(id);
    for (0..MAGAZINE_CPUS) |cpu| invalidateRecent(cpu, id);
    spans[id] = .{};
    spans[id].next_free = recycled;
    recycled = id;
}

fn pushFree(id: SpanId) void {
    const class_index = heap_geometry.freeListIndex(spans[id].length, PAGE_SIZE);
    spans[id].class_index = @intCast(class_index);
    storeSpanState(id, SPAN_FREE);
    spans[id].next_free = class_heads[class_index];
    spans[id].previous_free = NO_SPAN;
    if (class_heads[class_index] != NO_SPAN) spans[class_heads[class_index]].previous_free = id;
    class_heads[class_index] = id;
}

fn unlinkFree(id: SpanId) void {
    const class_index = spans[id].class_index;
    const previous = spans[id].previous_free;
    const next = spans[id].next_free;
    if (previous == NO_SPAN) {
        if (class_heads[class_index] != id) @panic("kernel heap free-list head mismatch");
        class_heads[class_index] = next;
    } else {
        if (spans[previous].next_free != id) @panic("kernel heap free-list predecessor mismatch");
        spans[previous].next_free = next;
    }
    if (next != NO_SPAN) {
        if (spans[next].previous_free != id) @panic("kernel heap free-list successor mismatch");
        spans[next].previous_free = previous;
    }
    spans[id].next_free = NO_SPAN;
    spans[id].previous_free = NO_SPAN;
}

fn takeSpan(start_class: usize, request: usize) ?SpanId {
    var class_index = start_class;
    while (class_index < CLASS_COUNT) : (class_index += 1) {
        var current = class_heads[class_index];
        while (current != NO_SPAN) {
            if (spans[current].length >= request) {
                unlinkFree(current);
                splitRemainder(current, @intCast(request));
                spans[current].class_index = @intCast(start_class);
                return current;
            }
            current = spans[current].next_free;
        }
    }
    return null;
}

fn splitRemainder(id: SpanId, request: u32) void {
    const length = spans[id].length;
    const remainder = heap_geometry.splitRemainder(length, request, 0, GRANULE) orelse return;
    const rest = createSpan(spans[id].offset + request, @intCast(remainder)) orelse return;
    spans[id].length = request;
    insertAfter(id, rest);
    pushFree(rest);
}

fn insertAfter(id: SpanId, rest: SpanId) void {
    const next = spans[id].address_next;
    spans[rest].address_prev = id;
    spans[rest].address_next = next;
    spans[id].address_next = rest;
    if (next != NO_SPAN) spans[next].address_prev = rest;
}

fn unlinkAddress(id: SpanId) void {
    const previous = spans[id].address_prev;
    const next = spans[id].address_next;
    if (previous == NO_SPAN) {
        address_head = next;
    } else {
        spans[previous].address_next = next;
    }
    if (next != NO_SPAN) spans[next].address_prev = previous;
}

fn freeSpan(id: SpanId) void {
    var current = id;
    storeSpanState(current, SPAN_FREE);
    if (spans[current].address_next != NO_SPAN) {
        const next = spans[current].address_next;
        if (loadSpanState(next) == SPAN_FREE) {
            unlinkFree(next);
            spans[current].length += spans[next].length;
            unlinkAddress(next);
            recycleSpan(next);
        }
    }
    if (spans[current].address_prev != NO_SPAN) {
        const previous = spans[current].address_prev;
        if (loadSpanState(previous) == SPAN_FREE) {
            unlinkFree(previous);
            spans[previous].length += spans[current].length;
            unlinkAddress(current);
            recycleSpan(current);
            current = previous;
        }
    }
    pushFree(current);
}

fn noteRecent(cpu: usize, span_id: SpanId) void {
    const heap = cpuHeap(cpu);
    heap.recent_span = span_id;
    heap.recent_payload = payload_base + spans[span_id].offset;
}

fn invalidateRecent(cpu: usize, span_id: SpanId) void {
    const heap = cpuHeap(cpu);
    if (heap.recent_span != span_id) return;
    heap.recent_span = NO_SPAN;
    heap.recent_payload = 0;
}

fn recentSpan(cpu: usize, payload: usize) ?SpanId {
    const heap = cpuHeap(cpu);
    if (heap.recent_span == NO_SPAN or payload != heap.recent_payload) return null;
    if (payload < payload_base) return null;
    const offset = payload - payload_base;
    if (spans[heap.recent_span].offset != offset) return null;
    return heap.recent_span;
}

fn spanForPayload(payload: usize) ?SpanId {
    if (recentSpan(currentCpu(), payload)) |span_id| return span_id;
    return findSpan(payload);
}

fn spanLookupSlot(offset: u32) usize {
    // Heap offsets are granule-aligned. Use the high product bits so large
    // aligned spans do not all land in the same one or two low-bit buckets.
    const product = (offset / @as(u32, GRANULE)) *% @as(u32, 0x9E37_79B1);
    const shift: u5 = comptime 32 - std.math.log2_int(usize, SPAN_LOOKUP_SLOTS);
    return product >> shift;
}

fn rememberSpan(id: SpanId) void {
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

fn forgetSpan(id: SpanId) void {
    var slot = spanLookupSlot(spans[id].offset);
    var steps: usize = 0;
    while (steps < SPAN_LOOKUP_SLOTS) : (steps += 1) {
        const found = span_lookup[slot];
        if (found == NO_SPAN) return;
        if (found == id) {
            // Move only entries whose probe path crosses the hole, in one
            // bounded pass rather than reinserting the whole cluster.
            var hole = slot;
            var next = (slot + 1) & (SPAN_LOOKUP_SLOTS - 1);
            for (0..SPAN_LOOKUP_SLOTS - 1) |_| {
                const moved = span_lookup[next];
                if (moved == NO_SPAN) break;
                const home = spanLookupSlot(spans[moved].offset);
                if (((hole + SPAN_LOOKUP_SLOTS - home) & (SPAN_LOOKUP_SLOTS - 1)) <
                    ((next + SPAN_LOOKUP_SLOTS - home) & (SPAN_LOOKUP_SLOTS - 1)))
                {
                    span_lookup[hole] = moved;
                    hole = next;
                }
                next = (next + 1) & (SPAN_LOOKUP_SLOTS - 1);
            }
            span_lookup[hole] = NO_SPAN;
            return;
        }
        slot = (slot + 1) & (SPAN_LOOKUP_SLOTS - 1);
    }
}

fn findSpan(payload: usize) ?SpanId {
    if (payload < payload_base) return null;
    const offset_usize = payload - payload_base;
    if (offset_usize >= payload_bytes or offset_usize % GRANULE != 0 or offset_usize > std.math.maxInt(u32)) return null;
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
    return loadSpanState(span_id) == SPAN_LIVE;
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
    if (loadSpanState(span_id) != SPAN_LIVE) return null;
    return spans[span_id].length;
}

test "heap address hashing distributes page-aligned spans across the table" {
    for ([_]u32{ PAGE_SIZE, 2 * PAGE_SIZE }) |stride| {
        var occupied: [SPAN_LOOKUP_SLOTS]bool = @splat(false);
        for (0..MAX_SPANS) |index| occupied[spanLookupSlot(@as(u32, @intCast(index)) * stride)] = true;
        var count: usize = 0;
        for (occupied) |used| count += @intFromBool(used);
        try std.testing.expect(count >= MAX_SPANS / 2);
    }
}
