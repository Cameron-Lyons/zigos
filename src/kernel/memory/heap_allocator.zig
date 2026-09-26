const std = @import("std");
const geometry = @import("heap_geometry.zig");

const Header = geometry.BlockHeader;
const Links = geometry.FreeLinks;
const alignment = geometry.block_alignment;
pub const minimum_arena_bytes = alignment + @sizeOf(Header) + geometry.minimum_free_data_size;

// Borrows one caller-owned arena. The caller serializes mutations and keeps
// this handle and the arena alive; copying a live handle does not clone it.
pub const Heap = struct {
    data: []align(alignment) u8,
    allocation_starts: []u8,
    free_lists: [geometry.first_level_count][geometry.second_level_count]?*Header,
    nonempty_first: u32,
    nonempty_second: [geometry.first_level_count]u32,

    pub fn init(self: *Heap, arena: []u8) error{ TooSmall, TooLarge }!void {
        const start = geometry.alignSize(@intFromPtr(arena.ptr), alignment) orelse return error.TooSmall;
        const prefix = start - @intFromPtr(arena.ptr);
        if (prefix > arena.len) return error.TooSmall;
        const usable = (arena.len - prefix) & ~(alignment - 1);
        if (usable > geometry.maximum_heap_bytes) return error.TooLarge;
        const marker_bytes = geometry.alignSize((usable / alignment + 7) / 8, alignment).?;
        if (usable < marker_bytes + @sizeOf(Header) + geometry.minimum_free_data_size) return error.TooSmall;

        self.data = @alignCast(arena[prefix + marker_bytes ..][0 .. usable - marker_bytes]);
        self.allocation_starts = arena[prefix..][0..marker_bytes];
        @memset(self.allocation_starts, 0);
        for (&self.free_lists) |*row| @memset(row, null);
        @memset(&self.nonempty_second, 0);
        self.nonempty_first = 0;
        const block: *Header = @ptrCast(self.data.ptr);
        block.* = .{ .size = self.data.len - @sizeOf(Header), .state = geometry.block_state_free, .next = null, .prev = null };
        self.insertFree(block);
    }

    // Keep constant-sized requests and exhausted-bucket returns in the caller.
    pub inline fn allocate(self: *Heap, requested_size: usize) ?*anyopaque {
        const size = geometry.allocationSize(requested_size) orelse return null;
        const class = geometry.sizeClass(size);
        var first = class.first;
        var second_bits = self.nonempty_second[first] & (~@as(u32, 0) << class.second);
        if (second_bits == 0) {
            const first_bits = self.nonempty_first & (~@as(u32, 0) << (first + 1));
            if (first_bits == 0) return null;
            first = @intCast(@ctz(first_bits));
            second_bits = self.nonempty_second[first];
        }
        const second: u5 = @intCast(@ctz(second_bits));
        const block = self.free_lists[first][second].?;
        std.debug.assert(block.size >= size);
        self.removeFreeInClass(block, .{ .first = first, .second = second });
        self.split(block, size);
        block.state = geometry.block_state_allocated;
        const payload: [*]u8 = @as([*]u8, @ptrCast(block)) + @sizeOf(Header);
        // The selected block belongs to this arena and yields an aligned
        // payload. Untrusted release pointers still pass through liveHeader.
        const index = (@intFromPtr(payload) - @intFromPtr(self.data.ptr)) / alignment;
        std.debug.assert(self.markerIndex(@intFromPtr(payload)).? == index);
        self.setMarker(index, true);
        return payload;
    }

    pub fn allocationSize(self: *const Heap, ptr: ?*const anyopaque) ?usize {
        const block = self.liveHeader(ptr) orelse return null;
        return block.size;
    }

    pub fn release(self: *Heap, ptr: ?*anyopaque) bool {
        const block = self.liveHeader(ptr) orelse return false;
        self.setMarker(self.markerIndex(@intFromPtr(ptr.?)).?, false);
        block.state = geometry.block_state_free;
        if (block.next) |next| {
            if (next.state == geometry.block_state_free) {
                self.removeFree(next);
                block.size += @sizeOf(Header) + next.size;
                block.next = next.next;
                if (next.next) |successor| successor.prev = block;
                next.state = 0;
            }
        }
        if (block.prev) |prev| {
            if (prev.state == geometry.block_state_free) {
                self.removeFree(prev);
                prev.size += @sizeOf(Header) + block.size;
                prev.next = block.next;
                if (block.next) |next| next.prev = prev;
                block.state = 0;
                self.insertFree(prev);
                return true;
            }
        }
        self.insertFree(block);
        return true;
    }

    fn liveHeader(self: *const Heap, ptr: ?*const anyopaque) ?*Header {
        const address = @intFromPtr(ptr orelse return null);
        if (address < @intFromPtr(self.data.ptr) + @sizeOf(Header)) return null;
        const index = self.markerIndex(address) orelse return null;
        const mask = @as(u8, 1) << @as(u3, @truncate(index));
        // Reject interior, foreign, and duplicate frees before reading a header.
        if ((self.allocation_starts[index / 8] & mask) == 0) return null;
        const block: *Header = @ptrFromInt(address - @sizeOf(Header));
        return if (block.state == geometry.block_state_allocated) block else null;
    }

    fn markerIndex(self: *const Heap, address: usize) ?usize {
        return geometry.allocationMarkerIndex(address, @intFromPtr(self.data.ptr), self.data.len, alignment);
    }

    fn setMarker(self: *Heap, index: usize, live: bool) void {
        const byte = &self.allocation_starts[index / 8];
        const mask = @as(u8, 1) << @as(u3, @truncate(index));
        if (live) byte.* |= mask else byte.* &= ~mask;
    }

    fn insertFree(self: *Heap, block: *Header) void {
        const class = geometry.sizeClass(block.size);
        const head = &self.free_lists[class.first][class.second];
        links(block).* = .{ .prev = null, .next = head.* };
        if (head.*) |next| links(next).prev = block;
        head.* = block;
        self.nonempty_second[class.first] |= @as(u32, 1) << class.second;
        self.nonempty_first |= @as(u32, 1) << class.first;
    }

    fn removeFree(self: *Heap, block: *Header) void {
        self.removeFreeInClass(block, geometry.sizeClass(block.size));
    }

    fn removeFreeInClass(self: *Heap, block: *Header, class: geometry.SizeClass) void {
        const head = &self.free_lists[class.first][class.second];
        const neighbors = links(block).*;
        if (neighbors.prev) |prev| links(prev).next = neighbors.next else head.* = neighbors.next;
        if (neighbors.next) |next| links(next).prev = neighbors.prev;
        if (head.* == null) {
            self.nonempty_second[class.first] &= ~(@as(u32, 1) << class.second);
            if (self.nonempty_second[class.first] == 0) self.nonempty_first &= ~(@as(u32, 1) << class.first);
        }
    }

    fn split(self: *Heap, block: *Header, size: usize) void {
        const remainder = geometry.splitRemainder(block.size, size, @sizeOf(Header), geometry.minimum_free_data_size) orelse return;
        const next: *Header = @ptrFromInt(@intFromPtr(block) + @sizeOf(Header) + size);
        next.* = .{ .size = remainder, .state = geometry.block_state_free, .next = block.next, .prev = block };
        if (block.next) |successor| successor.prev = next;
        block.size = size;
        block.next = next;
        self.insertFree(next);
    }

    fn links(block: *Header) *Links {
        return @ptrFromInt(@intFromPtr(block) + @sizeOf(Header));
    }
};

comptime {
    if (geometry.first_level_count >= 32 or geometry.second_level_count != 32) {
        @compileError("heap size classes must fit the two-level bitmap search");
    }
}
