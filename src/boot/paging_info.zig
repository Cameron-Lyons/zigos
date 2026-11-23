const std = @import("std");
const kernel_address = @import("../arch/kernel_address.zig");

pub const MAX_ARENA_PAGES: u32 = 4096;
pub const PHYSICAL_LIMIT: u64 = 1024 * 1024 * 1024;
pub const Span = struct { start: u64, end: u64 };

// Two disjoint firmware allocations keep construction away from the active
// transition root. The allocation receipts retain their capacities; verified boot-only
// retirement can release the old arena and the final hierarchy's unused tail.
pub const Info = extern struct {
    transition_pages: u32,
    final_pages: u32,
    transition_base: u64,
    final_base: u64,
    framebuffer_base: u64 = 0,
    framebuffer_bytes: u64 = 0,

    pub inline fn transitionBytes(self: Info) u64 {
        return @as(u64, self.transition_pages) * 4096;
    }

    pub inline fn finalBytes(self: Info) u64 {
        return @as(u64, self.final_pages) * 4096;
    }

    // This is the complete GOP allocation, including padding and modes that
    // cannot be rendered. Zero/zero denotes an absent advertised allocation.
    pub inline fn framebufferSpan(self: Info) error{InvalidPagingInfo}!?Span {
        if (self.framebuffer_base == 0 and self.framebuffer_bytes == 0) return null;
        if (self.framebuffer_base == 0 or self.framebuffer_bytes == 0) return error.InvalidPagingInfo;
        const end = std.math.add(u64, self.framebuffer_base, self.framebuffer_bytes) catch return error.InvalidPagingInfo;
        const rounded_end = std.math.add(u64, end, 4095) catch return error.InvalidPagingInfo;
        const span = Span{ .start = self.framebuffer_base & ~@as(u64, 4095), .end = rounded_end & ~@as(u64, 4095) };
        if (span.end > kernel_address.direct_map_capacity) return error.InvalidPagingInfo;
        return span;
    }

    pub fn validate(self: Info) error{InvalidPagingInfo}!void {
        if (self.transition_pages < 3 or self.transition_pages > MAX_ARENA_PAGES or
            self.final_pages < 3 or self.final_pages > MAX_ARENA_PAGES) return error.InvalidPagingInfo;
        const arenas = [_]struct { base: u64, length: u64 }{
            .{ .base = self.transition_base, .length = self.transitionBytes() },
            .{ .base = self.final_base, .length = self.finalBytes() },
        };
        for (arenas) |arena| {
            if (arena.base < 1024 * 1024 or arena.base % 4096 != 0 or arena.base > PHYSICAL_LIMIT - arena.length)
                return error.InvalidPagingInfo;
        }
        if (self.transition_base < self.final_base + self.finalBytes() and self.final_base < self.transition_base + self.transitionBytes())
            return error.InvalidPagingInfo;
        if (try self.framebufferSpan()) |span| {
            for (arenas) |arena| {
                if (arena.base < span.end and span.start < arena.base + arena.length) return error.InvalidPagingInfo;
            }
        }
    }
};

test "paging variable capacities admit adjacent extents" {
    for ([_]u32{ 3, 31, MAX_ARENA_PAGES }) |transition_pages| {
        for ([_]u32{ 3, 31, MAX_ARENA_PAGES }) |final_pages| {
            const info = Info{
                .transition_pages = transition_pages,
                .final_pages = final_pages,
                .transition_base = 0x100000,
                .final_base = 0x100000 + @as(u64, transition_pages) * 4096,
            };
            try info.validate();
            try std.testing.expectEqual(@as(u64, transition_pages) * 4096, info.transitionBytes());
            try std.testing.expectEqual(@as(u64, final_pages) * 4096, info.finalBytes());
            var overlap = info;
            overlap.final_base -= 4096;
            try std.testing.expectError(error.InvalidPagingInfo, overlap.validate());
            var boundary = info;
            boundary.final_base = PHYSICAL_LIMIT - info.finalBytes();
            try boundary.validate();
            boundary.final_base += 4096;
            try std.testing.expectError(error.InvalidPagingInfo, boundary.validate());
        }
    }
}

test "paging receipts reject invalid counts and arena geometry" {
    const valid = Info{ .transition_pages = 3, .final_pages = 31, .transition_base = 0x4000000, .final_base = 0x6000000 };
    try valid.validate();
    for ([_]u32{ 0, 1, 2, MAX_ARENA_PAGES + 1, std.math.maxInt(u32) }) |pages| {
        var changed = valid;
        changed.transition_pages = pages;
        try std.testing.expectError(error.InvalidPagingInfo, changed.validate());
        changed = valid;
        changed.final_pages = pages;
        try std.testing.expectError(error.InvalidPagingInfo, changed.validate());
    }
    for ([_]u64{ 0, 0x100001, std.math.maxInt(u64), valid.transition_base, valid.transition_base + valid.transitionBytes() - 4096 }) |base| {
        var changed = valid;
        changed.final_base = base;
        try std.testing.expectError(error.InvalidPagingInfo, changed.validate());
    }
}

test "paging receipts retain the complete advertised GOP extent above 4 GiB" {
    const high_base: u64 = 1 << 32;
    const info = Info{
        .transition_pages = 3,
        .final_pages = 31,
        .transition_base = 0x4000000,
        .final_base = 0x6000000,
        .framebuffer_base = high_base + 123,
        .framebuffer_bytes = 2 * 4096 + 7,
    };
    try info.validate();
    try std.testing.expectEqualDeep(Span{ .start = high_base, .end = high_base + 3 * 4096 }, (try info.framebufferSpan()).?);
    var absent = info;
    absent.framebuffer_base = 0;
    absent.framebuffer_bytes = 0;
    try std.testing.expect((try absent.framebufferSpan()) == null);
}

test "paging GOP receipts reject inconsistent pairs overflow and actual capacity collisions" {
    const valid = Info{ .transition_pages = 3, .final_pages = 31, .transition_base = 0x4000000, .final_base = 0x6000000 };
    const bad_extents = [_]struct { base: u64, length: u64 }{
        .{ .base = 0, .length = 4096 },
        .{ .base = 4096, .length = 0 },
        .{ .base = std.math.maxInt(u64) - 1023, .length = 2048 },
        .{ .base = std.math.maxInt(u64) - 100, .length = 1 },
        .{ .base = kernel_address.direct_map_capacity, .length = 1 },
        .{ .base = kernel_address.direct_map_capacity - 1, .length = 2 },
        .{ .base = valid.transition_base - 1, .length = 2 },
        .{ .base = valid.transition_base + valid.transitionBytes() - 1, .length = 1 },
        .{ .base = valid.final_base + valid.finalBytes() - 1, .length = 1 },
    };
    for (bad_extents) |extent| {
        var info = valid;
        info.framebuffer_base = extent.base;
        info.framebuffer_bytes = extent.length;
        try std.testing.expectError(error.InvalidPagingInfo, info.validate());
    }
    for ([_]u64{ valid.transition_base - 1, valid.transition_base + valid.transitionBytes(), valid.final_base - 1, valid.final_base + valid.finalBytes(), kernel_address.direct_map_capacity - 1 }) |base| {
        var info = valid;
        info.framebuffer_base = base;
        info.framebuffer_bytes = 1;
        try info.validate();
        try std.testing.expectEqual((base & ~@as(u64, 4095)) + 4096, (try info.framebufferSpan()).?.end);
    }
}
