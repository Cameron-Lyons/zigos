const std = @import("std");

pub const Identifier = u16;
pub const KERNEL_IDENTIFIER: Identifier = 0;
pub const MAX_IDENTIFIER: Identifier = 0x0FFF;

const IDENTIFIER_COUNT: usize = @as(usize, MAX_IDENTIFIER) + 1;
const WORD_BITS: usize = @bitSizeOf(u32);
const WORD_COUNT: usize = IDENTIFIER_COUNT / WORD_BITS;

pub const Error = error{
    KernelIdentifier,
    OutOfRange,
    NotAllocated,
};

pub const Allocator = struct {
    used: [WORD_COUNT]u32 = [_]u32{0} ** WORD_COUNT,
    next_hint: Identifier = 1,
    allocated_count: Identifier = 0,

    pub fn init() Allocator {
        var allocator = Allocator{};
        allocator.set(KERNEL_IDENTIFIER);
        return allocator;
    }

    pub fn allocate(self: *Allocator) ?Identifier {
        const start = @as(usize, self.next_hint);
        const raw_identifier = self.findFree(start, IDENTIFIER_COUNT) orelse
            self.findFree(1, start) orelse return null;
        const identifier: Identifier = @intCast(raw_identifier);
        self.set(identifier);
        self.allocated_count += 1;
        self.next_hint = if (identifier == MAX_IDENTIFIER) 1 else identifier + 1;
        return identifier;
    }

    pub fn release(self: *Allocator, identifier: Identifier) Error!void {
        if (identifier == KERNEL_IDENTIFIER) return error.KernelIdentifier;
        if (identifier > MAX_IDENTIFIER) return error.OutOfRange;
        if (!self.isSet(identifier)) return error.NotAllocated;

        self.clear(identifier);
        self.allocated_count -= 1;
        self.next_hint = @min(self.next_hint, identifier);
    }

    pub fn isAllocated(self: *const Allocator, identifier: Identifier) bool {
        if (identifier == KERNEL_IDENTIFIER or identifier > MAX_IDENTIFIER) return false;
        return self.isSet(identifier);
    }

    pub fn allocated(self: *const Allocator) Identifier {
        return self.allocated_count;
    }

    fn findFree(self: *const Allocator, start: usize, end: usize) ?usize {
        var identifier = start;
        while (identifier < end) : (identifier += 1) {
            if (!self.isSet(@intCast(identifier))) return identifier;
        }
        return null;
    }

    fn isSet(self: *const Allocator, identifier: Identifier) bool {
        const word_index = @as(usize, identifier) / WORD_BITS;
        const bit: u5 = @intCast(@as(usize, identifier) % WORD_BITS);
        return (self.used[word_index] & (@as(u32, 1) << bit)) != 0;
    }

    fn set(self: *Allocator, identifier: Identifier) void {
        const word_index = @as(usize, identifier) / WORD_BITS;
        const bit: u5 = @intCast(@as(usize, identifier) % WORD_BITS);
        self.used[word_index] |= @as(u32, 1) << bit;
    }

    fn clear(self: *Allocator, identifier: Identifier) void {
        const word_index = @as(usize, identifier) / WORD_BITS;
        const bit: u5 = @intCast(@as(usize, identifier) % WORD_BITS);
        self.used[word_index] &= ~(@as(u32, 1) << bit);
    }
};

test "PCID allocator reserves zero and reuses released identifiers" {
    var allocator = Allocator.init();
    try std.testing.expect(!allocator.isAllocated(KERNEL_IDENTIFIER));

    const first = allocator.allocate().?;
    const second = allocator.allocate().?;
    try std.testing.expectEqual(@as(Identifier, 1), first);
    try std.testing.expectEqual(@as(Identifier, 2), second);
    try std.testing.expectEqual(@as(Identifier, 2), allocator.allocated());

    try allocator.release(first);
    try std.testing.expectEqual(first, allocator.allocate().?);
    try std.testing.expectError(error.KernelIdentifier, allocator.release(KERNEL_IDENTIFIER));
    try std.testing.expectError(error.NotAllocated, allocator.release(3));
}

test "PCID allocator exhausts the architectural identifier space" {
    var allocator = Allocator.init();
    var expected: Identifier = 1;
    while (expected <= MAX_IDENTIFIER) : (expected += 1) {
        try std.testing.expectEqual(expected, allocator.allocate().?);
        if (expected == MAX_IDENTIFIER) break;
    }
    try std.testing.expectEqual(MAX_IDENTIFIER, allocator.allocated());
    try std.testing.expectEqual(@as(?Identifier, null), allocator.allocate());

    try allocator.release(MAX_IDENTIFIER);
    try std.testing.expectEqual(MAX_IDENTIFIER, allocator.allocate().?);
}
