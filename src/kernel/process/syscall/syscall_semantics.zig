const std = @import("std");

pub fn clampNice(prio: i32) i32 {
    return @max(-20, @min(19, prio));
}

pub fn userPriorityFromNice(nice: i32) i32 {
    return 20 - clampNice(nice);
}

pub fn isValidIndexedResource(resource: u32, count: usize) bool {
    return resource < count;
}

pub fn pageCount(length: usize, page_size: usize) usize {
    if (page_size == 0) return 0;
    return (length + page_size - 1) / page_size;
}

test "nice values clamp and map to getpriority results" {
    try std.testing.expectEqual(@as(i32, -20), clampNice(-50));
    try std.testing.expectEqual(@as(i32, 19), clampNice(99));
    try std.testing.expectEqual(@as(i32, 7), clampNice(7));

    try std.testing.expectEqual(@as(i32, 40), userPriorityFromNice(-20));
    try std.testing.expectEqual(@as(i32, 20), userPriorityFromNice(0));
    try std.testing.expectEqual(@as(i32, 1), userPriorityFromNice(19));
}

test "resource validation respects table bounds" {
    try std.testing.expect(isValidIndexedResource(0, 4));
    try std.testing.expect(isValidIndexedResource(3, 4));
    try std.testing.expect(!isValidIndexedResource(4, 4));
}

test "pageCount rounds up partial pages" {
    try std.testing.expectEqual(@as(usize, 0), pageCount(0, 4096));
    try std.testing.expectEqual(@as(usize, 1), pageCount(1, 4096));
    try std.testing.expectEqual(@as(usize, 1), pageCount(4096, 4096));
    try std.testing.expectEqual(@as(usize, 2), pageCount(4097, 4096));
}
