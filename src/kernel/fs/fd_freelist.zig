const std = @import("std");

pub fn initFreelist(freelist: []u8, top: *usize) void {
    for (0..freelist.len) |idx| {
        freelist[idx] = @intCast(freelist.len - 1 - idx);
    }
    top.* = freelist.len;
}

pub fn allocFd(freelist: []u8, top: *usize) ?u32 {
    if (top.* == 0) return null;
    top.* -= 1;
    return freelist[top.*];
}

pub fn freeFd(freelist: []u8, top: *usize, fd: u32) void {
    if (fd >= freelist.len) return;
    if (top.* >= freelist.len) return;
    freelist[top.*] = @intCast(fd);
    top.* += 1;
}

pub fn reserveFd(freelist: []u8, top: *usize, fd: u32) bool {
    if (fd >= freelist.len) return false;

    var idx: usize = 0;
    while (idx < top.*) : (idx += 1) {
        if (freelist[idx] != @as(u8, @intCast(fd))) continue;
        top.* -= 1;
        freelist[idx] = freelist[top.*];
        return true;
    }
    return false;
}

test "freelist allocates descriptors in ascending order" {
    var freelist: [8]u8 = undefined;
    var top: usize = 0;

    initFreelist(&freelist, &top);
    try std.testing.expectEqual(@as(?u32, 0), allocFd(&freelist, &top));
    try std.testing.expectEqual(@as(?u32, 1), allocFd(&freelist, &top));
    try std.testing.expectEqual(@as(?u32, 2), allocFd(&freelist, &top));
}

test "freelist reuses closed descriptors" {
    var freelist: [8]u8 = undefined;
    var top: usize = 0;

    initFreelist(&freelist, &top);
    _ = allocFd(&freelist, &top);
    const second = allocFd(&freelist, &top).?;
    _ = allocFd(&freelist, &top);
    freeFd(&freelist, &top, second);
    try std.testing.expectEqual(@as(?u32, second), allocFd(&freelist, &top));
}

test "freelist reserve supports dup2 style replacement" {
    var freelist: [8]u8 = undefined;
    var top: usize = 0;

    initFreelist(&freelist, &top);
    try std.testing.expect(reserveFd(&freelist, &top, 5));

    var seen = [_]bool{false} ** 8;
    while (allocFd(&freelist, &top)) |fd| {
        seen[fd] = true;
    }

    try std.testing.expect(!seen[5]);
    try std.testing.expect(seen[0]);
    try std.testing.expect(seen[7]);
}
