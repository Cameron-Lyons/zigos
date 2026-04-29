const std = @import("std");

pub const CopyTextExactError = error{DestinationTooSmall};

pub fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

pub fn copyTextWithReserve(dest: []u8, src: []const u8, comptime reserve: usize) usize {
    const capacity = dest.len -| reserve;
    const len = @min(capacity, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

pub fn copyTextExact(dest: []u8, src: []const u8) CopyTextExactError!usize {
    if (src.len > dest.len) return error.DestinationTooSmall;
    @memcpy(dest[0..src.len], src);
    return src.len;
}

pub fn fnv1a64(bytes: []const u8) u64 {
    return fnv1a64WithSeed(0xCBF29CE484222325, bytes);
}

pub fn fnv1a64WithSeed(seed: u64, bytes: []const u8) u64 {
    var hash = seed;
    for (bytes) |byte| {
        hash = fnv1a64AppendByte(hash, byte);
    }
    return hash;
}

pub fn fnv1a64AppendByte(hash: u64, byte: u8) u64 {
    var next = hash;
    next ^= @as(u64, byte);
    next *%= 1099511628211;
    return next;
}

pub fn fnv1a64AppendU64LittleEndian(hash: u64, value: u64) u64 {
    var next = hash;
    var remaining = value;
    inline for (0..8) |_| {
        next = fnv1a64AppendByte(next, @as(u8, @truncate(remaining & 0xFF)));
        remaining >>= 8;
    }
    return next;
}

pub fn impossibleByInvariant(comptime message: []const u8) noreturn {
    std.debug.panic("impossible by invariant: {s}", .{message});
}

pub fn impossibleByInvariantError(comptime message: []const u8, err: anyerror) noreturn {
    std.debug.panic("impossible by invariant: {s}: {s}", .{ message, @errorName(err) });
}

test "copyTextExact rejects undersized destinations and preserves exact lengths" {
    var buffer = [_]u8{0} ** 4;

    try std.testing.expectEqual(@as(usize, 4), try copyTextExact(&buffer, "zigo"));
    try std.testing.expectEqualStrings("zigo", &buffer);
    try std.testing.expectError(error.DestinationTooSmall, copyTextExact(buffer[0..3], "zigo"));
}
