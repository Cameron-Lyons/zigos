const std = @import("std");

pub fn deferInputDataPlaneToUserspace() void {}

pub fn has_char() bool {
    return false;
}

pub fn getchar() ?u8 {
    return null;
}

test "PS/2 bootstrap input remains fail closed" {
    deferInputDataPlaneToUserspace();

    try std.testing.expect(!has_char());
    try std.testing.expectEqual(@as(?u8, null), getchar());
}
