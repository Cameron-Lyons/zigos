const std = @import("std");

const zigos_sign = @import("../../tools/zigos_sign.zig");
const zigos_verify_release = @import("../../tools/zigos_verify_release.zig");

test "tools host tests import source-aware tools" {
    std.testing.refAllDecls(zigos_sign);
    std.testing.refAllDecls(zigos_verify_release);
}
