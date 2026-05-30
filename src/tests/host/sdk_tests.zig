const std = @import("std");

const native_app_sdk = @import("../../native/sdk/native_app_sdk.zig");

test "SDK host tests import native developer platform modules" {
    std.testing.refAllDecls(native_app_sdk);
}
