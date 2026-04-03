const std = @import("std");
const device_graph = @import("../../native/sync/device_graph.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const sync_service = @import("../../native/sync/sync_service.zig");

test "sync sync modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(device_graph);
    std.testing.refAllDecls(network_policy);
    std.testing.refAllDecls(sync_service);
}
