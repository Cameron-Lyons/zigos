const std = @import("std");
const device_graph = @import("kernel/process/native/device_graph.zig");
const network_policy = @import("kernel/process/native/network_policy.zig");
const sync_service = @import("kernel/process/native/sync_service.zig");

test "phase5 native sync modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(device_graph);
    std.testing.refAllDecls(network_policy);
    std.testing.refAllDecls(sync_service);
}
