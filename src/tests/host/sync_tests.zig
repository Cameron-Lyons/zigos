const std = @import("std");

const device_graph = @import("../../native/sync/device_graph.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const sync_adapters = @import("../../native/sync/sync_adapters.zig");
const sync_service = @import("../../native/sync/sync_service.zig");
const sync_service_test = @import("../../native/sync/sync_service_test.zig");
const sync_transport_harness = @import("../../native/sync/sync_transport_harness.zig");

test "sync host tests import native sync modules" {
    std.testing.refAllDecls(device_graph);
    std.testing.refAllDecls(network_policy);
    std.testing.refAllDecls(sync_adapters);
    std.testing.refAllDecls(sync_service);
    std.testing.refAllDecls(sync_service_test);
    std.testing.refAllDecls(sync_transport_harness);
}
