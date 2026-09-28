const std = @import("std");

const device_graph = @import("../../native/sync/device_graph.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const sync_adapters = @import("../../native/sync/sync_adapters.zig");
const sync_service = @import("../../native/sync/sync_service.zig");
const sync_service_test = @import("../../native/sync/sync_service_test.zig");
const sync_transport = @import("../../native/sync/sync_transport.zig");

test "sync host tests import native sync modules" {
    _ = @import("../../native/sync/peer_connections_test.zig");
    _ = @import("../../native/sync/object_sender_test.zig");
    _ = @import("../../native/sync/peer_handshake_test.zig");
    _ = @import("../../native/sync/peer_admission_test.zig");
    _ = @import("../../native/sync/peer_channel.zig");
    _ = @import("../../native/sync/sealed_peer_test.zig");
    _ = @import("../../native/sync/object_transfer_test.zig");
    std.testing.refAllDecls(device_graph);
    std.testing.refAllDecls(network_policy);
    std.testing.refAllDecls(sync_adapters);
    std.testing.refAllDecls(sync_service);
    std.testing.refAllDecls(sync_service_test);
    std.testing.refAllDecls(sync_transport);
}
