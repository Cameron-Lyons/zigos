const std = @import("std");
const contract = @import("contract.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");

pub const ServiceContract = struct {
    class: contract.ServiceClass,
    interface: manifest.InterfaceDecl,
    driver_class: ?driver_service.DeviceClass = null,
    description: []const u8,
    boot_correlation_base: u64,
    boot_tick: u64,
};

pub const ordered_service_contracts = [_]ServiceContract{
    .{
        .class = .policy_mediation,
        .interface = .{ .name = "zigos.policy.mediation" },
        .description = "runtime grants, denials, and policy enforcement",
        .boot_correlation_base = 301,
        .boot_tick = 31,
    },
    .{
        .class = .network_stack,
        .interface = .{ .name = "zigos.service.network.policy" },
        .driver_class = .network_adapter,
        .description = "network stack, egress mediation, and device-backed packet IO",
        .boot_correlation_base = 304,
        .boot_tick = 34,
    },
    .{
        .class = .storage_object,
        .interface = .{ .name = "zigos.object.workspace" },
        .driver_class = .storage_controller,
        .description = "content-addressed object versions, workspace authority, snapshots, and derived file-bridge views",
        .boot_correlation_base = 307,
        .boot_tick = 35,
    },
    .{
        .class = .package_install_update,
        .interface = .{ .name = "zigos.package.install" },
        .description = "bundle install, update, and channel management",
        .boot_correlation_base = 310,
        .boot_tick = 38,
    },
    .{
        .class = .compositor_ui_session,
        .interface = .{ .name = "zigos.ui.session" },
        .driver_class = .graphics_adapter,
        .description = "compositor, input routing, and UI session ownership",
        .boot_correlation_base = 313,
        .boot_tick = 41,
    },
    .{
        .class = .indexing_search,
        .interface = .{ .name = "zigos.index.search" },
        .description = "indexing and search query service",
        .boot_correlation_base = 316,
        .boot_tick = 44,
    },
    .{
        .class = .sync_replication,
        .interface = .{ .name = "zigos.sync.replication" },
        .description = "local-first sync and replication service",
        .boot_correlation_base = 319,
        .boot_tick = 47,
    },
    .{
        .class = .media_print_helpers,
        .interface = .{ .name = "zigos.media.print" },
        .driver_class = .audio_print_io,
        .description = "media and print helper pipeline",
        .boot_correlation_base = 322,
        .boot_tick = 50,
    },
    .{
        .class = .compatibility_portal,
        .interface = .{ .name = "zigos.compat.portal" },
        .description = "isolated compatibility portal service",
        .boot_correlation_base = 325,
        .boot_tick = 51,
    },
};

pub fn contractForClass(class: contract.ServiceClass) ?ServiceContract {
    for (ordered_service_contracts) |entry| {
        if (entry.class == class) return entry;
    }
    return null;
}

pub fn orderedIndex(class: contract.ServiceClass) ?usize {
    for (ordered_service_contracts, 0..) |entry, index| {
        if (entry.class == class) return index;
    }
    return null;
}

test "service contract order matches the requested decomposition sequence" {
    try std.testing.expectEqual(contract.ServiceClass.policy_mediation, ordered_service_contracts[0].class);
    try std.testing.expectEqual(contract.ServiceClass.network_stack, ordered_service_contracts[1].class);
    try std.testing.expectEqual(contract.ServiceClass.storage_object, ordered_service_contracts[2].class);
    try std.testing.expectEqual(contract.ServiceClass.package_install_update, ordered_service_contracts[3].class);
    try std.testing.expectEqual(contract.ServiceClass.compositor_ui_session, ordered_service_contracts[4].class);
    try std.testing.expectEqual(contract.ServiceClass.indexing_search, ordered_service_contracts[5].class);
    try std.testing.expectEqual(contract.ServiceClass.sync_replication, ordered_service_contracts[6].class);
    try std.testing.expectEqual(contract.ServiceClass.media_print_helpers, ordered_service_contracts[7].class);
    try std.testing.expectEqual(contract.ServiceClass.compatibility_portal, ordered_service_contracts[8].class);
}

test "service contract interfaces remain unique and discoverable" {
    for (ordered_service_contracts, 0..) |entry, index| {
        try std.testing.expect(contractForClass(entry.class) != null);
        try std.testing.expectEqual(index, orderedIndex(entry.class).?);

        var peer_index: usize = index + 1;
        while (peer_index < ordered_service_contracts.len) : (peer_index += 1) {
            try std.testing.expect(!std.mem.eql(u8, entry.interface.name, ordered_service_contracts[peer_index].interface.name));
        }
    }
}
