const std = @import("std");
const contract = @import("contract.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");

pub const Phase3Contract = struct {
    class: contract.ServiceClass,
    interface: manifest.InterfaceDecl,
    driver_class: ?driver_service.DeviceClass = null,
    description: []const u8,
};

pub const ordered_phase3_contracts = [_]Phase3Contract{
    .{
        .class = .policy_mediation,
        .interface = .{ .name = "zigos.policy.mediation" },
        .description = "runtime grants, denials, and policy enforcement",
    },
    .{
        .class = .network_stack,
        .interface = .{ .name = "zigos.service.network.policy" },
        .driver_class = .network_adapter,
        .description = "network stack, egress mediation, and device-backed packet IO",
    },
    .{
        .class = .storage_object,
        .interface = .{ .name = "zigos.object.workspace" },
        .driver_class = .storage_controller,
        .description = "content-addressed object versions, workspace authority, snapshots, and derived file-bridge views",
    },
    .{
        .class = .package_install_update,
        .interface = .{ .name = "zigos.package.install" },
        .description = "bundle install, update, and channel management",
    },
    .{
        .class = .compositor_ui_session,
        .interface = .{ .name = "zigos.ui.session" },
        .driver_class = .graphics_adapter,
        .description = "compositor, input routing, and UI session ownership",
    },
    .{
        .class = .indexing_search,
        .interface = .{ .name = "zigos.index.search" },
        .description = "indexing and search query service",
    },
    .{
        .class = .sync_replication,
        .interface = .{ .name = "zigos.sync.replication" },
        .description = "local-first sync and replication service",
    },
    .{
        .class = .media_print_helpers,
        .interface = .{ .name = "zigos.media.print" },
        .driver_class = .audio_print_io,
        .description = "media and print helper pipeline",
    },
};

pub fn contractForClass(class: contract.ServiceClass) ?Phase3Contract {
    for (ordered_phase3_contracts) |entry| {
        if (entry.class == class) return entry;
    }
    return null;
}

pub fn orderedIndex(class: contract.ServiceClass) ?usize {
    for (ordered_phase3_contracts, 0..) |entry, index| {
        if (entry.class == class) return index;
    }
    return null;
}

test "phase3 contract order matches the requested decomposition sequence" {
    try std.testing.expectEqual(contract.ServiceClass.policy_mediation, ordered_phase3_contracts[0].class);
    try std.testing.expectEqual(contract.ServiceClass.network_stack, ordered_phase3_contracts[1].class);
    try std.testing.expectEqual(contract.ServiceClass.storage_object, ordered_phase3_contracts[2].class);
    try std.testing.expectEqual(contract.ServiceClass.package_install_update, ordered_phase3_contracts[3].class);
    try std.testing.expectEqual(contract.ServiceClass.compositor_ui_session, ordered_phase3_contracts[4].class);
    try std.testing.expectEqual(contract.ServiceClass.indexing_search, ordered_phase3_contracts[5].class);
    try std.testing.expectEqual(contract.ServiceClass.sync_replication, ordered_phase3_contracts[6].class);
    try std.testing.expectEqual(contract.ServiceClass.media_print_helpers, ordered_phase3_contracts[7].class);
}

test "phase3 contract interfaces remain unique and discoverable" {
    for (ordered_phase3_contracts, 0..) |entry, index| {
        try std.testing.expect(contractForClass(entry.class) != null);
        try std.testing.expectEqual(index, orderedIndex(entry.class).?);

        var peer_index: usize = index + 1;
        while (peer_index < ordered_phase3_contracts.len) : (peer_index += 1) {
            try std.testing.expect(!std.mem.eql(u8, entry.interface.name, ordered_phase3_contracts[peer_index].interface.name));
        }
    }
}
