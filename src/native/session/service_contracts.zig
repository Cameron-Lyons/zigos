const std = @import("std");
const contract = @import("contract.zig");
const service_catalog = @import("service_catalog.zig");

pub const ServiceContract = service_catalog.ServiceContract;
pub const ordered_service_contracts = service_catalog.ordered_service_contracts;

pub fn contractForClass(class: contract.ServiceClass) ?ServiceContract {
    return service_catalog.serviceContractForClass(class);
}

pub fn orderedIndex(class: contract.ServiceClass) ?usize {
    return service_catalog.orderedServiceIndex(class);
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
