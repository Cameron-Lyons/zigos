const std = @import("std");
const contract = @import("contract.zig");
const service_catalog = @import("service_catalog.zig");

pub const Phase3Contract = service_catalog.Phase3Contract;
pub const ordered_phase3_contracts = service_catalog.ordered_phase3_contracts;

pub fn contractForClass(class: contract.ServiceClass) ?Phase3Contract {
    return service_catalog.phase3ContractForClass(class);
}

pub fn orderedIndex(class: contract.ServiceClass) ?usize {
    return service_catalog.orderedPhase3Index(class);
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
