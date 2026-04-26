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

test "service contract order follows declared dependencies" {
    try std.testing.expectEqual(contract.ServiceClass.service_registry, ordered_service_contracts[0].class);
    try std.testing.expect(orderedIndex(.service_registry).? < orderedIndex(.policy_mediation).?);
    try std.testing.expect(orderedIndex(.policy_mediation).? < orderedIndex(.network_stack).?);
    try std.testing.expect(orderedIndex(.policy_mediation).? < orderedIndex(.storage_object).?);
    try std.testing.expect(orderedIndex(.storage_object).? < orderedIndex(.package_install_update).?);
    try std.testing.expect(orderedIndex(.network_stack).? < orderedIndex(.package_install_update).?);
    try std.testing.expect(orderedIndex(.compositor_ui_session).? < orderedIndex(.compatibility_portal).?);
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
