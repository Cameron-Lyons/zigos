const std = @import("std");
const registry = @import("userspace_registry.zig");

pub const FLAG_SYSTEM_BUNDLE = registry.FLAG_SYSTEM_BUNDLE;
pub const FLAG_OWNS_UI_SURFACE = registry.FLAG_OWNS_UI_SURFACE;
pub const FLAG_PERMISSION_REVIEW = registry.FLAG_PERMISSION_REVIEW;
pub const FLAG_BACKGROUND_ELIGIBLE = registry.FLAG_BACKGROUND_ELIGIBLE;
pub const FLAG_STORAGE_BOUNDARY = registry.FLAG_STORAGE_BOUNDARY;
pub const FLAG_NETWORK_BOUNDARY = registry.FLAG_NETWORK_BOUNDARY;
pub const FLAG_POLICY_BOUNDARY = registry.FLAG_POLICY_BOUNDARY;
pub const FLAG_DRIVER_BOUNDARY = registry.FLAG_DRIVER_BOUNDARY;
pub const FLAG_COMPATIBILITY_BOUNDARY = registry.FLAG_COMPATIBILITY_BOUNDARY;

pub const ContractSpec = registry.ContractSpec;

pub const contracts = comptime blk: {
    var derived: [registry.boot_image_specs.len]ContractSpec = undefined;
    for (registry.boot_image_specs, 0..) |spec, index| {
        derived[index] = registry.contractForSpec(&spec);
    }
    break :blk derived;
};

pub fn find(bundle_id: []const u8) ?*const ContractSpec {
    for (&contracts) |*contract| {
        if (std.mem.eql(u8, contract.bundle_id, bundle_id)) return contract;
    }
    return null;
}

test "userspace contracts stay unique and cover every boot artifact" {
    try std.testing.expectEqual(registry.boot_image_specs.len, contracts.len);

    for (contracts, 0..) |contract, index| {
        try std.testing.expect(contract.role_tag != 0);
        try std.testing.expect(contract.heartbeat_increment != 0);

        var duplicate_index: usize = 0;
        while (duplicate_index < index) : (duplicate_index += 1) {
            try std.testing.expect(!std.mem.eql(u8, contracts[duplicate_index].bundle_id, contract.bundle_id));
            try std.testing.expect(contracts[duplicate_index].role_tag != contract.role_tag);
        }
    }
}
