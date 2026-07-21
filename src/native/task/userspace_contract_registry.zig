const std = @import("std");
const id_index = @import("../core/id_index.zig");
const native_util = @import("../core/util.zig");
const registry = @import("userspace_registry.zig");
const verification_registry = @import("userspace_verification_registry.zig");

pub const FLAG_SYSTEM_BUNDLE = registry.FLAG_SYSTEM_BUNDLE;
pub const FLAG_OWNS_UI_SURFACE = registry.FLAG_OWNS_UI_SURFACE;
pub const FLAG_PERMISSION_REVIEW = registry.FLAG_PERMISSION_REVIEW;
pub const FLAG_BACKGROUND_ELIGIBLE = registry.FLAG_BACKGROUND_ELIGIBLE;
pub const FLAG_STORAGE_BOUNDARY = registry.FLAG_STORAGE_BOUNDARY;
pub const FLAG_NETWORK_BOUNDARY = registry.FLAG_NETWORK_BOUNDARY;
pub const FLAG_POLICY_BOUNDARY = registry.FLAG_POLICY_BOUNDARY;
pub const FLAG_DRIVER_BOUNDARY = registry.FLAG_DRIVER_BOUNDARY;

pub const ContractSpec = registry.ContractSpec;

pub const contracts = blk: {
    var derived: [verification_registry.verification_boot_image_specs.len]ContractSpec = undefined;
    for (verification_registry.verification_boot_image_specs, 0..) |spec, index| {
        derived[index] = registry.contractForSpec(&spec);
    }
    break :blk derived;
};

const BUNDLE_INDEX_CAPACITY: usize = contracts.len * 2;
const bundle_index = buildBundleIndex();

pub fn find(bundle_id: []const u8) ?*const ContractSpec {
    const key = registry.bundleIndexKey(bundle_id);
    const contract_index = id_index.lookup(BUNDLE_INDEX_CAPACITY, &bundle_index, key) orelse {
        debugAssertBundleIndexMissAbsent(bundle_id);
        return null;
    };
    if (contract_index >= contracts.len) {
        native_util.impossibleByInvariant("contract bundle id index points outside contracts");
    }
    if (!std.mem.eql(u8, contracts[contract_index].bundle_id, bundle_id)) {
        native_util.impossibleByInvariant("contract bundle id index points at the wrong contract");
    }
    return &contracts[contract_index];
}

fn buildBundleIndex() [BUNDLE_INDEX_CAPACITY]id_index.Slot {
    @setEvalBranchQuota(10_000);
    var index = id_index.emptyTable(BUNDLE_INDEX_CAPACITY);
    for (contracts, 0..) |contract, contract_index| {
        id_index.insert(BUNDLE_INDEX_CAPACITY, &index, registry.bundleIndexKey(contract.bundle_id), contract_index, "contract bundle id index covers userspace contracts");
    }
    return index;
}

fn debugAssertBundleIndexMissAbsent(bundle_id: []const u8) void {
    if (@import("builtin").mode != .Debug) return;
    for (contracts) |contract| {
        if (std.mem.eql(u8, contract.bundle_id, bundle_id)) {
            native_util.impossibleByInvariant("contract bundle id index missed a contract");
        }
    }
}

test "userspace contracts stay unique and cover every boot artifact" {
    try std.testing.expectEqual(verification_registry.verification_boot_image_specs.len, contracts.len);

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
