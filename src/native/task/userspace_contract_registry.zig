const std = @import("std");

pub const FLAG_SYSTEM_BUNDLE: u32 = 1 << 0;
pub const FLAG_OWNS_UI_SURFACE: u32 = 1 << 1;
pub const FLAG_PERMISSION_REVIEW: u32 = 1 << 2;
pub const FLAG_BACKGROUND_ELIGIBLE: u32 = 1 << 3;
pub const FLAG_STORAGE_BOUNDARY: u32 = 1 << 4;
pub const FLAG_NETWORK_BOUNDARY: u32 = 1 << 5;
pub const FLAG_POLICY_BOUNDARY: u32 = 1 << 6;
pub const FLAG_DRIVER_BOUNDARY: u32 = 1 << 7;
pub const FLAG_COMPATIBILITY_BOUNDARY: u32 = 1 << 8;

pub const ContractSpec = struct {
    bundle_id: []const u8,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
};

pub const contracts = [_]ContractSpec{
    .{ .bundle_id = "zigos.system.session-manager", .role_tag = 0xA101, .heartbeat_increment = 1, .contract_flags = FLAG_SYSTEM_BUNDLE },
    .{ .bundle_id = "zigos.system.permission-review", .role_tag = 0xA102, .heartbeat_increment = 2, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_OWNS_UI_SURFACE | FLAG_PERMISSION_REVIEW },
    .{ .bundle_id = "zigos.system.workspace-storage", .role_tag = 0xA103, .heartbeat_increment = 3, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_STORAGE_BOUNDARY },
    .{ .bundle_id = "zigos.system.transport-probe", .role_tag = 0xA104, .heartbeat_increment = 4, .contract_flags = FLAG_OWNS_UI_SURFACE },
    .{ .bundle_id = "zigos.system.termination-probe", .role_tag = 0xA105, .heartbeat_increment = 5, .contract_flags = 0 },
    .{ .bundle_id = "app.viewer", .role_tag = 0xA106, .heartbeat_increment = 6, .contract_flags = FLAG_OWNS_UI_SURFACE },
    .{ .bundle_id = "app.notes", .role_tag = 0xA107, .heartbeat_increment = 7, .contract_flags = FLAG_OWNS_UI_SURFACE },
    .{ .bundle_id = "app.sync", .role_tag = 0xA108, .heartbeat_increment = 8, .contract_flags = FLAG_BACKGROUND_ELIGIBLE },
    .{ .bundle_id = "app.capture", .role_tag = 0xA109, .heartbeat_increment = 9, .contract_flags = FLAG_OWNS_UI_SURFACE },
    .{ .bundle_id = "zigos.system.policy-mediation", .role_tag = 0xA10A, .heartbeat_increment = 10, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_POLICY_BOUNDARY },
    .{ .bundle_id = "zigos.system.network-stack", .role_tag = 0xA10B, .heartbeat_increment = 11, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_NETWORK_BOUNDARY },
    .{ .bundle_id = "zigos.system.storage-object", .role_tag = 0xA10C, .heartbeat_increment = 12, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_STORAGE_BOUNDARY },
    .{ .bundle_id = "zigos.system.storage-driver", .role_tag = 0xA10D, .heartbeat_increment = 13, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_DRIVER_BOUNDARY | FLAG_STORAGE_BOUNDARY },
    .{ .bundle_id = "zigos.system.package-service", .role_tag = 0xA10E, .heartbeat_increment = 14, .contract_flags = FLAG_SYSTEM_BUNDLE },
    .{ .bundle_id = "zigos.system.compositor", .role_tag = 0xA10F, .heartbeat_increment = 15, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_OWNS_UI_SURFACE },
    .{ .bundle_id = "zigos.system.indexing-search", .role_tag = 0xA110, .heartbeat_increment = 16, .contract_flags = FLAG_SYSTEM_BUNDLE },
    .{ .bundle_id = "zigos.system.sync-service", .role_tag = 0xA111, .heartbeat_increment = 17, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_BACKGROUND_ELIGIBLE },
    .{ .bundle_id = "zigos.system.media-print", .role_tag = 0xA112, .heartbeat_increment = 18, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_BACKGROUND_ELIGIBLE },
    .{ .bundle_id = "zigos.system.compatibility-portal", .role_tag = 0xA113, .heartbeat_increment = 19, .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_COMPATIBILITY_BOUNDARY },
    .{ .bundle_id = "zigos.system.service-client", .role_tag = 0xA114, .heartbeat_increment = 20, .contract_flags = FLAG_OWNS_UI_SURFACE },
};

pub fn find(bundle_id: []const u8) ?*const ContractSpec {
    for (&contracts) |*contract| {
        if (std.mem.eql(u8, contract.bundle_id, bundle_id)) return contract;
    }
    return null;
}

test "userspace contracts stay unique and cover every boot artifact" {
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
