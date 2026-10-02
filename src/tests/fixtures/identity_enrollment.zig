const enrollment = @import("../../native/services/identity_enrollment.zig");
const pin = @import("../../native/platform/tpm2_pin.zig");

pub fn record() !enrollment.Record {
    const capsule = pin.Capsule{
        .owner = .{ .kind = .user, .serial = 3 },
        .device = .{ .kind = .device, .serial = 4 },
        .salt = @splat(5),
        .sealed = .{ .len = 3, .bytes = .{ 'a', 'b', 'c' } ++ @as([509]u8, @splat(0)) },
    };
    return .{ .enrollment = .{
        .owner = capsule.owner,
        .device = capsule.device,
        .capsule_digest = try capsule.digest(),
        .parent = .{ .handle = 0x8100_5432, .name = .{ 0, 0x0b } ++ @as([32]u8, @splat(6)) },
        .catalog_object_id = 1000,
        .anchor_index = 0x0180_5432,
        .catalog_secret_id = 1,
        .device_secret_id = 3,
    }, .capsule = capsule };
}
