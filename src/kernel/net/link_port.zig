// The single network device claim a userspace driver holds before the kernel
// starts its bootstrap link. The kernel never publishes a network data plane.
pub const DriverClaim = struct {
    device_id: u64 = 0,
    service_id: u64 = 0,
};

var active_claim: ?DriverClaim = null;

pub fn init() void {
    active_claim = null;
}

pub fn recordDriverClaim(device_id: u64, service_id: u64) bool {
    if (device_id == 0 or service_id == 0) return false;
    if (active_claim) |claim| {
        return claim.device_id == device_id and claim.service_id == service_id;
    }
    active_claim = .{
        .device_id = device_id,
        .service_id = service_id,
    };
    return true;
}

pub fn clearDriverClaim(service_id: u64) bool {
    const claim = active_claim orelse return false;
    if (claim.service_id != service_id) return false;
    active_claim = null;
    return true;
}

test "network link claim is exclusive and released only by its service" {
    const std = @import("std");
    init();
    try std.testing.expect(!recordDriverClaim(0, 7));
    try std.testing.expect(!recordDriverClaim(0x8086_100E, 0));
    try std.testing.expect(recordDriverClaim(0x8086_100E, 7));
    try std.testing.expect(recordDriverClaim(0x8086_100E, 7));
    try std.testing.expect(!recordDriverClaim(0x8086_100E, 8));
    try std.testing.expect(!clearDriverClaim(8));
    try std.testing.expect(clearDriverClaim(7));
    try std.testing.expect(!clearDriverClaim(7));
}
