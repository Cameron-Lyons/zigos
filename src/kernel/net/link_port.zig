const data_plane_boundary = @import("data_plane_boundary.zig");

pub const kernel_boundary_role = "bootstrap_network_link_shim";
pub const publishes_full_network_service = data_plane_boundary.publishes_full_network_service;
pub const network_data_plane_exports_fail_closed = data_plane_boundary.network_data_plane_exports_fail_closed;

pub const DataPlaneError = data_plane_boundary.DataPlaneError;

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

pub fn hasDriverClaim() bool {
    return active_claim != null;
}

pub fn claimForService(service_id: u64) ?DriverClaim {
    const claim = active_claim orelse return null;
    if (claim.service_id != service_id) return null;
    return claim;
}

pub fn rejectKernelDataPlaneTransport(_: DriverClaim) DataPlaneError!void {
    return data_plane_boundary.rejectKernelNetworkDataPlane();
}

test "kernel network link shim rejects data-plane transport publication" {
    try @import("std").testing.expectError(error.KernelNetworkDataPlaneDisabled, rejectKernelDataPlaneTransport(.{
        .device_id = 0x8086_100E,
        .service_id = 7,
    }));
}
