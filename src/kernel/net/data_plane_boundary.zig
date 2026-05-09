pub const publishes_full_network_service = false;
pub const network_data_plane_exports_fail_closed = true;

pub const DataPlaneError = error{
    KernelNetworkDataPlaneDisabled,
};

pub fn rejectKernelNetworkDataPlane() DataPlaneError!void {
    return error.KernelNetworkDataPlaneDisabled;
}
