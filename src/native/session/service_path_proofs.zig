const std = @import("std");
const impl = @import("proofs/service_path_proofs.zig");
const session_manager = @import("session_manager.zig");

pub const syscalls = impl.syscalls;
pub const driver_recovery = impl.driver_recovery;
pub const service_boundary = impl.service_boundary;
pub const sync_path = impl.sync_path;
pub const compositor_path = impl.compositor_path;
pub const platform_health = impl.platform_health;
pub const bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting = impl.bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting;

test "booted userspace service paths prove sync driver isolation and resource accounting" {
    try bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting();
}

test "booted userspace service paths prove process isolation visible-entitlement gates" {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    try syscalls.proveBootedProcessIsolationVisibleEntitlementGates(
        session_manager.testing.runtimePtr(),
        session_manager.system().capabilityTablePtr(),
        session_manager.testing.findTask("sync-service").?,
        session_manager.testing.findTask("workspace-storage").?,
        session_manager.testing.findTask("compositor-session").?,
    );
}

test "booted driver hot-swap and crash recovery rebind live brokered device authority" {
    try driver_recovery.proveBootedDriverHotSwapAndRecoveryRebindLiveBrokeredDeviceAuthority();
}
