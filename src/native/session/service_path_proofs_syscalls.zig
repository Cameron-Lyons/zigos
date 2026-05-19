const impl = @import("proofs/service_path_proofs_syscalls.zig");

pub const proveResourceAccountingSyscalls = impl.proveResourceAccountingSyscalls;
pub const proveBootedSharedMemoryMappingRevocation = impl.proveBootedSharedMemoryMappingRevocation;
pub const proveBootedDriverPermissions = impl.proveBootedDriverPermissions;
pub const proveBootedProcessIsolationVisibleEntitlementGates = impl.proveBootedProcessIsolationVisibleEntitlementGates;
