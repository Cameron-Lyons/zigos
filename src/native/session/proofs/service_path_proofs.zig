const std = @import("std");
const session_manager = @import("../session_manager.zig");

pub const syscalls = @import("service_path_proofs_syscalls.zig");
pub const driver_recovery = @import("service_path_proofs_driver_recovery.zig");
pub const service_boundary = @import("service_path_proofs_service_boundary.zig");
pub const sync_path = @import("service_path_proofs_sync.zig");
pub const compositor_path = @import("service_path_proofs_compositor.zig");
pub const platform_health = @import("service_path_proofs_platform.zig");

const common = @import("service_path_proofs_common.zig");

pub fn bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting() !void {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    const runtime = session_manager.testing.runtimePtr();
    const runtime_service = session_manager.testing.runtimeServicePtr();
    const capability_table = session_manager.system().capabilityTablePtr();
    const supervisor = session_manager.testing.supervisorPtr();
    const service_directory = session_manager.testing.serviceDirectoryPtr();
    const driver_directory = session_manager.testing.driverDirectoryPtr();
    const driver_runtime = session_manager.testing.driverRuntimePtr();
    const storage = session_manager.testing.storageServicePtr();
    const kernel_port = session_manager.kernelPort() orelse return error.KernelPortUnavailable;

    const session_task = session_manager.testing.findTask("session-manager").?;
    const sync_task = session_manager.testing.findTask("sync-service").?;
    const storage_task = session_manager.testing.findTask("workspace-storage").?;
    const storage_driver_task = session_manager.testing.findTask("storage-driver").?;
    const network_service_task = session_manager.testing.findTask("network-service").?;
    const compositor_task = session_manager.testing.findTask("compositor-session").?;

    try std.testing.expect(sync_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_driver_task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(?u64, 2), compositor_task.ui_surface_id);
    try std.testing.expect(runtime.processSeparated(sync_task.id, storage_task.id));
    try std.testing.expect(runtime.processSeparated(sync_task.id, storage_driver_task.id));
    try std.testing.expect(runtime.processSeparated(storage_driver_task.id, storage_task.id));
    try syscalls.proveBootedProcessIsolationVisibleEntitlementGates(
        runtime,
        capability_table,
        sync_task,
        storage_task,
        compositor_task,
    );

    const session_authority_id = common.findServiceAuthority(
        capability_table,
        session_task,
        .resource_query,
    ) orelse return error.MissingBootAuthority;

    runtime.allowHostPointerSyscallsForTask(session_task.id);
    try syscalls.proveResourceAccountingSyscalls(kernel_port, runtime, session_task.id, session_authority_id);
    try syscalls.proveBootedSharedMemoryMappingRevocation(kernel_port, runtime, capability_table, session_task.id, session_authority_id);
    try syscalls.proveBootedDriverPermissions(kernel_port, runtime, capability_table, driver_directory, storage_driver_task, network_service_task);
    try service_boundary.proveBootedUserspaceServiceOwnershipAndKernelBoundary(
        kernel_port,
        runtime,
        capability_table,
        supervisor,
        service_directory,
        driver_directory,
        driver_runtime,
    );
    try sync_path.proveBootedSyncServicePath(
        kernel_port,
        runtime,
        capability_table,
        supervisor.findByClass(.sync_replication).?,
        sync_task,
        network_service_task,
        storage,
        session_task.id,
        session_authority_id,
    );
    try compositor_path.proveBootedCompositorServicePath(
        kernel_port,
        runtime,
        capability_table,
        storage,
        runtime_service,
        supervisor.findByClass(.compositor_ui_session).?,
        compositor_task,
        session_manager.testing.compositorSessionPtr(),
    );
    try platform_health.proveBootedPostActivationHealthChecks(
        runtime,
        capability_table,
        supervisor,
        storage,
        sync_task,
        session_manager.testing.compositorSessionPtr(),
    );
    try platform_health.proveBootedSchedulerTelemetryProvider(
        kernel_port,
        runtime,
        session_manager.testing.userspaceSchedulerPtr(),
        session_task.id,
        session_authority_id,
    );
}
