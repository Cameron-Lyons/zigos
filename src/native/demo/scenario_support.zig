const builtin = @import("builtin");
const capability = @import("../kernel_api/capability.zig");
const driver_service = @import("../drivers/driver_service.zig");
const object_store_mod = @import("../storage/object_store.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const supervisor_mod = @import("../session/supervisor.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service_mod = @import("../task/task_runtime_service.zig");
const workspace_mod = @import("../storage/workspace.zig");

pub const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

pub const storage_signer = signing.SignerIdentity{
    .label = "zigos-storage-key",
    .seed = [_]u8{0x81} ** 32,
};
pub const workspace_signer = signing.SignerIdentity{
    .label = "zigos-workspace-key",
    .seed = [_]u8{0x82} ** 32,
};
pub const export_signer = signing.SignerIdentity{
    .label = "zigos-export-key",
    .seed = [_]u8{0x83} ** 32,
};
pub const diagnostic_ledger_signer = signing.SignerIdentity{
    .label = "zigos-diagnostic-ledger",
    .seed = [_]u8{0x84} ** 32,
};

pub const Context = struct {
    runtime: *task_runtime.Runtime,
    runtime_service: *task_runtime_service_mod.Service,
    supervisor: *supervisor_mod.Supervisor,
    compositor: *compositor_session.Session,
    driver_directory: *driver_service.Directory,
    storage_service_instance: *storage_service_mod.Service,
    storage_checkpoint_store: *storage_service_mod.CheckpointStore,
    export_package: *workspace_mod.ExportPackage,
    policy_authority: principal.PrincipalId,
    session_service: principal.PrincipalId,
    session_user: principal.PrincipalId,
    storage_service_id: u64,
    storage_task_id: u64,
    storage_service_principal: principal.PrincipalId,
    sync_service_id: u64,
    sync_task_id: u64,
    sync_service_principal: principal.PrincipalId,
    sync_resident_state: *sync_service_mod.ResidentState,
    policy_service_id: u64,
    network_service_id: u64,
    compositor_service_id: u64,
    package_service_id: u64,
    package_service_principal: principal.PrincipalId,
    update_ledger: *event_ledger.Ledger,
    notes_object_capability: capability.Capability,
};

pub const StorageScenarioState = struct {
    notes_workspace_id: u64,
    notes_object_id: u64,
    latest_notes_version_id: u64,
};

pub const SyncScenarioState = struct {
    workspace_policy: sync_service_mod.WorkspacePolicy,
    tablet_device_principal: principal.PrincipalId,
    user_root_signer: signing.SignerIdentity,
    local_network_policy_id: u64,
    relay_policy_id: ?u64,
    overlay_policy_id: ?u64,
};

pub fn latestInsertedVersion(storage: *const storage_service_mod.Service) ?*const object_store_mod.VersionRecord {
    return storage.latestInsertedVersion();
}
