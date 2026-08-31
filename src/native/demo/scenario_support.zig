const builtin = @import("builtin");
const native_util = @import("../core/util.zig");
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
const userspace_loader = @import("../task/userspace_loader.zig");
const workspace_mod = @import("../storage/workspace.zig");

pub const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

pub const storage_signer = signing.SignerIdentity{
    .label = "zigos-storage-key",
    .seed = signing.seedFromByte(0x81),
};
pub const workspace_signer = signing.SignerIdentity{
    .label = "zigos-workspace-key",
    .seed = signing.seedFromByte(0x82),
};
pub const export_signer = signing.SignerIdentity{
    .label = "zigos-export-key",
    .seed = signing.seedFromByte(0x83),
};
pub const diagnostic_ledger_signer = signing.SignerIdentity{
    .label = "zigos-diagnostic-ledger",
    .seed = signing.seedFromByte(0x84),
};

pub const Context = struct {
    capability_table: *capability.CapabilityTable,
    runtime: *task_runtime.Runtime,
    runtime_service: *task_runtime_service_mod.Service,
    userspace_catalog: *userspace_loader.Catalog,
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
    notes_task_id: u64,
    notes_object_capability: capability.Capability,
};

pub const StorageScenarioState = struct {
    notes_workspace_id: u64,
    notes_object_id: u64,
    latest_notes_version_id: u64,
};

pub const default_local_device_principal = principal.PrincipalId{ .kind = .device, .serial = 1 };
pub const default_tablet_device_principal = principal.PrincipalId{ .kind = .device, .serial = 2 };

pub const SyncScenarioState = struct {
    workspace_policy: sync_service_mod.WorkspacePolicy,
    tablet_device_principal: principal.PrincipalId,
    user_root_signer: signing.SignerIdentity,
    local_network_policy_id: u64,
    relay_policy_id: ?u64,
    overlay_policy_id: ?u64,
};

pub fn mintSyncAuthority(context: *Context, now_ticks: u64) sync_service_mod.AuthorityContext {
    const authority_capability = context.capability_table.mintBootRoot(.{
        .holder = context.sync_service_principal,
        .issuer = context.policy_authority,
        .target = .{ .kind = .service, .id = context.sync_service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = context.sync_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 1_000,
        },
        .audit = .{},
    }) catch |err| native_util.bootProofFailure("scenario support", err);
    return .{
        .task_id = context.sync_task_id,
        .principal = context.sync_service_principal,
        .capability_id = authority_capability.id,
        .now_ticks = now_ticks,
    };
}

pub fn latestInsertedVersion(storage: *const storage_service_mod.Service) ?*const object_store_mod.VersionRecord {
    return storage.latestInsertedVersion();
}
