const std = @import("std");
const console = @import("../utils/console.zig");
const qemu_exit = @import("../utils/qemu_exit.zig");
const boot_markers = @import("markers.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const immutable_base = @import("../../native/platform/immutable_base.zig");
const manifest = @import("../../native/policy/manifest.zig");
const object_store = @import("../../native/storage/object_store.zig");
const principal = @import("../../native/core/principal.zig");
const recovery_environment = @import("../../native/platform/recovery_environment.zig");
const signing = @import("../../native/core/signing.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const sync_service = @import("../../native/sync/sync_service.zig");

const Context = struct {
    checkpoint_store: storage_service.CheckpointStore = .{},
    storage: storage_service.Service = undefined,
    manager: immutable_base.Manager = undefined,
    sync: sync_service.Service = undefined,
    sync_capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    sync_authority: sync_service.AuthorityContext = zeroSyncAuthority(),
    environment: recovery_environment.Environment = undefined,
    workspace_id: u64 = 0,
    clean_version_id: u64 = 0,
};

var context = Context{};

pub fn run() noreturn {
    console.print("Running recovery boot profile...\n");
    printMarker(boot_markers.recovery_start);

    runRecoveryBoot() catch |err| {
        console.print("RECOVERY:ERROR:");
        console.print(@errorName(err));
        console.print("\n");
        printMarker(boot_markers.recovery_fail);
        qemu_exit.failure();
    };

    printMarker(boot_markers.recovery_pass);
    qemu_exit.success();
}

fn runRecoveryBoot() !void {
    const storage_owner = service(50);
    const sync_owner = service(51);
    const user = principal.PrincipalId{ .kind = .user, .serial = 5 };
    const primary = principal.PrincipalId{ .kind = .device, .serial = 51 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 52 };
    const policy_authority = principal.PrincipalId{ .kind = .policy_authority, .serial = 50 };

    try prepareFixture(storage_owner, sync_owner, user, primary, tablet);

    var ledger = event_ledger.Ledger.init();
    const recovery_boot = try context.environment.enterBreakGlassRecoveryBootProfile(&ledger, .{
        .profile = .recovery,
        .requester = storage_owner,
        .approver = policy_authority,
        .approval_capability_id = 7_001,
        .reason = "freestanding recovery boot",
        .actions = &.{
            .reinstall_base_image,
            .restore_workspace_snapshot,
            .repair_sync_metadata,
            .rotate_device_keys,
            .revoke_device_trust,
        },
    }, 16);

    try require(recovery_boot.entry.entered_from_boot_profile, error.RecoveryBootProfileMissing);
    try require(!recovery_boot.normal_session_authority, error.NormalSessionAuthorityLeaked);
    try require(!recovery_boot.entry.normal_session_authority, error.NormalSessionAuthorityLeaked);
    try require(recovery_boot.audited_break_glass, error.BreakGlassAuditMissing);
    try require(recovery_boot.break_glass_approver != null and recovery_boot.break_glass_approver.?.eql(policy_authority), error.BreakGlassAuditMissing);
    try verifyBreakGlassAudit(&ledger, storage_owner);
    printMarker(boot_markers.recovery_break_glass_audited);
    printMarker(boot_markers.recovery_no_normal_session_authority);

    try require(try context.environment.verifyAndReinstallImage(
        recovery_boot.session(),
        &context.manager,
        "kernel=v2",
        signer("recovery-image", 0x62),
        17,
    ), error.RecoveryImageReinstallFailed);
    try require(context.manager.verifyActiveImage(), error.RecoveryImageReinstallFailed);
    printMarker(boot_markers.recovery_reinstall_ok);

    const snapshot = context.storage.findSnapshot(context.workspace_id, "clean") orelse return error.RecoverySnapshotMissing;
    try require(try context.environment.restoreWorkspaceSnapshot(
        recovery_boot.session(),
        &context.storage,
        context.workspace_id,
        snapshot.id,
        18,
    ), error.RecoverySnapshotRestoreFailed);
    const restored = try context.storage.resolve(context.workspace_id, "documents/incident.md");
    try require(restored.version_id.raw() == context.clean_version_id, error.RecoverySnapshotRestoreFailed);
    printMarker(boot_markers.recovery_restore_ok);

    try require(try context.environment.repairSyncMetadata(
        recovery_boot.session(),
        &context.sync,
        &context.storage,
        context.workspace_id,
        tablet,
    ), error.RecoverySyncRepairFailed);
    try require(context.sync.findConflict(context.workspace_id, tablet, "documents/incident.md") == null, error.RecoverySyncRepairFailed);
    printMarker(boot_markers.recovery_repair_sync_ok);

    const next_generation = try context.environment.rotateDeviceKeys(
        recovery_boot.session(),
        &context.sync,
        user,
        tablet,
        signer("recovery-user", 0x64),
        signer("recovery-tablet-v2", 0x67),
        19,
    );
    try require(next_generation == 2, error.RecoveryKeyRotationFailed);
    printMarker(boot_markers.recovery_rotate_keys_ok);

    try require(try context.environment.revokeDeviceTrust(
        recovery_boot.session(),
        &context.sync,
        user,
        tablet,
        signer("recovery-user", 0x64),
        20,
    ), error.RecoveryTrustRevocationFailed);
    try require(!context.sync.isTrustedDevice(tablet), error.RecoveryTrustRevocationFailed);
    printMarker(boot_markers.recovery_revoke_trust_ok);
}

fn prepareFixture(
    storage_owner: principal.PrincipalId,
    sync_owner: principal.PrincipalId,
    user: principal.PrincipalId,
    primary: principal.PrincipalId,
    tablet: principal.PrincipalId,
) !void {
    context.checkpoint_store.resetPersistent();
    context.storage = storage_service.Service.initWithStore(800, 80, storage_owner, &context.checkpoint_store);
    context.manager = try immutable_base.Manager.init(&context.storage, storage_owner, signer("recovery-state", 0x61));
    _ = try context.manager.stageImage(0, "stable-a", "kernel=v1", signer("recovery-image", 0x62), 10);
    _ = try context.manager.activate(0, .{}, 11);

    const notes = try context.storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1),
        .object_type = .document,
        .payload = "incident-v1",
        .metadata = try object_store.signMetadata(
            signer("recovery-object", 0x63),
            "incident",
            "text/plain",
            .document,
            "incident-v1",
            12,
        ),
    });
    const drift = try context.storage.putVersion(.{
        .preferred_object_id = notes.object_id,
        .object_type = .document,
        .payload = "incident-drift",
        .metadata = try object_store.signMetadata(
            signer("recovery-object", 0x63),
            "incident",
            "text/plain",
            .document,
            "incident-drift",
            13,
        ),
        .parent_version_id = notes.version_id,
    });
    const workspace_record = try context.storage.createWorkspace(.{
        .owner = user,
        .label = "incident",
    });
    context.workspace_id = workspace_record.id.raw();
    context.clean_version_id = notes.version_id.raw();
    try context.storage.beginTransaction(workspace_record.id);
    try context.storage.stagePut(workspace_record.id, "documents/incident.md", notes.object_id, notes.version_id, .document);
    _ = try context.storage.commit(workspace_record.id, 14);
    _ = try context.storage.snapshot(workspace_record.id, "clean", signer("recovery-object", 0x63));
    try context.storage.beginTransaction(workspace_record.id);
    try context.storage.stagePut(workspace_record.id, "documents/incident.md", drift.object_id, drift.version_id, .document);
    _ = try context.storage.commit(workspace_record.id, 15);

    context.sync = sync_service.Service.init(801, 81, sync_owner);
    context.sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try mintSyncAuthority(&context.sync_capabilities, &context.sync);
    context.sync_authority = syncAuthority(&context.sync, sync_capability, 15);
    var sync_port = sync_service.SyncPort.init(&context.sync, &context.sync_capabilities);
    const authority = context.sync_authority;
    _ = try sync_port.ensureUserRoot(authority, user, "owner", signer("recovery-user", 0x64));
    _ = try sync_port.enrollTrustedDevice(authority, user, primary, "primary", signer("recovery-user", 0x64), signer("recovery-primary", 0x65), 14);
    _ = try sync_port.enrollTrustedDevice(authority, user, tablet, "tablet", signer("recovery-user", 0x64), signer("recovery-tablet", 0x66), 15);

    const local_policy = try sync_port.createNetworkPolicy(authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "local",
        .mode = .local_network,
    });
    _ = try sync_port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
    });
    try sync_port.setReplicaVersion(authority, workspace_record.id.raw(), tablet, "documents/incident.md", notes.object_id, drift.version_id.raw() + 1);
    _ = try sync_port.replicateWorkspace(authority, &context.storage, workspace_record.id.raw(), primary, tablet, .device_to_device);

    context.environment = recovery_environment.Environment.init(storage_owner);
}

fn verifyBreakGlassAudit(ledger: *const event_ledger.Ledger, subject: principal.PrincipalId) !void {
    var events: [2]event_ledger.Event = undefined;
    const decisions = ledger.queryEvents(.{
        .kind = .permission_decision,
        .subject = subject,
        .include_protected_content = true,
    }, &events);
    try require(decisions.len == 1, error.BreakGlassAuditMissing);
    try require(decisions[0].allowed, error.BreakGlassAuditMissing);
    try require(decisions[0].permission_kind != null and decisions[0].permission_kind.? == manifest.PermissionKind.device_access, error.BreakGlassAuditMissing);
}

fn mintSyncAuthority(
    capability_table: *capability.CapabilityTable,
    service_instance: *const sync_service.Service,
) !capability.Capability {
    return try capability_table.mintBootRoot(.{
        .holder = service_instance.owner,
        .issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 50 },
        .target = .{ .kind = .service, .id = service_instance.service_id },
        .rights = .{ .service = .{ .endpoint_connect = true } },
        .scope = .{
            .task_id = service_instance.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
        },
        .audit = .{},
    });
}

fn syncAuthority(
    service_instance: *const sync_service.Service,
    authority_capability: capability.Capability,
    now_ticks: u64,
) sync_service.AuthorityContext {
    return .{
        .task_id = service_instance.task_id,
        .principal = service_instance.owner,
        .capability_id = authority_capability.id,
        .now_ticks = now_ticks,
    };
}

fn zeroSyncAuthority() sync_service.AuthorityContext {
    return .{
        .task_id = 0,
        .principal = principal.PrincipalId{ .kind = .service, .serial = 0 },
        .capability_id = 0,
        .now_ticks = 0,
    };
}

fn service(serial: u64) principal.PrincipalId {
    return .{ .kind = .service, .serial = serial };
}

fn signer(label: []const u8, byte: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = signing.seedFromByte(byte),
    };
}

fn require(condition: bool, err: anyerror) !void {
    if (!condition) return err;
}

fn printMarker(marker: []const u8) void {
    console.print(marker);
    console.print("\n");
}
