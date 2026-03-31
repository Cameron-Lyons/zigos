const boot_markers = @import("../../kernel/boot/markers.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const support = @import("session_lifecycle_support.zig");

pub fn run(
    context: *support.Context,
    phase5_sync_service: *sync_service_mod.Service,
    phase4: support.Phase4State,
) support.Phase5State {
    const local_device_principal = principal.PrincipalId{ .kind = .device, .serial = 1 };
    const tablet_device_principal = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const phone_device_principal = principal.PrincipalId{ .kind = .device, .serial = 3 };
    const user_root_signer = signing.SignerIdentity{
        .label = "zigos-user-root",
        .seed = [_]u8{0x91} ** 32,
    };
    const local_device_signer = signing.SignerIdentity{
        .label = "local-device",
        .seed = [_]u8{0x92} ** 32,
    };
    const tablet_device_signer = signing.SignerIdentity{
        .label = "tablet-device",
        .seed = [_]u8{0x93} ** 32,
    };
    const tablet_rotated_signer = signing.SignerIdentity{
        .label = "tablet-device-v2",
        .seed = [_]u8{0x94} ** 32,
    };
    const phone_device_signer = signing.SignerIdentity{
        .label = "phone-device",
        .seed = [_]u8{0x95} ** 32,
    };
    const database_contract_signer = signing.SignerIdentity{
        .label = "zigos-db-sync",
        .seed = [_]u8{0x96} ** 32,
    };

    const phase5_root = phase5_sync_service.ensureUserRoot(context.session_user, "cameron", user_root_signer) catch unreachable;
    if (phase5_root.root_signature.isComplete()) {
        support.common.printBootMarker(boot_markers.phase5_device_graph_rooted);
    }

    const local_device_record = phase5_sync_service.findDeviceRecord(local_device_principal) orelse phase5_sync_service.enrollTrustedDevice(
        context.session_user,
        local_device_principal,
        "local-devbox",
        user_root_signer,
        local_device_signer,
        100,
    ) catch unreachable;
    if (phase5_sync_service.findDeviceRecord(tablet_device_principal) == null) {
        _ = phase5_sync_service.enrollTrustedDevice(
            context.session_user,
            tablet_device_principal,
            "tablet",
            user_root_signer,
            tablet_device_signer,
            101,
        ) catch unreachable;
    }
    if (phase5_sync_service.findDeviceRecord(phone_device_principal) == null) {
        _ = phase5_sync_service.enrollTrustedDevice(
            context.session_user,
            phone_device_principal,
            "phone",
            user_root_signer,
            phone_device_signer,
            102,
        ) catch unreachable;
    }
    if (local_device_record.overlay_id != 0 and
        phase5_sync_service.findDeviceRecord(tablet_device_principal) != null and
        phase5_sync_service.findDeviceRecord(phone_device_principal) != null)
    {
        support.common.printBootMarker("ZIGOS:PHASE5:DEVICE_ENROLL:OK");
    }

    if (phase5_sync_service.findDeviceRecord(tablet_device_principal).?.isTrusted() and
        phase5_sync_service.findDeviceRecord(tablet_device_principal).?.key_rotation_generation < 2)
    {
        _ = phase5_sync_service.rotateDeviceKey(
            context.session_user,
            tablet_device_principal,
            user_root_signer,
            tablet_rotated_signer,
            103,
        ) catch unreachable;
    }
    const rotated_tablet = phase5_sync_service.findDeviceRecord(tablet_device_principal).?;
    if (rotated_tablet.key_rotation_generation >= 2 and rotated_tablet.rotation_signature.isComplete()) {
        support.common.printBootMarker("ZIGOS:PHASE5:KEY_ROTATION:OK");
    }

    if (phase5_sync_service.isTrustedDevice(phone_device_principal)) {
        phase5_sync_service.revokeTrustedDevice(
            context.session_user,
            phone_device_principal,
            user_root_signer,
            104,
        ) catch unreachable;
        context.update_ledger.recordDeviceTrustChange(
            context.session_user,
            phone_device_principal,
            false,
            104,
            "device revoked",
        ) catch unreachable;
    }
    if (!phase5_sync_service.isTrustedDevice(phone_device_principal) and phase5_sync_service.trustedDeviceCount() >= 2) {
        support.common.printBootMarker("ZIGOS:PHASE5:DEVICE_REVOKE:OK");
    }

    const none_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = context.sync_service_principal,
        .workspace_id = phase4.notes_workspace_id,
        .label = "none",
        .mode = .none,
    }) catch unreachable;
    const local_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = context.sync_service_principal,
        .workspace_id = phase4.notes_workspace_id,
        .label = "local-net",
        .mode = .local_network,
    }) catch unreachable;
    const printer_discovery_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = context.sync_service_principal,
        .workspace_id = phase4.notes_workspace_id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    }) catch unreachable;
    const overlay_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = context.sync_service_principal,
        .workspace_id = phase4.notes_workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    }) catch unreachable;
    const relay_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = context.sync_service_principal,
        .workspace_id = phase4.notes_workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    }) catch unreachable;
    const inbound_collab_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = context.sync_service_principal,
        .workspace_id = phase4.notes_workspace_id,
        .label = "collab-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    }) catch unreachable;
    const internet_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = context.sync_service_principal,
        .workspace_id = phase4.notes_workspace_id,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    }) catch unreachable;

    if (!(phase5_sync_service.evaluateNetworkPolicy(none_network_policy.id, .public_internet) catch unreachable).allowed) {
        support.common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:NONE");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(local_network_policy.id, .local_network) catch unreachable).allowed and
        !(phase5_sync_service.evaluateNetworkPolicy(local_network_policy.id, .{ .domain = "relay.zigos.dev" }) catch unreachable).allowed)
    {
        support.common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:LOCAL");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(printer_discovery_policy.id, .{ .discovery_class = "printer" }) catch unreachable).allowed and
        !(phase5_sync_service.evaluateNetworkPolicy(printer_discovery_policy.id, .{ .discovery_class = "camera" }) catch unreachable).allowed)
    {
        support.common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:DISCOVERY");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(overlay_network_policy.id, .{ .service_identity = "overlay.notes.sync" }) catch unreachable).allowed) {
        support.common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:SERVICE");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(relay_network_policy.id, .{ .domain = "relay.zigos.dev" }) catch unreachable).allowed) {
        support.common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:DOMAIN");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(inbound_collab_policy.id, .{ .inbound_session_type = "document-review/v1" }) catch unreachable).allowed and
        !(phase5_sync_service.evaluateNetworkPolicy(inbound_collab_policy.id, .{ .inbound_session_type = "pair-screen/v1" }) catch unreachable).allowed)
    {
        support.common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:INBOUND");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(internet_network_policy.id, .public_internet) catch unreachable).allowed) {
        support.common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:INTERNET");
    }

    const workspace_policy = phase5_sync_service.configureWorkspacePolicy(.{
        .workspace_id = phase4.notes_workspace_id,
        .owner = context.session_user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/" },
        .device_to_device_policy_id = local_network_policy.id,
        .relay_policy_id = relay_network_policy.id,
        .overlay_policy_id = overlay_network_policy.id,
        .relay_domain = "relay.zigos.dev",
    }) catch unreachable;
    _ = phase5_sync_service.configureOverlay(phase4.notes_workspace_id, local_device_principal, "overlay.notes.sync", true) catch unreachable;
    _ = phase5_sync_service.publishPrivateService(phase4.notes_workspace_id, "notes.remote") catch unreachable;
    if (workspace_policy.offline_first) {
        support.common.printBootMarker("ZIGOS:PHASE5:SYNC_POLICY:OFFLINE_FIRST");
    }
    if (workspace_policy.personal_e2ee) {
        support.common.printBootMarker("ZIGOS:PHASE5:SYNC_POLICY:E2EE_PERSONAL");
    }

    phase5_sync_service.setReplicaVersion(
        phase4.notes_workspace_id,
        tablet_device_principal,
        "documents/notes.md",
        phase4.notes_object_id,
        phase4.latest_notes_version_id,
    ) catch unreachable;
    const device_sync_summary = phase5_sync_service.replicateWorkspace(
        context.storage_service_instance,
        phase4.notes_workspace_id,
        local_device_principal,
        tablet_device_principal,
        .device_to_device,
    ) catch unreachable;
    if (device_sync_summary.selected_entry_count == 2 and device_sync_summary.skipped_entry_count == 1) {
        support.common.printBootMarker("ZIGOS:PHASE5:SYNC_POLICY:SELECTIVE");
    }
    if (device_sync_summary.used_device_to_device) {
        support.common.printBootMarker("ZIGOS:PHASE5:SYNC:DEVICE_TO_DEVICE");
    }
    if (device_sync_summary.merged_count == 1) {
        support.common.printBootMarker("ZIGOS:PHASE5:SEMANTICS:CRDT");
    }
    if (device_sync_summary.snapshot_count == 1) {
        support.common.printBootMarker("ZIGOS:PHASE5:SEMANTICS:SNAPSHOT");
    }
    if (device_sync_summary.conflict_count == 1 and
        phase5_sync_service.findConflict(phase4.notes_workspace_id, tablet_device_principal, "documents/notes.md") != null)
    {
        context.update_ledger.recordSyncConflict(
            context.session_user,
            phase4.notes_workspace_id,
            109,
            "documents/notes.md conflict",
            true,
        ) catch unreachable;
        support.common.printBootMarker("ZIGOS:PHASE5:SYNC:CONFLICT_REPORT");
    }
    if (device_sync_summary.overlay_ready and
        device_sync_summary.remote_access_ready and
        device_sync_summary.private_service_published)
    {
        support.common.printBootMarker("ZIGOS:PHASE5:OVERLAY:READY");
    }

    if (phase5_sync_service.transferSecretObject(
        context.storage_service_instance.store,
        phase4.notes_workspace_id,
        922,
        local_device_principal,
        tablet_device_principal,
        .device_to_device,
    ) catch unreachable) {
        support.common.printBootMarker("ZIGOS:PHASE5:SEMANTICS:SECRET_TRANSFER");
    }

    const database_contract = phase5_sync_service.registerDatabaseContract(
        phase4.notes_workspace_id,
        "app.db.notes",
        "notes-db",
        database_contract_signer,
    ) catch unreachable;
    if (phase5_sync_service.replicateDatabaseContract(
        database_contract.id,
        phase4.notes_workspace_id,
        local_device_principal,
        tablet_device_principal,
        .relay_assisted,
    ) catch unreachable) {
        support.common.printBootMarker("ZIGOS:PHASE5:SYNC:RELAY");
        support.common.printBootMarker("ZIGOS:PHASE5:SEMANTICS:TRANSACTIONAL");
    }

    if (phase5_sync_service.replicateWorkspace(
        context.storage_service_instance,
        phase4.notes_workspace_id,
        local_device_principal,
        phone_device_principal,
        .device_to_device,
    )) |_| {} else |err| {
        if (err == error.DeviceNotTrusted) {
            support.common.printBootMarker("ZIGOS:PHASE5:DEVICE_REVOKE:ENFORCED");
        }
    }

    if (context.supervisor.recordCrash(context.sync_service_id, 105, 0x59)) {
        _ = context.supervisor.requestRestart(context.sync_service_id, 106);
        _ = context.runtime.rehostTask(context.sync_task_id, 106) catch unreachable;
        sync_service_mod.Service.resetPersistentState();
        var restarted_phase5_sync = sync_service_mod.Service.initWithStorage(
            context.sync_service_id,
            context.sync_task_id,
            context.sync_service_principal,
            context.storage_service_instance,
        ) catch unreachable;
        _ = context.supervisor.completeRestart(context.sync_service_id, 107);
        if (restarted_phase5_sync.loaded_existing_state and
            restarted_phase5_sync.findWorkspacePolicy(phase4.notes_workspace_id) != null and
            restarted_phase5_sync.findOverlay(phase4.notes_workspace_id) != null and
            restarted_phase5_sync.findConflict(phase4.notes_workspace_id, tablet_device_principal, "documents/notes.md") != null and
            restarted_phase5_sync.trustedDeviceCount() == 2)
        {
            support.common.printBootMarker("ZIGOS:PHASE5:SYNC_SERVICE:RECOVERED");
        }
    }

    return .{
        .workspace_policy = workspace_policy.*,
        .tablet_device_principal = tablet_device_principal,
        .user_root_signer = user_root_signer,
        .local_network_policy_id = local_network_policy.id,
        .relay_policy_id = relay_network_policy.id,
        .overlay_policy_id = overlay_network_policy.id,
    };
}
