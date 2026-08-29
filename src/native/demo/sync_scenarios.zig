const boot_markers = @import("../../kernel/boot/markers.zig");
const native_util = @import("../core/util.zig");
const network_driver_task = @import("../drivers/network_driver_task.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const std = @import("std");
const sync_service_mod = @import("../sync/sync_service.zig");
const transient_sync_service = @import("../sync/transient_service.zig");
const sync_transport = @import("../sync/sync_transport.zig");
const support = @import("scenario_support.zig");

const booted_native_sync_driver_payload = "booted native sync driver packet";
const booted_native_sync_driver_reconnect_payload = "booted native sync driver reconnect";
const booted_native_sync_driver_replay_payload = "booted native sync driver replay";
const booted_native_sync_driver_fill_payload = "booted native sync driver fill";
const booted_native_sync_driver_overflow_payload = "booted native sync driver overflow";
const booted_native_sync_driver_plaintexts = [_][]const u8{
    booted_native_sync_driver_payload,
    booted_native_sync_driver_reconnect_payload,
    booted_native_sync_driver_replay_payload,
    booted_native_sync_driver_fill_payload,
    booted_native_sync_driver_overflow_payload,
};

fn containsBootedNativeSyncPlaintext(frame: []const u8) bool {
    for (booted_native_sync_driver_plaintexts) |plaintext| {
        if (std.mem.indexOf(u8, frame, plaintext) != null) return true;
    }
    return false;
}

pub fn run(
    context: *support.Context,
    sync_service: *sync_service_mod.Service,
    storage_state: support.StorageScenarioState,
) support.SyncScenarioState {
    const local_device_principal = support.default_local_device_principal;
    const tablet_device_principal = support.default_tablet_device_principal;
    const phone_device_principal = principal.PrincipalId{ .kind = .device, .serial = 3 };
    const user_root_signer = signing.SignerIdentity{
        .label = "zigos-user-root",
        .seed = signing.seedFromByte(0x91),
    };
    const local_device_signer = signing.SignerIdentity{
        .label = "local-device",
        .seed = signing.seedFromByte(0x92),
    };
    const tablet_device_signer = signing.SignerIdentity{
        .label = "tablet-device",
        .seed = signing.seedFromByte(0x93),
    };
    const tablet_rotated_signer = signing.SignerIdentity{
        .label = "tablet-device-v2",
        .seed = signing.seedFromByte(0x94),
    };
    const phone_device_signer = signing.SignerIdentity{
        .label = "phone-device",
        .seed = signing.seedFromByte(0x95),
    };
    const database_contract_signer = signing.SignerIdentity{
        .label = "zigos-db-sync",
        .seed = signing.seedFromByte(0x96),
    };
    var sync_port = sync_service_mod.SyncPort.init(sync_service, context.capability_table);
    const sync_authority = support.mintSyncAuthority(context, 100);

    const sync_root = sync_port.ensureUserRoot(sync_authority, context.session_user, "cameron", user_root_signer) catch |err| native_util.bootProofFailure("sync scenarios", err);
    if (sync_root.root_signature.isComplete()) {
        support.common.printBootMarker(boot_markers.sync_device_graph_rooted);
    }

    const local_device_record = sync_service.findDeviceRecord(local_device_principal) orelse sync_port.enrollTrustedDevice(
        sync_authority,
        context.session_user,
        local_device_principal,
        "local-devbox",
        user_root_signer,
        local_device_signer,
        100,
    ) catch |err| native_util.bootProofFailure("sync scenarios", err);
    if (sync_service.findDeviceRecord(tablet_device_principal) == null) {
        _ = sync_port.enrollTrustedDevice(
            sync_authority,
            context.session_user,
            tablet_device_principal,
            "tablet",
            user_root_signer,
            tablet_device_signer,
            101,
        ) catch |err| native_util.bootProofFailure("sync scenarios", err);
    }
    if (sync_service.findDeviceRecord(phone_device_principal) == null) {
        _ = sync_port.enrollTrustedDevice(
            sync_authority,
            context.session_user,
            phone_device_principal,
            "phone",
            user_root_signer,
            phone_device_signer,
            102,
        ) catch |err| native_util.bootProofFailure("sync scenarios", err);
    }
    if (local_device_record.overlay_id != 0 and
        sync_service.findDeviceRecord(tablet_device_principal) != null and
        sync_service.findDeviceRecord(phone_device_principal) != null)
    {
        support.common.printBootMarker("ZIGOS:SYNC:DEVICE_ENROLL:OK");
    }

    if (sync_service.findDeviceRecord(tablet_device_principal).?.isTrusted() and
        sync_service.findDeviceRecord(tablet_device_principal).?.key_rotation_generation < 2)
    {
        _ = sync_port.rotateDeviceKey(
            sync_authority,
            context.session_user,
            tablet_device_principal,
            user_root_signer,
            tablet_rotated_signer,
            103,
        ) catch |err| native_util.bootProofFailure("sync scenarios", err);
    }
    const rotated_tablet = sync_service.findDeviceRecord(tablet_device_principal).?;
    if (rotated_tablet.key_rotation_generation >= 2 and rotated_tablet.rotation_signature.isComplete()) {
        support.common.printBootMarker("ZIGOS:SYNC:KEY_ROTATION:OK");
    }

    if (sync_service.isTrustedDevice(phone_device_principal)) {
        sync_port.revokeTrustedDevice(
            sync_authority,
            context.session_user,
            phone_device_principal,
            user_root_signer,
            104,
        ) catch |err| native_util.bootProofFailure("sync scenarios", err);
        context.update_ledger.recordDeviceTrustChange(
            context.session_user,
            phone_device_principal,
            false,
            104,
            "device revoked",
        ) catch |err| native_util.bootProofFailure("sync scenarios", err);
    }
    if (!sync_service.isTrustedDevice(phone_device_principal) and sync_service.trustedDeviceCount() >= 2) {
        support.common.printBootMarker("ZIGOS:SYNC:DEVICE_REVOKE:OK");
    }

    const none_network_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = context.sync_service_principal,
        .workspace_id = storage_state.notes_workspace_id,
        .label = "none",
        .mode = .none,
    }) catch |err| native_util.bootProofFailure("sync scenarios", err);
    const local_network_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = context.sync_service_principal,
        .workspace_id = storage_state.notes_workspace_id,
        .label = "local-net",
        .mode = .local_network,
    }) catch |err| native_util.bootProofFailure("sync scenarios", err);
    const printer_discovery_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = context.sync_service_principal,
        .workspace_id = storage_state.notes_workspace_id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    }) catch |err| native_util.bootProofFailure("sync scenarios", err);
    const overlay_network_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = context.sync_service_principal,
        .workspace_id = storage_state.notes_workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    }) catch |err| native_util.bootProofFailure("sync scenarios", err);
    const relay_network_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = context.sync_service_principal,
        .workspace_id = storage_state.notes_workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    }) catch |err| native_util.bootProofFailure("sync scenarios", err);
    const inbound_collab_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = context.sync_service_principal,
        .workspace_id = storage_state.notes_workspace_id,
        .label = "collab-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    }) catch |err| native_util.bootProofFailure("sync scenarios", err);
    const internet_network_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = context.sync_service_principal,
        .workspace_id = storage_state.notes_workspace_id,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    }) catch |err| native_util.bootProofFailure("sync scenarios", err);

    if (!(sync_port.evaluateNetworkPolicy(sync_authority, none_network_policy.id, .public_internet) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed) {
        support.common.printBootMarker("ZIGOS:SYNC:NETWORK_POLICY:NONE");
    }
    if ((sync_port.evaluateNetworkPolicy(sync_authority, local_network_policy.id, .local_network) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed and
        !(sync_port.evaluateNetworkPolicy(sync_authority, local_network_policy.id, .{ .domain = "relay.zigos.dev" }) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed)
    {
        support.common.printBootMarker("ZIGOS:SYNC:NETWORK_POLICY:LOCAL");
    }
    if ((sync_port.evaluateNetworkPolicy(sync_authority, printer_discovery_policy.id, .{ .discovery_class = "printer" }) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed and
        !(sync_port.evaluateNetworkPolicy(sync_authority, printer_discovery_policy.id, .{ .discovery_class = "camera" }) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed)
    {
        support.common.printBootMarker("ZIGOS:SYNC:NETWORK_POLICY:DISCOVERY");
    }
    if ((sync_port.evaluateNetworkPolicy(sync_authority, overlay_network_policy.id, .{ .service_identity = "overlay.notes.sync" }) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed) {
        support.common.printBootMarker("ZIGOS:SYNC:NETWORK_POLICY:SERVICE");
    }
    if ((sync_port.evaluateNetworkPolicy(sync_authority, relay_network_policy.id, .{ .domain = "relay.zigos.dev" }) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed) {
        support.common.printBootMarker("ZIGOS:SYNC:NETWORK_POLICY:DOMAIN");
    }
    if ((sync_port.evaluateNetworkPolicy(sync_authority, inbound_collab_policy.id, .{ .inbound_session_type = "document-review/v1" }) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed and
        !(sync_port.evaluateNetworkPolicy(sync_authority, inbound_collab_policy.id, .{ .inbound_session_type = "pair-screen/v1" }) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed)
    {
        support.common.printBootMarker("ZIGOS:SYNC:NETWORK_POLICY:INBOUND");
    }
    if ((sync_port.evaluateNetworkPolicy(sync_authority, internet_network_policy.id, .public_internet) catch |err| native_util.bootProofFailure("sync scenarios", err)).allowed) {
        support.common.printBootMarker("ZIGOS:SYNC:NETWORK_POLICY:INTERNET");
    }

    const workspace_policy = sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = storage_state.notes_workspace_id,
        .owner = context.session_user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/" },
        .device_to_device_policy_id = local_network_policy.id,
        .relay_policy_id = relay_network_policy.id,
        .overlay_policy_id = overlay_network_policy.id,
        .relay_domain = "relay.zigos.dev",
    }) catch |err| native_util.bootProofFailure("sync scenarios", err);
    _ = sync_port.configureOverlay(sync_authority, storage_state.notes_workspace_id, local_device_principal, "overlay.notes.sync", true) catch |err| native_util.bootProofFailure("sync scenarios", err);
    _ = sync_port.publishPrivateService(sync_authority, storage_state.notes_workspace_id, "notes.remote") catch |err| native_util.bootProofFailure("sync scenarios", err);
    if (workspace_policy.offline_first) {
        support.common.printBootMarker("ZIGOS:SYNC:SYNC_POLICY:OFFLINE_FIRST");
    }
    if (workspace_policy.personal_e2ee) {
        support.common.printBootMarker("ZIGOS:SYNC:SYNC_POLICY:E2EE_PERSONAL");
    }

    sync_port.setReplicaVersion(
        sync_authority,
        storage_state.notes_workspace_id,
        tablet_device_principal,
        "documents/notes.md",
        storage_state.notes_object_id,
        storage_state.latest_notes_version_id,
    ) catch |err| native_util.bootProofFailure("sync scenarios", err);
    const device_sync_summary = sync_port.replicateWorkspace(
        sync_authority,
        context.storage_service_instance,
        storage_state.notes_workspace_id,
        local_device_principal,
        tablet_device_principal,
        .device_to_device,
    ) catch |err| native_util.bootProofFailure("sync scenarios", err);
    if (device_sync_summary.selected_entry_count == 2 and device_sync_summary.skipped_entry_count == 1) {
        support.common.printBootMarker("ZIGOS:SYNC:SYNC_POLICY:SELECTIVE");
    }
    if (device_sync_summary.used_device_to_device) {
        support.common.printBootMarker("ZIGOS:SYNC:SYNC:DEVICE_TO_DEVICE");
    }
    if (device_sync_summary.merged_count == 1) {
        support.common.printBootMarker("ZIGOS:SYNC:SEMANTICS:CRDT");
    }
    if (device_sync_summary.snapshot_count == 1) {
        support.common.printBootMarker("ZIGOS:SYNC:SEMANTICS:SNAPSHOT");
    }
    if (device_sync_summary.conflict_count == 1 and
        sync_service.findConflict(storage_state.notes_workspace_id, tablet_device_principal, "documents/notes.md") != null)
    {
        context.update_ledger.recordSyncConflict(
            context.session_user,
            storage_state.notes_workspace_id,
            109,
            "documents/notes.md conflict",
            true,
        ) catch |err| native_util.bootProofFailure("sync scenarios", err);
        support.common.printBootMarker("ZIGOS:SYNC:SYNC:CONFLICT_REPORT");
    }
    if (device_sync_summary.overlay_ready and
        device_sync_summary.remote_access_ready and
        device_sync_summary.private_service_published)
    {
        support.common.printBootMarker("ZIGOS:SYNC:OVERLAY:READY");
    }

    if (sync_port.transferSecretObject(
        sync_authority,
        context.storage_service_instance,
        storage_state.notes_workspace_id,
        922,
        local_device_principal,
        tablet_device_principal,
        .device_to_device,
    ) catch |err| native_util.bootProofFailure("sync scenarios", err)) {
        support.common.printBootMarker("ZIGOS:SYNC:SEMANTICS:SECRET_TRANSFER");
    }

    const database_contract = sync_port.registerDatabaseContract(
        sync_authority,
        storage_state.notes_workspace_id,
        "app.db.notes",
        "notes-db",
        database_contract_signer,
    ) catch |err| native_util.bootProofFailure("sync scenarios", err);
    if (sync_port.replicateDatabaseContract(
        sync_authority,
        database_contract.id,
        storage_state.notes_workspace_id,
        local_device_principal,
        tablet_device_principal,
        .relay_assisted,
    ) catch |err| native_util.bootProofFailure("sync scenarios", err)) {
        support.common.printBootMarker("ZIGOS:SYNC:SYNC:RELAY");
        support.common.printBootMarker("ZIGOS:SYNC:SEMANTICS:TRANSACTIONAL");
    }

    if (proveNativeDriverPacketCapture(
        context,
        sync_service,
        relay_network_policy.id,
        local_device_principal,
        tablet_device_principal,
    )) {
        support.common.printBootMarker(boot_markers.sync_native_driver_packet_captured);
        support.common.printBootMarker(boot_markers.sync_native_driver_frame_sent);
        support.common.printBootMarker(boot_markers.sync_native_driver_malformed_packet_rejected);
        support.common.printBootMarker(boot_markers.sync_native_driver_reconnect_ok);
        support.common.printBootMarker(boot_markers.sync_native_driver_replay_rejected);
        support.common.printBootMarker(boot_markers.sync_native_driver_congestion_backpressure);
    }

    if (sync_port.replicateWorkspace(
        sync_authority,
        context.storage_service_instance,
        storage_state.notes_workspace_id,
        local_device_principal,
        phone_device_principal,
        .device_to_device,
    )) |_| {} else |err| {
        if (err == error.DeviceNotTrusted) {
            support.common.printBootMarker("ZIGOS:SYNC:DEVICE_REVOKE:ENFORCED");
        }
    }

    if (context.supervisor.recordCrash(context.sync_service_id, 105, 0x59)) {
        _ = context.supervisor.requestRestart(context.sync_service_id, 106);
        _ = context.runtime.rehostTask(context.sync_task_id, 106) catch |err| native_util.bootProofFailure("sync scenarios", err);
        var restarted_sync_resident = sync_service_mod.ResidentState{};
        var restarted_sync_instance: transient_sync_service.Instance = undefined;
        restarted_sync_instance.initInto(
            context.sync_service_id,
            context.sync_task_id,
            context.sync_service_principal,
            context.storage_service_instance,
            &restarted_sync_resident,
        ) catch |err| native_util.bootProofFailure("sync scenarios", err);
        defer restarted_sync_instance.deinit();
        const restarted_sync_service = restarted_sync_instance.ptr();
        _ = context.supervisor.completeRestart(context.sync_service_id, 107);
        if (restarted_sync_service.loaded_existing_state and
            restarted_sync_service.findWorkspacePolicy(storage_state.notes_workspace_id) != null and
            restarted_sync_service.findOverlay(storage_state.notes_workspace_id) != null and
            restarted_sync_service.trustedDeviceCount() >= 2)
        {
            support.common.printBootMarker("ZIGOS:SYNC:SYNC_SERVICE:RECOVERED");
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

fn proveNativeDriverPacketCapture(
    context: *support.Context,
    sync_service: *sync_service_mod.Service,
    relay_policy_id: u64,
    local_device_principal: principal.PrincipalId,
    tablet_device_principal: principal.PrincipalId,
) bool {
    if (!network_driver_task.hasActiveDevice()) return false;

    const DriverEgress = struct {
        var allowed_capability_id: u64 = 0;
        var allowed_policy_id: u64 = 0;
        var authorized_native_frames: usize = 0;

        fn broker(request: network_driver_task.EgressRequest) network_driver_task.EgressDecision {
            const native_sync_frame = std.mem.startsWith(u8, request.frame, &sync_transport.NativeTransportAbi.magic);
            const no_plaintext = !containsBootedNativeSyncPlaintext(request.frame);
            const allowed = request.egress_capability_id == allowed_capability_id and
                request.network_policy_id == allowed_policy_id and
                native_sync_frame and
                no_plaintext;
            if (allowed) authorized_native_frames += 1;
            return .{
                .allowed = allowed,
                .capability_backed = request.egress_capability_id == allowed_capability_id,
            };
        }
    };

    const packet_capability = context.capability_table.mintBootRoot(.{
        .holder = context.sync_service_principal,
        .issuer = context.policy_authority,
        .target = .{ .kind = .network_policy, .id = relay_policy_id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{
            .task_id = context.sync_task_id,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 301,
            .expires_at_ticks = 1_000,
        },
        .audit = .{},
    }) catch return false;

    DriverEgress.allowed_capability_id = packet_capability.id;
    DriverEgress.allowed_policy_id = relay_policy_id;
    DriverEgress.authorized_native_frames = 0;
    network_driver_task.clearTransmitTelemetry();
    network_driver_task.setEgressBroker(DriverEgress.broker);
    network_driver_task.bindEgressCapability(packet_capability.id, relay_policy_id);
    defer {
        network_driver_task.clearEgressCapability();
        network_driver_task.setEgressBroker(null);
    }

    var broker = sync_service.egressBroker(context.capability_table);
    var native_transport = sync_transport.NativeTransportService.init();
    defer native_transport.deinit();
    var connection = native_transport.openRelay(&broker, .{
        .task_id = context.sync_task_id,
        .principal_id = context.sync_service_principal,
        .capability_id = packet_capability.id,
        .policy_id = relay_policy_id,
        .evidence = .{ .destination = .{ .domain = "relay.zigos.dev" } },
        .now_ticks = 302,
    }, context.sync_task_id, context.network_service_id, local_device_principal, tablet_device_principal, "relay.zigos.dev") catch return false;

    const driver_tx_before = network_driver_task.activeDriverTransmitCount();
    const signer = signing.SignerIdentity{
        .label = "booted-native-sync-driver",
        .seed = signing.seedFromByte(0xA7),
    };
    const delivery = native_transport.sendSigned(&connection, booted_native_sync_driver_payload, signer) catch return false;
    if (!delivery.network_delivered or delivery.sequence == 0) return false;
    if (DriverEgress.authorized_native_frames != 1) return false;
    if (network_driver_task.activeDriverTransmitCount() != driver_tx_before + 1) return false;

    const captured = native_transport.capture.last() orelse return false;
    const driver_frame = network_driver_task.lastActiveDriverFrame();
    if (driver_frame.len == 0 or !std.mem.eql(u8, captured.slice(), driver_frame)) return false;

    const view = native_transport.assertLastCapturedFrame(.{
        .session_id = connection.session.id,
        .sequence = delivery.sequence,
        .source_task_id = connection.source_task_id,
        .target_task_id = connection.target_task_id,
        .transport = .relay_assisted,
        .source_device = local_device_principal,
        .target_device = tablet_device_principal,
        .policy_id = relay_policy_id,
        .capability_id = packet_capability.id,
        .forbidden_plaintext = booted_native_sync_driver_payload,
    }) catch return false;
    if (view.abi_version != sync_transport.NativeTransportAbi.version or
        !view.encrypted() or
        !view.egressAllowed() or
        native_transport.capture.capturedCount() != 1 or
        native_transport.network_frame_count != 1)
    {
        return false;
    }

    var malformed_packet = captured;
    malformed_packet.bytes[0] ^= 0x55;
    var malformed_rejected = false;
    _ = sync_transport.decodeNativeSyncFrame(malformed_packet.slice()) catch |err| {
        if (err != error.NativeTransportMalformedFrame) return false;
        malformed_rejected = true;
    };
    if (!malformed_rejected) return false;

    native_transport.disconnect(&connection);
    var disconnected_rejected = false;
    _ = native_transport.sendSigned(&connection, booted_native_sync_driver_reconnect_payload, signer) catch |err| {
        if (err != error.NativeTransportDisconnected) return false;
        disconnected_rejected = true;
    };
    if (!disconnected_rejected) return false;
    native_transport.reconnect(&connection);
    const reconnect_delivery = native_transport.sendSigned(&connection, booted_native_sync_driver_reconnect_payload, signer) catch return false;
    if (!reconnect_delivery.network_delivered or reconnect_delivery.sequence <= delivery.sequence) return false;
    if (native_transport.disconnected_connections != 1 or native_transport.reconnect_count != 1) return false;

    const next_sequence_after_reconnect = connection.next_sequence;
    connection.next_sequence = connection.highest_sent_sequence;
    var replay_rejected = false;
    _ = native_transport.sendSigned(&connection, booted_native_sync_driver_replay_payload, signer) catch |err| {
        if (err != error.NativeTransportReplayRejected) return false;
        replay_rejected = true;
    };
    if (!replay_rejected or native_transport.replay_rejection_count != 1) return false;
    connection.next_sequence = next_sequence_after_reconnect;

    while (connection.in_flight_frames < sync_transport.MAX_NATIVE_IN_FLIGHT_FRAMES) {
        const fill_delivery = native_transport.sendSigned(&connection, booted_native_sync_driver_fill_payload, signer) catch return false;
        if (!fill_delivery.network_delivered) return false;
    }
    const tx_before_congestion = network_driver_task.activeDriverTransmitCount();
    const drops_before_congestion = native_transport.congestion_drop_count;
    var congestion_rejected = false;
    _ = native_transport.sendSigned(&connection, booted_native_sync_driver_overflow_payload, signer) catch |err| {
        if (err != error.NativeTransportCongested) return false;
        congestion_rejected = true;
    };
    if (!congestion_rejected) return false;
    if (native_transport.congestion_drop_count != drops_before_congestion + 1) return false;
    if (network_driver_task.activeDriverTransmitCount() != tx_before_congestion) return false;

    return DriverEgress.authorized_native_frames == sync_transport.MAX_NATIVE_IN_FLIGHT_FRAMES and
        native_transport.network_frame_count == sync_transport.MAX_NATIVE_IN_FLIGHT_FRAMES and
        native_transport.capture.capturedCount() == sync_transport.MAX_NATIVE_IN_FLIGHT_FRAMES;
}
