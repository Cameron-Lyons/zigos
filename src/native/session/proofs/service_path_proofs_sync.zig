const std = @import("std");
const abi = @import("../../core/abi.zig");
const binary_cursor = @import("binary_cursor");
const capability = @import("../../kernel_api/capability.zig");
const component_port = @import("../../kernel_api/component_port.zig");
const object_store = @import("../../storage/object_store.zig");
const principal = @import("../../core/principal.zig");
const session_manager = @import("../session_manager.zig");
const storage_service = @import("../../storage/storage_service.zig");
const sync_service = @import("../../sync/sync_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const workspace = @import("../../storage/workspace.zig");
const common = @import("service_path_proofs_common.zig");

const createBootedServiceTask = common.createBootedServiceTask;
const expectEndpointConnect = common.expectEndpointConnect;
const expectEndpointCreateWithFlags = common.expectEndpointCreateWithFlags;
const expectEndpointRecv = common.expectEndpointRecv;
const expectEndpointSend = common.expectEndpointSend;
const signer = common.signer;

pub fn proveBootedSyncServicePath(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    sync_record: *const @import("../supervisor.zig").ServiceRecord,
    sync_task: *task_runtime.TaskRecord,
    storage: *@import("../../storage/storage_service.zig").Service,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    const sync_owner = sync_record.owner;
    const peer_owner = principal.PrincipalId{ .kind = .service, .serial = 7_008 };
    const overlay_relay_owner = principal.PrincipalId{ .kind = .service, .serial = 7_009 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 7_001 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 7_002 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 7_003 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 7_004 };
    const storage_signer = signer("service-path-storage", 0x61);
    const user_signer = signer("service-path-user", 0x62);
    const laptop_signer = signer("service-path-laptop", 0x63);
    const tablet_signer = signer("service-path-tablet", 0x64);
    const contract_signer = signer("service-path-contract", 0x65);

    const sync_resident_state = try session_manager.system().syncResidentStatePtr();
    var sync_instance = try sync_service.Service.initWithStorage(
        sync_record.id,
        sync_task.id,
        sync_owner,
        storage,
        sync_resident_state,
    );
    const authority = try capability_table.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = sync_instance.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .endpoint_create = true,
            .endpoint_send = true,
            .endpoint_recv = true,
        } },
        .scope = .{
            .task_id = sync_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 100,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(sync_task.id, authority.id);

    var sync_port = sync_service.SyncPort.init(&sync_instance, capability_table);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync_task.id,
        .principal = sync_owner,
        .capability_id = authority.id,
        .now_ticks = 101,
    };
    const peer_task = try createBootedServiceTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        peer_owner,
        7_008,
        "sync-peer-service",
        "zigos.system.sync-service.peer",
        111,
    );
    runtime.allowHostPointerSyscallsForTask(sync_task.id);
    runtime.allowHostPointerSyscallsForTask(peer_task.task_id);
    try std.testing.expect(runtime.processSeparated(sync_task.id, peer_task.task_id));

    var peer_resident = sync_service.ResidentState{};
    var peer_instance = try sync_service.Service.initWithStorage(
        sync_record.id + 10_000,
        peer_task.task_id,
        peer_owner,
        storage,
        &peer_resident,
    );
    const peer_authority_capability = try capability_table.mintBootRoot(.{
        .holder = peer_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = peer_instance.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .endpoint_create = true,
            .endpoint_send = true,
            .endpoint_recv = true,
        } },
        .scope = .{
            .task_id = peer_task.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 101,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(peer_task.task_id, peer_authority_capability.id);
    var peer_port = sync_service.SyncPort.init(&peer_instance, capability_table);
    const peer_authority = sync_service.AuthorityContext{
        .task_id = peer_task.task_id,
        .principal = peer_owner,
        .capability_id = peer_authority_capability.id,
        .now_ticks = 112,
    };

    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_000),
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v1", 101),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_000),
        .object_type = .document,
        .payload = "notes-v2",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v2", 102),
        .parent_version_id = notes_v1.version_id,
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_001),
        .object_type = .media_asset,
        .payload = "cover-bytes",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "cover-bytes", 103),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_002),
        .object_type = .secret,
        .payload = "enc:service-path-secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:service-path-secret", 104),
    });
    const db_events = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_003),
        .object_type = .event_stream,
        .payload = "txn:service-path-event",
        .metadata = try object_store.signMetadata(storage_signer, "db-events", "application/zigos-event-stream", .event_stream, "txn:service-path-event", 105),
    });

    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "service-path-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes_v2.object_id, notes_v2.version_id, .document);
    try storage.stagePut(workspace_record.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    try storage.stagePut(workspace_record.id, "secrets/token", secret.object_id, secret.version_id, .secret);
    try storage.stagePut(workspace_record.id, "databases/app.notes.db/events", db_events.object_id, db_events.version_id, .event_stream);
    _ = try storage.commit(workspace_record.id, 105);
    const workspace_id = workspace_record.id.raw();

    _ = try sync_port.ensureUserRoot(sync_authority, user, "owner", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, laptop, "laptop", user_signer, laptop_signer, 106);
    const enrolled_laptop = sync_instance.findDeviceRecord(laptop).?.*;
    // A live service capability does not authorize a different signing key to
    // enroll peers, replace a trusted device key, or revoke the owner's device.
    try std.testing.expectError(error.RootAuthorityMismatch, sync_port.enrollTrustedDevice(sync_authority, user, tablet, "tablet", laptop_signer, tablet_signer, 107));
    try std.testing.expectError(error.RootAuthorityMismatch, sync_port.rotateDeviceKey(sync_authority, user, laptop, tablet_signer, tablet_signer, 107));
    try std.testing.expectError(error.RootAuthorityMismatch, sync_port.revokeTrustedDevice(sync_authority, user, laptop, tablet_signer, 107));
    try std.testing.expectEqualDeep(enrolled_laptop, sync_instance.findDeviceRecord(laptop).?.*);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, tablet, "tablet", user_signer, tablet_signer, 107);
    _ = try peer_port.ensureUserRoot(peer_authority, user, "owner", user_signer);
    _ = try peer_port.enrollTrustedDevice(peer_authority, user, laptop, "laptop", user_signer, laptop_signer, 112);
    _ = try peer_port.enrollTrustedDevice(peer_authority, user, tablet, "tablet", user_signer, tablet_signer, 113);
    const local_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "local",
        .mode = .local_network,
    });
    const relay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.service-path.zigos",
    });
    const overlay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.service-path.notes",
    });
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/", "secrets/", "databases/" },
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.service-path.zigos",
    });
    _ = try sync_port.configureOverlay(sync_authority, workspace_id, laptop, "overlay.service-path.notes", true);
    _ = try sync_port.publishPrivateService(sync_authority, workspace_id, "notes.remote");
    const peer_local_policy = try peer_port.createNetworkPolicy(peer_authority, .{
        .owner = peer_owner,
        .workspace_id = workspace_id,
        .label = "peer-local",
        .mode = .local_network,
    });
    _ = try peer_port.configureWorkspacePolicy(peer_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/", "secrets/", "databases/" },
        .device_to_device_policy_id = peer_local_policy.id,
    });
    const source_database_contract = try sync_port.registerDatabaseContract(sync_authority, workspace_id, "app.notes.db", "notes-db", contract_signer);
    const peer_database_contract = try peer_port.registerDatabaseContract(peer_authority, workspace_id, "app.notes.db", "notes-db", contract_signer);
    try std.testing.expectEqual(source_database_contract.id, peer_database_contract.id);

    const source_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        sync_task.id,
        authority.id,
        sync_task.id,
        "zigos.sync.source",
        .{ .local_only = true },
        114,
    );
    const peer_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        peer_task.task_id,
        peer_authority_capability.id,
        peer_task.task_id,
        "zigos.sync.peer",
        .{ .local_only = true, .service_port = true },
        115,
    );
    _ = try expectEndpointConnect(
        kernel_port,
        sync_task.id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        peer_endpoint.endpoint.endpoint_id,
        116,
    );
    const overlay_relay_task = try createBootedServiceTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        overlay_relay_owner,
        7_009,
        "overlay-relay-service",
        "zigos.system.overlay-relay",
        122,
    );
    try std.testing.expect(runtime.processSeparated(sync_task.id, overlay_relay_task.task_id));
    try std.testing.expect(runtime.processSeparated(peer_task.task_id, overlay_relay_task.task_id));
    var booted_relay_service = try sync_service.transport.BootedOverlayRelayService.init(
        sync_record.id + 20_000,
        overlay_relay_task.task_id,
        "relay.service-path.zigos",
    );
    defer booted_relay_service.deinit();
    const relay_capability = try capability_table.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = relay_policy.id },
        .rights = .{ .network_policy = .{
            .network_remote = true,
        } },
        .scope = .{
            .task_id = sync_task.id,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 123,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(sync_task.id, relay_capability.id);

    try sync_port.setReplicaVersion(sync_authority, workspace_id, tablet, "documents/notes.md", notes_v1.object_id, cover.version_id);
    const summary = try sync_port.replicateWorkspace(sync_authority, storage, workspace_id, laptop, tablet, .device_to_device);
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_device_to_device);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expect(summary.remote_access_ready);
    try std.testing.expectEqual(@as(usize, 4), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.snapshot_count);
    try std.testing.expectEqual(@as(usize, 1), summary.secret_transfer_count);
    try std.testing.expectEqual(@as(usize, 1), summary.transactional_count);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expectEqual(summary.transport_frame_count, summary.encrypted_transport_count);
    try std.testing.expect(sync_instance.findConflict(workspace_id, tablet, "documents/notes.md") != null);

    var exchange_tick: u64 = 124;
    try exchangeSyncFrameOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        sync_instance.latestTransportFrameForPath(workspace_id, tablet, "documents/notes.md").?,
        &exchange_tick,
    );
    try exchangeSyncFrameOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        sync_instance.latestTransportFrameForPath(workspace_id, tablet, "assets/cover.jpg").?,
        &exchange_tick,
    );
    const secret_frame = sync_instance.latestTransportFrameForPath(workspace_id, tablet, "secrets/token").?;
    try std.testing.expectEqual(sync_service.SyncSemantic.secure_transfer, secret_frame.semantic);
    try exchangeSyncFrameOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        secret_frame,
        &exchange_tick,
    );
    const db_frame = sync_instance.latestTransportFrameForPath(workspace_id, tablet, "databases/app.notes.db/events").?;
    try std.testing.expectEqual(sync_service.SyncSemantic.transactional_contract, db_frame.semantic);
    try exchangeSyncFrameOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        db_frame,
        &exchange_tick,
    );
    try std.testing.expectEqual(@as(usize, 4), peer_instance.transportFrameCountFor(workspace_id, tablet));
    try std.testing.expectEqual(notes_v2.version_id.raw(), peer_instance.replicaVersion(workspace_id, tablet, "documents/notes.md").?);
    try std.testing.expectEqual(cover.version_id.raw(), peer_instance.replicaVersion(workspace_id, tablet, "assets/cover.jpg").?);
    try std.testing.expectEqual(secret.version_id.raw(), peer_instance.replicaVersion(workspace_id, tablet, "secrets/token").?);
    try std.testing.expectEqual(db_events.version_id.raw(), peer_instance.replicaVersion(workspace_id, tablet, "databases/app.notes.db/events").?);

    var wrong_semantic_frame = sync_instance.latestTransportFrameForPath(workspace_id, tablet, "documents/notes.md").?;
    wrong_semantic_frame.semantic = .chunked_snapshot;
    try expectSyncFrameRejectedOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        wrong_semantic_frame,
        error.SyncSemanticMismatch,
        &exchange_tick,
    );
    var plaintext_secret_frame = secret_frame;
    plaintext_secret_frame.encrypted = false;
    try expectSyncFrameRejectedOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        plaintext_secret_frame,
        error.TransportDenied,
        &exchange_tick,
    );
    var revoked_target_frame = sync_instance.latestTransportFrameForPath(workspace_id, tablet, "assets/cover.jpg").?;
    revoked_target_frame.target_device = phone;
    try expectSyncFrameRejectedOverNativeEndpoint(
        kernel_port,
        sync_task.id,
        peer_task.task_id,
        source_endpoint.capability_id,
        peer_endpoint.capability_id,
        &peer_port,
        peer_authority,
        storage,
        revoked_target_frame,
        error.DeviceNotTrusted,
        &exchange_tick,
    );
    try std.testing.expectEqual(@as(usize, 4), peer_instance.transportFrameCountFor(workspace_id, tablet));

    const relay_session = try sync_port.openOverlaySession(
        sync_authority,
        workspace_id,
        laptop,
        tablet,
        .private_service,
        .relay_assisted,
        "notes.remote",
        140,
    );
    try std.testing.expect(relay_session.encrypted);
    try std.testing.expect(relay_session.relay_encrypted);
    try std.testing.expectEqualStrings("notes.remote", relay_session.privateServiceSlice());
    try std.testing.expect(!(try sync_port.evaluateNetworkPolicy(sync_authority, relay_policy.id, .{ .domain = "other.service-path.zigos" })).allowed);
    try std.testing.expectError(error.EgressDenied, sync_port.sendOverlayRelayFrameViaService(
        sync_authority,
        capability_table,
        &booted_relay_service,
        .{
            .workspace_id = workspace_id,
            .from_device = laptop,
            .to_device = tablet,
            .usage = .private_service,
            .private_service_label = "notes.remote",
            .relay_capability_id = relay_capability.id + 1,
            .payload = "remote-open",
            .signer = laptop_signer,
            .tick = 141,
        },
    ));
    try std.testing.expectEqual(@as(usize, 0), booted_relay_service.accepted_packets);

    const relay_exchange = try sync_port.sendOverlayRelayFrameViaService(
        sync_authority,
        capability_table,
        &booted_relay_service,
        .{
            .workspace_id = workspace_id,
            .from_device = laptop,
            .to_device = tablet,
            .usage = .private_service,
            .private_service_label = "notes.remote",
            .relay_capability_id = relay_capability.id,
            .payload = "remote-open",
            .signer = laptop_signer,
            .tick = 142,
        },
    );
    try std.testing.expect(relay_exchange.encrypted);
    try std.testing.expect(relay_exchange.relay_encrypted);
    try std.testing.expect(relay_exchange.remote_access);
    try std.testing.expect(relay_exchange.egress_allowed);
    try std.testing.expect(relay_exchange.delivered);
    try std.testing.expectEqual(@as(usize, "remote-open".len), relay_exchange.delivered_len);
    try std.testing.expectEqual(sync_service.OverlaySessionUse.private_service, relay_exchange.usage);
    try std.testing.expectEqualStrings("overlay.service-path.notes", relay_exchange.serviceIdentitySlice());
    try std.testing.expectEqualStrings("relay.service-path.zigos", relay_exchange.relayDomainSlice());
    try std.testing.expectEqualStrings("notes.remote", relay_exchange.privateServiceSlice());
    try std.testing.expectEqual(@as(usize, 1), booted_relay_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay_service.delivered_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay_service.relay.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay_service.relay.delivered_packets);

    try std.testing.expect(try sync_port.transferSecretObject(sync_authority, storage, workspace_id, secret.object_id, laptop, tablet, .device_to_device));
    try std.testing.expect(try sync_port.replicateDatabaseContract(sync_authority, source_database_contract.id, workspace_id, laptop, tablet, .relay_assisted));
    try std.testing.expectError(sync_service.Error.DeviceNotTrusted, sync_port.replicateWorkspace(sync_authority, storage, workspace_id, laptop, phone, .device_to_device));

    var restarted_source_resident = sync_service.ResidentState{};
    var restarted_source = try sync_service.Service.initWithStorage(
        sync_record.id,
        sync_task.id,
        sync_owner,
        storage,
        &restarted_source_resident,
    );
    var restarted_peer_resident = sync_service.ResidentState{};
    var restarted_peer = try sync_service.Service.initWithStorage(
        peer_instance.service_id,
        peer_task.task_id,
        peer_owner,
        storage,
        &restarted_peer_resident,
    );
    try std.testing.expect(restarted_source.loaded_existing_state);
    try std.testing.expect(restarted_peer.loaded_existing_state);
    try std.testing.expectEqual(notes_v2.version_id.raw(), restarted_source.replicaVersion(workspace_id, tablet, "documents/notes.md").?);
    try std.testing.expectEqual(notes_v2.version_id.raw(), restarted_peer.replicaVersion(workspace_id, tablet, "documents/notes.md").?);
    try std.testing.expectEqual(cover.version_id.raw(), restarted_peer.replicaVersion(workspace_id, tablet, "assets/cover.jpg").?);
    try std.testing.expectEqual(secret.version_id.raw(), restarted_peer.replicaVersion(workspace_id, tablet, "secrets/token").?);
    try std.testing.expectEqual(db_events.version_id.raw(), restarted_peer.replicaVersion(workspace_id, tablet, "databases/app.notes.db/events").?);
    var restarted_peer_port = sync_service.SyncPort.init(&restarted_peer, capability_table);
    const clean_peer_summary = try restarted_peer_port.replicateWorkspace(peer_authority, storage, workspace_id, laptop, tablet, .device_to_device);
    try std.testing.expectEqual(@as(usize, 0), clean_peer_summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 0), clean_peer_summary.transport_frame_count);
}

fn exchangeSyncFrameOverNativeEndpoint(
    kernel_port: *component_port.KernelPort,
    source_task_id: u64,
    peer_task_id: u64,
    source_endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_port: *sync_service.SyncPort,
    peer_authority: sync_service.AuthorityContext,
    storage: *const storage_service.Service,
    frame: sync_service.TransportFrame,
    tick: *u64,
) !void {
    var payload_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const payload = try encodeSyncFrame(&payload_buffer, frame);
    try expectEndpointSend(kernel_port, source_task_id, source_endpoint_capability_id, payload, tick.*);
    tick.* += 1;

    const received = try expectEndpointRecv(kernel_port, peer_task_id, peer_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received.present);

    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    const request = try decodeSyncFrame(received.payload[0..received.message.payload_len], &path_buffer);
    const accepted = try peer_port.acceptTransportFrame(peer_authority, storage, request);
    try std.testing.expect(accepted.encrypted);
    try std.testing.expectEqual(frame.workspace_generation, accepted.workspace_generation);
}

fn expectSyncFrameRejectedOverNativeEndpoint(
    kernel_port: *component_port.KernelPort,
    source_task_id: u64,
    peer_task_id: u64,
    source_endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_port: *sync_service.SyncPort,
    peer_authority: sync_service.AuthorityContext,
    storage: *const storage_service.Service,
    frame: sync_service.TransportFrame,
    expected_error: anyerror,
    tick: *u64,
) !void {
    var payload_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const payload = try encodeSyncFrame(&payload_buffer, frame);
    try expectEndpointSend(kernel_port, source_task_id, source_endpoint_capability_id, payload, tick.*);
    tick.* += 1;

    const received = try expectEndpointRecv(kernel_port, peer_task_id, peer_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received.present);

    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    const request = try decodeSyncFrame(received.payload[0..received.message.payload_len], &path_buffer);
    try std.testing.expectError(expected_error, peer_port.acceptTransportFrame(peer_authority, storage, request));
}

const sync_frame_magic = [_]u8{ 'Z', 'G', 'S', 'F' };
const SyncFrameWriter = binary_cursor.Writer(anyerror, error.SyncFrameTooLarge);
const SyncFrameReader = binary_cursor.Reader(anyerror, error.InvalidSyncFrame);

fn encodeSyncFrame(buffer: []u8, frame: sync_service.TransportFrame) ![]const u8 {
    if (frame.source_device.kind != .device or frame.target_device.kind != .device) return error.InvalidSyncFrame;
    const path = frame.pathSlice();
    if (path.len > workspace.MAX_ENTRY_PATH_BYTES or path.len > std.math.maxInt(u8)) return error.InvalidSyncFrame;
    const required_len = sync_frame_magic.len + (5 * @sizeOf(u64)) + 3 + @sizeOf(u32) + 1 + path.len;
    if (buffer.len < required_len) return error.SyncFrameTooLarge;

    var writer = SyncFrameWriter{ .buffer = buffer };
    try writer.writeBytes(&sync_frame_magic);
    try writer.writeU64(frame.workspace_id);
    try writer.writeU64(frame.object_id);
    try writer.writeU64(frame.version_id);
    try writer.writeU64(frame.source_device.serial);
    try writer.writeU64(frame.target_device.serial);
    try writer.writeByte(@backingInt(frame.transport));
    try writer.writeByte(@backingInt(frame.semantic));
    try writer.writeByte(@intFromBool(frame.encrypted));
    try writer.writeU32(frame.workspace_generation);
    try writer.writeByte(@intCast(path.len));
    try writer.writeBytes(path);
    return buffer[0..writer.offset];
}

fn decodeSyncFrame(payload: []const u8, path_buffer: *[workspace.MAX_ENTRY_PATH_BYTES]u8) !sync_service.TransportFrameRequest {
    const min_len = sync_frame_magic.len + (5 * @sizeOf(u64)) + 3 + @sizeOf(u32) + 1;
    if (payload.len < min_len) return error.InvalidSyncFrame;

    var reader = SyncFrameReader{ .buffer = payload };
    if (!std.mem.eql(u8, try reader.readSlice(sync_frame_magic.len), &sync_frame_magic)) return error.InvalidSyncFrame;

    const workspace_id = try reader.readU64();
    const object_id = try reader.readU64();
    const version_id = try reader.readU64();
    const source_serial = try reader.readU64();
    const target_serial = try reader.readU64();
    const transport: sync_service.TransportMode = @fromBackingInt(@intCast(try reader.readByte()));
    const semantic: sync_service.SyncSemantic = @fromBackingInt(@intCast(try reader.readByte()));
    const encrypted = (try reader.readByte()) != 0;
    const workspace_generation = try reader.readU32();
    const path_len = try reader.readByte();
    if (path_len > path_buffer.len or reader.remaining() != path_len) return error.InvalidSyncFrame;
    @memset(path_buffer[0..], 0);
    @memcpy(path_buffer[0..path_len], try reader.readSlice(path_len));

    return .{
        .workspace_id = workspace_id,
        .object_id = object_id,
        .version_id = version_id,
        .source_device = .{ .kind = .device, .serial = source_serial },
        .target_device = .{ .kind = .device, .serial = target_serial },
        .transport = transport,
        .semantic = semantic,
        .encrypted = encrypted,
        .workspace_generation = workspace_generation,
        .path = path_buffer[0..path_len],
    };
}
