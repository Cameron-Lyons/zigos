const std = @import("std");
const abi = @import("../../core/abi.zig");
const attestation_service = @import("../../platform/attestation_service.zig");
const binary_cursor = @import("binary_cursor");
const capability = @import("../../kernel_api/capability.zig");
const component_port = @import("../../kernel_api/component_port.zig");
const crypto_hash = @import("../../core/crypto_hash.zig");
const manifest = @import("../../policy/manifest.zig");
const measured_boot = @import("../../platform/measured_boot.zig");
const network_driver_task = @import("../../drivers/network_driver_task.zig");
const network_policy = @import("../../sync/network_policy.zig");
const object_store = @import("../../storage/object_store.zig");
const principal = @import("../../core/principal.zig");
const session_manager = @import("../session_manager.zig");
const signing = @import("../../core/signing.zig");
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
const addMeasuredNetworkArtifact = measured_boot.addMeasuredArtifact;

pub fn proveBootedSyncServicePath(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    sync_record: *const @import("../supervisor.zig").ServiceRecord,
    sync_task: *task_runtime.TaskRecord,
    network_service_task: *task_runtime.TaskRecord,
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
    const discovery_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const network_attestation_root = signer("booted-network-attestation-root", 0x7B);
    const network_attestation_identity = try signing.publicIdentity(network_attestation_root);
    const network_attestation_key = attestation_service.AttestationRootKeyHandle{
        .key_id = "booted-network-attestation-root",
        .label = "booted-network-attestation-root",
        .public_identity = network_attestation_identity,
        .generation = 1,
        .origin = .tpm,
        .provider_boundary = .platform_tpm,
        .custody = .tpm,
    };
    const network_attestation_descriptor = attestation_service.RootProviderDescriptor{
        .name = "booted-sync-tpm-attestation-root",
        .role = .production,
        .origin = .tpm,
        .key_id = "booted-network-attestation-root",
        .key_generation = 1,
        .provider_boundary = .platform_tpm,
        .custody = .tpm,
        .customer_verifiable = true,
    };
    const NetworkAttestationSigner = struct {
        signer: signing.SignerIdentity,

        fn sign(context: *anyopaque, handle: attestation_service.AttestationRootKeyHandle, digest: []const u8) !manifest.Signature {
            const fixture: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, fixture.signer.label, handle.label)) return error.RootIdentityMismatch;
            return signing.signWithDefaultRegistry(.ed25519, fixture.signer, digest);
        }
    };
    var network_attestation_fixture = NetworkAttestationSigner{ .signer = network_attestation_root };
    var network_attestation_provider = try attestation_service.ExternalAttestationRootProvider.init(
        network_attestation_descriptor,
        network_attestation_key,
        &network_attestation_fixture,
        NetworkAttestationSigner.sign,
    );
    const network_attestation_metadata_digest = network_attestation_provider.verifierMetadataDigest();
    const peer_boot = try verifiedBootedNetworkPeer(7_050);
    var peer_attestation = attestation_service.Service.init(tablet);
    try peer_attestation.provisionRootProvider(network_attestation_provider.provider());
    const native_identity_request = try attestation_service.RemoteAttestationRequest.init(.{
        .remote_party = "overlay.service-path.notes",
        .nonce = "native-net-00001",
        .policy_label = "booted-service-path-network-identity",
        .expected_key_origin = .tpm,
        .root_key_id = "booted-network-attestation-root",
        .minimum_root_generation = 1,
        .attestation_verifier_metadata_digest_required = true,
        .attestation_verifier_metadata_digest = network_attestation_metadata_digest,
    });
    const native_identity_response = try peer_attestation.respondToRemoteAttestationRequest(peer_boot, native_identity_request);
    try std.testing.expect(attestation_service.Service.verifyRemoteAttestationResponse(
        native_identity_response,
        native_identity_request,
        &peer_boot,
        network_attestation_identity,
    ));
    try std.testing.expect(native_identity_response.attestation_verifier_metadata_digest_present);
    try std.testing.expect(std.mem.eql(u8, &network_attestation_metadata_digest, &native_identity_response.attestation_verifier_metadata_digest));
    const native_identity_statement = native_identity_response.statement;
    const native_identity_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "native-service-identity",
        .mode = .named_service_identity,
        .target = "overlay.service-path.notes",
        .require_remote_attestation = true,
        .pinned_root_digest = native_identity_statement.root_digest,
        .pinned_attestation_verifier_metadata_digest = network_attestation_metadata_digest,
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
        .{ .local_only = true, .service_port = true },
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
    try proveBootedIdentityFirstNativeNetworkStack(
        runtime,
        capability_table,
        &sync_instance,
        network_service_task,
        native_identity_policy.id,
        discovery_policy.id,
        native_identity_statement.root_digest,
        network_attestation_metadata_digest,
        laptop,
        tablet,
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

fn proveBootedIdentityFirstNativeNetworkStack(
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    sync: *sync_service.Service,
    network_service_task: *task_runtime.TaskRecord,
    policy_id: u64,
    discovery_policy_id: u64,
    peer_root_digest: crypto_hash.Digest,
    attestation_verifier_metadata_digest: crypto_hash.Digest,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
) !void {
    try std.testing.expect(runtime.processSeparated(sync.task_id, network_service_task.id));
    const policy_capability = try capability_table.mintBootRoot(.{
        .holder = network_service_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = policy_id },
        .rights = .{ .network_policy = .{
            .network_remote = true,
        } },
        .scope = .{
            .task_id = network_service_task.id,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 117,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(network_service_task.id, policy_capability.id);

    const Harness = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;

        fn send(_: [6]u8, frame: []const u8) bool {
            send_count += 1;
            last_frame_len = frame.len;
            return true;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0x5A, 0x47, 0, 0, 1 };
        }
    };
    Harness.send_count = 0;
    Harness.last_frame_len = 0;
    network_driver_task.reset();
    defer network_driver_task.reset();

    const device = network_driver_task.NetworkDevice{
        .send = Harness.send,
        .receive = network_driver_task.noNetworkFrame,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(network_driver_task.activateDevice(&device, network_service_task.id));

    var broker = sync.egressBroker(capability_table);
    var stack = network_driver_task.NativeNetworkStack.init();
    defer stack.deinit();
    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = policy_capability.id,
        .policy_id = policy_id,
        .evidence = .{ .destination = .{ .service_identity = "overlay.service-path.notes" } },
        .now_ticks = 118,
    }, source_device, target_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.attestation_required, stack.last_denial_reason);

    const network_attestation_request_digest = crypto_hash.digestFromByte(0x87);
    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = sync.task_id,
        .principal_id = network_service_task.owner,
        .capability_id = policy_capability.id,
        .policy_id = policy_id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.service-path.notes" },
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = network_attestation_request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = peer_root_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = attestation_verifier_metadata_digest,
        },
        .now_ticks = 119,
    }, source_device, target_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.scope_violation, stack.last_denial_reason);

    var wrong_root_digest = peer_root_digest;
    wrong_root_digest[0] ^= 0xFF;
    try std.testing.expectError(error.EgressDenied, stack.openServiceIdentity(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = policy_capability.id,
        .policy_id = policy_id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.service-path.notes" },
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = network_attestation_request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = wrong_root_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = attestation_verifier_metadata_digest,
        },
        .now_ticks = 120,
    }, source_device, target_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.identity_pin_mismatch, stack.last_denial_reason);
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    try stack.bindPeerLink(target_device, .{ 0x02, 0x5A, 0x47, 0, 0, 2 });
    const connection = try stack.openServiceIdentity(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = policy_capability.id,
        .policy_id = policy_id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.service-path.notes" },
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = network_attestation_request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = peer_root_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = attestation_verifier_metadata_digest,
        },
        .now_ticks = 121,
    }, source_device, target_device);
    try std.testing.expect(connection.attestation_required);
    try std.testing.expect(connection.identity_pinned);
    try std.testing.expectEqualStrings("overlay.service-path.notes", connection.serviceIdentitySlice());

    const frame = try stack.sendServiceIdentityFrame(&connection, "native service identity payload");
    try std.testing.expect(frame.flags.encrypted);
    try std.testing.expect(frame.flags.egress_allowed);
    try std.testing.expect(frame.flags.attested);
    try std.testing.expect(frame.flags.identity_pinned);
    try std.testing.expect(!std.mem.eql(u8, frame.ciphertextSlice(), "native service identity payload"));
    try std.testing.expectEqual(@as(usize, 4), stack.attempted_connections);
    try std.testing.expectEqual(@as(usize, 3), stack.denied_before_transmit);
    try std.testing.expectEqual(@as(usize, 1), stack.opened_connections);
    try std.testing.expectEqual(@as(usize, 1), stack.transmitted_packets);
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
    try std.testing.expect(Harness.last_frame_len > "native service identity payload".len);

    const discovery_capability = try capability_table.mintBootRoot(.{
        .holder = network_service_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = discovery_policy_id },
        .rights = .{ .network_policy = .{
            .network_local = true,
        } },
        .scope = .{
            .task_id = network_service_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 122,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(network_service_task.id, discovery_capability.id);

    var discovery_stack = network_driver_task.NativeNetworkStack.init();
    defer discovery_stack.deinit();
    try std.testing.expectError(error.EgressDenied, discovery_stack.openLocalDiscovery(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy_id,
        .evidence = .{ .destination = .local_network },
        .now_ticks = 122,
    }, source_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.destination_mismatch, discovery_stack.last_denial_reason);

    try std.testing.expectError(error.EgressDenied, discovery_stack.openLocalDiscovery(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy_id,
        .evidence = .{ .destination = .{ .discovery_class = "camera" } },
        .now_ticks = 123,
    }, source_device));
    try std.testing.expectEqual(network_policy.EgressDecisionReason.destination_mismatch, discovery_stack.last_denial_reason);

    const discovery_connection = try discovery_stack.openLocalDiscovery(&broker, .{
        .task_id = network_service_task.id,
        .principal_id = network_service_task.owner,
        .capability_id = discovery_capability.id,
        .policy_id = discovery_policy_id,
        .evidence = .{ .destination = .{ .discovery_class = "printer" } },
        .now_ticks = 124,
    }, source_device);
    try std.testing.expect(discovery_connection.scoped_discovery);
    try std.testing.expectEqualStrings("printer", discovery_connection.discoveryClassSlice());

    const discovery_frame = try discovery_stack.sendLocalDiscoveryProbe(&discovery_connection, "discover-printer");
    try std.testing.expect(discovery_frame.encrypted);
    try std.testing.expect(discovery_frame.egress_allowed);
    try std.testing.expect(discovery_frame.scoped_discovery);
    try std.testing.expectEqualStrings("printer", discovery_frame.discoveryClassSlice());
    try std.testing.expect(!std.mem.eql(u8, discovery_frame.ciphertextSlice(), "discover-printer"));
    try std.testing.expectEqual(@as(usize, 2), Harness.send_count);
}

fn verifiedBootedNetworkPeer(generation: u64) !measured_boot.BootRecord {
    var recorder = measured_boot.Recorder.init();
    var artifact_manifest = measured_boot.ArtifactManifest.init(generation);
    recorder.begin(generation);
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos", "kernel=network-peer");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .base_image, "base-network-peer", "image=network-peer");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .critical_service, "sync", "healthy");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .policy, "identity-first", "strict");
    try addMeasuredNetworkArtifact(&recorder, &artifact_manifest, .driver_set, "signed-network-driver", "net");
    var boot = recorder.finalize();
    try measured_boot.verifyBootRecordAgainstManifest(&boot, &artifact_manifest, .bootloader_provided);
    return boot;
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
    try writer.writeByte(@intFromEnum(frame.transport));
    try writer.writeByte(@intFromEnum(frame.semantic));
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
    const transport: sync_service.TransportMode = @enumFromInt(try reader.readByte());
    const semantic: sync_service.SyncSemantic = @enumFromInt(try reader.readByte());
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
