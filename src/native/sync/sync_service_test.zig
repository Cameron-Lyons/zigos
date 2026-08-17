const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const device_graph = @import("device_graph.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("../task/generated_image_fixtures.zig") else struct {};
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("sync_service.zig");
const sync_indexes = @import("sync_service/indexes.zig");
const sync_transport = @import("sync_transport.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");
const workspace = @import("../storage/workspace.zig");

const addSyncDeviceGraphMeasuredArtifact = measured_boot.addMeasuredArtifact;
const OverlaySessionState = sync_service.OverlaySessionState;
const OverlaySessionUse = sync_service.OverlaySessionUse;
const ResidentState = sync_service.ResidentState;
const Service = sync_service.Service;
const ServiceWith = sync_service.ServiceWith;
const SyncSemantic = sync_service.SyncSemantic;
const PEER_SYNC_MEDIA_PAYLOAD_BYTES: usize = 5000;

const EndToEndPolicyIds = struct {
    local_policy_id: u64,
    overlay_policy_id: u64,
    relay_policy_id: u64,
};

fn mintSyncServiceAuthority(
    capability_table: *capability.CapabilityTable,
    service: anytype,
    holder: principal.PrincipalId,
) !capability.Capability {
    return mintSyncServiceAuthorityWithRights(capability_table, service, holder, .{ .service = .{
        .endpoint_connect = true,
    } });
}

fn mintSyncServiceAuthorityWithRights(
    capability_table: *capability.CapabilityTable,
    service: anytype,
    holder: principal.PrincipalId,
    rights: capability.CapabilityRights,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = service.service_id },
        .rights = rights,
        .scope = .{
            .task_id = service.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 1_000,
        },
        .audit = .{},
    });
}

fn syncAuthority(
    service: anytype,
    holder: principal.PrincipalId,
    authority_capability: capability.Capability,
    now_ticks: u64,
) sync_service.AuthorityContext {
    return .{
        .task_id = service.task_id,
        .principal = holder,
        .capability_id = authority_capability.id,
        .now_ticks = now_ticks,
    };
}

test "sync port requires service-scoped authority before device graph mutation" {
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 820 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 821 };
    const signer = signing.SignerIdentity{
        .label = "sync-port-user",
        .seed = signing.seedFromByte(0x82),
    };

    var service = Service.init(8_200, 8_201, sync_owner);
    var capabilities = capability.CapabilityTable.init();
    var port = sync_service.SyncPort.init(&service, &capabilities);

    try std.testing.expectError(error.CapabilityNotFound, port.ensureUserRoot(.{
        .task_id = service.task_id,
        .principal = sync_owner,
        .capability_id = 0,
        .now_ticks = 10,
    }, user, "owner", signer));

    const wrong_right = try mintSyncServiceAuthorityWithRights(&capabilities, &service, sync_owner, .{ .service = .{
        .capability_query = true,
    } });
    try std.testing.expectError(error.PermissionDenied, port.ensureUserRoot(.{
        .task_id = service.task_id,
        .principal = sync_owner,
        .capability_id = wrong_right.id,
        .now_ticks = 10,
    }, user, "owner", signer));

    const valid = try mintSyncServiceAuthority(&capabilities, &service, sync_owner);
    try std.testing.expectError(error.PermissionDenied, port.ensureUserRoot(.{
        .task_id = service.task_id + 1,
        .principal = sync_owner,
        .capability_id = valid.id,
        .now_ticks = 10,
    }, user, "owner", signer));

    const wrong_target = try capabilities.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = service.service_id + 1 },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = service.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 1_000,
        },
        .audit = .{},
    });
    try std.testing.expectError(error.CapabilityRequired, port.ensureUserRoot(.{
        .task_id = service.task_id,
        .principal = sync_owner,
        .capability_id = wrong_target.id,
        .now_ticks = 10,
    }, user, "owner", signer));

    const root = try port.ensureUserRoot(syncAuthority(&service, sync_owner, valid, 11), user, "owner", signer);
    try std.testing.expectEqual(user, root.principal_id);
    try std.testing.expectEqualStrings("owner", root.labelSlice());
}

test "sync service configuration errors preserve live policy and overlay records" {
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8_250 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 8_251 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 8_252 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 8_253 };
    const workspace_id: u64 = 8_254;
    const too_long_label = "0123456789012345678901234567890123456789012345678";

    var service = Service.init(8_255, 8_256, sync_owner);
    _ = try service.configureWorkspacePolicy(.{
        .workspace_id = workspace_id,
        .owner = user,
        .selective_prefixes = &.{"documents/"},
        .relay_domain = "relay.valid",
    });
    try std.testing.expectError(error.NetworkTargetTooLong, service.configureWorkspacePolicy(.{
        .workspace_id = workspace_id,
        .owner = user,
        .selective_prefixes = &.{"secrets/"},
        .relay_domain = too_long_label,
    }));
    const policy = service.findWorkspacePolicy(workspace_id).?;
    try std.testing.expectEqualStrings("relay.valid", policy.relayDomainSlice());
    try std.testing.expect(policy.matchesPath("documents/notes.md"));
    try std.testing.expect(!policy.matchesPath("secrets/notes.md"));

    _ = try service.configureOverlay(workspace_id, laptop, "overlay.valid", true);
    try std.testing.expectError(error.ServiceIdentityTooLong, service.configureOverlay(workspace_id, tablet, too_long_label, false));
    const overlay = service.findOverlay(workspace_id).?;
    try std.testing.expectEqualStrings("overlay.valid", overlay.serviceIdentitySlice());
    try std.testing.expect(overlay.home_device.eql(laptop));
    try std.testing.expect(overlay.remote_access_enabled);

    _ = try service.publishPrivateService(workspace_id, "notes.remote");
    try std.testing.expectError(error.ServiceIdentityTooLong, service.publishPrivateService(workspace_id, too_long_label));
    const overlay_with_service = service.findOverlay(workspace_id).?;
    try std.testing.expectEqual(@as(usize, 1), overlay_with_service.private_service_count);
    try std.testing.expect(overlay_with_service.hasPrivateService("notes.remote"));
}

test "sync service persists platform-backed device key bindings across restart" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 9_300 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 9_301 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 9_302 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 9_303 };
    const user_signer = signing.SignerIdentity{
        .label = "persistent-platform-user",
        .seed = signing.seedFromByte(0x91),
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "persistent-platform-laptop",
        .seed = signing.seedFromByte(0x92),
    };
    const rotated_laptop_signer = signing.SignerIdentity{
        .label = "persistent-platform-laptop-v2",
        .seed = signing.seedFromByte(0x93),
    };
    const boot = try verifiedSyncDeviceGraphBoot(9_340, .bootloader_provided);
    const rotated_boot = try verifiedSyncDeviceGraphBoot(9_341, .bootloader_provided);
    const provider = device_graph.PlatformKeyBindingRequest{
        .root = try device_graph.PlatformDeviceRoot.fromBootRecord(laptop, .secure_enclave, "laptop-secure-enclave-key", &boot),
    };
    const rotated_provider = device_graph.PlatformKeyBindingRequest{
        .root = try device_graph.PlatformDeviceRoot.fromBootRecord(laptop, .tpm, "laptop-tpm-key", &rotated_boot),
    };

    var storage = storage_service.Service.initWithStore(9_310, 9_311, storage_owner, &storage_checkpoint_store);
    var resident = ResidentState{};
    var service = try Service.initWithStorage(9_320, 9_321, sync_owner, &storage, &resident);
    var capabilities = capability.CapabilityTable.init();
    var port = sync_service.SyncPort.init(&service, &capabilities);
    const authority_capability = try mintSyncServiceAuthority(&capabilities, &service, sync_owner);

    _ = try port.ensureUserRoot(syncAuthority(&service, sync_owner, authority_capability, 1), user, "owner", user_signer);
    const enrolled = try port.enrollPlatformBackedDevice(syncAuthority(&service, sync_owner, authority_capability, 2), user, laptop, "laptop", user_signer, laptop_signer, provider, 2);
    try std.testing.expect(enrolled.usesPlatformBackedKey());
    try std.testing.expect(enrolled.hasBootloaderBackedPlatformRoot());
    try std.testing.expectEqual(device_graph.DeviceKeyOrigin.secure_enclave, enrolled.device_key_origin);
    try std.testing.expectEqualSlices(u8, boot.root_digest[0..], enrolled.platform_root_digest[0..]);

    const rotated = try port.rotatePlatformBackedDeviceKey(syncAuthority(&service, sync_owner, authority_capability, 3), user, laptop, user_signer, rotated_laptop_signer, rotated_provider, 3);
    const rotated_digest = rotated.platform_key_digest;
    try port.revokeTrustedDevice(syncAuthority(&service, sync_owner, authority_capability, 4), user, laptop, user_signer, 4);

    var restarted_resident = ResidentState{};
    var restarted = try Service.initWithStorage(9_330, 9_331, sync_owner, &storage, &restarted_resident);
    const restored = restarted.findDeviceRecord(laptop).?;
    try std.testing.expect(restored.usesPlatformBackedKey());
    try std.testing.expect(restored.hasBootloaderBackedPlatformRoot());
    try std.testing.expectEqual(device_graph.DeviceKeyOrigin.tpm, restored.device_key_origin);
    try std.testing.expectEqualStrings("laptop-tpm-key", restored.platformKeyLabelSlice());
    try std.testing.expectEqualSlices(u8, rotated_digest[0..], restored.platform_key_digest[0..]);
    try std.testing.expectEqual(@as(u64, 9_341), restored.platform_root_generation);
    try std.testing.expectEqual(measured_boot.RootProvenance.bootloader_provided, restored.platform_root_provenance);
    try std.testing.expectEqualSlices(u8, rotated_boot.root_digest[0..], restored.platform_root_digest[0..]);
    try std.testing.expectEqual(@as(u32, 2), restored.key_rotation_generation);
    try std.testing.expect(!restored.isTrusted());
    try std.testing.expectEqual(@as(u64, 4), restored.revoked_at_ticks);
}

test "sync service requires database contract before transactional workspace replication" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 8_500 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8_501 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 8_502 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 8_503 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 8_504 };
    const storage_signer = signing.SignerIdentity{
        .label = "db-contract-storage",
        .seed = signing.seedFromByte(0x91),
    };
    const user_signer = signing.SignerIdentity{
        .label = "db-contract-user",
        .seed = signing.seedFromByte(0x92),
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "db-contract-laptop",
        .seed = signing.seedFromByte(0x93),
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "db-contract-tablet",
        .seed = signing.seedFromByte(0x94),
    };
    const contract_signer = signing.SignerIdentity{
        .label = "db-contract",
        .seed = signing.seedFromByte(0x95),
    };

    var storage = storage_service.Service.initWithStore(8_510, 8_511, storage_owner, &storage_checkpoint_store);
    const document = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(8_520),
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v1", 10),
    });
    const db_events = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(8_521),
        .object_type = .event_stream,
        .payload = "txn:insert-note",
        .metadata = try object_store.signMetadata(storage_signer, "db-events", "application/zigos-event-stream", .event_stream, "txn:insert-note", 11),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "db-contract-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", document.object_id, document.version_id, .document);
    try storage.stagePut(workspace_record.id, "databases/app.notes.db/events", db_events.object_id, db_events.version_id, .event_stream);
    _ = try storage.commit(workspace_record.id, 12);

    var service = Service.init(8_530, 8_531, sync_owner);
    var capabilities = capability.CapabilityTable.init();
    const service_authority_capability = try mintSyncServiceAuthority(&capabilities, &service, sync_owner);
    var port = sync_service.SyncPort.init(&service, &capabilities);
    const authority = syncAuthority(&service, sync_owner, service_authority_capability, 20);
    _ = try port.ensureUserRoot(authority, user, "owner", user_signer);
    _ = try port.enrollTrustedDevice(authority, user, laptop, "laptop", user_signer, laptop_signer, 21);
    _ = try port.enrollTrustedDevice(authority, user, tablet, "tablet", user_signer, tablet_signer, 22);

    const local_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "local",
        .mode = .local_network,
    });
    _ = try port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "databases/" },
        .device_to_device_policy_id = local_policy.id,
    });

    try std.testing.expectError(error.DatabaseContractNotFound, port.replicateWorkspace(
        authority,
        &storage,
        workspace_record.id.raw(),
        laptop,
        tablet,
        .device_to_device,
    ));
    try std.testing.expectEqual(@as(usize, 0), service.transportFrameCountFor(workspace_record.id.raw(), tablet));
    try std.testing.expect(service.replicaVersion(workspace_record.id.raw(), tablet, "documents/notes.md") == null);

    _ = try port.registerDatabaseContract(authority, workspace_record.id.raw(), "app.notes.db", "notes-db", contract_signer);
    const summary = try port.replicateWorkspace(
        authority,
        &storage,
        workspace_record.id.raw(),
        laptop,
        tablet,
        .device_to_device,
    );
    try std.testing.expectEqual(@as(usize, 2), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.transactional_count);
    try std.testing.expectEqual(@as(usize, 2), summary.transport_frame_count);
    try std.testing.expectEqual(summary.transport_frame_count, summary.encrypted_transport_count);
    try std.testing.expectEqual(document.version_id.raw(), service.replicaVersion(workspace_record.id.raw(), tablet, "documents/notes.md").?);
    try std.testing.expectEqual(db_events.version_id.raw(), service.replicaVersion(workspace_record.id.raw(), tablet, "databases/app.notes.db/events").?);
    const db_frame = service.latestTransportFrameForPath(workspace_record.id.raw(), tablet, "databases/app.notes.db/events").?;
    try std.testing.expectEqual(SyncSemantic.transactional_contract, db_frame.semantic);
}

test "sync service persists durable transport queues and enforces replay and workspace sharing policy" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 8_700 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8_701 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 8_702 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 8_703 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 8_704 };
    const storage_signer = signing.SignerIdentity{
        .label = "durable-queue-storage",
        .seed = signing.seedFromByte(0xB1),
    };
    const user_signer = signing.SignerIdentity{
        .label = "durable-queue-user",
        .seed = signing.seedFromByte(0xB2),
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "durable-queue-laptop",
        .seed = signing.seedFromByte(0xB3),
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "durable-queue-tablet",
        .seed = signing.seedFromByte(0xB4),
    };
    const path = "documents/queue.md";

    var storage = storage_service.Service.initWithStore(8_710, 8_711, storage_owner, &storage_checkpoint_store);
    const version = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(8_720),
        .object_type = .document,
        .payload = "queue v1",
        .metadata = try object_store.signMetadata(storage_signer, "queue-v1", "text/plain", .document, "queue v1", 10),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "durable-queue-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, path, version.object_id, version.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);

    var resident = ResidentState{};
    var service = try Service.initWithStorage(8_730, 8_731, sync_owner, &storage, &resident);
    var capabilities = capability.CapabilityTable.init();
    const authority_capability = try mintSyncServiceAuthority(&capabilities, &service, sync_owner);
    var port = sync_service.SyncPort.init(&service, &capabilities);
    const authority = syncAuthority(&service, sync_owner, authority_capability, 20);
    _ = try port.ensureUserRoot(authority, user, "owner", user_signer);
    _ = try port.enrollTrustedDevice(authority, user, laptop, "laptop", user_signer, laptop_signer, 21);
    _ = try port.enrollTrustedDevice(authority, user, tablet, "tablet", user_signer, tablet_signer, 22);
    const local_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "local",
        .mode = .local_network,
    });
    _ = try port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .require_shared_access = true,
        .selective_prefixes = &.{"documents/"},
        .device_to_device_policy_id = local_policy.id,
    });

    try std.testing.expectError(error.TransportDenied, port.replicateWorkspace(
        authority,
        &storage,
        workspace_record.id.raw(),
        laptop,
        tablet,
        .device_to_device,
    ));
    try std.testing.expectEqual(@as(usize, 0), service.transportFrameCountFor(workspace_record.id.raw(), tablet));

    try storage.shareWorkspace(workspace_record.id, .{
        .principal_id = tablet,
        .can_read = true,
        .expires_at_ticks = 19,
        .network_scope = .local_only,
    });
    try std.testing.expectError(error.TransportDenied, port.replicateWorkspace(
        authority,
        &storage,
        workspace_record.id.raw(),
        laptop,
        tablet,
        .device_to_device,
    ));

    try storage.shareWorkspace(workspace_record.id, .{
        .principal_id = tablet,
        .can_read = true,
        .network_scope = .local_only,
    });
    const summary = try port.replicateWorkspace(
        authority,
        &storage,
        workspace_record.id.raw(),
        laptop,
        tablet,
        .device_to_device,
    );
    try std.testing.expectEqual(@as(usize, 1), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.transport_frame_count);
    try std.testing.expectEqual(@as(usize, 1), resident.outboundTransportFrameCount());
    const frame_path_key = sync_indexes.transportFramePathLookupKey(workspace_record.id.raw(), tablet, path);
    try std.testing.expectEqual(@as(usize, 1), service.outbound_transport_path_index.count(frame_path_key));
    try std.testing.expectEqual(@as(usize, 0), service.inbound_transport_path_index.count(frame_path_key));

    const outbound = service.latestTransportFrameForPath(workspace_record.id.raw(), tablet, path).?;
    var request = sync_service.TransportFrameRequest{
        .source_frame_id = outbound.id,
        .workspace_id = workspace_record.id.raw(),
        .object_id = outbound.object_id,
        .version_id = outbound.version_id,
        .source_device = laptop,
        .target_device = tablet,
        .transport = .device_to_device,
        .semantic = .mergeable_crdt,
        .encrypted = true,
        .workspace_generation = outbound.workspace_generation,
        .path = path,
    };
    const accepted = try port.acceptTransportFrame(authority, &storage, request);
    const accepted_source_frame_key = sync_indexes.inboundSourceFrameLookupKey(
        workspace_record.id.raw(),
        laptop,
        tablet,
        outbound.id,
    );
    try std.testing.expectEqual(outbound.id, accepted.source_frame_id);
    try std.testing.expectEqual(@as(usize, 2), service.transportFrameCountFor(workspace_record.id.raw(), tablet));
    try std.testing.expectEqual(@as(usize, 1), service.outbound_transport_path_index.count(frame_path_key));
    try std.testing.expectEqual(@as(usize, 1), service.inbound_transport_path_index.count(frame_path_key));
    try std.testing.expectEqual(@as(usize, 1), service.inbound_source_frame_index.count(accepted_source_frame_key));

    const duplicate = try port.acceptTransportFrame(authority, &storage, request);
    try std.testing.expectEqual(accepted.id, duplicate.id);
    try std.testing.expectEqual(@as(usize, 2), service.transportFrameCountFor(workspace_record.id.raw(), tablet));
    try std.testing.expectEqual(@as(usize, 1), service.inbound_transport_path_index.count(frame_path_key));
    try std.testing.expectEqual(@as(usize, 1), service.inbound_source_frame_index.count(accepted_source_frame_key));

    request.source_frame_id = 100;
    _ = try port.acceptTransportFrame(authority, &storage, request);
    const latest_source_frame_key = sync_indexes.inboundSourceFrameLookupKey(
        workspace_record.id.raw(),
        laptop,
        tablet,
        request.source_frame_id,
    );
    try std.testing.expectEqual(@as(usize, 2), service.inbound_transport_path_index.count(frame_path_key));
    try std.testing.expectEqual(@as(usize, 1), service.inbound_source_frame_index.count(latest_source_frame_key));
    try std.testing.expectEqual(@as(u64, 100), service.latestTransportFrameForPath(workspace_record.id.raw(), tablet, path).?.source_frame_id);
    request.source_frame_id = 2;
    try std.testing.expectError(error.TransportReplayRejected, port.acceptTransportFrame(authority, &storage, request));

    var restarted_resident = ResidentState{};
    var restarted = try Service.initWithStorage(8_740, 8_741, sync_owner, &storage, &restarted_resident);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 1), restarted_resident.outboundTransportFrameCount());
    try std.testing.expectEqual(@as(usize, 2), restarted_resident.inboundTransportFrameCount());
    try std.testing.expectEqual(@as(usize, 3), restarted.transportFrameCountFor(workspace_record.id.raw(), tablet));
    try std.testing.expectEqual(@as(usize, 1), restarted.outbound_transport_path_index.count(frame_path_key));
    try std.testing.expectEqual(@as(usize, 2), restarted.inbound_transport_path_index.count(frame_path_key));
    try std.testing.expectEqual(@as(usize, 1), restarted.inbound_source_frame_index.count(accepted_source_frame_key));
    try std.testing.expectEqual(@as(usize, 1), restarted.inbound_source_frame_index.count(latest_source_frame_key));
    try std.testing.expectEqual(@as(u64, 100), restarted.latestTransportFrameForPath(workspace_record.id.raw(), tablet, path).?.source_frame_id);

    var saw_duplicate_count = false;
    for (restarted_resident.persisted_state.inbound_transport_frames.slots) |slot| {
        if (!slot.in_use or slot.frame.source_frame_id != outbound.id) continue;
        try std.testing.expectEqual(@as(u16, 1), slot.duplicate_count);
        saw_duplicate_count = true;
    }
    try std.testing.expect(saw_duplicate_count);
}

test "sync service inbound queue evicts out-of-window frames instead of the queue-full cliff" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 9_700 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 9_701 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 9_702 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 9_703 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 9_704 };
    const storage_signer = signing.SignerIdentity{ .label = "evict-storage", .seed = signing.seedFromByte(0xC1) };
    const user_signer = signing.SignerIdentity{ .label = "evict-user", .seed = signing.seedFromByte(0xC2) };
    const laptop_signer = signing.SignerIdentity{ .label = "evict-laptop", .seed = signing.seedFromByte(0xC3) };
    const tablet_signer = signing.SignerIdentity{ .label = "evict-tablet", .seed = signing.seedFromByte(0xC4) };
    const path = "documents/evict.md";

    var storage = storage_service.Service.initWithStore(9_710, 9_711, storage_owner, &storage_checkpoint_store);
    const version = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(9_720),
        .object_type = .document,
        .payload = "evict v1",
        .metadata = try object_store.signMetadata(storage_signer, "evict-v1", "text/plain", .document, "evict v1", 10),
    });
    const workspace_record = try storage.createWorkspace(.{ .owner = user, .label = "evict-notes" });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, path, version.object_id, version.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);

    var resident = ResidentState{};
    var service = try Service.initWithStorage(9_730, 9_731, sync_owner, &storage, &resident);
    var capabilities = capability.CapabilityTable.init();
    const authority_capability = try mintSyncServiceAuthority(&capabilities, &service, sync_owner);
    var port = sync_service.SyncPort.init(&service, &capabilities);
    const authority = syncAuthority(&service, sync_owner, authority_capability, 20);
    _ = try port.ensureUserRoot(authority, user, "owner", user_signer);
    _ = try port.enrollTrustedDevice(authority, user, laptop, "laptop", user_signer, laptop_signer, 21);
    _ = try port.enrollTrustedDevice(authority, user, tablet, "tablet", user_signer, tablet_signer, 22);
    const local_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "local",
        .mode = .local_network,
    });
    _ = try port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .require_shared_access = true,
        .selective_prefixes = &.{"documents/"},
        .device_to_device_policy_id = local_policy.id,
    });
    try storage.shareWorkspace(workspace_record.id, .{
        .principal_id = tablet,
        .can_read = true,
        .network_scope = .local_only,
    });

    var request = sync_service.TransportFrameRequest{
        .source_frame_id = 0,
        .workspace_id = workspace_record.id.raw(),
        .object_id = version.object_id.raw(),
        .version_id = version.version_id.raw(),
        .source_device = laptop,
        .target_device = tablet,
        .transport = .device_to_device,
        .semantic = .mergeable_crdt,
        .encrypted = true,
        .workspace_generation = 1,
        .path = path,
    };

    const total: u64 = sync_service.MAX_TRANSPORT_FRAMES * 2;
    var sfid: u64 = 1;
    while (sfid <= total) : (sfid += 1) {
        request.source_frame_id = sfid;
        _ = try port.acceptTransportFrame(authority, &storage, request);
    }

    try std.testing.expect(resident.inboundTransportFrameCount() <= sync_service.MAX_TRANSPORT_FRAMES);
    try std.testing.expectEqual(@as(usize, 0), service.inbound_source_frame_index.count(sync_indexes.inboundSourceFrameLookupKey(
        workspace_record.id.raw(),
        laptop,
        tablet,
        1,
    )));
    try std.testing.expectEqual(@as(usize, 1), service.inbound_source_frame_index.count(sync_indexes.inboundSourceFrameLookupKey(
        workspace_record.id.raw(),
        laptop,
        tablet,
        total,
    )));

    request.source_frame_id = 1;
    try std.testing.expectError(error.TransportReplayRejected, port.acceptTransportFrame(authority, &storage, request));

    request.source_frame_id = total;
    const before = resident.inboundTransportFrameCount();
    const duplicate = try port.acceptTransportFrame(authority, &storage, request);
    try std.testing.expectEqual(total, duplicate.source_frame_id);
    try std.testing.expectEqual(before, resident.inboundTransportFrameCount());
}

test "sync service treats per-object shares and conflict review as local-first primitives" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 8_800 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8_801 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 8_802 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 8_803 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 8_804 };
    const storage_signer = signing.SignerIdentity{
        .label = "object-share-storage",
        .seed = signing.seedFromByte(0xD1),
    };
    const user_signer = signing.SignerIdentity{
        .label = "object-share-user",
        .seed = signing.seedFromByte(0xD2),
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "object-share-laptop",
        .seed = signing.seedFromByte(0xD3),
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "object-share-tablet",
        .seed = signing.seedFromByte(0xD4),
    };
    const notes_path = "documents/shared.md";
    const private_path = "documents/private.md";

    var storage = storage_service.Service.initWithStore(8_810, 8_811, storage_owner, &storage_checkpoint_store);
    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(8_820),
        .object_type = .document,
        .payload = "base",
        .metadata = try object_store.signMetadata(storage_signer, "notes-v1", "text/plain", .document, "base", 10),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = notes_v1.object_id,
        .object_type = .document,
        .payload = "laptop edit",
        .metadata = try object_store.signMetadata(storage_signer, "notes-v2", "text/plain", .document, "laptop edit", 11),
        .parent_version_id = notes_v1.version_id,
    });
    const tablet_offline = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(8_822),
        .object_type = .document,
        .payload = "tablet offline edit",
        .metadata = try object_store.signMetadata(storage_signer, "notes-tablet", "text/plain", .document, "tablet offline edit", 12),
    });
    const private = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(8_821),
        .object_type = .document,
        .payload = "private",
        .metadata = try object_store.signMetadata(storage_signer, "private", "text/plain", .document, "private", 13),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "object-share-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, notes_path, notes_v2.object_id, notes_v2.version_id, .document);
    try storage.stagePut(workspace_record.id, private_path, private.object_id, private.version_id, .document);
    _ = try storage.commit(workspace_record.id, 14);
    const scoped_share = try (workspace.ShareGrant{
        .principal_id = tablet,
        .can_read = true,
        .network_scope = .local_only,
        .audit_visibility = .shared_participants,
    }).withObjectScope(notes_v2.object_id, notes_path);
    try storage.shareWorkspace(workspace_record.id, scoped_share);

    var resident = ResidentState{};
    var service = try Service.initWithStorage(8_830, 8_831, sync_owner, &storage, &resident);
    var capabilities = capability.CapabilityTable.init();
    const authority_capability = try mintSyncServiceAuthority(&capabilities, &service, sync_owner);
    var port = sync_service.SyncPort.init(&service, &capabilities);
    const authority = syncAuthority(&service, sync_owner, authority_capability, 20);
    _ = try port.ensureUserRoot(authority, user, "owner", user_signer);
    _ = try port.enrollTrustedDevice(authority, user, laptop, "laptop", user_signer, laptop_signer, 21);
    _ = try port.enrollTrustedDevice(authority, user, tablet, "tablet", user_signer, tablet_signer, 22);
    const local_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "local",
        .mode = .local_network,
    });
    _ = try port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .require_shared_access = true,
        .selective_prefixes = &.{"documents/"},
        .device_to_device_policy_id = local_policy.id,
    });

    try port.setReplicaVersion(authority, workspace_record.id.raw(), tablet, notes_path, notes_v2.object_id, tablet_offline.version_id);
    const summary = try port.replicateWorkspace(
        authority,
        &storage,
        workspace_record.id.raw(),
        laptop,
        tablet,
        .device_to_device,
    );
    try std.testing.expectEqual(@as(usize, 1), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.skipped_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.share_denied_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expectEqual(@as(usize, 1), summary.transport_frame_count);
    try std.testing.expect(service.latestTransportFrameForPath(workspace_record.id.raw(), tablet, private_path) == null);

    try std.testing.expectError(error.TransportDenied, port.acceptTransportFrame(authority, &storage, .{
        .workspace_id = workspace_record.id.raw(),
        .object_id = private.object_id.raw(),
        .version_id = private.version_id.raw(),
        .source_device = laptop,
        .target_device = tablet,
        .transport = .device_to_device,
        .semantic = .mergeable_crdt,
        .encrypted = true,
        .path = private_path,
    }));

    const review = try port.reviewConflict(authority, workspace_record.id.raw(), tablet, notes_path);
    try std.testing.expect(!review.resolved);
    try std.testing.expectEqualStrings(notes_path, review.pathSlice());
    try std.testing.expectEqual(notes_v2.version_id.raw(), review.local_version_id);
    try std.testing.expectEqual(tablet_offline.version_id.raw(), review.remote_version_id);

    const resolved = try port.resolveConflict(authority, workspace_record.id.raw(), tablet, notes_path, .accept_remote);
    try std.testing.expect(resolved.resolved);
    try std.testing.expectEqual(sync_service.ConflictReviewDecision.accept_remote, resolved.decision);
    try std.testing.expect(service.findConflict(workspace_record.id.raw(), tablet, notes_path) == null);
    try std.testing.expectEqual(tablet_offline.version_id.raw(), service.replicaVersion(workspace_record.id.raw(), tablet, notes_path).?);

    var restarted_resident = ResidentState{};
    var restarted = try Service.initWithStorage(8_840, 8_841, sync_owner, &storage, &restarted_resident);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expect(restarted.findConflict(workspace_record.id.raw(), tablet, notes_path) == null);
    try std.testing.expectEqual(tablet_offline.version_id.raw(), restarted.replicaVersion(workspace_record.id.raw(), tablet, notes_path).?);
}

fn verifiedSyncDeviceGraphBoot(generation: u64, provenance: measured_boot.RootProvenance) !measured_boot.BootRecord {
    var recorder = measured_boot.Recorder.init();
    var artifact_manifest = measured_boot.ArtifactManifest.init(generation);
    recorder.begin(generation);
    try addSyncDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos", "kernel=sync-device-graph");
    try addSyncDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .base_image, "stable-sync-device-graph", "image=sync-device-graph");
    try addSyncDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try addSyncDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try addSyncDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "sync", "healthy");
    try addSyncDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try addSyncDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .policy, "sync-device-graph-policy", "strict");
    try addSyncDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .driver_set, "sync-device-graph-drivers", "drivers");
    var boot = recorder.finalize();
    try measured_boot.verifyBootRecordAgainstManifest(&boot, &artifact_manifest, provenance);
    return boot;
}

pub fn deterministicTwoDeviceOverlayReplication() !void {
    var runtime = task_runtime.Runtime.init();
    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 920 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 921 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 922 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 923 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 924 };
    const policy_authority = principal.PrincipalId{ .kind = .policy_authority, .serial = 925 };
    const path = "documents/notes.md";
    const relay_domain = "relay.e2e.zigos";
    const overlay_identity = "overlay.e2e.notes";
    const private_service = "notes.remote";
    const object_id = object_store.ids.object(9_100);
    const user_signer = signing.SignerIdentity{
        .label = "sync-e2e-user",
        .seed = signing.seedFromByte(0x71),
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "sync-e2e-laptop",
        .seed = signing.seedFromByte(0x72),
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "sync-e2e-tablet",
        .seed = signing.seedFromByte(0x73),
    };
    const storage_signer = signing.SignerIdentity{
        .label = "sync-e2e-storage",
        .seed = signing.seedFromByte(0x74),
    };

    const source_task = try createSyncServiceTask(&runtime, sync_owner, "sync-source", "zigos.system.sync.source", 9_210);
    const target_task = try createSyncServiceTask(&runtime, sync_owner, "sync-target", "zigos.system.sync.target", 9_211);
    try std.testing.expect(source_task.runsAsUserspaceProcess());
    try std.testing.expect(target_task.runsAsUserspaceProcess());
    try std.testing.expect(source_task.hasLoadedExecutable());
    try std.testing.expect(target_task.hasLoadedExecutable());
    try std.testing.expectEqual(task_runtime.ComponentClass.service_component, source_task.component_class);
    try std.testing.expectEqual(task_runtime.ComponentClass.service_component, target_task.component_class);

    var source_checkpoint_store = storage_service.CheckpointStore{};
    var target_checkpoint_store = storage_service.CheckpointStore{};
    source_checkpoint_store.resetPersistent();
    target_checkpoint_store.resetPersistent();

    var source_storage = storage_service.Service.initWithStore(9_220, 9_220, storage_owner, &source_checkpoint_store);
    const source_base = try source_storage.putVersion(.{
        .preferred_object_id = object_id,
        .object_type = .document,
        .payload = "base notes",
        .metadata = try object_store.signMetadata(storage_signer, "notes-base", "text/plain", .document, "base notes", 10),
    });
    const source_edit = try source_storage.putVersion(.{
        .preferred_object_id = object_id,
        .object_type = .document,
        .payload = "laptop edit",
        .metadata = try object_store.signMetadata(storage_signer, "notes-laptop", "text/plain", .document, "laptop edit", 11),
        .parent_version_id = source_base.version_id,
    });
    const source_workspace = try source_storage.createWorkspace(.{
        .owner = user,
        .label = "notes",
    });
    try source_storage.beginTransaction(source_workspace.id);
    try source_storage.stagePut(source_workspace.id, path, source_edit.object_id, source_edit.version_id, .document);
    _ = try source_storage.commit(source_workspace.id, 12);

    var target_storage = storage_service.Service.initWithStore(9_221, 9_221, storage_owner, &target_checkpoint_store);
    const target_base = try target_storage.putVersion(.{
        .preferred_object_id = object_id,
        .object_type = .document,
        .payload = "base notes",
        .metadata = try object_store.signMetadata(storage_signer, "notes-base", "text/plain", .document, "base notes", 20),
    });
    const target_draft = try target_storage.putVersion(.{
        .preferred_object_id = object_id,
        .object_type = .document,
        .payload = "tablet draft",
        .metadata = try object_store.signMetadata(storage_signer, "notes-tablet-draft", "text/plain", .document, "tablet draft", 21),
        .parent_version_id = target_base.version_id,
    });
    const target_conflict = try target_storage.putVersion(.{
        .preferred_object_id = object_id,
        .object_type = .document,
        .payload = "tablet conflict",
        .metadata = try object_store.signMetadata(storage_signer, "notes-tablet-conflict", "text/plain", .document, "tablet conflict", 22),
        .parent_version_id = target_draft.version_id,
    });
    const target_workspace = try target_storage.createWorkspace(.{
        .owner = user,
        .label = "notes",
    });
    try std.testing.expectEqual(source_workspace.id.raw(), target_workspace.id.raw());
    try target_storage.beginTransaction(target_workspace.id);
    try target_storage.stagePut(target_workspace.id, path, target_conflict.object_id, target_conflict.version_id, .document);
    _ = try target_storage.commit(target_workspace.id, 23);

    const workspace_id = source_workspace.id.raw();
    var source_resident = ResidentState{};
    var target_resident = ResidentState{};
    var source_sync = try Service.initWithStorage(9_230, source_task.id, sync_owner, &source_storage, &source_resident);
    var target_sync = try Service.initWithStorage(9_231, target_task.id, sync_owner, &target_storage, &target_resident);
    var source_capabilities = capability.CapabilityTable.init();
    const source_authority_capability = try mintSyncServiceAuthority(&source_capabilities, &source_sync, sync_owner);
    var source_port = sync_service.SyncPort.init(&source_sync, &source_capabilities);
    const source_authority = syncAuthority(&source_sync, sync_owner, source_authority_capability, 30);
    var target_capabilities = capability.CapabilityTable.init();
    const target_authority_capability = try mintSyncServiceAuthority(&target_capabilities, &target_sync, sync_owner);
    var target_port = sync_service.SyncPort.init(&target_sync, &target_capabilities);
    const target_authority = syncAuthority(&target_sync, sync_owner, target_authority_capability, 40);
    const source_policies = try configureEndToEndSync(
        &source_port,
        source_authority,
        sync_owner,
        user,
        laptop,
        tablet,
        user_signer,
        laptop_signer,
        tablet_signer,
        workspace_id,
        overlay_identity,
        relay_domain,
        private_service,
        30,
    );
    const target_policies = try configureEndToEndSync(
        &target_port,
        target_authority,
        sync_owner,
        user,
        laptop,
        tablet,
        user_signer,
        laptop_signer,
        tablet_signer,
        workspace_id,
        overlay_identity,
        relay_domain,
        private_service,
        40,
    );

    const overlay_decision = try target_port.evaluateNetworkPolicy(target_authority, target_policies.overlay_policy_id, .{
        .service_identity = overlay_identity,
    });
    try std.testing.expect(overlay_decision.allowed);

    const source_private_session = try source_port.openOverlaySession(
        source_authority,
        workspace_id,
        laptop,
        tablet,
        .private_service,
        .relay_assisted,
        private_service,
        50,
    );
    try std.testing.expect(source_private_session.isActive());
    try std.testing.expect(source_private_session.encrypted);
    try std.testing.expect(source_private_session.relay_encrypted);
    try std.testing.expect(source_private_session.remote_access);
    try std.testing.expectEqualStrings(private_service, source_private_session.privateServiceSlice());

    const target_private_session = try target_port.openOverlaySession(
        target_authority,
        workspace_id,
        tablet,
        laptop,
        .private_service,
        .relay_assisted,
        private_service,
        51,
    );
    try std.testing.expect(target_private_session.isActive());
    try std.testing.expect(target_private_session.relay_encrypted);
    try std.testing.expectEqualStrings(private_service, target_private_session.privateServiceSlice());

    var capabilities = capability.CapabilityTable.init();
    const relay_capability = try capabilities.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = policy_authority,
        .target = .{ .kind = .network_policy, .id = source_policies.relay_policy_id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = source_task.id, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    var source_broker = source_sync.egressBroker(&capabilities);
    var transport = sync_transport.Harness.init();
    const relay_session = try transport.openRelay(&source_broker, .{
        .task_id = source_task.id,
        .principal_id = sync_owner,
        .capability_id = relay_capability.id,
        .policy_id = source_policies.relay_policy_id,
        .evidence = .{ .destination = .{ .domain = relay_domain } },
        .now_ticks = 52,
    }, laptop, tablet, relay_domain);
    try std.testing.expectEqual(sync_service.TransportMode.relay_assisted, relay_session.transport);
    try std.testing.expect(relay_session.egress_decision.allowed);
    try std.testing.expectEqualStrings(relay_domain, relay_session.relayDomainSlice());

    try std.testing.expectError(error.EgressDenied, transport.openRelay(&source_broker, .{
        .task_id = source_task.id,
        .principal_id = sync_owner,
        .capability_id = relay_capability.id,
        .policy_id = source_policies.relay_policy_id,
        .evidence = .{ .destination = .{ .domain = "unexpected.e2e.zigos" } },
        .now_ticks = 52,
    }, laptop, tablet, "unexpected.e2e.zigos"));
    try std.testing.expectEqual(@as(usize, 1), transport.denied_sessions);

    try source_port.setReplicaVersion(source_authority, workspace_id, tablet, path, source_edit.object_id, target_conflict.version_id);
    const summary = try source_port.replicateWorkspace(source_authority, &source_storage, workspace_id, laptop, tablet, .relay_assisted);
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_relay);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expect(summary.remote_access_ready);
    try std.testing.expect(summary.private_service_published);
    try std.testing.expectEqual(@as(usize, 1), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expectEqual(@as(usize, 1), summary.transport_frame_count);
    try std.testing.expectEqual(@as(usize, 1), summary.encrypted_transport_count);
    try std.testing.expect(source_sync.findConflict(workspace_id, tablet, path) != null);

    const frame = source_sync.latestTransportFrameForPath(workspace_id, tablet, path) orelse return error.MissingTransportFrame;
    try std.testing.expect(frame.encrypted);
    try std.testing.expectEqual(sync_service.TransportMode.relay_assisted, frame.transport);
    try std.testing.expectEqual(SyncSemantic.mergeable_crdt, frame.semantic);
    const source_frame_version = source_storage.version(frame.version_id) orelse return error.MissingTransportFrameVersion;
    const source_payload = try source_storage.versionPayload(source_frame_version);
    var payload_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const plaintext = try std.fmt.bufPrint(&payload_buffer, "{s}|{s}", .{ frame.pathSlice(), source_payload });
    const signed_frame = try transport.encryptSignedFrame(&relay_session, plaintext, laptop_signer);
    try std.testing.expect(sync_transport.verifySignedFrame(&signed_frame));
    try std.testing.expect(signed_frame.packet.encrypted);
    try std.testing.expect(signed_frame.packet.egress_allowed);
    try std.testing.expect(!std.mem.eql(u8, signed_frame.packet.ciphertextSlice(), plaintext));

    var relay_queue = sync_transport.Relay.init();
    try relay_queue.submit(signed_frame.packet);
    var delivered_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay_queue.deliverNext(&relay_session, delivered_buffer[0..])) orelse return error.MissingRelayFrame;
    try std.testing.expectEqualStrings(plaintext, delivered);
    try std.testing.expectEqual(@as(usize, 1), relay_queue.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), relay_queue.delivered_packets);

    var authenticated_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const authenticated = try sync_transport.decryptSignedFrame(&relay_session, &signed_frame, authenticated_buffer[0..]);
    try std.testing.expectEqualStrings(delivered, authenticated);
    var tampered = signed_frame;
    tampered.packet.ciphertext[0] ^= 0x01;
    try std.testing.expect(!sync_transport.verifySignedFrame(&tampered));
    try std.testing.expectError(error.PacketAuthenticationFailed, sync_transport.decryptSignedFrame(&relay_session, &tampered, authenticated_buffer[0..]));

    const delimiter = std.mem.indexOfScalar(u8, authenticated, '|') orelse return error.MissingPayloadDelimiter;
    const replicated_path = authenticated[0..delimiter];
    const replicated_payload = authenticated[delimiter + 1 ..];
    try std.testing.expectEqualStrings(path, replicated_path);
    try std.testing.expectEqualStrings("laptop edit", replicated_payload);

    const replicated_version = try target_storage.putVersion(.{
        .preferred_object_id = object_id,
        .object_type = .document,
        .payload = replicated_payload,
        .metadata = try object_store.signMetadata(storage_signer, "notes-replicated", "text/plain", .document, replicated_payload, 53),
        .parent_version_id = target_conflict.version_id,
    });
    try target_storage.beginTransaction(target_workspace.id);
    try target_storage.stagePut(target_workspace.id, replicated_path, replicated_version.object_id, replicated_version.version_id, .document);
    const replicated_generation = try target_storage.commit(target_workspace.id, 54);
    try std.testing.expect(replicated_generation > 1);
    try target_port.setReplicaVersion(target_authority, workspace_id, laptop, replicated_path, replicated_version.object_id, replicated_version.version_id);

    const resolved = try target_storage.resolve(target_workspace.id, path);
    try std.testing.expectEqual(replicated_version.version_id, resolved.version_id);
    const target_version = target_storage.version(resolved.version_id) orelse return error.MissingTargetVersion;
    const target_payload = try target_storage.versionPayload(target_version);
    try std.testing.expectEqualStrings("laptop edit", target_payload);
    try std.testing.expectEqual(replicated_version.version_id.raw(), target_sync.replicaVersion(workspace_id, laptop, path).?);
    try std.testing.expectEqual(source_edit.version_id.raw(), source_sync.replicaVersion(workspace_id, tablet, path).?);

    var restarted_source_storage = storage_service.Service.initWithStore(9_222, 9_222, storage_owner, &source_checkpoint_store);
    var restarted_target_storage = storage_service.Service.initWithStore(9_223, 9_223, storage_owner, &target_checkpoint_store);
    var restarted_source_resident = ResidentState{};
    var restarted_target_resident = ResidentState{};
    var restarted_source_sync = try Service.initWithStorage(9_232, source_task.id, sync_owner, &restarted_source_storage, &restarted_source_resident);
    var restarted_target_sync = try Service.initWithStorage(9_233, target_task.id, sync_owner, &restarted_target_storage, &restarted_target_resident);
    try std.testing.expect(restarted_source_sync.loaded_existing_state);
    try std.testing.expect(restarted_target_sync.loaded_existing_state);
    try std.testing.expectEqual(source_edit.version_id.raw(), restarted_source_sync.replicaVersion(workspace_id, tablet, path).?);
    try std.testing.expectEqual(replicated_version.version_id.raw(), restarted_target_sync.replicaVersion(workspace_id, laptop, path).?);
    try std.testing.expect(restarted_source_sync.findConflict(workspace_id, tablet, path) != null);
    try std.testing.expect(restarted_source_sync.findOverlay(workspace_id) != null);
    try std.testing.expect(restarted_target_sync.findOverlay(workspace_id) != null);

    const restarted_resolved = try restarted_target_storage.resolve(target_workspace.id, path);
    try std.testing.expectEqual(replicated_version.version_id, restarted_resolved.version_id);
    const restarted_target_version = restarted_target_storage.version(restarted_resolved.version_id) orelse return error.MissingTargetVersion;
    const restarted_target_payload = try restarted_target_storage.versionPayload(restarted_target_version);
    try std.testing.expectEqualStrings("laptop edit", restarted_target_payload);

    var restarted_source_capabilities = capability.CapabilityTable.init();
    const restarted_source_authority_capability = try mintSyncServiceAuthority(&restarted_source_capabilities, &restarted_source_sync, sync_owner);
    var restarted_source_port = sync_service.SyncPort.init(&restarted_source_sync, &restarted_source_capabilities);
    const restarted_source_authority = syncAuthority(&restarted_source_sync, sync_owner, restarted_source_authority_capability, 60);
    const restarted_clean = try restarted_source_port.replicateWorkspace(restarted_source_authority, &restarted_source_storage, workspace_id, laptop, tablet, .relay_assisted);
    try std.testing.expectEqual(@as(usize, 0), restarted_clean.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 0), restarted_clean.transport_frame_count);

    source_checkpoint_store.resetPersistent();
    target_checkpoint_store.resetPersistent();
}

fn createSyncServiceTask(
    runtime: *task_runtime.Runtime,
    owner: principal.PrincipalId,
    label: []const u8,
    bundle_id: []const u8,
    image_id: u64,
) !*task_runtime.TaskRecord {
    const image = try generated_image_fixtures.syncServiceImage();
    return runtime.createTask(.{
        .owner = owner,
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = units.kibibytes(128),
            .endpoint_slots = 8,
            .shared_memory_bytes = units.kibibytes(32),
            .background_allowed = true,
        },
        .local_only = true,
        .initial_component = .{
            .label = label,
            .entry = bundle_id,
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = image_id,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = bundle_id,
        },
        .userspace_image = &image,
    });
}

fn configureEndToEndSync(
    port: *sync_service.SyncPort,
    authority: sync_service.AuthorityContext,
    sync_owner: principal.PrincipalId,
    user: principal.PrincipalId,
    laptop: principal.PrincipalId,
    tablet: principal.PrincipalId,
    user_signer: signing.SignerIdentity,
    laptop_signer: signing.SignerIdentity,
    tablet_signer: signing.SignerIdentity,
    workspace_id: u64,
    overlay_identity: []const u8,
    relay_domain: []const u8,
    private_service: []const u8,
    tick_base: u64,
) !EndToEndPolicyIds {
    _ = try port.ensureUserRoot(authority, user, "owner", user_signer);
    _ = try port.enrollTrustedDevice(authority, user, laptop, "laptop", user_signer, laptop_signer, tick_base);
    _ = try port.enrollTrustedDevice(authority, user, tablet, "tablet", user_signer, tablet_signer, tick_base + 1);

    const local_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "local",
        .mode = .local_network,
    });
    const overlay_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = overlay_identity,
    });
    const relay_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = relay_domain,
    });
    _ = try port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/", "secrets/", "databases/" },
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = relay_domain,
    });
    _ = try port.configureOverlay(authority, workspace_id, laptop, overlay_identity, true);
    _ = try port.publishPrivateService(authority, workspace_id, private_service);
    return .{
        .local_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_policy_id = relay_policy.id,
    };
}

test "sync private overlay replicates end to end across two service tasks" {
    try deterministicTwoDeviceOverlayReplication();
}

test "sync service replicates payloads to peer storage through booted relay fallback" {
    var runtime = task_runtime.Runtime.init();
    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 9_500 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 9_501 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 9_502 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 9_503 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 9_504 };
    const policy_authority = principal.PrincipalId{ .kind = .policy_authority, .serial = 9_505 };
    const document_path = "documents/peer-notes.md";
    const media_path = "assets/peer-cover.bin";
    const secret_path = "secrets/peer-token";
    const database_path = "databases/app.notes.db/events";
    const relay_domain = "relay.peer.zigos";
    const overlay_identity = "overlay.peer.notes";
    const private_service = "peer.notes.remote";
    const document_object_id = object_store.ids.object(9_560);
    const media_object_id = object_store.ids.object(9_561);
    const secret_object_id = object_store.ids.object(9_562);
    const database_object_id = object_store.ids.object(9_563);
    const user_signer = signing.SignerIdentity{
        .label = "peer-sync-user",
        .seed = signing.seedFromByte(0xA1),
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "peer-sync-laptop",
        .seed = signing.seedFromByte(0xA2),
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "peer-sync-tablet",
        .seed = signing.seedFromByte(0xA3),
    };
    const storage_signer = signing.SignerIdentity{
        .label = "peer-sync-storage",
        .seed = signing.seedFromByte(0xA4),
    };
    const contract_signer = signing.SignerIdentity{
        .label = "peer-sync-db-contract",
        .seed = signing.seedFromByte(0xA5),
    };
    const media_payload = [_]u8{0x4d} ** PEER_SYNC_MEDIA_PAYLOAD_BYTES;
    const secret_payload = "enc:peer-secret";
    const database_payload = "txn:insert-note";

    const source_task = try createSyncServiceTask(&runtime, sync_owner, "peer-sync-source", "zigos.system.sync.peer.source", 9_570);
    const target_task = try createSyncServiceTask(&runtime, sync_owner, "peer-sync-target", "zigos.system.sync.peer.target", 9_571);
    try std.testing.expect(source_task.runsAsUserspaceProcess());
    try std.testing.expect(target_task.runsAsUserspaceProcess());

    var source_checkpoint_store = storage_service.CheckpointStore{};
    var target_checkpoint_store = storage_service.CheckpointStore{};
    source_checkpoint_store.resetPersistent();
    target_checkpoint_store.resetPersistent();

    var source_storage = storage_service.Service.initWithStore(9_580, 9_581, storage_owner, &source_checkpoint_store);
    const source_base = try source_storage.putVersion(.{
        .preferred_object_id = document_object_id,
        .object_type = .document,
        .payload = "base",
        .metadata = try object_store.signMetadata(storage_signer, "peer-base", "text/plain", .document, "base", 1),
    });
    const source_edit = try source_storage.putVersion(.{
        .preferred_object_id = document_object_id,
        .object_type = .document,
        .payload = "source edit",
        .metadata = try object_store.signMetadata(storage_signer, "peer-source", "text/plain", .document, "source edit", 2),
        .parent_version_id = source_base.version_id,
    });
    const source_media = try source_storage.putVersion(.{
        .preferred_object_id = media_object_id,
        .object_type = .media_asset,
        .payload = media_payload[0..],
        .metadata = try object_store.signMetadata(storage_signer, "peer-cover", "application/octet-stream", .media_asset, media_payload[0..], 3),
    });
    const source_secret = try source_storage.putVersion(.{
        .preferred_object_id = secret_object_id,
        .object_type = .secret,
        .payload = secret_payload,
        .metadata = try object_store.signMetadata(storage_signer, "peer-secret", "application/zigos-secret", .secret, secret_payload, 4),
    });
    const source_database = try source_storage.putVersion(.{
        .preferred_object_id = database_object_id,
        .object_type = .event_stream,
        .payload = database_payload,
        .metadata = try object_store.signMetadata(storage_signer, "peer-db-events", "application/zigos-event-stream", .event_stream, database_payload, 5),
    });
    const source_workspace = try source_storage.createWorkspace(.{
        .owner = user,
        .label = "peer-notes",
    });
    try source_storage.beginTransaction(source_workspace.id);
    try source_storage.stagePut(source_workspace.id, document_path, source_edit.object_id, source_edit.version_id, .document);
    try source_storage.stagePut(source_workspace.id, media_path, source_media.object_id, source_media.version_id, .media_asset);
    try source_storage.stagePut(source_workspace.id, secret_path, source_secret.object_id, source_secret.version_id, .secret);
    try source_storage.stagePut(source_workspace.id, database_path, source_database.object_id, source_database.version_id, .event_stream);
    _ = try source_storage.commit(source_workspace.id, 6);

    var target_storage = storage_service.Service.initWithStore(9_582, 9_583, storage_owner, &target_checkpoint_store);
    const target_base = try target_storage.putVersion(.{
        .preferred_object_id = document_object_id,
        .object_type = .document,
        .payload = "base",
        .metadata = try object_store.signMetadata(storage_signer, "peer-base", "text/plain", .document, "base", 7),
    });
    const target_draft = try target_storage.putVersion(.{
        .preferred_object_id = document_object_id,
        .object_type = .document,
        .payload = "tablet draft",
        .metadata = try object_store.signMetadata(storage_signer, "peer-tablet-draft", "text/plain", .document, "tablet draft", 8),
        .parent_version_id = target_base.version_id,
    });
    const target_conflict = try target_storage.putVersion(.{
        .preferred_object_id = document_object_id,
        .object_type = .document,
        .payload = "tablet offline conflict",
        .metadata = try object_store.signMetadata(storage_signer, "peer-tablet-conflict", "text/plain", .document, "tablet offline conflict", 9),
        .parent_version_id = target_draft.version_id,
    });
    const target_workspace = try target_storage.createWorkspace(.{
        .owner = user,
        .label = "peer-notes",
    });
    try std.testing.expectEqual(source_workspace.id.raw(), target_workspace.id.raw());
    try target_storage.beginTransaction(target_workspace.id);
    try target_storage.stagePut(target_workspace.id, document_path, target_conflict.object_id, target_conflict.version_id, .document);
    _ = try target_storage.commit(target_workspace.id, 10);

    const workspace_id = source_workspace.id.raw();
    var source_resident = ResidentState{};
    var target_resident = ResidentState{};
    var source_sync = try Service.initWithStorage(9_590, source_task.id, sync_owner, &source_storage, &source_resident);
    var target_sync = try Service.initWithStorage(9_591, target_task.id, sync_owner, &target_storage, &target_resident);
    var source_capabilities = capability.CapabilityTable.init();
    const source_authority_capability = try mintSyncServiceAuthority(&source_capabilities, &source_sync, sync_owner);
    var source_port = sync_service.SyncPort.init(&source_sync, &source_capabilities);
    const source_authority = syncAuthority(&source_sync, sync_owner, source_authority_capability, 30);
    var target_capabilities = capability.CapabilityTable.init();
    const target_authority_capability = try mintSyncServiceAuthority(&target_capabilities, &target_sync, sync_owner);
    var target_port = sync_service.SyncPort.init(&target_sync, &target_capabilities);
    const target_authority = syncAuthority(&target_sync, sync_owner, target_authority_capability, 40);

    const source_policies = try configureEndToEndSync(
        &source_port,
        source_authority,
        sync_owner,
        user,
        laptop,
        tablet,
        user_signer,
        laptop_signer,
        tablet_signer,
        workspace_id,
        overlay_identity,
        relay_domain,
        private_service,
        30,
    );
    _ = try configureEndToEndSync(
        &target_port,
        target_authority,
        sync_owner,
        user,
        laptop,
        tablet,
        user_signer,
        laptop_signer,
        tablet_signer,
        workspace_id,
        overlay_identity,
        relay_domain,
        private_service,
        40,
    );

    var network_capabilities = capability.CapabilityTable.init();
    const relay_capability = try network_capabilities.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = policy_authority,
        .target = .{ .kind = .network_policy, .id = source_policies.relay_policy_id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = source_task.id, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    var relay_service = try sync_transport.BootedOverlayRelayService.init(9_600, 9_601, relay_domain);

    _ = try source_port.registerDatabaseContract(source_authority, workspace_id, "app.notes.db", "notes-db", contract_signer);
    try std.testing.expectEqual(@as(usize, 0), target_resident.databaseContractCount());
    try source_port.setReplicaVersion(source_authority, workspace_id, tablet, document_path, source_edit.object_id, target_conflict.version_id);
    var denied_request = sync_service.PeerReplicationRequest{
        .source_storage = &source_storage,
        .target_storage = &target_storage,
        .workspace_id = workspace_id,
        .from_device = laptop,
        .to_device = tablet,
        .transport = .relay_assisted,
        .network_capabilities = &network_capabilities,
        .relay_service = &relay_service,
        .relay_capability_id = relay_capability.id + 1,
        .signer = laptop_signer,
        .tick = 50,
    };
    try std.testing.expectError(error.EgressDenied, source_port.replicateWorkspaceToPeer(
        source_authority,
        &target_port,
        target_authority,
        denied_request,
    ));
    try std.testing.expectEqual(@as(usize, 0), source_sync.transportFrameCountFor(workspace_id, tablet));
    const still_offline = try target_storage.resolve(target_workspace.id, document_path);
    try std.testing.expectEqual(target_conflict.version_id, still_offline.version_id);

    denied_request.relay_capability_id = relay_capability.id;
    const result = try source_port.replicateWorkspaceToPeer(
        source_authority,
        &target_port,
        target_authority,
        denied_request,
    );
    try std.testing.expect(result.summary.offline_first);
    try std.testing.expect(result.summary.personal_e2ee);
    try std.testing.expect(result.summary.used_relay);
    try std.testing.expect(result.summary.overlay_ready);
    try std.testing.expectEqual(@as(usize, 4), result.summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), result.summary.merged_count);
    try std.testing.expect(result.summary.snapshot_count > 1);
    try std.testing.expectEqual(@as(usize, 1), result.summary.secret_transfer_count);
    try std.testing.expectEqual(@as(usize, 1), result.summary.transactional_count);
    try std.testing.expectEqual(@as(usize, 1), result.summary.conflict_count);
    try std.testing.expectEqual(@as(usize, 4), result.accepted_frame_count);
    try std.testing.expectEqual(@as(usize, 4), result.persisted_object_count);
    const expected_relay_deliveries = 3 + (media_payload.len + sync_transport.MAX_NATIVE_PAYLOAD_BYTES - 1) / sync_transport.MAX_NATIVE_PAYLOAD_BYTES;
    try std.testing.expectEqual(@as(usize, expected_relay_deliveries), result.relay_delivery_count);
    try std.testing.expect(result.used_booted_relay_service);
    const expected_payload_bytes = "source edit".len + media_payload.len + secret_payload.len + database_payload.len;
    try std.testing.expectEqual(@as(usize, expected_payload_bytes), result.payload_bytes);
    try std.testing.expectEqual(@as(usize, expected_relay_deliveries), relay_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, expected_relay_deliveries), relay_service.delivered_packets);
    try std.testing.expectEqual(@as(usize, 1), target_resident.databaseContractCount());
    try std.testing.expect(source_sync.findConflict(workspace_id, tablet, document_path) != null);
    var pending_after_ack: [sync_service.MAX_TRANSPORT_FRAMES]sync_service.TransportFrame = undefined;
    try std.testing.expectEqual(@as(usize, 0), source_sync.copyTransportFramesForSince(
        workspace_id,
        tablet,
        0,
        pending_after_ack[0..],
    ));
    try std.testing.expectEqual(@as(usize, 0), source_resident.outboundTransportFrameCount());

    const replicated_entry = try target_storage.resolve(target_workspace.id, document_path);
    const replicated_version = target_storage.version(replicated_entry.version_id) orelse return error.VersionNotFound;
    const replicated_payload = try target_storage.versionPayload(replicated_version);
    try std.testing.expectEqualStrings("source edit", replicated_payload);
    try std.testing.expectEqual(target_conflict.version_id, replicated_version.previous_version_id);
    try std.testing.expectEqual(replicated_version.id.raw(), target_sync.replicaVersion(workspace_id, tablet, document_path).?);
    try std.testing.expect(source_sync.latestTransportFrameForPath(workspace_id, tablet, document_path) == null);

    const replicated_media_entry = try target_storage.resolve(target_workspace.id, media_path);
    const replicated_media_version = target_storage.version(replicated_media_entry.version_id) orelse return error.VersionNotFound;
    const replicated_media_payload = try target_storage.versionPayload(replicated_media_version);
    try std.testing.expectEqualSlices(u8, media_payload[0..], replicated_media_payload);
    try std.testing.expectEqual(replicated_media_version.id.raw(), target_sync.replicaVersion(workspace_id, tablet, media_path).?);
    try std.testing.expect(source_sync.latestTransportFrameForPath(workspace_id, tablet, media_path) == null);

    const replicated_secret_entry = try target_storage.resolve(target_workspace.id, secret_path);
    const replicated_secret_version = target_storage.version(replicated_secret_entry.version_id) orelse return error.VersionNotFound;
    const replicated_secret_payload = try target_storage.versionPayload(replicated_secret_version);
    try std.testing.expectEqualStrings(secret_payload, replicated_secret_payload);
    try std.testing.expectEqual(replicated_secret_version.id.raw(), target_sync.replicaVersion(workspace_id, tablet, secret_path).?);
    try std.testing.expect(source_sync.latestTransportFrameForPath(workspace_id, tablet, secret_path) == null);

    const replicated_database_entry = try target_storage.resolve(target_workspace.id, database_path);
    const replicated_database_version = target_storage.version(replicated_database_entry.version_id) orelse return error.VersionNotFound;
    const replicated_database_payload = try target_storage.versionPayload(replicated_database_version);
    try std.testing.expectEqualStrings(database_payload, replicated_database_payload);
    try std.testing.expectEqual(replicated_database_version.id.raw(), target_sync.replicaVersion(workspace_id, tablet, database_path).?);
    try std.testing.expect(source_sync.latestTransportFrameForPath(workspace_id, tablet, database_path) == null);

    var restarted_target_storage = storage_service.Service.initWithStore(9_584, 9_585, storage_owner, &target_checkpoint_store);
    var restarted_target_resident = ResidentState{};
    var restarted_target_sync = try Service.initWithStorage(9_592, target_task.id, sync_owner, &restarted_target_storage, &restarted_target_resident);
    try std.testing.expect(restarted_target_sync.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 1), restarted_target_resident.databaseContractCount());
    const restarted_entry = try restarted_target_storage.resolve(target_workspace.id, document_path);
    try std.testing.expectEqual(replicated_version.id, restarted_entry.version_id);
    const restarted_version = restarted_target_storage.version(restarted_entry.version_id) orelse return error.VersionNotFound;
    const restarted_payload = try restarted_target_storage.versionPayload(restarted_version);
    try std.testing.expectEqualStrings("source edit", restarted_payload);
    try std.testing.expectEqual(replicated_version.id.raw(), restarted_target_sync.replicaVersion(workspace_id, tablet, document_path).?);
    try std.testing.expectEqual(replicated_media_version.id.raw(), restarted_target_sync.replicaVersion(workspace_id, tablet, media_path).?);
    try std.testing.expectEqual(replicated_secret_version.id.raw(), restarted_target_sync.replicaVersion(workspace_id, tablet, secret_path).?);
    try std.testing.expectEqual(replicated_database_version.id.raw(), restarted_target_sync.replicaVersion(workspace_id, tablet, database_path).?);

    source_checkpoint_store.resetPersistent();
    target_checkpoint_store.resetPersistent();
}

test "sync service covers device graph policy replication semantics and restart recovery" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 11 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 12 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 13 };
    const storage_signer = signing.SignerIdentity{
        .label = "storage-signer",
        .seed = signing.seedFromByte(0x51),
    };
    const user_signer = signing.SignerIdentity{
        .label = "user-root",
        .seed = signing.seedFromByte(0x52),
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "laptop",
        .seed = signing.seedFromByte(0x53),
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "tablet",
        .seed = signing.seedFromByte(0x54),
    };
    const tablet_rotated_signer = signing.SignerIdentity{
        .label = "tablet-v2",
        .seed = signing.seedFromByte(0x55),
    };
    const phone_signer = signing.SignerIdentity{
        .label = "phone",
        .seed = signing.seedFromByte(0x56),
    };
    const contract_signer = signing.SignerIdentity{
        .label = "db-sync",
        .seed = signing.seedFromByte(0x57),
    };

    var storage = storage_service.Service.initWithStore(40, 4, storage_owner, &storage_checkpoint_store);
    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(800),
        .object_type = .document,
        .payload = "# Notes\n- v1\n",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/markdown", .document, "# Notes\n- v1\n", 10),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(800),
        .object_type = .document,
        .payload = "# Notes\n- v2\n",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/markdown", .document, "# Notes\n- v2\n", 11),
        .parent_version_id = notes_v1.version_id,
    });
    const inbox = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(801),
        .object_type = .collection,
        .payload = "inbox",
        .metadata = try object_store.signMetadata(storage_signer, "inbox", "application/zigos-collection", .collection, "inbox", 12),
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(802),
        .object_type = .media_asset,
        .payload = "jpeg:cover",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "jpeg:cover", 13),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(803),
        .object_type = .secret,
        .payload = "enc:secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:secret", 14),
    });

    const notes = try storage.createWorkspace(.{
        .owner = user,
        .label = "notes",
    });
    const notes_id = notes.id.raw();
    try storage.beginTransaction(notes.id);
    try storage.stagePut(notes.id, "documents/notes.md", notes_v1.object_id, notes_v1.version_id, .document);
    try storage.stagePut(notes.id, "collections/inbox", inbox.object_id, inbox.version_id, .collection);
    try storage.stagePut(notes.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    _ = try storage.commit(notes.id, 15);

    var resident = ResidentState{};
    var service = try Service.initWithStorage(80, 8, sync_owner, &storage, &resident);
    var service_capabilities = capability.CapabilityTable.init();
    const service_authority_capability = try mintSyncServiceAuthority(&service_capabilities, &service, sync_owner);
    var service_port = sync_service.SyncPort.init(&service, &service_capabilities);
    const service_authority = syncAuthority(&service, sync_owner, service_authority_capability, 25);
    _ = try service_port.ensureUserRoot(service_authority, user, "cameron", user_signer);
    _ = try service_port.enrollTrustedDevice(service_authority, user, laptop, "laptop", user_signer, laptop_signer, 20);
    _ = try service_port.enrollTrustedDevice(service_authority, user, tablet, "tablet", user_signer, tablet_signer, 21);
    _ = try service_port.enrollTrustedDevice(service_authority, user, phone, "phone", user_signer, phone_signer, 22);
    _ = try service_port.rotateDeviceKey(service_authority, user, tablet, user_signer, tablet_rotated_signer, 23);
    try service_port.revokeTrustedDevice(service_authority, user, phone, user_signer, 24);

    const none_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = notes_id,
        .label = "none",
        .mode = .none,
    });
    const local_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = notes_id,
        .label = "local",
        .mode = .local_network,
    });
    const discovery_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = notes_id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const overlay_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = notes_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    });
    const relay_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = notes_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    const inbound_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = notes_id,
        .label = "collab-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    });
    const internet_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = notes_id,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    });

    try std.testing.expect(!(try service_port.evaluateNetworkPolicy(service_authority, none_policy.id, .public_internet)).allowed);
    try std.testing.expect((try service_port.evaluateNetworkPolicy(service_authority, local_policy.id, .local_network)).allowed);
    try std.testing.expect((try service_port.evaluateNetworkPolicy(service_authority, discovery_policy.id, .{ .discovery_class = "printer" })).allowed);
    try std.testing.expect((try service_port.evaluateNetworkPolicy(service_authority, overlay_policy.id, .{ .service_identity = "overlay.notes.sync" })).allowed);
    try std.testing.expect((try service_port.evaluateNetworkPolicy(service_authority, relay_policy.id, .{ .domain = "relay.zigos.dev" })).allowed);
    try std.testing.expect((try service_port.evaluateNetworkPolicy(service_authority, inbound_policy.id, .{ .inbound_session_type = "document-review/v1" })).allowed);
    try std.testing.expect((try service_port.evaluateNetworkPolicy(service_authority, internet_policy.id, .public_internet)).allowed);

    _ = try service_port.configureWorkspacePolicy(service_authority, .{
        .workspace_id = notes_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/" },
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    });
    _ = try service_port.configureOverlay(service_authority, notes_id, laptop, "overlay.notes.sync", true);
    _ = try service_port.publishPrivateService(service_authority, notes_id, "notes.remote");

    try service_port.setReplicaVersion(service_authority, notes_id, tablet, "documents/notes.md", notes_v1.object_id, notes_v2.version_id);
    const summary = try service_port.replicateWorkspace(service_authority, &storage, notes_id, laptop, tablet, .device_to_device);
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_device_to_device);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expect(summary.remote_access_ready);
    try std.testing.expect(summary.private_service_published);
    try std.testing.expectEqual(@as(usize, 2), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.skipped_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.snapshot_count);
    try std.testing.expectEqual(@as(usize, 2), summary.transport_frame_count);
    try std.testing.expectEqual(@as(usize, 2), summary.encrypted_transport_count);
    try std.testing.expectEqual(@as(usize, 2), service.transportFrameCountFor(notes_id, tablet));
    const notes_frame = service.latestTransportFrameForPath(notes_id, tablet, "documents/notes.md").?;
    try std.testing.expect(notes_frame.encrypted);
    try std.testing.expectEqual(SyncSemantic.mergeable_crdt, notes_frame.semantic);
    const accepted_frame = try service_port.acceptTransportFrame(service_authority, &storage, .{
        .workspace_id = notes_id,
        .object_id = notes_frame.object_id,
        .version_id = notes_frame.version_id,
        .source_device = laptop,
        .target_device = tablet,
        .transport = .device_to_device,
        .semantic = .mergeable_crdt,
        .encrypted = true,
        .path = "documents/notes.md",
    });
    try std.testing.expectEqual(SyncSemantic.mergeable_crdt, accepted_frame.semantic);
    try std.testing.expect(accepted_frame.encrypted);
    try std.testing.expectEqual(@as(usize, 3), service.transportFrameCountFor(notes_id, tablet));
    try std.testing.expectError(error.SyncSemanticMismatch, service_port.acceptTransportFrame(service_authority, &storage, .{
        .workspace_id = notes_id,
        .object_id = notes_frame.object_id,
        .version_id = notes_frame.version_id,
        .source_device = laptop,
        .target_device = tablet,
        .transport = .device_to_device,
        .semantic = .chunked_snapshot,
        .encrypted = true,
        .path = "documents/notes.md",
    }));
    try std.testing.expectError(error.TransportDenied, service_port.acceptTransportFrame(service_authority, &storage, .{
        .workspace_id = notes_id,
        .object_id = notes_frame.object_id,
        .version_id = notes_frame.version_id,
        .source_device = laptop,
        .target_device = tablet,
        .transport = .device_to_device,
        .semantic = .mergeable_crdt,
        .encrypted = false,
        .path = "documents/notes.md",
    }));
    try std.testing.expectError(error.DeviceNotTrusted, service_port.acceptTransportFrame(service_authority, &storage, .{
        .workspace_id = notes_id,
        .object_id = notes_frame.object_id,
        .version_id = notes_frame.version_id,
        .source_device = laptop,
        .target_device = phone,
        .transport = .device_to_device,
        .semantic = .mergeable_crdt,
        .encrypted = true,
        .path = "documents/notes.md",
    }));
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expect(service.findConflict(notes_id, tablet, "documents/notes.md") != null);
    const clean_summary = try service_port.replicateWorkspace(service_authority, &storage, notes_id, laptop, tablet, .device_to_device);
    try std.testing.expectEqual(@as(usize, 0), clean_summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 0), clean_summary.transport_frame_count);

    try std.testing.expect(try service_port.transferSecretObject(service_authority, &storage, notes_id, secret.object_id, laptop, tablet, .device_to_device));
    const contract = try service_port.registerDatabaseContract(service_authority, notes_id, "app.db.notes", "notes-db", contract_signer);
    try std.testing.expect(try service_port.replicateDatabaseContract(service_authority, contract.id, notes_id, laptop, tablet, .relay_assisted));
    try std.testing.expectError(error.DeviceNotTrusted, service_port.replicateWorkspace(service_authority, &storage, notes_id, laptop, phone, .device_to_device));

    const state_entries = try storage.entries(service.state_workspace_id);
    var sync_record_count: usize = 0;
    for (state_entries) |entry| {
        const path = entry.pathSlice();
        try std.testing.expect(!std.mem.eql(u8, path, "state/index"));
        try std.testing.expect(!std.mem.startsWith(u8, path, "state/chunks/"));
        if (std.mem.startsWith(u8, path, "state/v7/")) sync_record_count += 1;
    }
    try std.testing.expect(sync_record_count >= 10);

    var restarted_resident = ResidentState{};
    var restarted = try Service.initWithStorage(80, 9, sync_owner, &storage, &restarted_resident);
    var restarted_capabilities = capability.CapabilityTable.init();
    const restarted_authority_capability = try mintSyncServiceAuthority(&restarted_capabilities, &restarted, sync_owner);
    var restarted_port = sync_service.SyncPort.init(&restarted, &restarted_capabilities);
    const restarted_authority = syncAuthority(&restarted, sync_owner, restarted_authority_capability, 35);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 2), restarted.trustedDeviceCount());
    try std.testing.expect(restarted.findWorkspacePolicy(notes_id) != null);
    try std.testing.expect(restarted.findOverlay(notes_id) != null);
    try std.testing.expectEqual(notes_v1.version_id.raw(), restarted.replicaVersion(notes_id, tablet, "documents/notes.md").?);
    try std.testing.expect(restarted.findConflict(notes_id, tablet, "documents/notes.md") != null);
    const restarted_local_policy = try restarted_port.createNetworkPolicy(restarted_authority, .{
        .owner = sync_owner,
        .workspace_id = notes_id,
        .label = "local",
        .mode = .local_network,
    });
    try std.testing.expectEqual(local_policy.id, restarted_local_policy.id);
    const restarted_overlay = try restarted_port.publishPrivateService(restarted_authority, notes_id, "notes.remote");
    try std.testing.expectEqual(@as(usize, 1), restarted_overlay.private_service_count);
    const restarted_contract = try restarted_port.registerDatabaseContract(restarted_authority, notes_id, "app.db.notes", "notes-db", contract_signer);
    try std.testing.expectEqual(contract.id, restarted_contract.id);

    storage_checkpoint_store.resetPersistent();
}

test "overlay sessions cover sync remote access private service publishing and encrypted relay" {
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 91 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 19 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 191 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 192 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 193 };
    const user_signer = signing.SignerIdentity{
        .label = "overlay-user",
        .seed = signing.seedFromByte(0x61),
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "overlay-laptop",
        .seed = signing.seedFromByte(0x62),
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "overlay-tablet",
        .seed = signing.seedFromByte(0x63),
    };
    const phone_signer = signing.SignerIdentity{
        .label = "overlay-phone",
        .seed = signing.seedFromByte(0x64),
    };

    var service = Service.init(901, 92, sync_owner);
    var service_capabilities = capability.CapabilityTable.init();
    const service_authority_capability = try mintSyncServiceAuthority(&service_capabilities, &service, sync_owner);
    var service_port = sync_service.SyncPort.init(&service, &service_capabilities);
    const service_authority = syncAuthority(&service, sync_owner, service_authority_capability, 20);
    _ = try service_port.ensureUserRoot(service_authority, user, "owner", user_signer);
    _ = try service_port.enrollTrustedDevice(service_authority, user, laptop, "laptop", user_signer, laptop_signer, 10);
    _ = try service_port.enrollTrustedDevice(service_authority, user, tablet, "tablet", user_signer, tablet_signer, 11);
    _ = try service_port.enrollTrustedDevice(service_authority, user, phone, "phone", user_signer, phone_signer, 12);

    const workspace_id: u64 = 4_200;
    const local_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "local",
        .mode = .local_network,
    });
    const overlay_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.workspace.sync",
    });
    const relay_policy = try service_port.createNetworkPolicy(service_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    _ = try service_port.configureWorkspacePolicy(service_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    });

    _ = try service_port.configureOverlay(service_authority, workspace_id, laptop, "overlay.workspace.sync", true);
    _ = try service_port.publishPrivateService(service_authority, workspace_id, "notes.remote");

    const sync_session = try service_port.openOverlaySession(
        service_authority,
        workspace_id,
        laptop,
        tablet,
        .sync_replication,
        .device_to_device,
        null,
        13,
    );
    try std.testing.expectEqual(OverlaySessionUse.sync_replication, sync_session.usage);
    try std.testing.expect(sync_session.isActive());
    try std.testing.expect(sync_session.encrypted);
    try std.testing.expect(!sync_session.relay_encrypted);
    try std.testing.expectEqualStrings("overlay.workspace.sync", sync_session.serviceIdentitySlice());
    try std.testing.expectEqual(@as(usize, 1), service.activeOverlaySessionCount());
    try std.testing.expect(try service_port.probeOverlaySession(service_authority, sync_session.session_id, 14));
    try std.testing.expectEqual(@as(u16, 1), service.findOverlaySession(sync_session.session_id).?.keepalive_count);

    const remote_session = try service_port.openOverlaySession(
        service_authority,
        workspace_id,
        laptop,
        tablet,
        .remote_access,
        .relay_assisted,
        null,
        15,
    );
    try std.testing.expectEqual(OverlaySessionUse.remote_access, remote_session.usage);
    try std.testing.expect(remote_session.remote_access);
    try std.testing.expect(remote_session.relay_encrypted);
    try std.testing.expectEqualStrings("relay.zigos.dev", remote_session.relayDomainSlice());
    const remote_session_id = remote_session.session_id;
    const remote_session_slot_index = service.overlay_sessions.slotIndexOf(remote_session_id).?;

    const private_service = try service_port.openOverlaySession(
        service_authority,
        workspace_id,
        tablet,
        laptop,
        .private_service,
        .relay_assisted,
        "notes.remote",
        16,
    );
    try std.testing.expectEqual(OverlaySessionUse.private_service, private_service.usage);
    try std.testing.expect(private_service.remote_access);
    try std.testing.expect(private_service.relay_encrypted);
    try std.testing.expectEqualStrings("notes.remote", private_service.privateServiceSlice());
    try std.testing.expectEqual(@as(usize, 3), service.activeOverlaySessionCount());

    var network_capabilities = capability.CapabilityTable.init();
    const relay_capability = try network_capabilities.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = relay_policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = service.task_id, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    var relay_service = try sync_transport.BootedOverlayRelayService.init(9_700, 9_701, "relay.zigos.dev");
    try std.testing.expectError(error.EgressDenied, service_port.sendOverlayRelayFrameViaService(
        service_authority,
        &network_capabilities,
        &relay_service,
        .{
            .workspace_id = workspace_id,
            .from_device = tablet,
            .to_device = laptop,
            .usage = .private_service,
            .private_service_label = "notes.remote",
            .relay_capability_id = relay_capability.id + 1,
            .payload = "remote-open",
            .signer = tablet_signer,
            .tick = 17,
        },
    ));
    try std.testing.expectEqual(@as(usize, 0), relay_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 3), service.activeOverlaySessionCount());

    const relay_exchange = try service_port.sendOverlayRelayFrameViaService(
        service_authority,
        &network_capabilities,
        &relay_service,
        .{
            .workspace_id = workspace_id,
            .from_device = tablet,
            .to_device = laptop,
            .usage = .private_service,
            .private_service_label = "notes.remote",
            .relay_capability_id = relay_capability.id,
            .payload = "remote-open",
            .signer = tablet_signer,
            .tick = 18,
        },
    );
    try std.testing.expect(relay_exchange.encrypted);
    try std.testing.expect(relay_exchange.relay_encrypted);
    try std.testing.expect(relay_exchange.remote_access);
    try std.testing.expect(relay_exchange.egress_allowed);
    try std.testing.expect(relay_exchange.delivered);
    try std.testing.expectEqual(@as(usize, "remote-open".len), relay_exchange.delivered_len);
    try std.testing.expectEqual(OverlaySessionUse.private_service, relay_exchange.usage);
    try std.testing.expectEqualStrings("overlay.workspace.sync", relay_exchange.serviceIdentitySlice());
    try std.testing.expectEqualStrings("relay.zigos.dev", relay_exchange.relayDomainSlice());
    try std.testing.expectEqualStrings("notes.remote", relay_exchange.privateServiceSlice());
    try std.testing.expectEqual(@as(usize, 1), relay_service.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), relay_service.delivered_packets);
    try std.testing.expectEqual(@as(usize, 4), service.activeOverlaySessionCount());
    try std.testing.expect(try service_port.closeOverlaySession(service_authority, relay_exchange.overlay_session_id, 19));
    try std.testing.expectEqual(@as(usize, 3), service.activeOverlaySessionCount());

    try std.testing.expect(try service_port.closeOverlaySession(service_authority, remote_session_id, 17));
    try std.testing.expectEqual(OverlaySessionState.closed, remote_session.state);
    try std.testing.expectEqual(@as(usize, 2), service.activeOverlaySessionCount());

    try std.testing.expectError(error.PrivateServiceNotPublished, service_port.openOverlaySession(
        service_authority,
        workspace_id,
        laptop,
        tablet,
        .private_service,
        .relay_assisted,
        "notes.missing",
        18,
    ));

    _ = try service_port.configureOverlay(service_authority, workspace_id, laptop, "overlay.workspace.sync", false);
    try std.testing.expectError(error.RemoteAccessDisabled, service_port.openOverlaySession(
        service_authority,
        workspace_id,
        laptop,
        phone,
        .remote_access,
        .relay_assisted,
        null,
        19,
    ));

    const unclaimed_session_count = sync_service.MAX_OVERLAY_SESSIONS - 4;
    for (0..unclaimed_session_count) |offset| {
        _ = try service_port.openOverlaySession(
            service_authority,
            workspace_id,
            laptop,
            tablet,
            .sync_replication,
            .device_to_device,
            null,
            20 + @as(u64, @intCast(offset)),
        );
    }

    const first_replacement = try service_port.openOverlaySession(
        service_authority,
        workspace_id,
        laptop,
        tablet,
        .sync_replication,
        .device_to_device,
        null,
        30,
    );
    const first_replacement_slot_index = service.overlay_sessions.slotIndexOf(first_replacement.session_id).?;
    const second_replacement = try service_port.openOverlaySession(
        service_authority,
        workspace_id,
        laptop,
        tablet,
        .sync_replication,
        .device_to_device,
        null,
        31,
    );
    const second_replacement_slot_index = service.overlay_sessions.slotIndexOf(second_replacement.session_id).?;

    try std.testing.expect(
        remote_session_slot_index == first_replacement_slot_index or
            remote_session_slot_index == second_replacement_slot_index,
    );
    try std.testing.expect(service.findOverlaySession(remote_session_id) == null);
}

test "sync service overlay session capacity is configurable" {
    const SmallService = ServiceWith(.{ .max_overlay_sessions = 2 });
    const service = SmallService.init(1, 2, .{ .kind = .service, .serial = 3 });

    try std.testing.expectEqual(@as(usize, 2), service.overlaySessionCapacity());
}
