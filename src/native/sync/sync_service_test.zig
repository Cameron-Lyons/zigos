const std = @import("std");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("sync_service_impl.zig");

const OverlaySessionState = sync_service.OverlaySessionState;
const OverlaySessionUse = sync_service.OverlaySessionUse;
const ResidentState = sync_service.ResidentState;
const Service = sync_service.Service;
const ServiceWith = sync_service.ServiceWith;
const SyncSemantic = sync_service.SyncSemantic;

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
        .seed = [_]u8{0x51} ** 32,
    };
    const user_signer = signing.SignerIdentity{
        .label = "user-root",
        .seed = [_]u8{0x52} ** 32,
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "laptop",
        .seed = [_]u8{0x53} ** 32,
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "tablet",
        .seed = [_]u8{0x54} ** 32,
    };
    const tablet_rotated_signer = signing.SignerIdentity{
        .label = "tablet-v2",
        .seed = [_]u8{0x55} ** 32,
    };
    const phone_signer = signing.SignerIdentity{
        .label = "phone",
        .seed = [_]u8{0x56} ** 32,
    };
    const contract_signer = signing.SignerIdentity{
        .label = "db-sync",
        .seed = [_]u8{0x57} ** 32,
    };

    var storage = storage_service.Service.initWithStore(40, 4, storage_owner, &storage_checkpoint_store);
    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = 800,
        .object_type = .document,
        .payload = "# Notes\n- v1\n",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/markdown", .document, "# Notes\n- v1\n", 10),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = 800,
        .object_type = .document,
        .payload = "# Notes\n- v2\n",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/markdown", .document, "# Notes\n- v2\n", 11),
        .parent_version_id = notes_v1.version_id,
    });
    const inbox = try storage.putVersion(.{
        .preferred_object_id = 801,
        .object_type = .collection,
        .payload = "inbox",
        .metadata = try object_store.signMetadata(storage_signer, "inbox", "application/zigos-collection", .collection, "inbox", 12),
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = 802,
        .object_type = .media_asset,
        .payload = "jpeg:cover",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "jpeg:cover", 13),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = 803,
        .object_type = .secret,
        .payload = "enc:secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:secret", 14),
    });

    const notes = try storage.createWorkspace(.{
        .owner = user,
        .label = "notes",
    });
    try storage.beginTransaction(notes.id);
    try storage.stagePut(notes.id, "documents/notes.md", notes_v1.object_id, notes_v1.version_id, .document);
    try storage.stagePut(notes.id, "collections/inbox", inbox.object_id, inbox.version_id, .collection);
    try storage.stagePut(notes.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    _ = try storage.commit(notes.id, 15);

    var resident = ResidentState{};
    var service = try Service.initWithStorage(80, 8, sync_owner, &storage, &resident);
    _ = try service.ensureUserRoot(user, "cameron", user_signer);
    _ = try service.enrollTrustedDevice(user, laptop, "laptop", user_signer, laptop_signer, 20);
    _ = try service.enrollTrustedDevice(user, tablet, "tablet", user_signer, tablet_signer, 21);
    _ = try service.enrollTrustedDevice(user, phone, "phone", user_signer, phone_signer, 22);
    _ = try service.rotateDeviceKey(user, tablet, user_signer, tablet_rotated_signer, 23);
    try service.revokeTrustedDevice(user, phone, user_signer, 24);

    const none_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "none",
        .mode = .none,
    });
    const local_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "local",
        .mode = .local_network,
    });
    const discovery_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const overlay_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    });
    const relay_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    const inbound_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "collab-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    });
    const internet_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    });

    try std.testing.expect(!(try service.evaluateNetworkPolicy(none_policy.id, .public_internet)).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(local_policy.id, .local_network)).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(discovery_policy.id, .{ .discovery_class = "printer" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(overlay_policy.id, .{ .service_identity = "overlay.notes.sync" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(relay_policy.id, .{ .domain = "relay.zigos.dev" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(inbound_policy.id, .{ .inbound_session_type = "document-review/v1" })).allowed);
    try std.testing.expect((try service.evaluateNetworkPolicy(internet_policy.id, .public_internet)).allowed);

    _ = try service.configureWorkspacePolicy(.{
        .workspace_id = notes.id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/" },
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    });
    _ = try service.configureOverlay(notes.id, laptop, "overlay.notes.sync", true);
    _ = try service.publishPrivateService(notes.id, "notes.remote");

    try service.setReplicaVersion(notes.id, tablet, "documents/notes.md", notes_v1.object_id, notes_v2.version_id);
    const summary = try service.replicateWorkspace(&storage, notes.id, laptop, tablet, .device_to_device);
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
    try std.testing.expectEqual(@as(usize, 2), service.transportFrameCountFor(notes.id, tablet));
    const notes_frame = service.latestTransportFrameForPath(notes.id, tablet, "documents/notes.md").?;
    try std.testing.expect(notes_frame.encrypted);
    try std.testing.expectEqual(SyncSemantic.mergeable_crdt, notes_frame.semantic);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expect(service.findConflict(notes.id, tablet, "documents/notes.md") != null);

    try std.testing.expect(try service.transferSecretObject(&storage, notes.id, secret.object_id, laptop, tablet, .device_to_device));
    const contract = try service.registerDatabaseContract(notes.id, "app.db.notes", "notes-db", contract_signer);
    try std.testing.expect(try service.replicateDatabaseContract(contract.id, notes.id, laptop, tablet, .relay_assisted));
    try std.testing.expectError(error.DeviceNotTrusted, service.replicateWorkspace(&storage, notes.id, laptop, phone, .device_to_device));

    var restarted_resident = ResidentState{};
    var restarted = try Service.initWithStorage(80, 9, sync_owner, &storage, &restarted_resident);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 2), restarted.trustedDeviceCount());
    try std.testing.expect(restarted.findWorkspacePolicy(notes.id) != null);
    try std.testing.expect(restarted.findOverlay(notes.id) != null);
    try std.testing.expect(restarted.findConflict(notes.id, tablet, "documents/notes.md") != null);
    const restarted_local_policy = try restarted.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = notes.id,
        .label = "local",
        .mode = .local_network,
    });
    try std.testing.expectEqual(local_policy.id, restarted_local_policy.id);
    const restarted_overlay = try restarted.publishPrivateService(notes.id, "notes.remote");
    try std.testing.expectEqual(@as(usize, 1), restarted_overlay.private_service_count);
    const restarted_contract = try restarted.registerDatabaseContract(notes.id, "app.db.notes", "notes-db", contract_signer);
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
        .seed = [_]u8{0x61} ** 32,
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "overlay-laptop",
        .seed = [_]u8{0x62} ** 32,
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "overlay-tablet",
        .seed = [_]u8{0x63} ** 32,
    };
    const phone_signer = signing.SignerIdentity{
        .label = "overlay-phone",
        .seed = [_]u8{0x64} ** 32,
    };

    var service = Service.init(901, 92, sync_owner);
    _ = try service.ensureUserRoot(user, "owner", user_signer);
    _ = try service.enrollTrustedDevice(user, laptop, "laptop", user_signer, laptop_signer, 10);
    _ = try service.enrollTrustedDevice(user, tablet, "tablet", user_signer, tablet_signer, 11);
    _ = try service.enrollTrustedDevice(user, phone, "phone", user_signer, phone_signer, 12);

    const workspace_id: u64 = 4_200;
    const local_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "local",
        .mode = .local_network,
    });
    const overlay_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.workspace.sync",
    });
    const relay_policy = try service.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    _ = try service.configureWorkspacePolicy(.{
        .workspace_id = workspace_id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    });

    _ = try service.configureOverlay(workspace_id, laptop, "overlay.workspace.sync", true);
    _ = try service.publishPrivateService(workspace_id, "notes.remote");

    const sync_session = try service.openOverlaySession(
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
    try std.testing.expect(try service.probeOverlaySession(sync_session.session_id, 14));
    try std.testing.expectEqual(@as(u16, 1), service.findOverlaySession(sync_session.session_id).?.keepalive_count);

    const remote_session = try service.openOverlaySession(
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

    const private_service = try service.openOverlaySession(
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
    try std.testing.expect(try service.closeOverlaySession(remote_session.session_id, 17));
    try std.testing.expectEqual(OverlaySessionState.closed, service.findOverlaySession(remote_session.session_id).?.state);
    try std.testing.expectEqual(@as(usize, 2), service.activeOverlaySessionCount());

    try std.testing.expectError(error.PrivateServiceNotPublished, service.openOverlaySession(
        workspace_id,
        laptop,
        tablet,
        .private_service,
        .relay_assisted,
        "notes.missing",
        18,
    ));

    _ = try service.configureOverlay(workspace_id, laptop, "overlay.workspace.sync", false);
    try std.testing.expectError(error.RemoteAccessDisabled, service.openOverlaySession(
        workspace_id,
        laptop,
        phone,
        .remote_access,
        .relay_assisted,
        null,
        19,
    ));
}

test "sync service overlay session capacity is configurable" {
    const SmallService = ServiceWith(.{ .max_overlay_sessions = 2 });
    const service = SmallService.init(1, 2, .{ .kind = .service, .serial = 3 });

    try std.testing.expectEqual(@as(usize, 2), service.overlay_sessions.len);
}
