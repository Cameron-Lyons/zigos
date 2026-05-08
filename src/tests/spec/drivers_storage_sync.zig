const std = @import("std");
const spec_support = @import("support.zig");
const bootstrap_driver_port = @import("../../native/drivers/bootstrap_driver_port.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const driver_runtime_mod = @import("../../native/drivers/driver_runtime.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const manifest = @import("../../native/policy/manifest.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const object_store = @import("../../native/storage/object_store.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const storage_service_ipc = @import("../../native/storage/storage_service_ipc.zig");
const storage_volume = @import("../../native/storage/storage_volume.zig");
const sync_service = @import("../../native/sync/sync_service.zig");
const workspace = @import("../../native/storage/workspace.zig");

pub fn publishedDriversActivateScopedTransports() !void {
    var capabilities = capability.CapabilityTable.init();
    const FakeNetworkDevice = struct {
        var activation_count: usize = 0;

        fn send(_: []const u8) void {}

        fn getMacAddress() [6]u8 {
            return .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
        }

        const published_device = bootstrap_driver_port.NetworkDevice{
            .send = send,
            .getMacAddress = getMacAddress,
        };

        fn activate(device_id: u64) ?*const bootstrap_driver_port.NetworkDevice {
            if (device_id != 0x8086_100E_0001) return null;
            activation_count += 1;
            return &published_device;
        }
    };
    const FakeBackend = struct {
        var image: []u8 = &.{};
        var activation_count: usize = 0;

        fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            const buffer = buffer_ptr[0..buffer_len];
            const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
            const end = start + buffer.len;
            if (end > image.len) return false;
            @memcpy(buffer, image[start..end]);
            return true;
        }

        fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
            const buffer = buffer_ptr[0..buffer_len];
            const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
            const end = start + buffer.len;
            if (end > image.len) return false;
            @memcpy(image[start..end], buffer);
            return true;
        }

        fn activate(device_id: u64) ?storage_volume.Backend {
            if (device_id != 0x0000_1F00_0001) return null;
            activation_count += 1;
            return .{
                .sector_count = storage_volume.required_device_sectors,
                .read = read,
                .write = write,
            };
        }
    };

    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();

    var image = [_]u8{0} ** storage_volume.image_bytes;
    FakeBackend.image = &image;

    const network_device_id: u64 = 0x8086_100E_0001;
    const storage_device_id: u64 = 0x0000_1F00_0001;
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.runtime",
        .display_name = "Published Driver Runtime",
        .publisher = "zigos.spec",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-spec-driver",
        },
    };

    try std.testing.expect(try bootstrap_driver_port.publishStorageActivator(
        storage_device_id,
        "ata-bootstrap",
        FakeBackend.activate,
        false,
    ));

    var directory = driver_service.Directory.init();
    const network_authority = try spec_support.driverAuthority(
        &capabilities,
        spec_support.service(91),
        901,
        network_device_id,
        .network_adapter,
    );
    const network_driver = try directory.register(.{
        .service_id = 91,
        .owner_task_id = 901,
        .device_id = network_device_id,
        .device_class = .network_adapter,
        .authority_capability_id = network_authority.id,
        .capability_table = &capabilities,
        .requester = network_authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
    });
    const storage_authority = try spec_support.driverAuthority(
        &capabilities,
        spec_support.service(92),
        902,
        storage_device_id,
        .storage_controller,
    );
    const storage_driver = try directory.register(.{
        .service_id = 92,
        .owner_task_id = 902,
        .device_id = storage_device_id,
        .device_class = .storage_controller,
        .authority_capability_id = storage_authority.id,
        .capability_table = &capabilities,
        .requester = storage_authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
        .bootstrap_transport = .kernel_published_data_plane,
    });
    const graphics_authority = try spec_support.driverAuthority(
        &capabilities,
        spec_support.service(93),
        903,
        0x1234_1111_0001,
        .graphics_adapter,
    );
    const graphics_driver = try directory.register(.{
        .service_id = 93,
        .owner_task_id = 903,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
        .authority_capability_id = graphics_authority.id,
        .capability_table = &capabilities,
        .requester = graphics_authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
    });

    var runtime = driver_runtime_mod.Runtime.init();
    const network_activation = try runtime.activateAt(network_driver, 1);
    const storage_activation = try runtime.activateAt(storage_driver, 1);
    const graphics_activation = try runtime.activateAt(graphics_driver, 1);

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.control_only, network_activation.mode);
    try std.testing.expect(!network_activation.exclusive_claim);
    try std.testing.expect(!network_activation.kernel_bootstrap);
    try std.testing.expectEqual(@as(usize, 0), FakeNetworkDevice.activation_count);
    try std.testing.expect(!bootstrap_driver_port.hasActiveNetworkDevice());
    try std.testing.expect(bootstrap_driver_port.networkPublication() == null);
    try std.testing.expect(runtime.deactivate(network_driver.service_id));

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, storage_activation.mode);
    try std.testing.expect(storage_activation.exclusive_claim);
    try std.testing.expect(!storage_activation.kernel_bootstrap);
    try std.testing.expectEqualStrings("ata-bootstrap", storage_activation.publisherSlice());
    try std.testing.expectEqual(@as(usize, 1), FakeBackend.activation_count);
    try std.testing.expect(storage_volume.hasAttachedDevice());
    try std.testing.expectEqual(@as(u64, 92), bootstrap_driver_port.storagePublication().?.active_service_id);

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.control_only, graphics_activation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.control_only, runtime.findByClass(.network_adapter).?.mode);
    try std.testing.expectEqualStrings("ata-bootstrap", runtime.findByClass(.storage_controller).?.publisherSlice());
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.control_only, runtime.findByClass(.graphics_adapter).?.mode);

    var unsupported_network_transport_directory = driver_service.Directory.init();
    try std.testing.expectError(driver_service.Error.InvalidBootstrapTransport, unsupported_network_transport_directory.register(.{
        .service_id = 95,
        .owner_task_id = 901,
        .device_id = network_device_id,
        .device_class = .network_adapter,
        .authority_capability_id = network_authority.id,
        .capability_table = &capabilities,
        .requester = network_authority.holder,
        .now_ticks = 2,
        .bundle = bundle,
        .bootstrap_transport = .kernel_published_data_plane,
    }));
    var unsupported_transport_directory = driver_service.Directory.init();
    try std.testing.expectError(driver_service.Error.InvalidBootstrapTransport, unsupported_transport_directory.register(.{
        .service_id = 94,
        .owner_task_id = 903,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
        .authority_capability_id = graphics_authority.id,
        .capability_table = &capabilities,
        .requester = graphics_authority.holder,
        .now_ticks = 2,
        .bundle = bundle,
        .bootstrap_transport = .kernel_published_data_plane,
    }));
}

pub fn storageStaysVersionedRecoverableSignedAndDerived() !void {
    try storage_service_ipc.userspaceCreateWorkspaceRoundTripProof();

    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = spec_support.service(20);
    const writer = spec_support.user(2);
    const storage_signer = spec_support.signer("spec.storage", 0x31);

    var storage = storage_service.Service.initWithStore(500, 50, storage_owner, &storage_checkpoint_store);
    var bridge_capabilities = capability.CapabilityTable.init();
    storage.bindCapabilityTable(&bridge_capabilities);
    const draft_v1 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_000),
        .object_type = .document,
        .payload = "report-v1",
        .metadata = try object_store.signMetadata(storage_signer, "report", "text/markdown", .document, "report-v1", 1),
    });
    const draft_v2 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_000),
        .object_type = .document,
        .payload = "report-v2",
        .metadata = try object_store.signMetadata(storage_signer, "report", "text/markdown", .document, "report-v2", 2),
        .parent_version_id = draft_v1.version_id,
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = writer,
        .label = "report-alpha",
    });

    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/report.md", draft_v1.object_id, draft_v1.version_id, .document);
    _ = try storage.commit(workspace_record.id, 3);
    const baseline = try storage.snapshot(workspace_record.id, "baseline", storage_signer);

    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/report.md", draft_v2.object_id, draft_v2.version_id, .document);
    _ = try storage.commit(workspace_record.id, 4);

    try storage.beginTransaction(workspace_record.id);
    try storage.stageDelete(workspace_record.id, "documents/report.md");
    _ = try storage.commit(workspace_record.id, 5);
    try std.testing.expect(try storage.recoverDeleted(workspace_record.id, "documents/report.md", 6));

    const recovered = try storage.resolve(workspace_record.id, "documents/report.md");
    try std.testing.expectEqual(draft_v2.object_id, recovered.object_id);
    try std.testing.expectEqual(draft_v2.version_id, recovered.version_id);
    try std.testing.expectEqual(@as(usize, 1), storage.objectCount());
    try std.testing.expectEqual(@as(usize, 2), storage.versionCount());

    const exported = try storage.exportSnapshot(workspace_record.id, baseline.id, storage_signer);
    const imported = try storage.importWorkspace(spec_support.user(3), "report-import", exported, 7);
    const imported_entry = try storage.resolve(imported.id, "documents/report.md");
    try std.testing.expectEqual(draft_v1.version_id, imported_entry.version_id);

    const workspace_capability = try bridge_capabilities.mintBootRoot(.{
        .holder = writer,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .workspace, .id = workspace_record.id.raw() },
        .rights = .{ .workspace = .{
            .object_read = true,
            .object_write = true,
        } },
        .scope = .{
            .task_id = 88,
            .workspace_id = workspace_record.id.raw(),
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    });
    const view = try storage.bridgeResolve(.{
        .workspace_id = workspace_record.id.raw(),
        .path = "/documents/report.md",
        .access = .read,
    }, .{
        .task_id = 88,
        .principal = workspace_capability.holder,
        .capability_id = workspace_capability.id,
        .now_ticks = 8,
    });
    try std.testing.expect(!view.authoritative);
    try std.testing.expect(view.readable);
    try std.testing.expect(view.writable);
    try std.testing.expectEqualStrings("documents/report.md", view.pathSlice());
    try std.testing.expectEqual(draft_v2.version_id.raw(), view.version_id);
}

pub fn trustedDeviceGraphSelectiveSyncAndPolicyNetworking() !void {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = spec_support.service(30);
    const sync_owner = spec_support.service(31);
    const person = spec_support.user(4);
    const laptop = spec_support.device(41);
    const tablet = spec_support.device(42);
    const storage_signer = spec_support.signer("spec.sync.storage", 0x41);
    const user_signer = spec_support.signer("spec.sync.user", 0x42);
    const laptop_signer = spec_support.signer("spec.sync.laptop", 0x43);
    const tablet_signer = spec_support.signer("spec.sync.tablet", 0x44);
    const contract_signer = spec_support.signer("spec.sync.contract", 0x45);

    var storage = storage_service.Service.initWithStore(600, 60, storage_owner, &storage_checkpoint_store);
    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_100),
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v1", 1),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_100),
        .object_type = .document,
        .payload = "notes-v2",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v2", 2),
        .parent_version_id = notes_v1.version_id,
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_101),
        .object_type = .media_asset,
        .payload = "cover.jpg",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "cover.jpg", 3),
    });
    const inbox = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_102),
        .object_type = .collection,
        .payload = "inbox",
        .metadata = try object_store.signMetadata(storage_signer, "inbox", "application/zigos-collection", .collection, "inbox", 4),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_103),
        .object_type = .secret,
        .payload = "enc:top-secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:top-secret", 5),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "shared-notes",
    });
    const workspace_id = workspace_record.id.raw();
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes_v1.object_id, notes_v1.version_id, .document);
    try storage.stagePut(workspace_record.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    try storage.stagePut(workspace_record.id, "collections/inbox", inbox.object_id, inbox.version_id, .collection);
    _ = try storage.commit(workspace_record.id, 6);

    var sync = sync_service.Service.init(601, 61, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try spec_support.serviceAuthority(&sync_capabilities, sync.service_id, sync_owner, sync.task_id);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = spec_support.serviceAuthorityContext(sync.task_id, sync_owner, sync_capability, 25);
    _ = try sync_port.ensureUserRoot(sync_authority, person, "owner", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, person, laptop, "laptop", user_signer, laptop_signer, 10);
    _ = try sync_port.enrollTrustedDevice(sync_authority, person, tablet, "tablet", user_signer, tablet_signer, 11);

    const local_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "local",
        .mode = .local_network,
    });
    const discovery_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const relay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.spec.zigos",
    });
    const overlay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.spec",
    });
    const inbound_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "document-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    });
    const collaborator = spec_support.app(63);
    const prefixes = [_][]const u8{ "documents/", "assets/" };
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_id,
        .owner = person,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &prefixes,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.spec.zigos",
    });
    _ = try sync_port.configureOverlay(sync_authority, workspace_id, laptop, "overlay.notes.spec", true);
    _ = try sync_port.publishPrivateService(sync_authority, workspace_id, "notes.remote");
    try storage.shareWorkspace(workspace_record.id, .{
        .principal_id = collaborator,
        .can_read = true,
        .can_write = true,
        .can_admin = true,
        .can_export = true,
        .expires_at_ticks = 40,
        .network_scope = .trusted_overlay,
        .reshare_policy = .admin_only,
        .audit_visibility = .shared_participants,
    });
    const share = storage.findShareGrant(workspace_record.id, collaborator).?;
    try std.testing.expectEqual(workspace.ShareNetworkScope.trusted_overlay, share.network_scope);
    try std.testing.expectEqual(workspace.ResharePolicy.admin_only, share.reshare_policy);
    try std.testing.expectEqual(workspace.AuditVisibility.shared_participants, share.audit_visibility);
    try std.testing.expect(storage.workspaceHasAccess(workspace_record.id, .{
        .principal_id = collaborator,
        .wants_write = true,
        .wants_export = true,
        .wants_admin = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 20,
    }));
    try std.testing.expect(storage.workspaceCanReshare(workspace_record.id, collaborator, .trusted_overlay, 20));
    try std.testing.expect(!storage.workspaceHasAccess(workspace_record.id, .{
        .principal_id = collaborator,
        .network_scope = .relay_assisted,
        .now_ticks = 50,
    }));

    try sync_port.setReplicaVersion(sync_authority, workspace_id, tablet, "documents/notes.md", notes_v1.object_id, notes_v2.version_id);
    const summary = try sync_port.replicateWorkspace(sync_authority, &storage, workspace_id, laptop, tablet, .device_to_device);
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
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expect(sync.findConflict(workspace_id, tablet, "documents/notes.md") != null);
    try std.testing.expect(sync.isTrustedDevice(laptop));
    try std.testing.expect(sync.isTrustedDevice(tablet));
    try std.testing.expect(try sync_port.transferSecretObject(sync_authority, &storage, workspace_id, secret.object_id, laptop, tablet, .device_to_device));

    const database_contract = try sync_port.registerDatabaseContract(sync_authority, workspace_id, "app.notes.db", "notes-db", contract_signer);
    try std.testing.expect(try sync_port.replicateDatabaseContract(sync_authority, database_contract.id, workspace_id, laptop, tablet, .relay_assisted));
    try std.testing.expect((try sync_port.evaluateNetworkPolicy(sync_authority, local_policy.id, .local_network)).allowed);
    try std.testing.expect((try sync_port.evaluateNetworkPolicy(sync_authority, discovery_policy.id, .{ .discovery_class = "printer" })).allowed);
    try std.testing.expect(!(try sync_port.evaluateNetworkPolicy(sync_authority, discovery_policy.id, .{ .discovery_class = "camera" })).allowed);
    try std.testing.expect((try sync_port.evaluateNetworkPolicy(sync_authority, relay_policy.id, .{ .domain = "relay.spec.zigos" })).allowed);
    try std.testing.expect((try sync_port.evaluateNetworkPolicy(sync_authority, overlay_policy.id, .{ .service_identity = "overlay.notes.spec" })).allowed);
    try std.testing.expect((try sync_port.evaluateNetworkPolicy(sync_authority, inbound_policy.id, .{ .inbound_session_type = "document-review/v1" })).allowed);
    try std.testing.expect(!(try sync_port.evaluateNetworkPolicy(sync_authority, inbound_policy.id, .{ .inbound_session_type = "pair-screen/v1" })).allowed);

    var egress_capabilities = capability.CapabilityTable.init();
    const relay_egress_capability = try egress_capabilities.mintBootRoot(.{
        .holder = collaborator,
        .issuer = spec_support.policyAuthority(31),
        .target = .{ .kind = .network_policy, .id = relay_policy.id },
        .rights = .{ .network_policy = .{
            .network_remote = true,
        } },
        .scope = .{
            .task_id = 631,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 20,
            .expires_at_ticks = 40,
        },
    });
    const local_egress_capability = try egress_capabilities.mintBootRoot(.{
        .holder = collaborator,
        .issuer = spec_support.policyAuthority(31),
        .target = .{ .kind = .network_policy, .id = local_policy.id },
        .rights = .{ .network_policy = .{
            .network_local = true,
        } },
        .scope = .{
            .task_id = 631,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 20,
            .expires_at_ticks = 40,
        },
    });
    const relay_connection = try sync.authorizeNetworkConnection(&egress_capabilities, .{
        .task_id = 631,
        .principal_id = collaborator,
        .capability_id = relay_egress_capability.id,
        .policy_id = relay_policy.id,
        .evidence = .{ .destination = .{ .domain = "relay.spec.zigos" } },
        .now_ticks = 25,
    });
    try std.testing.expect(relay_connection.allowed);

    const denied_relay_connection = try sync.authorizeNetworkConnection(&egress_capabilities, .{
        .task_id = 631,
        .principal_id = collaborator,
        .capability_id = relay_egress_capability.id,
        .policy_id = relay_policy.id,
        .evidence = .{ .destination = .{ .domain = "other.spec.zigos" } },
        .now_ticks = 25,
    });
    try std.testing.expect(!denied_relay_connection.allowed);
    try std.testing.expectEqual(network_policy.EgressDecisionReason.destination_mismatch, denied_relay_connection.reason);

    var packet_broker = sync.egressBroker(&egress_capabilities);
    var transport_harness = sync_service.transport_harness.Harness.init();
    const local_packet_session = try transport_harness.openDeviceToDevice(&packet_broker, .{
        .task_id = 631,
        .principal_id = collaborator,
        .capability_id = local_egress_capability.id,
        .policy_id = local_policy.id,
        .evidence = .{ .destination = .local_network },
        .now_ticks = 25,
    }, laptop, tablet);
    const local_packet = try transport_harness.encryptPacket(&local_packet_session, "documents/notes.md:v2");
    try std.testing.expect(local_packet.encrypted);
    try std.testing.expect(local_packet.egress_allowed);
    try std.testing.expectEqual(sync_service.TransportMode.device_to_device, local_packet.transport);
    try std.testing.expect(!std.mem.eql(u8, local_packet.ciphertextSlice(), "documents/notes.md:v2"));

    const relay_packet_session = try transport_harness.openRelay(&packet_broker, .{
        .task_id = 631,
        .principal_id = collaborator,
        .capability_id = relay_egress_capability.id,
        .policy_id = relay_policy.id,
        .evidence = .{ .destination = .{ .domain = "relay.spec.zigos" } },
        .now_ticks = 25,
    }, laptop, tablet, "relay.spec.zigos");
    const relay_packet = try transport_harness.encryptPacket(&relay_packet_session, "relay-sync-frame");
    try std.testing.expect(relay_packet.encrypted);
    try std.testing.expect(relay_packet.egress_allowed);
    try std.testing.expectEqual(sync_service.TransportMode.relay_assisted, relay_packet.transport);
    try std.testing.expectEqualStrings("relay.spec.zigos", relay_packet_session.relayDomainSlice());
    try std.testing.expect(!std.mem.eql(u8, relay_packet.ciphertextSlice(), "relay-sync-frame"));

    try std.testing.expectError(sync_service.transport_harness.Error.EgressDenied, transport_harness.openRelay(&packet_broker, .{
        .task_id = 631,
        .principal_id = collaborator,
        .capability_id = relay_egress_capability.id,
        .policy_id = relay_policy.id,
        .evidence = .{ .destination = .{ .domain = "other.spec.zigos" } },
        .now_ticks = 25,
    }, laptop, tablet, "other.spec.zigos"));
    try std.testing.expectEqual(@as(usize, 2), transport_harness.created_sessions);
    try std.testing.expectEqual(@as(usize, 1), transport_harness.denied_sessions);
    try std.testing.expectEqual(@as(usize, 2), transport_harness.encrypted_packets);

    const latest_notes_frame = sync.latestTransportFrameForPath(workspace_id, tablet, "documents/notes.md").?;
    try std.testing.expect(latest_notes_frame.encrypted);
    try std.testing.expectEqual(sync_service.TransportMode.device_to_device, latest_notes_frame.transport);
    try std.testing.expectEqual(sync_service.SyncSemantic.mergeable_crdt, latest_notes_frame.semantic);
    try std.testing.expectEqualStrings("documents/notes.md", latest_notes_frame.pathSlice());
    try std.testing.expectEqual(summary.transport_frame_count, summary.encrypted_transport_count);

    const relay_session = try sync_port.openOverlaySession(
        sync_authority,
        workspace_id,
        laptop,
        tablet,
        .remote_access,
        .relay_assisted,
        null,
        30,
    );
    try std.testing.expect(relay_session.encrypted);
    try std.testing.expect(relay_session.relay_encrypted);
    try std.testing.expect(relay_session.remote_access);
    try std.testing.expectEqualStrings("overlay.notes.spec", relay_session.serviceIdentitySlice());
    try std.testing.expectEqualStrings("relay.spec.zigos", relay_session.relayDomainSlice());
    try std.testing.expectError(sync_service.Error.DeviceNotTrusted, sync_port.openOverlaySession(
        sync_authority,
        workspace_id,
        laptop,
        spec_support.device(99),
        .sync_replication,
        .device_to_device,
        null,
        31,
    ));

    try realDriverEgressRequiresNetworkPolicyCapability(collaborator);
}

fn realDriverEgressRequiresNetworkPolicyCapability(requester: @TypeOf(spec_support.app(1))) !void {
    if (@import("builtin").target.os.tag == .freestanding) return error.SkipZigTest;

    const Harness = struct {
        var send_count: usize = 0;
        var policies = network_policy.Directory.init();
        var capabilities = capability.CapabilityTable.init();
        var task_id: u64 = 0;
        var principal_id = spec_support.app(0);
        var live_policy_id: u64 = 0;

        fn send(_: []const u8) void {
            send_count += 1;
        }

        fn mac() [6]u8 {
            return .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
        }

        fn broker(request: bootstrap_driver_port.EgressRequest) bootstrap_driver_port.EgressDecision {
            var egress = network_policy.EgressBroker.init(&policies, &capabilities);
            const decision = egress.connect(.{
                .task_id = task_id,
                .principal_id = principal_id,
                .capability_id = request.egress_capability_id,
                .policy_id = request.network_policy_id,
                .evidence = .{ .destination = .{ .domain = "relay.spec.zigos" } },
                .now_ticks = 25,
            }) catch return .{ .allowed = false, .capability_backed = false };
            return .{
                .allowed = decision.allowed,
                .capability_backed = decision.allowed and decision.capability_id != 0 and decision.policy_id == live_policy_id,
            };
        }
    };

    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();

    Harness.send_count = 0;
    Harness.policies = network_policy.Directory.init();
    Harness.capabilities = capability.CapabilityTable.init();
    Harness.task_id = 631;
    Harness.principal_id = requester;
    const policy = try Harness.policies.create(.{
        .owner = spec_support.service(31),
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.spec.zigos",
    });
    Harness.live_policy_id = policy.id;
    const authority = try Harness.capabilities.mintBootRoot(.{
        .holder = requester,
        .issuer = spec_support.policyAuthority(31),
        .target = .{ .kind = .network_policy, .id = policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = Harness.task_id, .broker_only = true },
        .lease = .{ .issued_at_ticks = 20, .expires_at_ticks = 40 },
    });
    const device = bootstrap_driver_port.NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(try bootstrap_driver_port.publishNetworkDevice(0xCAFE, "policy-egress", &device, false));
    try std.testing.expect(bootstrap_driver_port.activateNetworkDevice(0xCAFE, 800));
    bootstrap_driver_port.setEgressBroker(Harness.broker);

    const frame = "dst=relay.spec.zigos";
    try std.testing.expect(!bootstrap_driver_port.sendActiveNetworkFrame(frame));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    bootstrap_driver_port.bindEgressCapability(authority.id + 1, policy.id);
    try std.testing.expect(!bootstrap_driver_port.sendActiveNetworkFrame(frame));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    bootstrap_driver_port.bindEgressCapability(authority.id, policy.id + 1);
    try std.testing.expect(!bootstrap_driver_port.sendActiveNetworkFrame(frame));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    bootstrap_driver_port.bindEgressCapability(authority.id, policy.id);
    try std.testing.expect(bootstrap_driver_port.sendActiveNetworkFrame(frame));
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
}
