const std = @import("std");
const spec_support = @import("support.zig");
const bootstrap_driver_port = @import("../kernel/process/native/bootstrap_driver_port.zig");
const capability = @import("../kernel/process/native/capability.zig");
const driver_runtime_mod = @import("../kernel/process/native/driver_runtime.zig");
const driver_service = @import("../kernel/process/native/driver_service.zig");
const manifest = @import("../kernel/process/native/manifest.zig");
const object_store = @import("../kernel/process/native/object_store.zig");
const storage_service = @import("../kernel/process/native/storage_service.zig");
const storage_volume = @import("../kernel/process/native/storage_volume.zig");
const sync_service = @import("../kernel/process/native/sync_service.zig");
const workspace = @import("../kernel/process/native/workspace.zig");

pub fn publishedDriversActivateScopedTransports() !void {
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

    try std.testing.expect(bootstrap_driver_port.publishNetworkActivator(
        network_device_id,
        "e1000",
        FakeNetworkDevice.activate,
        true,
    ));
    try std.testing.expect(bootstrap_driver_port.publishStorageActivator(
        storage_device_id,
        "ata-bootstrap",
        FakeBackend.activate,
        true,
    ));

    var directory = driver_service.Directory.init();
    const network_driver = try directory.register(.{
        .service_id = 91,
        .owner_task_id = 901,
        .device_id = network_device_id,
        .device_class = .network_adapter,
        .authority = spec_support.driverAuthority(spec_support.service(91), 501, 901, network_device_id, .network_adapter),
        .bundle = bundle,
    });
    const storage_driver = try directory.register(.{
        .service_id = 92,
        .owner_task_id = 902,
        .device_id = storage_device_id,
        .device_class = .storage_controller,
        .authority = spec_support.driverAuthority(spec_support.service(92), 502, 902, storage_device_id, .storage_controller),
        .bundle = bundle,
    });
    const graphics_driver = try directory.register(.{
        .service_id = 93,
        .owner_task_id = 903,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
        .authority = spec_support.driverAuthority(spec_support.service(93), 503, 903, 0x1234_1111_0001, .graphics_adapter),
        .bundle = bundle,
    });

    var runtime = driver_runtime_mod.Runtime.init();
    const network_activation = try runtime.activate(network_driver);
    const storage_activation = try runtime.activate(storage_driver);
    const graphics_activation = try runtime.activate(graphics_driver);

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, network_activation.mode);
    try std.testing.expect(network_activation.exclusive_claim);
    try std.testing.expect(network_activation.kernel_bootstrap);
    try std.testing.expectEqualStrings("e1000", network_activation.publisherSlice());
    try std.testing.expectEqual(@as(usize, 1), FakeNetworkDevice.activation_count);
    try std.testing.expect(bootstrap_driver_port.hasActiveNetworkDevice());
    try std.testing.expectEqual(@as(u64, 91), bootstrap_driver_port.networkPublication().?.active_service_id);
    try std.testing.expect(!bootstrap_driver_port.activateNetworkDevice(network_device_id, 999));
    try std.testing.expect(runtime.deactivate(network_driver.service_id));
    try std.testing.expect(!bootstrap_driver_port.hasActiveNetworkDevice());
    try std.testing.expect(bootstrap_driver_port.activateNetworkDevice(network_device_id, 999));
    try std.testing.expect(bootstrap_driver_port.deactivateNetworkDevice(999));

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, storage_activation.mode);
    try std.testing.expect(storage_activation.exclusive_claim);
    try std.testing.expect(storage_activation.kernel_bootstrap);
    try std.testing.expectEqualStrings("ata-bootstrap", storage_activation.publisherSlice());
    try std.testing.expectEqual(@as(usize, 1), FakeBackend.activation_count);
    try std.testing.expect(storage_volume.hasAttachedDevice());
    try std.testing.expectEqual(@as(u64, 92), bootstrap_driver_port.storagePublication().?.active_service_id);

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.control_only, graphics_activation.mode);
    try std.testing.expectEqualStrings("e1000", runtime.findByClass(.network_adapter).?.publisherSlice());
    try std.testing.expectEqualStrings("ata-bootstrap", runtime.findByClass(.storage_controller).?.publisherSlice());
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.control_only, runtime.findByClass(.graphics_adapter).?.mode);
}

pub fn storageStaysVersionedRecoverableSignedAndDerived() !void {
    storage_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();

    const storage_owner = spec_support.service(20);
    const writer = spec_support.user(2);
    const storage_signer = spec_support.signer("spec.storage", 0x31);

    var storage = storage_service.Service.init(500, 50, storage_owner);
    const draft_v1 = try storage.putVersion(.{
        .preferred_object_id = 1_000,
        .object_type = .document,
        .payload = "report-v1",
        .metadata = try object_store.signMetadata(storage_signer, "report", "text/markdown", .document, "report-v1", 1),
    });
    const draft_v2 = try storage.putVersion(.{
        .preferred_object_id = 1_000,
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
    try std.testing.expectEqual(@as(usize, 1), storage.store.objectCount());
    try std.testing.expectEqual(@as(usize, 2), storage.store.versionCount());

    const exported = try storage.exportSnapshot(workspace_record.id, baseline.id, storage_signer);
    const imported = try storage.importWorkspace(spec_support.user(3), "report-import", exported, 7);
    const imported_entry = try storage.resolve(imported.id, "documents/report.md");
    try std.testing.expectEqual(draft_v1.version_id, imported_entry.version_id);

    const workspace_capability = capability.Capability{
        .id = 1,
        .holder = writer,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .workspace, .id = workspace_record.id },
        .rights = .{
            .object_read = true,
            .object_write = true,
        },
        .scope = .{
            .task_id = 88,
            .workspace_id = workspace_record.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .revocation_generation = 1,
        .audit = .{},
    };
    const view = try storage.bridgeResolve(.{
        .workspace_id = workspace_record.id,
        .path = "/documents/report.md",
        .access = .read,
    }, workspace_capability, 8);
    try std.testing.expect(!view.authoritative);
    try std.testing.expect(view.readable);
    try std.testing.expect(view.writable);
    try std.testing.expectEqualStrings("documents/report.md", view.pathSlice());
    try std.testing.expectEqual(draft_v2.version_id, view.version_id);
}

pub fn trustedDeviceGraphSelectiveSyncAndPolicyNetworking() !void {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

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

    var storage = storage_service.Service.init(600, 60, storage_owner);
    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = 1_100,
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v1", 1),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = 1_100,
        .object_type = .document,
        .payload = "notes-v2",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v2", 2),
        .parent_version_id = notes_v1.version_id,
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = 1_101,
        .object_type = .media_asset,
        .payload = "cover.jpg",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "cover.jpg", 3),
    });
    const inbox = try storage.putVersion(.{
        .preferred_object_id = 1_102,
        .object_type = .collection,
        .payload = "inbox",
        .metadata = try object_store.signMetadata(storage_signer, "inbox", "application/zigos-collection", .collection, "inbox", 4),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = 1_103,
        .object_type = .secret,
        .payload = "enc:top-secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:top-secret", 5),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "shared-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes_v1.object_id, notes_v1.version_id, .document);
    try storage.stagePut(workspace_record.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    try storage.stagePut(workspace_record.id, "collections/inbox", inbox.object_id, inbox.version_id, .collection);
    _ = try storage.commit(workspace_record.id, 6);

    var sync = sync_service.Service.init(601, 61, sync_owner);
    _ = try sync.ensureUserRoot(person, "owner", user_signer);
    _ = try sync.enrollTrustedDevice(person, laptop, "laptop", user_signer, laptop_signer, 10);
    _ = try sync.enrollTrustedDevice(person, tablet, "tablet", user_signer, tablet_signer, 11);

    const local_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "local",
        .mode = .local_network,
    });
    const discovery_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const relay_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.spec.zigos",
    });
    const overlay_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.spec",
    });
    const inbound_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "document-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    });
    const collaborator = spec_support.app(63);
    const prefixes = [_][]const u8{ "documents/", "assets/" };
    _ = try sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_record.id,
        .owner = person,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &prefixes,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.spec.zigos",
    });
    _ = try sync.configureOverlay(workspace_record.id, laptop, "overlay.notes.spec", true);
    _ = try sync.publishPrivateService(workspace_record.id, "notes.remote");
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
    const share = storage.workspaces.findShareGrant(workspace_record.id, collaborator).?;
    try std.testing.expectEqual(workspace.ShareNetworkScope.trusted_overlay, share.network_scope);
    try std.testing.expectEqual(workspace.ResharePolicy.admin_only, share.reshare_policy);
    try std.testing.expectEqual(workspace.AuditVisibility.shared_participants, share.audit_visibility);
    try std.testing.expect(storage.workspaces.hasAccess(workspace_record.id, .{
        .principal_id = collaborator,
        .wants_write = true,
        .wants_export = true,
        .wants_admin = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 20,
    }));
    try std.testing.expect(storage.workspaces.canReshare(workspace_record.id, collaborator, .trusted_overlay, 20));
    try std.testing.expect(!storage.workspaces.hasAccess(workspace_record.id, .{
        .principal_id = collaborator,
        .network_scope = .relay_assisted,
        .now_ticks = 50,
    }));

    try sync.setReplicaVersion(workspace_record.id, tablet, "documents/notes.md", notes_v1.object_id, notes_v2.version_id);
    const summary = try sync.replicateWorkspace(&storage, workspace_record.id, laptop, tablet, .device_to_device);
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
    try std.testing.expect(sync.findConflict(workspace_record.id, tablet, "documents/notes.md") != null);
    try std.testing.expect(sync.isTrustedDevice(laptop));
    try std.testing.expect(sync.isTrustedDevice(tablet));
    try std.testing.expect(try sync.transferSecretObject(storage.store, workspace_record.id, secret.object_id, laptop, tablet, .device_to_device));

    const database_contract = try sync.registerDatabaseContract(workspace_record.id, "app.notes.db", "notes-db", contract_signer);
    try std.testing.expect(try sync.replicateDatabaseContract(database_contract.id, workspace_record.id, laptop, tablet, .relay_assisted));
    try std.testing.expect((try sync.evaluateNetworkPolicy(local_policy.id, .local_network)).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(discovery_policy.id, .{ .discovery_class = "printer" })).allowed);
    try std.testing.expect(!(try sync.evaluateNetworkPolicy(discovery_policy.id, .{ .discovery_class = "camera" })).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(relay_policy.id, .{ .domain = "relay.spec.zigos" })).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(overlay_policy.id, .{ .service_identity = "overlay.notes.spec" })).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(inbound_policy.id, .{ .inbound_session_type = "document-review/v1" })).allowed);
    try std.testing.expect(!(try sync.evaluateNetworkPolicy(inbound_policy.id, .{ .inbound_session_type = "pair-screen/v1" })).allowed);
}
