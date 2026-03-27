const std = @import("std");
const abi = @import("kernel/process/native/abi.zig");
const accelerator_scheduler = @import("kernel/process/native/accelerator_scheduler.zig");
const attestation_service = @import("kernel/process/native/attestation_service.zig");
const capability = @import("kernel/process/native/capability.zig");
const contract = @import("kernel/process/native/contract.zig");
const driver_service = @import("kernel/process/native/driver_service.zig");
const event_ledger = @import("kernel/process/native/event_ledger.zig");
const file_bridge = @import("kernel/process/native/file_bridge.zig");
const immutable_base = @import("kernel/process/native/immutable_base.zig");
const indexing_service = @import("kernel/process/native/indexing_service.zig");
const manifest = @import("kernel/process/native/manifest.zig");
const media_print_service = @import("kernel/process/native/media_print_service.zig");
const measured_boot = @import("kernel/process/native/measured_boot.zig");
const native_ux = @import("kernel/process/native/native_ux.zig");
const network_policy = @import("kernel/process/native/network_policy.zig");
const notification_center = @import("kernel/process/native/notification_center.zig");
const object_store = @import("kernel/process/native/object_store.zig");
const package_service = @import("kernel/process/native/package_service.zig");
const policy_mediation = @import("kernel/process/native/policy_mediation.zig");
const policy_object = @import("kernel/process/native/policy_object.zig");
const principal = @import("kernel/process/native/principal.zig");
const recovery_environment = @import("kernel/process/native/recovery_environment.zig");
const secure_secret_store = @import("kernel/process/native/secure_secret_store.zig");
const service_registry = @import("kernel/process/native/service_registry.zig");
const signing = @import("kernel/process/native/signing.zig");
const storage_service = @import("kernel/process/native/storage_service.zig");
const sync_service = @import("kernel/process/native/sync_service.zig");
const task_runtime = @import("kernel/process/native/task_runtime.zig");

fn signer(label: []const u8, fill: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = [_]u8{fill} ** 32,
    };
}

fn user(serial: u64) principal.PrincipalId {
    return .{ .kind = .user, .serial = serial };
}

fn device(serial: u64) principal.PrincipalId {
    return .{ .kind = .device, .serial = serial };
}

fn app(serial: u64) principal.PrincipalId {
    return .{ .kind = .app, .serial = serial };
}

fn service(serial: u64) principal.PrincipalId {
    return .{ .kind = .service, .serial = serial };
}

fn policyAuthority(serial: u64) principal.PrincipalId {
    return .{ .kind = .policy_authority, .serial = serial };
}

fn defaultBudget(background_allowed: bool) task_runtime.ResourceBudget {
    return .{
        .cpu_time_ticks = 10_000,
        .memory_bytes = 256 * 1024,
        .endpoint_slots = 8,
        .shared_memory_bytes = 16 * 1024,
        .background_allowed = background_allowed,
    };
}

test "spec 2.1 6.2 and 7 explicit grants are required before a task gains authority" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    var mediator = policy_mediation.PolicyMediator.init(
        policyAuthority(1),
        &capability_table,
        &runtime,
        .{
            .network_service_id = 41,
            .compositor_service_id = 42,
            .policy_service_id = 43,
            .service_registry_id = 44,
        },
    );

    const bundle_requests = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://report-alpha/documents/report.md",
            .rights = .{
                .object_read = true,
                .object_write = true,
            },
            .target_id = 9_001,
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{
                .network_local = true,
            },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 50,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.report.writer",
        .display_name = "Report Writer",
        .publisher = "zigos.spec",
        .requested_permissions = &bundle_requests,
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-spec-bundle",
        },
    };

    const denied_task = try runtime.createTask(.{
        .owner = app(1),
        .component_class = .app_component,
        .budget = defaultBudget(false),
        .local_only = true,
    });
    try std.testing.expect(denied_task.zero_ambient_authority);
    try std.testing.expectEqual(@as(usize, 0), denied_task.capability_count);

    const denied = try mediator.applyManifest(denied_task.id, bundle, &.{}, 10);
    try std.testing.expectEqual(@as(usize, 0), denied.granted_count);
    try std.testing.expectEqual(@as(usize, 2), denied.denied_count);
    try std.testing.expectEqual(@as(usize, 1), denied.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.suspended, denied_task.state);
    try std.testing.expectEqual(@as(usize, 0), denied_task.capability_count);

    const grants = [_]policy_mediation.UserGrant{
        .{
            .kind = .object_access,
            .resource = "workspace://report-alpha/documents/report.md",
            .allow = true,
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .allow = true,
            .local_only = true,
            .expires_at_ticks = 70,
        },
    };
    const granted_task = try runtime.createTask(.{
        .owner = app(2),
        .component_class = .app_component,
        .budget = defaultBudget(false),
        .local_only = true,
    });
    try std.testing.expect(granted_task.zero_ambient_authority);
    try std.testing.expectEqual(@as(usize, 0), granted_task.capability_count);

    const granted = try mediator.applyManifest(granted_task.id, bundle, &grants, 20);
    try std.testing.expectEqual(@as(usize, 2), granted.granted_count);
    try std.testing.expectEqual(@as(usize, 0), granted.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.active, granted_task.state);
    try std.testing.expectEqual(@as(usize, 2), granted_task.capability_count);

    const network_decision = granted.decisionForKind(.network_egress).?;
    try std.testing.expect(network_decision.allowed);
    try std.testing.expect(network_decision.local_only);
    try std.testing.expectEqual(@as(u64, 70), network_decision.expires_at_ticks);

    const network_capability = capability_table.query(network_decision.capability_id.?).?;
    try std.testing.expectEqual(granted_task.id, network_capability.scope.task_id.?);
    try std.testing.expect(network_capability.scope.local_only);
    try std.testing.expect(network_capability.scope.broker_only);
    try std.testing.expect(network_capability.rights.network_local);
    try std.testing.expect(!network_capability.rights.network_remote);
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, network_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 41), network_capability.target.id);
}

test "spec 4 6.3 13 and 17 keep the kernel typed minimal and free of legacy ambient authority" {
    try std.testing.expectEqual(@as(usize, 7), contract.kernel_tcb.len);
    try std.testing.expectEqualStrings("ipc_transport", contract.tcbName(.ipc_transport));
    try std.testing.expectEqualStrings("iommu_dma_isolation_hooks", contract.tcbName(.iommu_dma_isolation_hooks));

    const network = contract.serviceDescriptor(.network_stack).?;
    const storage = contract.serviceDescriptor(.storage_object).?;
    const compositor = contract.serviceDescriptor(.compositor_ui_session).?;
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, network.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, storage.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, compositor.boundary);
    try std.testing.expect(network.restartable);
    try std.testing.expect(storage.restartable);
    try std.testing.expect(compositor.restartable);

    try std.testing.expect(abi.opcode(.task_create) >= 0x100);
    try std.testing.expect(abi.policyOpcode(.authorize_request) >= 0x200);
    try std.testing.expect(abi.reviewOpcode(.review_bundle) >= 0x240);
    try std.testing.expectEqual(@as(u16, 1), abi.ABI_VERSION);

    var registry = service_registry.Registry.init();
    try registry.register(55, 7, 101, .{
        .name = "zigos.service.storage",
        .version_major = 1,
        .version_minor = 2,
    });
    const connection = try registry.connect(.{
        .name = "zigos.service.storage",
        .version_major = 1,
        .version_minor = 1,
    });
    try std.testing.expectEqual(@as(u64, 55), connection.service_id);
    try std.testing.expectEqual(@as(u64, 101), connection.endpoint_id);
    try std.testing.expect(connection.interface_hash != 0);
    try std.testing.expectError(service_registry.Error.VersionMismatch, registry.connect(.{
        .name = "zigos.service.storage",
        .version_major = 2,
        .version_minor = 0,
    }));

    const network_rights = driver_service.allowedRightsFor(.network_adapter);
    const audio_rights = driver_service.allowedRightsFor(.audio_print_io);
    try std.testing.expect(network_rights.device_use);
    try std.testing.expect(network_rights.network_local);
    try std.testing.expect(!network_rights.network_remote);
    try std.testing.expect(audio_rights.device_use);
    try std.testing.expect(!audio_rights.network_local);
    try std.testing.expect(!audio_rights.object_write);
}

test "spec 8 storage stays versioned recoverable signed and exposed through a derived file bridge" {
    storage_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();

    const storage_owner = service(20);
    const writer = user(2);
    const storage_signer = signer("spec.storage", 0x31);

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
    const imported = try storage.importWorkspace(user(3), "report-import", exported, 7);
    const imported_entry = try storage.resolve(imported.id, "documents/report.md");
    try std.testing.expectEqual(draft_v1.version_id, imported_entry.version_id);

    const workspace_capability = capability.Capability{
        .id = 1,
        .holder = writer,
        .issuer = policyAuthority(1),
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

test "spec 9 and 10 use a trusted device graph selective sync and policy-gated networking" {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

    const storage_owner = service(30);
    const sync_owner = service(31);
    const person = user(4);
    const laptop = device(41);
    const tablet = device(42);
    const storage_signer = signer("spec.sync.storage", 0x41);
    const user_signer = signer("spec.sync.user", 0x42);
    const laptop_signer = signer("spec.sync.laptop", 0x43);
    const tablet_signer = signer("spec.sync.tablet", 0x44);
    const contract_signer = signer("spec.sync.contract", 0x45);

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
    try std.testing.expect((try sync.evaluateNetworkPolicy(relay_policy.id, .{ .domain = "relay.spec.zigos" })).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(overlay_policy.id, .{ .service_identity = "overlay.notes.spec" })).allowed);
}

test "spec 5 and 14 keep the base image signed measured atomic and rollback-capable" {
    storage_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();

    const owner = service(40);
    const state_signer = signer("spec.base.state", 0x51);
    const image_signer = signer("spec.base.image", 0x52);

    var storage = storage_service.Service.init(700, 70, owner);
    var manager = try immutable_base.Manager.init(&storage, owner, state_signer);

    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    const first_activation = try manager.activate(0, .{}, 11);
    try std.testing.expectEqual(@as(?usize, 0), first_activation.active_slot);
    try std.testing.expect(!first_activation.rolled_back);
    try std.testing.expect(manager.verifyActiveImage());

    _ = try manager.stageImage(1, "stable-b", "kernel=v2", image_signer, 12);
    const rollback = try manager.activate(1, .{
        .network_ok = false,
    }, 13);
    try std.testing.expect(rollback.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.network, rollback.failure);
    try std.testing.expectEqual(@as(?usize, 0), rollback.active_slot);
    try std.testing.expectEqual(@as(u64, 1), rollback.rollback_generation);

    const active = manager.activeImage().?;
    try std.testing.expectEqualStrings("stable-a", active.labelSlice());
    try std.testing.expect(manager.verifySlot(0));
    try std.testing.expect(manager.verifySlot(1));

    var recorder = measured_boot.Recorder.init();
    recorder.begin(rollback.activation_generation);
    try recorder.add(.kernel, "kernel-zigos-native", "kernel=v1");
    try recorder.add(.base_image, active.labelSlice(), active.measurement[0..]);
    try recorder.add(.critical_service, "storage", "healthy");
    try recorder.add(.policy, "network-egress", "explicit-grants");
    try recorder.add(.driver_set, "signed-drivers", "network+storage+graphics");
    const boot = recorder.finalize();

    try std.testing.expectEqual(rollback.activation_generation, boot.generation);
    try std.testing.expectEqual(@as(usize, 5), boot.record_count);
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.kernel));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.base_image));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.critical_service));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.policy));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.driver_set));
    try std.testing.expect(!std.mem.allEqual(u8, &boot.root_digest, 0));
}

test "spec 5.3 recovery mode can reinstall restore repair rotate and revoke" {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

    const storage_owner = service(50);
    const sync_owner = service(51);
    const person = user(5);
    const primary = device(51);
    const tablet = device(52);
    const state_signer = signer("spec.recovery.state", 0x61);
    const image_signer = signer("spec.recovery.image", 0x62);
    const object_signer = signer("spec.recovery.object", 0x63);
    const user_signer = signer("spec.recovery.user", 0x64);
    const primary_signer = signer("spec.recovery.primary", 0x65);
    const tablet_signer = signer("spec.recovery.tablet", 0x66);
    const rotated_tablet_signer = signer("spec.recovery.tablet.v2", 0x67);

    var storage = storage_service.Service.init(800, 80, storage_owner);
    var manager = try immutable_base.Manager.init(&storage, storage_owner, state_signer);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    _ = try manager.activate(0, .{}, 11);

    const notes = try storage.putVersion(.{
        .preferred_object_id = 1_200,
        .object_type = .document,
        .payload = "incident-v1",
        .metadata = try object_store.signMetadata(object_signer, "incident", "text/plain", .document, "incident-v1", 12),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "incident",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/incident.md", notes.object_id, notes.version_id, .document);
    _ = try storage.commit(workspace_record.id, 13);
    const snapshot = try storage.snapshot(workspace_record.id, "clean", object_signer);

    var sync = sync_service.Service.init(801, 81, sync_owner);
    _ = try sync.ensureUserRoot(person, "owner", user_signer);
    _ = try sync.enrollTrustedDevice(person, primary, "primary", user_signer, primary_signer, 14);
    _ = try sync.enrollTrustedDevice(person, tablet, "tablet", user_signer, tablet_signer, 15);

    const local_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "local",
        .mode = .local_network,
    });
    _ = try sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_record.id,
        .owner = person,
        .device_to_device_policy_id = local_policy.id,
    });
    try sync.setReplicaVersion(workspace_record.id, tablet, "documents/incident.md", notes.object_id, notes.version_id + 1);
    _ = try sync.replicateWorkspace(&storage, workspace_record.id, primary, tablet, .device_to_device);

    var recovery = recovery_environment.Environment.init(storage_owner);
    try std.testing.expect(try recovery.verifyAndReinstallImage(&manager, "kernel=v2", image_signer, 16));
    try std.testing.expect(try recovery.restoreWorkspaceSnapshot(&storage, workspace_record.id, snapshot.id, 17));
    try std.testing.expect(try recovery.repairSyncMetadata(&sync, &storage, workspace_record.id, tablet));
    try std.testing.expectEqual(@as(u32, 2), try recovery.rotateDeviceKeys(&sync, person, tablet, user_signer, rotated_tablet_signer, 18));
    try std.testing.expect(try recovery.revokeDeviceTrust(&sync, person, tablet, user_signer, 19));

    try std.testing.expect(recovery.report.image_verified);
    try std.testing.expect(recovery.report.image_reinstalled);
    try std.testing.expect(recovery.report.snapshot_restored);
    try std.testing.expect(recovery.report.sync_metadata_repaired);
    try std.testing.expect(recovery.report.device_keys_rotated);
    try std.testing.expect(recovery.report.device_trust_revoked);
    try std.testing.expect(!sync.isTrustedDevice(tablet));
}

test "spec 11 task-first UX records structured task workspace permission and pairing flows" {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

    const storage_owner = service(60);
    const sync_owner = service(61);
    const person = user(6);
    const paired_device = device(61);
    const object_signer = signer("spec.ux.object", 0x71);
    const user_signer = signer("spec.ux.user", 0x72);
    const device_signer = signer("spec.ux.device", 0x73);

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.init(900, 90, storage_owner);
    const document = try storage.putVersion(.{
        .preferred_object_id = 1_300,
        .object_type = .document,
        .payload = "trip-plan",
        .metadata = try object_store.signMetadata(object_signer, "trip", "text/plain", .document, "trip-plan", 10),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "trip",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/plan.md", document.object_id, document.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);

    var sync = sync_service.Service.init(901, 91, sync_owner);
    _ = try sync.ensureUserRoot(person, "owner", user_signer);

    var controller = native_ux.Controller.init();
    const task = try controller.startTask(&runtime, .{
        .owner = person,
        .component_class = .app_component,
        .budget = defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "trip-planner",
            .entry = "app.trip",
        },
    });
    const opened = try controller.openWorkspace(&storage, workspace_record.id, "documents/plan.md", person);
    try controller.pairDevice(&sync, person, paired_device, "tablet", user_signer, device_signer, 12);
    try std.testing.expect(try controller.reviewPermissionRequest(task.id, person, .object_access, true));
    try controller.recoverSystem(task.id, person, "recovery-environment");

    try std.testing.expectEqual(@as(usize, 5), controller.flow_count);
    try std.testing.expectEqual(native_ux.FlowKind.start_task, controller.flows[0].kind);
    try std.testing.expectEqual(task.id, controller.flows[0].task_id);
    try std.testing.expectEqual(native_ux.FlowKind.open_workspace, controller.flows[1].kind);
    try std.testing.expectEqual(workspace_record.id, controller.flows[1].workspace_id);
    try std.testing.expectEqualStrings("documents/plan.md", controller.flows[1].detailSlice());
    try std.testing.expectEqual(document.version_id, opened.version_id);
    try std.testing.expectEqual(native_ux.FlowKind.pair_device, controller.flows[2].kind);
    try std.testing.expect(sync.isTrustedDevice(paired_device));
    try std.testing.expect(controller.flows[3].approved);
    try std.testing.expectEqual(native_ux.FlowKind.recover_system, controller.flows[4].kind);
    try std.testing.expectEqualStrings("recovery-environment", controller.flows[4].detailSlice());
}

test "spec 6.1 14.3 and 16 keep package lifecycle declarative signed and policy scoped" {
    var policies = policy_object.Directory.init();
    const org_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 1,
        .issuer = policyAuthority(7),
        .label = "org-defaults",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.corp.example"},
        .removable_storage_allowed = false,
        .screen_capture_allowed = false,
        .retention_days = 180,
        .audit_export_required = true,
    }, signer("spec.policy.org", 0x81));

    var packages = package_service.Service.init();
    const bundle_signer = signer("spec.bundle.notes", 0x82);

    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 0,
        .requested_permissions = &v1_permissions,
    };
    v1.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v1));

    const first = try packages.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, org_policy);
    try std.testing.expect(first.installed_new);
    try std.testing.expect(!first.rollback_available);
    try std.testing.expect(policies.installSourceAllowed(.organization, 1, "store:zigos"));
    try std.testing.expect(!policies.installSourceAllowed(.organization, 1, "repo:personal"));
    try std.testing.expect(policies.syncDestinationAllowed(.organization, 1, "relay.corp.example"));

    const v2_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
        .{
            .kind = .notification_post,
            .resource = "notifications://task",
            .rights = .{ .notification_post = true },
            .required = false,
        },
    };
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .requested_permissions = &v2_permissions,
    };
    v2.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v2));

    const updated = try packages.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .migration_manifest = "notes-v2-migration",
        .declared_permission_change = true,
    }, org_policy);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(updated.rollback_available);

    const installed = packages.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), installed.current_version_major);
    try std.testing.expectEqual(@as(u16, 1), installed.current_version_minor);
    try std.testing.expectEqual(@as(u32, 2), installed.current_schema_version);
    try std.testing.expect(!org_policy.removable_storage_allowed);
    try std.testing.expect(!org_policy.screen_capture_allowed);
    try std.testing.expect(org_policy.audit_export_required);

    _ = try packages.rollback("app.notes");
    try std.testing.expectEqual(@as(u16, 0), packages.find("app.notes").?.current_version_minor);
}

test "spec 2.3 11.4 12 and 15 keep indexing notifications media helpers and diagnostics structured" {
    var index = indexing_service.Service.init();
    try index.upsert(11, 500, 1, "Trip Draft", "alpha itinerary and booking checklist");
    try index.upsert(12, 600, 1, "Payroll", "alpha restricted finance details");

    var results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    const permitted = [_]u64{11};
    const results = index.query(&permitted, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(@as(u64, 500), results[0].object_id);

    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var media = media_print_service.Service.init();
    const source = app(70);

    const export_job = try media.submit(.{
        .kind = .media_export,
        .task_id = 501,
        .workspace_id = 11,
        .source_principal = source,
        .label = "render reel",
        .visibility = .task,
    }, &scheduler, &notifications, 20);
    const print_job = try media.submit(.{
        .kind = .print_document,
        .task_id = 502,
        .workspace_id = 11,
        .source_principal = source,
        .label = "print itinerary",
        .printer_identity = "printer://lobby",
        .visibility = .user,
    }, &scheduler, &notifications, 21);
    _ = try media.complete(export_job.id, &notifications, 30);
    _ = try media.complete(print_job.id, &notifications, 31);

    try std.testing.expectEqual(accelerator_scheduler.Engine.media, export_job.engine);
    try std.testing.expectEqual(media_print_service.JobState.completed, print_job.state);
    try std.testing.expectEqual(notification_center.Reason.print_complete, notifications.latestVisible(31).?.reason);

    var ledger = event_ledger.Ledger.init();
    try ledger.recordDriverRestart(contract.ServiceClass.media_print_helpers, service(71), 9, 32, "printer helper restart");
    try ledger.recordSyncConflict(user(8), 11, 33, "documents/itinerary.md conflict", true);
    var export_buffer: [1024]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "media_print_helpers") != null);
}

test "spec 5.2 7.5 and 12 keep attestation secrets and accelerator policy explicit" {
    var recorder = measured_boot.Recorder.init();
    recorder.begin(21);
    try recorder.add(.kernel, "kernel-zigos", "kernel=v3");
    try recorder.add(.base_image, "stable-b", "image=v3");
    try recorder.add(.critical_service, "storage", "healthy");
    try recorder.add(.policy, "org-defaults", "strict");
    try recorder.add(.driver_set, "signed-drivers", "gpu+npu+net");
    const boot = recorder.finalize();

    var attestation = attestation_service.Service.init(device(99));
    const statement = try attestation.attest(boot, "attest.example", "nonce-7", signer("spec.attest.device", 0x91), true);
    try std.testing.expect(attestation_service.Service.verify(statement));
    try std.testing.expect(statement.user_visible);
    try std.testing.expectEqual(@as(usize, 1), attestation.visible_request_count);
    try std.testing.expect(!std.mem.allEqual(u8, &statement.root_digest, 0));

    var secrets = secure_secret_store.Store.init();
    const imported = try secrets.importSecret(user(9), "signing-key", "opaque-secret", true, false);
    const handle = try secrets.lendHandle(imported.id, app(90), 700, true);
    try std.testing.expect(handle.hardware_backed);
    try std.testing.expectError(secure_secret_store.Error.RawExportDenied, secrets.exportRaw(handle.id));

    var scheduler = accelerator_scheduler.Controller.init();
    scheduler.configure(.{
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });
    const inference = scheduler.plan(.{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    });
    const media_export_plan = scheduler.plan(.{
        .class = .media_export,
        .wants_gpu = true,
        .wants_media_engine = true,
        .shared_memory_bytes = 4096,
    });
    try std.testing.expectEqual(accelerator_scheduler.Engine.cpu, inference.engine);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.privacy_mode, inference.reason);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, media_export_plan.engine);
    try std.testing.expect(media_export_plan.zero_copy_allowed);
}
