const std = @import("std");
const spec_support = @import("support.zig");
const accelerator_scheduler = @import("../../native/task/accelerator_scheduler.zig");
const attestation_service = @import("../../native/platform/attestation_service.zig");
const contract = @import("../../native/session/contract.zig");
const denial_explanation = @import("../../native/policy/denial_explanation.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const device_graph = @import("../../native/sync/device_graph.zig");
const ids = @import("../../native/core/ids.zig");
const manifest = @import("../../native/policy/manifest.zig");
const measured_boot = @import("../../native/platform/measured_boot.zig");
const native_ux = @import("../../native/platform/native_ux.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const notification_center = @import("../../native/services/notification_center.zig");
const os_identity = @import("../../native/platform/os_identity.zig");
const secure_secret_store = @import("../../native/platform/secure_secret_store.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const supervisor = @import("../../native/session/supervisor.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const units = @import("../../native/core/units.zig");

const DENIAL_EXPLANATION_BUFFER_BYTES: usize = 256;
const LEDGER_EXPORT_BUFFER_BYTES: usize = units.kibibytes(1);

pub fn attestationSecretsAndAcceleratorPolicyStayExplicit() !void {
    var recorder = measured_boot.Recorder.init();
    var artifact_manifest = measured_boot.ArtifactManifest.init(21);
    recorder.begin(21);
    try artifact_manifest.add(.kernel, "kernel-zigos", "kernel=v3");
    try recorder.add(.kernel, "kernel-zigos", "kernel=v3");
    try artifact_manifest.add(.base_image, "stable-b", "image=v3");
    try recorder.add(.base_image, "stable-b", "image=v3");
    try artifact_manifest.add(.critical_service, "policy", "healthy");
    try recorder.add(.critical_service, "policy", "healthy");
    try artifact_manifest.add(.critical_service, "storage", "healthy");
    try recorder.add(.critical_service, "storage", "healthy");
    try artifact_manifest.add(.critical_service, "compositor", "healthy");
    try recorder.add(.critical_service, "compositor", "healthy");
    try artifact_manifest.add(.critical_service, "network", "healthy");
    try recorder.add(.critical_service, "network", "healthy");
    try artifact_manifest.add(.policy, "org-defaults", "strict");
    try recorder.add(.policy, "org-defaults", "strict");
    try artifact_manifest.add(.driver_set, "signed-drivers", "gpu+npu+net");
    try recorder.add(.driver_set, "signed-drivers", "gpu+npu+net");
    var boot = recorder.finalize();
    try measured_boot.verifyBootRecordAgainstManifest(&boot, &artifact_manifest, .bootloader_provided);

    var checkpoint_store = storage_service.CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const measurement_owner = spec_support.service(99);
    const measurement_signer = spec_support.signer("spec.measured.state", 0x90);
    var measurement_storage = storage_service.Service.initWithStore(990, 99, measurement_owner, &checkpoint_store);
    var journal = try measured_boot.MeasurementJournal.init(&measurement_storage, measurement_owner, measurement_signer);
    const first_measurement = try journal.record(boot, 5);
    try std.testing.expect(first_measurement.previous == null);
    try std.testing.expect(journal.latestMatches(&boot));

    var restarted_measurement_storage = storage_service.Service.initWithStore(990, 100, measurement_owner, &checkpoint_store);
    var restarted_journal = try measured_boot.MeasurementJournal.init(&restarted_measurement_storage, measurement_owner, measurement_signer);
    try std.testing.expect(restarted_journal.loaded_existing_state);
    try std.testing.expect(restarted_journal.hasPreviousMeasurement());
    try std.testing.expect(restarted_journal.latestMatches(&boot));

    var attestation = attestation_service.Service.init(spec_support.device(99));
    var attestation_root = attestation_service.FakeSecureEnclaveRootProvider.init(spec_support.signer("spec.attest.device", 0x91));
    try attestation.provisionRootProvider(attestation_root.provider());
    const statement = try attestation.attestWithProvisionedRoot(boot, "attest.example", "remote-nonce-0007", true);
    try std.testing.expect(attestation_service.Service.verify(statement));
    try std.testing.expect(statement.user_visible);
    try std.testing.expectEqual(@as(usize, 1), attestation.visible_request_count);
    try std.testing.expect(!std.mem.allEqual(u8, &statement.root_digest, 0));
    try std.testing.expectEqual(attestation_service.KeyOrigin.secure_enclave, statement.key_origin);

    var secrets = secure_secret_store.Store.init();
    const imported = try secrets.importSecret(spec_support.user(9), "signing-key", "opaque-secret", true, false);
    const handle = try secrets.lendHandle(imported.id, spec_support.app(90), 700, true);
    try std.testing.expect(handle.hardware_backed);
    try std.testing.expect(!imported.resident_material);
    try std.testing.expect(imported.sealed_digest_present);
    try std.testing.expectError(secure_secret_store.Error.RawExportDenied, secrets.exportRaw(handle.id));

    var graph = device_graph.Graph.init();
    const passkey_user = spec_support.user(19);
    const passkey_device = spec_support.device(190);
    const passkey_user_signer = spec_support.signer("spec.passkey.user", 0xA8);
    const passkey_device_signer = spec_support.signer("spec.passkey.device", 0xA9);
    const passkey_credential_signer = spec_support.signer("spec.passkey.credential", 0xAA);
    _ = try graph.ensureUserRoot(passkey_user, "passkey-owner", passkey_user_signer);
    _ = try graph.enrollDevice(passkey_user, passkey_device, "laptop", passkey_user_signer, passkey_device_signer, 6);
    var identities = os_identity.Store.init();
    const passkey = try identities.registerCredential(&graph, &secrets, .{
        .owner = passkey_user,
        .device = passkey_device,
        .relying_party_id = "zigos.dev",
        .label = "default-passkey",
        .scope = .synced,
        .credential_identity = passkey_credential_signer,
        .tick = 7,
    });
    const unlock = try os_identity.createLocalUnlockProof(passkey_user, passkey_device, "zigos.dev", "spec-nonce", .biometric, 8, 12, passkey_device_signer);
    const passkey_assertion = try identities.assertCredential(&graph, .{
        .credential_id = passkey.id,
        .device = passkey_device,
        .relying_party_id = "zigos.dev",
        .origin = "https://zigos.dev",
        .challenge = "spec-nonce",
        .local_unlock = unlock,
        .credential_identity = passkey_credential_signer,
        .tick = 9,
    });
    try std.testing.expect(passkey.isRecoverableThroughDeviceGraph());
    try std.testing.expect(passkey_assertion.local_unlock_verified);
    try std.testing.expect(passkey_assertion.phishing_resistant);
    try std.testing.expectError(error.PhishingOriginRejected, identities.assertCredential(&graph, .{
        .credential_id = passkey.id,
        .device = passkey_device,
        .relying_party_id = "zigos.dev",
        .origin = "https://zigos.dev.evil.test",
        .challenge = "spec-nonce",
        .local_unlock = unlock,
        .credential_identity = passkey_credential_signer,
        .tick = 10,
    }));

    var policy_directory = network_policy.Directory.init();
    const peer_policy = try policy_directory.create(.{
        .owner = spec_support.service(99),
        .label = "notes-overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = statement.root_digest,
    });
    try std.testing.expectEqual(network_policy.DecisionReason.attestation_required, (try policy_directory.authorizeConnection(peer_policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
    })).reason);
    const peer_decision = try policy_directory.authorizeConnection(peer_policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
        .attested = true,
        .peer_root_digest_present = true,
        .peer_root_digest = statement.root_digest,
    });
    try std.testing.expect(peer_decision.allowed);
    try std.testing.expect(peer_decision.identity_pinned);

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
        .shared_memory_bytes = shared_memory.PAGE_SIZE,
    });
    var runtime = task_runtime.Runtime.init();
    const foreground_task = try runtime.createTask(.{
        .owner = spec_support.app(91),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    var shared = shared_memory.Table.init();
    const zero_copy = try shared.createWithAccess(ids.task(foreground_task.id), shared_memory.PAGE_SIZE, .{
        .media = true,
    });
    const engine_claim = try scheduler.claimWithSharedMemory(.{
        .task_id = foreground_task.id,
        .request = .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
        },
        .require_accelerator = true,
        .shared_memory_object_id = zero_copy.id,
    }, &shared);
    const background_task = try runtime.createTask(.{
        .owner = spec_support.app(92),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(true),
        .local_only = true,
    });
    const critical_task = try runtime.createTask(.{
        .owner = spec_support.service(93),
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = units.kibibytes(128),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(4),
            .resource_class = .emergency_system_critical,
        },
        .local_only = true,
    });
    try std.testing.expectEqual(accelerator_scheduler.Engine.cpu, inference.engine);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.privacy_mode, inference.reason);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, media_export_plan.engine);
    try std.testing.expect(media_export_plan.zero_copy_allowed);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, engine_claim.engine);
    try std.testing.expect(engine_claim.zero_copy);
    try std.testing.expect(try shared.isAcceleratorAttached(zero_copy.id, .media));
    try std.testing.expect(try scheduler.releaseClaim(engine_claim.id, &shared));
    try std.testing.expect(!(try shared.isAcceleratorAttached(zero_copy.id, .media)));
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.foreground_interactive, foreground_task.resourceClass());
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.background_light, background_task.resourceClass());
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.emergency_system_critical, critical_task.resourceClass());
}

pub fn failuresStayExplainableRestartableAndRedacted() !void {
    const denied = denial_explanation.forPermissionDecision(.screen_capture, .policy_denied);
    var explanation_buffer: [DENIAL_EXPLANATION_BUFFER_BYTES]u8 = undefined;
    const rendered = try denial_explanation.renderToBuffer(&explanation_buffer, denied);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "policy=user-grant-policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "missing=screen-capture-capability") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "approval=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "retry_safe=no") != null);

    const FakeRuntime = struct {
        activation_count: usize = 0,
        last_service_id: u64 = 0,

        pub fn activate(self: *@This(), driver: *const driver_service.DriverRecord) !void {
            self.activation_count += 1;
            self.last_service_id = driver.service_id;
        }
    };

    var supervisor_instance = supervisor.Supervisor.init();
    const storage_record = try supervisor_instance.register(.storage_object, spec_support.service(140));
    try std.testing.expect(supervisor_instance.markHealthy(storage_record.id, 1));

    var directory = driver_service.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.storage-runtime",
        .display_name = "Storage Driver Runtime",
        .publisher = "zigos.spec",
        .signature = .{
            .format = manifest.SIGNATURE_FORMAT_ED25519,
            .signer = "zigos-spec-driver",
        },
    };
    const storage_authority = try spec_support.driverAuthority(
        &capabilities,
        storage_record.owner,
        1_401,
        0x0000_1F00_0002,
        .storage_controller,
    );
    const storage_driver = try directory.register(.{
        .service_id = storage_record.id,
        .owner_task_id = 1_401,
        .device_id = 0x0000_1F00_0002,
        .device_class = .storage_controller,
        .authority_capability_id = storage_authority.id,
        .capability_table = &capabilities,
        .requester = storage_authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
    });

    var runtime = FakeRuntime{};
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    try ledger.recordPermissionDecision(spec_support.user(12), 700, .screen_capture, false, .policy_denied, 19, "screen capture blocked", true);
    const recovery = try supervisor_instance.recoverDriverCrash(
        storage_record.id,
        &directory,
        &runtime,
        &notifications,
        &ledger,
        20,
        0xDEAD,
        "",
    );

    try std.testing.expect(!recovery.visible_impact);
    try std.testing.expectEqual(@as(?u64, null), recovery.notification_id);
    try std.testing.expectEqual(@as(usize, 1), runtime.activation_count);
    try std.testing.expectEqual(storage_record.id, runtime.last_service_id);
    try std.testing.expectEqual(supervisor.ServiceState.healthy, storage_record.state);
    try std.testing.expectEqual(@as(u16, 1), storage_record.restart_count);
    try std.testing.expectEqual(@as(u32, 2), storage_driver.restart_generation);
    try std.testing.expect(notifications.latestVisible(30) == null);

    var export_buffer: [LEDGER_EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "policy=user-grant-policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "blocked_help=\"Blocked: This app") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "service=storage_object") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "detail=storage driver restarted") != null);
    try std.testing.expectEqual(contract.ServiceClass.storage_object, ledger.latestKind(.process_crash).?.service_class);
    try std.testing.expectEqual(contract.ServiceClass.storage_object, ledger.latestKind(.driver_restart).?.service_class);

    var checkpoint_store = storage_service.CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();
    const ledger_owner = spec_support.service(141);
    const ledger_signer = spec_support.signer("spec.policy.ux.history", 0x94);
    var history_storage = storage_service.Service.initWithStore(991, 141, ledger_owner, &checkpoint_store);
    var durable_ledger = try event_ledger.Ledger.initPersistent(&history_storage, ledger_owner, ledger_signer);
    try durable_ledger.recordPermissionReview(spec_support.user(12), 700, .screen_capture, false, 21, "screen capture review denied", false);
    try durable_ledger.recordPermissionDecision(spec_support.user(12), 700, .screen_capture, false, .policy_denied, 22, "screen capture blocked", true);
    try durable_ledger.recordCapabilityGrant(spec_support.user(12), 700, 8801, .object_access, 23, "workspace grant");
    try durable_ledger.recordCapabilityRevocation(spec_support.user(12), 700, 8801, .object_access, 24, "workspace grant revoked");

    const notification = try notifications.post(.{
        .source = spec_support.app(12),
        .reason = .permission_request,
        .urgency = .high,
        .task_id = 700,
        .detail = "review needed",
    });
    try durable_ledger.recordNotification(notification.*, 25);

    var ux = native_ux.Controller.init();
    const flow = try ux.reviewPermissionDecision(
        700,
        spec_support.user(12),
        "app.capture",
        .{
            .kind = .screen_capture,
            .resource = "screen:main",
            .rights = .{ .service = .{} },
        },
        false,
        false,
        null,
    );
    try durable_ledger.recordTaskFlow(flow.*, 26);

    var restarted_storage = storage_service.Service.initWithStore(991, 142, ledger_owner, &checkpoint_store);
    var restarted_ledger = try event_ledger.Ledger.initPersistent(&restarted_storage, ledger_owner, ledger_signer);
    try std.testing.expect(restarted_ledger.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 1), restarted_ledger.countMatching(.{ .kind = .permission_review, .task_id = 700 }));
    try std.testing.expectEqual(@as(usize, 1), restarted_ledger.countMatching(.{ .kind = .permission_decision, .task_id = 700 }));
    try std.testing.expectEqual(@as(usize, 1), restarted_ledger.countMatching(.{ .kind = .capability_grant, .task_id = 700 }));
    try std.testing.expectEqual(@as(usize, 1), restarted_ledger.countMatching(.{ .kind = .capability_revocation, .task_id = 700 }));
    try std.testing.expectEqual(@as(usize, 1), restarted_ledger.countMatching(.{ .kind = .notification, .task_id = 700 }));
    try std.testing.expectEqual(@as(usize, 1), restarted_ledger.countMatching(.{ .kind = .task_flow, .task_id = 700 }));

    var history_buffer: [2]event_ledger.Event = undefined;
    const redacted = restarted_ledger.queryEvents(.{ .kind = .permission_decision, .task_id = 700 }, &history_buffer);
    try std.testing.expectEqualStrings("redacted", redacted[0].detailSlice());
    const protected = restarted_ledger.queryEvents(.{ .kind = .permission_decision, .task_id = 700, .include_protected_content = true }, &history_buffer);
    try std.testing.expectEqualStrings("screen capture blocked", protected[0].detailSlice());
}
