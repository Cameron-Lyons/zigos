const std = @import("std");
const spec_support = @import("support.zig");
const accelerator_scheduler = @import("../../native/task/accelerator_scheduler.zig");
const background_dispatch = @import("../../native/task/background_dispatch.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const contract = @import("../../native/session/contract.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const indexing_service = @import("../../native/services/indexing_service.zig");
const manifest = @import("../../native/policy/manifest.zig");
const media_print_service = @import("../../native/services/media_print_service.zig");
const native_ux = @import("../../native/platform/native_ux.zig");
const notification_center = @import("../../native/services/notification_center.zig");
const object_store = @import("../../native/storage/object_store.zig");
const package_service = @import("../../native/services/package_service.zig");
const policy_object = @import("../../native/policy/policy_object.zig");
const principal = @import("../../native/core/principal.zig");
const signing = @import("../../native/core/signing.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const sync_service = @import("../../native/sync/sync_service.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");

const package_migration = struct {
    var apply_count: usize = 0;

    fn reset() void {
        apply_count = 0;
    }

    fn apply(_: package_service.MigrationContext) anyerror!void {
        apply_count += 1;
    }
};

const PackageHarness = struct {
    port: package_service.PackagePort,
    authority: package_service.AuthorityContext,
};

fn packageHarness(
    packages: *package_service.Service,
    capability_table: *capability.CapabilityTable,
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
) !PackageHarness {
    packages.bind(service_id, owner);
    const authority_capability = try spec_support.serviceAuthority(capability_table, service_id, owner, task_id);
    return .{
        .port = package_service.PackagePort.init(packages, capability_table),
        .authority = spec_support.serviceAuthorityContext(task_id, owner, authority_capability, 10),
    };
}

pub fn taskFirstUxRecordsStructuredFlows() !void {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = spec_support.service(60);
    const sync_owner = spec_support.service(61);
    const person = spec_support.user(6);
    const paired_device = spec_support.device(61);
    const object_signer = spec_support.signer("spec.ux.object", 0x71);
    const user_signer = spec_support.signer("spec.ux.user", 0x72);
    const device_signer = spec_support.signer("spec.ux.device", 0x73);

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.initWithStore(900, 90, storage_owner, &storage_checkpoint_store);
    const document = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_300),
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
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try spec_support.serviceAuthority(&sync_capabilities, sync.service_id, sync_owner, sync.task_id);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = spec_support.serviceAuthorityContext(sync.task_id, sync_owner, sync_capability, 12);
    _ = try sync_port.ensureUserRoot(sync_authority, person, "owner", user_signer);

    var controller = native_ux.Controller.init();
    const task = try controller.startTask(&runtime, .{
        .owner = person,
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "trip-planner",
            .entry = "app.trip",
        },
    });
    const opened = try controller.openWorkspace(&storage, workspace_record.id, "documents/plan.md", person);
    try controller.pairDevice(&sync_port, sync_authority, person, paired_device, "tablet", user_signer, device_signer, 12);
    try std.testing.expect(try controller.reviewPermissionRequest(task.id, person, .object_access, true));
    try controller.recoverSystem(task.id, person, "recovery-environment");

    try std.testing.expectEqual(@as(usize, 5), controller.flow_count);
    try std.testing.expectEqual(native_ux.FlowKind.start_task, controller.flows[0].kind);
    try std.testing.expectEqual(task.id, controller.flows[0].task_id);
    try std.testing.expectEqual(native_ux.FlowKind.open_workspace, controller.flows[1].kind);
    try std.testing.expectEqual(workspace_record.id.raw(), controller.flows[1].workspace_id);
    try std.testing.expectEqualStrings("documents/plan.md", controller.flows[1].detailSlice());
    try std.testing.expectEqual(document.version_id, opened.version_id);
    try std.testing.expectEqual(native_ux.FlowKind.pair_device, controller.flows[2].kind);
    try std.testing.expect(sync.isTrustedDevice(paired_device));
    try std.testing.expect(controller.flows[3].approved);
    try std.testing.expectEqual(native_ux.FlowKind.recover_system, controller.flows[4].kind);
    try std.testing.expectEqualStrings("recovery-environment", controller.flows[4].detailSlice());
}

pub fn userJourneyKeepsInstallSyncPermissionUpdateAndRecoveryCohesive() !void {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = spec_support.service(62);
    const sync_owner = spec_support.service(63);
    const person = spec_support.user(16);
    const primary_device = spec_support.device(161);
    const paired_device = spec_support.device(162);
    const object_signer = spec_support.signer("spec.journey.object", 0x84);
    const user_signer = spec_support.signer("spec.journey.user", 0x85);
    const primary_signer = spec_support.signer("spec.journey.primary", 0x86);
    const paired_signer = spec_support.signer("spec.journey.paired", 0x87);
    const bundle_signer = spec_support.signer("spec.journey.bundle", 0x88);

    var policies = policy_object.Directory.init();
    const org_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 16,
        .issuer = spec_support.policyAuthority(16),
        .label = "journey-defaults",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{"store:zigos"},
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.zigos.example"},
        .audit_export_required = true,
    }, spec_support.signer("spec.journey.policy", 0x89));

    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "trip-ui", .entry = "app.trip.ui" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://trip/documents/plan.md",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 120,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .publisher = "Example Software",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &assets,
        .requested_permissions = &v1_permissions,
    };
    v1.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v1));

    var packages = package_service.Service.init();
    var package_capabilities = capability.CapabilityTable.init();
    var packages_entry = try packageHarness(&packages, &package_capabilities, 9_100, 9_101, spec_support.service(9_100));
    try spec_support.trustPackagePublisher(&packages_entry.port, packages_entry.authority, bundle_signer, "Example Software");
    const installed = try packages_entry.port.install(packages_entry.authority, .{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, org_policy);
    try std.testing.expect(installed.installed_new);

    var storage = storage_service.Service.initWithStore(910, 96, storage_owner, &storage_checkpoint_store);
    const document = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(1_360),
        .object_type = .document,
        .payload = "trip-plan-v1",
        .metadata = try object_store.signMetadata(object_signer, "trip-plan", "text/plain", .document, "trip-plan-v1", 10),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "trip",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/plan.md", document.object_id, document.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);

    var sync = sync_service.Service.init(911, 97, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try spec_support.serviceAuthority(&sync_capabilities, sync.service_id, sync_owner, sync.task_id);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = spec_support.serviceAuthorityContext(sync.task_id, sync_owner, sync_capability, 13);
    _ = try sync_port.ensureUserRoot(sync_authority, person, "owner", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, person, primary_device, "laptop", user_signer, primary_signer, 12);

    var runtime = task_runtime.Runtime.init();
    var controller = native_ux.Controller.init();
    const task = try controller.startTask(&runtime, .{
        .owner = person,
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "trip-planner",
            .entry = "app.trip.ui",
        },
        .launch = .{
            .signed = true,
            .bundle_id = "app.trip",
        },
    });
    try std.testing.expectEqualStrings("app.trip", task.launchBundleIdSlice());

    const opened = try controller.openWorkspace(&storage, workspace_record.id, "documents/plan.md", person);
    try std.testing.expectEqual(document.version_id, opened.version_id);
    try controller.pairDevice(&sync_port, sync_authority, person, paired_device, "tablet", user_signer, paired_signer, 13);

    const local_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "trip-local",
        .mode = .local_network,
    });
    const overlay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "trip-overlay",
        .mode = .named_service_identity,
        .target = "overlay.trip.sync",
    });
    const relay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "trip-relay",
        .mode = .named_domain,
        .target = "relay.zigos.example",
    });
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = person,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{"documents/"},
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.example",
    });
    _ = try sync_port.configureOverlay(sync_authority, workspace_record.id.raw(), primary_device, "overlay.trip.sync", true);

    const review = try controller.reviewPermissionDecision(
        task.id,
        person,
        "app.trip",
        v1_permissions[0],
        true,
        true,
        120,
    );
    var review_buffer: [512]u8 = undefined;
    const rendered_review = try native_ux.renderReviewFlowToBuffer(&review_buffer, review);
    try std.testing.expect(std.mem.indexOf(u8, rendered_review, "bundle=app.trip") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered_review, "decision=allow") != null);

    const summary = try sync_port.replicateWorkspace(
        sync_authority,
        &storage,
        workspace_record.id.raw(),
        primary_device,
        paired_device,
        .device_to_device,
    );
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_device_to_device);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expectEqual(@as(usize, 1), summary.selected_entry_count);

    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/theme.css", .content_type = "text/css" },
    };
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &v2_assets,
        .requested_permissions = &v1_permissions,
    };
    v2.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v2));

    const updated = try packages_entry.port.install(packages_entry.authority, .{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, org_policy);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.rollback_available);
    _ = try packages_entry.port.rollback(packages_entry.authority, "app.trip");
    try std.testing.expectEqual(@as(u16, 0), packages.find("app.trip").?.versionMinor());

    try controller.recoverSystem(task.id, person, "restored previous trip planner version");
    try std.testing.expectEqual(@as(usize, 5), controller.flow_count);
    try std.testing.expectEqual(native_ux.FlowKind.recover_system, controller.flows[4].kind);
    try std.testing.expectEqualStrings("restored previous trip planner version", controller.flows[4].detailSlice());
}

pub fn packageLifecycleStaysDeclarativeSignedAndPolicyScoped() !void {
    package_migration.reset();
    var policies = policy_object.Directory.init();
    const org_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 1,
        .issuer = spec_support.policyAuthority(7),
        .label = "org-defaults",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.corp.example"},
        .removable_storage_allowed = false,
        .screen_capture_allowed = false,
        .retention_days = 180,
        .audit_export_required = true,
    }, spec_support.signer("spec.policy.org", 0x81));

    var packages = package_service.Service.init();
    const bundle_signer = spec_support.signer("spec.bundle.notes", 0x82);
    var package_capabilities = capability.CapabilityTable.init();
    var packages_entry = try packageHarness(&packages, &package_capabilities, 9_200, 9_201, spec_support.service(9_200));
    try spec_support.trustPackagePublisher(&packages_entry.port, packages_entry.authority, bundle_signer, "Example Software");

    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
        },
    };
    const v1_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
    };
    const v1_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const v1_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 0,
        .provided_interfaces = &v1_interfaces,
        .consumed_interfaces = &v1_interfaces,
        .components = &v1_components,
        .assets = &v1_assets,
        .requested_permissions = &v1_permissions,
    };
    v1.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v1));

    const first = try packages_entry.port.install(packages_entry.authority, .{
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
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
        },
        .{
            .kind = .notification_post,
            .resource = "notifications://task",
            .rights = .{ .task = .{ .notification_post = true } },
            .required = false,
        },
    };
    const v2_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        .{ .id = "notes-sync", .entry = "zigos.notes.sync", .abi = .native_sandbox },
    };
    const v2_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/editor.css", .content_type = "text/css" },
    };
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .provided_interfaces = v2_interfaces[0..1],
        .consumed_interfaces = v2_interfaces[1..2],
        .components = &v2_components,
        .assets = &v2_assets,
        .requested_permissions = &v2_permissions,
    };
    v2.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v2));

    const updated = try packages_entry.port.install(packages_entry.authority, .{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .migration_manifest = "schema:1->2;notes-v2-migration",
        .declared_permission_change = true,
        .migration_applier = package_migration.apply,
    }, org_policy);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(updated.rollback_available);
    try std.testing.expect(updated.migration_applied);
    try std.testing.expectEqual(@as(usize, 1), package_migration.apply_count);

    const installed = packages.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), installed.versionMajor());
    try std.testing.expectEqual(@as(u16, 1), installed.versionMinor());
    try std.testing.expectEqual(@as(u32, 2), installed.schemaVersion());
    try std.testing.expectEqual(@as(usize, 2), installed.componentCount());
    try std.testing.expectEqualStrings("zigos.notes.sync", installed.componentAt(1).entrySlice());
    const launch_plan = try packages.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(usize, 2), launch_plan.component_count);
    try std.testing.expectEqual(@as(usize, 2), launch_plan.asset_count);
    try std.testing.expectEqualStrings("assets/editor.css", launch_plan.assets[1].pathSlice());
    try std.testing.expect(!org_policy.removable_storage_allowed);
    try std.testing.expect(!org_policy.screen_capture_allowed);
    try std.testing.expect(org_policy.audit_export_required);

    _ = try packages_entry.port.rollback(packages_entry.authority, "app.notes");
    try std.testing.expectEqual(@as(u16, 0), packages.find("app.notes").?.versionMinor());
    try std.testing.expectEqual(@as(usize, 1), packages.find("app.notes").?.componentCount());
}

pub fn backgroundWorkStaysDeclaredTriggeredBudgetedAndThrottled() !void {
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "sync", .entry = "app.sync" },
    };
    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.background.sync" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/sync/icon.svg", .content_type = "image/svg+xml" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = "schedule", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "push", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "change", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "proximity", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "sensor", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "sync", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "media", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "policy", .rights = .{ .task = .{ .background_run = true } } },
    };
    const background_tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "schedule", .trigger = .user_approved_scheduled_job, .expected_duration_seconds = 30, .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = 64 * 1024 }, .network = .none, .visibility = .status_only },
        .{ .id = "push", .trigger = .push_event, .expected_duration_seconds = 20, .budget = .{ .cpu_time_ticks = 900, .memory_bytes = 48 * 1024 }, .network = .named_service_identities, .visibility = .hidden },
        .{ .id = "change", .trigger = .local_object_change, .expected_duration_seconds = 15, .budget = .{ .cpu_time_ticks = 800, .memory_bytes = 32 * 1024 }, .network = .none, .visibility = .audit_only },
        .{ .id = "proximity", .trigger = .device_proximity, .expected_duration_seconds = 10, .budget = .{ .cpu_time_ticks = 700, .memory_bytes = 24 * 1024 }, .network = .none, .visibility = .user_visible },
        .{ .id = "sensor", .trigger = .sensor_rule, .expected_duration_seconds = 25, .budget = .{ .cpu_time_ticks = 750, .memory_bytes = 32 * 1024 }, .network = .none, .visibility = .status_only },
        .{ .id = "sync", .trigger = .sync_completion, .expected_duration_seconds = 40, .budget = .{ .cpu_time_ticks = 1_100, .memory_bytes = 96 * 1024 }, .network = .local_network_only, .visibility = .status_only },
        .{ .id = "media", .trigger = .media_export_completion, .expected_duration_seconds = 35, .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = 48 * 1024 }, .network = .named_domains, .visibility = .status_only },
        .{ .id = "policy", .trigger = .organization_policy_task, .expected_duration_seconds = 45, .budget = .{ .cpu_time_ticks = 1_200, .memory_bytes = 80 * 1024 }, .network = .none, .visibility = .audit_only },
    };

    var package_bundle = manifest.BundleManifest{
        .bundle_id = "app.background.spec",
        .display_name = "Background Spec",
        .publisher = "zigos.spec",
        .provided_interfaces = &provided_interfaces,
        .components = &components,
        .assets = &assets,
        .requested_permissions = &permissions,
        .background_tasks = &background_tasks,
        .update_channel = .stable,
    };
    const package_signer = spec_support.signer("spec.background.bundle", 0x79);
    package_bundle.signature = try signing.sign(package_signer, &package_service.digestBundle(package_bundle));

    var packages = package_service.Service.init();
    var package_capabilities = capability.CapabilityTable.init();
    var packages_entry = try packageHarness(&packages, &package_capabilities, 9_300, 9_301, spec_support.service(9_300));
    try spec_support.trustPackagePublisher(&packages_entry.port, packages_entry.authority, package_signer, "zigos.spec");
    _ = try packages_entry.port.install(packages_entry.authority, .{
        .bundle = package_bundle,
        .source_identity = "store.zigos.spec",
        .data_schema_version = 1,
    }, null);

    var resolved: package_service.ResolvedManifest = undefined;
    const installed_bundle = try packages.resolveCurrentManifest("app.background.spec", &resolved);

    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = spec_support.app(93),
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = 2 * 1024 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = true,
        },
        .ui_surface_id = 9,
        .local_only = false,
        .launch = .{
            .bundle_id = "app.background.spec",
        },
    });
    task.state = .active;

    var dispatcher = background_dispatch.Controller.init();
    for (installed_bundle.background_tasks) |background_task| {
        const decision = try dispatcher.dispatch(
            &runtime,
            task.id,
            installed_bundle,
            background_task.id,
            background_task.trigger,
            40,
        );
        try std.testing.expect(decision.allowed);
        try std.testing.expectEqual(background_task.expected_duration_seconds, decision.expected_duration_seconds);
        try std.testing.expectEqual(background_task.network, decision.network);
        try std.testing.expectEqual(background_task.visibility, decision.visibility);
        try std.testing.expect(try dispatcher.complete(&runtime, decision.record_id.?));
    }

    const first = try dispatcher.dispatch(&runtime, task.id, installed_bundle, "sync", .sync_completion, 50);
    const second = try dispatcher.dispatch(&runtime, task.id, installed_bundle, "sync", .sync_completion, 51);
    const third = try dispatcher.dispatch(&runtime, task.id, installed_bundle, "sync", .sync_completion, 52);
    try std.testing.expect(first.allowed);
    try std.testing.expect(second.allowed);
    try std.testing.expect(third.delayed);
    try std.testing.expectEqual(background_dispatch.DecisionReason.throttled, third.reason);
    try std.testing.expectEqual(@as(u64, 9_650), task.background_cpu_consumed_ticks);
    try std.testing.expectEqual(@as(u16, 2), task.background_active_count);
    try std.testing.expectEqual(manifest.BackgroundNetworkMode.local_network_only, task.last_background_network);
    try std.testing.expectEqual(manifest.BackgroundVisibility.status_only, task.last_background_visibility);
    try std.testing.expectEqual(task_runtime.AuditEventKind.background_dispatched, task.latestAuditEvent().?.kind);
}

pub fn structuredServicesAndDiagnosticsStayRedacted() !void {
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
    const source = spec_support.app(70);

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
    _ = try media.complete(export_job.id, &scheduler, &notifications, 30);
    _ = try media.complete(print_job.id, &scheduler, &notifications, 31);

    try std.testing.expectEqual(accelerator_scheduler.Engine.media, export_job.engine);
    try std.testing.expectEqual(media_print_service.JobState.completed, print_job.state);
    try std.testing.expectEqual(notification_center.Reason.print_complete, notifications.latestVisible(31).?.reason);
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());

    var ledger = event_ledger.Ledger.init();
    try ledger.recordPermissionDecision(spec_support.user(8), 503, .screen_capture, false, .policy_denied, 31, "screen capture blocked", true);
    try ledger.recordDriverRestart(contract.ServiceClass.media_print_helpers, spec_support.service(71), 9, 32, "printer helper restart");
    try ledger.recordSyncConflict(spec_support.user(8), 11, 33, "documents/itinerary.md conflict", true);
    var export_buffer: [1024]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "media_print_helpers") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "policy=user-grant-policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "missing=screen-capture-capability") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "approval=yes") != null);
}
