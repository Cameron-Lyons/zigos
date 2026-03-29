const std = @import("std");
const spec_support = @import("support.zig");
const accelerator_scheduler = @import("../../native/task/accelerator_scheduler.zig");
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
const signing = @import("../../native/core/signing.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const sync_service = @import("../../native/sync/sync_service.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");

pub fn taskFirstUxRecordsStructuredFlows() !void {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

    const storage_owner = spec_support.service(60);
    const sync_owner = spec_support.service(61);
    const person = spec_support.user(6);
    const paired_device = spec_support.device(61);
    const object_signer = spec_support.signer("spec.ux.object", 0x71);
    const user_signer = spec_support.signer("spec.ux.user", 0x72);
    const device_signer = spec_support.signer("spec.ux.device", 0x73);

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
        .budget = spec_support.defaultBudget(false),
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

pub fn packageLifecycleStaysDeclarativeSignedAndPolicyScoped() !void {
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

    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
    };
    const v1_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
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
        .components = &v1_components,
        .assets = &v1_assets,
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
    const v2_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        .{ .id = "notes-sync", .entry = "zigos.notes.sync", .abi = .native_sandbox },
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
        .components = &v2_components,
        .assets = &v2_assets,
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
    try std.testing.expectEqual(@as(usize, 2), installed.current_component_count);
    try std.testing.expectEqualStrings("zigos.notes.sync", installed.current_components[1].entrySlice());
    const launch_plan = try packages.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(usize, 2), launch_plan.component_count);
    try std.testing.expectEqual(@as(usize, 2), launch_plan.asset_count);
    try std.testing.expectEqualStrings("assets/editor.css", launch_plan.assets[1].pathSlice());
    try std.testing.expect(!org_policy.removable_storage_allowed);
    try std.testing.expect(!org_policy.screen_capture_allowed);
    try std.testing.expect(org_policy.audit_export_required);

    _ = try packages.rollback("app.notes");
    try std.testing.expectEqual(@as(u16, 0), packages.find("app.notes").?.current_version_minor);
    try std.testing.expectEqual(@as(usize, 1), packages.find("app.notes").?.current_component_count);
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
