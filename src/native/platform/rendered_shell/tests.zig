const std = @import("std");
const abi = @import("../../core/abi.zig");
const capability = @import("../../kernel_api/capability.zig");
const compatibility_environment = @import("../../services/compatibility_environment.zig");
const compositor_session = @import("../compositor_session.zig");
const event_ledger = @import("../event_ledger.zig");
const manifest = @import("../../policy/manifest.zig");
const native_ux = @import("../native_ux.zig");
const object_store = @import("../../storage/object_store.zig");
const package_service = @import("../../services/package_service.zig");
const policy_object = @import("../../policy/policy_object.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const storage_service = @import("../../storage/storage_service.zig");
const sync_service = @import("../../sync/sync_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const task_runtime_service = @import("../../task/task_runtime_service.zig");
const journey_surface = @import("journey_surface.zig");
const model = @import("model.zig");
const production_journey = @import("production_journey.zig");
const shell_mod = @import("shell.zig");
const task_shell_service = @import("task_shell_service.zig");
const task_shell_wire = @import("task_shell_wire.zig");

const Config = model.Config;
const Control = model.Control;
const JourneySurface = journey_surface.JourneySurface;
const ProductionJourneyService = production_journey.ProductionJourneyService;
const ProductionJourneyStatus = production_journey.ProductionJourneyStatus;
const Shell = shell_mod.Shell;
const TaskShellCheckpointStore = task_shell_service.TaskShellCheckpointStore;
const TaskShellOperation = task_shell_wire.TaskShellOperation;
const TaskShellResponse = task_shell_wire.TaskShellResponse;
const TaskShellService = task_shell_service.TaskShellService;
const TaskShellStatus = task_shell_wire.TaskShellStatus;
const decodeTaskShellResponse = task_shell_wire.decodeResponse;
const encodeTaskShellRequest = task_shell_wire.encodeRequest;

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return error.ExpectedSubstringMissing;
}

fn seedShellWorkspace(storage: *storage_service.Service, owner: principal.PrincipalId, path: []const u8) !u64 {
    const signer_identity = signing.SignerIdentity{
        .label = "rendered-shell-object",
        .seed = [_]u8{0x9a} ** 32,
    };
    const document = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(92_001),
        .object_type = .document,
        .payload = "rendered shell document",
        .metadata = try object_store.signMetadata(
            signer_identity,
            "rendered shell document",
            "text/markdown",
            .document,
            "rendered shell document",
            10,
        ),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = owner,
        .label = "rendered-shell",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, path, document.object_id, document.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);
    return workspace_record.id.raw();
}

fn mintRenderedShellServiceAuthority(
    capability_table: *capability.CapabilityTable,
    service_id: u64,
    holder: principal.PrincipalId,
    task_id: u64,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .capability_mint = true,
            .capability_revoke = true,
        } },
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{},
    });
}

fn shellConfig(user: principal.PrincipalId, workspace_id: u64, document_path: []const u8) Config {
    return .{
        .user = user,
        .app_owner = user,
        .reviewer_task_id = 71,
        .workspace_id = workspace_id,
        .workspace_label = "Rendered Shell Workspace",
        .document_path = document_path,
        .task_label = "trip-planner",
        .task_entry = "app.trip.ui",
        .task_title = "Plan Trip",
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .ui_surface_id = 88,
        .image_id = 92_001,
    };
}

fn dispatchTaskShellForTest(
    service: *TaskShellService,
    operation: TaskShellOperation,
    control: Control,
    tick: u64,
) !TaskShellResponse {
    var request_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    var response_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const payload = try encodeTaskShellRequest(&request_buffer, .{
        .operation = operation,
        .control = control,
        .tick = tick,
    });
    return decodeTaskShellResponse(try service.dispatchPayload(payload, &response_buffer));
}

test "rendered demo journey drives install sync permission update recovery and removal controls" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 94 };
    const package_owner = principal.PrincipalId{ .kind = .service, .serial = 95 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 96 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 94 };
    const primary_device = principal.PrincipalId{ .kind = .device, .serial = 941 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 942 };
    const document_path = "documents/plan.md";
    const bundle_signer = signing.SignerIdentity{
        .label = "rendered-journey-bundle",
        .seed = [_]u8{0x9c} ** 32,
    };
    const user_signer = signing.SignerIdentity{
        .label = "rendered-journey-user",
        .seed = [_]u8{0x9d} ** 32,
    };
    const primary_signer = signing.SignerIdentity{
        .label = "rendered-journey-primary",
        .seed = [_]u8{0x9e} ** 32,
    };
    const paired_signer = signing.SignerIdentity{
        .label = "rendered-journey-paired",
        .seed = [_]u8{0x9f} ** 32,
    };

    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "trip-ui", .entry = "app.trip.ui" },
    };
    const v1_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/theme.css", .content_type = "text/css" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "documents/plan.md",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 240,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .publisher = "Example Software",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &v1_assets,
        .requested_permissions = &permissions,
    };
    v1.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v1));
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
        .requested_permissions = &permissions,
    };
    v2.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v2));

    var package_capabilities = capability.CapabilityTable.init();
    var packages_service = package_service.Service.init();
    packages_service.bind(9_500, package_owner);
    var package_port = package_service.PackagePort.init(&packages_service, &package_capabilities);
    const package_capability = try mintRenderedShellServiceAuthority(&package_capabilities, packages_service.service_id, package_owner, 9_501);
    const package_authority = package_service.AuthorityContext{
        .task_id = 9_501,
        .principal = package_owner,
        .capability_id = package_capability.id,
        .now_ticks = 10,
    };
    _ = try package_port.trustPolicyAuthorityRoot(package_authority, .{ .kind = .policy_authority, .serial = 1 }, [_]u8{0x5A} ** 32);
    _ = try package_port.trustPublisher(
        package_authority,
        .{ .kind = .app, .serial = 9_502 },
        .{ .kind = .policy_authority, .serial = 1 },
        "Example Software",
        try signing.publicKey(bundle_signer),
    );

    var storage = storage_service.Service.initWithStore(940, 941, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);

    var sync = sync_service.Service.init(9_510, 9_511, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try mintRenderedShellServiceAuthority(&sync_capabilities, sync.service_id, sync_owner, sync.task_id);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync.task_id,
        .principal = sync_owner,
        .capability_id = sync_capability.id,
        .now_ticks = 12,
    };
    _ = try sync_port.ensureUserRoot(sync_authority, user, "owner", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, primary_device, "laptop", user_signer, primary_signer, 12);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, paired_device, "tablet", user_signer, paired_signer, 13);
    const local_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "trip-local",
        .mode = .local_network,
    });
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{"documents/"},
        .device_to_device_policy_id = local_policy.id,
    });

    var runtime = task_runtime.Runtime.init();
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compatibility = compatibility_environment.Manager.init();
    var ledger = event_ledger.Ledger.init();
    var journey = JourneySurface.init(
        &runtime,
        &ux,
        &compositor,
        &storage,
        &package_port,
        package_authority,
        &sync_port,
        sync_authority,
        &compatibility,
        &ledger,
        .{
            .user = user,
            .app_owner = user,
            .reviewer_task_id = 77,
            .workspace_id = workspace_id,
            .workspace_label = "Trip Workspace",
            .document_path = document_path,
            .task_label = "trip-planner",
            .task_entry = "app.trip.ui",
            .task_title = "Plan Trip",
            .bundle_id = "app.trip",
            .display_name = "Trip Planner",
            .source_identity = "store:zigos",
            .install_bundle = v1,
            .update_bundle = v2,
            .ui_surface_id = 94,
            .image_id = 94_001,
            .sync_from_device = primary_device,
            .sync_to_device = paired_device,
        },
    );

    var render_buffer: [2048]u8 = undefined;
    const initial = try journey.render(&render_buffer);
    try expectContains(initial, "control=install-app state=ready");
    try expectContains(initial, "control=remove-app state=ready");

    try journey.click(.install_app, 20);
    try journey.click(.start_task, 21);
    try journey.click(.open_workspace, 22);
    try journey.click(.open_document, 23);
    try journey.click(.open_app_panel, 24);
    try journey.click(.review_permission, 25);
    try journey.click(.sync_workspace, 26);
    try journey.click(.update_app, 27);
    try journey.click(.rollback_update, 28);
    try journey.click(.containment_denial, 29);
    try journey.click(.recover_system, 30);
    try journey.click(.remove_app, 31);

    try std.testing.expect(packages_service.find("app.trip") == null);
    try std.testing.expectError(error.AppNotInstalled, journey.click(.start_task, 32));
    try std.testing.expectEqual(@as(usize, 12), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 3), compositor.window_count);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);

    const rendered = try journey.render(&render_buffer);
    try expectContains(rendered, "control=remove-app state=done");
    try expectContains(rendered, "package installed=yes updated=yes rolled_back=yes removed=yes");
    try expectContains(rendered, "task_flow_events=12");

    var export_buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "flow_kind=install_app");
    try expectContains(exported, "flow_kind=start_task");
    try expectContains(exported, "flow_kind=open_workspace");
    try expectContains(exported, "flow_kind=open_document");
    try expectContains(exported, "flow_kind=open_app_panel");
    try expectContains(exported, "flow_kind=review_permission_request");
    try expectContains(exported, "flow_kind=sync_workspace");
    try expectContains(exported, "flow_kind=update_app");
    try expectContains(exported, "flow_kind=rollback_app_update");
    try expectContains(exported, "flow_kind=containment_denial");
    try expectContains(exported, "flow_kind=recover_system");
    try expectContains(exported, "flow_kind=remove_app");
}

test "production journey service rejects premature controls then routes lifecycle policy device trust and recovery through service ports" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 97 };
    const package_owner = principal.PrincipalId{ .kind = .service, .serial = 98 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 99 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 97 };
    const admin = principal.PrincipalId{ .kind = .policy_authority, .serial = 97 };
    const primary_device = principal.PrincipalId{ .kind = .device, .serial = 971 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 972 };
    const document_path = "documents/plan.md";
    const bundle_signer = signing.SignerIdentity{
        .label = "production-journey-bundle",
        .seed = [_]u8{0xa1} ** 32,
    };
    const policy_signer = signing.SignerIdentity{
        .label = "production-journey-policy",
        .seed = [_]u8{0xa2} ** 32,
    };
    const user_signer = signing.SignerIdentity{
        .label = "production-journey-user",
        .seed = [_]u8{0xa3} ** 32,
    };
    const primary_signer = signing.SignerIdentity{
        .label = "production-journey-primary",
        .seed = [_]u8{0xa4} ** 32,
    };
    const paired_signer = signing.SignerIdentity{
        .label = "production-journey-paired",
        .seed = [_]u8{0xa5} ** 32,
    };

    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "trip-ui", .entry = "app.trip.ui" },
    };
    const v1_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/theme.css", .content_type = "text/css" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "documents/plan.md",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 240,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.trip.production",
        .display_name = "Trip Planner",
        .publisher = "Example Software",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &v1_assets,
        .requested_permissions = &permissions,
    };
    v1.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v1));
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.trip.production",
        .display_name = "Trip Planner",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &v2_assets,
        .requested_permissions = &permissions,
    };
    v2.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v2));

    var package_capabilities = capability.CapabilityTable.init();
    var packages_service = package_service.Service.init();
    packages_service.bind(9_700, package_owner);
    var package_port = package_service.PackagePort.init(&packages_service, &package_capabilities);
    const package_capability = try mintRenderedShellServiceAuthority(&package_capabilities, packages_service.service_id, package_owner, 9_701);
    const package_authority = package_service.AuthorityContext{
        .task_id = 9_701,
        .principal = package_owner,
        .capability_id = package_capability.id,
        .now_ticks = 10,
    };
    _ = try package_port.trustPolicyAuthorityRoot(package_authority, .{ .kind = .policy_authority, .serial = 1 }, [_]u8{0x5A} ** 32);
    _ = try package_port.trustPublisher(
        package_authority,
        .{ .kind = .app, .serial = 9_702 },
        .{ .kind = .policy_authority, .serial = 1 },
        "Example Software",
        try signing.publicKey(bundle_signer),
    );

    var storage = storage_service.Service.initWithStore(970, 971, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);

    var sync = sync_service.Service.init(9_710, 9_711, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try mintRenderedShellServiceAuthority(&sync_capabilities, sync.service_id, sync_owner, sync.task_id);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync.task_id,
        .principal = sync_owner,
        .capability_id = sync_capability.id,
        .now_ticks = 12,
    };

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(9_720, .{ .kind = .service, .serial = 9_720 });
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(
        9_721,
        9_722,
        &runtime,
        &compositor,
        &compositor_checkpoint_store,
    );
    var policies = policy_object.Directory.init();
    var ledger = event_ledger.Ledger.init();
    var journey = ProductionJourneyService.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &package_port,
        package_authority,
        &sync_port,
        sync_authority,
        &policies,
        &ledger,
        .{
            .user = user,
            .admin = admin,
            .app_owner = user,
            .organization_id = 97,
            .reviewer_task_id = 78,
            .workspace_id = workspace_id,
            .workspace_label = "Trip Workspace",
            .document_path = document_path,
            .task_label = "trip-planner",
            .task_entry = "app.trip.ui",
            .task_title = "Plan Trip",
            .bundle_id = "app.trip.production",
            .display_name = "Trip Planner",
            .source_identity = "store:zigos",
            .sync_destination = "relay.production.zigos",
            .device_label = "tablet",
            .policy_label = "production-journey-defaults",
            .install_bundle = v1,
            .update_bundle = v2,
            .ui_surface_id = 97,
            .image_id = 97_001,
            .sync_from_device = primary_device,
            .sync_to_device = paired_device,
            .policy_signer = policy_signer,
            .user_signer = user_signer,
            .primary_device_signer = primary_signer,
            .paired_device_signer = paired_signer,
        },
    );

    try std.testing.expectEqual(
        ProductionJourneyStatus.policy_rejected,
        journey.dispatch(.{ .control = .install_app, .tick = 19 }).status,
    );
    try std.testing.expectEqual(
        ProductionJourneyStatus.policy_rejected,
        journey.dispatch(.{ .control = .sync_workspace, .tick = 19 }).status,
    );

    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .apply_policy, .tick = 20 }).status);
    try std.testing.expect(policies.activeForScope(.organization, 97) != null);
    try std.testing.expectEqual(ProductionJourneyStatus.package_rejected, journey.dispatch(.{ .control = .start_task, .tick = 20 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.sync_rejected, journey.dispatch(.{ .control = .sync_workspace, .tick = 20 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .trust_device, .tick = 21 }).status);
    try std.testing.expect(sync.isTrustedDevice(primary_device));
    try std.testing.expect(sync.isTrustedDevice(paired_device));
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .install_app, .tick = 22 }).status);
    const start_response = journey.dispatch(.{ .control = .start_task, .tick = 23 });
    try std.testing.expectEqual(ProductionJourneyStatus.ok, start_response.status);
    const started_task_id = start_response.task_id;
    try std.testing.expect(started_task_id != 0);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .open_workspace, .tick = 24 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .open_document, .tick = 25 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .review_permission, .tick = 26 }).status);
    try std.testing.expectEqual(@as(usize, 3), compositor.window_count);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .sync_workspace, .tick = 27 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .update_app, .tick = 28 }).status);
    try std.testing.expectEqual(@as(u16, 1), packages_service.find("app.trip.production").?.versionMinor());
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .rollback_update, .tick = 29 }).status);
    try std.testing.expectEqual(@as(u16, 0), packages_service.find("app.trip.production").?.versionMinor());
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .recover_system, .tick = 30 }).status);
    const remove_response = journey.dispatch(.{ .control = .remove_app, .tick = 31 });
    try std.testing.expectEqual(ProductionJourneyStatus.ok, remove_response.status);
    try std.testing.expectEqual(@as(u64, 0), remove_response.task_id);
    try std.testing.expectEqual(@as(u16, 0), remove_response.visible_window_count);
    try std.testing.expect(packages_service.find("app.trip.production") == null);
    try std.testing.expectEqual(task_runtime.TaskState.terminated, runtime.find(started_task_id).?.state);
    try std.testing.expectEqual(@as(usize, 0), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 0), compositor.item_count);
    try std.testing.expectEqual(@as(u64, 0), compositor.active_window_id);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .revoke_device, .tick = 32 }).status);
    try std.testing.expect(!sync.isTrustedDevice(paired_device));
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .revoke_policy, .tick = 33 }).status);
    try std.testing.expectEqual(
        ProductionJourneyStatus.policy_rejected,
        journey.dispatch(.{ .control = .install_app, .tick = 34 }).status,
    );

    try std.testing.expectEqual(@as(usize, 11), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{ .kind = .policy_change }));
    try std.testing.expectEqual(@as(usize, 3), ledger.countMatching(.{ .kind = .device_trust_change }));
    try std.testing.expect(runtime_checkpoint_store.has_checkpoint);
    try std.testing.expect(compositor_checkpoint_store.valid);

    var render_buffer: [2048]u8 = undefined;
    const rendered = try journey.render(&render_buffer);
    try expectContains(rendered, "control=apply-policy state=done");
    try expectContains(rendered, "control=remove-app state=done");
    try expectContains(rendered, "control=revoke-policy state=done");
    try expectContains(rendered, "task=0 bundle=app.trip.production");
    try expectContains(rendered, "visible_windows=0");
    try expectContains(rendered, "task_flow_events=11");

    var export_buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "kind=policy_change");
    try expectContains(exported, "kind=device_trust_change");
    try expectContains(exported, "flow_kind=review_permission_request");
    try expectContains(exported, "flow_kind=recover_system");
}

test "rendered task shell drives task workspace document panel and focus controls" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 92 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 92 };
    const document_path = "documents/plan.md";

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.initWithStore(920, 921, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var ledger = event_ledger.Ledger.init();
    var shell = Shell.init(&runtime, &ux, &compositor, &storage, &ledger, shellConfig(user, workspace_id, document_path));

    var render_buffer: [768]u8 = undefined;
    const initial = try shell.render(&render_buffer);
    try expectContains(initial, "control=start-task");
    try expectContains(initial, "task=0");

    try shell.click(.start_task, 20);
    try shell.click(.open_workspace, 21);
    try shell.click(.open_document, 22);
    try shell.click(.open_app_panel, 23);
    try shell.click(.focus_full_screen, 24);

    const task = runtime.find(shell.taskId()) orelse return error.TaskMissing;
    try std.testing.expect(task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(?u64, 88), task.ui_surface_id);
    try std.testing.expectEqual(@as(usize, 4), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 1), compositor.item_count);
    try std.testing.expectEqual(compositor_session.ViewType.workspace_view, compositor.windowAtOrder(0).?.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.document_view, compositor.windowAtOrder(1).?.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.full_screen_task_view, compositor.windowAtOrder(3).?.view_type);
    try std.testing.expectEqual(compositor.windowAtOrder(3).?.id, compositor.active_window_id);

    try std.testing.expectEqual(@as(usize, 5), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 4), ledger.countMatching(.{ .kind = .task_flow, .task_id = task.id }));
    try std.testing.expectEqual(@as(usize, 3), ledger.countMatching(.{ .kind = .task_flow, .workspace_id = workspace_id }));

    var export_buffer: [1024]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "flow_kind=start_task");
    try expectContains(exported, "flow_kind=open_workspace");
    try expectContains(exported, "flow_kind=open_document");
    try expectContains(exported, "flow_kind=open_app_panel");
    try expectContains(exported, "flow_kind=focus_task");

    const rendered = try shell.render(&render_buffer);
    try expectContains(rendered, "active_type=full_screen_task_view");
    try expectContains(rendered, "active_title=Plan Trip");
    try expectContains(rendered, "task_flow_events=5");
}

test "task shell service routes controls through compositor service and recovers persistent task state" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 95 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 95 };
    const document_path = "documents/plan.md";

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(9_600, .{ .kind = .service, .serial = 9_600 });

    var storage = storage_service.Service.initWithStore(950, 951, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(9_601, 9_602, &runtime, &compositor, &compositor_checkpoint_store);
    var ledger = event_ledger.Ledger.init();
    var shell_checkpoint_store = TaskShellCheckpointStore{};
    const config = shellConfig(user, workspace_id, document_path);
    var shell_service = TaskShellService.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &ledger,
        config,
        &shell_checkpoint_store,
    );

    const start = try dispatchTaskShellForTest(&shell_service, .click, .start_task, 40);
    try std.testing.expectEqual(TaskShellStatus.ok, start.status);
    const workspace_response = try dispatchTaskShellForTest(&shell_service, .click, .open_workspace, 41);
    try std.testing.expectEqual(TaskShellStatus.ok, workspace_response.status);
    const document_response = try dispatchTaskShellForTest(&shell_service, .click, .open_document, 42);
    try std.testing.expectEqual(TaskShellStatus.ok, document_response.status);
    const panel_response = try dispatchTaskShellForTest(&shell_service, .click, .open_app_panel, 43);
    try std.testing.expectEqual(TaskShellStatus.ok, panel_response.status);
    const focus_response = try dispatchTaskShellForTest(&shell_service, .click, .focus_full_screen, 44);
    try std.testing.expectEqual(TaskShellStatus.ok, focus_response.status);

    const task_id = focus_response.task_id;
    try std.testing.expect(task_id != 0);
    try std.testing.expect(runtime_checkpoint_store.has_checkpoint);
    try std.testing.expect(compositor_checkpoint_store.valid);
    try std.testing.expect(shell_checkpoint_store.valid);
    try std.testing.expectEqual(@as(u16, 4), focus_response.visible_window_count);
    try std.testing.expectEqual(@as(u16, 5), focus_response.task_flow_events);
    try std.testing.expectEqual(@as(usize, 4), compositor.window_count);
    try std.testing.expectEqual(compositor_session.ViewType.full_screen_task_view, compositor.windowAtOrder(3).?.view_type);
    try std.testing.expectEqual(compositor.windowAtOrder(3).?.id, compositor.active_window_id);

    var restarted_runtime = task_runtime.Runtime.init();
    var restarted_runtime_service = task_runtime_service.Service.initWithStore(&restarted_runtime, &runtime_checkpoint_store);
    restarted_runtime_service.bind(9_600, .{ .kind = .service, .serial = 9_600 });
    var restarted_compositor = compositor_session.Session.init();
    var restarted_compositor_service = compositor_session.Service.initWithCheckpoint(
        9_601,
        9_602,
        &restarted_runtime,
        &restarted_compositor,
        &compositor_checkpoint_store,
    );
    var restarted_shell_service = TaskShellService.init(
        &restarted_runtime_service,
        &ux,
        &restarted_compositor_service,
        &storage,
        &ledger,
        config,
        &shell_checkpoint_store,
    );
    const recovered = try dispatchTaskShellForTest(&restarted_shell_service, .recover_state, .start_task, 50);
    try std.testing.expectEqual(TaskShellStatus.ok, recovered.status);
    try std.testing.expect(recovered.recovered);
    try std.testing.expectEqual(task_id, recovered.task_id);
    try std.testing.expect(restarted_runtime.find(task_id) != null);
    try std.testing.expectEqual(@as(usize, 4), restarted_compositor.window_count);
    try std.testing.expectEqual(restarted_compositor.windowAtOrder(3).?.id, restarted_compositor.active_window_id);

    var render_buffer: [768]u8 = undefined;
    const rendered = try restarted_shell_service.render(&render_buffer);
    try expectContains(rendered, "control=focus-full-screen state=done");
    try expectContains(rendered, "active_type=full_screen_task_view");
    try expectContains(rendered, "active_title=Task: Plan Trip");
    try expectContains(rendered, "task_flow_events=5");
}

test "rendered task shell rejects out-of-order or missing workspace interactions" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 93 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 93 };

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.initWithStore(930, 931, storage_owner, &storage_checkpoint_store);
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "empty-rendered-shell",
    });
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var ledger = event_ledger.Ledger.init();
    var shell = Shell.init(&runtime, &ux, &compositor, &storage, &ledger, shellConfig(user, workspace_record.id.raw(), "documents/missing.md"));

    try std.testing.expectError(error.TaskRequired, shell.click(.open_workspace, 30));
    try std.testing.expectError(error.TaskRequired, shell.click(.focus_full_screen, 31));

    try shell.click(.start_task, 32);
    try std.testing.expectError(error.WorkspaceRequired, shell.click(.open_document, 33));
    try std.testing.expectError(error.EntryNotFound, shell.click(.open_workspace, 34));
    try std.testing.expectError(error.WorkspaceRequired, shell.click(.open_app_panel, 35));

    try std.testing.expectEqual(@as(usize, 0), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .task_flow }));
}

test "task shell service rejects out-of-order controls before creating compositor state" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 96 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 96 };

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(9_700, .{ .kind = .service, .serial = 9_700 });

    var storage = storage_service.Service.initWithStore(960, 961, storage_owner, &storage_checkpoint_store);
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "empty-service-shell",
    });
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(9_701, 9_702, &runtime, &compositor, &compositor_checkpoint_store);
    var ledger = event_ledger.Ledger.init();
    var shell_checkpoint_store = TaskShellCheckpointStore{};
    var shell_service = TaskShellService.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &ledger,
        shellConfig(user, workspace_record.id.raw(), "documents/missing.md"),
        &shell_checkpoint_store,
    );

    const missing_task = try dispatchTaskShellForTest(&shell_service, .click, .open_workspace, 60);
    try std.testing.expectEqual(TaskShellStatus.invalid_order, missing_task.status);
    try std.testing.expect(!shell_checkpoint_store.valid);

    const start = try dispatchTaskShellForTest(&shell_service, .click, .start_task, 61);
    try std.testing.expectEqual(TaskShellStatus.ok, start.status);
    const document_before_workspace = try dispatchTaskShellForTest(&shell_service, .click, .open_document, 62);
    try std.testing.expectEqual(TaskShellStatus.invalid_order, document_before_workspace.status);
    const missing_workspace_entry = try dispatchTaskShellForTest(&shell_service, .click, .open_workspace, 63);
    try std.testing.expectEqual(TaskShellStatus.not_found, missing_workspace_entry.status);
    const panel_before_document = try dispatchTaskShellForTest(&shell_service, .click, .open_app_panel, 64);
    try std.testing.expectEqual(TaskShellStatus.invalid_order, panel_before_document.status);

    try std.testing.expectEqual(@as(usize, 0), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .task_flow }));
}
