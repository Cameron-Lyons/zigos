const std = @import("std");
const abi = @import("../../core/abi.zig");
const boot_markers = @import("../../../kernel/boot/markers.zig");
const capability = @import("../../kernel_api/capability.zig");
const compositor_session = @import("../compositor_session.zig");
const event_ledger = @import("../event_ledger.zig");
const manifest = @import("../../policy/manifest.zig");
const manifest_fixtures = @import("../../policy/manifest_fixtures.zig");
const native_util = @import("../../core/util.zig");
const native_ux = @import("../native_ux.zig");
const notification_center = @import("../../services/notification_center.zig");
const object_store = @import("../../storage/object_store.zig");
const package_service = @import("../../services/package_service.zig");
const policy_object = @import("../../policy/policy_object.zig");
const principal = @import("../../core/principal.zig");
const public_store = @import("../../services/public_store.zig");
const signing = @import("../../core/signing.zig");
const storage_service = @import("../../storage/storage_service.zig");
const sync_service = @import("../../sync/sync_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const task_runtime_service = @import("../../task/task_runtime_service.zig");
const units = @import("../../core/units.zig");
const booted_system = @import("booted_system.zig");
const humane_shell = @import("humane_shell.zig");
const humane_shell_wire = @import("humane_shell_wire.zig");
const journey_surface = @import("journey_surface.zig");
const model = @import("model.zig");
const production_journey = @import("production_journey.zig");
const shell_mod = @import("shell.zig");
const task_shell_service = @import("task_shell_service.zig");
const task_shell_wire = @import("task_shell_wire.zig");

const FULL_RENDER_BUFFER_BYTES: usize = units.kibibytes(8);
const EXPORT_BUFFER_BYTES: usize = units.kibibytes(4);
const RENDER_BUFFER_BYTES: usize = units.kibibytes(2);
const COMPACT_RENDER_BUFFER_BYTES: usize = 768;
const SMALL_EXPORT_BUFFER_BYTES: usize = units.kibibytes(1);
const WIRE_BUFFER_BYTES: usize = 128;

const Config = model.Config;
const Control = model.Control;
const HumaneShell = humane_shell.HumaneShell;
const HumaneShellCheckpointStore = humane_shell.HumaneShellCheckpointStore;
const HumaneShellControl = humane_shell.HumaneShellControl;
const HumaneShellStatus = humane_shell.HumaneShellStatus;
const BootedSystem = booted_system.BootedSystem;
const ShellInput = booted_system.ShellInput;
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

fn expectNotContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) return error.UnexpectedSubstringPresent;
}

fn seedShellWorkspace(storage: *storage_service.Service, owner: principal.PrincipalId, path: []const u8) !u64 {
    const signer_identity = signing.SignerIdentity{
        .label = "rendered-shell-object",
        .seed = signing.seedFromByte(0x9a),
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

fn signReleaseBundle(identity: signing.SignerIdentity, bundle: manifest.BundleManifest) !manifest.Signature {
    return signing.signWithDefaultRegistry(
        .ed25519,
        identity,
        &package_service.digestBundle(bundle),
    );
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
        .seed = signing.seedFromByte(0x9c),
    };
    const user_signer = signing.SignerIdentity{
        .label = "rendered-journey-user",
        .seed = signing.seedFromByte(0x9d),
    };
    const primary_signer = signing.SignerIdentity{
        .label = "rendered-journey-primary",
        .seed = signing.seedFromByte(0x9e),
    };
    const paired_signer = signing.SignerIdentity{
        .label = "rendered-journey-paired",
        .seed = signing.seedFromByte(0x9f),
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
    v1.signature = try signReleaseBundle(bundle_signer, v1);
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
    v2.signature = try signReleaseBundle(bundle_signer, v2);

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
    _ = try package_port.trustPolicyAuthorityRoot(package_authority, .{ .kind = .policy_authority, .serial = 1 }, signing.publicKeyFromByte(0x5A));
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
    try sync_port.setReplicaVersion(sync_authority, workspace_id, paired_device, document_path, 92_001, 99_001);

    var runtime = task_runtime.Runtime.init();
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
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

    var render_buffer: [RENDER_BUFFER_BYTES]u8 = undefined;
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
    try std.testing.expectEqual(@as(usize, 13), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 4), compositor.window_count);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.sync_conflict_review, compositor.windowAtOrder(3).?.view_type);

    const rendered = try journey.render(&render_buffer);
    try expectContains(rendered, "control=remove-app state=done");
    try expectContains(rendered, "package installed=yes updated=yes rolled_back=yes removed=yes");
    try expectContains(rendered, "task_flow_events=13");

    var export_buffer: [EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "flow_kind=install_app");
    try expectContains(exported, "flow_kind=start_task");
    try expectContains(exported, "flow_kind=open_workspace");
    try expectContains(exported, "flow_kind=open_document");
    try expectContains(exported, "flow_kind=open_app_panel");
    try expectContains(exported, "flow_kind=review_permission_request");
    try expectContains(exported, "flow_kind=sync_workspace");
    try expectContains(exported, "flow_kind=sync_conflict_review");
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
    const collaborator = principal.PrincipalId{ .kind = .user, .serial = 973 };
    const document_path = "documents/notes.md";
    const bundle_signer = signing.SignerIdentity{
        .label = "production-journey-bundle",
        .seed = signing.seedFromByte(0xa1),
    };
    const policy_signer = signing.SignerIdentity{
        .label = "production-journey-policy",
        .seed = signing.seedFromByte(0xa2),
    };
    const user_signer = signing.SignerIdentity{
        .label = "production-journey-user",
        .seed = signing.seedFromByte(0xa3),
    };
    const primary_signer = signing.SignerIdentity{
        .label = "production-journey-primary",
        .seed = signing.seedFromByte(0xa4),
    };
    const paired_signer = signing.SignerIdentity{
        .label = "production-journey-paired",
        .seed = signing.seedFromByte(0xa5),
    };

    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "app.notes.ui" },
    };
    const v1_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/theme.css", .content_type = "text/css" },
    };
    const v1_store_assets = [_]public_store.ReleaseAsset{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml", .digest = "sha256:7070707070707070707070707070707070707070707070707070707070707070", .size_bytes = 1536 },
    };
    const v2_store_assets = [_]public_store.ReleaseAsset{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml", .digest = "sha256:7171717171717171717171717171717171717171717171717171717171717171", .size_bytes = 1600 },
        .{ .path = "assets/theme.css", .content_type = "text/css", .digest = "sha256:7272727272727272727272727272727272727272727272727272727272727272", .size_bytes = 4096 },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "documents/notes.md",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 240,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes.daily",
        .display_name = "Notes",
        .publisher = "Example Software",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &v1_assets,
        .requested_permissions = &permissions,
        .supply_chain = .{
            .sbom_digest = "sha256:7373737373737373737373737373737373737373737373737373737373737373",
            .source_archive_digest = "sha256:7474747474747474747474747474747474747474747474747474747474747474",
            .build_recipe_digest = "sha256:7575757575757575757575757575757575757575757575757575757575757575",
            .vulnerability_scan_digest = "sha256:7676767676767676767676767676767676767676767676767676767676767676",
            .build_provenance_identity = "builder:zigos/reproducible-notes",
            .reproducible_build = true,
            .trusted_builder = true,
        },
    };
    v1.signature = try signReleaseBundle(bundle_signer, v1);
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.notes.daily",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &v2_assets,
        .requested_permissions = &permissions,
        .supply_chain = .{
            .sbom_digest = "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            .source_archive_digest = "sha256:7878787878787878787878787878787878787878787878787878787878787878",
            .build_recipe_digest = "sha256:7979797979797979797979797979797979797979797979797979797979797979",
            .vulnerability_scan_digest = "sha256:8080808080808080808080808080808080808080808080808080808080808080",
            .build_provenance_identity = "builder:zigos/reproducible-notes",
            .reproducible_build = true,
            .trusted_builder = true,
        },
    };
    v2.signature = try signReleaseBundle(bundle_signer, v2);
    var store_channel = public_store.Channel.init("store:zigos/public", .stable);
    try store_channel.trustPublisher("Example Software", try signing.publicKey(bundle_signer));
    try store_channel.publish(store_channel.prepareRelease(v1, &v1_store_assets, 1));
    try store_channel.publish(store_channel.prepareRelease(v2, &v2_store_assets, 1));

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
    _ = try package_port.trustPolicyAuthorityRoot(package_authority, .{ .kind = .policy_authority, .serial = 1 }, signing.publicKeyFromByte(0x5A));
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
            .workspace_label = "Notes Workspace",
            .document_path = document_path,
            .task_label = "notes",
            .task_entry = "app.notes.ui",
            .task_title = "Notes",
            .bundle_id = "app.notes.daily",
            .display_name = "Notes",
            .source_identity = "store:zigos/public",
            .sync_destination = "relay.production.zigos",
            .device_label = "tablet",
            .policy_label = "production-journey-defaults",
            .install_bundle = v1,
            .update_bundle = v2,
            .public_store_channel = &store_channel,
            .ui_surface_id = 97,
            .image_id = 97_001,
            .share_principal = collaborator,
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
    const installed_bundle = packages_service.find("app.notes.daily").?;
    try std.testing.expectEqualStrings("store:zigos/public", installed_bundle.sourceIdentitySlice());
    try std.testing.expectEqual(@as(usize, 1), installed_bundle.activeRevision().asset_count);
    try std.testing.expectEqualStrings("assets/icon.svg", installed_bundle.activeRevision().assets[0].pathSlice());
    try std.testing.expectEqualStrings("sha256:7373737373737373737373737373737373737373737373737373737373737373", installed_bundle.activeRevision().supply_chain.sbomDigestSlice());
    const installed_launch_plan = try packages_service.buildLaunchPlan("app.notes.daily");
    try std.testing.expectEqualStrings("store:zigos/public", installed_launch_plan.provenance.source_identity);
    try std.testing.expectEqual(@as(u64, 1), installed_launch_plan.provenance.release_transparency.sequence);
    const start_response = journey.dispatch(.{ .control = .start_task, .tick = 23 });
    try std.testing.expectEqual(ProductionJourneyStatus.ok, start_response.status);
    const started_task_id = start_response.task_id;
    try std.testing.expect(started_task_id != 0);
    const started_task = runtime_service.runtimePtr().find(started_task_id).?;
    try std.testing.expectEqualStrings("store:zigos/public", started_task.launchSourceIdentitySlice());
    try std.testing.expect(started_task.launch.hasReleaseTransparency());
    try std.testing.expectEqual(@as(u64, 1), started_task.launch.release_transparency_sequence);
    try std.testing.expectEqual(native_util.fnv1a64("store:zigos/public"), started_task.latestProvenanceEvent().?.source_identity_fingerprint);
    try std.testing.expect(started_task.latestProvenanceEvent().?.hasReleaseTransparency());
    try std.testing.expectEqual(@as(u64, 1), started_task.latestProvenanceEvent().?.release_transparency_sequence);
    try std.testing.expect(std.mem.indexOf(u8, started_task.latestProvenanceEvent().?.detailSlice(), "source=store:zigos/public") != null);
    try std.testing.expect(std.mem.indexOf(u8, started_task.latestProvenanceEvent().?.detailSlice(), "seq=1") != null);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .open_workspace, .tick = 24 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .open_document, .tick = 25 }).status);
    var marker_buffer: [SMALL_EXPORT_BUFFER_BYTES]u8 = undefined;
    const opened_markers = try journey.renderMarkerContract(&marker_buffer);
    try expectContains(opened_markers, boot_markers.notes_daily_driver_install_open_ok);
    try expectNotContains(opened_markers, boot_markers.notes_daily_driver_edit_saved_ok);

    const before_edit = try storage.resolve(workspace_id, document_path);
    try std.testing.expectEqual(ProductionJourneyStatus.invalid_order, journey.dispatch(.{ .control = .sync_workspace, .tick = 26 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .edit_document, .tick = 26 }).status);
    const edited_markers = try journey.renderMarkerContract(&marker_buffer);
    try expectContains(edited_markers, boot_markers.notes_daily_driver_edit_saved_ok);
    try expectNotContains(edited_markers, boot_markers.notes_daily_driver_share_sync_ok);

    const edited_entry = try storage.resolve(workspace_id, document_path);
    try std.testing.expectEqual(before_edit.object_id, edited_entry.object_id);
    try std.testing.expect(!before_edit.version_id.eql(edited_entry.version_id));
    try std.testing.expectEqual(edited_entry.version_id.raw(), journey.document_version_id);
    try std.testing.expectEqual(before_edit.version_id.raw(), journey.document_previous_version_id);
    try std.testing.expectEqualStrings(journey.config.edit_payload, try storage.versionPayload(storage.version(edited_entry.version_id).?));
    try std.testing.expect(storage_checkpoint_store.has_persisted_state);
    try std.testing.expect(storage_checkpoint_store.checkpointHealthy());
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .review_permission, .tick = 27 }).status);
    try std.testing.expectEqual(@as(usize, 3), compositor.window_count);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);
    try std.testing.expectEqual(ProductionJourneyStatus.invalid_order, journey.dispatch(.{ .control = .sync_workspace, .tick = 28 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .share_document, .tick = 28 }).status);
    const shared_entry = try storage.resolve(workspace_id, document_path);
    try std.testing.expectEqual(edited_entry.version_id, shared_entry.version_id);
    try std.testing.expect(storage.workspaceHasAccess(workspace_id, .{
        .principal_id = collaborator,
        .object_id = shared_entry.object_id,
        .path = shared_entry.pathSlice(),
        .wants_write = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 28,
    }));
    const tablet_offline = try storage.putVersion(.{
        .preferred_object_id = shared_entry.object_id,
        .object_type = .document,
        .payload = "tablet offline conflict",
        .metadata = try object_store.signMetadata(
            user_signer,
            "tablet-offline-conflict",
            "text/markdown",
            .document,
            "tablet offline conflict",
            28,
        ),
        .parent_version_id = edited_entry.version_id,
    });
    try sync_port.setReplicaVersion(
        sync_authority,
        workspace_id,
        paired_device,
        document_path,
        shared_entry.object_id,
        tablet_offline.version_id,
    );
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .sync_workspace, .tick = 29 }).status);
    const synced_markers = try journey.renderMarkerContract(&marker_buffer);
    try expectContains(synced_markers, boot_markers.notes_daily_driver_share_sync_ok);
    try expectNotContains(synced_markers, boot_markers.notes_daily_driver_update_rollback_ok);

    try std.testing.expectEqual(edited_entry.version_id.raw(), sync.replicaVersion(workspace_id, paired_device, document_path).?);
    try std.testing.expect(sync.findConflict(workspace_id, paired_device, document_path) == null);
    try std.testing.expect(journey.share_object_scope_verified);
    try std.testing.expect(journey.share_write_verified);
    try std.testing.expectEqual(shared_entry.object_id.raw(), journey.shared_object_id);
    try std.testing.expectEqual(@as(u64, 508), journey.share_expires_at_ticks);
    try std.testing.expectEqual(@as(u16, 1), journey.sync_conflict_count);
    try std.testing.expect(journey.sync_conflict_reviewed);
    try std.testing.expect(journey.sync_conflict_resolved);
    try std.testing.expectEqual(edited_entry.version_id.raw(), journey.sync_conflict_local_version_id);
    try std.testing.expectEqual(tablet_offline.version_id.raw(), journey.sync_conflict_remote_version_id);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .update_app, .tick = 30 }).status);
    const updated_bundle = packages_service.find("app.notes.daily").?;
    try std.testing.expectEqual(@as(u16, 1), updated_bundle.versionMinor());
    try std.testing.expectEqualStrings("store:zigos/public", updated_bundle.sourceIdentitySlice());
    try std.testing.expectEqual(@as(usize, 2), updated_bundle.activeRevision().asset_count);
    try std.testing.expectEqualStrings("assets/theme.css", updated_bundle.activeRevision().assets[1].pathSlice());
    try std.testing.expectEqualStrings("sha256:7777777777777777777777777777777777777777777777777777777777777777", updated_bundle.activeRevision().supply_chain.sbomDigestSlice());
    const updated_launch_plan = try packages_service.buildLaunchPlan("app.notes.daily");
    try std.testing.expectEqual(@as(u64, 2), updated_launch_plan.provenance.release_transparency.sequence);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .rollback_update, .tick = 31 }).status);
    const rolled_back_markers = try journey.renderMarkerContract(&marker_buffer);
    try expectContains(rolled_back_markers, boot_markers.notes_daily_driver_update_rollback_ok);
    try expectNotContains(rolled_back_markers, boot_markers.notes_daily_driver_recovery_remove_ok);

    const rolled_back_bundle = packages_service.find("app.notes.daily").?;
    try std.testing.expectEqual(@as(u16, 0), rolled_back_bundle.versionMinor());
    try std.testing.expectEqual(@as(usize, 1), rolled_back_bundle.activeRevision().asset_count);
    try std.testing.expectEqualStrings("sha256:7373737373737373737373737373737373737373737373737373737373737373", rolled_back_bundle.activeRevision().supply_chain.sbomDigestSlice());
    const rollback_launch_plan = try packages_service.buildLaunchPlan("app.notes.daily");
    try std.testing.expectEqual(@as(u64, 1), rollback_launch_plan.provenance.release_transparency.sequence);
    try std.testing.expectEqual(edited_entry.version_id, (try storage.resolve(workspace_id, document_path)).version_id);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .recover_system, .tick = 32 }).status);
    try std.testing.expectEqual(edited_entry.version_id, (try storage.resolve(workspace_id, document_path)).version_id);
    const remove_response = journey.dispatch(.{ .control = .remove_app, .tick = 33 });
    try std.testing.expectEqual(ProductionJourneyStatus.ok, remove_response.status);
    try std.testing.expectEqual(@as(u64, 0), remove_response.task_id);
    try std.testing.expectEqual(@as(u16, 0), remove_response.visible_window_count);
    try std.testing.expect(packages_service.find("app.notes.daily") == null);
    try std.testing.expectEqual(task_runtime.TaskState.terminated, runtime.find(started_task_id).?.state);
    try std.testing.expectEqual(@as(usize, 0), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 0), compositor.item_count);
    try std.testing.expectEqual(@as(u64, 0), compositor.active_window_id);
    try std.testing.expectEqual(edited_entry.version_id, (try storage.resolve(workspace_id, document_path)).version_id);
    const removed_markers = try journey.renderMarkerContract(&marker_buffer);
    try expectContains(removed_markers, boot_markers.notes_daily_driver_recovery_remove_ok);
    try expectNotContains(removed_markers, boot_markers.notes_daily_driver_authority_revoked_ok);

    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .revoke_device, .tick = 34 }).status);
    try std.testing.expect(!sync.isTrustedDevice(paired_device));
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .revoke_policy, .tick = 35 }).status);
    const complete_markers = try journey.renderMarkerContract(&marker_buffer);
    try expectContains(complete_markers, boot_markers.notes_daily_driver_install_open_ok);
    try expectContains(complete_markers, boot_markers.notes_daily_driver_edit_saved_ok);
    try expectContains(complete_markers, boot_markers.notes_daily_driver_share_sync_ok);
    try expectContains(complete_markers, boot_markers.notes_daily_driver_update_rollback_ok);
    try expectContains(complete_markers, boot_markers.notes_daily_driver_recovery_remove_ok);
    try expectContains(complete_markers, boot_markers.notes_daily_driver_authority_revoked_ok);
    try expectContains(complete_markers, boot_markers.notes_daily_driver_complete);

    try std.testing.expectEqual(
        ProductionJourneyStatus.policy_rejected,
        journey.dispatch(.{ .control = .install_app, .tick = 36 }).status,
    );

    try std.testing.expectEqual(@as(usize, 14), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{ .kind = .policy_change }));
    try std.testing.expectEqual(@as(usize, 3), ledger.countMatching(.{ .kind = .device_trust_change }));
    try std.testing.expect(runtime_checkpoint_store.has_checkpoint);
    try std.testing.expect(compositor_checkpoint_store.valid);

    var render_buffer: [RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered = try journey.render(&render_buffer);
    try expectContains(rendered, "control=apply-policy state=done");
    try expectContains(rendered, "control=edit-document state=done");
    try expectContains(rendered, "control=share-document state=done");
    try expectContains(rendered, "control=remove-app state=done");
    try expectContains(rendered, "control=revoke-policy state=done");
    try expectContains(rendered, "document object=");
    try expectContains(rendered, "edited=yes");
    try expectContains(rendered, "task=0 bundle=app.notes.daily");
    try expectContains(rendered, "visible_windows=0");
    try expectContains(rendered, "task_flow_events=14");
    try expectContains(rendered, "share object_scoped=yes write_verified=yes");
    try expectContains(rendered, "sync conflict_count=1 reviewed=yes resolved=yes");
    try expectContains(rendered, "notes_daily_driver complete=yes");
    try expectContains(rendered, boot_markers.notes_daily_driver_complete);

    var export_buffer: [EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "kind=policy_change");
    try expectContains(exported, "kind=device_trust_change");
    try expectContains(exported, "flow_kind=review_permission_request");
    try expectContains(exported, "flow_kind=edit_document");
    try expectContains(exported, "flow_kind=share_document");
    try expectContains(exported, "flow_kind=sync_conflict_review");
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

    var render_buffer: [COMPACT_RENDER_BUFFER_BYTES]u8 = undefined;
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

    var export_buffer: [SMALL_EXPORT_BUFFER_BYTES]u8 = undefined;
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

    var render_buffer: [COMPACT_RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered = try restarted_shell_service.render(&render_buffer);
    try expectContains(rendered, "control=focus-full-screen state=done");
    try expectContains(rendered, "active_type=full_screen_task_view");
    try expectContains(rendered, "active_title=Task: Plan Trip");
    try expectContains(rendered, "task_flow_events=5");
}

test "humane shell composes task-first review pairing snapshots diagnostics notifications keyboard and recovery" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 98 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 981 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 98 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 982 };
    const document_path = "documents/plan.md";
    const user_signer = signing.SignerIdentity{
        .label = "humane-shell-user",
        .seed = signing.seedFromByte(0xb1),
    };
    const device_signer = signing.SignerIdentity{
        .label = "humane-shell-device",
        .seed = signing.seedFromByte(0xb2),
    };
    const snapshot_signer = signing.SignerIdentity{
        .label = "humane-shell-snapshot",
        .seed = signing.seedFromByte(0xb3),
    };

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(9_800, .{ .kind = .service, .serial = 9_800 });

    var storage = storage_service.Service.initWithStore(980, 981, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);

    var sync = sync_service.Service.init(9_810, 9_811, sync_owner);
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

    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(
        9_820,
        9_821,
        &runtime,
        &compositor,
        &compositor_checkpoint_store,
    );
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    var shell_checkpoint_store = HumaneShellCheckpointStore{};
    const config = humane_shell.HumaneShellConfig{
        .user = user,
        .app_owner = user,
        .reviewer_task_id = 79,
        .workspace_id = workspace_id,
        .workspace_label = "Trip Workspace",
        .document_path = document_path,
        .task_label = "trip-planner",
        .task_entry = "app.trip.ui",
        .task_title = "Plan Trip",
        .bundle_id = "app.trip.humane",
        .display_name = "Trip Planner",
        .ui_surface_id = 98,
        .image_id = 98_001,
        .paired_device = paired_device,
        .device_label = "tablet",
        .user_signer = user_signer,
        .device_signer = device_signer,
        .snapshot_label = "before-trip-edit",
        .snapshot_signer = snapshot_signer,
    };
    const accessibility = humane_shell.AccessibilityProfile{
        .high_contrast = true,
    };
    var shell = HumaneShell.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &sync_port,
        sync_authority,
        &notifications,
        &ledger,
        config,
        accessibility,
        &shell_checkpoint_store,
    );

    var render_buffer: [FULL_RENDER_BUFFER_BYTES]u8 = undefined;
    const initial = try shell.render(&render_buffer);
    try expectContains(initial, "task_first=yes");
    try expectContains(initial, "accessibility keyboard=yes screen_reader=yes visible_focus=yes reduce_motion=yes high_contrast=yes");
    try expectContains(initial, "keyboard next=Tab previous=Shift+Tab activate=Enter");
    try expectContains(initial, "control=open-workspace state=blocked");
    try expectContains(initial, "shortcut=W label=Open workspace reason=task required next=start task");
    try expectContains(initial, "label=Deny requested permission and explain why");
    const initial_workspace_guidance = shell.controlGuidance(.open_workspace);
    try std.testing.expectEqual(humane_shell.ControlState.blocked, initial_workspace_guidance.state);
    try std.testing.expectEqualStrings("task required", initial_workspace_guidance.blocked_reason);
    try std.testing.expectEqualStrings("start task", initial_workspace_guidance.next_action);

    const missing_recovery = shell.dispatch(.{ .control = .recover_state, .tick = 18 });
    try std.testing.expectEqual(HumaneShellStatus.recovery_missing, missing_recovery.status);
    const blocked_workspace = shell.dispatch(.{ .control = .open_workspace, .tick = 19 });
    try std.testing.expectEqual(HumaneShellStatus.invalid_order, blocked_workspace.status);
    try std.testing.expectEqual(@as(u64, 0), blocked_workspace.task_id);

    var request_buffer: [WIRE_BUFFER_BYTES]u8 = undefined;
    var response_buffer: [WIRE_BUFFER_BYTES]u8 = undefined;
    try std.testing.expectError(error.MalformedRequest, humane_shell_wire.decodeRequest("bad"));
    try std.testing.expectError(error.RequestTooLarge, humane_shell_wire.encodeRequest(request_buffer[0..4], .{}));
    const next_payload = try humane_shell_wire.encodeRequest(&request_buffer, .{ .operation = .keyboard, .keyboard = .next, .tick = 20 });
    const decoded_next_request = try humane_shell_wire.decodeRequest(next_payload);
    try std.testing.expectEqual(humane_shell.HumaneShellOperation.keyboard, decoded_next_request.operation);
    try std.testing.expectEqual(humane_shell.KeyboardIntent.next, decoded_next_request.keyboard);
    const next_focus = try humane_shell_wire.decodeResponse(try humane_shell_wire.dispatchPayload(&shell, next_payload, &response_buffer));
    try std.testing.expectEqual(HumaneShellStatus.ok, next_focus.status);
    try std.testing.expectEqual(HumaneShellControl.open_workspace, next_focus.focused_control);
    const previous_focus = shell.dispatch(.{ .operation = .keyboard, .keyboard = .previous, .tick = 21 });
    try std.testing.expectEqual(HumaneShellStatus.ok, previous_focus.status);
    try std.testing.expectEqual(HumaneShellControl.start_task, previous_focus.focused_control);
    const start_response = shell.dispatch(.{ .operation = .keyboard, .keyboard = .activate, .tick = 22 });
    try std.testing.expectEqual(HumaneShellStatus.ok, start_response.status);
    const task_id = start_response.task_id;
    try std.testing.expect(task_id != 0);

    try shell.click(.open_workspace, 23);
    try shell.click(.open_document, 24);
    try shell.click(.review_permission, 25);
    try shell.click(.deny_permission, 26);
    const denied_allow_guidance = shell.controlGuidance(.allow_permission);
    try std.testing.expectEqual(humane_shell.ControlState.blocked, denied_allow_guidance.state);
    try std.testing.expectEqualStrings("permission already decided", denied_allow_guidance.blocked_reason);
    try std.testing.expectEqualStrings("continue", denied_allow_guidance.next_action);
    const missing_snapshot = shell.dispatch(.{ .control = .rollback_snapshot, .tick = 27 });
    try std.testing.expectEqual(HumaneShellStatus.invalid_order, missing_snapshot.status);
    try std.testing.expectEqual(@as(u64, 0), missing_snapshot.snapshot_id);
    const rollback_guidance = shell.controlGuidance(.rollback_snapshot);
    try std.testing.expectEqual(humane_shell.ControlState.blocked, rollback_guidance.state);
    try std.testing.expectEqualStrings("snapshot required", rollback_guidance.blocked_reason);
    try std.testing.expectEqualStrings("create snapshot", rollback_guidance.next_action);
    try shell.click(.pair_device, 28);
    try shell.click(.create_snapshot, 29);
    try shell.click(.rollback_snapshot, 30);
    try shell.click(.run_diagnostics, 31);
    const notify_payload = try humane_shell_wire.encodeRequest(&request_buffer, .{ .control = .post_notification, .tick = 32 });
    const notify_response = try humane_shell_wire.decodeResponse(try humane_shell_wire.dispatchPayload(&shell, notify_payload, &response_buffer));
    try std.testing.expectEqual(HumaneShellStatus.ok, notify_response.status);
    try std.testing.expectEqual(@as(u16, 4), notify_response.notification_events);
    try std.testing.expectError(error.ResponseTooLarge, humane_shell_wire.encodeResponse(response_buffer[0..4], notify_response));

    try std.testing.expect(sync.isTrustedDevice(paired_device));
    try std.testing.expect(shell.state.snapshot_id != 0);
    try std.testing.expect(shell.state.remote_diagnostics_require_opt_in);
    try std.testing.expectEqual(@as(usize, 6), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .permission_review }));
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .permission_decision }));
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .device_trust_change }));
    try std.testing.expectEqual(@as(usize, 4), ledger.countMatching(.{ .kind = .notification }));

    const rendered = try shell.render(&render_buffer);
    try expectContains(rendered, "control=deny-permission state=done");
    try expectContains(rendered, "control=allow-permission state=blocked");
    try expectContains(rendered, "reason=permission already decided next=continue");
    try expectContains(rendered, "permission reviewed=yes denied=yes");
    try expectContains(rendered, "denial reason=policy_denied policy=user-grant-policy missing=object-access-capability approval=yes retry_safe=no");
    try expectContains(rendered, "device paired=yes trusted=yes label=tablet");
    try expectContains(rendered, "snapshot id=");
    try expectContains(rendered, "label=before-trip-edit restored=yes");
    try expectContains(rendered, "diagnostics ran=yes");
    try expectContains(rendered, "remote_share_requires_opt_in=yes");
    try expectContains(rendered, "diagnostics user_visible=yes privacy=redacted evidence_of_intrusion_capable=yes");
    try expectContains(rendered, "diagnostic_evidence capability_denials=1");
    try expectContains(rendered, "notification id=");
    try expectContains(rendered, "reason=policy_notice detail=shell status available");
    try expectContains(rendered, "recovery checkpoint=yes recovered=no");

    var restarted_runtime = task_runtime.Runtime.init();
    var restarted_runtime_service = task_runtime_service.Service.initWithStore(&restarted_runtime, &runtime_checkpoint_store);
    restarted_runtime_service.bind(9_800, .{ .kind = .service, .serial = 9_800 });
    var restarted_compositor = compositor_session.Session.init();
    var restarted_compositor_service = compositor_session.Service.initWithCheckpoint(
        9_820,
        9_821,
        &restarted_runtime,
        &restarted_compositor,
        &compositor_checkpoint_store,
    );
    var restarted_shell = HumaneShell.init(
        &restarted_runtime_service,
        &ux,
        &restarted_compositor_service,
        &storage,
        &sync_port,
        sync_authority,
        &notifications,
        &ledger,
        config,
        accessibility,
        &shell_checkpoint_store,
    );
    try restarted_shell.click(.recover_state, 40);
    try std.testing.expect(restarted_runtime.find(task_id) != null);
    try std.testing.expectEqual(@as(usize, 3), restarted_compositor.window_count);
    try std.testing.expectEqual(@as(usize, 7), ledger.countMatching(.{ .kind = .task_flow }));

    const recovered = try restarted_shell.render(&render_buffer);
    try expectContains(recovered, "recovery checkpoint=yes recovered=yes");
    try expectContains(recovered, "task_flow_events=7");
    try expectContains(recovered, "active_type=app_panel");
}

test "humane shell exposes object-native query history sharing capabilities and conflict review" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 100 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 1_001 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 100 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 1_002 };
    const document_path = "exports/plan.md";
    const user_signer = signing.SignerIdentity{
        .label = "object-shell-user",
        .seed = signing.seedFromByte(0xd1),
    };
    const device_signer = signing.SignerIdentity{
        .label = "object-shell-device",
        .seed = signing.seedFromByte(0xd2),
    };
    const snapshot_signer = signing.SignerIdentity{
        .label = "object-shell-snapshot",
        .seed = signing.seedFromByte(0xd3),
    };

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(10_000, .{ .kind = .service, .serial = 10_000 });

    var storage = storage_service.Service.initWithStore(10_001, 10_002, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);

    var sync = sync_service.Service.init(10_010, 10_011, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try mintRenderedShellServiceAuthority(&sync_capabilities, sync.service_id, sync_owner, sync.task_id);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync.task_id,
        .principal = sync_owner,
        .capability_id = sync_capability.id,
        .now_ticks = 12,
    };
    try sync.recordConflict(
        workspace_id,
        paired_device,
        92_001,
        document_path,
        storage.latestVersion(92_001).?.id.raw(),
        88_001,
        .mergeable_crdt,
    );

    var object_capabilities = capability.CapabilityTable.init();
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(
        10_020,
        10_021,
        &runtime,
        &compositor,
        &compositor_checkpoint_store,
    );
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    var shell_checkpoint_store = HumaneShellCheckpointStore{};
    const config = humane_shell.HumaneShellConfig{
        .user = user,
        .app_owner = user,
        .reviewer_task_id = 81,
        .workspace_id = workspace_id,
        .workspace_label = "Object Workspace",
        .document_path = document_path,
        .task_label = "object-planner",
        .task_entry = "app.object.ui",
        .task_title = "Object Plan",
        .bundle_id = "app.object.shell",
        .display_name = "Object Planner",
        .ui_surface_id = 100,
        .image_id = 100_001,
        .object_query_label = "rendered shell",
        .object_capability_table = &object_capabilities,
        .paired_device = paired_device,
        .device_label = "tablet",
        .user_signer = user_signer,
        .device_signer = device_signer,
        .snapshot_signer = snapshot_signer,
    };
    var shell = HumaneShell.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &sync_port,
        sync_authority,
        &notifications,
        &ledger,
        config,
        .{},
        &shell_checkpoint_store,
    );

    try shell.click(.start_task, 20);
    const query_response = shell.dispatch(.{ .control = .query_objects, .tick = 21 });
    try std.testing.expectEqual(HumaneShellStatus.ok, query_response.status);
    try std.testing.expectEqual(@as(u16, 1), query_response.object_query_count);
    try std.testing.expectEqual(@as(u64, 92_001), query_response.selected_object_id);

    try shell.click(.open_object, 22);
    try shell.click(.show_object_history, 23);
    try shell.click(.mint_object_capability, 24);
    try shell.click(.share_object, 25);
    try shell.click(.review_object_conflict, 26);

    try std.testing.expect(shell.state.object_opened);
    try std.testing.expectEqual(@as(u16, 1), shell.state.object_history_count);
    try std.testing.expect(shell.state.object_capability_id != 0);
    try std.testing.expect(shell.state.object_shared);
    try std.testing.expect(shell.state.object_conflict_reviewed);
    try std.testing.expect(shell.state.object_conflict_resolved);
    var minted_buffer: [2]capability.Capability = undefined;
    const minted_object_caps = object_capabilities.queryByTarget(.{ .kind = .object, .id = 92_001 }, &minted_buffer);
    try std.testing.expectEqual(@as(usize, 1), minted_object_caps.len);
    try std.testing.expectEqual(capability.CapabilityTargetKind.object, minted_object_caps[0].target.kind);
    try std.testing.expect(storage.findShareGrant(workspace_id, paired_device).?.isObjectScoped());
    try std.testing.expect(sync.findConflictForObject(workspace_id, paired_device, 92_001) == null);
    try std.testing.expectEqual(compositor_session.ViewType.sync_conflict_review, compositor.windowAtOrder(1).?.view_type);

    var render_buffer: [FULL_RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered = try shell.render(&render_buffer);
    try expectContains(rendered, "object_model first_class=yes file_bridge=export-import-only");
    try expectContains(rendered, "object_query count=1 selected=92001 opened=yes capability=");
    try expectContains(rendered, "object[0] id=92001");
    try expectContains(rendered, "object_history count=1");
    try expectContains(rendered, "object_conflict reviewed=yes resolved=yes");
}

test "booted rendered system runs input loop compositor prompts task switching recovery and readable errors" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 99 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 991 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 99 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 992 };
    const document_path = "documents/plan.md";
    const user_signer = signing.SignerIdentity{
        .label = "booted-shell-user",
        .seed = signing.seedFromByte(0xc1),
    };
    const device_signer = signing.SignerIdentity{
        .label = "booted-shell-device",
        .seed = signing.seedFromByte(0xc2),
    };
    const snapshot_signer = signing.SignerIdentity{
        .label = "booted-shell-snapshot",
        .seed = signing.seedFromByte(0xc3),
    };

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(9_900, .{ .kind = .service, .serial = 9_900 });

    var storage = storage_service.Service.initWithStore(990, 991, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);

    var sync = sync_service.Service.init(9_910, 9_911, sync_owner);
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

    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(
        9_920,
        9_921,
        &runtime,
        &compositor,
        &compositor_checkpoint_store,
    );
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    var shell_checkpoint_store = HumaneShellCheckpointStore{};
    const config = humane_shell.HumaneShellConfig{
        .user = user,
        .app_owner = user,
        .reviewer_task_id = 80,
        .workspace_id = workspace_id,
        .workspace_label = "Trip Workspace",
        .document_path = document_path,
        .task_label = "trip-planner",
        .task_entry = "app.trip.ui",
        .task_title = "Plan Trip",
        .bundle_id = "app.trip.booted",
        .display_name = "Trip Planner",
        .ui_surface_id = 99,
        .image_id = 99_001,
        .paired_device = paired_device,
        .device_label = "tablet",
        .user_signer = user_signer,
        .device_signer = device_signer,
        .snapshot_label = "before-booted-recovery",
        .snapshot_signer = snapshot_signer,
    };
    const accessibility = humane_shell.AccessibilityProfile{
        .visible_focus = true,
        .reduce_motion = true,
        .high_contrast = true,
    };
    var shell = HumaneShell.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &sync_port,
        sync_authority,
        &notifications,
        &ledger,
        config,
        accessibility,
        &shell_checkpoint_store,
    );
    var system = BootedSystem.init(&shell);

    var render_buffer: [FULL_RENDER_BUFFER_BYTES]u8 = undefined;
    const cold = try system.render(&render_buffer);
    try expectContains(cold, "boot_phase=cold input_loop=stopped");

    const preboot = system.dispatchInput(.{ .kind = .open_workspace, .tick = 9 });
    try std.testing.expect(!preboot.accepted);
    try std.testing.expectEqual(HumaneShellStatus.invalid_order, preboot.status);
    const preboot_rendered = try system.render(&render_buffer);
    try expectContains(preboot_rendered, "error_surface visible=yes status=invalid_order");
    try expectContains(preboot_rendered, "summary=action blocked by current shell state");

    const booted = system.dispatchInput(.{ .kind = .boot, .tick = 10 });
    try std.testing.expect(booted.accepted);
    try std.testing.expectEqual(booted_system.BootPhase.running, booted.phase);
    const blocked = system.dispatchInput(.{ .kind = .open_workspace, .tick = 11 });
    try std.testing.expect(!blocked.accepted);
    try std.testing.expectEqual(HumaneShellStatus.invalid_order, blocked.status);
    const blocked_rendered = try system.render(&render_buffer);
    try expectContains(blocked_rendered, "cause=task required next=start task");

    const inputs = [_]ShellInput{
        .{ .kind = .start_task, .tick = 12 },
        .{ .kind = .open_workspace, .tick = 13 },
        .{ .kind = .open_document, .tick = 14 },
        .{ .kind = .review_permission, .tick = 15 },
    };
    const reviewed = system.runInputLoop(&inputs);
    try std.testing.expect(reviewed.accepted);
    try std.testing.expectEqual(@as(u16, 3), reviewed.visible_window_count);
    try std.testing.expectEqual(compositor.windowAtOrder(2).?.id, reviewed.active_window_id);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);

    const review_rendered = try system.render(&render_buffer);
    try expectContains(review_rendered, "boot_phase=running input_loop=running");
    try expectContains(review_rendered, "accessibility keyboard=yes screen_reader=yes visible_focus=yes reduce_motion=yes high_contrast=yes");
    try expectContains(review_rendered, "window[2] id=3 type=app_panel active=yes modal=yes");
    try expectContains(review_rendered, "permission_prompt state=pending window=3 decision=pending resource=documents/plan.md local_only=yes lease_ticks=240");
    try expectContains(review_rendered, "notifications active=1");
    try expectContains(review_rendered, "error_surface visible=no status=ok");

    const switched = system.dispatchInput(.{ .kind = .task_switch_next, .tick = 16 });
    try std.testing.expect(switched.accepted);
    try std.testing.expectEqual(compositor.windowAtOrder(0).?.id, switched.active_window_id);
    const switched_rendered = try system.render(&render_buffer);
    try expectContains(switched_rendered, "task_switcher visible=yes index=0 active_window=1");
    try expectContains(switched_rendered, "window[0] id=1 type=workspace_view active=yes");

    const denied = system.dispatchInput(.{ .kind = .deny_permission, .tick = 17 });
    try std.testing.expect(denied.accepted);
    const denied_rendered = try system.render(&render_buffer);
    try expectContains(denied_rendered, "permission_prompt state=denied window=3 decision=deny resource=documents/plan.md");
    try expectContains(denied_rendered, "permission_error reason=policy_denied policy=user-grant-policy missing=object-access-capability");

    const recovery_opened = system.dispatchInput(.{ .kind = .show_recovery, .tick = 18 });
    try std.testing.expect(recovery_opened.accepted);
    try std.testing.expectEqual(booted_system.BootPhase.recovery, recovery_opened.phase);
    try std.testing.expect(system.dispatchInput(.{ .kind = .create_snapshot, .tick = 19 }).accepted);
    try std.testing.expect(system.dispatchInput(.{ .kind = .run_diagnostics, .tick = 20 }).accepted);
    const recovered = system.dispatchInput(.{ .kind = .recover_state, .tick = 21 });
    try std.testing.expect(recovered.accepted);
    try std.testing.expectEqual(booted_system.BootPhase.recovery, recovered.phase);
    try std.testing.expectEqual(@as(u32, 1), runtime_service.restart_generation);

    const recovered_rendered = try system.render(&render_buffer);
    try expectContains(recovered_rendered, "recovery_ui visible=yes checkpoint=yes recovered=yes runtime_checkpoint=yes restart_generation=1");
    try expectContains(recovered_rendered, "notifications active=");
    try expectContains(recovered_rendered, "latest_id=");
    try expectContains(recovered_rendered, "detail=local diagnostics ready");
    try expectContains(recovered_rendered, "diagnostics user_visible=yes privacy=redacted evidence_of_intrusion_capable=yes");
    try expectContains(recovered_rendered, "diagnostic_evidence capability_denials=1");
    try expectContains(recovered_rendered, "error_surface visible=no status=ok");
}

test "booted notes docs loop edits shares syncs reviews rollback recovery and removes package" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 110 };
    const package_owner = principal.PrincipalId{ .kind = .service, .serial = 111 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 112 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 110 };
    const primary_device = principal.PrincipalId{ .kind = .device, .serial = 1_101 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 1_102 };
    const document_path = "documents/notes.md";
    const notes_signer = signing.SignerIdentity{
        .label = "booted-notes-bundle",
        .seed = signing.seedFromByte(0xe1),
    };
    const user_signer = signing.SignerIdentity{
        .label = "booted-notes-user",
        .seed = signing.seedFromByte(0xe2),
    };
    const primary_signer = signing.SignerIdentity{
        .label = "booted-notes-primary",
        .seed = signing.seedFromByte(0xe3),
    };
    const paired_signer = signing.SignerIdentity{
        .label = "booted-notes-paired",
        .seed = signing.seedFromByte(0xe4),
    };
    const snapshot_signer = signing.SignerIdentity{
        .label = "booted-notes-snapshot",
        .seed = signing.seedFromByte(0xe5),
    };

    var package_capabilities = capability.CapabilityTable.init();
    var packages_service = package_service.Service.init();
    packages_service.bind(11_100, package_owner);
    var package_port = package_service.PackagePort.init(&packages_service, &package_capabilities);
    const package_capability = try mintRenderedShellServiceAuthority(&package_capabilities, packages_service.service_id, package_owner, 11_101);
    const package_authority = package_service.AuthorityContext{
        .task_id = 11_101,
        .principal = package_owner,
        .capability_id = package_capability.id,
        .now_ticks = 10,
    };
    _ = try package_port.trustPolicyAuthorityRoot(package_authority, .{ .kind = .policy_authority, .serial = 1 }, signing.publicKeyFromByte(0x5A));
    _ = try package_port.trustPublisher(
        package_authority,
        .{ .kind = .app, .serial = 11_102 },
        .{ .kind = .policy_authority, .serial = 1 },
        "zigos.dev",
        try signing.publicKey(notes_signer),
    );
    var notes_bundle = manifest_fixtures.notesBundle();
    notes_bundle.signature = try signReleaseBundle(notes_signer, notes_bundle);
    _ = try package_port.install(package_authority, .{
        .bundle = notes_bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);
    try std.testing.expect(packages_service.find("app.notes") != null);

    var storage = storage_service.Service.initWithStore(11_110, 11_111, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);
    const original_entry = try storage.resolve(workspace_id, document_path);
    const original_version_id = original_entry.version_id.raw();

    var sync = sync_service.Service.init(11_120, 11_121, sync_owner);
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
        .label = "notes-local",
        .mode = .local_network,
    });
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .require_shared_access = true,
        .selective_prefixes = &.{"documents/"},
        .device_to_device_policy_id = local_policy.id,
    });

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(11_130, .{ .kind = .service, .serial = 11_130 });
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(
        11_131,
        11_132,
        &runtime,
        &compositor,
        &compositor_checkpoint_store,
    );
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    var shell_checkpoint_store = HumaneShellCheckpointStore{};
    const config = humane_shell.HumaneShellConfig{
        .user = user,
        .app_owner = user,
        .reviewer_task_id = 83,
        .workspace_id = workspace_id,
        .workspace_label = "Notes Workspace",
        .document_path = document_path,
        .task_label = "notes",
        .task_entry = "app.notes",
        .task_title = "Notes",
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .ui_surface_id = 110,
        .image_id = 110_001,
        .object_query_label = document_path,
        .sync_from_device = primary_device,
        .sync_to_device = paired_device,
        .package_port = &package_port,
        .package_authority = package_authority,
        .paired_device = paired_device,
        .device_label = "tablet",
        .user_signer = user_signer,
        .device_signer = paired_signer,
        .snapshot_label = "before-notes-edit",
        .snapshot_signer = snapshot_signer,
    };
    var shell = HumaneShell.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &sync_port,
        sync_authority,
        &notifications,
        &ledger,
        config,
        .{},
        &shell_checkpoint_store,
    );
    var system = BootedSystem.init(&shell);

    try std.testing.expect(system.dispatchInput(.{ .kind = .boot, .tick = 20 }).accepted);
    try std.testing.expect(system.dispatchInput(.{ .kind = .start_task, .tick = 21 }).accepted);
    const task_id = shell.state.task_id;
    try std.testing.expect(task_id != 0);
    try std.testing.expect(system.dispatchInput(.{ .kind = .open_workspace, .tick = 22 }).accepted);
    try std.testing.expect(system.dispatchInput(.{ .kind = .open_document, .tick = 23 }).accepted);
    try std.testing.expectEqual(original_version_id, shell.state.document_version_id);
    try std.testing.expect(system.dispatchInput(.{ .kind = .create_snapshot, .tick = 24 }).accepted);

    const edited = system.dispatchInput(.{
        .kind = .text_input,
        .tick = 25,
        .text = "booted notes edit: product feels tangible",
    });
    try std.testing.expect(edited.accepted);
    try std.testing.expect(shell.state.document_edited);
    try std.testing.expect(shell.state.document_version_id != original_version_id);

    try std.testing.expect(system.dispatchInput(.{ .kind = .query_objects, .tick = 26 }).accepted);
    try std.testing.expect(system.dispatchInput(.{ .kind = .show_object_history, .tick = 27 }).accepted);
    try std.testing.expectEqual(@as(u16, 2), shell.state.object_history_count);
    try std.testing.expect(system.dispatchInput(.{ .kind = .share_object, .tick = 28 }).accepted);
    try std.testing.expect(storage.findShareGrant(workspace_id, paired_device).?.isObjectScoped());

    const synced = system.dispatchInput(.{ .kind = .sync_document, .tick = 29 });
    try std.testing.expect(synced.accepted);
    try std.testing.expect(shell.state.document_synced);
    try std.testing.expectEqual(@as(u16, 1), shell.state.sync_selected_entries);
    try std.testing.expectEqual(@as(u16, 1), shell.state.sync_transport_frames);

    var render_buffer: [FULL_RENDER_BUFFER_BYTES]u8 = undefined;
    const synced_rendered = try system.render(&render_buffer);
    try expectContains(synced_rendered, "document_text=booted notes edit: product feels tangible");

    const recovered_after_sync = system.dispatchInput(.{ .kind = .recover_state, .tick = 30 });
    try std.testing.expect(recovered_after_sync.accepted);
    try std.testing.expect(shell.state.recovered);
    try std.testing.expectEqual(@as(u32, 1), runtime_service.restart_generation);
    try std.testing.expectEqualStrings("booted notes edit: product feels tangible", shell.documentTextSlice());

    try sync.recordConflict(
        workspace_id,
        paired_device,
        shell.state.selected_object_id,
        document_path,
        shell.state.document_version_id,
        shell.state.document_version_id + 1_000,
        .mergeable_crdt,
    );
    try std.testing.expect(system.dispatchInput(.{ .kind = .review_object_conflict, .tick = 31 }).accepted);
    try std.testing.expect(shell.state.object_conflict_reviewed);
    try std.testing.expect(shell.state.object_conflict_resolved);
    try std.testing.expect(sync.findConflictForObject(workspace_id, paired_device, shell.state.selected_object_id) == null);

    try std.testing.expect(system.dispatchInput(.{ .kind = .rollback_snapshot, .tick = 32 }).accepted);
    try std.testing.expect(shell.state.snapshot_restored);
    try std.testing.expectEqual(original_version_id, shell.state.document_version_id);

    const recovered = system.dispatchInput(.{ .kind = .recover_state, .tick = 33 });
    try std.testing.expect(recovered.accepted);
    try std.testing.expect(shell.state.recovered);
    try std.testing.expectEqual(@as(u32, 2), runtime_service.restart_generation);

    const removed = system.dispatchInput(.{ .kind = .remove_package, .tick = 34 });
    try std.testing.expect(removed.accepted);
    try std.testing.expect(shell.state.package_removed);
    try std.testing.expect(packages_service.find("app.notes") == null);
    try std.testing.expectEqual(task_runtime.TaskState.terminated, runtime.find(task_id).?.state);
    try std.testing.expectEqual(@as(usize, 0), compositor.visibleWindowCount());

    const rendered = try system.render(&render_buffer);
    try expectContains(rendered, "document_loop opened=no edited=no version=");
    try expectContains(rendered, "synced=no sync_selected=1 frames=1 conflicts=0 object_shared=yes conflict_reviewed=yes package_removed=yes");
    try expectContains(rendered, "recovery_ui visible=yes checkpoint=yes recovered=yes");
    try expectContains(rendered, "compositor active_window=0");

    var shell_render_buffer: [FULL_RENDER_BUFFER_BYTES]u8 = undefined;
    const shell_rendered = try shell.render(&shell_render_buffer);
    try expectContains(shell_rendered, "package bundle=app.notes removed=yes removed_revisions=1");
    try expectContains(shell_rendered, "snapshot id=");
    try expectContains(shell_rendered, "label=before-notes-edit restored=yes");

    var export_buffer: [EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "flow_kind=edit_document");
    try expectContains(exported, "flow_kind=share_document");
    try expectContains(exported, "flow_kind=sync_workspace");
    try expectContains(exported, "flow_kind=sync_conflict_review");
    try expectContains(exported, "flow_kind=remove_app");
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
