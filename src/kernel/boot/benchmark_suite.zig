const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const abi = @import("../../native/core/abi.zig");
const console = @import("../utils/console.zig");
const qemu_exit = @import("../utils/qemu_exit.zig");
const boot_markers = @import("markers.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const principal = @import("../../native/core/principal.zig");
const signing = @import("../../native/core/signing.zig");
const manifest = @import("../../native/policy/manifest.zig");
const denial_explanation = @import("../../native/policy/denial_explanation.zig");
const permission_review = @import("../../native/policy/permission_review.zig");
const policy_mediation = @import("../../native/policy/policy_mediation.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const background_dispatch = @import("../../native/task/background_dispatch.zig");
const accelerator_scheduler = @import("../../native/task/accelerator_scheduler.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const sync_service = @import("../../native/sync/sync_service.zig");
const workspace = @import("../../native/storage/workspace.zig");
const file_bridge = @import("../../native/storage/file_bridge.zig");
const object_store = @import("../../native/storage/object_store.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const package_service = @import("../../native/services/package_service.zig");
const package_service_bundle_ops = @import("../../native/services/package_service_bundle_ops.zig");
const indexing_service = @import("../../native/services/indexing_service.zig");
const notification_center = @import("../../native/services/notification_center.zig");
const media_print_service = @import("../../native/services/media_print_service.zig");
const compatibility_environment = @import("../../native/services/compatibility_environment.zig");
const compositor_session = @import("../../native/platform/compositor_session.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const immutable_base = @import("../../native/platform/immutable_base.zig");
const recovery_environment = @import("../../native/platform/recovery_environment.zig");
const secure_secret_store = @import("../../native/platform/secure_secret_store.zig");
const update_health = @import("../../native/platform/update_health.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const contract = @import("../../native/session/contract.zig");
const supervisor_mod = @import("../../native/session/supervisor.zig");

const BenchmarkCase = struct {
    name: []const u8,
    iterations: u32,
    runIteration: *const fn (iteration: u32) u64,
};

const FileBridgeContext = struct {
    expected_workspace_id: u64 = 0,
    expected_path: []const u8 = "",
    expected_version_id: u64 = 0,
    entry: workspace.Entry = .{},
    version_present: bool = false,
    capability_table: capability.CapabilityTable = capability.CapabilityTable.init(),
    bridge: ?file_bridge.Bridge = null,
    authority_capability_id: u64 = 0,
    requester: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
};

const PermissionReviewContext = struct {
    decisions: [2]permission_review.ReviewDecision = undefined,
};

const NetworkPolicyContext = struct {
    directory: network_policy.Directory = network_policy.Directory.init(),
    policy_id: u64 = 0,
    evidence: network_policy.ConnectionEvidence = .{ .destination = .{ .public_internet = {} } },
};

const BackgroundContext = struct {
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    dispatcher: background_dispatch.Controller = background_dispatch.Controller.init(),
};

const WorkspaceCommitContext = struct {
    baseline: workspace.Directory = workspace.Directory.init(),
    workspace_id: u64 = 0,
};

const TaskCheckpointContext = struct {
    source_runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    restored_runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    snapshot: task_runtime.Snapshot = task_runtime.Runtime.initSnapshot(),
    primary_task_id: u64 = 0,
    secondary_task_id: u64 = 0,
};

const PackageContext = struct {
    service: package_service.Service = package_service.Service.init(),
    resolved: package_service.ResolvedManifest = undefined,
};

const IndexingContext = struct {
    service: indexing_service.Service = indexing_service.Service.init(),
    results: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined,
};

const MediaContext = struct {
    scheduler: accelerator_scheduler.Controller = accelerator_scheduler.Controller.init(),
    notifications: notification_center.Center = notification_center.Center.init(),
    service: media_print_service.Service = media_print_service.Service.init(),
};

const CompatibilityContext = struct {
    manager: compatibility_environment.Manager = compatibility_environment.Manager.init(),
};

const EventLedgerContext = struct {
    ledger: event_ledger.Ledger = event_ledger.Ledger.init(),
};

const SecretStoreContext = struct {
    store: secure_secret_store.Store = secure_secret_store.Store.init(),
    owner: principal.PrincipalId = .{ .kind = .user, .serial = 61 },
    holder: principal.PrincipalId = .{ .kind = .app, .serial = 62 },
};

const OverlaySessionContext = struct {
    service: sync_service.Service = sync_service.Service.init(930, 71, .{ .kind = .service, .serial = 33 }),
    workspace_id: u64 = 0,
    source_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    target_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
};

const RecoveryContext = struct {
    checkpoint_store: storage_service.CheckpointStore = .{},
    storage: storage_service.Service = undefined,
    manager: immutable_base.Manager = undefined,
    sync: sync_service.Service = undefined,
    environment: recovery_environment.Environment = undefined,
    workspace_id: u64 = 0,
    snapshot_id: u64 = 0,
    user: principal.PrincipalId = .{ .kind = .user, .serial = 1 },
    primary_device: principal.PrincipalId = .{ .kind = .device, .serial = 21 },
    tablet: principal.PrincipalId = .{ .kind = .device, .serial = 22 },
};

const UpdateHealthContext = struct {
    checkpoint_store: storage_service.CheckpointStore = .{},
    storage: storage_service.Service = undefined,
    manager: immutable_base.Manager = undefined,
    sync: sync_service.Service = undefined,
    compositor: compositor_session.Session = compositor_session.Session.init(),
    supervisor: supervisor_mod.Supervisor = supervisor_mod.Supervisor.init(),
    ledger: event_ledger.Ledger = event_ledger.Ledger.init(),
    core_service_ids: [3]u64 = [_]u64{0} ** 3,
    request: update_health.CheckRequest = undefined,
};

const cases = [_]BenchmarkCase{
    .{ .name = "capability.derive.workspace_object", .iterations = 40_000, .runIteration = benchmarkCapabilityDerive },
    .{ .name = "permission.review.render_grants", .iterations = 12_000, .runIteration = benchmarkPermissionReviewRender },
    .{ .name = "network_policy.authorize_connection", .iterations = 60_000, .runIteration = benchmarkNetworkPolicyAuthorize },
    .{ .name = "background_dispatch.allowed_sync", .iterations = 8_000, .runIteration = benchmarkBackgroundDispatch },
    .{ .name = "task_runtime.checkpoint.write_restore", .iterations = 8_000, .runIteration = benchmarkTaskCheckpointWriteRestore },
    .{ .name = "accelerator_scheduler.claim_release", .iterations = 25_000, .runIteration = benchmarkAcceleratorClaimRelease },
    .{ .name = "storage.file_bridge.resolve_view", .iterations = 40_000, .runIteration = benchmarkFileBridgeResolve },
    .{ .name = "storage.workspace.commit_overlay", .iterations = 12_000, .runIteration = benchmarkWorkspaceCommitOverlay },
    .{ .name = "package_revision.rollforward_rollback", .iterations = 20_000, .runIteration = benchmarkPackageRevision },
    .{ .name = "indexing_service.query_ranked", .iterations = 20_000, .runIteration = benchmarkIndexingQuery },
    .{ .name = "media_print.submit_complete", .iterations = 8_000, .runIteration = benchmarkMediaPrintSubmitComplete },
    .{ .name = "compatibility_environment.launch_portal", .iterations = 12_000, .runIteration = benchmarkCompatibilityLaunchPortal },
    .{ .name = "event_ledger.export_redacted", .iterations = 4_000, .runIteration = benchmarkEventLedgerExport },
    .{ .name = "secret_store.import_handle_export", .iterations = 20_000, .runIteration = benchmarkSecretStoreImportHandleExport },
    .{ .name = "denial_explanation.render_policy_hint", .iterations = 32_000, .runIteration = benchmarkDenialExplanationRender },
    .{ .name = "sync_service.overlay_session_flow", .iterations = 8_000, .runIteration = benchmarkOverlaySessionFlow },
    .{ .name = "recovery_environment.reinstall_restore_repair", .iterations = 4, .runIteration = benchmarkRecoveryLifecycle },
    .{ .name = "update_health.validate_pending_activation", .iterations = 8, .runIteration = benchmarkUpdateHealthValidation },
    .{ .name = "driver_recovery.restart_driver", .iterations = 512, .runIteration = benchmarkDriverRecoveryRestart },
};

const permission_review_requests = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://trip/documents/plan.md",
        .rights = .{ .object = .{
            .object_read = true,
            .object_write = true,
        } },
        .local_only = true,
        .max_lease_ticks = 400,
    },
    .{
        .kind = .network_egress,
        .resource = "https://api.example.com",
        .rights = .{ .network_policy = .{
            .network_remote = true,
        } },
        .required = false,
        .max_lease_ticks = 60,
    },
};

const permission_review_bundle = manifest.BundleManifest{
    .bundle_id = "app.trip",
    .display_name = "Trip Planner",
    .publisher = "zigos.spec",
    .requested_permissions = &permission_review_requests,
};

const background_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "sync", .entry = "app.sync" },
};

const background_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .background_execution,
        .resource = "sync",
        .rights = .{ .task = .{ .background_run = true } },
    },
};

const background_tasks = [_]manifest.BackgroundTaskDecl{
    .{
        .id = "sync",
        .trigger = .sync_completion,
        .expected_duration_seconds = 40,
        .budget = .{
            .cpu_time_ticks = 1_100,
            .memory_bytes = 96 * 1024,
        },
        .network = .local_network_only,
        .visibility = .status_only,
    },
};

const background_bundle = manifest.BundleManifest{
    .bundle_id = "app.background.spec",
    .display_name = "Background Spec",
    .publisher = "zigos.spec",
    .components = &background_components,
    .requested_permissions = &background_permissions,
    .background_tasks = &background_tasks,
    .update_channel = .stable,
};

const package_v1_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://notes",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
    },
};

const package_v2_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://notes",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
    },
    .{
        .kind = .network_egress,
        .resource = "relay.notes.example",
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .required = false,
    },
};

const package_v1_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
};

const package_v2_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
    .{ .id = "notes-sync", .entry = "zigos.notes.sync", .abi = .native_sandbox },
};

const package_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.workspace.document" },
    .{ .name = "zigos.object.workspace" },
};

const package_v1_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
};

const package_v2_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    .{ .path = "assets/editor.css", .content_type = "text/css" },
};

const package_bundle_v1 = manifest.BundleManifest{
    .bundle_id = "app.notes",
    .display_name = "Notes",
    .publisher = "Example Software",
    .version_major = 1,
    .version_minor = 0,
    .provided_interfaces = package_interfaces[0..1],
    .consumed_interfaces = package_interfaces[1..2],
    .components = &package_v1_components,
    .assets = &package_v1_assets,
    .requested_permissions = &package_v1_permissions,
    .update_channel = .stable,
    .signature = .{
        .signer = "bench-package",
    },
};

const package_bundle_v2 = manifest.BundleManifest{
    .bundle_id = "app.notes",
    .display_name = "Notes",
    .publisher = "Example Software",
    .version_major = 1,
    .version_minor = 1,
    .provided_interfaces = package_interfaces[0..1],
    .consumed_interfaces = package_interfaces[1..2],
    .components = &package_v2_components,
    .assets = &package_v2_assets,
    .requested_permissions = &package_v2_permissions,
    .update_channel = .stable,
    .signature = .{
        .signer = "bench-package",
    },
};

const compatibility_bundle = manifest.BundleManifest{
    .bundle_id = "app.legacy.workbench",
    .display_name = "Legacy Workbench",
    .publisher = "Example Software",
    .signature = .{
        .signer = "bench-compat",
    },
};

var permission_review_buffer: [2048]u8 = undefined;
var permission_review_grants: [permission_review.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
var event_ledger_buffer: [2048]u8 = undefined;
var denial_explanation_buffer: [192]u8 = undefined;

var file_bridge_context = FileBridgeContext{};
var permission_review_context = PermissionReviewContext{};
var network_policy_context = NetworkPolicyContext{};
var background_context = BackgroundContext{};
var workspace_commit_context = WorkspaceCommitContext{};
var task_checkpoint_context = TaskCheckpointContext{};
var package_context = PackageContext{};
var indexing_context = IndexingContext{};
var media_context = MediaContext{};
var compatibility_context = CompatibilityContext{};
var event_ledger_context = EventLedgerContext{};
var secret_store_context = SecretStoreContext{};
var overlay_session_context = OverlaySessionContext{};
var recovery_context = RecoveryContext{};
var update_health_context = UpdateHealthContext{};

pub fn run() noreturn {
    console.print("Running native spec-aligned benchmarks...\n");
    console.print(boot_markers.bench_start);
    console.print("\n");

    var total_cycles: u64 = 0;
    inline for (cases) |case| {
        total_cycles +%= runCase(case);
    }

    emitSummary(cases.len, total_cycles);
    console.print(boot_markers.bench_pass);
    console.print("\n");
    qemu_exit.success();
}

fn prepareFixtures() void {
    prepareFileBridgeFixture();
    preparePermissionReviewFixture();
    prepareNetworkPolicyFixture();
    prepareOverlaySessionFixture();
    prepareWorkspaceCommitFixture();
    prepareTaskCheckpointFixture();
}

fn prepareFileBridgeFixture() void {
    file_bridge_context.capability_table = capability.CapabilityTable.init();
    file_bridge_context.expected_workspace_id = 41;
    file_bridge_context.expected_path = "documents/plan.md";
    file_bridge_context.expected_version_id = 901;
    file_bridge_context.entry = workspace.Entry.init(
        file_bridge_context.expected_path,
        900,
        file_bridge_context.expected_version_id,
        .document,
    );
    file_bridge_context.version_present = true;
    const authority = file_bridge_context.capability_table.mintBootRoot(.{
        .holder = app(1),
        .issuer = policyAuthority(1),
        .target = .{ .kind = .object, .id = 900 },
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .scope = .{
            .task_id = 7,
            .workspace_id = file_bridge_context.expected_workspace_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
        },
        .audit = .{},
    }) catch unreachable;
    file_bridge_context.bridge = file_bridge.Bridge.init(
        &file_bridge_context,
        &file_bridge_context.capability_table,
        resolveBridgeEntry,
        bridgeHasVersion,
    );
    file_bridge_context.authority_capability_id = authority.id;
    file_bridge_context.requester = authority.holder;
}

fn prepareNetworkPolicyFixture() void {
    network_policy_context.directory = network_policy.Directory.init();
    const digest = [_]u8{0xAA} ** 32;
    const policy = network_policy_context.directory.create(.{
        .owner = service(8),
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
        .require_remote_attestation = true,
        .pinned_root_digest = digest,
    }) catch unreachable;
    network_policy_context.policy_id = policy.id;
    network_policy_context.evidence = .{
        .destination = .{ .domain = "relay.zigos.dev" },
        .attested = true,
        .peer_root_digest_present = true,
        .peer_root_digest = digest,
    };
}

fn preparePermissionReviewFixture() void {
    permission_review_context.decisions = .{
        permission_review.decisionFromCommand(
            permission_review_requests[0],
            permission_review.parseCommand("allow local lease=200") catch unreachable,
        ),
        permission_review.decisionFromCommand(
            permission_review_requests[1],
            permission_review.parseCommand("allow lease=30") catch unreachable,
        ),
    };
}

fn prepareWorkspaceCommitFixture() void {
    workspace_commit_context.baseline = workspace.Directory.init();
    const notes = workspace_commit_context.baseline.create(.{
        .owner = app(41),
        .label = "benchmark-notes",
    }) catch unreachable;
    workspace_commit_context.workspace_id = notes.id;

    workspace_commit_context.baseline.beginTransaction(notes.id) catch unreachable;
    workspace_commit_context.baseline.stagePut(notes.id, "documents/plan.md", 900, 901, .document) catch unreachable;
    workspace_commit_context.baseline.stagePut(notes.id, "assets/cover.jpg", 902, 903, .media_asset) catch unreachable;
    workspace_commit_context.baseline.stagePut(notes.id, "collections/inbox", 904, 905, .collection) catch unreachable;
    _ = workspace_commit_context.baseline.commit(notes.id, 10) catch unreachable;
}

fn prepareTaskCheckpointFixture() void {
    task_checkpoint_context.source_runtime = task_runtime.Runtime.init();
    task_checkpoint_context.restored_runtime = task_runtime.Runtime.init();
    task_checkpoint_context.snapshot = task_runtime.Runtime.initSnapshot();

    const sync_image = task_runtime.syntheticUserspaceImage("sync-ui", "app.sync.ui");
    const primary = task_checkpoint_context.source_runtime.createTask(.{
        .owner = app(120),
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = 2 * 1024 * 1024,
            .endpoint_slots = 8,
            .shared_memory_bytes = 128 * 1024,
            .background_allowed = true,
        },
        .ui_surface_id = 12,
        .local_only = false,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 44,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.sync",
        },
        .userspace_image = &sync_image,
    }) catch unreachable;
    task_checkpoint_context.primary_task_id = primary.id;
    _ = task_checkpoint_context.source_runtime.attachComponent(primary.id, .{
        .label = "sync-worker",
        .entry = "app.sync.worker",
    }, 60) catch unreachable;
    task_checkpoint_context.source_runtime.grantCapability(primary.id, 301) catch unreachable;
    task_checkpoint_context.source_runtime.grantCapability(primary.id, 302) catch unreachable;
    _ = task_checkpoint_context.source_runtime.reserveBackgroundWork(
        primary.id,
        .{
            .cpu_time_ticks = 400,
            .memory_bytes = 32 * 1024,
            .shared_memory_bytes = 4 * 1024,
        },
        .local_network_only,
        .status_only,
        61,
    ) catch unreachable;
    task_checkpoint_context.source_runtime.audit(primary.id, .{
        .kind = .service_connected,
        .detail = 7,
        .tick = 62,
    }) catch unreachable;

    const helper = task_checkpoint_context.source_runtime.createTask(.{
        .owner = service(121),
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 4_000,
            .memory_bytes = 128 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 8 * 1024,
            .background_allowed = false,
        },
        .local_only = true,
        .initial_component = .{
            .label = "checkpoint-helper",
            .entry = "service.checkpoint.helper",
        },
    }) catch unreachable;
    task_checkpoint_context.secondary_task_id = helper.id;
    task_checkpoint_context.source_runtime.grantCapability(helper.id, 401) catch unreachable;
    task_checkpoint_context.source_runtime.audit(helper.id, .{
        .kind = .policy_allowed,
        .detail = 1,
        .tick = 63,
    }) catch unreachable;
}

fn prepareOverlaySessionFixture() void {
    overlay_session_context.service = sync_service.Service.init(930, 71, service(33));
    overlay_session_context.workspace_id = 4_200;
    overlay_session_context.source_device = device(191);
    overlay_session_context.target_device = device(192);

    const owner = user(19);
    _ = overlay_session_context.service.ensureUserRoot(owner, "overlay-owner", signer("overlay-user", 0x61)) catch unreachable;
    _ = overlay_session_context.service.enrollTrustedDevice(
        owner,
        overlay_session_context.source_device,
        "overlay-laptop",
        signer("overlay-user", 0x61),
        signer("overlay-laptop", 0x62),
        10,
    ) catch unreachable;
    _ = overlay_session_context.service.enrollTrustedDevice(
        owner,
        overlay_session_context.target_device,
        "overlay-tablet",
        signer("overlay-user", 0x61),
        signer("overlay-tablet", 0x63),
        11,
    ) catch unreachable;

    const local_policy = overlay_session_context.service.createNetworkPolicy(.{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-local",
        .mode = .local_network,
    }) catch unreachable;
    const overlay_policy = overlay_session_context.service.createNetworkPolicy(.{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-service",
        .mode = .named_service_identity,
        .target = "overlay.workspace.sync",
    }) catch unreachable;
    const relay_policy = overlay_session_context.service.createNetworkPolicy(.{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    }) catch unreachable;
    _ = overlay_session_context.service.configureWorkspacePolicy(.{
        .workspace_id = overlay_session_context.workspace_id,
        .owner = owner,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    }) catch unreachable;
    _ = overlay_session_context.service.configureOverlay(
        overlay_session_context.workspace_id,
        overlay_session_context.source_device,
        "overlay.workspace.sync",
        true,
    ) catch unreachable;
    _ = overlay_session_context.service.publishPrivateService(
        overlay_session_context.workspace_id,
        "notes.remote",
    ) catch unreachable;
}

fn runCase(case: BenchmarkCase) u64 {
    // Benchmark cases mutate shared fixtures, so rebuild them before each case.
    prepareFixtures();
    var checksum: u64 = 0;
    const start = x86.rdtsc();
    var iteration: u32 = 0;
    while (iteration < case.iterations) : (iteration += 1) {
        checksum +%= case.runIteration(iteration);
    }
    const cycles = x86.rdtsc() - start;
    emitResult(case.name, case.iterations, cycles, checksum);
    return cycles;
}

fn emitResult(name: []const u8, iterations: u32, cycles: u64, checksum: u64) void {
    const scaled_cycles_per_op = if (iterations == 0)
        0
    else
        @divTrunc(cycles * 100, iterations);
    const whole = @divTrunc(scaled_cycles_per_op, 100);
    const frac = @mod(scaled_cycles_per_op, 100);

    var buffer: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "BENCH:RESULT:{s}:iterations={d}:cycles={d}:cycles_per_op={d}.{d:0>2}:checksum={d}\n",
        .{ name, iterations, cycles, whole, frac, checksum },
    ) catch unreachable;
    console.print(line);
}

fn emitSummary(benchmark_count: usize, total_cycles: u64) void {
    var buffer: [96]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "BENCH:SUMMARY:benchmarks={d}:total_cycles={d}\n",
        .{ benchmark_count, total_cycles },
    ) catch unreachable;
    console.print(line);
}

fn benchmarkCapabilityDerive(iteration: u32) u64 {
    var table = capability.CapabilityTable.init();
    const parent = table.mintBootRoot(.{
        .holder = app(10),
        .issuer = policyAuthority(1),
        .target = .{ .kind = .workspace, .id = 500 + iteration },
        .rights = .{ .object = .{
            .object_read = true,
            .object_write = true,
            .capability_derive = true,
        } },
        .scope = .{
            .task_id = 700 + iteration,
            .workspace_id = 500 + iteration,
            .local_only = true,
        },
        .lease = .{
            .issued_at_ticks = 10,
            .expires_at_ticks = 400,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = 700 + iteration,
        },
    }) catch unreachable;
    const derived = table.derive(.{
        .parent_capability_id = parent.id,
        .holder = app(11),
        .rights = .{ .object = .{ .object_read = true } },
        .scope = .{
            .task_id = 700 + iteration,
            .workspace_id = 500 + iteration,
            .local_only = true,
        },
        .lease = .{
            .issued_at_ticks = 20,
            .expires_at_ticks = 200,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = 700 + iteration,
        },
    }) catch unreachable;
    return derived.id + derived.target.id + derived.scope.workspace_id.?;
}

fn benchmarkPermissionReviewRender(iteration: u32) u64 {
    const session = permission_review.initSession(
        200 + iteration,
        &permission_review_bundle,
        permission_review_context.decisions[0..],
    );
    const rendered = permission_review.renderToBuffer(
        &permission_review_buffer,
        &session,
        &permission_review_bundle,
    ) catch unreachable;
    const grants = permission_review.decisionsToGrants(
        &permission_review_bundle,
        permission_review_context.decisions[0..],
        50 + iteration,
        &permission_review_grants,
    );

    var expires_sum: u64 = 0;
    for (grants) |grant| {
        expires_sum +%= grant.expires_at_ticks orelse 0;
    }
    return rendered.len + grants.len + expires_sum;
}

fn benchmarkNetworkPolicyAuthorize(iteration: u32) u64 {
    _ = iteration;
    const decision = network_policy_context.directory.authorizeConnection(
        network_policy_context.policy_id,
        network_policy_context.evidence,
    ) catch unreachable;
    return @as(u64, @intFromBool(decision.allowed)) +
        @as(u64, @intFromBool(decision.attestation_required)) +
        @as(u64, @intFromBool(decision.identity_pinned)) +
        @as(u64, @intFromEnum(decision.matched_mode));
}

fn benchmarkBackgroundDispatch(iteration: u32) u64 {
    background_context.runtime = task_runtime.Runtime.init();
    background_context.dispatcher = background_dispatch.Controller.init();

    const task = background_context.runtime.createTask(.{
        .owner = app(93 + iteration),
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
            .bundle_id = background_bundle.bundle_id,
        },
    }) catch unreachable;
    task.state = .active;

    const decision = background_context.dispatcher.dispatch(
        &background_context.runtime,
        task.id,
        background_bundle,
        "sync",
        .sync_completion,
        40 + iteration,
    ) catch unreachable;
    _ = background_context.dispatcher.complete(&background_context.runtime, decision.record_id.?) catch unreachable;
    return @intFromBool(decision.allowed) +
        decision.expected_duration_seconds +
        task.background_cpu_consumed_ticks +
        @intFromEnum(task.last_background_network);
}

fn benchmarkTaskCheckpointWriteRestore(iteration: u32) u64 {
    _ = iteration;
    task_checkpoint_context.source_runtime.writeSnapshot(&task_checkpoint_context.snapshot);
    task_checkpoint_context.restored_runtime.restoreFromSnapshot(&task_checkpoint_context.snapshot);

    const restored_primary = task_checkpoint_context.restored_runtime.find(task_checkpoint_context.primary_task_id) orelse unreachable;
    const restored_helper = task_checkpoint_context.restored_runtime.find(task_checkpoint_context.secondary_task_id) orelse unreachable;
    const latest_primary = restored_primary.latestAuditEvent() orelse unreachable;
    const latest_helper = restored_helper.latestAuditEvent() orelse unreachable;

    return restored_primary.id +
        restored_primary.execution_component_count +
        restored_primary.capability_count +
        restored_primary.userspaceImage().segment_count +
        restored_primary.background_cpu_consumed_ticks +
        latest_primary.tick +
        restored_helper.capability_count +
        latest_helper.tick;
}

fn benchmarkAcceleratorClaimRelease(iteration: u32) u64 {
    var controller = accelerator_scheduler.Controller.init();
    controller.configure(.{
        .thermal_pressure = .nominal,
        .battery_saver = false,
        .privacy_mode = false,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });

    var shared = shared_memory.Table.init();
    const object = shared.createWithAccess(800 + iteration, 64 * 1024, .{
        .cpu = true,
        .gpu = true,
    }) catch unreachable;
    const claim = controller.claimWithSharedMemory(.{
        .task_id = 800 + iteration,
        .request = .{
            .class = .foreground_interactive,
            .wants_gpu = true,
            .shared_memory_bytes = object.size_bytes,
        },
        .shared_memory_object_id = object.id,
    }, &shared) catch unreachable;
    const released = controller.releaseClaim(claim.id, &shared) catch unreachable;
    return claim.id + object.id + @intFromBool(released) + @intFromEnum(claim.engine);
}

fn benchmarkFileBridgeResolve(iteration: u32) u64 {
    var bridge = file_bridge_context.bridge.?;
    const view = bridge.resolve(.{
        .workspace_id = file_bridge_context.expected_workspace_id,
        .path = if ((iteration & 1) == 0) "/documents/plan.md" else "documents/plan.md",
        .access = .read,
    }, file_bridge_context.requester, file_bridge_context.authority_capability_id, 30 + iteration) catch unreachable;
    return view.object_id + view.version_id + view.path_len + @intFromBool(view.readable);
}

fn benchmarkWorkspaceCommitOverlay(iteration: u32) u64 {
    prepareWorkspaceCommitFixture();
    const directory = &workspace_commit_context.baseline;
    const workspace_id = workspace_commit_context.workspace_id;

    directory.beginTransaction(workspace_id) catch unreachable;
    directory.stagePut(workspace_id, "documents/plan.md", 900, 1_100 + iteration, .document) catch unreachable;
    directory.stageDelete(workspace_id, "assets/cover.jpg") catch unreachable;
    directory.stagePut(workspace_id, "documents/draft.md", 1_200 + iteration, 1_300 + iteration, .document) catch unreachable;
    directory.stagePut(workspace_id, "documents/tmp.md", 1_400 + iteration, 1_500 + iteration, .document) catch unreachable;
    directory.stageDelete(workspace_id, "documents/tmp.md") catch unreachable;

    const generation = directory.commit(workspace_id, 70 + iteration) catch unreachable;
    const entries = directory.entries(workspace_id) catch unreachable;
    const plan = directory.resolve(workspace_id, "documents/plan.md") catch unreachable;
    const draft = directory.resolve(workspace_id, "documents/draft.md") catch unreachable;
    return generation + entries.len + plan.version_id + draft.object_id;
}

fn benchmarkPackageRevision(iteration: u32) u64 {
    _ = iteration;
    package_context.service = package_service.Service.init();

    const slot = &package_context.service.slots[0];
    slot.in_use = true;
    package_service_bundle_ops.installNew(&slot.bundle, package_bundle_v1, 1, [_]u8{0x11} ** 32, "") catch unreachable;
    package_service_bundle_ops.installRevision(
        &slot.bundle,
        package_bundle_v2,
        2,
        [_]u8{0x22} ** 32,
        "schema:1->2;notes-v2-migration",
    ) catch unreachable;
    const active = package_service_bundle_ops.resolveActiveManifest(&slot.bundle, &package_context.resolved);
    const launch_plan = package_context.service.buildLaunchPlan("app.notes") catch unreachable;
    package_service_bundle_ops.rollback(&slot.bundle);
    return active.version_minor +
        launch_plan.component_count +
        launch_plan.asset_count +
        slot.bundle.activeRevision().version_minor +
        @intFromBool(slot.bundle.rollbackAvailable());
}

fn benchmarkIndexingQuery(iteration: u32) u64 {
    _ = iteration;
    indexing_context.service = indexing_service.Service.init();
    indexing_context.service.upsert(1, 100, 1, "Alpha Notes", "alpha alpha roadmap") catch unreachable;
    indexing_context.service.upsert(1, 101, 2, "Quarterly Report", "finance alpha summary") catch unreachable;
    indexing_context.service.upsert(2, 200, 1, "Private Contract", "alpha restricted") catch unreachable;

    const permitted = [_]u64{1};
    const results = indexing_context.service.query(&permitted, "alpha", &indexing_context.results);
    if (results.len == 0) return 0;
    return results.len + results[0].score + results[0].object_id + results[0].version_id;
}

fn benchmarkMediaPrintSubmitComplete(iteration: u32) u64 {
    media_context.scheduler = accelerator_scheduler.Controller.init();
    media_context.scheduler.configure(.{
        .thermal_pressure = .nominal,
        .battery_saver = false,
        .privacy_mode = false,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });
    media_context.notifications = notification_center.Center.init();
    media_context.service = media_print_service.Service.init();

    const source = app(70 + iteration);
    const export_job = media_context.service.submit(.{
        .kind = .media_export,
        .task_id = 501 + iteration,
        .workspace_id = 11,
        .source_principal = source,
        .label = "render reel",
        .visibility = .task,
    }, &media_context.scheduler, &media_context.notifications, 20 + iteration) catch unreachable;
    const print_job = media_context.service.submit(.{
        .kind = .print_document,
        .task_id = 502 + iteration,
        .workspace_id = 11,
        .source_principal = source,
        .label = "print itinerary",
        .printer_identity = "printer://lobby",
        .visibility = .user,
    }, &media_context.scheduler, &media_context.notifications, 21 + iteration) catch unreachable;

    _ = media_context.service.complete(print_job.id, &media_context.scheduler, &media_context.notifications, 30 + iteration) catch unreachable;
    _ = media_context.service.complete(export_job.id, &media_context.scheduler, &media_context.notifications, 31 + iteration) catch unreachable;

    return export_job.id +
        print_job.id +
        @intFromEnum(export_job.engine) +
        media_context.notifications.activeCount(31 + iteration);
}

fn benchmarkCompatibilityLaunchPortal(iteration: u32) u64 {
    compatibility_context.manager = compatibility_environment.Manager.init();
    const env = compatibility_context.manager.launch(.{
        .service_id = 900 + iteration,
        .owner = app(210 + iteration),
        .kind = .container,
        .label = "legacy-workbench",
        .bundle = compatibility_bundle,
        .network_class = .named_service_only,
    }) catch unreachable;
    compatibility_context.manager.grantPortal(env.id, .{
        .kind = .file_import,
        .capability_id = 700 + iteration,
        .expires_at_ticks = 100,
    }) catch unreachable;
    compatibility_context.manager.grantPortal(env.id, .{
        .kind = .open_uri,
        .capability_id = 800 + iteration,
        .read_only = false,
        .expires_at_ticks = 20,
    }) catch unreachable;
    const revoked = compatibility_context.manager.revokeExpiredPortals(50 + iteration);
    return env.id +
        env.portal_count +
        revoked +
        @intFromBool(env.hasPortal(.file_import));
}

fn benchmarkEventLedgerExport(iteration: u32) u64 {
    event_ledger_context.ledger = event_ledger.Ledger.init();
    const user_subject = user(7 + iteration);
    const service_subject = service(9 + iteration);
    const device_subject = device(42 + iteration);

    event_ledger_context.ledger.recordPermissionDecision(
        user_subject,
        11 + iteration,
        .screen_capture,
        false,
        .policy_denied,
        20 + iteration,
        "org policy denied capture",
        true,
    ) catch unreachable;
    event_ledger_context.ledger.recordProcessCrash(.network_stack, service_subject, 21 + iteration, 5001, "segfault") catch unreachable;
    event_ledger_context.ledger.recordDriverRestart(.media_print_helpers, service_subject, 88 + iteration, 22 + iteration, "audio-print restarted") catch unreachable;
    event_ledger_context.ledger.recordUpdateTransition(service_subject, 1, .boot, true, 23 + iteration, "rolled back to stable-a") catch unreachable;
    event_ledger_context.ledger.recordSyncConflict(user_subject, 5, 24 + iteration, "documents/tax-return.pdf conflict", true) catch unreachable;
    event_ledger_context.ledger.recordDeviceTrustChange(user_subject, device_subject, false, 25 + iteration, "device revoked") catch unreachable;

    const exported = event_ledger_context.ledger.exportText(&event_ledger_buffer, .{}) catch unreachable;
    return exported.len + event_ledger_context.ledger.next_sequence;
}

fn benchmarkSecretStoreImportHandleExport(iteration: u32) u64 {
    secret_store_context.store = secure_secret_store.Store.init();
    const exportable = (iteration & 1) != 0;
    const secret = secret_store_context.store.importSecret(
        secret_store_context.owner,
        if (exportable) "backup-code" else "api-key",
        if (exportable) "abcd-efgh" else "super-secret-token",
        !exportable,
        exportable,
    ) catch unreachable;
    const handle = secret_store_context.store.lendHandle(
        secret.id,
        secret_store_context.holder,
        700 + iteration,
        true,
    ) catch unreachable;
    const described = secret_store_context.store.describeHandle(handle.id) orelse unreachable;
    if (exportable) {
        const exported = secret_store_context.store.exportRaw(handle.id) catch unreachable;
        return secret.id +
            handle.id +
            described.task_id +
            exported.len +
            @as(u64, @intFromBool(described.export_allowed));
    }
    _ = secret_store_context.store.exportRaw(handle.id) catch |err| switch (err) {
        error.RawExportDenied => {},
        else => unreachable,
    };
    return secret.id +
        handle.id +
        described.task_id +
        @as(u64, @intFromBool(secret.hardware_backed)) +
        @as(u64, @intFromBool(secret.sealed_digest_present));
}

fn benchmarkDenialExplanationRender(iteration: u32) u64 {
    const kind: manifest.PermissionKind = switch (@mod(iteration, 4)) {
        0 => .network_egress,
        1 => .object_access,
        2 => .background_execution,
        else => .screen_capture,
    };
    const reason: abi.DenialReason = switch (@mod(iteration, 4)) {
        0 => .policy_denied,
        1 => .capability_missing,
        2 => .budget_exhausted,
        else => .capability_expired,
    };
    const explanation = denial_explanation.forPermissionDecision(kind, reason);
    const rendered = denial_explanation.renderToBuffer(&denial_explanation_buffer, explanation) catch unreachable;
    return rendered.len +
        explanation.policy_len +
        explanation.missing_capability_len +
        @as(u64, @intFromBool(explanation.user_approval_can_resolve)) +
        @as(u64, @intFromBool(explanation.retry_safe));
}

fn benchmarkOverlaySessionFlow(iteration: u32) u64 {
    const usage: sync_service.OverlaySessionUse = switch (@mod(iteration, 3)) {
        0 => .sync_replication,
        1 => .remote_access,
        else => .private_service,
    };
    const transport: sync_service.TransportMode = switch (usage) {
        .sync_replication => .device_to_device,
        .remote_access, .private_service => .relay_assisted,
    };
    const session = overlay_session_context.service.openOverlaySession(
        overlay_session_context.workspace_id,
        overlay_session_context.source_device,
        overlay_session_context.target_device,
        usage,
        transport,
        if (usage == .private_service) "notes.remote" else null,
        40 + iteration,
    ) catch unreachable;
    _ = overlay_session_context.service.probeOverlaySession(session.session_id, 41 + iteration) catch unreachable;
    const live = overlay_session_context.service.findOverlaySession(session.session_id) orelse unreachable;
    _ = overlay_session_context.service.closeOverlaySession(session.session_id, 42 + iteration) catch unreachable;

    return session.session_id +
        session.overlay_id +
        live.keepalive_count +
        @as(u64, @intFromBool(session.encrypted)) +
        @as(u64, @intFromBool(session.relay_encrypted)) +
        @as(u64, @intFromBool(session.remote_access));
}

fn benchmarkRecoveryLifecycle(iteration: u32) u64 {
    prepareRecoveryFixture(iteration);
    const payload = if ((iteration & 1) == 0) "kernel=v2" else "kernel=v3";
    const reinstalled = recovery_context.environment.verifyAndReinstallImage(
        &recovery_context.manager,
        payload,
        signer("platform-image", 0x72),
        16 + iteration,
    ) catch unreachable;
    const restored = recovery_context.environment.restoreWorkspaceSnapshot(
        &recovery_context.storage,
        recovery_context.workspace_id,
        recovery_context.snapshot_id,
        17 + iteration,
    ) catch unreachable;
    const repaired = recovery_context.environment.repairSyncMetadata(
        &recovery_context.sync,
        &recovery_context.storage,
        recovery_context.workspace_id,
        recovery_context.tablet,
    ) catch unreachable;
    const rotation_generation = recovery_context.environment.rotateDeviceKeys(
        &recovery_context.sync,
        recovery_context.user,
        recovery_context.tablet,
        signer("platform-user", 0x74),
        signer("tablet-device-v2", 0x77),
        18 + iteration,
    ) catch unreachable;
    const revoked = recovery_context.environment.revokeDeviceTrust(
        &recovery_context.sync,
        recovery_context.user,
        recovery_context.tablet,
        signer("platform-user", 0x74),
        19 + iteration,
    ) catch unreachable;

    return @as(u64, @intFromBool(reinstalled)) +
        @as(u64, @intFromBool(restored)) +
        @as(u64, @intFromBool(repaired)) +
        rotation_generation +
        @as(u64, @intFromBool(revoked)) +
        @as(u64, @intFromBool(recovery_context.environment.report.image_activated));
}

fn benchmarkUpdateHealthValidation(iteration: u32) u64 {
    prepareUpdateHealthFixture(iteration);
    update_health_context.manager.beginActivation(0, 13 + iteration) catch unreachable;
    update_health.recordBootSuccess(&update_health_context.manager, 14 + iteration) catch unreachable;
    const result = update_health.validatePendingActivation(
        &update_health_context.manager,
        &update_health_context.supervisor,
        &update_health_context.storage,
        update_health_context.request,
        &update_health_context.ledger,
        15 + iteration,
    ) catch unreachable;
    const event = update_health_context.ledger.latestKind(.update_transition) orelse unreachable;
    return result.evaluation.core_services_started +
        @as(u64, @intFromBool(result.evaluation.report.isHealthy())) +
        @as(u64, @intFromBool(result.evaluation.network_service_ok)) +
        @as(u64, @intFromBool(result.evaluation.ui_service_ok)) +
        result.activation.activation_generation +
        event.sequence;
}

fn benchmarkDriverRecoveryRestart(iteration: u32) u64 {
    var supervisor = supervisor_mod.Supervisor.init();
    const compositor = supervisor.register(.compositor_ui_session, service(50 + iteration)) catch unreachable;
    if (!supervisor.markHealthy(compositor.id, 1 + iteration)) unreachable;

    var directory = driver_service.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const authority = mintDriverAuthority(
        &capabilities,
        compositor.owner,
        401 + iteration,
        @as(u64, 0x1234_1111_0001) + iteration,
        .graphics_adapter,
    );
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.runtime",
        .display_name = "Driver Runtime",
        .publisher = "zigos.spec",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-driver-key",
        },
    };
    const driver = directory.register(.{
        .service_id = compositor.id,
        .owner_task_id = 401 + iteration,
        .device_id = @as(u64, 0x1234_1111_0001) + iteration,
        .device_class = .graphics_adapter,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = authority.holder,
        .now_ticks = 1 + iteration,
        .bundle = bundle,
    }) catch unreachable;

    var runtime = DriverRecoveryRuntime{};
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    const recovery = supervisor.recoverDriverCrash(
        compositor.id,
        &directory,
        &runtime,
        &notifications,
        &ledger,
        10 + iteration,
        0xD1,
        "display driver restart",
    ) catch unreachable;

    return driver.restart_generation +
        runtime.activation_count +
        compositor.restart_count +
        @as(u64, @intFromBool(recovery.visible_impact)) +
        @as(u64, @intFromBool(recovery.notification_id != null)) +
        ledger.latestKind(.driver_restart).?.sequence;
}

const DriverRecoveryRuntime = struct {
    activation_count: usize = 0,

    pub fn activate(self: *@This(), _: *const driver_service.DriverRecord) !void {
        self.activation_count += 1;
    }
};

fn prepareRecoveryFixture(iteration: u32) void {
    recovery_context.checkpoint_store.resetPersistent();

    const storage_owner = service(4);
    const sync_owner = service(8);
    recovery_context.storage = storage_service.Service.initWithStore(920, 51, storage_owner, &recovery_context.checkpoint_store);
    recovery_context.manager = immutable_base.Manager.init(
        &recovery_context.storage,
        storage_owner,
        signer("platform-state", 0x71),
    ) catch unreachable;
    _ = recovery_context.manager.stageImage(0, "stable-a", "kernel=v1", signer("platform-image", 0x72), 10 + iteration) catch unreachable;
    _ = recovery_context.manager.activate(0, .{}, 11 + iteration) catch unreachable;

    const notes_v1 = recovery_context.storage.putVersion(.{
        .preferred_object_id = 980,
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = object_store.signMetadata(
            signer("platform-storage", 0x73),
            "notes",
            "text/plain",
            .document,
            "notes-v1",
            12 + iteration,
        ) catch unreachable,
    }) catch unreachable;
    const notes_v2 = recovery_context.storage.putVersion(.{
        .preferred_object_id = 980,
        .object_type = .document,
        .payload = "notes-v2",
        .metadata = object_store.signMetadata(
            signer("platform-storage", 0x73),
            "notes",
            "text/plain",
            .document,
            "notes-v2",
            13 + iteration,
        ) catch unreachable,
        .parent_version_id = notes_v1.version_id,
    }) catch unreachable;
    const workspace_record = recovery_context.storage.createWorkspace(.{
        .owner = recovery_context.user,
        .label = "recovery-notes",
    }) catch unreachable;
    recovery_context.workspace_id = workspace_record.id;
    recovery_context.storage.beginTransaction(workspace_record.id) catch unreachable;
    recovery_context.storage.stagePut(
        workspace_record.id,
        "documents/notes.md",
        notes_v1.object_id,
        notes_v1.version_id,
        .document,
    ) catch unreachable;
    _ = recovery_context.storage.commit(workspace_record.id, 14 + iteration) catch unreachable;
    const snapshot = recovery_context.storage.snapshot(
        workspace_record.id,
        "baseline",
        signer("platform-storage", 0x73),
    ) catch unreachable;
    recovery_context.snapshot_id = snapshot.id;
    recovery_context.storage.beginTransaction(workspace_record.id) catch unreachable;
    recovery_context.storage.stagePut(
        workspace_record.id,
        "documents/notes.md",
        notes_v2.object_id,
        notes_v2.version_id,
        .document,
    ) catch unreachable;
    _ = recovery_context.storage.commit(workspace_record.id, 15 + iteration) catch unreachable;

    recovery_context.sync = sync_service.Service.init(921, 52, sync_owner);
    _ = recovery_context.sync.ensureUserRoot(recovery_context.user, "cameron", signer("platform-user", 0x74)) catch unreachable;
    _ = recovery_context.sync.enrollTrustedDevice(
        recovery_context.user,
        recovery_context.primary_device,
        "primary",
        signer("platform-user", 0x74),
        signer("primary-device", 0x75),
        16 + iteration,
    ) catch unreachable;
    _ = recovery_context.sync.enrollTrustedDevice(
        recovery_context.user,
        recovery_context.tablet,
        "tablet",
        signer("platform-user", 0x74),
        signer("tablet-device", 0x76),
        17 + iteration,
    ) catch unreachable;
    const local_policy = recovery_context.sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "local-net",
        .mode = .local_network,
    }) catch unreachable;
    _ = recovery_context.sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_record.id,
        .owner = recovery_context.user,
        .device_to_device_policy_id = local_policy.id,
        .selective_prefixes = &.{"documents/"},
    }) catch unreachable;
    recovery_context.sync.setReplicaVersion(
        workspace_record.id,
        recovery_context.tablet,
        "documents/notes.md",
        notes_v1.object_id,
        notes_v1.version_id,
    ) catch unreachable;

    recovery_context.environment = recovery_environment.Environment.init(storage_owner);
}

fn prepareUpdateHealthFixture(iteration: u32) void {
    update_health_context.checkpoint_store.resetPersistent();
    const owner = service(70);
    update_health_context.storage = storage_service.Service.initWithStore(1_001, 201, owner, &update_health_context.checkpoint_store);
    const probe_workspace_id = seedUpdateHealthStorageProbe(
        &update_health_context.storage,
        owner,
        signer("update-health-object", 0x33),
        9 + iteration,
    );
    update_health_context.manager = immutable_base.Manager.init(
        &update_health_context.storage,
        owner,
        signer("update-health-state", 0x31),
    ) catch unreachable;
    update_health_context.sync = sync_service.Service.init(1_500, 401, owner);
    update_health_context.compositor = compositor_session.Session.init();
    update_health_context.supervisor = supervisor_mod.Supervisor.init();
    update_health_context.ledger = event_ledger.Ledger.init();

    const network_probe = seedUpdateHealthNetworkProbe(
        &update_health_context.sync,
        probe_workspace_id,
        12 + iteration,
    );
    const ui_probe = seedUpdateHealthUiProbe(&update_health_context.compositor);
    _ = update_health_context.manager.stageImage(
        0,
        "stable-a",
        "kernel=v1",
        signer("update-health-image", 0x32),
        11 + iteration,
    ) catch unreachable;

    update_health_context.core_service_ids[0] = registerHealthyServiceForBenchmark(
        &update_health_context.supervisor,
        .policy_mediation,
        owner,
        12 + iteration,
    );
    update_health_context.core_service_ids[1] = registerHealthyServiceForBenchmark(
        &update_health_context.supervisor,
        .package_install_update,
        owner,
        12 + iteration,
    );
    update_health_context.core_service_ids[2] = registerHealthyServiceForBenchmark(
        &update_health_context.supervisor,
        .sync_replication,
        owner,
        12 + iteration,
    );
    const network_service_id = registerHealthyServiceForBenchmark(
        &update_health_context.supervisor,
        .network_stack,
        owner,
        12 + iteration,
    );
    const ui_service_id = registerHealthyServiceForBenchmark(
        &update_health_context.supervisor,
        .compositor_ui_session,
        owner,
        12 + iteration,
    );

    update_health_context.request = .{
        .core_service_ids = update_health_context.core_service_ids[0..],
        .storage_workspace_id = probe_workspace_id,
        .storage_probe_path = "documents/notes.md",
        .network_service_id = network_service_id,
        .ui_service_id = ui_service_id,
        .network_probe = network_probe,
        .ui_probe = ui_probe,
    };
}

fn registerHealthyServiceForBenchmark(
    supervisor: *supervisor_mod.Supervisor,
    class: contract.ServiceClass,
    owner: principal.PrincipalId,
    tick: u64,
) u64 {
    const service_record = supervisor.register(class, owner) catch unreachable;
    if (!supervisor.noteContractBound(service_record.id, 100 + service_record.id, tick)) unreachable;
    if (!supervisor.markHealthy(service_record.id, tick)) unreachable;
    return service_record.id;
}

fn seedUpdateHealthStorageProbe(
    storage: *storage_service.Service,
    owner: principal.PrincipalId,
    identity: signing.SignerIdentity,
    tick: u64,
) u64 {
    const record = storage.putVersion(.{
        .preferred_object_id = 7_700,
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = object_store.signMetadata(
            identity,
            "notes",
            "text/plain",
            .document,
            "notes-v1",
            tick,
        ) catch unreachable,
    }) catch unreachable;
    const workspace_record = storage.createWorkspace(.{
        .owner = owner,
        .label = "update-health",
    }) catch unreachable;
    storage.beginTransaction(workspace_record.id) catch unreachable;
    storage.stagePut(workspace_record.id, "documents/notes.md", record.object_id, record.version_id, .document) catch unreachable;
    _ = storage.commit(workspace_record.id, tick + 1) catch unreachable;
    return workspace_record.id;
}

fn seedUpdateHealthNetworkProbe(
    sync: *sync_service.Service,
    workspace_id: u64,
    tick_base: u64,
) update_health.NetworkProbe {
    const owner = user(88);
    const source_device = device(881);
    const target_device = device(882);
    _ = sync.ensureUserRoot(owner, "update-health", signer("update-health-user", 0x51)) catch unreachable;
    _ = sync.enrollTrustedDevice(
        owner,
        source_device,
        "source",
        signer("update-health-user", 0x51),
        signer("update-health-source", 0x52),
        tick_base,
    ) catch unreachable;
    _ = sync.enrollTrustedDevice(
        owner,
        target_device,
        "target",
        signer("update-health-user", 0x51),
        signer("update-health-target", 0x53),
        tick_base + 1,
    ) catch unreachable;

    const local_policy = sync.createNetworkPolicy(.{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "health-local",
        .mode = .local_network,
    }) catch unreachable;
    const overlay_policy = sync.createNetworkPolicy(.{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "health-overlay",
        .mode = .named_service_identity,
        .target = "overlay.health.sync",
    }) catch unreachable;
    _ = sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_id,
        .owner = owner,
        .device_to_device_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
    }) catch unreachable;
    _ = sync.configureOverlay(workspace_id, source_device, "overlay.health.sync", true) catch unreachable;

    return .{
        .sync = sync,
        .workspace_id = workspace_id,
        .source_device = source_device,
        .target_device = target_device,
        .tick = tick_base + 2,
    };
}

fn seedUpdateHealthUiProbe(session: *compositor_session.Session) update_health.UiProbe {
    var runtime = task_runtime.Runtime.init();
    const task = runtime.createTask(.{
        .owner = service(89),
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 4 * 1024,
        },
        .ui_surface_id = 3,
        .initial_component = .{
            .label = "health-ui",
            .entry = "zigos.health.ui",
        },
    }) catch unreachable;
    _ = session.openTaskView(task, "Update Health") catch unreachable;
    return .{ .session = session };
}

fn mintDriverAuthority(
    capability_table: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    task_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
) capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = policyAuthority(1),
        .target = driver_service.authorityTarget(device_id),
        .rights = driver_service.allowedRightsFor(device_class),
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
    }) catch unreachable;
}

fn signer(label: []const u8, seed_byte: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = [_]u8{seed_byte} ** 32,
    };
}

fn resolveBridgeEntry(
    context: *const anyopaque,
    workspace_id: u64,
    path: []const u8,
) workspace.Error!workspace.Entry {
    const bridge_context: *const FileBridgeContext = @ptrCast(@alignCast(context));
    if (workspace_id != bridge_context.expected_workspace_id) return error.EntryNotFound;
    if (!std.mem.eql(u8, path, bridge_context.expected_path)) return error.EntryNotFound;
    return bridge_context.entry;
}

fn bridgeHasVersion(context: *const anyopaque, version_id: u64) bool {
    const bridge_context: *const FileBridgeContext = @ptrCast(@alignCast(context));
    return bridge_context.version_present and version_id == bridge_context.expected_version_id;
}

fn user(serial: u64) principal.PrincipalId {
    return .{ .kind = .user, .serial = serial };
}

fn app(serial: u64) principal.PrincipalId {
    return .{ .kind = .app, .serial = serial };
}

fn service(serial: u64) principal.PrincipalId {
    return .{ .kind = .service, .serial = serial };
}

fn device(serial: u64) principal.PrincipalId {
    return .{ .kind = .device, .serial = serial };
}

fn policyAuthority(serial: u64) principal.PrincipalId {
    return .{ .kind = .policy_authority, .serial = serial };
}
