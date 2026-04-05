const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const console = @import("../utils/console.zig");
const qemu_exit = @import("../utils/qemu_exit.zig");
const boot_markers = @import("markers.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const principal = @import("../../native/core/principal.zig");
const manifest = @import("../../native/policy/manifest.zig");
const permission_review = @import("../../native/policy/permission_review.zig");
const policy_mediation = @import("../../native/policy/policy_mediation.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const background_dispatch = @import("../../native/task/background_dispatch.zig");
const accelerator_scheduler = @import("../../native/task/accelerator_scheduler.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const workspace = @import("../../native/storage/workspace.zig");
const file_bridge = @import("../../native/storage/file_bridge.zig");
const package_service = @import("../../native/services/package_service.zig");
const package_service_bundle_ops = @import("../../native/services/package_service_bundle_ops.zig");
const indexing_service = @import("../../native/services/indexing_service.zig");
const notification_center = @import("../../native/services/notification_center.zig");
const media_print_service = @import("../../native/services/media_print_service.zig");
const compatibility_environment = @import("../../native/services/compatibility_environment.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");

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
    bridge: ?file_bridge.Bridge = null,
    authority: capability.Capability = zeroCapability(),
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
};

const permission_review_requests = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://trip/documents/plan.md",
        .rights = .{
            .object_read = true,
            .object_write = true,
        },
        .local_only = true,
        .max_lease_ticks = 400,
    },
    .{
        .kind = .network_egress,
        .resource = "https://api.example.com",
        .rights = .{
            .network_remote = true,
        },
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
        .rights = .{ .background_run = true },
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
        .rights = .{ .object_read = true, .object_write = true },
        .local_only = true,
    },
};

const package_v2_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://notes",
        .rights = .{ .object_read = true, .object_write = true },
        .local_only = true,
    },
    .{
        .kind = .network_egress,
        .resource = "relay.notes.example",
        .rights = .{ .network_remote = true },
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

var file_bridge_context = FileBridgeContext{};
var network_policy_context = NetworkPolicyContext{};
var background_context = BackgroundContext{};
var workspace_commit_context = WorkspaceCommitContext{};
var task_checkpoint_context = TaskCheckpointContext{};
var package_context = PackageContext{};
var indexing_context = IndexingContext{};
var media_context = MediaContext{};
var compatibility_context = CompatibilityContext{};
var event_ledger_context = EventLedgerContext{};
var fixtures_prepared = false;

pub fn run() noreturn {
    prepareFixtures();

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
    if (fixtures_prepared) return;
    prepareFileBridgeFixture();
    prepareNetworkPolicyFixture();
    prepareWorkspaceCommitFixture();
    prepareTaskCheckpointFixture();
    fixtures_prepared = true;
}

fn prepareFileBridgeFixture() void {
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
    file_bridge_context.bridge = file_bridge.Bridge.init(&file_bridge_context, resolveBridgeEntry, bridgeHasVersion);
    file_bridge_context.authority = .{
        .id = 1,
        .holder = app(1),
        .issuer = policyAuthority(1),
        .target = .{ .kind = .object, .id = 900 },
        .rights = .{ .object_read = true, .object_write = true },
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
        .revocation_generation = 1,
        .audit = .{},
    };
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

fn runCase(case: BenchmarkCase) u64 {
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
    const parent = table.mint(.{
        .holder = app(10),
        .issuer = policyAuthority(1),
        .target = .{ .kind = .workspace, .id = 500 + iteration },
        .rights = .{
            .object_read = true,
            .object_write = true,
            .capability_derive = true,
        },
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
        .rights = .{ .object_read = true },
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
    const decision_a = permission_review.decisionFromCommand(
        permission_review_requests[0],
        permission_review.parseCommand("allow local lease=200") catch unreachable,
    );
    const decision_b = permission_review.decisionFromCommand(
        permission_review_requests[1],
        permission_review.parseCommand("allow lease=30") catch unreachable,
    );
    const decisions = [_]permission_review.ReviewDecision{ decision_a, decision_b };
    var session = permission_review.initSession(200 + iteration, permission_review_bundle, &decisions);
    const rendered = permission_review.renderToBuffer(&permission_review_buffer, &session, permission_review_bundle) catch unreachable;
    const grants = permission_review.decisionsToGrants(
        permission_review_bundle,
        &decisions,
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
    }, file_bridge_context.authority, 30 + iteration) catch unreachable;
    return view.object_id + view.version_id + view.path_len + @intFromBool(view.readable);
}

fn benchmarkWorkspaceCommitOverlay(iteration: u32) u64 {
    var directory = workspace_commit_context.baseline;
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
    package_service_bundle_ops.installNew(&slot.bundle, package_bundle_v1, 1, [_]u8{0x11} ** 32, "");
    package_service_bundle_ops.installRevision(
        &slot.bundle,
        package_bundle_v2,
        2,
        [_]u8{0x22} ** 32,
        "schema:1->2;notes-v2-migration",
    );
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

fn zeroCapability() capability.Capability {
    return .{
        .id = 0,
        .holder = .{ .kind = .service, .serial = 0 },
        .issuer = .{ .kind = .service, .serial = 0 },
        .target = .{ .kind = .object, .id = 0 },
        .rights = .{},
        .scope = .{},
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 0,
        },
        .revocation_generation = 0,
        .audit = .{},
    };
}
